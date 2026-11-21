package unlock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Schedule ownership (the keys plan §11.2): with no instance lease at the holders, several VMs (releases, providers) may
// be unlocked at once. Sealed state is safe (a second writer's save fails the Worker's compare-and-set and stops
// it), but two VMs must never both fire a space's schedules. So agentd fires a space's schedule only while it holds
// that space's ownership row at the chat Worker, a D1 row claimed and renewed by compare-and-set and signed with the
// state/v1 store-auth key (the KMS id certifies it; the Worker checks it as for sealed state):
//
//	POST /api/vm/owner/<OwnerName(space)>   {"owner": "<this VM's owner id>", "ttl": <seconds>}
//	  200 {"owner": ..., "until": <unix>}   this VM holds it until then (claimed, or renewed: it held it)
//	  409 {"owner": ..., "until": <unix>}   another VM does
//	  401 not the VM's
//
// The Worker's row: (app, name) -> owner, until; an UPDATE wins only WHERE owner = ? OR until < now (one statement).
// The owner id is the attested instance id (a restarted agentd of the same VM takes its row back at once; another
// VM waits for the row to lapse, at most TTL).

// OwnerTTL is how long a claim lasts.
const OwnerTTL = 5 * time.Minute

// OwnerName is a space's row name: no space id at the Worker beyond what the relay already sees, and a valid path.
func OwnerName(space string) string {
	h := sha256.Sum256([]byte("tacy/owner/v1\x00" + space))
	return "o" + hex.EncodeToString(h[:24])
}

// OwnerClaim is the request body.
type OwnerClaim struct {
	Owner string `json:"owner"`
	TTL   int    `json:"ttl"`
}

// OwnerRow is the answer.
type OwnerRow struct {
	Owner string `json:"owner"`
	Until int64  `json:"until"`
}

// Owner is agentd's side.
type Owner struct {
	// Client carries the request to the Worker (gateway.StateHTTP: gatewayd's state target).
	Client interface {
		Do(*http.Request) (*http.Response, error)
	}
	Auth func(*http.Request) // Keys.StoreAuth("state/v1")
	ID   string              // this VM's owner id
	TTL  time.Duration       // 0: OwnerTTL
	Now  func() time.Time

	mu   sync.Mutex
	held map[string]time.Time
}

// Holds says whether this VM may fire space's schedules now: a claim (or a renewal past half its life) at the
// Worker. Fail closed: no answer, no fire (the slot fires late, by the VM that holds it, rather than twice).
func (o *Owner) Holds(ctx context.Context, space string) bool {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = OwnerTTL
	}
	name := OwnerName(space)
	o.mu.Lock()
	until, ok := o.held[name]
	o.mu.Unlock()
	if ok && now().Add(ttl/2).Before(until) {
		return true
	}
	row, mine, err := o.claim(ctx, name, ttl)
	if err != nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.held == nil {
		o.held = map[string]time.Time{}
	}
	if !mine {
		delete(o.held, name)
		return false
	}
	o.held[name] = time.Unix(row.Until, 0)
	return now().Before(o.held[name])
}

func (o *Owner) claim(ctx context.Context, name string, ttl time.Duration) (*OwnerRow, bool, error) {
	body, _ := json.Marshal(OwnerClaim{Owner: o.ID, TTL: int(ttl / time.Second)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://state/api/vm/owner/"+name, bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.Auth != nil {
		o.Auth(req)
	}
	res, err := o.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()
	var row OwnerRow
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusConflict {
		return nil, false, fmt.Errorf("owner: HTTP %d", res.StatusCode)
	}
	if err := json.Unmarshal(b, &row); err != nil {
		return nil, false, err
	}
	return &row, res.StatusCode == http.StatusOK && row.Owner == o.ID, nil
}

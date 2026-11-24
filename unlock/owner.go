package unlock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// LeaseName is the row name of a sealed-state writer lease (app/lease.go): the same route and row form as a space's
// ownership row, under its own prefix, so no name is both. scope: "state/all" (every state of the app, v1), later one
// per shard ("state/s07", docs/41).
func LeaseName(scope string) string {
	h := sha256.Sum256([]byte("tacy/state-lease/v1\x00" + scope))
	return "o" + hex.EncodeToString(h[:24])
}

// ErrNoOwnerRoute: the Worker (or stand-in) has no such route (404, 405): one built before it.
var ErrNoOwnerRoute = errors.New("owner: the Worker has no such route")

// LeaseRow is the writer lease's row as the Worker answers it (apps/chat vm-lease.ts).
type LeaseRow struct {
	Holder string `json:"holder"`
	Until  int64  `json:"until"`
}

// LegacyHolder is the lease row of a VM built before the lease (the Worker writes it at such a VM's first save, and a
// lease VM hands the lease to it when the Worker switches back to one): never lapses, never claimed on its own.
const LegacyHolder = "legacy"

// ClaimLease claims or renews the writer lease row name for holder (POST /api/vm/lease/<name>, the same client and
// signature as the ownership rows): the row as it stands, and whether it is holder's now. The Worker gives it only
// when there is none, it is holder's, or it lapsed and was the same app's. from: a takeover the Worker's switch
// ordered (in its signed undrain or drain): the row moves only if it is from's (compare and set); "": none.
func (o *Owner) ClaimLease(ctx context.Context, name, holder, from string, ttl time.Duration) (LeaseRow, bool, error) {
	if ttl < time.Second {
		ttl = time.Second
	}
	c := map[string]any{"holder": holder, "ttl": int(ttl / time.Second)}
	if from != "" {
		c["from"] = from
	}
	body, _ := json.Marshal(c)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://state/api/vm/lease/"+name, bytes.NewReader(body))
	if err != nil {
		return LeaseRow{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.Auth != nil {
		o.Auth(req)
	}
	res, err := o.Client.Do(req)
	if err != nil {
		return LeaseRow{}, false, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusMethodNotAllowed {
		return LeaseRow{}, false, ErrNoOwnerRoute
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusConflict {
		return LeaseRow{}, false, fmt.Errorf("lease: HTTP %d", res.StatusCode)
	}
	var row LeaseRow
	if err := json.Unmarshal(b, &row); err != nil {
		return LeaseRow{}, false, err
	}
	return row, res.StatusCode == http.StatusOK && row.Holder == holder, nil
}

// Release gives up every ownership row this VM holds (a drained VM's, so the VM taking over fires the spaces'
// schedules at once rather than when the rows lapse): each claimed again for one second.
func (o *Owner) Release(ctx context.Context) {
	o.mu.Lock()
	names := make([]string, 0, len(o.held))
	for n := range o.held {
		names = append(names, n)
	}
	o.held = nil
	o.mu.Unlock()
	for _, n := range names {
		o.claim(ctx, n, time.Second) //nolint:errcheck // best effort: the row lapses within OwnerTTL anyway
	}
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
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusMethodNotAllowed {
		return nil, false, ErrNoOwnerRoute
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusConflict {
		return nil, false, fmt.Errorf("owner: HTTP %d", res.StatusCode)
	}
	if err := json.Unmarshal(b, &row); err != nil {
		return nil, false, err
	}
	return &row, res.StatusCode == http.StatusOK && row.Owner == o.ID, nil
}

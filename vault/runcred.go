package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tacyhq/tacy/safety"
)

// Per-task mail logins (v1, the v1 design §5.4). The person's apps keep the login (the mail-login/v1 item, under
// their own key) and send it sealed to this boot's vault key with each task that may read mail. agentd passes the
// box on unopened (RunGrant); only this process opens it, checks it is for the task's space and start key and not
// past its expiry, and holds {task, space, host, username, password} in memory only: never in a Persister, the
// sealed state, unlockd's cache, a record or a log. The gateway's IMAP connector leases it per call for that task
// (Request.Task); a lease for another task finds nothing. It is forgotten (zeroed) at the earliest of the task's
// end (RunCredEnd: agentd's Host.TaskEnded, a cancel or a delete), RunCredIdle without a mail call, the box's
// expiry, and a vaultd restart (memory only). After a restart the task's next mail call finds no login
// (ErrLoginNeeded): agentd asks the client for it again (need_credential).

// The per-task box's labels (the connections contract, v1).
const (
	RunCredLabel  = "tacy/v2/mail-credential"
	MailLoginType = "tacy.mail-login/v1"
	// RunCredMaxAhead is how far ahead a box's expiry may be; RunCredSkew the client's clock is allowed beyond it.
	RunCredMaxAhead = 2 * time.Hour
	RunCredSkew     = 5 * time.Minute
	// RunCredIdle: a login no mail call used for this long is forgotten.
	RunCredIdle = 15 * time.Minute
	maxRunCreds = 1024
)

// RunGrant is a task's sealed mail login as agentd passes it on (POST /tasks credentials, POST /tasks/credential):
// the task, its space, the identity that asked for it (the request's verified signer, guard.TaskOptions.Identity;
// review 2 L5), the connection, hex(SHA-256(the task's start key)) and the box's expiry (ms since the epoch, as the
// client sent it next to the box): all but the task are in the box's associated data.
type RunGrant struct {
	Task       string `json:"task"`
	Space      string `json:"space"`
	Identity   string `json:"identity,omitzero"`
	Connection string `json:"connection"`
	KeyHash    string `json:"key_hash"`
	Expires    int64  `json:"expires"`
	Sealed     Sealed `json:"sealed"`
}

type runCred struct {
	task     string
	info     ConnInfo
	password []byte
	expires  time.Time
	last     time.Time
	timer    *time.Timer
}

// RunCredAAD is a per-task box's associated data: label ‖ 0 ‖ space ‖ 0 ‖ connection ‖ 0 ‖ keyHash ‖ 0 ‖ expires ‖ 0 ‖
// identity (review 2, L5: a box made by one person's app opens only for a task that person's identity asked for, even
// in a shared space with the same start key; "" for a task no identity signed).
func RunCredAAD(space, identity, conn, keyHash string, expires int64) []byte {
	return []byte(RunCredLabel + "\x00" + space + "\x00" + conn + "\x00" + keyHash + "\x00" + strconv.FormatInt(expires, 10) + "\x00" + identity)
}

// KeyHash is hex(SHA-256(key)), a task start key as the box names it.
func KeyHash(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// SealRunCred seals a login's JSON to the vault key pub for one task no identity signed (tests and tools).
func SealRunCred(pub, space, conn, keyHash string, expires int64, plaintext []byte) (Sealed, error) {
	return SealRunCredFor(pub, space, "", conn, keyHash, expires, plaintext)
}

// SealRunCredFor seals a login's JSON to the vault key pub for one task of identity (the client's job; tests).
func SealRunCredFor(pub, space, identity, conn, keyHash string, expires int64, plaintext []byte) (Sealed, error) {
	hp, err := sealPub(pub)
	if err != nil {
		return Sealed{}, err
	}
	enc, sender, err := hpke.NewSender(hp, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(RunCredLabel))
	if err != nil {
		return Sealed{}, err
	}
	ct, err := sender.Seal(RunCredAAD(space, identity, conn, keyHash, expires), plaintext)
	return Sealed{Key: pub, Enc: enc, CT: ct}, err
}

func sealPub(pub string) (hpke.PublicKey, error) {
	raw, ok := strings.CutPrefix(pub, "x25519:")
	b, err := base64.StdEncoding.DecodeString(raw)
	if !ok || err != nil {
		return nil, errors.New("vault: bad seal key")
	}
	pk, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, err
	}
	return hpke.NewDHKEMPublicKey(pk)
}

func validKeyHash(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// RunCredPut opens a task's sealed login and holds it for that task (replacing one the task had). The box must be
// sealed to this boot's key (ErrStaleKey), bound to the task's space, connection, start key and expiry, and the
// expiry ahead and at most RunCredMaxAhead away (ErrBadSealed, the detail naming the rule).
func (v *Vault) RunCredPut(g RunGrant) (ConnInfo, error) {
	cs := v.connState()
	if cs == nil {
		return ConnInfo{}, ErrNoConn
	}
	if !validID(g.Task) || !safety.ValidID(g.Space) || g.Connection != ConnEmail || !validKeyHash(g.KeyHash) ||
		g.Identity != "" && (!strings.HasPrefix(g.Identity, "i_") || !safety.ValidID(g.Identity)) {
		return ConnInfo{}, ErrBadRequest
	}
	if g.Sealed.Key != cs.pub {
		v.recordRun("run_put", g.Space, g.Task, "stale_key")
		return ConnInfo{}, ErrStaleKey
	}
	now := v.now()
	exp := time.UnixMilli(g.Expires)
	switch {
	case !exp.After(now):
		v.recordRun("run_put", g.Space, g.Task, "expired")
		return ConnInfo{}, fmt.Errorf("%w: expired", ErrBadSealed)
	case exp.After(now.Add(RunCredMaxAhead + RunCredSkew)):
		v.recordRun("run_put", g.Space, g.Task, "expires")
		return ConnInfo{}, fmt.Errorf("%w: expires", ErrBadSealed)
	}
	pt, err := openRunCred(cs.key, g)
	if err != nil {
		v.recordRun("run_put", g.Space, g.Task, "bad_sealed")
		return ConnInfo{}, fmt.Errorf("%w: it didn't open", ErrBadSealed)
	}
	defer clear(pt)
	var b emailBox
	if err := json.Unmarshal(bytes.TrimRight(pt, " "), &b, json.RejectUnknownMembers(true)); err != nil {
		clear(b.Password)
		v.recordRun("run_put", g.Space, g.Task, "bad_sealed")
		return ConnInfo{}, fmt.Errorf("%w: not the login's JSON", ErrBadSealed)
	}
	b.Host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(b.Host), "."))
	if err := checkEmail(&b, MailLoginType); err != nil {
		clear(b.Password)
		v.recordRun("run_put", g.Space, g.Task, "bad_sealed")
		return ConnInfo{}, fmt.Errorf("%w: %s", ErrBadSealed, err.Error())
	}
	rc := &runCred{task: g.Task, info: ConnInfo{Space: g.Space, Connection: g.Connection, Kind: "email", Provider: b.Provider,
		Address: b.Address, Username: b.Username, Host: b.Host, Port: b.Port, Security: b.Security},
		password: b.Password, expires: earlier(exp, now.Add(RunCredMaxAhead)), last: now} // the decoded bytes: no copy
	b.Password = nil
	cs.mu.Lock()
	cs.sweep(now)
	if old := cs.runs[g.Task]; old != nil {
		cs.forget(old)
	} else if len(cs.runs) >= maxRunCreds {
		cs.mu.Unlock()
		clear(rc.password)
		v.recordRun("run_put", g.Space, g.Task, "full")
		return ConnInfo{}, ErrRateLimited
	}
	cs.runs[g.Task] = rc
	cs.arm(v, rc)
	info := rc.info
	cs.mu.Unlock()
	v.recordRun("run_put", g.Space, g.Task, "")
	return info, nil
}

func openRunCred(key *ecdh.PrivateKey, g RunGrant) ([]byte, error) {
	hk, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		return nil, err
	}
	rc, err := hpke.NewRecipient(g.Sealed.Enc, hk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(RunCredLabel))
	if err != nil {
		return nil, err
	}
	return rc.Open(RunCredAAD(g.Space, g.Identity, g.Connection, g.KeyHash, g.Expires), g.Sealed.CT)
}

// RunCredInfo is a task's login without its password (the connector's host, port, user name), ErrLoginNeeded when
// the task has none (or it was for another space).
func (v *Vault) RunCredInfo(task, space string) (ConnInfo, error) {
	cs := v.connState()
	if cs == nil {
		return ConnInfo{}, ErrNoConn
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	rc, err := cs.run(v.now(), task, space)
	if err != nil {
		return ConnInfo{}, err
	}
	return rc.info, nil
}

// RunCredEnd forgets a task's login (it ended, was cancelled or deleted). None is fine.
func (v *Vault) RunCredEnd(task string) {
	cs := v.connState()
	if cs == nil {
		return
	}
	cs.mu.Lock()
	rc := cs.runs[task]
	if rc != nil {
		cs.forget(rc)
	}
	cs.mu.Unlock()
	if rc != nil {
		v.recordRun("run_end", rc.info.Space, task, "")
	}
}

// RunCreds is how many task logins this process holds (a count only).
func (v *Vault) RunCreds() int {
	cs := v.connState()
	if cs == nil {
		return 0
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.sweep(v.now())
	return len(cs.runs)
}

// run is task's login for space, after forgetting the expired and idle ones (cs.mu held).
func (cs *connState) run(now time.Time, task, space string) (*runCred, error) {
	cs.sweep(now)
	rc := cs.runs[task]
	if rc == nil || !validID(task) {
		return nil, ErrLoginNeeded
	}
	if rc.info.Space != space {
		return nil, ErrNotSet
	}
	return rc, nil
}

// used marks a login used now (a lease): its idle time starts again (cs.mu held).
func (cs *connState) used(v *Vault, rc *runCred) {
	rc.last = v.now()
	cs.arm(v, rc)
}

// deadline is when rc is forgotten if nothing uses it.
func (rc *runCred) deadline() time.Time { return earlier(rc.expires, rc.last.Add(RunCredIdle)) }

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// arm sets rc's timer to its deadline (cs.mu held): the login is zeroed then even if no call comes.
func (cs *connState) arm(v *Vault, rc *runCred) {
	d := rc.deadline().Sub(v.now())
	if rc.timer != nil {
		rc.timer.Stop()
	}
	rc.timer = time.AfterFunc(max(d, 0)+time.Second, func() {
		cs.mu.Lock()
		cs.sweep(v.now())
		cs.mu.Unlock()
	})
}

// sweep forgets every login past its deadline (cs.mu held).
func (cs *connState) sweep(now time.Time) {
	for _, rc := range cs.runs {
		if !now.Before(rc.deadline()) {
			cs.forget(rc)
		}
	}
}

// forget zeroes rc's password and drops it (cs.mu held).
func (cs *connState) forget(rc *runCred) {
	clear(rc.password)
	rc.password = nil
	if rc.timer != nil {
		rc.timer.Stop()
	}
	if cs.runs[rc.task] == rc {
		delete(cs.runs, rc.task)
	}
}

func (v *Vault) recordRun(op, space, task, reason string) {
	if v.record == nil {
		return
	}
	if space != "" && !safety.ValidID(space) {
		space = ""
	}
	if !validID(task) {
		task = ""
	}
	v.record(Record{Time: v.now().UTC(), Secret: ConnSecret, Connector: MailConnector, Space: space, Task: task, Decision: op,
		Reason: reason})
}

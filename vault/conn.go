package vault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/sealstate"
)

// Connections (v0.19.0; v1: the v1 design §5): a person's own accounts, the first an email account read by IMAP
// with an app password. The browser seals the account (server, address, user name, password) to the vault's
// per-boot key; only this process opens it.
//
// v1: the vault keeps no account. The login lives only in the person's own apps, encrypted under their own key
// (the mail-login/v1 item), and comes sealed with each task that may read mail (runcred.go): held in this process's
// memory for that task only and forgotten when it ends. A box for Settings' test (ConnPut) is pending until the
// gateway's test login with it is done, then dropped (ConnDiscard): nothing is kept. The "connections" sealed state
// stays, and stays empty: what an older release kept there is wiped at the first load (EnableConns). The gateway's
// IMAP connector leases the password for one call at a time (Lease with Request.Conn), to the account's own host
// only, under the space's policy; every lease is recorded without the value.

// ConnInfo is a connection without its password: what Settings shows and what the connector needs to connect.
type ConnInfo struct {
	Space       string    `json:"space"`
	Connection  string    `json:"connection"`
	Kind        string    `json:"kind"`
	Provider    string    `json:"provider"`
	Address     string    `json:"address"`
	Username    string    `json:"username"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Security    string    `json:"security"`
	ConnectedAt time.Time `json:"connected_at,omitzero"`
}

// Sealed is a box the browser sealed to the vault's key.
type Sealed struct {
	Key string `json:"key"` // the vault key it was sealed to ("x25519:<base64>")
	Enc []byte `json:"enc"`
	CT  []byte `json:"ct"`
}

// The seal's labels (the connections contract).
const (
	ConnInfoLabel = "tacy/v2/connection"
	EmailType     = "tacy.connection.email/v1"
	// ConnEmail is the one connection id this release has.
	ConnEmail = "email"
	// ConnSecret is the name a connection's password is leased under (records).
	ConnSecret = "MAIL_PASSWORD"
	// MailConnector is the connector that may lease it.
	MailConnector = "mail"
	pendingTTL    = 3 * time.Minute
	maxPending    = 64
	// maxSpacePending bounds one space's pending test logins, so one account can't take every slot of the VM's.
	maxSpacePending = 4
)

// Errors of the connection ops (the gateway maps them to the person's words).
var (
	ErrStaleKey  = errors.New("vault: sealed to another boot's key")
	ErrBadSealed = errors.New("vault: the sealed connection didn't open or isn't valid")
	ErrNoConn    = errors.New("vault: no such connection")
	ErrConnStore = errors.New("vault: the connections file failed")
	// ErrLoginNeeded: no mail login for this task (none came with it, it was forgotten, or vaultd restarted): the
	// client sends it again (runcred.go).
	ErrLoginNeeded = errors.New("vault: no mail login for this task")
)

var connKnown = []error{ErrStaleKey, ErrBadSealed, ErrNoConn, ErrConnStore, ErrLoginNeeded}

type conn struct {
	info     ConnInfo
	password []byte
	expires  time.Time // pending only
}

type connState struct {
	mu      sync.Mutex
	key     *ecdh.PrivateKey
	pub     string
	pending map[string]*conn
	runs    map[string]*runCred // task -> its mail login (runcred.go): memory only
	persist Persister           // the "connections" sealed state, kept empty (nil: none)
	// wiped is how many accounts an older release had kept in the sealed state, dropped at load.
	wiped int
}

// EnableConns turns connections on: a fresh seal key for this boot. p is the "connections" sealed state (nil:
// none; never a file: SealedConns on the VM): v1 keeps nothing there, and an account an older release kept is
// dropped and the state saved empty, at once. A state that can't be read is an error (the vault doesn't start over
// it silently).
func (v *Vault) EnableConns(p Persister) error {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return v.EnableConnsKey(p, k)
}

// EnableConnsKey is EnableConns with a given seal key (the golden vectors' tests; vaultd always makes a fresh one).
func (v *Vault) EnableConnsKey(p Persister, k *ecdh.PrivateKey) error {
	cs := &connState{key: k, pub: "x25519:" + base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()),
		pending: map[string]*conn{}, runs: map[string]*runCred{}, persist: p}
	if p != nil {
		if err := cs.load(); err != nil {
			return err
		}
		if cs.wiped > 0 {
			if err := cs.saveEmpty(); err != nil {
				return err
			}
		}
	}
	v.mu.Lock()
	v.conns = cs
	v.mu.Unlock()
	if cs.wiped > 0 {
		v.recordConn("conn_wiped", "", "", strconv.Itoa(cs.wiped))
	}
	return nil
}

// Wiped is how many accounts an older release had kept, dropped when connections were enabled (a count only).
func (v *Vault) Wiped() int {
	cs := v.connState()
	if cs == nil {
		return 0
	}
	return cs.wiped
}

func (v *Vault) connState() *connState {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.conns
}

// SealKey is this boot's connection seal key ("" when connections are off).
func (v *Vault) SealKey() string {
	cs := v.connState()
	if cs == nil {
		return ""
	}
	return cs.pub
}

// emailBox is the sealed plaintext (strict): a test's (EmailType), or a task's login (MailLoginType, with the
// item's added_at).
type emailBox struct {
	Type     string     `json:"type"`
	Provider string     `json:"provider"`
	Host     string     `json:"host"`
	Port     int        `json:"port"`
	Security string     `json:"security"`
	Address  string     `json:"address"`
	Username string     `json:"username"`
	Password secretText `json:"password"`
	AddedAt  string     `json:"added_at,omitzero"`
}

// secretText is a JSON string decoded straight into bytes this package zeroes (review 2, L7): a Go string can't be
// cleared, and json would make one. The decoder reads it from the opened box, which its caller clears.
type secretText []byte

func (p *secretText) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	v, err := d.ReadValue()
	if err != nil {
		return err
	}
	if v.Kind() != '"' {
		return errors.New("vault: password isn't a string")
	}
	b, err := jsontext.AppendUnquote(nil, v)
	if err != nil {
		clear(b)
		return err
	}
	clear(*p)
	*p = b
	return nil
}

var providers = []string{"gmail", "icloud", "fastmail", "yahoo", "other"}

// checkEmail checks an opened box's fields (typ: the box's type); the error names a field, never a value.
func checkEmail(b *emailBox, typ string) error {
	switch {
	case b.Type != typ:
		return errors.New("type")
	case !slices.Contains(providers, b.Provider):
		return errors.New("provider")
	case !validHost(b.Host):
		return errors.New("host")
	case b.Security != "tls" && b.Security != "starttls":
		return errors.New("security")
	case !ValidMailPort(b.Port, b.Provider):
		return errors.New("port")
	case !validText(b.Address, 254) || !strings.Contains(b.Address, "@"):
		return errors.New("address")
	case !validText(b.Username, 254):
		return errors.New("username")
	case len(b.Password) == 0 || len(b.Password) > 256 || !utf8.Valid(b.Password) || bytes.ContainsAny(b.Password, "\r\n\x00"):
		return errors.New("password")
	}
	if _, err := netip.ParseAddr(b.Host); err == nil {
		return errors.New("host")
	}
	if b.AddedAt != "" && (typ != MailLoginType || len(b.AddedAt) > 40) {
		return errors.New("added_at")
	}
	return nil
}

// ValidMailPort: 993 or 143, or (for "other") any port from 1024; never the SMTP ports.
func ValidMailPort(port int, provider string) bool {
	switch {
	case port == 993 || port == 143:
		return true
	case port == 25 || port == 465 || port == 587:
		return false
	}
	return provider == "other" && port >= 1024 && port <= 65535
}

func validText(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ConnPut opens a sealed connection for space and holds it as pending, for Settings' test login only (until
// ConnDiscard, or pendingTTL; v1 never keeps it). It returns the pending id and the connection's info.
func (v *Vault) ConnPut(space, id string, s Sealed) (string, ConnInfo, error) {
	cs := v.connState()
	if cs == nil {
		return "", ConnInfo{}, ErrNoConn
	}
	if !safety.ValidID(space) || id != ConnEmail {
		return "", ConnInfo{}, ErrBadRequest
	}
	if s.Key != cs.pub {
		v.recordConn("conn_put", space, "", "stale_key")
		return "", ConnInfo{}, ErrStaleKey
	}
	pt, err := openConn(cs.key, space, id, s.Enc, s.CT)
	if err != nil {
		v.recordConn("conn_put", space, "", "bad_sealed")
		return "", ConnInfo{}, fmt.Errorf("%w: it didn't open", ErrBadSealed)
	}
	defer clear(pt)
	var b emailBox
	if err := json.Unmarshal(bytes.TrimRight(pt, " "), &b, json.RejectUnknownMembers(true)); err != nil {
		clear(b.Password)
		v.recordConn("conn_put", space, "", "bad_sealed")
		return "", ConnInfo{}, fmt.Errorf("%w: not the connection's JSON", ErrBadSealed)
	}
	b.Host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(b.Host), "."))
	if err := checkEmail(&b, EmailType); err != nil {
		clear(b.Password)
		v.recordConn("conn_put", space, "", "bad_sealed")
		return "", ConnInfo{}, fmt.Errorf("%w: %s", ErrBadSealed, err.Error())
	}
	c := &conn{info: ConnInfo{Space: space, Connection: id, Kind: "email", Provider: b.Provider, Address: b.Address,
		Username: b.Username, Host: b.Host, Port: b.Port, Security: b.Security},
		password: b.Password, expires: v.now().Add(pendingTTL)} // the decoded bytes themselves: no copy left behind
	b.Password = nil
	p := make([]byte, 12)
	rand.Read(p)
	pid := "p_" + hex.EncodeToString(p)
	cs.mu.Lock()
	now := v.now()
	for k, old := range cs.pending {
		if now.After(old.expires) {
			clear(old.password)
			delete(cs.pending, k)
		}
	}
	mine := 0
	for _, c := range cs.pending {
		if c.info.Space == space {
			mine++
		}
	}
	if len(cs.pending) >= maxPending || mine >= maxSpacePending {
		cs.mu.Unlock()
		clear(c.password)
		return "", ConnInfo{}, ErrRateLimited
	}
	cs.pending[pid] = c
	cs.mu.Unlock()
	v.recordConn("conn_put", space, pid, "")
	return pid, c.info, nil
}

// openConn opens a box with the seal key, bound to space and connection.
func openConn(key *ecdh.PrivateKey, space, id string, enc, ct []byte) ([]byte, error) {
	hk, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		return nil, err
	}
	rc, err := hpke.NewRecipient(enc, hk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(ConnInfoLabel))
	if err != nil {
		return nil, err
	}
	return rc.Open(ConnAAD(space, id), ct)
}

// ConnAAD is a box's associated data: label ‖ 0 ‖ space ‖ 0 ‖ connection.
func ConnAAD(space, id string) []byte {
	return []byte(ConnInfoLabel + "\x00" + space + "\x00" + id)
}

// SealConn seals a connection's JSON to the vault key pub (the browser's job; tests and tools).
func SealConn(pub, space, id string, plaintext []byte) (Sealed, error) {
	hp, err := sealPub(pub)
	if err != nil {
		return Sealed{}, err
	}
	enc, sender, err := hpke.NewSender(hp, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(ConnInfoLabel))
	if err != nil {
		return Sealed{}, err
	}
	ct, err := sender.Seal(ConnAAD(space, id), plaintext)
	return Sealed{Key: pub, Enc: enc, CT: ct}, err
}

// ConnDiscard drops a pending connection (its test login failed).
func (v *Vault) ConnDiscard(pending string) {
	cs := v.connState()
	if cs == nil {
		return
	}
	cs.mu.Lock()
	if c, ok := cs.pending[pending]; ok {
		clear(c.password)
		delete(cs.pending, pending)
	}
	cs.mu.Unlock()
	v.recordConn("conn_discard", "", pending, "")
}

// ConnList is a space's kept connections: none in v1 (the login stays with the person; runcred.go). Kept for
// Settings' list call, which also gives the seal key.
func (v *Vault) ConnList(space string) []ConnInfo { return nil }

// ConnRemove forgets a space's kept connection: v1 keeps none, so there is nothing to do (Settings' disconnect
// deletes the person's own item; an account's deletion its forget). Recorded.
func (v *Vault) ConnRemove(space, id string) error {
	v.recordConn("conn_remove", space, "", "none")
	return nil
}

func (v *Vault) recordConn(op, space, pending, reason string) {
	if v.record == nil {
		return
	}
	if space != "" && !safety.ValidID(space) {
		space = ""
	}
	v.record(Record{Time: v.now().UTC(), Secret: ConnSecret, Connector: MailConnector, Space: space, Decision: op,
		Reason: reason, Lease: pending})
}

// leaseConn is Lease for a connection's password (Request.Conn set): the task's own login (runcred.go: Request.Task
// names it; another task's is never released), or a pending one (Request.Pending: Settings' test login) of the same
// space; only to the mail connector, to the connection's own host, under the space's policy (the mail connector on,
// the host among its fetch patterns) and the lease rates.
func (v *Vault) leaseConn(r Request) ([]byte, string, error) {
	cs := v.connState()
	if cs == nil {
		return nil, "", ErrNotSet
	}
	if r.Secret != ConnSecret || r.Connector != MailConnector || !safety.ValidID(r.Space) || !validHost(r.Host) ||
		!validID(r.Task) || !validID(r.Action) || len(r.Docs) > 0 {
		if r.Connector != MailConnector && r.Connector != "" && validConnector(r.Connector) {
			return nil, "", ErrNoGrant
		}
		return nil, "", ErrBadRequest
	}
	cs.mu.Lock()
	var info ConnInfo
	var pw []byte
	if r.Pending != "" {
		c := cs.pending[r.Pending]
		if c != nil && v.now().After(c.expires) {
			c = nil
		}
		if c == nil || c.info.Space != r.Space || c.info.Connection != r.Conn {
			cs.mu.Unlock()
			return nil, "", ErrNotSet
		}
		info, pw = c.info, c.password
	} else {
		rc, err := cs.run(v.now(), r.Task, r.Space)
		if err != nil {
			cs.mu.Unlock()
			return nil, "", err
		}
		if rc.info.Connection != r.Conn {
			cs.mu.Unlock()
			return nil, "", ErrNotSet
		}
		if rc.info.Host == r.Host {
			cs.used(v, rc)
		}
		info, pw = rc.info, rc.password
	}
	if info.Host != r.Host {
		cs.mu.Unlock()
		return nil, "", ErrHost
	}
	val := slices.Clone(pw)
	cs.mu.Unlock()
	v.mu.Lock()
	err := v.checkConnSafety(r)
	v.mu.Unlock()
	if err != nil {
		clear(val)
		return nil, "", err
	}
	return val, newLease(), nil
}

// checkConnSafety is checkSafety for a connection's lease: the policy must have the mail connector and allow the
// connection's host among its fetch patterns (a person's own server, not a host fixed in the release).
func (v *Vault) checkConnSafety(r Request) error {
	if v.safety == nil {
		return nil
	}
	e, err := v.safety.Check(r.Space, r.Effect)
	switch safety.CodeOf(err) {
	case "":
	case safety.CodeStopped:
		return ErrStopped
	case safety.CodeStale:
		return ErrStale
	default:
		return ErrPolicyMissing
	}
	if !e.AllowsConnector(r.Connector) || !e.AllowsConnectorFetch(r.Connector, r.Host) {
		return ErrPolicy
	}
	rt := e.Rates()
	if v.rates.Now == nil {
		v.rates.Now = v.now
	}
	if v.rates.Allow([]string{"key:" + r.Secret + ":" + r.Space, "connector:" + r.Connector, "space:" + r.Space},
		[]safety.Rate{rt.Key, rt.Connector, rt.Space}) != "" {
		return ErrRateLimited
	}
	return nil
}

// The state's document: JSON, the accounts an older release kept (v0.19.0 to v0.21.x). v1 writes it with none.
type connFile struct {
	Version     int         `json:"version"`
	Connections []connEntry `json:"connections"`
}

type connEntry struct {
	ConnInfo
	Password []byte `json:"password"`
}

// load reads the state and counts the accounts in it (wiped); nothing of them is kept, and their bytes are cleared.
func (cs *connState) load() error {
	b, err := cs.persist.Load()
	if err != nil {
		return fmt.Errorf("vault: connections: %w", err)
	}
	if len(b) == 0 {
		return nil
	}
	defer clear(b)
	var f connFile
	if err := json.Unmarshal(b, &f); err != nil || f.Version != 1 {
		return errors.New("vault: connections unreadable")
	}
	for _, e := range f.Connections {
		clear(e.Password)
	}
	cs.wiped = len(f.Connections)
	return nil
}

// saveEmpty writes the state with no account (to the Persister: sealed under the key service's conn/v1 key and
// stored outside the VM, SealedConns).
func (cs *connState) saveEmpty() error {
	b, err := json.Marshal(connFile{Version: 1, Connections: []connEntry{}})
	if err != nil {
		return err
	}
	return cs.persist.Save(b)
}

// SealedConns is the connections' Persister on the VM (the keys plan Stage D): the "connections" state of a sealstate
// Store under connKey (the key service's conn/v1 purpose, never a provider's), loaded now, and the Keeper that saves
// it (run it; flush on SIGTERM). v1 keeps it empty (EnableConns wipes an older release's accounts). A state there
// that doesn't open is an error: the vault doesn't start over it silently.
func SealedConns(ctx context.Context, b sealstate.Backend, connKey []byte, binding string, reg sealstate.Register) (Persister, *sealstate.Keeper, error) {
	st, err := sealstate.New(b, connKey, binding)
	if err != nil {
		return nil, nil, err
	}
	if reg != nil { // the key service's generation register: no older set of accounts opens
		st.WithRegister(reg)
	}
	loaded, err := st.Load(ctx, ConnState)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: connections: %w", err)
	}
	slot := sealstate.NewSlot(loaded)
	clear(loaded)
	k := &sealstate.Keeper{Store: st}
	if err := k.Add(ConnState, slot); err != nil {
		return nil, nil, err
	}
	return slot, k, nil
}

// ConnState is the connections' sealed state name.
const ConnState = "connections"

// Persister is the connections' sealed state (sealstate.Slot); nil: none.
type Persister = safety.Persister

package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/tacyhq/tacy/safety"
)

// Connections (CONNECTIONS.md, docs/34 step 4): a person's own accounts, the first an email account read by IMAP
// with an app password. The browser seals the account (server, address, user name, password) to the vault's
// per-boot key; only this process opens it. A new account is pending until the gateway's test login with it works
// (Commit), then it is kept in memory and in a file on the vault's own volume of the encrypted disk, so scheduled
// runs can read mail after the VM restarts. The gateway's IMAP connector leases the password for one call at a
// time (Lease with Request.Conn), to the account's own host only, under the space's policy; every lease is recorded
// without the value.

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

// The seal's labels (CONNECTIONS.md).
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
	maxConns      = 10000
)

// Errors of the connection ops (the gateway maps them to the person's words).
var (
	ErrStaleKey  = errors.New("vault: sealed to another boot's key")
	ErrBadSealed = errors.New("vault: the sealed connection didn't open or isn't valid")
	ErrNoConn    = errors.New("vault: no such connection")
	ErrConnStore = errors.New("vault: the connections file failed")
)

var connKnown = []error{ErrStaleKey, ErrBadSealed, ErrNoConn, ErrConnStore}

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
	conns   map[string]*conn // space\x00connection
	path    string           // "": memory only
}

func connKey(space, id string) string { return space + "\x00" + id }

// EnableConns turns connections on: a fresh seal key for this boot, and the accounts kept in path ("": memory only;
// a missing file is an empty store). A file that can't be read is an error: the vault doesn't start with someone's
// accounts silently dropped.
func (v *Vault) EnableConns(path string) error {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return v.EnableConnsKey(path, k)
}

// EnableConnsKey is EnableConns with a given seal key (the golden vectors' tests; vaultd always makes a fresh one).
func (v *Vault) EnableConnsKey(path string, k *ecdh.PrivateKey) error {
	cs := &connState{key: k, pub: "x25519:" + base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()),
		pending: map[string]*conn{}, conns: map[string]*conn{}, path: path}
	if path != "" {
		if err := cs.load(); err != nil {
			return err
		}
	}
	v.mu.Lock()
	v.conns = cs
	v.mu.Unlock()
	return nil
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

// emailBox is the sealed plaintext (strict).
type emailBox struct {
	Type     string `json:"type"`
	Provider string `json:"provider"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"`
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var providers = []string{"gmail", "icloud", "fastmail", "yahoo", "other"}

// checkEmail checks an opened box's fields; the error names a field, never a value.
func checkEmail(b *emailBox) error {
	switch {
	case b.Type != EmailType:
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
	case b.Password == "" || len(b.Password) > 256 || !utf8.ValidString(b.Password) || strings.ContainsAny(b.Password, "\r\n\x00"):
		return errors.New("password")
	}
	if _, err := netip.ParseAddr(b.Host); err == nil {
		return errors.New("host")
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

// ConnPut opens a sealed connection for space and holds it as pending (until Commit, Discard, or pendingTTL). It
// returns the pending id and the connection's info.
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
		v.recordConn("conn_put", space, "", "bad_sealed")
		return "", ConnInfo{}, fmt.Errorf("%w: not the connection's JSON", ErrBadSealed)
	}
	b.Host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(b.Host), "."))
	if err := checkEmail(&b); err != nil {
		v.recordConn("conn_put", space, "", "bad_sealed")
		return "", ConnInfo{}, fmt.Errorf("%w: %s", ErrBadSealed, err.Error())
	}
	c := &conn{info: ConnInfo{Space: space, Connection: id, Kind: "email", Provider: b.Provider, Address: b.Address,
		Username: b.Username, Host: b.Host, Port: b.Port, Security: b.Security},
		password: []byte(b.Password), expires: v.now().Add(pendingTTL)}
	b.Password = ""
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
	if len(cs.pending) >= maxPending {
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
	raw, ok := strings.CutPrefix(pub, "x25519:")
	b, err := base64.StdEncoding.DecodeString(raw)
	if !ok || err != nil {
		return Sealed{}, errors.New("vault: bad seal key")
	}
	pk, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return Sealed{}, err
	}
	hp, err := hpke.NewDHKEMPublicKey(pk)
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

// ConnCommit keeps a pending connection (its test login worked): it replaces the space's earlier one and is
// written to the file.
func (v *Vault) ConnCommit(pending string) (ConnInfo, error) {
	cs := v.connState()
	if cs == nil {
		return ConnInfo{}, ErrNoConn
	}
	cs.mu.Lock()
	c, ok := cs.pending[pending]
	if !ok || v.now().After(c.expires) {
		cs.mu.Unlock()
		return ConnInfo{}, ErrNoConn
	}
	delete(cs.pending, pending)
	c.expires = time.Time{}
	c.info.ConnectedAt = v.now().UTC().Truncate(time.Second)
	k := connKey(c.info.Space, c.info.Connection)
	old := cs.conns[k]
	if old == nil && len(cs.conns) >= maxConns {
		cs.mu.Unlock()
		clear(c.password)
		return ConnInfo{}, ErrConnStore
	}
	cs.conns[k] = c
	err := cs.save()
	if err != nil {
		if old != nil {
			cs.conns[k] = old
		} else {
			delete(cs.conns, k)
		}
		cs.mu.Unlock()
		clear(c.password)
		v.recordConn("conn_commit", c.info.Space, pending, "store")
		return ConnInfo{}, ErrConnStore
	}
	if old != nil {
		clear(old.password)
	}
	info := c.info
	cs.mu.Unlock()
	v.recordConn("conn_commit", info.Space, pending, "")
	return info, nil
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

// ConnGet is a space's connection's info (no password).
func (v *Vault) ConnGet(space, id string) (ConnInfo, error) {
	cs := v.connState()
	if cs == nil {
		return ConnInfo{}, ErrNoConn
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c, ok := cs.conns[connKey(space, id)]
	if !ok {
		return ConnInfo{}, ErrNoConn
	}
	return c.info, nil
}

// ConnList is a space's connections (no passwords).
func (v *Vault) ConnList(space string) []ConnInfo {
	cs := v.connState()
	if cs == nil {
		return nil
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	var out []ConnInfo
	for _, c := range cs.conns {
		if c.info.Space == space {
			out = append(out, c.info)
		}
	}
	slices.SortFunc(out, func(a, b ConnInfo) int { return strings.Compare(a.Connection, b.Connection) })
	return out
}

// ConnRemove forgets a space's connection, in memory and in the file. Removing one that isn't there is fine.
func (v *Vault) ConnRemove(space, id string) error {
	cs := v.connState()
	if cs == nil {
		return nil
	}
	cs.mu.Lock()
	k := connKey(space, id)
	c, ok := cs.conns[k]
	if !ok {
		cs.mu.Unlock()
		v.recordConn("conn_remove", space, "", "none")
		return nil
	}
	delete(cs.conns, k)
	if err := cs.save(); err != nil {
		cs.conns[k] = c
		cs.mu.Unlock()
		v.recordConn("conn_remove", space, "", "store")
		return ErrConnStore
	}
	clear(c.password)
	cs.mu.Unlock()
	v.recordConn("conn_remove", space, "", "")
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

// leaseConn is Lease for a connection's password (Request.Conn set): the space's kept connection, or a pending one
// (Request.Pending: the test login) of the same space; only to the mail connector, to the connection's own host,
// under the space's policy (the mail connector on, the host among its fetch patterns) and the lease rates.
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
	var c *conn
	if r.Pending != "" {
		c = cs.pending[r.Pending]
		if c != nil && v.now().After(c.expires) {
			c = nil
		}
	} else {
		c = cs.conns[connKey(r.Space, r.Conn)]
	}
	if c == nil || c.info.Space != r.Space || c.info.Connection != r.Conn {
		cs.mu.Unlock()
		return nil, "", ErrNotSet
	}
	if c.info.Host != r.Host {
		cs.mu.Unlock()
		return nil, "", ErrHost
	}
	val := slices.Clone(c.password)
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

// The file: JSON, 0600, written whole to a temporary file and renamed.
type connFile struct {
	Version     int         `json:"version"`
	Connections []connEntry `json:"connections"`
}

type connEntry struct {
	ConnInfo
	Password []byte `json:"password"`
}

func (cs *connState) load() error {
	b, err := os.ReadFile(cs.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("vault: connections file: %w", err)
	}
	defer clear(b)
	var f connFile
	if err := json.Unmarshal(b, &f); err != nil || f.Version != 1 {
		return errors.New("vault: connections file unreadable")
	}
	for _, e := range f.Connections {
		if !safety.ValidID(e.Space) || e.Connection != ConnEmail || !validHost(e.Host) || len(e.Password) == 0 {
			continue
		}
		cs.conns[connKey(e.Space, e.Connection)] = &conn{info: e.ConnInfo, password: e.Password}
	}
	return nil
}

// save writes every kept connection (cs.mu held).
func (cs *connState) save() error {
	if cs.path == "" {
		return nil
	}
	f := connFile{Version: 1, Connections: []connEntry{}}
	keys := make([]string, 0, len(cs.conns))
	for k := range cs.conns {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		c := cs.conns[k]
		f.Connections = append(f.Connections, connEntry{ConnInfo: c.info, Password: c.password})
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	defer clear(b)
	tmp, err := os.CreateTemp(filepath.Dir(cs.path), ".connections-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, cs.path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(filepath.Dir(cs.path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

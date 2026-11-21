package vault

import (
	"context"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tacyhq/tacy/keylog"
	"github.com/tacyhq/tacy/safety"
)

// The wire: harness/v1's framing (a 4-byte big-endian length, then one JSON object), one request and one reply
// per frame, any number per connection. Decoding is strict: unknown members, a bad length or trailing data close
// the connection.

// maxFrame: a lease is small; a safety push carries up to 8 signed documents and the firm key log.
const maxFrame = 16<<10 + 8*2*safety.MaxEnvelope + keylog.MaxEntries*keylog.MaxEntryWire

type reply struct {
	Value []byte   `json:"value,omitzero"` // base64 in JSON
	Lease string   `json:"lease,omitzero"`
	Names []string `json:"names,omitzero"` // a names request's answer
	Error string   `json:"error,omitzero"`
	// Connections (conn.go): the seal key, a pending id, one connection's info or a space's list, and an error's
	// detail (which field of a sealed box was wrong; never a value).
	Key     string     `json:"key,omitzero"`
	Pending string     `json:"pending,omitzero"`
	Info    *ConnInfo  `json:"info,omitzero"`
	Infos   []ConnInfo `json:"infos,omitzero"`
	Detail  string     `json:"detail,omitzero"`
	// Pushed secrets (secrets.go): the names taken and the run token's hash.
	Secrets *SecretsResult `json:"secrets,omitzero"`
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	defer clear(b) // a lease's frame holds the secret (base64): zeroed, as the copy below is (review 2, L7)
	if len(b) > maxFrame {
		return errors.New("vault: frame too large")
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err = w.Write(buf)
	clear(buf)
	return err
}

func readFrame(r io.Reader, v any) error {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > maxFrame {
		return fmt.Errorf("vault: frame length %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	defer clear(b)
	return json.Unmarshal(b, v, json.RejectUnknownMembers(true))
}

// Listen makes the vault's socket: its directory is created 0700 if missing, a stale socket is removed, and the
// socket is 0600, so only the gateway's user (the directory's owner, or a shared volume mounted only into the
// gateway's container) can connect. On Linux, Serve also checks the peer's uid.
func Listen(path string) (net.Listener, error) { return ListenMode(path, 0o600) }

// ListenMode is Listen with the socket's mode: 0660 when the gateway connects through the socket's group (the
// CVM: the vault runs with the gateway's group as its primary group, its own uid, and the peer uid check).
func ListenMode(path string, mode os.FileMode) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Serve answers lease requests on l until it is closed. peerUID is the only uid allowed to connect (checked on
// Linux; -1 skips the check, for tests and macOS).
func (v *Vault) Serve(l net.Listener, peerUID int) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go v.serveConn(c, peerUID)
	}
}

func (v *Vault) serveConn(c net.Conn, peerUID int) {
	defer c.Close()
	if peerUID >= 0 {
		if err := checkPeer(c, peerUID); err != nil {
			return // not the gateway: nothing is read, nothing released
		}
	}
	for {
		c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		var r Request
		if err := readFrame(c, &r); err != nil {
			return
		}
		var val []byte
		var rep reply
		switch r.Op {
		case "":
			var lease string
			var err error
			val, lease, err = v.Lease(r)
			rep = reply{Value: val, Lease: lease}
			if err != nil {
				rep = reply{Error: err.Error()}
			}
		case "names":
			rep = reply{Names: v.Names()}
		case "safety":
			// Signed documents the gateway passes on: each is verified here, against this process's pinned keys.
			if st := v.Safety(); st == nil {
				rep = reply{Error: "vault: no safety controls"}
			} else {
				errs, changed := st.ApplyOrdered(r.Docs)
				if err := errors.Join(errs...); err != nil {
					rep = reply{Error: "vault: " + err.Error()}
				}
				if changed && v.record != nil {
					s := st.StatusOf("")
					v.record(Record{Time: v.now().UTC(), Decision: "controls", Reason: fmt.Sprintf("policy %v, operator seq %d, firm seq %d",
						s.Policy, s.OperatorSeq, s.FirmSeq)})
				}
			}
		case "secrets_status":
			rep = v.secretsOp(r)
		case "conn_key", "conn_put", "conn_discard", "conn_list", "conn_remove":
			rep = v.connOp(r)
		case "run_put", "run_info", "run_end":
			rep = v.runOp(r)
		default:
			return // unknown op: closed, like any malformed frame
		}
		c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		err := writeFrame(c, rep)
		clear(val)
		if err != nil {
			return
		}
	}
}

// connOpFail is a refused connection op's reply: the vault error's text and its detail (never a value).
func (v *Vault) connOpFail(err error) reply {
	rep := reply{Error: err.Error()}
	for _, k := range append(connKnown, known...) {
		if errors.Is(err, k) {
			rep.Error = k.Error()
			if d, ok := strings.CutPrefix(err.Error(), k.Error()+": "); ok {
				rep.Detail = d
			}
			break
		}
	}
	return rep
}

// connOp answers a connection op (conn.go). A request carries only the fields its op needs.
func (v *Vault) connOp(r Request) reply {
	fail := v.connOpFail
	extra := r.Secret != "" || r.Connector != "" || r.Host != "" || r.Task != "" || r.Action != "" || r.Effect || len(r.Docs) > 0 ||
		r.Run != nil
	if extra {
		return reply{Error: ErrBadRequest.Error()}
	}
	switch r.Op {
	case "conn_key":
		if k := v.SealKey(); k != "" {
			return reply{Key: k}
		}
		return reply{Error: ErrNoConn.Error()}
	case "conn_put":
		if r.Sealed == nil {
			return reply{Error: ErrBadRequest.Error()}
		}
		pid, info, err := v.ConnPut(r.Space, r.Conn, *r.Sealed)
		if err != nil {
			return fail(err)
		}
		return reply{Pending: pid, Info: &info}
	case "conn_discard":
		v.ConnDiscard(r.Pending)
		return reply{}
	case "conn_list":
		return reply{Infos: v.ConnList(r.Space), Key: v.SealKey()}
	case "conn_remove":
		if err := v.ConnRemove(r.Space, r.Conn); err != nil {
			return fail(err)
		}
		return reply{}
	}
	return reply{Error: ErrBadRequest.Error()}
}

// runOp answers a per-task login op (runcred.go). A request carries only the fields its op needs.
func (v *Vault) runOp(r Request) reply {
	fail := func(err error) reply { return v.connOpFail(err) }
	if r.Secret != "" || r.Connector != "" || r.Host != "" || r.Action != "" || r.Effect || len(r.Docs) > 0 || r.Conn != "" ||
		r.Pending != "" || r.Sealed != nil {
		return reply{Error: ErrBadRequest.Error()}
	}
	switch r.Op {
	case "run_put":
		if r.Run == nil || r.Task != "" || r.Space != "" {
			return reply{Error: ErrBadRequest.Error()}
		}
		info, err := v.RunCredPut(*r.Run)
		if err != nil {
			return fail(err)
		}
		return reply{Info: &info}
	case "run_info":
		if r.Run != nil {
			return reply{Error: ErrBadRequest.Error()}
		}
		info, err := v.RunCredInfo(r.Task, r.Space)
		if err != nil {
			return fail(err)
		}
		return reply{Info: &info}
	case "run_end":
		if r.Run != nil || r.Space != "" {
			return reply{Error: ErrBadRequest.Error()}
		}
		v.RunCredEnd(r.Task)
		return reply{}
	}
	return reply{Error: ErrBadRequest.Error()}
}

// secretsOp answers a secrets op (secrets.go): the status only (the names held). The secrets themselves come from
// the key service's release in vaultd's own process, never over a socket.
func (v *Vault) secretsOp(r Request) reply {
	if r.Secret != "" || r.Connector != "" || r.Host != "" || r.Task != "" || r.Action != "" || r.Effect || len(r.Docs) > 0 ||
		r.Space != "" || r.Conn != "" || r.Pending != "" || r.Sealed != nil || r.Run != nil || r.Op != "secrets_status" {
		return reply{Error: ErrBadRequest.Error()}
	}
	st := v.SecretsStatus()
	return reply{Secrets: &st}
}

// SecretsCall is a secrets op through the gateway: "status".
type SecretsCall struct {
	Op string `json:"op"`
}

// SecretsAnswer is its answer (Error: "bad request" or "unavailable").
type SecretsAnswer struct {
	Secrets *SecretsResult `json:"secrets,omitzero"`
	Error   string         `json:"error,omitzero"`
}

// Secrets passes a secrets op to the vault.
func (c *Client) Secrets(ctx context.Context, call *SecretsCall) *SecretsAnswer {
	if call.Op != "status" {
		return &SecretsAnswer{Error: ErrBadRequest.Error()}
	}
	var rep reply
	if err := c.do(ctx, Request{Op: "secrets_status"}, &rep); err != nil {
		return &SecretsAnswer{Error: "unavailable"}
	}
	if rep.Error != "" {
		if rep.Error == ErrBadRequest.Error() {
			return &SecretsAnswer{Error: rep.Error}
		}
		return &SecretsAnswer{Error: "unavailable"}
	}
	return &SecretsAnswer{Secrets: rep.Secrets}
}

// ConnError is a connection op's refusal over the wire: one of the vault's errors (errors.Is works) and its detail.
type ConnError struct {
	Err    error
	Detail string
}

func (e *ConnError) Error() string {
	if e.Detail != "" {
		return e.Err.Error() + ": " + e.Detail
	}
	return e.Err.Error()
}
func (e *ConnError) Unwrap() error { return e.Err }

func (c *Client) conn(ctx context.Context, r Request) (*reply, error) {
	var rep reply
	if err := c.do(ctx, r, &rep); err != nil {
		return nil, err
	}
	if rep.Error != "" {
		for _, k := range known {
			if rep.Error == k.Error() {
				return nil, &ConnError{Err: k, Detail: rep.Detail}
			}
		}
		return nil, errors.New("vault: refused")
	}
	return &rep, nil
}

// SealKey is the vault's connection seal key for this boot.
func (c *Client) SealKey(ctx context.Context) (string, error) {
	rep, err := c.conn(ctx, Request{Op: "conn_key"})
	if err != nil {
		return "", err
	}
	return rep.Key, nil
}

// ConnPut has the vault open a sealed connection and hold it pending.
func (c *Client) ConnPut(ctx context.Context, space, id string, s Sealed) (string, ConnInfo, error) {
	rep, err := c.conn(ctx, Request{Op: "conn_put", Space: space, Conn: id, Sealed: &s})
	if err != nil {
		return "", ConnInfo{}, err
	}
	if rep.Info == nil || rep.Pending == "" {
		return "", ConnInfo{}, errors.New("vault: empty reply")
	}
	return rep.Pending, *rep.Info, nil
}

// ConnDiscard drops a pending connection.
func (c *Client) ConnDiscard(ctx context.Context, pending string) error {
	_, err := c.conn(ctx, Request{Op: "conn_discard", Pending: pending})
	return err
}

// RunPut has the vault open a task's sealed mail login and hold it for that task.
func (c *Client) RunPut(ctx context.Context, g RunGrant) (ConnInfo, error) {
	rep, err := c.conn(ctx, Request{Op: "run_put", Run: &g})
	if err != nil {
		return ConnInfo{}, err
	}
	if rep.Info == nil {
		return ConnInfo{}, errors.New("vault: empty reply")
	}
	return *rep.Info, nil
}

// RunInfo is a task's mail login without its password (ErrLoginNeeded: none).
func (c *Client) RunInfo(ctx context.Context, task, space string) (ConnInfo, error) {
	rep, err := c.conn(ctx, Request{Op: "run_info", Task: task, Space: space})
	if err != nil {
		return ConnInfo{}, err
	}
	if rep.Info == nil {
		return ConnInfo{}, errors.New("vault: empty reply")
	}
	return *rep.Info, nil
}

// RunEnd forgets a task's mail login.
func (c *Client) RunEnd(ctx context.Context, task string) error {
	_, err := c.conn(ctx, Request{Op: "run_end", Task: task})
	return err
}

// ConnList is a space's connections and the seal key.
func (c *Client) ConnList(ctx context.Context, space string) ([]ConnInfo, string, error) {
	rep, err := c.conn(ctx, Request{Op: "conn_list", Space: space})
	if err != nil {
		return nil, "", err
	}
	return rep.Infos, rep.Key, nil
}

// ConnRemove forgets a space's connection.
func (c *Client) ConnRemove(ctx context.Context, space, id string) error {
	_, err := c.conn(ctx, Request{Op: "conn_remove", Space: space, Conn: id})
	return err
}

// Client is the gateway's side: one short connection per lease, so a gateway restart or a vault restart needs
// no reconnect logic.
type Client struct {
	Path string
}

// Names asks which granted secrets are set (names only).
func (c *Client) Names(ctx context.Context) ([]string, error) {
	var rep reply
	if err := c.do(ctx, Request{Op: "names"}, &rep); err != nil {
		return nil, err
	}
	if rep.Error != "" {
		return nil, errors.New("vault: refused")
	}
	return rep.Names, nil
}

func (c *Client) do(ctx context.Context, r Request, rep *reply) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if err := writeFrame(conn, r); err != nil {
		return err
	}
	return readFrame(conn, rep)
}

// Push passes signed policies and stop lists to the vault, which checks each itself. The error lists the ones it
// refused (older, forged, for another firm); the others are taken.
func (c *Client) Push(ctx context.Context, docs []safety.Envelope) error {
	var rep reply
	if err := c.do(ctx, Request{Op: "safety", Docs: docs}, &rep); err != nil {
		return err
	}
	if rep.Error != "" {
		return errors.New(rep.Error)
	}
	return nil
}

// Lease asks the vault for one secret for one action. The error names the rule that refused it.
func (c *Client) Lease(ctx context.Context, r Request) (*Secret, error) {
	r.Op = ""
	var rep reply
	if err := c.do(ctx, r, &rep); err != nil {
		return nil, err
	}
	if rep.Error != "" {
		for _, k := range known {
			if rep.Error == k.Error() {
				return nil, k
			}
		}
		return nil, errors.New("vault: refused")
	}
	if len(rep.Value) == 0 || rep.Lease == "" {
		return nil, errors.New("vault: empty reply")
	}
	return &Secret{v: rep.Value, Lease: rep.Lease}, nil
}

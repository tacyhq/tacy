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
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
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
		case "conn_key", "conn_put", "conn_commit", "conn_discard", "conn_get", "conn_list", "conn_remove":
			rep = v.connOp(r)
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

// connOp answers a connection op (conn.go). A request carries only the fields its op needs.
func (v *Vault) connOp(r Request) reply {
	fail := func(err error) reply {
		rep := reply{Error: err.Error()}
		for _, k := range connKnown {
			if errors.Is(err, k) {
				rep.Error = k.Error()
				if d, ok := strings.CutPrefix(err.Error(), k.Error()+": "); ok {
					rep.Detail = d
				}
			}
		}
		return rep
	}
	extra := r.Secret != "" || r.Connector != "" || r.Host != "" || r.Task != "" || r.Action != "" || r.Effect || len(r.Docs) > 0
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
	case "conn_commit":
		info, err := v.ConnCommit(r.Pending)
		if err != nil {
			return fail(err)
		}
		return reply{Info: &info}
	case "conn_discard":
		v.ConnDiscard(r.Pending)
		return reply{}
	case "conn_get":
		info, err := v.ConnGet(r.Space, r.Conn)
		if err != nil {
			return fail(err)
		}
		return reply{Info: &info}
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

// ConnCommit keeps a pending connection.
func (c *Client) ConnCommit(ctx context.Context, pending string) (ConnInfo, error) {
	rep, err := c.conn(ctx, Request{Op: "conn_commit", Pending: pending})
	if err != nil {
		return ConnInfo{}, err
	}
	if rep.Info == nil {
		return ConnInfo{}, errors.New("vault: empty reply")
	}
	return *rep.Info, nil
}

// ConnDiscard drops a pending connection.
func (c *Client) ConnDiscard(ctx context.Context, pending string) error {
	_, err := c.conn(ctx, Request{Op: "conn_discard", Pending: pending})
	return err
}

// ConnGet is a space's connection's info.
func (c *Client) ConnGet(ctx context.Context, space, id string) (ConnInfo, error) {
	rep, err := c.conn(ctx, Request{Op: "conn_get", Space: space, Conn: id})
	if err != nil {
		return ConnInfo{}, err
	}
	if rep.Info == nil {
		return ConnInfo{}, errors.New("vault: empty reply")
	}
	return *rep.Info, nil
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

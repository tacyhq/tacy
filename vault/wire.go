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
	"time"
)

// The wire: harness/v1's framing (a 4-byte big-endian length, then one JSON object), one request and one reply
// per frame, any number per connection. Decoding is strict: unknown members, a bad length or trailing data close
// the connection.

const maxFrame = 16 << 10

type reply struct {
	Value []byte   `json:"value,omitzero"` // base64 in JSON
	Lease string   `json:"lease,omitzero"`
	Names []string `json:"names,omitzero"` // a names request's answer
	Error string   `json:"error,omitzero"`
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

// Lease asks the vault for one secret for one action. The error names the rule that refused it.
func (c *Client) Lease(ctx context.Context, r Request) (*Secret, error) {
	r.Op = ""
	var rep reply
	if err := c.do(ctx, r, &rep); err != nil {
		return nil, err
	}
	if rep.Error != "" {
		for _, known := range []error{ErrNoGrant, ErrHost, ErrNotSet, ErrBadRequest} {
			if rep.Error == known.Error() {
				return nil, known
			}
		}
		return nil, errors.New("vault: refused")
	}
	if len(rep.Value) == 0 || rep.Lease == "" {
		return nil, errors.New("vault: empty reply")
	}
	return &Secret{v: rep.Value, Lease: rep.Lease}, nil
}

package unlock

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kmsvm"
	"github.com/tacyhq/tacy/proto"
)

// The sockets (unlock/v0 between unlockd and its two peers): one connection, one JSON request line, one JSON reply.
//
//	{"version":"unlock/v0","op":"keys"}                          -> Reply{state, keys}   (agentd's, vaultd's)
//	{"version":"unlock/v0","op":"status"}                        -> Reply{state, reason, message}
//	{"version":"unlock/v0","op":"attest","nonce":hex,"key":hex}  -> Reply{quote, info}  (agentd's socket only)
//
// Each socket serves one role, its peer's uid checked by the kernel (SO_PEERCRED). "attest" makes a quote whose
// report_data is proto.AgentReportData(nonce, key): agentd's /attest, never an unlock's.

// Version names the socket protocol.
const Version = "unlock/v0"

// Request is one call.
type Request struct {
	Version string `json:"version"`
	Op      string `json:"op"`
	Nonce   string `json:"nonce,omitempty"` // attest: 32 bytes, hex
	Key     string `json:"key,omitempty"`   // attest: the HPKE key, 32 bytes, hex
}

// Reply is its answer.
type Reply struct {
	Version string          `json:"version"`
	State   string          `json:"state"`
	Reason  string          `json:"reason,omitempty"`
	Message string          `json:"message,omitempty"`
	Keys    *Keys           `json:"keys,omitempty"`
	Quote   json.RawMessage `json:"quote,omitempty"`
	Info    json.RawMessage `json:"info,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// Keys is one process's share of the keyring.
type Keys struct {
	KMSID   string                   `json:"kms_id"`
	Epoch   uint32                   `json:"epoch"`
	App     string                   `json:"app"`
	Firm    string                   `json:"firm"`
	Release string                   `json:"release"`
	Keys    map[string][]byte        `json:"keys"`
	Certs   map[string]kms.StoreCert `json:"certs,omitempty"`
	Secrets map[string]string        `json:"secrets,omitempty"`
	// Floors: this process's sealed state names and the lowest generation of each it may open (none set yet: Keyring.Floors).
	Floors map[string]uint64 `json:"floors,omitempty"`
	// EpochCert (agentd only): the unlock's epoch certificate, for its unlock proof (Keyring.EpochCert).
	EpochCert json.RawMessage `json:"epoch_cert,omitempty"`
}

// Key is a copy of purpose's key.
func (k *Keys) Key(_ context.Context, purpose string) ([]byte, error) {
	b, ok := k.Keys[purpose]
	if !ok || len(b) != 32 {
		return nil, fmt.Errorf("unlock: no %s key for this process", purpose)
	}
	return slices.Clone(b), nil
}

// StoreAuth signs requests to the Worker's sealed-state API with purpose's store-auth key (sealstate.Relay's Auth);
// the Worker checks the KMS id's certificate for it (vm-state.ts). now: nil is time.Now.
func (k *Keys) StoreAuth(purpose string, now func() time.Time) (func(*http.Request), error) {
	cert, ok := k.Certs[purpose]
	key, err := k.Key(context.Background(), purpose)
	if !ok || err != nil {
		return nil, fmt.Errorf("unlock: no store certificate for %s", purpose)
	}
	sk, err := kms.StoreAuthKey(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return func(req *http.Request) {
		var body []byte
		if req.GetBody != nil {
			if rc, err := req.GetBody(); err == nil {
				body, _ = io.ReadAll(rc)
				rc.Close()
			}
		}
		name := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
		c, a := kmsvm.SignState(sk, cert, req.Method, name, now().Unix(), req.Header.Get("X-Tacy-Gen"), req.Header.Get("X-Tacy-Prev-Gen"), body)
		req.Header.Set("X-Tacy-Cert", c)
		req.Header.Set("X-Tacy-Auth", a)
	}, nil
}

// StoreSigner is purpose's store-auth key and certificate (the schedule ownership rows sign with them too).
func (k *Keys) StoreSigner(purpose string) (ed25519.PrivateKey, kms.StoreCert, error) {
	cert, ok := k.Certs[purpose]
	key, err := k.Key(context.Background(), purpose)
	if !ok || err != nil {
		return nil, kms.StoreCert{}, fmt.Errorf("unlock: no store certificate for %s", purpose)
	}
	defer clear(key)
	sk, err := kms.StoreAuthKey(key)
	return sk, cert, err
}

// Server serves unlockd's sockets.
type Server struct {
	U        *Unlocker
	Evidence client.Evidence // dstack's GetQuote (unlockd alone has its socket)
	Platform string
	Logf     func(string, ...any)
	once     sync.Once
	quotes   chan struct{}
}

// Serve accepts role's connections on l; peerUID (>= 0) is the only uid allowed.
func (s *Server) Serve(l net.Listener, peerUID int, role string) error {
	s.once.Do(func() { s.quotes = make(chan struct{}, 4) })
	logf := s.Logf
	if logf == nil {
		logf = log.Printf
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		if peerUID >= 0 {
			if err := gateway.CheckPeer(c, peerUID); err != nil {
				logf("unlockd: %s socket: %v", role, err)
				c.Close()
				continue
			}
		}
		go s.serve(c, role)
	}
}

func (s *Server) serve(c net.Conn, role string) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(c, 4096)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req Request
	rep := s.answer(json.Unmarshal(line, &req), &req, role)
	json.NewEncoder(c).Encode(rep)
	if rep.Keys != nil {
		for _, v := range rep.Keys.Keys {
			clear(v)
		}
	}
}

func (s *Server) answer(perr error, req *Request, role string) *Reply {
	st := s.U.Status()
	rep := &Reply{Version: Version, State: st.State, Reason: st.Reason, Message: Message(st.State)}
	if perr != nil || req.Version != Version {
		rep.Error = "bad_request"
		return rep
	}
	switch req.Op {
	case "status":
	case "keys":
		k, st, err := s.U.Keys(role)
		rep.State, rep.Reason, rep.Message = st.State, st.Reason, Message(st.State)
		if err == nil {
			rep.Keys = k
		} else if st.State == StateReady {
			rep.State, rep.Message = StateStarting, Message(StateStarting) // ready, but this role's keys aren't (API keys)
		}
	case "attest":
		if role != RoleAgent || s.Evidence == nil {
			rep.Error = "not_allowed"
			return rep
		}
		nonce, err1 := hex.DecodeString(req.Nonce)
		key, err2 := hex.DecodeString(req.Key)
		if err1 != nil || err2 != nil || len(nonce) != 32 || len(key) != 32 {
			rep.Error = "bad_request"
			return rep
		}
		select {
		case s.quotes <- struct{}{}:
			defer func() { <-s.quotes }()
		default:
			rep.Error = "busy"
			return rep
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		q, info, err := s.Evidence(ctx, proto.AgentReportData(nonce, key))
		if err != nil {
			rep.Error = "evidence_unavailable"
			return rep
		}
		rep.Quote, rep.Info = q, info
	default:
		rep.Error = "bad_request"
	}
	return rep
}

// Client is agentd's or vaultd's side.
type Client struct {
	Path string
}

// ErrNotReady: unlockd has no keys for this process yet (Reply's state says why).
var ErrNotReady = errors.New("unlock: no keys yet")

// Do sends one request.
func (c *Client) Do(ctx context.Context, req Request) (*Reply, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, err
	}
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(30 * time.Second))
	req.Version = Version
	b, _ := json.Marshal(req)
	if _, err := nc.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	var rep Reply
	if err := json.NewDecoder(io.LimitReader(nc, 4<<20)).Decode(&rep); err != nil {
		return nil, err
	}
	if rep.Error != "" {
		return &rep, fmt.Errorf("unlockd: %s", rep.Error)
	}
	return &rep, nil
}

// Keys asks once.
func (c *Client) Keys(ctx context.Context) (*Keys, *Reply, error) {
	rep, err := c.Do(ctx, Request{Op: "keys"})
	if err != nil {
		return nil, rep, err
	}
	if rep.Keys == nil {
		return nil, rep, fmt.Errorf("%w: %s %s", ErrNotReady, rep.State, rep.Reason)
	}
	return rep.Keys, rep, nil
}

// Wait asks until unlockd has this process's keys (no deadline: the holders may be down a while; the state is
// logged when it changes). want, when set, are the purposes the process can't start without.
func (c *Client) Wait(ctx context.Context, logf func(string, ...any), want ...string) (*Keys, error) {
	if logf == nil {
		logf = log.Printf
	}
	back, last := time.Second, ""
	for {
		k, rep, err := c.Keys(ctx)
		if err == nil {
			for _, p := range want {
				if _, ok := k.Keys[p]; !ok {
					return nil, fmt.Errorf("unlock: the policy gives this process no %s key", p)
				}
			}
			return k, nil
		}
		now := err.Error()
		if rep != nil {
			now = rep.State + ": " + rep.Reason
		}
		if now != last {
			logf("keys: waiting for unlockd (%s)", now)
			last = now
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(back):
		}
		back = min(back*2, 15*time.Second)
	}
}

// Attest is agentd's attestation evidence for nonce and its HPKE key, made by unlockd under proto.VersionAgent.
func (c *Client) Attest(ctx context.Context, nonce, key []byte) (json.RawMessage, json.RawMessage, error) {
	rep, err := c.Do(ctx, Request{Op: "attest", Nonce: hex.EncodeToString(nonce), Key: hex.EncodeToString(key)})
	if err != nil {
		return nil, nil, err
	}
	return rep.Quote, rep.Info, nil
}

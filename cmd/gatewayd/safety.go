package main

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/keylog"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/vault"
)

// vaultPusher passes gatewayd's documents to the vault (which checks each itself), one push at a time.
func vaultPusher(vc *vault.Client, st *safety.State) func() {
	var mu sync.Mutex
	return func() {
		mu.Lock()
		defer mu.Unlock()
		docs := st.Docs()
		if len(docs) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := vc.Push(ctx, docs); err != nil {
			log.Printf("safety: vault: %v", err)
		}
	}
}

// retryLease: a vault that restarted holds no documents yet and refuses leases (no policy, stale); gatewayd
// passes its documents on and asks once more.
func retryLease(lease guard.Lease, push func()) guard.Lease {
	return func(ctx context.Context, secret, connector, host string) (*vault.Secret, error) {
		s, err := lease(ctx, secret, connector, host)
		if errors.Is(err, vault.ErrPolicyMissing) || errors.Is(err, vault.ErrStale) {
			push()
			s, err = lease(ctx, secret, connector, host)
		}
		return s, err
	}
}

// retryVault is the vault client for the mail connector (guard.MailVault) with retryLease's rule for its leases.
type retryVault struct {
	*vault.Client
	push func()
}

func (r retryVault) Lease(ctx context.Context, req vault.Request) (*vault.Secret, error) {
	s, err := r.Client.Lease(ctx, req)
	if errors.Is(err, vault.ErrPolicyMissing) || errors.Is(err, vault.ErrStale) {
		r.push()
		s, err = r.Client.Lease(ctx, req)
	}
	return s, err
}

// pullSafety fetches the firm key log from ku (keys v2 slice 5) and the signed stop lists and policies from u every
// so often, and passes them to agentd (POST /keylog, then POST /safety on its HTTP socket), which checks them and
// keeps the floors on disk; gatewayd then gets agentd's newest documents back (and checks them itself). The log
// goes first, so a policy signed by a key admin it adds is taken in the same round. gatewayd doesn't take what it
// pulls directly: right after a gatewayd restart it has no floors, so an older document served at u could
// otherwise count here for a moment. The host learns only that the VM is up. If u can't be reached, nothing new
// arrives: after 3 minutes agentd counts the list silent and nothing goes out (fail closed;
// safety.DefaultMaxSilence).
func pullSafety(u, ku string, every time.Duration, agentSock string) {
	for _, x := range []string{u, ku} {
		if x == "" {
			continue
		}
		if pu, err := url.Parse(x); err != nil || pu.Scheme != "https" || pu.Host == "" {
			log.Fatalf("gatewayd: -safety-url and -keylog-url must be https URLs")
		}
	}
	client := guard.NewFetcher(false) // public addresses only
	agent := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", agentSock)
		}}}
	get := func(ctx context.Context, x string, limit int64) ([]byte, bool) {
		req, _ := http.NewRequestWithContext(ctx, "GET", x, nil)
		res, err := client.Do(req)
		if err != nil {
			log.Printf("safety: pull: %v", err)
			return nil, false
		}
		defer res.Body.Close()
		body, err := io.ReadAll(io.LimitReader(res.Body, limit))
		if err != nil || res.StatusCode != 200 {
			log.Printf("safety: pull: HTTP %d", res.StatusCode)
			return nil, false
		}
		return body, true
	}
	post := func(ctx context.Context, path string, body []byte) bool {
		req, _ := http.NewRequestWithContext(ctx, "POST", "http://agentd"+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r2, err := agent.Do(req)
		if err != nil {
			return false
		}
		r2.Body.Close()
		return true
	}
	delivered := false
	for {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if ku != "" {
				if body, ok := get(ctx, ku, keylog.MaxEntries*keylog.MaxEntryWire); ok {
					var entries []jsontext.Value
					if err := json.Unmarshal(body, &entries); err != nil || len(entries) > keylog.MaxEntries {
						log.Printf("safety: pull: the key log isn't a JSON array of entries")
					} else {
						// In order, at most 64 a request (agentd's cap); entries it holds are no-ops.
						for i := 0; i < len(entries); i += 64 {
							chunk, _ := json.Marshal(entries[i:min(i+64, len(entries))])
							post(ctx, "/keylog", chunk)
						}
					}
				}
			}
			if u != "" {
				if body, ok := get(ctx, u, 8*2*safety.MaxEnvelope); ok {
					if _, err := safety.DecodeEnvelopes(body); err != nil {
						log.Printf("safety: pull: %v", err)
					} else if post(ctx, "/safety", body) {
						delivered = true
					}
				}
			}
		}()
		// Until the first delivery of the stop lists (agentd may still be starting), try again every second: agentd
		// refuses everything until the operator's list reaches it.
		if !delivered && u != "" {
			time.Sleep(min(every, time.Second))
			continue
		}
		time.Sleep(every)
	}
}

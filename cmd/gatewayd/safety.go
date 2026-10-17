package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/tacyhq/tacy/guard"
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

// pullSafety fetches the signed stop lists and policies from u every so often and passes the body to agentd (POST
// /safety on its HTTP socket), which checks them and keeps the floors on disk; gatewayd then gets agentd's newest
// documents back (and checks them itself). gatewayd doesn't take what it pulls directly: right after a gatewayd
// restart it has no floors, so an older document served at u could otherwise count here for a moment. The host
// learns only that the VM is up. If u can't be reached, nothing new arrives and the stop list goes stale: side
// effects stop (fail closed).
func pullSafety(u string, every time.Duration, agentSock string) {
	pu, err := url.Parse(u)
	if err != nil || pu.Scheme != "https" || pu.Host == "" {
		log.Fatalf("gatewayd: -safety-url must be an https URL")
	}
	client := guard.NewFetcher(false) // public addresses only
	agent := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", agentSock)
		}}}
	for {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
			res, err := client.Do(req)
			if err != nil {
				log.Printf("safety: pull: %v", err)
				return
			}
			defer res.Body.Close()
			body, err := io.ReadAll(io.LimitReader(res.Body, 8*2*safety.MaxEnvelope))
			if err != nil || res.StatusCode != 200 {
				log.Printf("safety: pull: HTTP %d", res.StatusCode)
				return
			}
			if _, err := safety.DecodeEnvelopes(body); err != nil {
				log.Printf("safety: pull: %v", err)
				return
			}
			req, _ = http.NewRequestWithContext(ctx, "POST", "http://agentd/safety", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if r2, err := agent.Do(req); err == nil {
				r2.Body.Close()
			}
		}()
		time.Sleep(every)
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Platform is everything host-specific: where secrets come from, how attestation evidence is produced, and where
// (encrypted) scratch storage lives. Moving to Google TDX (dstack too: same adapter) or Tinfoil Containers (their
// attestation document and secrets) means one more implementation of this, nothing else.
type Platform interface {
	Name() string
	// Secret returns a named secret, or "" when it isn't set.
	Secret(name string) string
	// Evidence returns attestation evidence whose report_data is exactly reportData (64 bytes), plus platform
	// info the verifier needs (for dstack: the app compose and event log).
	Evidence(ctx context.Context, reportData []byte) (quote, info json.RawMessage, err error)
	// StoragePath is a directory on the platform's encrypted disk for later tools, or "" when there's none.
	// Nothing uses it yet: the service is stateless.
	StoragePath() string
	// ActivityKey is key material only this attested app gets, for the activity signing key (docs/24): dstack's
	// KMS-derived key for a fixed path, the same after a restart. Locally, random per boot.
	ActivityKey(ctx context.Context) ([]byte, error)
	// TaskIDKey is key material for once-only task ids (docs/27 section 1): dstack's KMS-derived key at
	// "tacy/task-ids/v1", the same after a restart, so a repeated start finds its task across restarts. Locally,
	// random per boot.
	TaskIDKey(ctx context.Context) ([]byte, error)
}

// dstack: Phala Cloud, or open-source dstack on Google Cloud. Secrets are dstack's encrypted environment
// variables (encrypted to the CVM by the deployer, decrypted inside it); evidence comes from the guest agent socket.
type dstack struct {
	sock    string
	storage string
	http    *http.Client

	// info is the guest agent's /Info, kept for the boot (vm-speed): the guest agent answers one request at a
	// time and /Info takes about as long as a quote (~1 s each on tdx.small, measured 2026-10-18), so fetching it
	// for every /attest doubled the attestation's time. It's only reused for a quote whose RTMR3 equals the RTMR3
	// in it (the same event log); otherwise /attest fetches it again, as before. The quote is always fresh.
	infoMu    sync.Mutex
	info      json.RawMessage
	infoRTMR3 []byte
}

func newDstack(sock, storage string) *dstack {
	return &dstack{sock: sock, storage: storage, http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}}
}

func (d *dstack) Name() string              { return "dstack" }
func (d *dstack) Secret(name string) string { return os.Getenv(name) }
func (d *dstack) StoragePath() string       { return d.storage }

func (d *dstack) call(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, "http://dstack"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	res, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("dstack %s: %d", path, res.StatusCode)
	}
	return b, nil
}

func (d *dstack) Evidence(ctx context.Context, reportData []byte) (json.RawMessage, json.RawMessage, error) {
	if len(reportData) != 64 {
		return nil, nil, errors.New("report_data must be 64 bytes")
	}
	q, err := d.call(ctx, "POST", "/GetQuote", map[string]string{"report_data": hex.EncodeToString(reportData)})
	if err != nil {
		return nil, nil, err
	}
	rtmr3 := quoteRTMR3(q)
	if info := d.cachedInfo(rtmr3); info != nil {
		return q, info, nil
	}
	info, err := d.fetchInfo(ctx)
	if err != nil {
		return nil, nil, err
	}
	return q, info, nil
}

// cachedInfo is the kept /Info when its RTMR3 is rtmr3 (nil otherwise, or when rtmr3 is unknown).
func (d *dstack) cachedInfo(rtmr3 []byte) json.RawMessage {
	d.infoMu.Lock()
	defer d.infoMu.Unlock()
	if len(rtmr3) == 0 || d.info == nil || !bytes.Equal(rtmr3, d.infoRTMR3) {
		return nil
	}
	return d.info
}

// fetchInfo asks the guest agent for /Info and keeps it with its RTMR3 (an /Info whose RTMR3 can't be read isn't
// kept). It reports whether dstack's boot finished (the event log ends with "system-ready"): after that, RTMR3
// doesn't change unless something extends it, and then the next quote won't match and /Info is fetched again.
func (d *dstack) fetchInfo(ctx context.Context) (json.RawMessage, error) {
	info, err := d.call(ctx, "GET", "/Info", nil)
	if err != nil {
		return nil, err
	}
	if rtmr3, _ := infoRTMR3(info); len(rtmr3) > 0 {
		d.infoMu.Lock()
		d.info, d.infoRTMR3 = info, rtmr3
		d.infoMu.Unlock()
	}
	return info, nil
}

// PrefetchInfo fetches /Info at boot, until dstack's boot finished (the "system-ready" event: until then RTMR3
// still changes), so the first /attest after a cold start already finds it. Each try is one guest agent request;
// it gives up after `until`.
func (d *dstack) PrefetchInfo(ctx context.Context, every, until time.Duration) {
	end := time.Now().Add(until)
	for time.Now().Before(end) && ctx.Err() == nil {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		info, err := d.fetchInfo(c)
		cancel()
		if err == nil {
			if _, ready := infoRTMR3(info); ready {
				return
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(every):
		}
	}
}

// tdxQuoteRTMR3 is where RTMR3 sits in a TDX quote v4: the 48-byte header, then the TD report body, whose RTMR3
// starts 472 bytes in (TEE_TCB_SVN, MRSEAM, MRSIGNERSEAM, SEAMATTRIBUTES, TDATTRIBUTES, XFAM, MRTD, MRCONFIGID,
// MROWNER, MROWNERCONFIG, RTMR0-2 before it).
const tdxQuoteRTMR3 = 48 + 472

// quoteRTMR3 reads RTMR3 from the guest agent's /GetQuote response ({"quote": hex, ...}), nil when it can't: then
// nothing kept is reused. Parsed only to choose the cached /Info; the browser verifies the quote itself.
func quoteRTMR3(getQuote json.RawMessage) []byte {
	var r struct {
		Quote string `json:"quote"`
	}
	if json.Unmarshal(getQuote, &r) != nil {
		return nil
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(r.Quote, "0x"))
	if err != nil || len(raw) < tdxQuoteRTMR3+48 || raw[0] != 4 || raw[1] != 0 || !bytes.Equal(raw[4:8], []byte{0x81, 0, 0, 0}) {
		return nil // not a TDX quote v4
	}
	return bytes.Clone(raw[tdxQuoteRTMR3 : tdxQuoteRTMR3+48])
}

// infoRTMR3 reads /Info's RTMR3 (tcb_info.rtmr3) and whether its event log has dstack's "system-ready" event.
// tcb_info comes as a JSON string or an object.
func infoRTMR3(info json.RawMessage) ([]byte, bool) {
	var i struct {
		TcbInfo json.RawMessage `json:"tcb_info"`
	}
	if json.Unmarshal(info, &i) != nil {
		return nil, false
	}
	var str string
	if json.Unmarshal(i.TcbInfo, &str) == nil {
		i.TcbInfo = []byte(str)
	}
	var t struct {
		RTMR3    string `json:"rtmr3"`
		EventLog []struct {
			IMR   int    `json:"imr"`
			Event string `json:"event"`
		} `json:"event_log"`
	}
	if json.Unmarshal(i.TcbInfo, &t) != nil {
		return nil, false
	}
	rtmr3, err := hex.DecodeString(t.RTMR3)
	if err != nil || len(rtmr3) != 48 {
		return nil, false
	}
	ready := false
	for _, e := range t.EventLog {
		if e.IMR == 3 && e.Event == "system-ready" {
			ready = true
		}
	}
	return rtmr3, ready
}

// ActivityKey asks the guest agent for the app's key at path "tacy/activity/v1" (dstack derives it from the KMS
// root, the app id and the path; it never leaves the CVM). The response's key is hex; its signature chain (which
// proves the key to dstack's KMS) isn't needed here: the browser learns the derived public key over EHBP from the
// attested VM (meta.activity).
func (d *dstack) ActivityKey(ctx context.Context) ([]byte, error) {
	return d.appKey(ctx, "tacy/activity/v1", "signing")
}

// TaskIDKey asks the guest agent for the app's key at path "tacy/task-ids/v1" (as ActivityKey).
func (d *dstack) TaskIDKey(ctx context.Context) ([]byte, error) {
	return d.appKey(ctx, "tacy/task-ids/v1", "task-ids")
}

func (d *dstack) appKey(ctx context.Context, path, purpose string) ([]byte, error) {
	b, err := d.call(ctx, "POST", "/GetKey", map[string]string{"path": path, "purpose": purpose})
	if err != nil {
		return nil, err
	}
	var r struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	k, err := hex.DecodeString(strings.TrimPrefix(r.Key, "0x"))
	if err != nil || len(k) < 32 {
		return nil, errors.New("dstack GetKey: no usable key")
	}
	return k, nil
}

// local is for development on a laptop: secrets from the environment, no attestation. The verifier refuses it
// unless told to skip attestation.
type local struct{}

func (local) Name() string              { return "local" }
func (local) Secret(name string) string { return os.Getenv(name) }
func (local) StoragePath() string       { return "" }
func (local) ActivityKey(context.Context) ([]byte, error) {
	k := make([]byte, 32)
	_, err := rand.Read(k)
	return k, err
}
func (local) TaskIDKey(ctx context.Context) ([]byte, error) { return local{}.ActivityKey(ctx) }
func (local) Evidence(context.Context, []byte) (json.RawMessage, json.RawMessage, error) {
	return nil, nil, nil
}

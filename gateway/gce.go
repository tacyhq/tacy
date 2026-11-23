package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The Google Cloud host hints (registry mode on the VM). A registry-mode machine
// certificate needs the VM's GCE instance id and zone: MR_OWNER is sha384 of the PZID JSON
// {"instanceId":…,"numericalProjectId":…,"zone":…} that Google writes at launch, so the verifier needs the id and
// zone to recompute it. They are hints, not evidence: they come from Google's metadata server (Google is the party the
// check is about), and only MR_OWNER in the quote and Google's host registry make them count. A wrong hint fails the
// check; it can't pass a VM that isn't in the certified project.
//
// agentd and unlockd have no network, so gatewayd answers one fixed call for them, target "gce", GET /instance. It
// asks the metadata server only on a Google Compute Engine VM (DMI product name), so on Phala the call is answered
// no_target and nothing is sent anywhere.

// TargetGCE is the Google Cloud hints target (gatewayd answers it itself; it never forwards a call).
const TargetGCE = "gce"

// GCEPath is its one call: GET, no query, no body.
const GCEPath = "/instance"

// GCEHints are the two hints, as they go into the attestation info.
type GCEHints struct {
	InstanceID string `json:"gce_instance_id"`
	Zone       string `json:"gce_zone"`
}

var (
	gceIDRe   = regexp.MustCompile(`^[0-9]{1,20}$`)
	gceZoneRe = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]{1,2}-[a-z]$`)
)

// Valid says both hints have the right form.
func (h GCEHints) Valid() bool {
	return gceIDRe.MatchString(h.InstanceID) && gceZoneRe.MatchString(h.Zone)
}

// GCEProduct is the DMI product name of a Google Compute Engine VM.
const GCEProduct = "Google Compute Engine"

// GCEMeta reads the hints from Google's metadata server, once per boot (the instance id and zone don't change).
type GCEMeta struct {
	// DMIPath: the DMI product name file (default /sys/class/dmi/id/product_name).
	DMIPath string
	// Base: the metadata server's instance URL (default http://169.254.169.254/computeMetadata/v1/instance/: the
	// link-local address, no DNS).
	Base   string
	Client *http.Client

	mu    sync.Mutex
	hints *GCEHints
}

var errNotGCE = errors.New("not a Google Compute Engine VM")

func (m *GCEMeta) onGCE() bool {
	p := m.DMIPath
	if p == "" {
		p = "/sys/class/dmi/id/product_name"
	}
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 128))
	return strings.TrimSpace(string(b)) == GCEProduct
}

var defaultGCEClient = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
	Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, DisableKeepAlives: true,
}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (m *GCEMeta) get(ctx context.Context, name string) (string, error) {
	base := m.Base
	if base == "" {
		base = "http://169.254.169.254/computeMetadata/v1/instance/"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+name, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	c := m.Client
	if c == nil {
		c = defaultGCEClient
	}
	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 257))
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK || res.Header.Get("Metadata-Flavor") != "Google" || len(b) > 256 {
		return "", errors.New("not a metadata server answer")
	}
	return strings.TrimSpace(string(b)), nil
}

// Hints are the VM's hints (errNotGCE off Google Compute Engine, with nothing sent).
func (m *GCEMeta) Hints(ctx context.Context) (*GCEHints, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hints != nil {
		return m.hints, nil
	}
	if !m.onGCE() {
		return nil, errNotGCE
	}
	id, err := m.get(ctx, "id")
	if err != nil {
		return nil, err
	}
	zone, err := m.get(ctx, "zone") // projects/<number>/zones/<zone>
	if err != nil {
		return nil, err
	}
	h := &GCEHints{InstanceID: id, Zone: zone[strings.LastIndexByte(zone, '/')+1:]}
	if !h.Valid() {
		return nil, errors.New("the metadata server's instance id or zone has the wrong form")
	}
	m.hints = h
	return h, nil
}

func (m *GCEMeta) answer(ctx context.Context) *FixedAnswer {
	if m == nil {
		return &FixedAnswer{Error: "no_target"}
	}
	h, err := m.Hints(ctx)
	if errors.Is(err, errNotGCE) {
		return &FixedAnswer{Error: "no_target"}
	}
	if err != nil {
		return &FixedAnswer{Error: "unreachable"}
	}
	b, _ := json.Marshal(h)
	return &FixedAnswer{Status: http.StatusOK, Body: b}
}

// GCEHinter adds the hints to a dstack attestation's info (agentd's /attest, unlockd's unlock attestations) when the
// guest agent says the VM is on Google (cloud_vendor "Google"); any other info is returned as it is, and no call is
// made. Hints it can't get are left out (the machine check then refuses a registry-mode VM, fail closed).
type GCEHinter struct {
	D FixedDoer // gatewayd (a Client on the caller's socket)

	mu    sync.Mutex
	hints []byte // `,"gce_instance_id":…,"gce_zone":…`, once got
}

// Augment is info with the hints added before its closing brace (the rest of its bytes unchanged).
func (g *GCEHinter) Augment(ctx context.Context, info json.RawMessage) json.RawMessage {
	if g == nil || g.D == nil {
		return info
	}
	var v struct {
		CloudVendor string          `json:"cloud_vendor"`
		ID          json.RawMessage `json:"gce_instance_id"`
		Zone        json.RawMessage `json:"gce_zone"`
	}
	if json.Unmarshal(info, &v) != nil || v.CloudVendor != "Google" || v.ID != nil || v.Zone != nil {
		return info
	}
	t := bytes.TrimRight(info, " \t\r\n")
	if len(t) < 3 || t[len(t)-1] != '}' {
		return info
	}
	add := g.get(ctx)
	if add == nil {
		return info
	}
	out := make([]byte, 0, len(t)+len(add))
	out = append(append(append(out, t[:len(t)-1]...), add...), '}')
	return out
}

func (g *GCEHinter) get(ctx context.Context) []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.hints != nil {
		return g.hints
	}
	a := g.D.Fixed(ctx, &FixedCall{Target: TargetGCE, Method: http.MethodGet, Path: GCEPath})
	if a == nil || a.Error != "" || a.Status != http.StatusOK {
		return nil
	}
	var h GCEHints
	if json.Unmarshal(a.Body, &h) != nil || !h.Valid() {
		return nil
	}
	b, _ := json.Marshal(h)
	g.hints = append([]byte{','}, b[1:len(b)-1]...)
	return g.hints
}

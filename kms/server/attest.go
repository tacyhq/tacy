package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"
	"go.yaml.in/yaml/v3"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/verifier"
)

// CheckOptions are the attestation checks' test and development switches (zero in production), and the Tacy KMS
// ids a VM's compose may name (-kms-key): a replica passes its own.
type CheckOptions struct {
	VerifyQuote   func(ctx context.Context, raw []byte) (*tdx.Quote, error)
	AllowStaleTCB bool
	Getter        trust.HTTPSGetter
	Now           time.Time
	DevLocal      bool
	KMSIDs        map[string]string
	// AllowE2EDiag: a staging key service whose policy lets e2e overlays in (their diag service; Config.Staging).
	AllowE2EDiag bool
	// Machines are the machines a VM may run on (verifier.Policy.Machines). A holder always sets them from its
	// signed policy (never the built-in ones); nil (the key service, kmsctl) takes the verifier's built-in ones.
	Machines *safety.MachineSet
	// RequireUnlockd: the release must have unlockd (verifier.Policy.RequireUnlockd; a split-key holder sets it on
	// every request, review L3).
	RequireUnlockd bool
}

// Attested is what a verified attestation established.
type Attested struct {
	Key         *ecdh.PublicKey // the X25519 key bound in report_data: replies are sealed to it
	Pin         kms.ReleasePin  // the release its app-compose.json is pinned as
	Instance    string          // the attested instance-id event
	AppID       string
	ComposeHash string // sha256(app-compose.json), attested
	Facts       map[string]string
	// Key service attestations: the replica's role (its kmsd -role, which its pin's Role matches) and its kmsd
	// flags (nil for a development replica: nothing attested).
	Role  string
	Flags map[string]string
}

func (s *Server) checkOptions() CheckOptions {
	o := CheckOptions{VerifyQuote: s.cfg.VerifyQuote, AllowStaleTCB: s.cfg.AllowStaleTCB, Getter: s.cfg.Getter,
		Now: s.cfg.CheckNow, DevLocal: s.cfg.DevLocal}
	s.mu.Lock()
	if id := s.kmsIDLocked(); id != "" {
		o.KMSIDs = map[string]string{id: "this key service"}
	}
	o.AllowE2EDiag = s.cfg.Staging && s.policy != nil && s.policy.AllowE2EDiag
	s.mu.Unlock()
	return o
}

// VerifyVM checks an agent VM's attestation for nonce against the policy's release pins (not floors or purposes).
func VerifyVM(ctx context.Context, raw json.RawMessage, nonce []byte, pol *kms.Policy, o CheckOptions) (*Attested, error) {
	return verifyAttestation(ctx, raw, nonce, pol, pol.Releases, false, o)
}

// VerifyKMS checks a key service replica's attestation for nonce against the policy's KMS pins: kmsctl before it
// sends shares or secrets, and peers before a join.
func VerifyKMS(ctx context.Context, raw json.RawMessage, nonce []byte, pol *kms.Policy, o CheckOptions) (*Attested, error) {
	return verifyAttestation(ctx, raw, nonce, pol, pol.KMS, true, o)
}

func verifyAttestation(ctx context.Context, raw json.RawMessage, nonce []byte, pol *kms.Policy, pins []kms.ReleasePin,
	isKMS bool, o CheckOptions) (*Attested, error) {
	var att proto.Attestation
	if err := json.Unmarshal(raw, &att); err != nil {
		return nil, refuse(http.StatusBadRequest, "attestation isn't JSON")
	}
	// Which release this claims to be: sha256 of the whole app-compose.json in its info. Unverified here: the
	// verifier then checks the attested compose-hash event is this file's hash and that the hash is the pin's.
	appCompose, err := kms.AppCompose(att.Info)
	if err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	sum := sha256.Sum256(appCompose)
	h := hex.EncodeToString(sum[:])
	i := slices.IndexFunc(pins, func(p kms.ReleasePin) bool { return p.AppComposeSHA256 == h })
	if i < 0 {
		what := "release"
		if isKMS {
			what = "key service release"
		}
		return nil, refuse(http.StatusForbidden, "app-compose.json sha256 %s isn't a pinned %s", short(h), what)
	}
	pin := pins[i]
	if isKMS && pol.KMSFloor != "" {
		if c, ok := kms.CompareVersions(pin.Version, pol.KMSFloor); !ok || c < 0 {
			return nil, refuse(http.StatusForbidden, "key service release %s is below the policy's kms floor %s", pin.Version, pol.KMSFloor)
		}
	}
	dc, err := kms.DockerCompose(appCompose)
	if err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	if pin.ComposeSHA256 != "" {
		if d := sha256.Sum256([]byte(dc)); hex.EncodeToString(d[:]) != pin.ComposeSHA256 {
			return nil, refuse(http.StatusForbidden, "docker compose isn't the pinned release's")
		}
	}
	vp := verifier.Policy{Compose: []byte(dc), AppComposeSHA256: []string{pin.AppComposeSHA256}, KMSFallback: pol.KMSFallback,
		ProdImages: pol.OSImages, PreLaunch: pol.PreLaunch, Boot: bootSets(pol.Boot), KMSRoots: pol.KMSRoots, KMSIDs: o.KMSIDs,
		AllowStaleTCB: o.AllowStaleTCB, SkipAttestation: o.DevLocal, VerifyQuote: o.VerifyQuote, Getter: o.Getter, Now: o.Now,
		KeyRelease: true, Machines: o.Machines, RequireUnlockd: o.RequireUnlockd && !isKMS}
	if vp.KMSIDs == nil {
		vp.KMSIDs = map[string]string{} // only the ids given: never the verifier's built-in list by default
	}
	if isKMS {
		vp.Services, vp.Port = []string{KMSService}, KMSPort
	} else {
		vp.AllowE2EDiag = o.AllowE2EDiag // staging only (Config.Staging)
	}
	res, err := verifier.Verify(ctx, &att, nonce, vp)
	if err != nil {
		return nil, refuse(http.StatusForbidden, "attestation: %v", err)
	}
	local := att.Platform == "local" && o.DevLocal // development: nothing attested, no release compose
	if isKMS && !local {
		// The key service's own rules on top of the verifier's: one kmsd, no env, logging off, no swap.
		if err := CheckCompose(dc); err != nil {
			return nil, refuse(http.StatusForbidden, "key service compose: %v", err)
		}
		if err := checkKMSAppCompose(appCompose); err != nil {
			return nil, refuse(http.StatusForbidden, "%v", err)
		}
	}
	key, err := ecdh.X25519().NewPublicKey(res.HPKEPublicKey)
	if err != nil {
		return nil, refuse(http.StatusForbidden, "attestation key isn't X25519")
	}
	a := &Attested{Key: key, Pin: pin, ComposeHash: h, Facts: res.Facts, Instance: res.Facts["instance id"], AppID: res.Facts["app id"]}
	if isKMS {
		a.Role = pin.PinRole()
		if !local {
			flags, err := KMSFlags(dc)
			if err != nil {
				return nil, refuse(http.StatusForbidden, "key service compose: %v", err)
			}
			role := flags["role"]
			if role == "" {
				role = kms.RolePrimary
			}
			if role != a.Role {
				return nil, refuse(http.StatusForbidden, "key service runs as %s, pinned as %s", role, a.Role)
			}
			a.Flags = flags
		}
	}
	if local {
		// Development only: nothing is attested; the instance and app id are what the info says.
		var info struct {
			AppID      string `json:"app_id"`
			InstanceID string `json:"instance_id"`
		}
		json.Unmarshal(att.Info, &info)
		a.Instance, a.AppID = info.InstanceID, info.AppID
	} else if res.Facts["app-compose sha256"] != h {
		return nil, refuse(http.StatusForbidden, "attested app-compose.json isn't the pinned one")
	}
	if a.Instance == "" {
		return nil, refuse(http.StatusForbidden, "no instance-id event (the lease needs one)")
	}
	if pin.AppID != "" && a.AppID != pin.AppID {
		return nil, refuse(http.StatusForbidden, "app id %s isn't the pinned %s", short(a.AppID), short(pin.AppID))
	}
	return a, nil
}

// KMSFlags are kmsd's flags in a key service compose (services.kmsd.command): name (without dashes) -> value. A
// bare boolean flag is "true".
func KMSFlags(compose string) (map[string]string, error) {
	var doc struct {
		Services map[string]struct {
			Command any `yaml:"command"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return nil, fmt.Errorf("not YAML: %w", err)
	}
	svc, ok := doc.Services[KMSService]
	if !ok {
		return nil, fmt.Errorf("no %s service", KMSService)
	}
	var args []string
	switch c := svc.Command.(type) {
	case nil:
	case string:
		args = strings.Fields(c)
	case []any:
		for _, x := range c {
			s, ok := x.(string)
			if !ok {
				return nil, errors.New("command entries must be strings")
			}
			args = append(args, s)
		}
	default:
		return nil, errors.New("command must be a list or a string")
	}
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			return nil, fmt.Errorf("command argument %q isn't a flag", a)
		}
		name := strings.TrimLeft(a, "-")
		if n, v, ok := strings.Cut(name, "="); ok {
			flags[n] = v
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			flags[name] = args[i+1]
			i++
			continue
		}
		flags[name] = "true"
	}
	return flags, nil
}

// sameFlags: a peer runs with this replica's admin keys, admin threshold and release floor (a join gives M only
// between replicas that obey the same admins and floors).
func (s *Server) sameFlags(a *Attested) error {
	if a.Flags == nil {
		if s.cfg.DevLocal {
			return nil // a development replica: nothing attested, nothing to compare
		}
		return refuse(http.StatusForbidden, "the peer's kmsd flags aren't attested")
	}
	keys, err := safety.ParseKeys(a.Flags["admin-keys"])
	if err != nil {
		return refuse(http.StatusForbidden, "the peer's -admin-keys: %v", err)
	}
	var strs []string
	for _, k := range keys {
		strs = append(strs, kms.IDString(k))
	}
	th := 1
	if v := a.Flags["admin-threshold"]; v != "" {
		if th, err = strconv.Atoi(v); err != nil {
			return refuse(http.StatusForbidden, "the peer's -admin-threshold isn't a number")
		}
	}
	if !s.cfg.Admin.SameKeys(strs, th) {
		return refuse(http.StatusForbidden, "the peer runs with other admin keys or threshold")
	}
	if a.Flags["floor"] != s.cfg.FloorMin {
		return refuse(http.StatusForbidden, "the peer's release floor %q isn't this replica's %q", a.Flags["floor"], s.cfg.FloorMin)
	}
	return nil
}

func bootSets(b []kms.BootSet) []verifier.BootMeasurement {
	if b == nil {
		return nil
	}
	out := make([]verifier.BootMeasurement, 0, len(b))
	for _, s := range b {
		out = append(out, verifier.BootMeasurement{Name: s.Name, OSImage: s.OSImage, MRTD: s.MRTD, RTMR0: s.RTMR0,
			RTMR1: s.RTMR1, RTMR2: s.RTMR2, Source: "kms policy"})
	}
	return out
}

// checkKMSAppCompose: the key service's app-compose.json gives it no swap, no deployer env and no public logs (the
// verifier's flag rules check these too; the key service doesn't depend on them alone). Phala writes swap_size as
// a string ("0"); a number 0 is accepted too.
func checkKMSAppCompose(appCompose []byte) error {
	var ac struct {
		SwapSize    json.RawMessage `json:"swap_size"`
		AllowedEnvs []string        `json:"allowed_envs"`
		PublicLogs  bool            `json:"public_logs"`
	}
	if err := json.Unmarshal(appCompose, &ac); err != nil {
		return errors.New("key service app-compose.json isn't JSON")
	}
	if !zeroSwap(ac.SwapSize) {
		return fmt.Errorf("key service app-compose has swap_size %s (memory could reach the disk)", ac.SwapSize)
	}
	if len(ac.AllowedEnvs) != 0 {
		return errors.New("key service app-compose allows deployer env")
	}
	if ac.PublicLogs {
		return errors.New("key service app-compose has public logs")
	}
	return nil
}

// zeroSwap: swap_size absent, null, 0, or a size string of zero ("0", "0G", "0 MB").
func zeroSwap(raw json.RawMessage) bool {
	s := string(bytes.TrimSpace(raw))
	if s == "" || s == "null" || s == "0" {
		return true
	}
	var str string
	if json.Unmarshal(raw, &str) != nil {
		return false
	}
	str = strings.TrimSpace(str)
	digits := strings.TrimRight(str, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ")
	return digits != "" && strings.Trim(digits, "0") == ""
}

// The key service's compose: its only service, its port, and the only bind mount it may have (dstack's socket,
// for its own quotes).
const (
	KMSService   = "kmsd"
	KMSPort      = 8000
	DstackSocket = "/var/run/dstack.sock:/var/run/dstack.sock"
)

// KMSAppComposeName is the app name in the key service release's app-compose.json.
const KMSAppComposeName = "tacy-kms"

// KMSAppCompose is the app-compose.json a key service release's CVM attests, in Phala's stored form: the agent VM's
// release rules (verifier.ReleaseAppCompose, KMS fallback: Phala's gateway needs Phala's KMS; nothing on the disk,
// an ephemeral data disk, no swap, nothing public, no deployer env, no pre-launch script) with its own name and only
// port KMSPort. Its sha256 is the release's pin (Policy.KMS).
func KMSAppCompose(compose []byte) ([]byte, error) {
	if err := CheckCompose(string(compose)); err != nil {
		return nil, err
	}
	out, err := verifier.ReleaseAppCompose(compose, nil, true)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(out))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		return nil, err
	}
	m["name"] = KMSAppComposeName
	m["port_policy"] = map[string]any{"ports": []any{map[string]any{"port": KMSPort, "pp": false}}, "restrict_mode": true}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // jq -cS, as Phala stores it
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// CheckCompose is the key service's compose rule: one YAML document with one service, kmsd, its image by digest;
// no build, extends or include; nothing on the disk (volumes only memory, tmpfs, or dstack's socket); no
// environment; logging driver none; read-only root; not privileged, no pid or host network; memory swap no larger
// than memory.
func CheckCompose(compose string) error {
	dec := yaml.NewDecoder(strings.NewReader(compose))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("not YAML: %w", err)
	}
	var more any
	if err := dec.Decode(&more); err == nil {
		return errors.New("more than one YAML document")
	}
	mem := map[string]bool{}
	for k, v := range doc {
		switch k {
		case "services":
		case "volumes":
			vols, _ := v.(map[string]any)
			for n, def := range vols {
				m, _ := def.(map[string]any)
				opts, _ := m["driver_opts"].(map[string]any)
				if opts["type"] != "tmpfs" || (m["driver"] != nil && m["driver"] != "local") || m["external"] != nil {
					return fmt.Errorf("volume %s isn't memory (driver_opts type tmpfs)", n)
				}
				mem[n] = true
			}
		default:
			return fmt.Errorf("top-level %s: (only services and memory volumes)", k)
		}
	}
	services, ok := doc["services"].(map[string]any)
	if !ok || len(services) != 1 {
		return errors.New("want exactly one service")
	}
	svc, ok := services[KMSService].(map[string]any)
	if !ok {
		return fmt.Errorf("the service must be %s", KMSService)
	}
	allowed := []string{"image", "entrypoint", "command", "restart", "user", "read_only", "cap_drop", "security_opt",
		"ports", "volumes", "logging", "mem_limit", "memswap_limit", "pids_limit", "tmpfs", "ulimits", "stop_grace_period"}
	for k := range svc {
		if !slices.Contains(allowed, k) {
			return fmt.Errorf("service %s has %s:", KMSService, k)
		}
	}
	img, _ := svc["image"].(string)
	if !digestRef(img) {
		return fmt.Errorf("image %q isn't name@sha256:<digest>", img)
	}
	if v, ok := svc["volumes"]; ok {
		list, ok := v.([]any)
		if !ok {
			return errors.New("volumes must be a list")
		}
		for _, x := range list {
			s, _ := x.(string)
			src, _, _ := strings.Cut(s, ":")
			if s != DstackSocket && !mem[src] {
				return fmt.Errorf("volume %v: only %s and memory volumes", x, DstackSocket)
			}
		}
	}
	lg, _ := svc["logging"].(map[string]any)
	if lg == nil || lg["driver"] != "none" || len(lg) != 1 {
		return errors.New("logging must be driver none")
	}
	if svc["read_only"] != true {
		return errors.New("read_only must be true")
	}
	if fmt.Sprint(svc["mem_limit"]) == "" || fmt.Sprint(svc["memswap_limit"]) != fmt.Sprint(svc["mem_limit"]) {
		return errors.New("memswap_limit must equal mem_limit (no swap)")
	}
	if t, ok := svc["tmpfs"]; ok {
		list, ok := t.([]any)
		if !ok {
			list = []any{t}
		}
		for _, x := range list {
			if p := fmt.Sprint(x); p != "/tmp" && !strings.HasPrefix(p, "/tmp:") {
				return errors.New("tmpfs: only /tmp")
			}
		}
	}
	return nil
}

func digestRef(s string) bool {
	name, d, ok := strings.Cut(s, "@sha256:")
	if !ok || len(d) != 64 || strings.ContainsAny(name, ":$ ") || !strings.Contains(name, "/") {
		return false
	}
	_, err := hex.DecodeString(d)
	return err == nil && strings.ToLower(d) == d
}

// LocalAppCompose is the app-compose.json a development replica (platform local, no TDX) reports. A development
// policy pins its sha256 as a KMS release; nothing about it is attested.
const LocalAppCompose = `{"docker_compose_file":"services:\n  kmsd:\n    image: local-development\n","runner":"docker-compose"}`

// LocalInfo is a development replica's dstack-like Info: LocalAppCompose and an instance id.
func LocalInfo(instance string) json.RawMessage {
	tcb, _ := json.Marshal(map[string]string{"app_compose": LocalAppCompose})
	b, _ := json.Marshal(map[string]string{"app_id": "local", "instance_id": instance, "tcb_info": string(tcb)})
	return b
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

// Package tdx verifies Intel TDX quotes from dstack CVMs: Intel signature chain and TCB via go-tdx-guest
// (Apache-2.0), report_data, and an RTMR3 replay of dstack's runtime event log.
package tdx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
)

// Quote is what a verified quote tells us.
type Quote struct {
	ReportData []byte
	MrTd       []byte
	Rtmrs      [4][]byte
	// TcbStatus is the TD's TCB status from Intel PCS collateral (e.g. UpToDate, OutOfDate): the worse of
	// PlatformStatus and ModuleStatus.
	TcbStatus string
	// PlatformStatus is the platform's TCB level (TCB info tcbLevels against the PCK certificate's CPU SVNs and PCESVN
	// and the quote's TEE_TCB_SVN): CPU microcode, SEAM loader and, before TDX module identities, the module too.
	PlatformStatus string
	// ModuleStatus is the TDX module's level (TCB info tdxModuleIdentities), when TEE_TCB_SVN[1] names a module
	// identity; "" when the platform level covers the module.
	ModuleStatus string
	QeStatus     string // the quoting enclave's level (QE identity)
	TcbDate      string // the older of the platform's and the module's TCB dates
	Debug        bool
	TdAttributes string // TD_ATTRIBUTES as in the quote (hex, little-endian)
}

// Verify checks the quote's Intel signature chain against fresh PCS collateral and revocation lists, the TD's
// attributes (no debug, not migratable, SEPT_VE_DISABLE, no PERFMON) and that no part of its TCB is Revoked. Any other
// TCB status is reported, not enforced, so the caller decides the policy.
func Verify(ctx context.Context, raw []byte) (*Quote, error) {
	return VerifyWith(ctx, raw, Options{})
}

// Options changes how collateral is fetched and when it is checked. The zero value is Verify's behaviour.
type Options struct {
	// Getter fetches Intel PCS URLs (TCB info, QE identity, PCK CRL, root CA CRL); nil = net/http. The browser build
	// passes one that goes through a same-origin relay: the responses are signed by Intel and checked here, so the
	// relay can withhold collateral (verification fails) but can't forge it.
	Getter trust.HTTPSGetter
	// Now is the time certificates and collateral are checked at; zero = now. Only tests set it (recorded collateral).
	Now time.Time
}

// VerifyWith is Verify with a custom collateral getter and clock.
func VerifyWith(ctx context.Context, raw []byte, o Options) (*Quote, error) {
	q, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("parse quote: %w", err)
	}
	v4, ok := q.(*pb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("quote %T not handled (v4 only)", q)
	}
	body := v4.GetTdQuoteBody()
	chain, err := verify.ExtractChainFromQuote(q)
	if err != nil {
		return nil, fmt.Errorf("PCK chain: %w", err)
	}
	exts, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		return nil, fmt.Errorf("PCK certificate extensions: %w", err)
	}
	opts := verify.DefaultOptions()
	opts.GetCollateral = true
	opts.CheckRevocations = true
	// The library's own status check stops at the first status that isn't UpToDate and says which only in its error
	// text; the levels are evaluated below instead, from the same signed collateral.
	opts.DisableTcbStatusCheck = true
	if o.Getter != nil {
		opts.Getter = o.Getter
	}
	// The TCB info and QE identity the library fetches and verifies (Intel's signature, FMSPC, PCEID, expiry) are
	// kept, so the levels below are read from exactly the bytes it checked.
	kept := &keepCollateral{inner: opts.Getter, keep: map[string][]byte{pcs.TcbInfoURL(exts.FMSPC): nil, pcs.QeIdentityURL(): nil}}
	opts.Getter = kept
	if !o.Now.IsZero() {
		opts.Now = &verify.TimeSet{PckCertChain: o.Now, TcbInfo: o.Now, QeIdentity: o.Now, PckCrl: o.Now, RootCaCrl: o.Now}
	}
	if err := verify.TdxQuoteContext(ctx, q, opts); err != nil {
		return nil, fmt.Errorf("intel verification: %w", err)
	}
	var tcbInfo pcs.TdxTcbInfo
	var qeIdentity pcs.QeIdentity
	if err := json.Unmarshal(kept.keep[pcs.TcbInfoURL(exts.FMSPC)], &tcbInfo); err != nil {
		return nil, fmt.Errorf("TCB info: %w", err)
	}
	if err := json.Unmarshal(kept.keep[pcs.QeIdentityURL()], &qeIdentity); err != nil {
		return nil, fmt.Errorf("QE identity: %w", err)
	}
	qeSvn := v4.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetQeReport().GetIsvSvn()
	out, err := tcbQuote(tcbInfo.TcbInfo, qeIdentity.EnclaveIdentity, body, exts, qeSvn)
	if err != nil {
		return nil, err
	}
	// The library's reading of the same collateral (the module level when TEE_TCB_SVN[1] > 0, else the platform's)
	// must agree with ours: a check that both read the same levels.
	libTcb, libQe, err := verify.SupportedTcbLevelsFromCollateral(q, opts)
	if err != nil {
		return nil, fmt.Errorf("tcb level: %w", err)
	}
	want := out.PlatformStatus
	if out.ModuleStatus != "" {
		want = out.ModuleStatus
	}
	if tcbStatus(libTcb.TcbStatus) != want || tcbStatus(libQe.TcbStatus) != out.QeStatus {
		return nil, fmt.Errorf("tcb level: go-tdx-guest reads %s (QE %s), this verifier %s (QE %s)", libTcb.TcbStatus, libQe.TcbStatus, want, out.QeStatus)
	}
	out.ReportData = body.GetReportData()
	out.MrTd = body.GetMrTd()
	out.Debug = body.GetTdAttributes()[0]&1 == 1
	out.TdAttributes = hex.EncodeToString(body.GetTdAttributes())
	for i, r := range body.GetRtmrs() {
		out.Rtmrs[i] = r
	}
	// Field validation through the library too: debug and migratable bits off, the fixed bits; then ours.
	if err := validate.TdxQuote(q, &validate.Options{TdQuoteBodyOptions: validate.TdQuoteBodyOptions{EnableTdDebugCheck: true,
		EnableTdMigratableCheck: true}}); err != nil {
		return out, fmt.Errorf("validate: %w", err)
	}
	if err := checkTdAttributes(body); err != nil {
		return out, err
	}
	return out, nil
}

// keepCollateral is a collateral getter that keeps the bodies of the URLs in keep as it passes them on.
type keepCollateral struct {
	inner trust.HTTPSGetter
	keep  map[string][]byte
}

func (k *keepCollateral) Get(url string) (map[string][]string, []byte, error) {
	return k.GetContext(context.Background(), url)
}

func (k *keepCollateral) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	h, b, err := trust.GetWith(ctx, k.inner, url)
	if _, ok := k.keep[url]; ok && err == nil {
		k.keep[url] = b
	}
	return h, b, err
}

// TD_ATTRIBUTES bits (Intel TDX module ABI, TDCS.ATTRIBUTES).
const (
	attrDebug         = uint64(1) << 0
	attrSeptVeDisable = uint64(1) << 28 // EPT violations aren't turned into #VE in the guest (zero-step attacks)
	attrMigratable    = uint64(1) << 29 // the host may migrate the TD (with its own migration TD)
	attrPerfmon       = uint64(1) << 63 // the TD uses the host's performance monitoring
)

// checkTdAttributes requires DEBUG=0, MIGRATABLE=0, SEPT_VE_DISABLE=1 and PERFMON=0, as Phala's TDs run
// (0x10000000). A TD started otherwise is refused loudly, even if a provider changes its default.
func checkTdAttributes(body *pb.TDQuoteBody) error {
	raw := body.GetTdAttributes()
	if len(raw) != 8 {
		return fmt.Errorf("TD attributes: %d bytes", len(raw))
	}
	a := binary.LittleEndian.Uint64(raw)
	for _, c := range []struct {
		name string
		bit  uint64
		want bool
	}{{"DEBUG", attrDebug, false}, {"MIGRATABLE", attrMigratable, false}, {"SEPT_VE_DISABLE", attrSeptVeDisable, true},
		{"PERFMON", attrPerfmon, false}} {
		if (a&c.bit != 0) != c.want {
			return fmt.Errorf("TD attributes %#x: %s must be %v", a, c.name, map[bool]int{false: 0, true: 1}[c.want])
		}
	}
	return nil
}

// statusRank orders Intel's TCB statuses from best to worst; a status not listed ranks worst.
var statusRank = map[pcs.TcbComponentStatus]int{
	pcs.TcbComponentStatusUpToDate:                           0,
	pcs.TcbComponentStatusSwHardeningNeeded:                  1,
	pcs.TcbComponentStatusConfigurationNeeded:                2,
	pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded:  3,
	pcs.TcbComponentStatusOutOfDate:                          4,
	pcs.TcbComponentStatusOutOfDateConfigurationNeeded:       5,
	pcs.TcbComponentStatusRelaunchAdvisedConfigurationNeeded: 5,
	pcs.TcbComponentStatusRevoked:                            6,
}

func rank(s pcs.TcbComponentStatus) int {
	if r, ok := statusRank[s]; ok {
		return r
	}
	return 7
}

// worse is the worse of two statuses; an out-of-date part with a part that needs configuration is
// OutOfDateConfigurationNeeded, as Intel's QVL reports it.
func worse(a, b pcs.TcbComponentStatus) pcs.TcbComponentStatus {
	if rank(b) > rank(a) {
		a, b = b, a
	}
	if a == pcs.TcbComponentStatusOutOfDate && (b == pcs.TcbComponentStatusConfigurationNeeded || b == pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded) {
		return pcs.TcbComponentStatusOutOfDateConfigurationNeeded
	}
	return a
}

// tcbQuote evaluates the TD's TCB from Intel's (verified) TCB info and QE identity, as Intel's QVL does: the platform
// level is the first of tcbLevels whose SGX components and PCESVN the PCK certificate meets and whose TDX components
// TEE_TCB_SVN meets (from byte 2 when byte 1 names a TDX module identity); the module level is that identity's first
// level whose isvsvn TEE_TCB_SVN[0] meets; the QE level is the QE identity's first level whose isvsvn the QE report
// meets. The TD's status is the worse of the platform's and the module's. Revoked, or a status this code doesn't know,
// in any part is refused.
func tcbQuote(info pcs.TcbInfo, qe pcs.EnclaveIdentity, body *pb.TDQuoteBody, exts *pcs.PckExtensions, qeSvn uint32) (*Quote, error) {
	svn := body.GetTeeTcbSvn()
	if len(svn) != 16 {
		return nil, fmt.Errorf("TEE_TCB_SVN: %d bytes", len(svn))
	}
	from := 0
	if svn[1] > 0 {
		from = 2
	}
	var platform *pcs.TcbLevel
	for i, l := range info.TcbLevels {
		if meets(exts.TCB.CPUSvnComponents, l.Tcb.SgxTcbcomponents, 0) && exts.TCB.PCESvn >= l.Tcb.Pcesvn &&
			meets(svn, l.Tcb.TdxTcbcomponents, from) {
			platform = &info.TcbLevels[i]
			break
		}
	}
	if platform == nil {
		return nil, fmt.Errorf("tcb level: no TCB level of FMSPC %s matches this platform", info.Fmspc)
	}
	out := &Quote{PlatformStatus: tcbStatus(platform.TcbStatus), TcbDate: platform.TcbDate}
	status := platform.TcbStatus
	if svn[1] > 0 {
		id := fmt.Sprintf("TDX_%02X", svn[1])
		var module *pcs.TcbLevel
		for _, m := range info.TdxModuleIdentities {
			if strings.EqualFold(m.ID, id) {
				for i, l := range m.TcbLevels {
					if uint32(svn[0]) >= l.Tcb.Isvsvn {
						module = &m.TcbLevels[i]
						break
					}
				}
				break
			}
		}
		if module == nil {
			return nil, fmt.Errorf("tcb level: no level of TDX module identity %s matches TDX module SVN %d", id, svn[0])
		}
		out.ModuleStatus = tcbStatus(module.TcbStatus)
		status = worse(status, module.TcbStatus)
		if module.TcbDate != "" && module.TcbDate < out.TcbDate {
			out.TcbDate = module.TcbDate
		}
	}
	out.TcbStatus = tcbStatus(status)
	var qeLevel *pcs.TcbLevel
	for i, l := range qe.TcbLevels {
		if qeSvn >= l.Tcb.Isvsvn {
			qeLevel = &qe.TcbLevels[i]
			break
		}
	}
	if qeLevel == nil {
		return nil, fmt.Errorf("tcb level: no QE identity level matches QE SVN %d", qeSvn)
	}
	out.QeStatus = tcbStatus(qeLevel.TcbStatus)
	for _, c := range []struct {
		what string
		st   pcs.TcbComponentStatus
	}{{"TCB", status}, {"QE TCB", qeLevel.TcbStatus}} {
		if rank(c.st) >= rank(pcs.TcbComponentStatusRevoked) {
			return out, fmt.Errorf("%s status %s (platform %s, TDX module %s, QE %s): refused", c.what, c.st, out.PlatformStatus,
				out.ModuleStatus, out.QeStatus)
		}
	}
	return out, nil
}

// meets says whether every component SVN from index from on is at least the level's.
func meets(svns []byte, level []pcs.TcbComponent, from int) bool {
	if len(svns) != len(level) {
		return false
	}
	for i := from; i < len(svns); i++ {
		if svns[i] < level[i].Svn {
			return false
		}
	}
	return true
}

func tcbStatus(s any) string {
	b, _ := json.Marshal(s)
	return string(bytes.Trim(b, `"`))
}

// Event is one entry of dstack's event log.
type Event struct {
	IMR          int    `json:"imr"`
	EventType    uint32 `json:"event_type"`
	Digest       string `json:"digest"`
	Event        string `json:"event"`
	EventPayload string `json:"event_payload"`
	Version      *int   `json:"version,omitempty"`
}

const runtimeEventType = 0x08000001

// runtimeDigest recomputes an RTMR3 event digest instead of trusting the log (dstack cc-eventlog V1 and V2).
func runtimeDigest(e Event) ([]byte, error) {
	payload, err := hex.DecodeString(e.EventPayload)
	if err != nil {
		return nil, err
	}
	if e.Version != nil && *e.Version >= 2 {
		// V2: sha384 over canonical JSON {"name","payload","type"} (keys already sorted).
		j, _ := json.Marshal(struct {
			Name    string `json:"name"`
			Payload string `json:"payload"`
			Type    uint32 `json:"type"`
		}{e.Event, e.EventPayload, runtimeEventType})
		h := sha512.Sum384(j)
		return h[:], nil
	}
	h := sha512.New384()
	binary.Write(h, binary.LittleEndian, uint32(runtimeEventType))
	h.Write([]byte(":" + e.Event + ":"))
	h.Write(payload)
	return h.Sum(nil), nil
}

// Runtime is the RTMR3 replay result plus the payloads of the events we care about.
type Runtime struct {
	RTMR3  []byte
	Events []Event
	// Values holds the boot-time events only: those dstack's guest measured before "system-ready", name -> payload
	// (hex), each the one and only event of its name (see bootValues).
	Values map[string]string
}

// SystemReady is the event dstack's guest (dstack-util) measures last, when it has set the system up and before it
// starts the app. Events after it are the app's: any root process in the CVM can extend RTMR3 and append to the log
// (dstack-util extend, the TDX guest device), so a value read past it is whatever the app chose.
const SystemReady = "system-ready"

// systemEvents are the names dstack's guest measures into RTMR3 while it boots (dstack-util system_setup.rs, 0.5 to
// 0.6.5). Their values are trusted only before SystemReady; one of these names after it is a forgery attempt.
var systemEvents = map[string]bool{
	"system-preparing": true, "app-id": true, "compose-hash": true, "init-script-hash": true, "gpu-policy-hash": true,
	"instance-id": true, "boot-mr-done": true, "mr-kms": true, "os-image-hash": true, "key-provider": true,
	"gpu-attestation": true, "storage-fs": true, "storage-encrypted": true, "rootfs-hash": true, SystemReady: true,
}

// repeatable boot events: dstack measures one init-script-hash per init script, in order.
var repeatable = map[string]bool{"init-script-hash": true}

// ReplayRTMR3 replays the imr=3 events from 48 zero bytes (the whole log: it must equal the quote's RTMR3) and reads
// the boot-time values. Earlier IMRs come from the host and aren't trusted.
func ReplayRTMR3(eventLog []Event) (*Runtime, error) {
	mr := make([]byte, 48)
	rt := &Runtime{}
	for _, e := range eventLog {
		if e.IMR != 3 {
			continue
		}
		d, err := runtimeDigest(e)
		if err != nil {
			return nil, fmt.Errorf("event %s: %w", e.Event, err)
		}
		if e.Digest != "" && e.Digest != hex.EncodeToString(d) {
			return nil, fmt.Errorf("event %s: logged digest doesn't match its payload", e.Event)
		}
		h := sha512.New384()
		h.Write(mr)
		h.Write(d)
		mr = h.Sum(nil)
		rt.Events = append(rt.Events, e)
	}
	v, err := bootValues(rt.Events)
	if err != nil {
		return nil, err
	}
	rt.Values = v
	rt.RTMR3 = mr
	return rt, nil
}

// bootValues reads the RTMR3 events up to and including the first SystemReady, as dstack's own verifier does
// (dstack-attest attestation.rs find_event: the first match, stopping at system-ready, "events after system-ready are
// application-controlled"). Stricter than upstream, it refuses a log that has no SystemReady, a boot event measured
// twice (except init-script-hash) and any system event name after SystemReady, so no reader can take a later value.
func bootValues(events []Event) (map[string]string, error) {
	values := map[string]string{}
	ready := false
	for _, e := range events {
		if ready {
			if systemEvents[e.Event] {
				return nil, fmt.Errorf("event log: %q after %s (an app-measured event with a system event's name)", e.Event, SystemReady)
			}
			continue
		}
		if e.Event == SystemReady {
			ready = true
			continue
		}
		if _, dup := values[e.Event]; dup && !repeatable[e.Event] {
			return nil, fmt.Errorf("event log: boot event %q measured twice", e.Event)
		}
		if _, seen := values[e.Event]; !seen {
			values[e.Event] = e.EventPayload
		}
	}
	if !ready {
		return nil, fmt.Errorf("event log: no %s event (the VM hasn't finished booting)", SystemReady)
	}
	return values, nil
}

// CheckApp ties a quote to an app: RTMR3 replays to the quoted value and the boot-time compose-hash event equals
// sha256(appCompose), where appCompose is dstack's app-compose.json bytes.
func CheckApp(q *Quote, eventLog []Event, appCompose []byte) (*Runtime, error) {
	rt, err := ReplayRTMR3(eventLog)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(rt.RTMR3, q.Rtmrs[3]) {
		return rt, fmt.Errorf("RTMR3 replay %x doesn't match the quote %x", rt.RTMR3, q.Rtmrs[3])
	}
	h := sha256.Sum256(appCompose)
	if got := rt.Values["compose-hash"]; got != hex.EncodeToString(h[:]) {
		return rt, fmt.Errorf("compose-hash event %s != sha256(app_compose) %x", got, h)
	}
	return rt, nil
}

// ParseEventLog accepts the event log as a JSON string or array.
func ParseEventLog(raw json.RawMessage) ([]Event, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		raw = []byte(s)
	}
	var ev []Event
	return ev, json.Unmarshal(raw, &ev)
}

// ReplayFirmware replays RTMR0-2 from the firmware part of the event log (digests as logged; the replay proves
// the log is the one the quote covers) and returns the RTMR1 digests, where UEFI measures boot applications.
func ReplayFirmware(q *Quote, eventLog []Event) (bootApps []string, err error) {
	for i := 0; i < 3; i++ {
		mr := make([]byte, 48)
		for _, e := range eventLog {
			if e.IMR != i || e.EventType == 3 { // EV_NO_ACTION isn't extended
				continue
			}
			d, err := hex.DecodeString(e.Digest)
			if err != nil || len(d) != 48 {
				return nil, fmt.Errorf("RTMR%d event: bad digest %q", i, e.Digest)
			}
			h := sha512.New384()
			h.Write(mr)
			h.Write(d)
			mr = h.Sum(nil)
			if i == 1 && e.EventType == 0x80000003 { // EV_EFI_BOOT_SERVICES_APPLICATION
				bootApps = append(bootApps, e.Digest)
			}
		}
		if !bytes.Equal(mr, q.Rtmrs[i]) {
			return nil, fmt.Errorf("RTMR%d replay %x doesn't match the quote %x", i, mr, q.Rtmrs[i])
		}
	}
	return bootApps, nil
}

// Parse reads a quote's fields without verifying anything. Only for offline tests of the checks that follow
// quote verification (report_data binding, RTMR3 replay, compose); never use it to trust a quote.
func Parse(raw []byte) (*Quote, error) {
	q, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, err
	}
	v4, ok := q.(*pb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("not a v4 quote")
	}
	body := v4.GetTdQuoteBody()
	out := &Quote{ReportData: body.GetReportData(), MrTd: body.GetMrTd(), TcbStatus: "not checked (parsed only)",
		Debug: body.GetTdAttributes()[0]&1 == 1}
	for i, r := range body.GetRtmrs() {
		out.Rtmrs[i] = r
	}
	return out, nil
}

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
	"time"

	"github.com/google/go-tdx-guest/abi"
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
	TcbStatus  string // from Intel PCS collateral, e.g. UpToDate, OutOfDate
	QeStatus   string
	TcbDate    string
	Debug      bool
}

// Verify checks the quote's Intel signature chain against fresh PCS collateral and revocation lists.
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
	opts := verify.DefaultOptions()
	opts.GetCollateral = true
	opts.CheckRevocations = true
	opts.DisableTcbStatusCheck = true
	if o.Getter != nil {
		opts.Getter = o.Getter
	}
	if !o.Now.IsZero() {
		opts.Now = &verify.TimeSet{PckCertChain: o.Now, TcbInfo: o.Now, QeIdentity: o.Now, PckCrl: o.Now, RootCaCrl: o.Now}
	}
	if err := verify.TdxQuoteContext(ctx, q, opts); err != nil {
		return nil, fmt.Errorf("intel verification: %w", err)
	}
	tcb, qe, err := verify.SupportedTcbLevelsFromCollateral(q, opts)
	if err != nil {
		return nil, fmt.Errorf("tcb level: %w", err)
	}
	var body *pb.TDQuoteBody
	switch v := q.(type) {
	case *pb.QuoteV4:
		body = v.GetTdQuoteBody()
	case *pb.QuoteV5:
		return nil, fmt.Errorf("quote v5 not handled in this POC")
	}
	out := &Quote{
		ReportData: body.GetReportData(),
		MrTd:       body.GetMrTd(),
		TcbStatus:  tcbStatus(tcb.TcbStatus),
		QeStatus:   tcbStatus(qe.TcbStatus),
		TcbDate:    tcb.TcbDate,
		Debug:      body.GetTdAttributes()[0]&1 == 1,
	}
	for i, r := range body.GetRtmrs() {
		out.Rtmrs[i] = r
	}
	// Re-run field validation through the library too (debug bit off).
	if err := validate.TdxQuote(q, &validate.Options{TdQuoteBodyOptions: validate.TdQuoteBodyOptions{EnableTdDebugCheck: true}}); err != nil {
		return out, fmt.Errorf("validate: %w", err)
	}
	return out, nil
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
	Values map[string]string // event name -> payload (hex), last one wins
}

// ReplayRTMR3 replays the imr=3 events from 48 zero bytes. Earlier IMRs come from the host and aren't trusted.
func ReplayRTMR3(eventLog []Event) (*Runtime, error) {
	mr := make([]byte, 48)
	rt := &Runtime{Values: map[string]string{}}
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
		rt.Values[e.Event] = e.EventPayload
	}
	rt.RTMR3 = mr
	return rt, nil
}

// CheckApp ties a quote to an app: RTMR3 replays to the quoted value and the compose-hash event equals
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

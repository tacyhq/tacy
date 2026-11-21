package tdx

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

// The recorded quotes come from Phala prod5 hosts (FMSPC 20a06f000000). Their TEE_TCB_SVN is 0b 01 05 00..: byte 1
// (the TDX module's major version) is 1, so Intel's TCB evaluation has two parts, the platform level (TcbInfo's
// tcbLevels against the PCK certificate's CPU SVNs and PCESVN, and TEE_TCB_SVN from byte 2) and the TDX module level
// (tdxModuleIdentities "TDX_01" against TEE_TCB_SVN byte 0). go-tdx-guest's SupportedTcbLevelsFromCollateral returns
// only the module's when byte 1 is set, so a host whose CPU or SEAM loader Intel marked OutOfDate or Revoked was
// reported UpToDate. Intel's collateral is signed, so these tests edit a parsed copy of the recorded collateral and
// evaluate it with the same code VerifyWith runs after the signatures checked.

// collateralTime is when testdata/intel-collateral-20261121.json was fetched from Intel PCS (all of it valid then).
var collateralTime = time.Date(2026, 11, 21, 0, 27, 0, 0, time.UTC)

const recordedTcbInfoURL = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=20a06f000000"
const recordedQeURL = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"

// replay serves recorded Intel PCS responses; edit may change a body before it is served.
type replay struct {
	resp map[string]struct {
		Header map[string][]string `json:"header"`
		Body   string              `json:"body"`
	}
	edit func(url string, body []byte) []byte
}

func (r *replay) Get(url string) (map[string][]string, []byte, error) {
	e, ok := r.resp[url]
	if !ok {
		return nil, nil, errors.New("not recorded: " + url)
	}
	b, _ := base64.StdEncoding.DecodeString(e.Body)
	if r.edit != nil {
		b = r.edit(url, b)
	}
	return e.Header, b, nil
}

func loadReplay(t *testing.T) *replay {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/intel-collateral-20261121.json")
	if err != nil {
		t.Fatal(err)
	}
	r := &replay{}
	if err := json.Unmarshal(raw, &r.resp); err != nil {
		t.Fatal(err)
	}
	return r
}

func recordedQuote(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Quote struct {
			Quote string `json:"quote"`
		} `json:"quote"`
	}
	json.Unmarshal(raw, &a)
	q, err := hex.DecodeString(a.Quote.Quote)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// recorded is a recorded quote's parts that the TCB evaluation reads, with the recorded collateral (parsed).
type recorded struct {
	body  *pb.TDQuoteBody
	exts  *pcs.PckExtensions
	qeSvn uint32
	info  pcs.TcbInfo
	qe    pcs.EnclaveIdentity
}

func loadRecorded(t *testing.T) *recorded {
	t.Helper()
	q, err := abi.QuoteToProto(recordedQuote(t, "attest-064.json"))
	if err != nil {
		t.Fatal(err)
	}
	v4 := q.(*pb.QuoteV4)
	chain, err := verify.ExtractChainFromQuote(q)
	if err != nil {
		t.Fatal(err)
	}
	exts, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		t.Fatal(err)
	}
	r := loadReplay(t)
	_, tb, _ := r.Get(recordedTcbInfoURL)
	_, qb, _ := r.Get(recordedQeURL)
	var ti pcs.TdxTcbInfo
	var qi pcs.QeIdentity
	if json.Unmarshal(tb, &ti) != nil || json.Unmarshal(qb, &qi) != nil {
		t.Fatal("recorded collateral doesn't parse")
	}
	return &recorded{body: v4.GetTdQuoteBody(), exts: exts,
		qeSvn: v4.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetQeReport().GetIsvSvn(),
		info:  ti.TcbInfo, qe: qi.EnclaveIdentity}
}

// copyLevels deep-copies the level slices the tests edit.
func (r *recorded) copyLevels() {
	r.info.TcbLevels = append([]pcs.TcbLevel{}, r.info.TcbLevels...)
	for i := range r.info.TcbLevels {
		l := &r.info.TcbLevels[i]
		l.Tcb.SgxTcbcomponents = append([]pcs.TcbComponent{}, l.Tcb.SgxTcbcomponents...)
	}
	ids := append([]pcs.TdxModuleIdentity{}, r.info.TdxModuleIdentities...)
	for i := range ids {
		ids[i].TcbLevels = append([]pcs.TcbLevel{}, ids[i].TcbLevels...)
	}
	r.info.TdxModuleIdentities = ids
	r.qe.TcbLevels = append([]pcs.TcbLevel{}, r.qe.TcbLevels...)
}

func (r *recorded) module(t *testing.T, id string) *pcs.TdxModuleIdentity {
	t.Helper()
	for i := range r.info.TdxModuleIdentities {
		if r.info.TdxModuleIdentities[i].ID == id {
			return &r.info.TdxModuleIdentities[i]
		}
	}
	t.Fatalf("no module identity %s", id)
	return nil
}

// The recordings: TEE_TCB_SVN byte 1 is set (so the old code reported only the module level) and the host is
// UpToDate on every part in the recorded collateral.
func TestRecordedTCBLevels(t *testing.T) {
	r := loadRecorded(t)
	if svn := r.body.GetTeeTcbSvn(); svn[1] == 0 {
		t.Fatalf("tee_tcb_svn %x: byte 1 is 0, the test premise doesn't hold", svn)
	}
	q, err := tcbQuote(r.info, r.qe, r.body, r.exts, r.qeSvn)
	if err != nil {
		t.Fatal(err)
	}
	if q.TcbStatus != "UpToDate" || q.PlatformStatus != "UpToDate" || q.ModuleStatus != "UpToDate" || q.QeStatus != "UpToDate" ||
		q.TcbDate != "2025-08-13T00:00:00Z" {
		t.Fatalf("recorded: %+v", q)
	}
}

// Each case edits Intel's (parsed) collateral the way a TCB recovery or a revocation would, and says what VerifyWith
// must report or refuse. The module level stays UpToDate in the platform cases: those are the ones the old code
// reported as UpToDate.
func TestTCBLevelsEdited(t *testing.T) {
	cases := []struct {
		name       string
		edit       func(t *testing.T, r *recorded)
		tcb, qe    string
		date       string
		refuse     string // VerifyWith refuses with this in the error
		platform   string
		moduleWant string
	}{
		{name: "platform level revoked", tcb: "Revoked", refuse: "Revoked", edit: func(_ *testing.T, r *recorded) {
			r.info.TcbLevels[0].TcbStatus = pcs.TcbComponentStatusRevoked
		}},
		{name: "platform level out of date", tcb: "OutOfDate", qe: "UpToDate", platform: "OutOfDate", moduleWant: "UpToDate", edit: func(_ *testing.T, r *recorded) {
			r.info.TcbLevels[0].TcbStatus = pcs.TcbComponentStatusOutOfDate
		}},
		{name: "new CPU microcode released, this host not updated", tcb: "OutOfDate", qe: "UpToDate", date: "2025-05-14T00:00:00Z",
			platform: "OutOfDate", moduleWant: "UpToDate", edit: func(_ *testing.T, r *recorded) {
				// Intel adds a level above the host's CPU SVNs; the host now matches the next one down (OutOfDate).
				top := r.info.TcbLevels[0]
				top.Tcb.SgxTcbcomponents = append([]pcs.TcbComponent{}, top.Tcb.SgxTcbcomponents...)
				top.Tcb.SgxTcbcomponents[0].Svn++
				top.TcbDate = "2026-11-11T00:00:00Z"
				r.info.TcbLevels[0].TcbStatus = pcs.TcbComponentStatusOutOfDate
				r.info.TcbLevels[0].TcbDate = "2025-05-14T00:00:00Z"
				r.info.TcbLevels = append([]pcs.TcbLevel{top}, r.info.TcbLevels...)
			}},
		{name: "platform needs configuration", tcb: "ConfigurationNeeded", qe: "UpToDate", platform: "ConfigurationNeeded", moduleWant: "UpToDate",
			edit: func(_ *testing.T, r *recorded) {
				r.info.TcbLevels[0].TcbStatus = pcs.TcbComponentStatusConfigurationNeeded
			}},
		{name: "platform needs configuration, module out of date", tcb: "OutOfDateConfigurationNeeded", qe: "UpToDate",
			platform: "ConfigurationNeeded", moduleWant: "OutOfDate", edit: func(t *testing.T, r *recorded) {
				r.info.TcbLevels[0].TcbStatus = pcs.TcbComponentStatusConfigurationNeeded
				r.module(t, "TDX_01").TcbLevels[0].TcbStatus = pcs.TcbComponentStatusOutOfDate
			}},
		{name: "TDX module revoked", tcb: "Revoked", refuse: "Revoked", edit: func(t *testing.T, r *recorded) {
			r.module(t, "TDX_01").TcbLevels[0].TcbStatus = pcs.TcbComponentStatusRevoked
		}},
		{name: "TDX module out of date", tcb: "OutOfDate", qe: "UpToDate", platform: "UpToDate", moduleWant: "OutOfDate", edit: func(t *testing.T, r *recorded) {
			r.module(t, "TDX_01").TcbLevels[0].TcbStatus = pcs.TcbComponentStatusOutOfDate
		}},
		{name: "quoting enclave out of date", tcb: "UpToDate", qe: "OutOfDate", platform: "UpToDate", moduleWant: "UpToDate", edit: func(_ *testing.T, r *recorded) {
			r.qe.TcbLevels = []pcs.TcbLevel{{Tcb: pcs.Tcb{Isvsvn: r.qeSvn + 2}, TcbStatus: pcs.TcbComponentStatusUpToDate, TcbDate: "2026-11-11T00:00:00Z"},
				{Tcb: pcs.Tcb{Isvsvn: r.qeSvn}, TcbStatus: pcs.TcbComponentStatusOutOfDate, TcbDate: "2024-03-13T00:00:00Z"}}
		}},
		{name: "quoting enclave revoked", qe: "Revoked", refuse: "QE TCB status Revoked", edit: func(_ *testing.T, r *recorded) {
			r.qe.TcbLevels[0].TcbStatus = pcs.TcbComponentStatusRevoked
		}},
		{name: "a status Intel may add later counts as the worst", tcb: "SomethingNew", refuse: "SomethingNew", edit: func(_ *testing.T, r *recorded) {
			r.info.TcbLevels[0].TcbStatus = "SomethingNew"
		}},
		{name: "no platform level matches", refuse: "no TCB level", edit: func(_ *testing.T, r *recorded) {
			r.info.TcbLevels = r.info.TcbLevels[:0]
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := loadRecorded(t)
			r.copyLevels()
			c.edit(t, r)
			q, err := tcbQuote(r.info, r.qe, r.body, r.exts, r.qeSvn)
			if c.refuse != "" {
				if err == nil || !strings.Contains(err.Error(), c.refuse) {
					t.Fatalf("want refused (%s), got %v %+v", c.refuse, err, q)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if q.TcbStatus != c.tcb || q.QeStatus != c.qe || q.PlatformStatus != c.platform || q.ModuleStatus != c.moduleWant {
				t.Fatalf("got TCB %s (platform %s, module %s), QE %s; want %s (platform %s, module %s), QE %s",
					q.TcbStatus, q.PlatformStatus, q.ModuleStatus, q.QeStatus, c.tcb, c.platform, c.moduleWant, c.qe)
			}
			if c.date != "" && q.TcbDate != c.date {
				t.Fatalf("TCB date %s, want %s", q.TcbDate, c.date)
			}
		})
	}
}

// The full VerifyWith on the recorded quotes and Intel's recorded collateral (signatures, CRLs, the TCB levels).
func TestVerifyRecordedCollateral(t *testing.T) {
	for _, name := range []string{"attest-064.json", "attest-061.json"} {
		q, err := VerifyWith(context.Background(), recordedQuote(t, name), Options{Getter: loadReplay(t), Now: collateralTime})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if q.TcbStatus != "UpToDate" || q.PlatformStatus != "UpToDate" || q.ModuleStatus != "UpToDate" || q.QeStatus != "UpToDate" ||
			q.TdAttributes != "0000001000000000" {
			t.Fatalf("%s: %+v", name, q)
		}
	}
}

// Edited collateral never reaches the evaluation: Intel's signature over the TCB info fails first.
func TestVerifyEditedCollateralRefused(t *testing.T) {
	r := loadReplay(t)
	r.edit = func(url string, b []byte) []byte {
		if url == recordedTcbInfoURL {
			return []byte(strings.Replace(string(b), `"tcbStatus":"UpToDate"`, `"tcbStatus":"OutOfDate"`, 1))
		}
		return b
	}
	if _, err := VerifyWith(context.Background(), recordedQuote(t, "attest-064.json"), Options{Getter: r, Now: collateralTime}); err == nil {
		t.Fatal("edited TCB info accepted")
	}
}

// TD attributes (TDX module ABI, TDCS.ATTRIBUTES): DEBUG bit 0, SEPT_VE_DISABLE bit 28, MIGRATABLE bit 29, PERFMON
// bit 63. Phala's TDs are 0x10000000: SEPT_VE_DISABLE only.
func TestTdAttributes(t *testing.T) {
	r := loadRecorded(t)
	if got := hex.EncodeToString(r.body.GetTdAttributes()); got != "0000001000000000" {
		t.Fatalf("recorded td_attributes %s", got)
	}
	if err := checkTdAttributes(r.body); err != nil {
		t.Fatalf("recorded: %v", err)
	}
	for _, c := range []struct {
		name       string
		set, unset uint64
	}{
		{"DEBUG", 1 << 0, 0},
		{"MIGRATABLE", 1 << 29, 0},
		{"SEPT_VE_DISABLE", 0, 1 << 28},
		{"PERFMON", 1 << 63, 0},
	} {
		a := (binary.LittleEndian.Uint64(r.body.GetTdAttributes()) | c.set) &^ c.unset
		attrs := make([]byte, 8)
		binary.LittleEndian.PutUint64(attrs, a)
		body := &pb.TDQuoteBody{TdAttributes: attrs}
		if err := checkTdAttributes(body); err == nil || !strings.Contains(err.Error(), c.name) {
			t.Fatalf("%s (td_attributes %x): want refused naming it, got %v", c.name, attrs, err)
		}
	}
}

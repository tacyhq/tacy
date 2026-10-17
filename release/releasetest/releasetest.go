// Package releasetest makes Sigstore bundles that look like this repository's releases, signed by a throwaway
// Sigstore: a Fulcio CA, a CT log and a Rekor log with fresh keys (tests only). Certificates carry GitHub's Fulcio
// extensions and an embedded SCT; the Rekor entry has an inclusion proof, a signed checkpoint and a signed entry
// timestamp, like GitHub's bundles. The verifier then runs with its production thresholds against this trusted
// root instead of Sigstore's.
//
// It follows sigstore-go's virtual Sigstore (pkg/testing/ca), which can't be used directly: it issues email
// certificates without GitHub's extensions or SCTs, and it imports all of Rekor's key formats (more modules in
// go.sum, which compose.yaml embeds). Everything here is already in the verifier's dependency graph.
package releasetest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekortypes "github.com/sigstore/rekor/pkg/types"
	rekordsse "github.com/sigstore/rekor/pkg/types/dsse"
	_ "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	rekorutil "github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"

	"github.com/tacyhq/tacy/release"
)

// Sigstore is a throwaway Fulcio CA, CT log and Rekor log.
type Sigstore struct {
	root, inter     *x509.Certificate
	interKey        *ecdsa.PrivateKey
	ctKey, rekorKey *ecdsa.PrivateKey
	ctLogID         [32]byte
	rekorLogID      [32]byte
	createdAt       time.Time
}

func newKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func logID(k *ecdsa.PrivateKey) [32]byte {
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		panic(err)
	}
	return sha256.Sum256(der)
}

// New makes a Sigstore whose keys are valid from an hour ago to an hour from now.
func New() (*Sigstore, error) {
	now := time.Now()
	rootKey, interKey := newKey(), newKey()
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "sigstore", Organization: []string{"sigstore.test"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	interTmpl := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject:   pkix.Name{CommonName: "sigstore-intermediate", Organization: []string{"sigstore.test"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, interKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	interCert, _ := x509.ParseCertificate(interDER)
	s := &Sigstore{root: rootCert, inter: interCert, interKey: interKey, ctKey: newKey(), rekorKey: newKey(), createdAt: now}
	s.ctLogID, s.rekorLogID = logID(s.ctKey), logID(s.rekorKey)
	return s, nil
}

// Trusted is the trusted root to verify this Sigstore's bundles with (release.Policy.Trusted).
func (s *Sigstore) Trusted() root.TrustedMaterial {
	start, end := s.createdAt.Add(-time.Hour), s.createdAt.Add(time.Hour)
	ctlogs := map[string]*root.TransparencyLog{hex.EncodeToString(s.ctLogID[:]): {
		BaseURL: "https://ctlog.localhost", ID: s.ctLogID[:], HashFunc: crypto.SHA256, PublicKey: s.ctKey.Public(),
		ValidityPeriodStart: start, ValidityPeriodEnd: end,
	}}
	rekor := map[string]*root.TransparencyLog{hex.EncodeToString(s.rekorLogID[:]): {
		BaseURL: "https://rekor.localhost", ID: s.rekorLogID[:], HashFunc: crypto.SHA256, PublicKey: s.rekorKey.Public(),
		SignatureHashFunc: crypto.SHA256, ValidityPeriodStart: start, ValidityPeriodEnd: end,
	}}
	cas := []root.CertificateAuthority{&root.FulcioCertificateAuthority{Root: s.root,
		Intermediates: []*x509.Certificate{s.inter}, URI: "https://fulcio.localhost",
		ValidityPeriodStart: start, ValidityPeriodEnd: end}}
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01, cas, ctlogs, nil, rekor)
	if err != nil {
		panic(err)
	}
	return tr
}

// Options describe one release bundle. The zero value plus Subjects is a valid release v1.0.0 of tacyhq/tacy.
type Options struct {
	Repo     string // default release.Repo
	RepoID   string // default release.RepoID
	OwnerID  string // default release.OwnerID
	NoIDs    bool   // no repository and owner id extensions (certificates before Fulcio added them)
	Workflow string // default release.Workflow
	Ref      string // default refs/tags/<Version>; e.g. refs/heads/main for a branch build
	Version  string // default v1.0.0
	Trigger  string // default push
	Runner   string // default github-hosted
	Issuer   string // default release.Issuer
	// Subjects are the in-toto subjects, name to sha256. Required.
	Subjects      map[string][]byte
	PredicateType string // default release.PredicateType
	NoTlog        bool   // no transparency log entry
	NoSCT         bool   // no embedded SCT
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func oid(n int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, n} }

func utf8Ext(n int, v string) pkix.Extension {
	b, _ := asn1.MarshalWithParams(v, "utf8")
	return pkix.Extension{Id: oid(n), Value: b}
}

// Bundle signs an in-toto statement for o.Subjects and returns the bundle as JSON (v0.3, as GitHub makes them).
func (s *Sigstore) Bundle(o Options) ([]byte, error) {
	ctx := context.Background()
	repo := or(o.Repo, release.Repo)
	version := or(o.Version, "v1.0.0")
	ref := or(o.Ref, "refs/tags/"+version)
	issuer := or(o.Issuer, release.Issuer)
	workflow := or(o.Workflow, release.Workflow)
	san := "https://github.com/" + repo + "/" + workflow + "@" + ref
	commit := "0123456789abcdef0123456789abcdef01234567"

	// Fulcio: a leaf for the workflow identity, with GitHub's extensions and an embedded SCT.
	key := newKey()
	sanURL, _ := url.Parse(san)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:         []*url.URL{sanURL},
		ExtraExtensions: []pkix.Extension{
			{Id: oid(1), Value: []byte(issuer)},
			utf8Ext(8, issuer),
			utf8Ext(9, san),
			utf8Ext(10, commit),
			utf8Ext(11, or(o.Runner, "github-hosted")),
			utf8Ext(12, "https://github.com/"+repo),
			utf8Ext(13, commit),
			utf8Ext(14, ref),
			utf8Ext(16, "https://github.com/"+strings.Split(repo, "/")[0]),
			utf8Ext(18, san),
			utf8Ext(19, commit),
			utf8Ext(20, or(o.Trigger, "push")),
			utf8Ext(21, "https://github.com/"+repo+"/actions/runs/1/attempts/1"),
		},
	}
	if !o.NoIDs {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, utf8Ext(15, or(o.RepoID, release.RepoID)),
			utf8Ext(17, or(o.OwnerID, release.OwnerID)))
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, s.inter, key.Public(), s.interKey)
	if err != nil {
		return nil, err
	}
	if !o.NoSCT {
		pre, _ := x509.ParseCertificate(leafDER)
		sctExt, err := s.sct(pre.RawTBSCertificate, now)
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, sctExt)
		if leafDER, err = x509.CreateCertificate(rand.Reader, tmpl, s.inter, key.Public(), s.interKey); err != nil {
			return nil, err
		}
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}

	// The in-toto statement, DSSE-signed by the leaf key.
	type subject struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	}
	var subjects []subject
	for name, d := range o.Subjects {
		subjects = append(subjects, subject{name, map[string]string{"sha256": hex.EncodeToString(d)}})
	}
	statement, _ := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       subjects,
		"predicateType": or(o.PredicateType, release.PredicateType),
		"predicate": map[string]any{"buildDefinition": map[string]any{
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"externalParameters": map[string]any{"workflow": map[string]any{
				"ref": ref, "repository": "https://github.com/" + repo, "path": workflow}},
		}},
	})
	signer, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	es, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: signer, Pub: &key.PublicKey})
	if err != nil {
		return nil, err
	}
	env, err := es.SignPayload(ctx, "application/vnd.in-toto+json", statement)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return nil, err
	}

	vm := &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw}},
	}
	if !o.NoTlog {
		envJSON, _ := json.Marshal(env)
		tle, err := s.logEntry(ctx, envJSON, leaf, now.Unix())
		if err != nil {
			return nil, err
		}
		vm.TlogEntries = []*protorekor.TransparencyLogEntry{tle}
	}
	pb := &protobundle.Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: vm,
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload: statement, PayloadType: env.PayloadType,
			Signatures: []*protodsse.Signature{{Sig: sig}},
		}},
	}
	return (&bundle.Bundle{Bundle: pb}).MarshalJSON()
}

// logEntry makes a Rekor v1 dsse entry for the envelope as the only leaf of a one-entry log: inclusion proof,
// signed checkpoint, and signed entry timestamp.
func (s *Sigstore) logEntry(ctx context.Context, envJSON []byte, leaf *x509.Certificate, integrated int64) (*protorekor.TransparencyLogEntry, error) {
	certPEM, err := cryptoutils.MarshalCertificateToPEM(leaf)
	if err != nil {
		return nil, err
	}
	pe, err := rekortypes.NewProposedEntry(ctx, rekordsse.KIND, "0.0.1", rekortypes.ArtifactProperties{
		ArtifactBytes: envJSON, PublicKeyBytes: [][]byte{certPEM}, PKIFormat: "x509"})
	if err != nil {
		return nil, err
	}
	impl, err := rekortypes.CreateVersionedEntry(pe)
	if err != nil {
		return nil, err
	}
	body, err := rekortypes.CanonicalizeEntry(ctx, impl)
	if err != nil {
		return nil, err
	}
	rekorSigner, err := signature.LoadECDSASignerVerifier(s.rekorKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	// Signed entry timestamp: the log's signature over the canonical JSON of body, time, index and log id.
	payload, _ := json.Marshal(map[string]any{"body": base64.StdEncoding.EncodeToString(body),
		"integratedTime": integrated, "logIndex": 0, "logID": hex.EncodeToString(s.rekorLogID[:])})
	canon, err := jsoncanonicalizer.Transform(payload)
	if err != nil {
		return nil, err
	}
	set, err := rekorSigner.SignMessage(bytes.NewReader(canon))
	if err != nil {
		return nil, err
	}
	// A tree of one leaf: the root is the leaf hash; the checkpoint commits to it.
	rootHash := sha256.Sum256(append([]byte{0}, body...))
	cp, err := rekorutil.CreateAndSignCheckpoint(ctx, "rekor.localhost", 1, 1, rootHash[:], rekorSigner)
	if err != nil {
		return nil, err
	}
	return &protorekor.TransparencyLogEntry{
		LogIndex:          0,
		LogId:             &protocommon.LogId{KeyId: s.rekorLogID[:]},
		KindVersion:       &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"},
		IntegratedTime:    integrated,
		InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: set},
		InclusionProof:    &protorekor.InclusionProof{LogIndex: 0, RootHash: rootHash[:], TreeSize: 1, Checkpoint: &protorekor.Checkpoint{Envelope: string(cp)}},
		CanonicalizedBody: body,
	}, nil
}

// sct returns the embedded-SCT extension for a precertificate TBS, signed by the test CT log.
func (s *Sigstore) sct(tbs []byte, at time.Time) (pkix.Extension, error) {
	ts := uint64(at.UnixMilli())
	entry := ct.LogEntry{Leaf: ct.MerkleTreeLeaf{Version: ct.V1, LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{Timestamp: ts, EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{IssuerKeyHash: sha256.Sum256(s.inter.RawSubjectPublicKeyInfo), TBSCertificate: tbs}}}}
	sct := ct.SignedCertificateTimestamp{SCTVersion: ct.V1, LogID: ct.LogID{KeyID: s.ctLogID}, Timestamp: ts}
	data, err := ct.SerializeSCTSignatureInput(sct, entry)
	if err != nil {
		return pkix.Extension{}, err
	}
	h := sha256.Sum256(data)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, s.ctKey, h[:])
	if err != nil {
		return pkix.Extension{}, err
	}
	sct.Signature = ct.DigitallySigned{Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA},
		Signature: sigBytes}
	list, err := ctx509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{&sct})
	if err != nil {
		return pkix.Extension{}, err
	}
	raw, err := cttls.Marshal(*list)
	if err != nil {
		return pkix.Extension{}, err
	}
	val, err := asn1.Marshal(raw)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: val}, nil
}

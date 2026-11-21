// kmsctl is the admins' offline tool for the Tacy key service (kmsd; wire format package kms). It never ships in a VM.
// Before it sends anything to a replica it checks the replica's attestation against the admin-signed policy's KMS
// pins, and it seals what it sends to the key that attestation binds.
//
// Keys. Admin keys (Ed25519) sign genesis, policies, secrets bundles and generation confirmations. Their files are
// wrapped under a passphrase like the shares (kms/passshare: Argon2id, 1 GiB); kmsctl asks for it when it signs, and
// never writes a seed in the clear (wrap-admin converts an older plaintext file; -dev-plain-keys reads plaintext
// development keys). The admin threshold is 1 for now (one admin key); kmsd and kmsctl take
// 2-of-n (-admin-threshold 2, kmsctl sign -key A,B) once there is a second admin key, which is the plan. Share
// recipients:
//
//   - pass:LABEL (no hardware keys for now): the share is wrapped under a passphrase
//     (kms/passshare: Argon2id, 1 GiB). kmsctl asks for each passphrase twice, without echo, before the genesis,
//     and prints each share as text, armored base64 (a password manager, a USB drive) and a paper form (base32 lines
//     with a checksum each); share-N.pass.txt holds the same text. No passphrase and no share in the clear is ever
//     written. Keep the shares in different places (2 of 3 rebuild M).
//
//   - p256:<public>: a P-256 key; software key files today (base64 raw scalar; development and tests), hardware
//     keys (YubiKey PIV, ECDH on the token) later, by re-issuing shares, behind the same open-one-share step.
//
//     kmsctl keygen-admin DIR NAME                     DIR/NAME.key (wrapped; asks a passphrase twice); prints ed25519:<public>
//     kmsctl wrap-admin -in PLAIN.key -out NAME.key    wraps an older plaintext admin key file
//     kmsctl keygen-recipient DIR NAME                 DIR/NAME.p256; prints p256:<public>
//     kmsctl sign -kind kms-policy -key K[,K] DOC.json  signed envelope on stdout (kms-policy, kms-gen, kms-lease-move)
//     kmsctl status -url U
//     kmsctl attest -url U -policy P -admin-keys A
//     kmsctl genesis -url U -policy P -admin-keys A -sign-key K[,K] -recipients pass:manager,pass:paper,pass:usb -threshold 2 -floor vX.Y.Z -out DIR
//     kmsctl unlock -url U -policy P -admin-keys A -genesis DIR/genesis.signed.json -share DIR/share-1.pass.txt -key pass [-share - -key pass]
//     (a passphrase share's text, '-' to paste it; or share-N.json -key R.p256;
//     DIR/commitments.json goes with the first share)
//     kmsctl secret-put -url U -policy P -admin-keys A -kms-id ID -sign-key K -seq N -in values.json -out secrets.sealed
//     kmsctl secret-load -url U -in secrets.sealed
//     kmsctl policy-push -url U -in P
//     kmsctl gen-snapshot -url U -kms-id ID -out S       the register, signed by the KMS id (keep it offline; often)
//     kmsctl gen-doc -url U -kms-id ID -snapshot S [-worker W] -out G   after a cold start: the kms-gen document
//     kmsctl gen-confirm -url U -in G                    (G signed with kmsctl sign -kind kms-gen)
//     kmsctl log -url U -kms-id ID [-from N]
//
// P is an admin-signed kms-policy envelope (kmsctl sign). Every policy names the KMS id and epoch it is for, except
// the one genesis takes (no id yet, epoch 1): kmsctl genesis signs the same policy bound to the new id right after
// the ceremony, loads it, and writes it as policy.signed.json (the one unlock and policy-push take from then on).
// gen-doc builds the confirmation from a snapshot gen-snapshot exported (checked under the KMS id), with the
// Worker's newer generations (-worker: a JSON list of {app, name, gen, hash}) taken only at or above the snapshot's. Attestation flags: -allow-stale-tcb (a TCB status other
// than UpToDate) and -dev-local (a development replica with no TDX: nothing is verified).
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/passshare"
	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/safety"
)

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "kmsctl: "+format+"\n", args...)
	os.Exit(1)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	if len(os.Args) < 2 {
		die("usage: keygen-admin | wrap-admin | keygen-recipient | sign | status | attest | genesis | unlock | secret-put | secret-load | policy-push | gen-snapshot | gen-doc | gen-confirm | log; split key: resplit | holder-keygen | unlock-policy | approve | holder-push | split-dev | break-glass (see the source)")
	}
	cmd, args := os.Args[1], os.Args[2:]
	if slices.Contains(splitCommands, cmd) {
		splitMain(cmd, args) // split.go: the split-key commands
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	url := fs.String("url", "", "replica URL")
	policyPath := fs.String("policy", "", "admin-signed kms-policy envelope")
	adminKeys := fs.String("admin-keys", "", "admin public keys (ed25519:<base64>, comma-separated)")
	adminThreshold := fs.Int("admin-threshold", 1, "admin signatures needed")
	staleTCB := fs.Bool("allow-stale-tcb", false, "accept a TCB status other than UpToDate")
	devLocal := fs.Bool("dev-local", false, "development replica without TDX (nothing verified)")
	signKeys := fs.String("sign-key", "", "admin private key files (comma-separated)")
	kind := fs.String("kind", "", "document kind to sign")
	var shares, recipKeys multi
	fs.Var(&shares, "share", "unlock: a sealed share file (repeat, each with its -key)")
	fs.Var(&recipKeys, "key", "sign: admin key files; unlock: each share's recipient key file (P-256); repeat or comma-separate")
	recipients := fs.String("recipients", "", "share recipients (p256:<base64>, comma-separated)")
	threshold := fs.Int("threshold", 2, "shares needed to rebuild M")
	floor := fs.String("floor", "", "release floor (vX.Y.Z)")
	out := fs.String("out", "", "output path")
	in := fs.String("in", "", "input path ('-' for stdin)")
	genesisPath := fs.String("genesis", "", "admin-signed genesis envelope")
	kmsIDStr := fs.String("kms-id", "", "the KMS id (ed25519:<base64>)")
	seq := fs.Uint64("seq", 0, "secrets bundle seq (higher than the loaded one)")
	from := fs.Uint64("from", 0, "first audit entry")
	snapshotPath := fs.String("snapshot", "", "gen-doc: a register snapshot (kmsctl gen-snapshot)")
	workerPath := fs.String("worker", "", "gen-doc: the generations the Worker holds (JSON list of {app, name, gen, hash})")
	fs.BoolVar(&devPlainKeys, "dev-plain-keys", false, "development only: read plaintext (base64 seed) admin key files")
	fs.Parse(args)
	ctx := context.Background()
	t := client.HTTP{Base: *url}
	opts := server.CheckOptions{AllowStaleTCB: *staleTCB, DevLocal: *devLocal}
	admin := func() kms.AdminKeys {
		k, err := safety.ParseKeys(*adminKeys)
		if err != nil || len(k) == 0 {
			die("-admin-keys: %v", errOr(err, "required"))
		}
		return kms.AdminKeys{Keys: k, Threshold: *adminThreshold}
	}
	policy := func() (*kms.Policy, safety.Envelope) {
		var e safety.Envelope
		readJSON(*policyPath, &e)
		var p kms.Policy
		if err := admin().Open(&e, kms.KindPolicy, &p); err != nil {
			die("%s: %v", *policyPath, err)
		}
		if err := p.Validate(); err != nil {
			die("%s: %v", *policyPath, err)
		}
		return &p, e
	}
	switch cmd {
	case "keygen-admin":
		keygenAdmin(fs.Args())
	case "wrap-admin":
		wrapAdmin(*in, *out)
	case "keygen-recipient":
		keygenRecipient(fs.Args())
	case "sign":
		if fs.NArg() != 1 || *kind == "" || len(recipKeys) == 0 {
			die("usage: sign -kind KIND -key K[,K] DOC.json")
		}
		doc := readFile(fs.Arg(0))
		if *kind == kms.KindPolicy {
			var p kms.Policy
			if err := kms.Strict(doc, &p); err != nil {
				die("policy: %v", err)
			}
			if err := p.Validate(); err != nil {
				die("%v", err)
			}
			if err := kms.CheckKMSFallbackRemoval(p.KMSFallback, latest(p.IssuedAt, time.Now())); err != nil {
				die("%v", err)
			}
		}
		if *kind == split.KindUnlockPolicy {
			var p split.UnlockPolicy
			if err := kms.Strict(doc, &p); err != nil {
				die("unlock policy: %v", err)
			}
			if err := checkUnlockPolicy(&p); err != nil {
				die("%v", err)
			}
		}
		e := safety.Sign(*kind, doc, readAdminKeys(strings.Join(recipKeys, ","))...)
		printJSON(e)
		fmt.Fprintf(os.Stderr, "hash %s\n", e.Hash())
	case "status":
		var st kms.Status
		get(ctx, t, "/v1/status", &st)
		printJSON(st)
	case "attest":
		p, _ := policy()
		a := attest(ctx, t, p, opts)
		facts := make([]string, 0, len(a.Facts))
		for k, v := range a.Facts {
			facts = append(facts, k+": "+v)
		}
		sort.Strings(facts)
		fmt.Printf("verified key service %s (app-compose %s), instance %s\n  %s\n", a.Pin.Version, a.ComposeHash, a.Instance,
			strings.Join(facts, "\n  "))
	case "genesis":
		p, pe := policy()
		genesis(ctx, t, p, pe, opts, admin(), readAdminKeys(*signKeys), *recipients, *threshold, *floor, *out)
	case "unlock":
		p, pe := policy()
		var ge safety.Envelope
		readJSON(*genesisPath, &ge)
		if len(shares) == 0 || len(shares) != len(recipKeys) {
			die("unlock: give -share FILE -key FILE pairs")
		}
		for i := range shares {
			unlock(ctx, t, p, opts, &ge, &pe, *genesisPath, shares[i], recipKeys[i], i == 0)
		}
	case "secret-put":
		p, _ := policy()
		secretPut(ctx, t, p, opts, *kmsIDStr, readAdminKeys(*signKeys), *seq, *in, *out)
	case "secret-load":
		var r kms.SecretsReply
		post(ctx, t, "/v1/secrets/load", kms.SecretsLoad{Sealed: readFile(*in)}, &r)
		fmt.Printf("loaded secrets seq %d: %v\n", r.Seq, r.Names)
	case "gen-snapshot":
		id, err := kms.ParseID(*kmsIDStr)
		if err != nil || *out == "" {
			die("gen-snapshot: -kms-id ID -out FILE")
		}
		ss, err := client.Snapshot(ctx, t, id)
		if err != nil {
			die("snapshot: %v", err)
		}
		b, _ := json.MarshalIndent(ss, "", "  ")
		writeFile(*out, b)
		fmt.Printf("register snapshot: %d entries at audit entry %d, signed by %s: %s\n", len(ss.Snapshot.Entries), ss.Snapshot.LogSeq, *kmsIDStr, *out)
	case "gen-doc":
		id, err := kms.ParseID(*kmsIDStr)
		if err != nil || *out == "" || *snapshotPath == "" {
			die("gen-doc: -kms-id ID -snapshot S -out FILE")
		}
		var ss kms.SignedSnapshot
		readJSON(*snapshotPath, &ss)
		var worker []kms.Gen
		if *workerPath != "" {
			readJSON(*workerPath, &worker)
		}
		var st kms.Status
		get(ctx, t, "/v1/status", &st)
		doc, err := genDoc(&ss, id, worker, st, time.Now().UTC())
		if err != nil {
			die("gen-doc: %v", err)
		}
		b, _ := json.MarshalIndent(doc, "", "  ")
		writeFile(*out, b)
		fmt.Printf("kms-gen document for %s (confirm nonce %s…): %d generations; sign it with kmsctl sign -kind kms-gen within %s\n",
			st.KMSID, short(st.ConfirmNonce), len(doc.Gens), kms.LeaseMoveTTL)
	case "policy-push", "gen-confirm":
		var e safety.Envelope
		readJSON(*in, &e)
		path := map[string]string{"policy-push": "/v1/policy", "gen-confirm": "/v1/gen/confirm"}[cmd]
		var st kms.Status
		post(ctx, t, path, e, &st)
		printJSON(st)
	case "log":
		id, err := kms.ParseID(*kmsIDStr)
		if err != nil {
			die("-kms-id: %v", err)
		}
		var entries []kms.AuditEntry
		get(ctx, t, "/v1/log?from="+strconv.FormatUint(*from, 10), &entries)
		prev := ""
		if len(entries) > 0 {
			prev = entries[0].Prev
		}
		head, err := kms.VerifyLog(entries, prev, id)
		if err != nil {
			die("audit log: %v", err)
		}
		for _, e := range entries {
			fmt.Printf("%6d %s %-8s ok=%-5v %s %s %s\n", e.Seq, time.Unix(e.Time, 0).UTC().Format(time.RFC3339), e.Kind, e.OK, e.App, short(e.Instance), e.Detail)
		}
		fmt.Printf("%d entries verified under %s; head %s\n", len(entries), *kmsIDStr, head)
	default:
		die("unknown command %q", cmd)
	}
}

func errOr(err error, s string) string {
	if err != nil {
		return err.Error()
	}
	return s
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func readFile(p string) []byte {
	if p == "" {
		die("missing input path")
	}
	var b []byte
	var err error
	if p == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(p)
	}
	if err != nil {
		die("%v", err)
	}
	return b
}

func readJSON(p string, v any) {
	if err := kms.Strict(readFile(p), v); err != nil {
		die("%s: %v", p, err)
	}
}

func writeFile(p string, b []byte) {
	if err := os.WriteFile(p, b, 0o600); err != nil {
		die("%v", err)
	}
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func get(ctx context.Context, t client.Transport, path string, out any) {
	b, err := t.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		die("%s: %v", path, err)
	}
	if err := kms.Strict(b, out); err != nil {
		die("%s: %v", path, err)
	}
}

func post(ctx context.Context, t client.Transport, path string, in, out any) {
	body, _ := json.Marshal(in)
	b, err := t.Do(ctx, http.MethodPost, path, body)
	if err != nil {
		die("%s: %v", path, err)
	}
	if err := kms.Strict(b, out); err != nil {
		die("%s: %v", path, err)
	}
}

// devPlainKeys: -dev-plain-keys (development: plaintext admin key files).
var devPlainKeys bool

// readAdminKeys reads admin key files (loadAdminKeys), or dies.
func readAdminKeys(files string) []ed25519.PrivateKey {
	k, err := loadAdminKeys(files)
	if err != nil {
		die("%v", err)
	}
	return k
}

// loadAdminKeys reads admin key files: wrapped ones (keygen-admin), each opened with its passphrase; plaintext ones
// only with -dev-plain-keys.
func loadAdminKeys(files string) ([]ed25519.PrivateKey, error) {
	var out []ed25519.PrivateKey
	for _, f := range strings.Split(files, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		text := string(raw)
		if passshare.IsAdminKey(text) {
			pub, _ := passshare.AdminKeyPublic(text)
			pass, err := readPassphrase(fmt.Sprintf("Passphrase for admin key %s (%s): ", f, kms.IDString(pub)))
			if err != nil {
				return nil, err
			}
			k, err := passshare.OpenAdminKey(text, pass)
			clear(pass)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			out = append(out, k)
			continue
		}
		if !devPlainKeys {
			return nil, fmt.Errorf("%s isn't a wrapped admin key file (kmsctl wrap-admin wraps a plaintext one; -dev-plain-keys reads development keys)", f)
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s isn't an admin key file", f)
		}
		out = append(out, ed25519.NewKeyFromSeed(seed))
	}
	if len(out) == 0 {
		return nil, errors.New("no admin key files")
	}
	return out, nil
}

func readRecipientKey(f string) *ecdh.PrivateKey {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(readFile(f))))
	if err != nil {
		die("%s isn't a recipient key file", f)
	}
	k, err := ecdh.P256().NewPrivateKey(raw)
	if err != nil {
		die("%s isn't a P-256 key", f)
	}
	return k
}

func keygenAdmin(a []string) {
	if len(a) != 2 {
		die("usage: keygen-admin DIR NAME")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	writeWrappedAdmin(filepath.Join(a[0], a[1]+".key"), a[1], priv)
	fmt.Println(kms.IDString(pub))
}

// wrapAdmin wraps an older plaintext admin key file (base64 seed) under a passphrase.
func wrapAdmin(in, out string) {
	if in == "" || out == "" || in == out {
		die("usage: wrap-admin -in PLAIN.key -out NAME.key (a new file)")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(readFile(in))))
	if err != nil || len(seed) != ed25519.SeedSize {
		die("%s isn't a plaintext admin key file", in)
	}
	k := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	writeWrappedAdmin(out, filepath.Base(out), k)
	fmt.Printf("%s wrapped as %s; delete %s yourself once you have checked the new file signs\n", kms.IDString(k.Public().(ed25519.PublicKey)), out, in)
}

func writeWrappedAdmin(path, label string, k ed25519.PrivateKey) {
	if _, err := os.Stat(path); err == nil {
		die("%s exists", path)
	}
	pass, err := newPassphrase("admin key " + label)
	if err != nil {
		die("%v", err)
	}
	text, err := passshare.WrapAdminKey(pass, k, passParams)
	clear(pass)
	if err != nil {
		die("%v", err)
	}
	writeFile(path, []byte(text))
}

// genDoc is the kms-gen document after a cold start: the generations of a snapshot the KMS id signed, each raised to
// the Worker's when the Worker holds that one or a later one (a Worker below the snapshot is a rollback: refused),
// for st's KMS id, epoch and confirm nonce.
func genDoc(ss *kms.SignedSnapshot, id ed25519.PublicKey, worker []kms.Gen, st kms.Status, now time.Time) (*kms.GenConfirm, error) {
	if err := client.CheckSnapshot(ss, id); err != nil {
		return nil, fmt.Errorf("the snapshot isn't signed by %s", kms.IDString(id))
	}
	if st.KMSID != kms.IDString(id) || st.State != "unlocked" || st.GensOK || st.ConfirmNonce == "" {
		return nil, fmt.Errorf("the replica (%s, %s, confirmed %v) doesn't wait for a confirmation", st.KMSID, st.State, st.GensOK)
	}
	if ss.Snapshot.Epoch != st.Epoch {
		return nil, fmt.Errorf("the snapshot is of epoch %d, the replica %d", ss.Snapshot.Epoch, st.Epoch)
	}
	key := func(app, name string) string { return app + "\x00" + name }
	w := map[string]kms.Gen{}
	for _, g := range worker {
		if g.Gen == 0 || !kms.ValidName(g.App) || !kms.ValidName(g.Name) || len(g.Hash) != 64 {
			return nil, fmt.Errorf("worker entry %s/%s isn't a generation", g.App, g.Name)
		}
		if _, ok := w[key(g.App, g.Name)]; ok {
			return nil, fmt.Errorf("worker entry %s/%s twice", g.App, g.Name)
		}
		w[key(g.App, g.Name)] = g
	}
	doc := &kms.GenConfirm{KMSID: st.KMSID, Epoch: st.Epoch, Nonce: st.ConfirmNonce, IssuedAt: now, Gens: []kms.Gen{}}
	seen := map[string]bool{}
	for _, e := range ss.Snapshot.Entries {
		k := key(e.Gen.App, e.Gen.Name)
		seen[k] = true
		wg, held := w[k]
		switch {
		case held && wg.Gen > e.Gen.Gen:
			doc.Gens = append(doc.Gens, wg) // saved since the snapshot
		case held && wg.Gen == e.Gen.Gen && wg.Hash == e.Gen.Hash:
			doc.Gens = append(doc.Gens, wg)
		case held && !e.Stored && wg.Gen+1 == e.Gen.Gen && wg.Hash == e.Prev:
			doc.Gens = append(doc.Gens, wg) // reserved, never stored: the one before
		case held:
			return nil, fmt.Errorf("%s/%s: the Worker holds generation %d %s…, the snapshot says %d %s… (stored %v): a rollback or a fork",
				e.Gen.App, e.Gen.Name, wg.Gen, short(wg.Hash), e.Gen.Gen, short(e.Gen.Hash), e.Stored)
		case !e.Stored:
			return nil, fmt.Errorf("%s/%s: generation %d is only reserved in the snapshot; give the Worker's generations (-worker)", e.Gen.App, e.Gen.Name, e.Gen.Gen)
		default:
			doc.Gens = append(doc.Gens, e.Gen)
		}
	}
	for k, g := range w {
		if !seen[k] {
			doc.Gens = append(doc.Gens, g) // a state first saved after the snapshot
		}
	}
	sort.Slice(doc.Gens, func(i, j int) bool {
		return key(doc.Gens[i].App, doc.Gens[i].Name) < key(doc.Gens[j].App, doc.Gens[j].Name)
	})
	return doc, nil
}

func keygenRecipient(a []string) {
	if len(a) != 2 {
		die("usage: keygen-recipient DIR NAME")
	}
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		die("%v", err)
	}
	writeFile(filepath.Join(a[0], a[1]+".p256"), []byte(base64.StdEncoding.EncodeToString(k.Bytes())+"\n"))
	fmt.Println(kms.RecipientString(k.PublicKey()))
}

// attest checks the replica is a pinned key service release and returns the key its quote binds.
func attest(ctx context.Context, t client.Transport, p *kms.Policy, o server.CheckOptions) *server.Attested {
	n := make([]byte, 32)
	rand.Read(n)
	b, err := t.Do(ctx, http.MethodGet, "/v1/attest?nonce="+hex.EncodeToString(n), nil)
	if err != nil {
		die("attest: %v", err)
	}
	a, err := server.VerifyKMS(ctx, b, n, p, o)
	if err != nil {
		die("the replica isn't a pinned key service release: %v", err)
	}
	return a
}

// passRecipient is a "pass:LABEL" recipient: a P-256 key made here, in memory, for this genesis only, and the
// passphrase its share will be wrapped under (kms/passshare).
type passRecipient struct {
	label string
	key   *ecdh.PrivateKey
	pass  []byte
}

// passParams is the passphrase shares' Argon2id cost (tests lower it).
var passParams = passshare.Default

// readPassphrase reads a passphrase from the terminal without echo (tests replace it). Never from a file, a flag or
// the environment.
var readPassphrase = func(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("a passphrase is read from a terminal only")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return b, err
}

// newPassphrase asks for a share's passphrase twice.
func newPassphrase(label string) ([]byte, error) {
	p1, err := readPassphrase(fmt.Sprintf("Passphrase for share %q (at least %d characters): ", label, passshare.MinPassphrase))
	if err != nil {
		return nil, err
	}
	if len([]rune(string(p1))) < passshare.MinPassphrase {
		clear(p1)
		return nil, fmt.Errorf("the passphrase for %q is shorter than %d characters", label, passshare.MinPassphrase)
	}
	p2, err := readPassphrase(fmt.Sprintf("Again, for share %q: ", label))
	defer clear(p2)
	if err != nil || !bytes.Equal(p1, p2) {
		clear(p1)
		return nil, fmt.Errorf("the passphrases for %q don't match", label)
	}
	return p1, nil
}

func genesis(ctx context.Context, t client.Transport, p *kms.Policy, pe safety.Envelope, o server.CheckOptions, admin kms.AdminKeys,
	sign []ed25519.PrivateKey, recipients string, threshold int, floor, out string) {
	if out == "" {
		die("genesis: -out DIR")
	}
	// Pass recipients first: every passphrase is in hand before the one-time genesis is spent.
	var passes []passRecipient
	defer func() {
		for _, pr := range passes {
			clear(pr.pass)
		}
	}()
	var recips []string
	for _, r := range strings.Split(recipients, ",") {
		r = strings.TrimSpace(r)
		label, isPass := strings.CutPrefix(r, "pass:")
		switch {
		case r == "":
			continue
		case isPass:
			if label == "" || slices.ContainsFunc(passes, func(pr passRecipient) bool { return pr.label == label }) {
				die("genesis: each pass recipient needs its own label (pass:LABEL)")
			}
			pass, err := newPassphrase(label)
			if err != nil {
				die("genesis: %v", err)
			}
			k, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				die("%v", err)
			}
			passes = append(passes, passRecipient{label: label, key: k, pass: pass})
			r = kms.RecipientString(k.PublicKey())
		}
		recips = append(recips, r)
	}
	a := attest(ctx, t, p, o)
	var adminStr []string
	for _, k := range admin.Keys {
		adminStr = append(adminStr, kms.IDString(k))
	}
	doc := kms.GenesisDoc{Threshold: threshold, AdminKeys: adminStr, AdminThreshold: admin.Threshold, Floor: floor,
		Target: hex.EncodeToString(a.Key.Bytes()), IssuedAt: time.Now().UTC(), Recipients: recips}
	if err := doc.Validate(); err != nil {
		die("%v", err)
	}
	b, _ := json.Marshal(doc)
	ge := safety.Sign(kms.KindGenesis, b, sign...)
	var rep kms.GenesisReply
	post(ctx, t, "/v1/genesis", kms.GenesisRequest{Genesis: ge, Policy: pe}, &rep)
	id, err := kms.ParseID(rep.KMSID)
	if err != nil || !ed25519.Verify(id, kms.GenesisSigMessage(ge.Hash(), rep.Shares), rep.Sig) || len(rep.Shares) != len(doc.Recipients) {
		die("genesis reply isn't signed by its KMS id or has the wrong shares")
	}
	gb, _ := json.MarshalIndent(ge, "", "  ")
	writeFile(filepath.Join(out, "genesis.signed.json"), gb)
	for _, s := range rep.Shares {
		i := slices.IndexFunc(passes, func(pr passRecipient) bool { return kms.RecipientString(pr.key.PublicKey()) == s.Recipient })
		if i < 0 {
			sb, _ := json.MarshalIndent(s, "", "  ")
			writeFile(filepath.Join(out, fmt.Sprintf("share-%d.json", s.Index)), sb)
			continue
		}
		// A pass share: its P-256 key leaves this process only wrapped under the passphrase; the text below is
		// what to keep (sealed: safe to print, store and copy; useless without its passphrase).
		ps, err := passshare.New(passes[i].pass, passes[i].key, s, passParams)
		if err != nil {
			die("share %d: %v", s.Index, err)
		}
		text := passshare.Armor(ps) + "\n" + passshare.Paper(ps)
		writeFile(filepath.Join(out, fmt.Sprintf("share-%d.pass.txt", s.Index)), []byte(text))
		fmt.Printf("\n==== share %d (%s): keep this text; it opens only with its passphrase ====\n%s", s.Index, passes[i].label, text)
	}
	if !ed25519.Verify(id, kms.CommitmentsSigMessage(rep.KMSID, rep.Epoch, rep.Commitments), rep.CommitSig) {
		die("share commitments aren't signed by the KMS id")
	}
	cb, _ := json.MarshalIndent(commitments{Commitments: rep.Commitments, CommitSig: rep.CommitSig}, "", "  ")
	writeFile(filepath.Join(out, "commitments.json"), cb)
	writeFile(filepath.Join(out, "kms-id.txt"), []byte(rep.KMSID+"\n"))
	// The policy bound to the new KMS id: unlocks, joins and every later policy-push need one.
	bound := *p
	bound.KMSID, bound.Seq, bound.IssuedAt = rep.KMSID, p.Seq+1, time.Now().UTC()
	pb, _ := json.Marshal(bound)
	be := safety.Sign(kms.KindPolicy, pb, sign...)
	var st kms.Status
	post(ctx, t, "/v1/policy", be, &st)
	bb, _ := json.MarshalIndent(be, "", "  ")
	writeFile(filepath.Join(out, "policy.signed.json"), bb)
	fmt.Printf("KMS id %s (%d-of-%d shares in %s); policy seq %d bound to it: %s\n", rep.KMSID, rep.Threshold, len(rep.Shares), out,
		st.PolicySeq, filepath.Join(out, "policy.signed.json"))
}

// commitments is commitments.json: the KMS id's commitments to every share (public; a locked replica needs them).
type commitments struct {
	Commitments []string `json:"commitments"`
	CommitSig   []byte   `json:"commit_sig"`
}

// unlock opens one share on its recipient key and reseals it at once to the attested replica: only this one share
// is ever in memory here, and only between the two steps.
func unlock(ctx context.Context, t client.Transport, p *kms.Policy, o server.CheckOptions, ge, pe *safety.Envelope,
	genesisPath, sharePath, keyPath string, first bool) {
	sh, k, err := loadShare(sharePath, keyPath)
	if err != nil {
		die("%v", err)
	}
	var st kms.Status
	get(ctx, t, "/v1/status", &st)
	if st.KMSID != sh.KMSID {
		die("replica pins %s, the share is for %s", st.KMSID, sh.KMSID)
	}
	a := attest(ctx, t, p, o)
	aad := kms.ShareAAD(sh.KMSID, sh.Index, sh.Epoch)
	y, err := kms.Open(k, kms.LabelShare, aad, sh.Sealed)
	if err != nil {
		die("%s doesn't open with %s", sharePath, keyPath)
	}
	box, err := kms.Seal(a.Key, kms.LabelUnlock, aad, y)
	clear(y)
	if err != nil {
		die("%v", err)
	}
	req := kms.UnlockRequest{Index: sh.Index, Epoch: sh.Epoch, Share: box}
	if first {
		var c commitments
		readJSON(filepath.Join(filepath.Dir(genesisPath), "commitments.json"), &c)
		req.Genesis, req.Policy, req.Commitments, req.CommitSig = ge, pe, c.Commitments, c.CommitSig
	}
	var r kms.UnlockReply
	post(ctx, t, "/v1/unlock", req, &r)
	fmt.Printf("share %d sent: %s (%d of %d)\n", sh.Index, r.State, r.Shares, r.Threshold)
}

// loadShare reads one share and its recipient key: a P-256 share file (share-N.json) with its key file, or a
// passphrase share's text (share-N.pass.txt, the armored or the paper form, or '-' to paste it on stdin) with -key
// pass, whose passphrase is asked for here. A wrong passphrase or a mistyped paper copy fails here, before anything
// is sent.
func loadShare(sharePath, keyPath string) (kms.SealedShare, *ecdh.PrivateKey, error) {
	b := readFile(sharePath)
	if keyPath == "pass" {
		ps, err := passshare.Decode(string(b))
		if err != nil {
			return kms.SealedShare{}, nil, fmt.Errorf("%s: %w", sharePath, err)
		}
		pass, err := readPassphrase(fmt.Sprintf("Passphrase for share %d: ", ps.Index))
		if err != nil {
			return kms.SealedShare{}, nil, err
		}
		defer clear(pass)
		k, sh, err := ps.Open(pass)
		if err != nil {
			return kms.SealedShare{}, nil, fmt.Errorf("share %d: %w", ps.Index, err)
		}
		return sh, k, nil
	}
	var sh kms.SealedShare
	if err := kms.Strict(b, &sh); err != nil {
		return kms.SealedShare{}, nil, fmt.Errorf("%s: %v (a passphrase share takes -key pass)", sharePath, err)
	}
	k := readRecipientKey(keyPath)
	if kms.RecipientString(k.PublicKey()) != sh.Recipient {
		return kms.SealedShare{}, nil, fmt.Errorf("%s isn't %s's recipient key", keyPath, sharePath)
	}
	return sh, k, nil
}

func secretPut(ctx context.Context, t client.Transport, p *kms.Policy, o server.CheckOptions, kmsID string, sign []ed25519.PrivateKey,
	seq uint64, in, out string) {
	if out == "" || seq == 0 {
		die("secret-put: -seq N and -out FILE")
	}
	var st kms.Status
	get(ctx, t, "/v1/status", &st)
	if st.State != "unlocked" || st.KMSID != kmsID {
		die("replica is %s with KMS id %s, want unlocked %s", st.State, st.KMSID, kmsID)
	}
	var values map[string]string
	if err := kms.Strict(readFile(in), &values); err != nil || len(values) == 0 {
		die("%s: a JSON object of names to values: %v", in, err)
	}
	a := attest(ctx, t, p, o)
	b, _ := json.Marshal(kms.SecretsDoc{KMSID: kmsID, Epoch: st.Epoch, Seq: seq, Values: values, IssuedAt: time.Now().UTC()})
	env, _ := json.Marshal(safety.Sign(kms.KindSecrets, b, sign...))
	clear(b)
	box, err := kms.Seal(a.Key, kms.LabelSecretPut, []byte(kmsID), env)
	clear(env)
	if err != nil {
		die("%v", err)
	}
	var r kms.SecretsReply
	post(ctx, t, "/v1/secrets/put", kms.SecretsPut{Sealed: box}, &r)
	if r.Seq != seq || len(r.Sealed) == 0 {
		die("unexpected reply")
	}
	writeFile(out, r.Sealed)
	fmt.Printf("secrets seq %d (%v) sealed under the KMS: %s\n", r.Seq, r.Names, out)
}

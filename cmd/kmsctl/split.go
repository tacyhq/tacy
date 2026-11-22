package main

// The split-key commands (the keys plan §11, FD-17): the master key re-split across online holders, the unlock policy
// they serve under, and the admin's break-glass. Offline except holder-push and break-glass.
//
//	kmsctl resplit -kms-id ID -share S -key pass -share S -key pass -holder ID=RECIPIENT [-holder ...] -threshold T -set N -epoch E -out DIR
//	    two passphrase shares (set 1) rebuild M in memory; M must derive ID; epoch E's VM root R_E (never M) is split
//	    T-of-n to the holders (RECIPIENT: x25519:<base64> or p256:<base64>, from holder-keygen). DIR (new) gets
//	    share-set-N.json and epoch-cert-E.json (public, signed by the KMS id: R_E's root id, its store certificates
//	    and activity signer) and holder-<id>-set-N.json (each sealed to its holder's key). Nothing else is written. A
//	    leaked R_E is answered by the same command with -epoch E+1 (and secrets-seal for E+1).
//	kmsctl secrets-seal -kms-id ID -share S -key pass -share S -key pass -epoch E -seq N -apps G.json -in values.json|- -out F
//	    values.json must carry exactly the names the grants G list (for the agent VM both tunnel tokens, VMA and
//	    VMB, so a release on either slot unlocks from one bundle), each with a value.
//	kmsctl secrets-push -in F -sign-key K -worker URL
//	    the sealed bundle to the chat Worker (POST /api/vm/unlock-secrets, which unlockd fetches): a kms-unlock-secrets
//	    envelope signed with the kms-admin key, {"sealed": base64}. The Worker keeps it only above the stored seq.
//	    our API keys sealed under R_E (F is ciphertext; the Worker serves it to the VM).
//	kmsctl holder-keygen [-curve x25519|p256]
//	    a holder's key: the private key (base64) on stdout, which must be a pipe (into wrangler secret put or vercel
//	    env add --sensitive), never a terminal or a file; its recipient string on stderr.
//	kmsctl unlock-policy -kms-id ID -seq N -floor vX.Y.Z -holders ID=URL[,ID=URL] -share-set F [-share-set F] [-break-glass URL]
//	        [-from-kms-policy P.signed.json] [-base U.json] [-apps kms/policies/agent-vm-v1.json] [-machine-cert F ...]
//	    an unsigned kms-unlock-policy (stdout): from a base, or from the key service's signed kms-policy (its pins,
//	    floors, OS images, boot sets and apps), with the holders, share sets and break-glass relay given. -apps F sets
//	    the policy's app grants to exactly F's (kms/policies.Load: a grant naming a tunnel token names both); a
//	    policy with no grant is refused (approve couldn't pin a release in it), so the first policy takes -apps.
//	    Each grant is summed up on stderr.
//	kmsctl approve -base U.json [-release app=APP,version=vX.Y.Z,app-compose=F,compose=F] [-remove vX.Y.Z]
//	        [-share-set F ...] [-trust-base T.json -trust-release R.json] -sign-key K [-trust-key K] -out DIR -expect F
//	        [-emergency REASON [-emergency-item ITEM ...] -share S -key pass -share S -key pass]
//	    -emergency (the no-downtime plan row 13): the releases added unlock at once, without the holders' 24 h delay. It takes the
//	    admin key and two passphrase shares (M signs the override with the KMS id), so the fix and the withdrawal
//	    of the vulnerable release go in one push. Every holder alerts on it. -emergency-item expedites another of
//	    the new policy's items too (split.PolicyItems; "other" is its catch-all item): what a VM relies on besides
//	    its release, which a holder that is new, or whose record of the policy is new, has seen for less than 24 h;
//	    "release:vX.Y.Z" a release already pinned. With only -emergency-item (nothing added or removed), the next seq
//	    carries the override alone: a release pinned earlier unlocks at once.
//	    the next unlock policy (seq + 1; a release added or removed) and, with -trust-base, the next trust list with
//	    the same release added or removed, both signed in one session: DIR/unlock-policy-<seq>.signed.json and
//	    DIR/trust-list-<seq>.signed.json. -dry-run prints both unsigned (stdout: {"unlock_policy", "trust_list"}) and
//	    signs and writes nothing (no -sign-key, -out or -emergency): what a run without it would sign. The run that
//	    signs takes that output back (-expect F, required but with -emergency) and signs only if it derives the same
//	    bytes again, issued_at aside. Both print each document's sha256 (issued_at left out) on stderr.
//	    -machine-cert F (repeat) adds a machine certificate (machine-cert's output) to the policy and the trust list;
//	    -revoke-machine HASH|F (repeat) revokes one: its hash joins machines_revoked in both, for good (holders keep
//	    every revocation they have seen, clients the union of every list), and the certificate leaves machine_certs.
//	    Both take only the admin keys: a certificate is already the KMS id's, and an admin key alone can revoke but
//	    never re-allow (a revoked machine needs a new certificate). With only these (nothing else changed), the next
//	    seq of both documents carries the change. With -trust-base, the trust list always carries the policy's
//	    machine_certs and the union of both documents' machines_revoked.
//	    -end-overlap (needs -trust-base): the trust list ends the KMS-fallback overlap ("overlap_ended": true,
//	    safety/overlapend.go): a Fix B client that verified it refuses v0.20.0 at once and for good. With only it, the
//	    next seq of both documents carries it. A trust base that has it keeps it: there is no flag to turn it off.
//	kmsctl machine-cert -kms-id ID -share S -key pass -share S -key pass (-builtin prod5|prod9 | -ppid HEX -fmspc HEX
//	        -label "phala prodN") [-issued-at T] -out F
//	    a machine certificate (V1-DESIGN §3.2) signed by the KMS id (M from two passphrase shares; -dev-master for
//	    staging): F (new) and its hash on stdout. -builtin signs exactly the document this build has built in
//	    (verifier.MachineDocs, issued 2026-11-21), so the certificate's hash is the built-in one's. Every certificate
//	    is one Phala machine (host phala, mode ppid); the Google Cloud host modes are gone (the v1 Google host removal).
//	kmsctl sign -kind kms-unlock-policy -key K DOC.json   (checked as an unlock policy first)
//	kmsctl holder-push -in U.signed.json -worker URL -native native-addresses.json [-url HOLDER_URL]
//	    in order: the Worker first (POST /api/vm/unlock-policy), then a check that a VM's fetch (GET) returns that
//	    seq, then POST /v1/policy to every holder the policy names (or one, -url) at its tacy.io URL and at its
//	    provider-native address (vercel.app for Vercel, run.app for Google), so Cloudflare, which runs
//	    tacy.io's DNS, isn't the only route to a holder. The native addresses come from the local file -native
//	    (never from the policy: gatewayd refuses holder URLs off tacy.io). Every holder but Cloudflare must have one,
//	    and the push fails unless each holder took the policy on at least one route. Signed receipts come later. A
//	    security withdrawal also raises every holder's PolicyFloor at its next deploy.
//	kmsctl split-dev -holders cloudflare,vercel -threshold 2 -out DIR   staging files (dev KMS id, dev keys)
//	kmsctl break-glass -relay URL -policy U.signed.json -admin-keys A -sign-key K -share S -key pass -share S -key pass [-boots 1]
//	    emergency only: rebuilds M from two passphrase shares, attaches to the relay with an admin-signed document and
//	    serves exactly -boots unlocks as the break-glass holder (the same checks as a holder), then exits.
//	    -dev-master F (staging only) takes a dev M instead of shares.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	neturl "net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/policies"
	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/kms/split/glass"
	"github.com/tacyhq/tacy/kms/split/holder"
	"github.com/tacyhq/tacy/kms/split/splitdev"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/verifier"
)

// splitCommands are the commands this file serves.
var splitCommands = []string{"resplit", "secrets-seal", "secrets-push", "holder-keygen", "unlock-policy", "approve", "holder-push", "split-dev", "break-glass", "machine-cert"}

// splitMain runs a split-key command.
func splitMain(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	kmsIDStr := fs.String("kms-id", "", "the KMS id (ed25519:<base64>)")
	var shares, keys, holders, shareSets multi
	fs.Var(&shares, "share", "a passphrase share's text file ('-' to paste), repeat")
	fs.Var(&keys, "key", "each share's key: pass")
	fs.Var(&holders, "holder", "resplit: ID=RECIPIENT, repeat (in index order)")
	fs.Var(&shareSets, "share-set", "a share-set-N.json, repeat (at most 2: the live set and the one replacing it)")
	var epochCerts multi
	fs.Var(&epochCerts, "epoch-cert", "an epoch-cert-E.json, repeat (one per epoch the share sets use)")
	app := fs.String("app", "agent-vm", "resplit: the app its epoch certificate is for")
	firm := fs.String("firm", "f_chat", "resplit: the app's firm")
	tcbGrace := fs.String("tcb-grace", "", "approve: until=RFC3339,statuses=OutOfDate[+ConfigurationNeeded][,min-tcb-date=YYYY-MM-DD] (into both documents)")
	worker := fs.String("worker", "", "holder-push: the chat Worker's base URL (pushed and checked first)")
	adminGen := fs.String("admin-gen", "kms-admin-1", "break-glass: the admin-key generation")
	emergency := fs.String("emergency", "", "approve: the reason for an emergency override (needs two -share -key pass)")
	var emergencyItems multi
	fs.Var(&emergencyItems, "emergency-item", `approve -emergency: another policy item to expedite, repeat ("other": the policy's catch-all item)`)
	threshold := fs.Int("threshold", 2, "shares needed")
	set := fs.Uint("set", 0, "resplit: the new share set's number (> every earlier one; the genesis is 1)")
	epoch := fs.Uint("epoch", 1, "the KMS epoch")
	out := fs.String("out", "", "output folder (new) or file")
	in := fs.String("in", "", "input file")
	curve := fs.String("curve", "x25519", "holder-keygen: x25519 or p256")
	seq := fs.Uint64("seq", 0, "unlock-policy: its seq")
	floor := fs.String("floor", "", "unlock-policy: the release floor")
	holderURLs := fs.String("holders", "", "unlock-policy: ID=URL,...; split-dev: ID,...")
	var holderBuilds multi
	fs.Var(&holderBuilds, "holder-build", "unlock-policy: ID=SHA256, the holder's pinned reproducible build (repeat)")
	breakGlass := fs.String("break-glass", "", "unlock-policy: the break-glass relay URL")
	fromKMS := fs.String("from-kms-policy", "", "unlock-policy: the key service's signed kms-policy to take pins from")
	base := fs.String("base", "", "the current unsigned unlock policy")
	appsFile := fs.String("apps", "", "unlock-policy: the app grants file (kms/policies/agent-vm-v1.json), the policy's apps become exactly its; "+
		"secrets-seal: the grants the bundle must carry every name of")
	dryRun := fs.Bool("dry-run", false, "approve: print the unsigned policy and trust list it would sign; sign and write nothing")
	expect := fs.String("expect", "", "approve: the -dry-run output (would-sign.json) this run must derive again, byte for byte but issued_at, before it signs")
	previous := fs.String("previous", "", "unlock-policy: the last unsigned unlock policy before (another admin-key generation's): its machine revocations carry over")
	var releases, removes multi
	fs.Var(&releases, "release", "approve: app=APP,version=vX.Y.Z,app-compose=FILE,compose=FILE")
	fs.Var(&removes, "remove", "approve: a release version to withdraw")
	trustBase := fs.String("trust-base", "", "approve: the current unsigned trust list")
	trustRelease := fs.String("trust-release", "", "approve: the release's releases.json entry (version, commit, compose_sha256, bundle)")
	signKey := fs.String("sign-key", "", "admin key file(s) for the unlock policy (kms-admin)")
	trustKey := fs.String("trust-key", "", "admin key file(s) for the trust list (the safety admin key)")
	adminKeys := fs.String("admin-keys", "", "admin public keys (ed25519:<base64>, comma-separated)")
	adminThreshold := fs.Int("admin-threshold", 1, "admin signatures needed")
	url := fs.String("url", "", "holder-push: one holder's URL")
	nativeFile := fs.String("native", "", "holder-push: native-addresses.json, each holder's provider-native address (required without -url)")
	relay := fs.String("relay", "", "break-glass: the relay URL")
	policyPath := fs.String("policy", "", "break-glass: the current signed unlock policy")
	boots := fs.Int("boots", 1, "break-glass: unlocks to serve before exiting")
	devMaster := fs.String("dev-master", "", "staging only: a dev M (base64) instead of passphrase shares")
	staleTCB := fs.Bool("allow-stale-tcb", false, "break-glass: accept a TCB status other than UpToDate")
	var machineCerts, revokeMachines multi
	fs.Var(&machineCerts, "machine-cert", "unlock-policy, approve: a machine certificate file (machine-cert's output), repeat")
	fs.Var(&revokeMachines, "revoke-machine", "approve: a machine certificate's hash (or its file) to revoke for good, repeat")
	endOverlap := fs.Bool("end-overlap", false, "approve: the trust list ends the KMS-fallback overlap (needs -trust-base; for good)")
	builtin := fs.String("builtin", "", "machine-cert: prod5 or prod9, the document this build has built in")
	ppid := fs.String("ppid", "", "machine-cert: the machine's PPID (16 bytes, hex)")
	fmspc := fs.String("fmspc", "", "machine-cert: its FMSPC (6 bytes, hex)")
	label := fs.String("label", "", `machine-cert: its label ("phala prod5")`)
	issuedAt := fs.String("issued-at", "", "machine-cert: the issue time (RFC 3339; default now, -builtin its own)")
	fs.BoolVar(&devPlainKeys, "dev-plain-keys", false, "development only: read plaintext (base64 seed) admin key files")
	fs.Parse(args)
	ctx := context.Background()
	now := time.Now().UTC()

	switch cmd {
	case "resplit":
		id := parseKMSID(*kmsIDStr)
		m := masterFrom(id, shares, keys, *devMaster)
		defer clear(m)
		var recips []split.HolderRecipient
		for _, h := range holders {
			hid, r, ok := strings.Cut(h, "=")
			if !ok {
				die("-holder ID=RECIPIENT, got %q", h)
			}
			recips = append(recips, split.HolderRecipient{Holder: hid, Recipient: r})
		}
		if err := resplit(m, kms.IDString(id), uint32(*epoch), uint32(*set), *threshold, recips, *app, *firm, now, *out); err != nil {
			die("%v", err)
		}
	case "secrets-seal":
		if *appsFile == "" {
			die("secrets-seal: -apps F, the grants the bundle serves (kms/policies/agent-vm-v1.json): it must carry every name they list")
		}
		apps, err := policies.Load(readFile(*appsFile))
		if err != nil {
			die("%s: %v", *appsFile, err)
		}
		id := parseKMSID(*kmsIDStr)
		m := masterFrom(id, shares, keys, *devMaster)
		defer clear(m)
		var values map[string]string
		if err := kms.Strict(readFile(*in), &values); err != nil || len(values) == 0 {
			die("%s: a JSON object of names to values: %v", *in, err)
		}
		if err := bundleNames(values, apps); err != nil {
			clear(values)
			die("%s: %v", *in, err)
		}
		sealed, err := secretsSeal(m, kms.IDString(id), uint32(*epoch), *seq, values)
		for k := range values {
			delete(values, k)
		}
		if err != nil {
			die("%v", err)
		}
		writeFile(*out, sealed)
		fmt.Printf("secrets seq %d sealed under epoch %d's root: %s\n", *seq, *epoch, *out)
	case "secrets-push":
		if *in == "" || *signKey == "" || *worker == "" {
			die("secrets-push: -in F (secrets-seal's output) -sign-key K -worker URL")
		}
		env, err := secretsEnvelope(readFile(*in), readAdminKeys(*signKey))
		if err != nil {
			die("%v", err)
		}
		b, err := client.HTTP{Base: *worker}.Do(ctx, "POST", unlockSecretsPath, env)
		if err != nil {
			die("worker push: %v", err)
		}
		fmt.Printf("worker %s: %s\n", *worker, strings.TrimSpace(string(b)))
	case "holder-keygen":
		if term.IsTerminal(int(os.Stdout.Fd())) {
			die("holder-keygen: stdout is a terminal; pipe it into the holder's secret store (wrangler secret put, vercel env add --sensitive)")
		}
		priv, rcp, err := holderKeygen(*curve)
		if err != nil {
			die("%v", err)
		}
		fmt.Println(priv)
		fmt.Fprintln(os.Stderr, rcp)
	case "unlock-policy":
		p, err := unlockPolicy(*base, *fromKMS, *kmsIDStr, *seq, *floor, *holderURLs, shareSets, epochCerts, *breakGlass, now,
			kms.AdminKeys{Keys: parseKeysOrNil(*adminKeys), Threshold: *adminThreshold}, *appsFile)
		if p != nil && len(machineCerts) > 0 { // every unlock policy needs machine certificates (machine-cert)
			p.MachineCerts = readMachineCerts(machineCerts)
			err = checkUnlockPolicy(p)
		}
		// A holder keeps machine revocations per admin-key generation (review2 L2): a policy for a new generation
		// must carry every earlier one itself, or each holder forgets them.
		if err == nil && *previous != "" {
			var prev split.UnlockPolicy
			readJSON(*previous, &prev)
			err = carryRevocations(p, &prev)
		} else if err == nil && *base == "" && len(p.MachinesRevoked) == 0 {
			fmt.Fprintln(os.Stderr, "unlock-policy: no -base or -previous: no machine revocation carried over (a new admin-key generation's holders "+
				"keep none of the old one's; pass -previous with the last policy unless this is the first)")
		}
		if err == nil {
			err = pinBuilds(p, holderBuilds)
		}
		if err != nil {
			die("%v", err)
		}
		describeApps(os.Stderr, p.Apps)
		printJSON(p)
	case "approve":
		if *dryRun && *emergency != "" {
			die("approve: -dry-run signs nothing, so no -emergency (check the policy without it)")
		}
		if *base == "" || (!*dryRun && (*out == "" || *signKey == "")) {
			die("approve: -base U.json -sign-key K -out DIR (or -base U.json -dry-run)")
		}
		var p split.UnlockPolicy
		readJSON(*base, &p)
		var tl *safety.TrustList
		if *trustBase != "" {
			tl = &safety.TrustList{}
			readJSON(*trustBase, tl)
		}
		var entry *safety.TrustRelease
		if *trustRelease != "" {
			entry = &safety.TrustRelease{}
			if err := json.Unmarshal(readFile(*trustRelease), entry); err != nil {
				die("%s: %v", *trustRelease, err)
			}
		}
		var adds []releaseSpec
		for _, r := range releases {
			rs, err := parseReleaseSpec(r)
			if err != nil {
				die("%v", err)
			}
			adds = append(adds, rs)
		}
		var sets []split.SignedShareSet
		for _, f := range shareSets {
			var ss split.SignedShareSet
			readJSON(f, &ss)
			sets = append(sets, ss)
		}
		var certs []split.SignedEpochCert
		for _, f := range epochCerts {
			var c split.SignedEpochCert
			readJSON(f, &c)
			certs = append(certs, c)
		}
		grace, err := parseTCBGrace(*tcbGrace)
		if err != nil {
			die("%v", err)
		}
		var np *split.UnlockPolicy
		var ntl *safety.TrustList
		mAdd, mRevoke := readMachineCerts(machineCerts), revocationHashes(revokeMachines)
		switch {
		case expediteOnly(*emergency, emergencyItems, adds, removes, sets, grace):
			np, err = nextSeq(p, now) // the override alone: a release pinned earlier unlocks at once from this seq
		case len(adds) == 0 && len(removes) == 0 && len(sets) == 0 && grace == nil && (len(mAdd) > 0 || len(mRevoke) > 0 || *endOverlap):
			np, ntl, err = nextSeqs(p, tl, now) // a machine change, or the overlap's end, alone
		default:
			np, ntl, err = approve(p, tl, adds, removes, entry, sets, certs, grace, now)
		}
		if err == nil {
			err = changeMachines(np, ntl, mAdd, mRevoke)
		}
		if err == nil && *endOverlap {
			if ntl == nil {
				die("approve: -end-overlap needs -trust-base (it is a trust-list member)")
			}
			ntl.SetOverlapEnded()
			err = ntl.Validate()
		}
		if err != nil {
			die("%v", err)
		}
		if *emergency != "" {
			m := masterFrom(parseKMSID(np.KMSID), shares, keys, *devMaster)
			err := attachEmergency(np, m, adds, emergencyItems, *emergency, now)
			if err == nil && ntl != nil {
				// The same items in the trust list: clients take them at once too (their 24 h delay, safety/trustdelay.go).
				var prev []string
				if tl != nil {
					prev = tl.RevokedReleases
				}
				err = attachTrustEmergency(ntl, prev, m, np.KMSID, adds, emergencyItems, *emergency, now)
			}
			clear(m)
			if err != nil {
				die("%v", err)
			}
			em, _ := np.Emergency.Open(parseKMSID(np.KMSID), np)
			fmt.Printf("EMERGENCY override: %d release(s) unlock at once at every holder (each alerts); items %s\n", len(adds),
				strings.Join(em.Items, ", "))
		} else if len(emergencyItems) > 0 {
			die("approve: -emergency-item needs -emergency REASON")
		}
		if *dryRun {
			describeApps(os.Stderr, np.Apps)
			fmt.Fprintf(os.Stderr, "approve -dry-run: unlock policy seq %d (%d release(s)) and the trust list: unsigned, nothing written\n",
				np.Seq, len(np.Releases))
			printDigests(os.Stderr, np, ntl)
			os.Stdout.Write(wouldSign(np, ntl))
			return
		}
		switch {
		case *emergency == "" && *expect == "":
			die("approve: -expect would-sign.json, the -dry-run output of this same command (it signs only what that showed)")
		case *emergency != "" && *expect != "":
			die("approve: -emergency has no dry run, so no -expect")
		case *expect != "":
			if err := matchDryRun(readFile(*expect), np, ntl); err != nil {
				die("approve: %s: %v (nothing signed)", *expect, err)
			}
		}
		printDigests(os.Stderr, np, ntl)
		uk := readAdminKeys(*signKey)
		var tk []ed25519.PrivateKey
		if ntl != nil {
			if *trustKey == "" {
				die("approve: -trust-key (the safety admin key) signs the trust list")
			}
			tk = readAdminKeys(*trustKey)
		}
		if err := writeApproved(*out, np, ntl, uk, tk); err != nil {
			die("%v", err)
		}
	case "holder-push":
		raw := readFile(*in)
		var env safety.Envelope
		var p split.UnlockPolicy
		if err := kms.Strict(raw, &env); err != nil || env.Kind != split.KindUnlockPolicy || kms.Strict(env.Payload, &p) != nil {
			die("%s isn't a signed kms-unlock-policy", *in)
		}
		if *worker == "" {
			die("holder-push: -worker URL (the Worker takes the policy first, so a VM fetches it before holders need it)")
		}
		targets := []split.HolderURL{{Holder: "holder", URL: *url}}
		var native map[string]string
		if *url == "" {
			if *nativeFile == "" {
				die("holder-push: -native native-addresses.json (each holder's provider-native address: Cloudflare must not be the only route)")
			}
			var err error
			if native, err = readNative(*nativeFile, p.Holders); err != nil {
				die("%v (nothing was pushed)", err)
			}
			targets = p.Holders
		}
		if err := pushWorker(ctx, client.HTTP{Base: *worker}, raw, p.Seq); err != nil {
			die("%v (no holder was pushed)", err)
		}
		fmt.Printf("worker %s: serves policy seq %d\n", *worker, p.Seq)
		do := func(ctx context.Context, base string, body []byte) ([]byte, error) {
			return client.HTTP{Base: base}.Do(ctx, "POST", "/v1/policy", body)
		}
		if err := pushHolders(ctx, do, raw, targets, native, os.Stdout); err != nil {
			die("%v; policy seq %d (push again; holders that took it already refuse older ones)", err, p.Seq)
		}
	case "split-dev":
		ids := strings.Split(*holderURLs, ",")
		d, err := splitdev.New(ids, *threshold, now)
		if err != nil {
			die("%v", err)
		}
		if err := writeSplitDev(d, *out); err != nil {
			die("%v", err)
		}
		fmt.Printf("dev KMS id %s, %d-of-%d across %s: %s\n", d.KMSID, *threshold, len(ids), *holderURLs, *out)
	case "machine-cert":
		if *out == "" {
			die("machine-cert: -out F (a new file)")
		}
		doc, err := machineDoc(*builtin, *ppid, *fmspc, *label, *issuedAt, now)
		if err != nil {
			die("%v", err)
		}
		id := parseKMSID(*kmsIDStr)
		if *devMaster != "" && kms.IDString(id) == verifier.ReleaseKMSID {
			die("machine-cert: -dev-master is for staging; production takes two passphrase shares")
		}
		m := masterFrom(id, shares, keys, *devMaster)
		c, err := split.NewMachineCert(m, kms.IDString(id), doc)
		clear(m)
		if err != nil {
			die("%v", err)
		}
		if err := writeNew(*out, c); err != nil {
			die("%v", err)
		}
		fmt.Printf("machine certificate %s (%s %s, PPID %s, FMSPC %s): %s\n", c.Hash(), doc.Host, doc.Label, orDash(doc.PPID), doc.FMSPC, *out)
	case "break-glass":
		var env safety.Envelope
		readJSON(*policyPath, &env)
		admin := kms.AdminKeys{Keys: parseKeysOrNil(*adminKeys), Threshold: *adminThreshold}
		var p split.UnlockPolicy
		if err := admin.Open(&env, split.KindUnlockPolicy, &p); err != nil {
			die("%s: %v", *policyPath, err)
		}
		if *kmsIDStr == "" {
			*kmsIDStr = p.KMSID
		}
		id := parseKMSID(*kmsIDStr)
		if *devMaster != "" && verifier.ReleaseKMSID != "" && kms.IDString(id) == verifier.ReleaseKMSID {
			die("break-glass: -dev-master is for staging; production takes two passphrase shares")
		}
		if *boots < 1 || *relay == "" || *signKey == "" {
			die("break-glass: -relay URL -sign-key K and -boots 1 or more")
		}
		m := masterFrom(id, shares, keys, *devMaster)
		defer clear(m)
		h, served, err := breakGlassHolder(m, kms.IDString(id), p, split.PolicyHash(env.Payload), admin, *adminGen, *staleTCB, *boots) // only this policy
		if err != nil {
			die("%v", err)
		}
		att, _ := json.Marshal(glass.BreakGlassAttach{KMSID: kms.IDString(id), IssuedAt: now})
		attach, _ := json.Marshal(safety.Sign(glass.KindBreakGlassAttach, att, readAdminKeys(*signKey)...))
		fmt.Fprintf(os.Stderr, "break-glass: serving %d boot(s) through %s (Ctrl-C to stop)\n", *boots, *relay)
		err = glass.ServeRelay(ctx, client.HTTP{Base: *relay}, attach, h.Handler(), func() bool { return *served >= *boots })
		if err != nil {
			die("%v", err)
		}
		fmt.Fprintf(os.Stderr, "break-glass: served %d boot(s); M cleared\n", *served)
	}
}

func parseKMSID(s string) ed25519.PublicKey {
	id, err := kms.ParseID(s)
	if err != nil {
		die("-kms-id: %v", err)
	}
	return id
}

func parseKeysOrNil(s string) []ed25519.PublicKey {
	if s == "" {
		return nil
	}
	k, err := safety.ParseKeys(s)
	if err != nil {
		die("-admin-keys: %v", err)
	}
	return k
}

// masterFrom rebuilds M from two (or more) passphrase shares, or reads a staging dev M; either way M must derive
// id.
func masterFrom(id ed25519.PublicKey, shares, keys []string, devMaster string) []byte {
	var m []byte
	if devMaster != "" {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(readFile(devMaster))))
		if err != nil {
			die("%s: %v", devMaster, err)
		}
		m = b
	} else {
		if len(shares) < 2 || len(shares) != len(keys) {
			die("give two -share FILE -key pass pairs")
		}
		var err error
		if m, err = combineShares(shares, keys); err != nil {
			die("%v", err)
		}
	}
	d, err := kms.DeriveID(m)
	if err != nil || !d.Public().(ed25519.PublicKey).Equal(id) {
		clear(m)
		die("these shares don't rebuild the KMS id %s", kms.IDString(id))
	}
	clear(d)
	return m
}

// combineShares opens each share (passphrase or recipient key, loadShare) one at a time and combines them.
func combineShares(paths, keys []string) ([]byte, error) {
	var parts []kms.Share
	defer func() {
		for _, p := range parts {
			clear(p.Y)
		}
	}()
	for i := range paths {
		sh, k, err := loadShare(paths[i], keys[i])
		if err != nil {
			return nil, err
		}
		y, err := kms.Open(k, kms.LabelShare, kms.ShareAAD(sh.KMSID, sh.Index, sh.Epoch), sh.Sealed)
		if err != nil {
			return nil, fmt.Errorf("%s doesn't open", paths[i])
		}
		if slices.ContainsFunc(parts, func(p kms.Share) bool { return p.X == sh.Index }) {
			clear(y)
			return nil, fmt.Errorf("share %d given twice", sh.Index)
		}
		parts = append(parts, kms.Share{X: sh.Index, Y: y})
	}
	return kms.Combine(parts)
}

// resplit splits m to the holders and writes only the public share set and the sealed holder shares into out (a new
// folder).
func resplit(m []byte, kmsID string, epoch, set uint32, threshold int, holders []split.HolderRecipient, app, firm string,
	now time.Time, out string) error {
	if out == "" || set < 2 || epoch == 0 {
		return errors.New("resplit: -set N (2 or more; the genesis is 1), -epoch E (1 or more) and -out DIR")
	}
	ss, hs, err := split.Resplit(m, kmsID, epoch, set, threshold, holders, now, rand.Reader)
	if err != nil {
		return err
	}
	cert, err := epochCert(m, kmsID, epoch, app, firm, now)
	if err != nil {
		return err
	}
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("resplit: %s exists (write to a fresh folder)", out)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(out, fmt.Sprintf("share-set-%d.json", set)), ss); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(out, fmt.Sprintf("epoch-cert-%d.json", epoch)), cert); err != nil {
		return err
	}
	for _, h := range hs {
		if err := writeNew(filepath.Join(out, fmt.Sprintf("holder-%s-set-%d.json", h.Holder, set)), h); err != nil {
			return err
		}
	}
	fmt.Printf("share set %d of epoch %d: %d-of-%d for %s (%s)\n", set, epoch, threshold, len(hs), kmsID, out)
	return nil
}

// writeNew writes v as JSON to a file that must not exist.
func writeNew(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// holderKeygen makes a holder key: its private key (base64 raw) and its recipient string.
func holderKeygen(curve string) (string, string, error) {
	var c ecdh.Curve
	switch curve {
	case "x25519":
		c = ecdh.X25519()
	case "p256":
		c = ecdh.P256()
	default:
		return "", "", fmt.Errorf("curve %q: x25519 or p256", curve)
	}
	k, err := c.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), split.RecipientString(k.PublicKey()), nil
}

// unlockPolicy builds an unsigned unlock policy.
func unlockPolicy(base, fromKMS, kmsIDStr string, seq uint64, floor, holderURLs string, shareSets, epochCerts []string, breakGlass string,
	now time.Time, admin kms.AdminKeys, appsFile string) (*split.UnlockPolicy, error) {
	var p split.UnlockPolicy
	switch {
	case base != "":
		readJSON(base, &p)
	case fromKMS != "":
		if len(admin.Keys) == 0 {
			return nil, errors.New("-from-kms-policy needs -admin-keys (it is checked)")
		}
		var env safety.Envelope
		readJSON(fromKMS, &env)
		if err := admin.Open(&env, kms.KindPolicy, &p.Policy); err != nil {
			return nil, fmt.Errorf("%s: %w", fromKMS, err)
		}
		p.KMS, p.KMSFloor, p.WorkerKeys, p.SecretsFloor = nil, "", nil, 0 // the key service's own: no holder use
	}
	if kmsIDStr != "" {
		p.KMSID = kmsIDStr
	}
	if seq != 0 {
		p.Seq = seq
	}
	if floor != "" {
		p.Floor = floor
	}
	if p.Epoch == 0 {
		p.Epoch = 1
	}
	p.IssuedAt = now
	if holderURLs != "" {
		p.Holders = nil
		for _, h := range strings.Split(holderURLs, ",") {
			id, u, ok := strings.Cut(h, "=")
			if !ok {
				return nil, fmt.Errorf("-holders ID=URL, got %q", h)
			}
			p.Holders = append(p.Holders, split.HolderURL{Holder: id, URL: u})
		}
	}
	if len(shareSets) > 0 {
		p.ShareSets = nil
		for _, f := range shareSets {
			var ss split.SignedShareSet
			readJSON(f, &ss)
			p.ShareSets = append(p.ShareSets, ss)
		}
	}
	if len(epochCerts) > 0 {
		p.EpochCerts = nil
		for _, f := range epochCerts {
			var c split.SignedEpochCert
			readJSON(f, &c)
			p.EpochCerts = append(p.EpochCerts, c)
		}
	}
	if breakGlass != "" {
		p.BreakGlass = breakGlass
	}
	if appsFile != "" {
		apps, err := policies.Load(readFile(appsFile))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", appsFile, err)
		}
		p.Apps = apps
	}
	if len(p.Apps) == 0 {
		return nil, errors.New("unlock-policy: no app grant, so no release could be pinned (approve refuses a pin for an unknown app): " +
			"pass -apps kms/policies/agent-vm-v1.json")
	}
	if p.Epoch == 1 && len(p.ShareSets) > 0 { // the epoch is the newest share set's
		id, _ := kms.ParseID(p.KMSID)
		for _, ss := range p.ShareSets {
			if s, err := ss.Open(id); err == nil && s.Epoch > p.Epoch {
				p.Epoch = s.Epoch
			}
		}
	}
	return &p, checkUnlockPolicy(&p)
}

// dryRunDoc is approve -dry-run's output: what the same command signs (approve -expect takes it back).
type dryRunDoc struct {
	UnlockPolicy *split.UnlockPolicy `json:"unlock_policy"`
	TrustList    *safety.TrustList   `json:"trust_list,omitempty"`
}

// wouldSign is approve -dry-run's output for np and ntl.
func wouldSign(np *split.UnlockPolicy, ntl *safety.TrustList) []byte {
	b, _ := json.MarshalIndent(dryRunDoc{np, ntl}, "", "  ")
	return append(b, '\n')
}

// matchDryRun is nil only when raw is exactly wouldSign(np, ntl) with each document's issued_at the dry run's (slots
// review M2): an input changed between the dry run and this run (a base, a compose, a trust entry, a certificate) is
// refused rather than signed unseen.
func matchDryRun(raw []byte, np *split.UnlockPolicy, ntl *safety.TrustList) error {
	var d struct {
		UnlockPolicy *struct {
			IssuedAt time.Time `json:"issued_at"`
		} `json:"unlock_policy"`
		TrustList *struct {
			IssuedAt time.Time `json:"issued_at"`
		} `json:"trust_list"`
	}
	if json.Unmarshal(raw, &d) != nil || d.UnlockPolicy == nil {
		return errors.New("not approve -dry-run's output")
	}
	p := *np
	p.IssuedAt = d.UnlockPolicy.IssuedAt
	var tl *safety.TrustList
	if ntl != nil {
		c := *ntl
		if d.TrustList != nil {
			c.IssuedAt = d.TrustList.IssuedAt
		}
		tl = &c
	}
	if bytes.Equal(wouldSign(&p, tl), raw) {
		return nil
	}
	var e dryRunDoc
	json.Unmarshal(raw, &e)
	what := "the unlock policy"
	if e.UnlockPolicy != nil && digest(e.UnlockPolicy) == digest(np) {
		what = "the trust list"
	}
	return fmt.Errorf("%s this run derives isn't the one the dry run showed: run -dry-run again and check it", what)
}

// digest is the sha256 of a policy or trust list as signed (canonical JSON) with its issued_at left out: the same in
// approve -dry-run and the approve that signs it.
func digest(v any) string {
	switch d := v.(type) {
	case *split.UnlockPolicy:
		c := *d
		c.IssuedAt = time.Time{}
		v = &c
	case *safety.TrustList:
		c := *d
		c.IssuedAt = time.Time{}
		v = &c
	}
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// printDigests prints both documents' digests (approve -dry-run, and the approve that signs: they must match).
func printDigests(w io.Writer, np *split.UnlockPolicy, ntl *safety.TrustList) {
	fmt.Fprintf(w, "unlock policy seq %d sha256 %s (issued_at left out)\n", np.Seq, digest(np))
	if ntl != nil {
		fmt.Fprintf(w, "trust list seq %d sha256 %s (issued_at left out)\n", ntl.Seq, digest(ntl))
	}
}

// describeApps sums up each app grant, for the person about to sign it.
func describeApps(w io.Writer, apps map[string]kms.AppPolicy) {
	for _, name := range slices.Sorted(maps.Keys(apps)) {
		a := apps[name]
		floor := a.Floor
		if floor == "" {
			floor = "the policy's"
		}
		fmt.Fprintf(w, "app %s: firm %s, floor %s, purposes %s, secrets %s\n", name, a.Firm, floor, strings.Join(a.Purposes, " "), strings.Join(a.Secrets, " "))
	}
}

// checkUnlockPolicy validates a policy and its share sets under its own KMS id.
func checkUnlockPolicy(p *split.UnlockPolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	// Review M2: past its removal date, no policy with the KMS fallback is signed (approve, unlock-policy, sign).
	if err := kms.CheckKMSFallbackRemoval(p.KMSFallback, latest(p.IssuedAt, time.Now())); err != nil {
		return err
	}
	id, err := kms.ParseID(p.KMSID)
	if err != nil {
		return err
	}
	if _, err = p.OpenShareSets(id); err != nil {
		return err
	}
	if _, err = p.OpenMachines(id); err != nil { // every certificate the KMS id's, every one a Phala machine
		return err
	}
	// Fail closed on platforms (the v1 Google host removal): holders built from this tree check only dstack and refuse a policy
	// naming any other (kms/split/holder), so kmsctl doesn't sign one ("dstack-gcp" included).
	for _, pl := range p.Platforms {
		if !verifier.KnownPlatform(pl) {
			return fmt.Errorf("unlock policy: unknown platform %q (holders check only %q)", pl, safety.PlatformDstack)
		}
	}
	return nil
}

// latest is the later of a document's issue time and now: a document dated before the removal date and signed
// after it is still refused.
func latest(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// releaseSpec is approve's -release.
type releaseSpec struct {
	App, Version, AppCompose, Compose string
}

func parseReleaseSpec(s string) (releaseSpec, error) {
	var r releaseSpec
	for _, kv := range strings.Split(s, ",") {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "app":
			r.App = v
		case "version":
			r.Version = v
		case "app-compose":
			r.AppCompose = v
		case "compose":
			r.Compose = v
		default:
			return r, fmt.Errorf("-release: unknown %q", k)
		}
	}
	if r.App == "" || r.Version == "" || r.AppCompose == "" {
		return r, errors.New("-release app=APP,version=vX.Y.Z,app-compose=FILE[,compose=FILE]")
	}
	return r, nil
}

func fileSHA256(p string) string {
	h := sha256.Sum256(readFile(p))
	return hex.EncodeToString(h[:])
}

// approve is the next unlock policy (seq + 1) and, with tl, the next trust list (seq + 1): the releases added, the
// versions removed, the share sets replaced when given. The two always change together.
func approve(p split.UnlockPolicy, tl *safety.TrustList, adds []releaseSpec, removes []string, entry *safety.TrustRelease,
	sets []split.SignedShareSet, certs []split.SignedEpochCert, grace *safety.TCBGrace, now time.Time) (*split.UnlockPolicy, *safety.TrustList, error) {
	if len(adds) == 0 && len(removes) == 0 && len(sets) == 0 && grace == nil {
		return nil, nil, errors.New("approve: nothing to change (-release, -remove, -share-set or -tcb-grace)")
	}
	if tl != nil && len(adds) > 0 && entry == nil {
		return nil, nil, errors.New("approve: a release added to the trust list needs its -trust-release entry")
	}
	np := p
	np.Seq++
	np.IssuedAt = now
	np.Emergency = nil // an override is for one seq only (attachEmergency adds a new one)
	np.Releases = slices.Clone(p.Releases)
	for _, v := range removes {
		n := len(np.Releases)
		np.Releases = slices.DeleteFunc(np.Releases, func(r kms.ReleasePin) bool { return r.Version == v })
		if len(np.Releases) == n {
			return nil, nil, fmt.Errorf("approve: %s isn't pinned", v)
		}
	}
	for _, a := range adds {
		pin := kms.ReleasePin{App: a.App, Version: a.Version, AppComposeSHA256: fileSHA256(a.AppCompose)}
		if a.Compose != "" {
			pin.ComposeSHA256 = fileSHA256(a.Compose)
		}
		np.Releases = append(np.Releases, pin)
	}
	if len(sets) > 0 {
		np.ShareSets = sets
	}
	if len(certs) > 0 {
		np.EpochCerts = certs
	}
	if grace != nil {
		np.TCBGrace = grace
	}
	if err := checkUnlockPolicy(&np); err != nil {
		return nil, nil, err
	}
	if tl == nil {
		return &np, nil, nil
	}
	ntl := *tl
	ntl.Seq++
	ntl.IssuedAt = now
	ntl.Expires = time.Time{}                                   // trust lists don't expire (2026-11-20): a newer seq withdraws
	if _, ok := ntl.Optional[safety.TrustEmergencyMember]; ok { // an override is for one seq only (attachTrustEmergency adds a new one)
		ntl.Optional = maps.Clone(ntl.Optional)
		delete(ntl.Optional, safety.TrustEmergencyMember)
	}
	if grace != nil {
		ntl.TCBGrace = grace // the same grace in both documents
	}
	ntl.Releases = slices.DeleteFunc(slices.Clone(tl.Releases), func(r safety.TrustRelease) bool { return slices.Contains(removes, r.Version) })
	// A withdrawn release is also revoked, so a client refuses it even where its build bundles it.
	ntl.RevokedReleases = slices.Clone(tl.RevokedReleases)
	for _, v := range removes {
		if !slices.Contains(ntl.RevokedReleases, v) {
			ntl.RevokedReleases = append(ntl.RevokedReleases, v)
		}
	}
	// Approving a revoked version again (-release vX) is its un-revocation (review2 H1): it leaves revoked_releases
	// here, and each client keeps it revoked for 24 h from when it first sees it left out (unrevoke:vX,
	// safety/trustdelay.go), as each holder waits 24 h on the pin added again; -emergency expedites both.
	ntl.RevokedReleases = slices.DeleteFunc(ntl.RevokedReleases, func(v string) bool {
		return slices.ContainsFunc(adds, func(a releaseSpec) bool { return a.Version == v })
	})
	if entry != nil {
		if !slices.ContainsFunc(adds, func(a releaseSpec) bool { return a.Version == entry.Version }) {
			return nil, nil, fmt.Errorf("approve: the trust-release entry is %s, not a -release added", entry.Version)
		}
		if a := adds[slices.IndexFunc(adds, func(a releaseSpec) bool { return a.Version == entry.Version })]; a.Compose != "" &&
			fileSHA256(a.Compose) != entry.ComposeSHA256 {
			return nil, nil, errors.New("approve: the trust-release entry's compose isn't the -release compose")
		}
		ntl.Releases = append(ntl.Releases, *entry)
	}
	if err := ntl.Validate(); err != nil {
		return nil, nil, err
	}
	return &np, &ntl, nil
}

// writeApproved signs both documents and writes them into out (a new folder).
func writeApproved(out string, p *split.UnlockPolicy, tl *safety.TrustList, policyKeys, trustKeys []ed25519.PrivateKey) error {
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("approve: %s exists (write to a fresh folder)", out)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(p)
	if err := writeNew(filepath.Join(out, fmt.Sprintf("unlock-policy-%d.signed.json", p.Seq)), safety.Sign(split.KindUnlockPolicy, b, policyKeys...)); err != nil {
		return err
	}
	fmt.Printf("unlock policy seq %d: %d release(s), %d share set(s)\n", p.Seq, len(p.Releases), len(p.ShareSets))
	if tl != nil {
		b, _ := json.Marshal(tl)
		if err := writeNew(filepath.Join(out, fmt.Sprintf("trust-list-%d.signed.json", tl.Seq)), safety.Sign(safety.KindTrustList, b, trustKeys...)); err != nil {
			return err
		}
		fmt.Printf("trust list seq %d: %d release(s)\n", tl.Seq, len(tl.Releases))
	}
	fmt.Println("next: kmsctl holder-push -worker URL -native native-addresses.json -in the unlock policy (the Worker, then every holder at its",
		"tacy.io URL and its provider-native address), then publish the trust list")
	if len(p.Releases) > 0 {
		fmt.Printf("a security withdrawal: push it to every holder's native address too (holder-push -native does), and raise every holder's PolicyFloor to %d at its next deploy\n", p.Seq)
	}
	return nil
}

// breakGlassHolder is the break-glass holder for one policy: M itself, the policy's seq as its floor, the
// attestation checks of a holder. served counts the unlocks it gave.
func breakGlassHolder(m []byte, kmsID string, p split.UnlockPolicy, policyHash string, admin kms.AdminKeys, adminGen string, staleTCB bool, boots int) (*holder.Holder, *int, error) {
	nk := make([]byte, 32)
	rand.Read(nk)
	served := new(int)
	st := &holder.MemoryStore{}
	st.Init(adminGen, p.Seq) // only this policy or a newer one; the admin, present, is the pin delay
	h, err := holder.New(holder.Config{ID: split.BreakGlassHolder, KMSID: kmsID, Admin: admin, AdminGeneration: adminGen,
		PolicyFloor: p.Seq, Master: m, PolicyHash: policyHash, MaxUnlocks: boots, NonceKey: nk, Nonces: holder.NewMemoryNonces(64), Store: st,
		NoPinDelay: true,
		Check:      server.CheckOptions{AllowStaleTCB: staleTCB},
		Notify: func(e holder.Event) {
			if e.Kind == "unlock" && e.OK {
				*served++
			}
			status := "refused: " + e.Reason
			if e.OK {
				status = "SERVED"
			}
			fmt.Fprintf(os.Stderr, "break-glass: %s %s %s instance %s: %s\n", e.Time.Format(time.RFC3339), e.App, e.Release, e.Instance, status)
		}})
	return h, served, err
}

// writeSplitDev writes a dev split's staging files into dir (which must not exist yet): the public ones (kms-id.txt,
// admin.pub, share-set.json, holder-<id>.share.json, unlock-policy.json unsigned) and the dev secrets, marked dev
// (dev-admin.key: base64 seed, for kmsctl -dev-plain-keys; dev-holder-<id>.key: base64 X25519; dev-nonce-<id>.key;
// dev-master.key for a staging break-glass). Staging only.
func writeSplitDev(d *splitdev.Dev, dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("split-dev: %s exists (write to a fresh folder)", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b64 := base64.StdEncoding.EncodeToString
	files := map[string][]byte{
		"kms-id.txt":     []byte(d.KMSID + "\n"),
		"admin.pub":      []byte(kms.IDString(d.AdminPub) + "\n"),
		"dev-admin.key":  []byte(b64(d.Admin.Seed()) + "\n"),
		"dev-master.key": []byte(b64(d.Master) + "\n"),
	}
	set, err := json.MarshalIndent(d.Set, "", "  ")
	if err != nil {
		return err
	}
	files["share-set.json"] = set
	cert, err := json.MarshalIndent(d.Cert, "", "  ")
	if err != nil {
		return err
	}
	files["epoch-cert.json"] = cert
	pol, err := json.MarshalIndent(d.Policy, "", "  ")
	if err != nil {
		return err
	}
	files["unlock-policy.json"] = pol
	for _, h := range d.Holders {
		sh, err := json.MarshalIndent(d.Shares[h], "", "  ")
		if err != nil {
			return err
		}
		files["holder-"+h+".share.json"] = sh
		files["dev-holder-"+h+".key"] = []byte(b64(d.Keys[h].Bytes()) + "\n")
		files["dev-nonce-"+h+".key"] = []byte(b64(d.NonceKeys[h]) + "\n")
	}
	for name, b := range files {
		mode := os.FileMode(0o644)
		if len(name) > 4 && name[:4] == "dev-" {
			mode = 0o600
		}
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// readHolderKey reads a dev-holder-<id>.key (or any base64 raw X25519 private key).
func readHolderKey(path string) (*ecdh.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(string(trim(b)))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("a holder key is base64 of 32 bytes")
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

func trim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// epochCert is epoch's certificate for app and firm, with the activity signer the VM derives from R_e
// (activity.DeriveSigner of the activity-sign/v1 key) so clients can check activity records against the KMS id.
func epochCert(m []byte, kmsID string, epoch uint32, app, firm string, now time.Time) (*split.SignedEpochCert, error) {
	root, err := split.EpochRoot(m, epoch)
	if err != nil {
		return nil, err
	}
	defer clear(root)
	k, err := split.RootKey(root, app, firm, "activity-sign/v1", epoch)
	if err != nil {
		return nil, err
	}
	signer, err := activity.DeriveSigner(k, firm)
	clear(k)
	if err != nil {
		return nil, err
	}
	wpub, err := split.WitnessPublic(root, app, firm, epoch)
	if err != nil {
		return nil, err
	}
	return split.NewEpochCert(m, kmsID, epoch, app, firm, map[string]string{"activity-sign/v1": signer.Public(), split.WitnessPurpose: wpub}, now)
}

// secretsSeal seals values under R_epoch.
func secretsSeal(m []byte, kmsID string, epoch uint32, seq uint64, values map[string]string) ([]byte, error) {
	if seq == 0 || epoch == 0 {
		return nil, errors.New("secrets-seal: -epoch E and -seq N (above the policy's secrets_floor)")
	}
	root, err := split.EpochRoot(m, epoch)
	if err != nil {
		return nil, err
	}
	defer clear(root)
	return split.SealSecrets(root, split.SecretsBundle{KMSID: kmsID, Epoch: epoch, Seq: seq, Values: values})
}

// bundleNames checks a secrets bundle carries exactly the names the grants list, each with a value: a VM's unlock
// fails on a name its grant lists and the bundle lacks (unlock.Keyring.SetSecrets), and a name no grant lists would
// go to the Worker for nothing. Errors name names, never values.
func bundleNames(values map[string]string, apps map[string]kms.AppPolicy) error {
	want := map[string]bool{}
	for _, a := range apps {
		for _, n := range a.Secrets {
			want[n] = true
		}
	}
	var missing, extra []string
	for n := range want {
		if strings.TrimSpace(values[n]) == "" {
			missing = append(missing, n)
		}
	}
	for n := range values {
		if !want[n] {
			extra = append(extra, n)
		}
	}
	slices.Sort(missing)
	slices.Sort(extra)
	if len(missing) > 0 || len(extra) > 0 {
		return fmt.Errorf("the bundle must carry exactly the grants' names: missing or empty %v, not granted %v", missing, extra)
	}
	return nil
}

// parseTCBGrace reads -tcb-grace: until=RFC3339,statuses=A+B[,min-tcb-date=YYYY-MM-DD][,min-tcb-eval=N].
func parseTCBGrace(s string) (*safety.TCBGrace, error) {
	if s == "" {
		return nil, nil
	}
	g := &safety.TCBGrace{}
	for _, kv := range strings.Split(s, ",") {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "until":
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return nil, fmt.Errorf("-tcb-grace until: %w", err)
			}
			g.Until = t
		case "statuses":
			g.Statuses = strings.Split(v, "+")
		case "min-tcb-date":
			g.MinTCBDate = v
		case "min-tcb-eval":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("-tcb-grace min-tcb-eval: %w", err)
			}
			g.MinTCBEval = n
		default:
			return nil, fmt.Errorf("-tcb-grace: unknown %q", k)
		}
	}
	return g, nil
}

// nativeSuffix is the provider-native host each holder must have in native-addresses.json: an address
// whose DNS and TLS the holder's own provider runs, so a push doesn't depend on Cloudflare's tacy.io DNS alone.
var nativeSuffix = map[string]string{"vercel": ".vercel.app", "gcp": ".run.app", "cloudflare": ".workers.dev"}

// readNative reads native-addresses.json ({"vercel": "https://<project>.vercel.app", "gcp": "https://<service>.run.app"}),
// strictly: a known holder id each, an https origin on that provider's own domain. Every holder of the policy but
// Cloudflare (whose own provider runs tacy.io's DNS: its tacy.io URL is its native route) must have one.
func readNative(path string, holders []split.HolderURL) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("native addresses: %w", err)
	}
	var m map[string]string
	if err := kms.Strict(b, &m); err != nil {
		return nil, fmt.Errorf("native addresses: %s: %w", path, err)
	}
	for id, raw := range m {
		suffix, ok := nativeSuffix[id]
		if !ok {
			return nil, fmt.Errorf("native addresses: %q isn't a holder with a native address (vercel, gcp, cloudflare)", id)
		}
		u, err := neturl.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Port() != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" ||
			u.User != nil || u.Fragment != "" || !strings.HasSuffix(u.Hostname(), suffix) || u.Hostname() == strings.TrimPrefix(suffix, ".") {
			return nil, fmt.Errorf("native addresses: %s: %q isn't https://<name>%s", id, raw, suffix)
		}
		m[id] = "https://" + u.Hostname()
	}
	for _, h := range holders {
		if h.Holder != "cloudflare" && m[h.Holder] == "" {
			return nil, fmt.Errorf("native addresses: none for %s (Cloudflare's DNS would be its only route)", h.Holder)
		}
	}
	return m, nil
}

// pushHolders posts the signed policy to each holder at its policy URL and at its native address (native[holder],
// when it has one), printing every answer to out. A holder counts as pushed when at least one route took it; the
// error names the holders no route took.
func pushHolders(ctx context.Context, do func(ctx context.Context, base string, body []byte) ([]byte, error), raw []byte,
	targets []split.HolderURL, native map[string]string, out io.Writer) error {
	var missed []string
	for _, h := range targets {
		routes := []string{h.URL}
		if n := native[h.Holder]; n != "" && n != h.URL {
			routes = append(routes, n)
		}
		took := false
		for _, r := range routes {
			b, err := do(ctx, r, raw)
			if err != nil {
				fmt.Fprintf(out, "%s %s: %v\n", h.Holder, r, err)
				continue
			}
			took = true
			fmt.Fprintf(out, "%s %s: %s\n", h.Holder, r, strings.TrimSpace(string(b)))
		}
		if !took {
			missed = append(missed, h.Holder)
		}
	}
	if len(missed) > 0 {
		return fmt.Errorf("no route took the policy at %s", strings.Join(missed, ", "))
	}
	return nil
}

// unlockPolicyPath is where the Worker serves the newest unlock policy to VMs (GET) and takes a newer one (POST, a
// signed kms-unlock-policy envelope; it keeps only a higher seq).
const unlockPolicyPath = "/api/vm/unlock-policy"

// pushWorker pushes the policy to the Worker and checks that a VM's fetch returns its seq: the Worker serves the new
// policy before any holder refuses the old one.
func pushWorker(ctx context.Context, w client.Transport, raw []byte, seq uint64) error {
	if _, err := w.Do(ctx, "POST", unlockPolicyPath, raw); err != nil {
		return fmt.Errorf("worker push: %w", err)
	}
	b, err := w.Do(ctx, "GET", unlockPolicyPath, nil)
	if err != nil {
		return fmt.Errorf("worker fetch: %w", err)
	}
	var env safety.Envelope
	var p split.UnlockPolicy
	if err := kms.Strict(b, &env); err != nil || env.Kind != split.KindUnlockPolicy || kms.Strict(env.Payload, &p) != nil {
		return errors.New("worker fetch: not a signed kms-unlock-policy")
	}
	if p.Seq != seq {
		return fmt.Errorf("worker fetch returns policy seq %d, not %d", p.Seq, seq)
	}
	return nil
}

// expediteOnly: approve -emergency -emergency-item with nothing else changed (a release pinned earlier, normally,
// that must now unlock at once: the policy's next seq carries only the override).
func expediteOnly(reason string, items []string, adds []releaseSpec, removes []string, sets []split.SignedShareSet, grace *safety.TCBGrace) bool {
	return reason != "" && len(items) > 0 && len(adds) == 0 && len(removes) == 0 && len(sets) == 0 && grace == nil
}

// nextSeq is p at its next seq, unchanged otherwise (no override yet: attachEmergency adds one).
func nextSeq(p split.UnlockPolicy, now time.Time) (*split.UnlockPolicy, error) {
	np := p
	np.Seq++
	np.IssuedAt = now
	np.Emergency = nil
	return &np, checkUnlockPolicy(&np)
}

// attachEmergency signs, with the KMS id M derives, an emergency override for np's seq naming the releases added
// and the extra items (each one of np's policy items; "other" is np's catch-all item), and puts it in np.
func attachEmergency(np *split.UnlockPolicy, m []byte, adds []releaseSpec, extra []string, reason string, now time.Time) error {
	if len(adds) == 0 && len(extra) == 0 {
		return errors.New("approve: -emergency expedites the releases -release adds and the -emergency-item items; there are none")
	}
	var items []string
	all := split.PolicyItems(np)
	for _, it := range extra {
		if it == "other" {
			it = split.OtherItem(np)
		}
		if v, ok := strings.CutPrefix(it, split.ItemRelease); ok && strings.HasPrefix(v, "v") { // release:vX.Y.Z, pinned
			i := slices.IndexFunc(np.Releases, func(r kms.ReleasePin) bool { return r.Version == v })
			if i < 0 {
				return fmt.Errorf("approve: -emergency-item %s: %s isn't pinned in the new policy", it, v)
			}
			it = split.ReleaseItem(np.Releases[i])
		}
		if !slices.Contains(all, it) {
			return fmt.Errorf("approve: -emergency-item %s isn't an item of the new policy", it)
		}
		if !slices.Contains(items, it) {
			items = append(items, it)
		}
	}
	for _, a := range adds {
		h := fileSHA256(a.AppCompose)
		i := slices.IndexFunc(np.Releases, func(r kms.ReleasePin) bool { return r.AppComposeSHA256 == h && r.Version == a.Version })
		if i < 0 {
			return fmt.Errorf("approve: %s isn't pinned in the new policy", a.Version)
		}
		items = append(items, split.ReleaseItem(np.Releases[i]))
	}
	em, err := split.NewEmergency(m, np.KMSID, np.Seq, items, reason, now)
	if err != nil {
		return err
	}
	np.Emergency = em
	return checkUnlockPolicy(np)
}

// attachTrustEmergency signs, with the KMS id M derives, the trust list's emergency override (safety
// SignedTrustEmergency, its optional member "emergency") for ntl's seq: the trust-list entries of the releases added
// and the extra items that are also items of the list (an OS image, a boot set, a platform...; "release:vX.Y.Z" is
// the list's entry for that version). None of them in the list: no override (clients delay as usual).
func attachTrustEmergency(ntl *safety.TrustList, prevRevoked []string, m []byte, kmsID string, adds []releaseSpec, extra []string, reason string, now time.Time) error {
	all := safety.TrustItems(ntl)
	var items []string
	add := func(it string) {
		// An un-revocation (unrevoke:vX) of a version this list leaves out of revoked_releases counts as one it adds.
		v, unrevoke := strings.CutPrefix(it, safety.TrustItemUnrevoke)
		unrevoke = unrevoke && !slices.Contains(ntl.RevokedReleases, v)
		if (unrevoke || slices.Contains(all, it)) && !slices.Contains(items, it) {
			items = append(items, it)
		}
	}
	// A revoked version approved again: its un-revocation is expedited with its release (review2 H1).
	for _, a := range adds {
		if slices.Contains(prevRevoked, a.Version) {
			add(safety.TrustItemUnrevoke + a.Version)
		}
	}
	versions := map[string]bool{}
	for _, a := range adds {
		versions[a.Version] = true
	}
	for _, it := range extra {
		if v, ok := strings.CutPrefix(it, split.ItemRelease); ok && strings.HasPrefix(v, "v") {
			versions[v] = true
			continue
		}
		add(it)
	}
	for _, r := range ntl.Releases {
		if versions[r.Version] {
			add(safety.TrustReleaseItem(r))
		}
	}
	if len(items) == 0 {
		return nil
	}
	em, err := split.NewTrustEmergency(m, kmsID, ntl.Seq, items, reason, now)
	if err != nil {
		return err
	}
	return ntl.SetEmergency(em)
}

// KindUnlockSecrets is the envelope the chat Worker takes a sealed secrets bundle in (the chat Worker's unlock routes).
const KindUnlockSecrets = "kms-unlock-secrets"

// unlockSecretsPath is the Worker's route unlockd fetches the bundle from (gateway.UnlockSecretsPath).
const unlockSecretsPath = "/api/vm/unlock-secrets"

// secretsEnvelope wraps a sealed bundle (split.SealSecrets) for the Worker, signed with the kms-admin key(s).
func secretsEnvelope(sealed []byte, keys []ed25519.PrivateKey) ([]byte, error) {
	if len(sealed) < 12 || string(sealed[:12]) != "TACYSECRETS1" {
		return nil, errors.New("secrets-push: -in isn't a sealed secrets bundle (kmsctl secrets-seal)")
	}
	p, err := json.Marshal(struct {
		Sealed []byte `json:"sealed"`
	}{sealed})
	if err != nil {
		return nil, err
	}
	return json.Marshal(safety.Sign(KindUnlockSecrets, p, keys...))
}

// pinBuilds sets each named holder's pinned build (ID=SHA256) and checks the policy again.
func pinBuilds(p *split.UnlockPolicy, pins []string) error {
	for _, pin := range pins {
		id, build, ok := strings.Cut(pin, "=")
		i := slices.IndexFunc(p.Holders, func(h split.HolderURL) bool { return h.Holder == id })
		if !ok || i < 0 {
			return fmt.Errorf("-holder-build %q: ID=SHA256 for a holder the policy lists", pin)
		}
		p.Holders[i].Build = build
	}
	return checkUnlockPolicy(p)
}

// ---- the machine allowlist (V1-DESIGN §3) ----

// machineDoc is machine-cert's document: a built-in one exactly as this build has it, or one from the flags.
func machineDoc(builtin, ppid, fmspc, label, issuedAt string, now time.Time) (safety.MachineDoc, error) {
	if builtin != "" {
		if ppid != "" || fmspc != "" || label != "" || issuedAt != "" {
			return safety.MachineDoc{}, errors.New("machine-cert: -builtin takes the document as built in (no -ppid, -fmspc, -label or -issued-at)")
		}
		for _, d := range verifier.MachineDocs {
			if verifier.MachineNode(d) == builtin {
				return d, nil
			}
		}
		return safety.MachineDoc{}, fmt.Errorf("machine-cert: -builtin %q isn't a built-in machine", builtin)
	}
	at := now
	if issuedAt != "" {
		t, err := time.Parse(time.RFC3339, issuedAt)
		if err != nil {
			return safety.MachineDoc{}, fmt.Errorf("machine-cert: -issued-at: %w", err)
		}
		at = t
	}
	d := safety.MachineDoc{Type: safety.MachineType, Platform: safety.PlatformDstack, Host: safety.MachineHostPhala,
		Mode: safety.MachineModePPID, PPID: strings.ToLower(ppid), FMSPC: strings.ToLower(fmspc), Label: label, IssuedAt: at.UTC()}
	d.KMSID = verifier.ReleaseKMSID // replaced by the signing key's id
	return d, d.Validate()
}

// readMachineCerts reads machine certificate files.
func readMachineCerts(files []string) []safety.SignedMachineCert {
	var out []safety.SignedMachineCert
	for _, f := range files {
		var c safety.SignedMachineCert
		if err := kms.Strict(readFile(f), &c); err != nil {
			die("%s isn't a machine certificate: %v", f, err)
		}
		out = append(out, c)
	}
	return out
}

// revocationHashes reads -revoke-machine values: a certificate's hash, or its file.
func revocationHashes(vals []string) []string {
	var out []string
	for _, v := range vals {
		if len(v) == 64 && strings.Trim(v, "0123456789abcdef") == "" {
			out = append(out, v)
			continue
		}
		out = append(out, readMachineCerts([]string{v})[0].Hash())
	}
	return out
}

// nextSeqs is p and tl at their next seqs, unchanged otherwise (a machine change alone).
func nextSeqs(p split.UnlockPolicy, tl *safety.TrustList, now time.Time) (*split.UnlockPolicy, *safety.TrustList, error) {
	np := p
	np.Seq++
	np.IssuedAt = now
	np.Emergency = nil
	if tl == nil {
		return &np, nil, nil
	}
	ntl := *tl
	ntl.Seq++
	ntl.IssuedAt, ntl.Expires = now, time.Time{}
	if _, ok := ntl.Optional[safety.TrustEmergencyMember]; ok {
		ntl.Optional = maps.Clone(ntl.Optional)
		delete(ntl.Optional, safety.TrustEmergencyMember)
	}
	return &np, &ntl, nil
}

// changeMachines adds certificates to np and revokes hashes for good (np's machines_revoked only grows; a revoked
// certificate leaves machine_certs), then gives ntl (when there is one) np's machine_certs and the union of both
// documents' revocations, and checks both.
func changeMachines(np *split.UnlockPolicy, ntl *safety.TrustList, add []safety.SignedMachineCert, revoke []string) error {
	np.MachineCerts = slices.Clone(np.MachineCerts)
	for _, c := range add {
		if slices.ContainsFunc(np.MachineCerts, func(o safety.SignedMachineCert) bool { return o.Hash() == c.Hash() }) {
			return fmt.Errorf("approve: machine certificate %s is already in the policy", c.Hash())
		}
		if slices.Contains(np.MachinesRevoked, c.Hash()) || slices.Contains(revoke, c.Hash()) {
			return fmt.Errorf("approve: machine certificate %s is revoked (for good: issue a new one with machine-cert)", c.Hash())
		}
		np.MachineCerts = append(np.MachineCerts, c)
	}
	revoke, extra := machineRevocations(np.MachineCerts, revoke)
	for _, h := range extra {
		fmt.Fprintf(os.Stderr, "approve: also revoking %s: another certificate for the same machine (PPID) as one revoked\n", h)
	}
	for _, c := range add {
		if d, err := machineDocOf(c); err == nil && slices.ContainsFunc(np.MachineCerts, func(o safety.SignedMachineCert) bool {
			od, err := machineDocOf(o)
			return err == nil && slices.Contains(revoke, o.Hash()) && od.Mode == safety.MachineModePPID && od.PPID == d.PPID && d.Mode == safety.MachineModePPID
		}) {
			return fmt.Errorf("approve: machine certificate %s is for a machine being revoked", c.Hash())
		}
	}
	np.MachinesRevoked = slices.Clone(np.MachinesRevoked)
	for _, h := range revoke {
		if !slices.Contains(np.MachinesRevoked, h) {
			np.MachinesRevoked = append(np.MachinesRevoked, h)
		}
	}
	np.MachineCerts = slices.DeleteFunc(np.MachineCerts, func(c safety.SignedMachineCert) bool { return slices.Contains(np.MachinesRevoked, c.Hash()) })
	if err := checkUnlockPolicy(np); err != nil {
		return err
	}
	if ntl == nil {
		return nil
	}
	_, kept, _, err := ntl.TrustMachines()
	if err != nil {
		return err
	}
	revoked := slices.Clone(np.MachinesRevoked)
	for _, h := range kept {
		if !slices.Contains(revoked, h) {
			revoked = append(revoked, h)
		}
	}
	slices.Sort(revoked)
	if err := ntl.SetMachines(np.MachineCerts, revoked); err != nil {
		return err
	}
	id, _ := kms.ParseID(np.KMSID)
	if _, err := safety.OpenMachineCerts(id, np.MachineCerts, revoked, "trust list"); err != nil {
		return fmt.Errorf("approve: the trust list's machines: %w", err)
	}
	for _, pl := range ntl.Platforms {
		if !verifier.KnownPlatform(pl) { // clients refuse the whole list (verifier.WithTrustList): fail closed here too
			return fmt.Errorf("approve: the trust list names unknown platform %q (clients check only %q)", pl, safety.PlatformDstack)
		}
	}
	return ntl.Validate()
}

// carryRevocations adds prev's machines_revoked to p (a policy for a new admin-key generation, review2 L2) and drops
// the revoked certificates from p's machine_certs.
func carryRevocations(p, prev *split.UnlockPolicy) error {
	for _, h := range prev.MachinesRevoked {
		if !slices.Contains(p.MachinesRevoked, h) {
			p.MachinesRevoked = append(p.MachinesRevoked, h)
		}
	}
	p.MachineCerts = slices.DeleteFunc(slices.Clone(p.MachineCerts), func(c safety.SignedMachineCert) bool { return slices.Contains(p.MachinesRevoked, c.Hash()) })
	return checkUnlockPolicy(p)
}

// machineRevocations is revoke plus every known certificate of the same machine (review2 L3: a revocation is per
// certificate, so a second certificate for one PPID, such as one issued with -issued-at now beside the built-in one,
// would stay valid): the policy's certificates and the build's built-in documents with a revoked certificate's PPID.
// extra are the hashes added. A revoked hash whose certificate isn't known here (already out of the policy) adds
// nothing: its other certificates must be named.
func machineRevocations(certs []safety.SignedMachineCert, revoke []string) (all, extra []string) {
	type known struct {
		hash string
		doc  safety.MachineDoc
	}
	var ks []known
	for _, c := range certs {
		if d, err := machineDocOf(c); err == nil {
			ks = append(ks, known{c.Hash(), *d})
		}
	}
	for _, d := range verifier.MachineDocs {
		if h, err := safety.MachineDocHash(d); err == nil {
			ks = append(ks, known{h, d})
		}
	}
	all = slices.Clone(revoke)
	for _, h := range revoke {
		for _, k := range ks {
			if k.hash != h || k.doc.Mode != safety.MachineModePPID {
				continue
			}
			for _, o := range ks {
				if o.doc.Mode == safety.MachineModePPID && o.doc.PPID == k.doc.PPID && !slices.Contains(all, o.hash) {
					all, extra = append(all, o.hash), append(extra, o.hash)
				}
			}
		}
	}
	return all, extra
}

// machineDocOf reads a certificate's document (unverified: only to find its machine; the KMS id's signature is
// checked where it counts).
func machineDocOf(c safety.SignedMachineCert) (*safety.MachineDoc, error) {
	var d safety.MachineDoc
	if err := json.Unmarshal(c.Doc, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

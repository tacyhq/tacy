package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/safety"
)

// The key service (cmd/kmsd, package kms) is its own release with its own compose, kms-compose.yaml: one container,
// its image built like the agent VM's (the reproducible binary on the pinned distroless base, one layer), named by
// digest. No volumes but dstack's socket (kmsd asks it for its own quotes), no environment (every setting is a flag
// here, so the attested compose names it), logging off (nothing it prints reaches a disk), memory swap equal to
// memory (no swap), read-only root, no capabilities. Its app-compose.json (server.KMSAppCompose: the KMS fallback,
// since the provider's gateway needs the provider's KMS; an ephemeral data disk, nothing on it, no pre-launch
// script, only port 8000) is written next to it: its sha256 is what the key service policy pins (Policy.KMS).
//
//	go run ./cmd/compose --kms --kms-release [--check] [--oci DIR] [--manifest kms-release.json --version V --commit C]
//	go run ./cmd/compose --kms --kms-admin-keys ed25519:…[,…] [--kms-admin-threshold N] [--kms-role primary|standby]
//	    [--kms-staging] [--kms-id ed25519:…] [--kms-floor vX.Y.Z] [--kms-peers URL,…] [--oci DIR]
//
// --kms-release is the production key service, the one the committed kms-compose.yaml and the release describe: its
// admin keys are kmsAdminKeys (pinned below), its KMS id the release's (kmsID, verifier.ReleaseKMSID) once there is
// one, and nothing else is a flag. --check and --manifest take only it, so a release can only check and sign that.
// Without a KMS id the replica starts empty (genesis); a release made after genesis pins the id and starts locked.
// --kms-admin-keys has no default: the key service's admins are named on purpose, every time. A staging key service
// (--kms-staging) must have admin keys of its own: none of the production admin keys (adminKeys, kmsAdminKeys) may
// sign for it, so a staging document can never be signed by a key production trusts (each document also names its
// KMS id).

// kmsAdminKeys are the production key service's admin keys (ed25519:<base64>, comma-separated): they sign its genesis,
// policies and secrets bundles. Made offline with `go run ./cmd/kmsctl keygen-admin DIR NAME` (it prints the public
// key for here; the wrapped private key never leaves the admin's machine). They may not be the safety admin keys
// (adminKeys). Empty: not pinned yet, and --kms-release refuses to write or check a release.
const kmsAdminKeys = ""

// kmsAdminThreshold is how many of kmsAdminKeys an admin document needs (1 while there is one admin key).
const kmsAdminThreshold = 1

// Where --kms writes: the docker compose and the app-compose.json the CVM attests; KMSManifestFile is the release
// manifest's usual name (--manifest).
const (
	KMSComposeFile    = "kms-compose.yaml"
	KMSAppComposeFile = "kms-app-compose.json"
	KMSManifestFile   = "kms-release.json"
)

// KMSSchema is kms-release.json's schema.
const KMSSchema = "tacy-kms-release/v1"

// KMSManifest describes the key service's release (kms-release.json, a release asset next to release.json): like the
// agent VM's Manifest, everything in it can be recomputed from the tagged source with scripts/reproduce.sh.
type KMSManifest struct {
	Schema     string `json:"schema"`
	Repository string `json:"repository"`
	Version    string `json:"version"` // the tag
	Commit     string `json:"commit"`
	// sha256(kms-compose.yaml) and sha256(kms-app-compose.json): the attested compose and the CVM manifest, whose hash
	// the key service policy pins (Policy.KMS).
	ComposeSHA256    string            `json:"kms_compose_sha256"`
	AppComposeSHA256 string            `json:"kms_app_compose_sha256"`
	Binaries         map[string]string `json:"binaries"` // kmsd -> sha256 of the binary (linux/amd64)
	Images           map[string]string `json:"images"`   // kmsd -> Registry/kmsd@sha256:<digest>, as kms-compose.yaml names it
	BaseImage        string            `json:"base_image"`
	GoVersion        string            `json:"go_version"`
	BuildImage       string            `json:"build_image"`
}

// releaseKMSArgs are the production key service's flags (--kms-release).
func releaseKMSArgs() (KMSArgs, error) {
	return releaseKMSArgsWith(kmsAdminKeys, kmsAdminThreshold, kmsID)
}

func releaseKMSArgsWith(admin string, threshold int, id string) (KMSArgs, error) {
	if admin == "" {
		return KMSArgs{}, fmt.Errorf("kmsAdminKeys isn't pinned (cmd/compose/kms.go): the key service's release needs its admin public key")
	}
	keys, err := safety.ParseKeys(admin)
	if err != nil {
		return KMSArgs{}, fmt.Errorf("kmsAdminKeys: %w", err)
	}
	safetyKeys, _ := safety.ParseKeys(adminKeys)
	for _, k := range keys {
		for _, s := range safetyKeys {
			if k.Equal(s) {
				return KMSArgs{}, fmt.Errorf("kmsAdminKeys: %s is a safety admin key (adminKeys); the key service needs its own", kms.IDString(k))
			}
		}
	}
	return KMSArgs{AdminKeys: admin, AdminThreshold: threshold, KMSID: id, Role: kms.RolePrimary}, nil
}

const (
	kmsUID = "10005"
	kmsMem = "512m"
)

var kmsPort = strconv.Itoa(server.KMSPort)

// KMSArgs are kmsd's flags in the compose.
type KMSArgs struct {
	AdminKeys      string // the offline admin keys (comma-separated)
	AdminThreshold int
	KMSID          string // "" = start empty
	Floor          string
	Peers          string
	Role           string // kms.RolePrimary ("" too) or kms.RoleStandby
	Staging        bool   // a staging key service: no production admin key may be among AdminKeys
}

// kmsdArgs is the command line the compose gives kmsd.
func kmsdArgs(a KMSArgs) ([]string, error) {
	keys, err := safety.ParseKeys(a.AdminKeys)
	if err != nil || len(keys) == 0 {
		return nil, fmt.Errorf("kms admin keys: %v", errOr(err, "none"))
	}
	if a.AdminThreshold < 1 || a.AdminThreshold > len(keys) {
		return nil, fmt.Errorf("kms admin threshold %d of %d keys", a.AdminThreshold, len(keys))
	}
	if a.Staging {
		prod, _ := safety.ParseKeys(adminKeys)
		if kmsAdminKeys != "" {
			k, _ := safety.ParseKeys(kmsAdminKeys)
			prod = append(prod, k...)
		}
		for _, k := range keys {
			for _, p := range prod {
				if k.Equal(p) {
					return nil, fmt.Errorf("a staging key service needs its own admin keys: %s is a production admin key", kms.IDString(k))
				}
			}
		}
	}
	switch a.Role {
	case "":
		a.Role = kms.RolePrimary
	case kms.RolePrimary, kms.RoleStandby:
	default:
		return nil, fmt.Errorf("kms role %q (want %s or %s)", a.Role, kms.RolePrimary, kms.RoleStandby)
	}
	args := []string{"-listen", ":" + kmsPort, "-admin-keys", a.AdminKeys, "-admin-threshold", strconv.Itoa(a.AdminThreshold), "-role", a.Role}
	if a.Staging {
		args = append(args, "-staging") // its policy may let e2e overlays in (server.Config.Staging)
	}
	if a.KMSID != "" {
		if _, err := kms.ParseID(a.KMSID); err != nil {
			return nil, err
		}
		args = append(args, "-kms-id", a.KMSID)
	}
	if a.Floor != "" {
		if _, ok := kms.CompareVersions(a.Floor, a.Floor); !ok {
			return nil, fmt.Errorf("kms floor %q isn't vX.Y.Z", a.Floor)
		}
		args = append(args, "-floor", a.Floor)
	}
	if a.Peers != "" {
		for _, p := range strings.Split(a.Peers, ",") {
			if !strings.HasPrefix(p, "https://") {
				return nil, fmt.Errorf("kms peer %q isn't https://", p)
			}
		}
		args = append(args, "-peers", a.Peers)
	}
	return args, nil
}

func errOr(err error, s string) string {
	if err != nil {
		return err.Error()
	}
	return s
}

// generateKMS returns kms-compose.yaml for the kmsd image ref (Registry/kmsd@sha256:…) and its binary's sha256.
func generateKMS(ref, binSHA256 string, a KMSArgs) (string, error) {
	args, err := kmsdArgs(a)
	if err != nil {
		return "", err
	}
	q := make([]string, len(args))
	for i, s := range args {
		q[i] = `"` + s + `"`
	}
	var b strings.Builder
	b.WriteString(`# Generated by go run ./cmd/compose --kms from the key service's source. Don't edit by hand.
#
# The Tacy key service: one container, kmsd, holding the master key in memory only. Its image is the pinned
# distroless base (` + baseImage + `)
# plus one layer with /tacy/kmsd (linux/amd64, sha256 ` + binSHA256 + `).
# No volumes but dstack's socket (its own quotes), no environment, logging off, no swap.
services:
  kmsd:
    image: ` + ref + `
    entrypoint: ["/tacy/kmsd"]
    command: [` + strings.Join(q, ", ") + `]
    restart: unless-stopped
    user: "` + kmsUID + `:` + kmsUID + `"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    ports:
      - "` + kmsPort + `:` + kmsPort + `"
    volumes:
      - ` + server.DstackSocket + `
    logging:
      driver: none
    mem_limit: ` + kmsMem + `
    memswap_limit: ` + kmsMem + `
    ulimits:
      core: 0
`)
	out := b.String()
	if err := server.CheckCompose(out); err != nil {
		return "", fmt.Errorf("kms-compose.yaml: %w", err)
	}
	if w := refusedWord(out); w != "" {
		return "", fmt.Errorf("kms-compose.yaml would contain %q, which Phala refuses", w)
	}
	return out, nil
}

// kmsMain is --kms: build kmsd's image and write (or check) kms-compose.yaml and kms-app-compose.json; with a
// manifest path, also write the release manifest (KMSManifest) for version and commit.
func kmsMain(check bool, ociDir, devOut, manifest, version, commit string, a KMSArgs) {
	if v, err := run(nil, "go", "env", "GOVERSION"); err != nil || strings.TrimSpace(v) != goVersion() {
		fail(fmt.Errorf("go is %q, want %s: %v", strings.TrimSpace(v), goVersion(), err))
	}
	base, err := fetchBase()
	if err != nil {
		fail(err)
	}
	bin, err := buildBinary("./cmd/kmsd")
	if err != nil {
		fail(err)
	}
	h := sha256.Sum256(bin)
	img, err := buildImage(base, "kmsd", bin)
	if err != nil {
		fail(err)
	}
	d, err := img.Digest()
	if err != nil {
		fail(err)
	}
	ref := registry + "/kmsd@" + d.String()
	out, err := generateKMS(ref, hex.EncodeToString(h[:]), a)
	if err != nil {
		fail(err)
	}
	ac, err := server.KMSAppCompose([]byte(out))
	if err != nil {
		fail(err)
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{KMSComposeFile, []byte(out)}, {KMSAppComposeFile, ac}} {
		if check {
			if cur, _ := os.ReadFile(devPath(devOut, f.name)); string(cur) != string(f.data) {
				fmt.Println(f.name + " is stale or was edited: run go run ./cmd/compose --kms --kms-release")
				os.Exit(1)
			}
		} else if err := os.WriteFile(devPath(devOut, f.name), f.data, 0o644); err != nil {
			fail(err)
		}
	}
	if ociDir != "" {
		if err := writeLayout(filepath.Join(ociDir, "kmsd"), img); err != nil {
			fail(err)
		}
	}
	cs, as := sha256.Sum256([]byte(out)), sha256.Sum256(ac)
	if check {
		fmt.Printf("%s and %s match the source, the reproducible binary and its image\n", KMSComposeFile, KMSAppComposeFile)
	}
	fmt.Printf("kmsd binary sha256 %x\nkmsd image %s\n%s sha256 %x (%d bytes)\n%s sha256 %x (the policy's KMS pin)\n",
		h, ref, KMSComposeFile, cs, len(out), KMSAppComposeFile, as)
	if manifest != "" {
		m := KMSManifest{Schema: KMSSchema, Repository: "https://" + modulePath, Version: version, Commit: commit,
			ComposeSHA256: hex.EncodeToString(cs[:]), AppComposeSHA256: hex.EncodeToString(as[:]),
			Binaries: map[string]string{"kmsd": hex.EncodeToString(h[:])}, Images: map[string]string{"kmsd": ref},
			BaseImage: baseImage, GoVersion: goVersion(), BuildImage: image}
		j, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(manifest, append(j, '\n'), 0o644); err != nil {
			fail(err)
		}
		fmt.Printf("wrote %s\n", manifest)
	}
}

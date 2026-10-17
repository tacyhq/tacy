# Tacy

Tacy runs AI agents in confidential VMs. Your requests are encrypted to a key that exists only inside a VM whose code you can check, so nobody else can read them, us included.

This repository is the code inside that trust boundary: everything the agent VM runs, how its definition is built reproducibly, and the verifier that checks a running VM.

## Why it's public

Attestation proves which code a VM runs. It proves nothing about what that code does. So the code has to be public, rebuildable, and every release signed in a public log. Then a client can check that a VM runs a release from this repository, and anyone can read and rebuild that release.

Only what runs inside the VM, and what checks it, is here. Everything outside only sees ciphertext and metadata.

## What's here

| Path | What |
|---|---|
| `app/` | `agentd`, the front door and runtime: `GET /attest`, `POST /run` (end-to-end encrypted, EHBP), the `harness/v1` runtime with its queue and journal. It holds the per-boot HPKE key but no API keys, and has no network: requests reach it through gatewayd. |
| `brain/`, `cmd/brain/` | Our agent loop as a `harness/v1` brain: untrusted, in its own container with no network, no keys and one unix socket to the runtime. |
| `cmd/gatewayd/`, `gateway/` | `gatewayd`, the only process with a network: the model gateway and the web connector (from `guard/`), leak scanning, one leased key per call; it also forwards the published port to agentd's socket without reading the encrypted bodies. `gateway/` is the internal `gateway/v0` protocol between agentd and gatewayd. |
| `cmd/vaultd/`, `vault/` | `vaultd`, the vault: holds the API keys, no network, releases one key per call to gatewayd only, for a granted connector and exact host, and records every lease without the value. |
| `guard/` | The runtime side the brain can't bypass: model gateway (attested models only), web connector (search, page reading, images, site icons) with PII masking and a public-only fetcher, leak scanning, and the events people see. |
| `harness/` | The `harness/v1` protocol between brain and runtime: messages, strict codec, runtime engine, fake runtime and the conformance suite every brain must pass. |
| `queue/` | The runtime's task queue and journal in SQLite on the VM's encrypted disk; a run's rows are deleted when it ends. |
| `leakscan/` | Credential scanner (patterns ported from IronClaw, MIT; decodes before scanning): blocks credentials in an agent's outbound arguments and redacts them from what comes back. |
| `proto/` | Wire format shared by the service and its verifiers. |
| `internal/tinfoil/` | Verifies the model provider's enclave (Tinfoil, AMD SEV-SNP, Sigstore-signed releases) before the VM sends it anything. |
| `internal/tdx/` | Intel TDX quote verification and dstack event log replay. |
| `internal/procinfo/` | Each process logs its uid, groups and network interfaces at start. |
| `verifier/` | Checks a running agent VM's attestation (Go library), including the pinned boot measurements (`measurements.go`). |
| `release/` | Checks that a compose is a signed release of this repository (Sigstore). |
| `wasm/` | The verifier compiled to WebAssembly, for the browser. |
| `agentclient/` | Attest, verify, then send encrypted runs; used by the service's end-to-end tests. |
| `cmd/compose/` | Generates `compose.yaml` (the VM's definition: embeds the source and pins the four binaries' sha256) and the release manifest. |
| `compose.yaml`, `pins.go` | What the VM runs. Its sha256 is what the attestation measures and what a release signs. `pins.go` embeds it for the browser verifier. |
| `scripts/` | `build-wasm.sh` (browser verifier), `reproduce.sh` (rebuild a release and compare). |
| `.github/workflows/` | CI (tests, and the compose rebuilt on the runner and in the pinned Go container must match) and the release workflow that signs. |
| `testdata/` | A recorded attestation from a test VM on dstack 0.6.1 (public data: quote, event log, app compose), used by the verifier's tests. |
| `docs/` | Specs: [harness/v1](docs/20-harness-protocol.md) (brain ↔ runtime) and [gateway v0 and the vault](docs/21-gateway-v0.md). |

## How it works

1. **Boot.** The VM (Intel TDX, dstack 0.6.1) runs `compose.yaml`: four processes, each in its own container with its own uid, linked only by unix sockets ([docs/21](docs/21-gateway-v0.md)): `agentd` (front door and runtime), `brain` (the agent loop, untrusted), `gatewayd` (service `agentvm`, the only one with a network) and `vaultd` (the keys). A one-shot `build` container builds the four binaries from the embedded source and refuses to finish unless each has its pinned sha256; every other container checks its own pin again before running it. agentd makes a fresh HPKE key in memory.
2. **Attest.** `GET /attest?nonce=<64 hex>` returns a TDX quote whose report_data is `sha512("sealed-agent-vm/v1" || 0x00 || nonce || hpke_public_key)`, plus the event log and the app compose.
3. **Verify.** The client checks the quote (Intel signature chain, collateral, revocation, TCB, debug off), the key binding, the event log replay to RTMR3 and the compose hash, a production OS image, pinned boot measurements (MRTD, RTMR0-2: firmware, kernel, initramfs, root filesystem and VM size), the pre-launch script, no init script, and that the compose is a signed release.
4. **Run.** Requests and responses are encrypted to the verified key. No request logs; a run's task and journal sit in the queue on the VM's encrypted disk while it runs and are deleted when it ends.

## How the browser verifies a VM

The web app loads the WebAssembly verifier (`wasm/`, built with `scripts/build-wasm.sh`; JavaScript entry point `globalThis.sealedAgentVM`). For each VM it:

1. asks the VM for `/attest` with a fresh random nonce;
2. fetches the Sigstore bundle for the attested compose's sha256 from GitHub's attestations API (through a relay, which can't forge one);
3. runs `verifyRelease`: every check above, in the same Go code as `verifier/` and `release/`;
4. only if all checks pass, encrypts the request to the HPKE key the quote binds.

The release check accepts a compose only if this repository's release workflow signed it on a version tag at or above the pinned minimum (below).

## Reproduce the compose and binary hashes

```sh
mise exec -- go run ./cmd/compose --check
```

It rebuilds the four binaries the way the VM does (linux/amd64, `CGO_ENABLED=0`, `-trimpath`, no VCS stamp, Go 1.27.2) and checks that `compose.yaml` matches this tree byte for byte, then prints the compose sha256 and each binary's. To see exactly what a compose runs: `go run ./cmd/compose --extract DIR`. CI runs the same check on the runner and in the pinned Go container and fails on any difference.

**The compose hash** is `sha256(compose.yaml)`. dstack copies the file unchanged into `app-compose.json` (`docker_compose_file`), whose own hash is the attested `compose-hash`. The verifier hashes that attested copy, so the signed value and the measured value are the same bytes.

**Status:** the live agent VM doesn't yet run a signed release built from this repository; v0.1.0 will be the first. Until then, its hashes come from the same code built in a private tree with a different Go module path, so they don't match a build of this repository.

To rebuild a published release and compare it with its manifest:

```sh
scripts/reproduce.sh v0.1.0
```

It clones the tag, rebuilds in the pinned Go container (`cmd/compose`'s image, by digest) and compares with the release's `release.json`. Needs git, curl and docker.

## Releases and signing

A release is a tag `vMAJOR.MINOR.PATCH` (no suffixes). `.github/workflows/release.yml` builds it and publishes a GitHub Release with three files:

| File | What |
|---|---|
| `compose.yaml` | What the VM runs. It embeds the source and pins the sha256 of the four binaries (`agentd`, `brain`, `gatewayd`, `vaultd`). |
| `release.json` | Manifest: `schema` (`tacy-release/v1`), `repository`, `version`, `commit`, `compose_sha256`, `binaries` (name → sha256), `go_version`, `build_image`. |
| `compose.sigstore.json` | The Sigstore bundle that signs both files. |

Signing uses GitHub artifact attestations (`actions/attest-build-provenance`) on Sigstore's public-good instance: the release job gets a short-lived Fulcio certificate for its GitHub Actions OIDC identity (no long-lived keys), signs an in-toto statement (SLSA provenance v1) with `compose.yaml` and `release.json` as subjects, and the signature is logged in Rekor. The workflow has two jobs: `build` (read-only token, tests and build) and `release` (checks out nothing, runs no repository code; only it can get the OIDC token), so test or build code can't sign anything.

The verifier (`release/`) accepts a bundle only if all of these hold:

| Field | Required value |
|---|---|
| Issuer | `https://token.actions.githubusercontent.com` |
| Certificate SAN | `https://github.com/tacyhq/tacy/.github/workflows/release.yml@refs/tags/vX.Y.Z` |
| Source repository | `https://github.com/tacyhq/tacy`, ref `refs/tags/vX.Y.Z` (same tag) |
| Repository and owner ids | `1423086047` and `233153967` (GitHub's numeric ids of tacyhq/tacy and tacyhq; certificate extensions `1.3.6.1.4.1.57264.1.15` and `.17`). Names can be taken again after a delete or rename, ids can't. |
| Build signer and build config | the SAN above (release.yml is the top-level workflow) |
| Trigger, runner | `push` (of the tag), `github-hosted` |
| Certificate | chains to Sigstore's Fulcio, has an embedded SCT, valid when the signature was logged |
| Transparency log | a Rekor entry with an inclusion proof |
| Statement | SLSA provenance v1, with a subject named `compose.yaml` whose sha256 is the VM's compose hash |
| Version | the tag, at least the pinned minimum |

Sigstore's trusted root is embedded (`release/trusted_root.json`, from Sigstore's TUF repository); refresh it with `RECORD=1 go test ./release -run TestRecordTrustedRoot` and review the diff.

**Getting the bundle:** `GET https://api.github.com/repos/tacyhq/tacy/attestations/sha256:<compose sha256>` (no auth for a public repo). GitHub often answers with `"bundle": null` and a short-lived `bundle_url` to Azure blob storage serving the bundle Snappy-compressed; `release.FetchBundles` follows it (https to `*.blob.core.windows.net` only, no redirects, size and time limits). GitHub may also list its own attestation for immutable release assets (`"initiator": "github"`, no Rekor entry), which the verifier refuses; try each bundle (`release.VerifyAny`). The release asset `compose.sigstore.json` is the same bundle. By hand:

```sh
gh attestation verify compose.yaml --repo tacyhq/tacy \
  --signer-workflow tacyhq/tacy/.github/workflows/release.yml --source-ref refs/tags/v0.1.0
```

**Rollback protection:** a relay could serve an older, validly signed release with a known bug, so the verifier refuses releases older than `release.MinVersion` (`release/release.go`, currently `v0.1.0`), raised when a release must stop being used. A caller can raise the minimum further but never lower it, and can pass the newest version it has accepted before (`release.Policy.LastSeen`; the optional last argument of the browser's `verifyRelease` and `verifyReleaseBundle`) so a relay can't move it back. Pre-release tags are never accepted.

## Boot measurements

A signed compose says what the app is. What boots underneath it (firmware, kernel, initramfs, root filesystem) and on what VM shape is pinned separately: the verifier accepts a quote only if its MRTD and RTMR0-2 are one of the sets in `verifier.BootMeasurements` (`verifier/measurements.go`), and that set is for the OS image the event log reports. A new set needs a new verifier build, not a new compose.

| Register | Covers | Changes when |
|---|---|---|
| MRTD | the firmware (dstack's OVMF) | the OS image changes (or QEMU moves across 9.0, which changes how pages are added) |
| RTMR0 | firmware configuration: TD HOB (memory size), ACPI tables (vCPUs, devices, hotplug, PCI hole, QEMU version), boot variables | the VM size or VM configuration changes |
| RTMR1 | the kernel, with the setup header the firmware patches | the OS image or the memory size changes |
| RTMR2 | kernel command line (carries the root filesystem's dm-verity hash) and initramfs | the OS image changes |

The verifier accepts only **dstack-0.6.1 on 1 vCPU / 2 GiB** (Phala tdx.small, QEMU 8.2.2). Its values were computed with `dstack-mr` (Dstack-TEE/dstack v0.6.1, commit `7f14314`, built from source) from `dstack-0.6.1.tar.gz` of the GitHub release `mkosi-os-v0.6.1` (its `sha256sum.txt` hashes to the os-image-hash `ec43cb8c…`; `metadata.json` says `is_dev: false`; MRTD is the image's two-pass value in `measurement.tdx.cbor`, which QEMU 8.2.2 uses), and they equal the quote of a real VM (`testdata/attest-061.json`, checked by `TestRecorded061Offline` and `TestBootMeasurementsRecorded`). Older images (dstack 0.5.8, 0.5.9, 0.6.0) are kept in `RetiredImages` / `RetiredBootMeasurements` for the record and refused.

To compute a set yourself:

```sh
git clone --depth 1 --branch v0.6.1 https://github.com/Dstack-TEE/dstack && (cd dstack/dstack && cargo build --release -p dstack-mr-cli)
dstack/dstack/target/release/dstack-mr diagnose --vm-config vm_config.json --image-dir <unpacked image> \
  --actual-mrtd … --actual-rtmr0 … --actual-rtmr1 … --actual-rtmr2 …     # the VM's vm_config and quote, from /attest
```

Not checked by us: a full rebuild of the dstack OS image from source (the image bytes are trusted as published; what is checked is that the measured VM runs exactly those bytes).

## Develop

```sh
mise exec -- go test -short ./...    # offline
mise exec -- go test ./...           # adds Intel PCS, live Tinfoil verification and the compose rebuild (network)
mise exec -- go run ./cmd/compose    # after editing anything the four binaries build from
scripts/build-wasm.sh                # browser verifier -> wasm/verifier.wasm
```

## What's not here

The rest of Tacy is closed and outside the trust boundary: the web app and the relay service (accounts, rate limits, billing), the control plane (scheduling, start/stop, metrics), infrastructure and deploy tooling. They only see ciphertext and metadata.

What you still have to trust, honestly:

- **The web app** that runs the checks in your browser is served by us. Closing that gap is planned.
- **Hardware vendors** (Intel, AMD, NVIDIA). TEEs have been broken by side channels and physical attacks before.
- **Metadata:** timing, sizes and IP addresses are visible outside the VM.

## Legacy identifiers

Tacy was renamed from an earlier working name. These identifiers keep the old name on purpose, because they are part of the protocol or of signed data:

- `sealed-agent-vm/v1`: the attestation format version and the report_data label.
- User agents: `sealed-agent-vm/0.1` (the VM's requests to verify Tinfoil: its enclave, GitHub proxy and AMD's key server) and `Mozilla/5.0 (compatible; sealed-agent/0.1)` (web pages, images and site icons the VM fetches).
- `globalThis.sealedAgentVM`: the browser verifier's JavaScript entry point.
- `testdata/attest-061.json`: the recorded VM ran a compose that predates this repository (old Go module path in its embedded source).

## Security

Report vulnerabilities privately to info@tacy.io, not in a public issue.

## License

Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).

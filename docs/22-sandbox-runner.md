# Sandbox runner: the brain in gVisor

> **Status:** in the agent VM since v0.4.0. The brain (our agent loop, untrusted) runs in a gVisor sandbox that `runnerd` starts for agentd. The hands' profile (code execution for agents) exists in `runner/` but is off in the release. Code: `runner/` (protocol `runner/v0`, profiles), `cmd/runnerd`, `sandbox/` (rootless runsc, gVisor pins in `sandbox/gvisor.go`), agentd's brain supervisor (`app/brains.go`), `cmd/brain -fd`.

Builds on [harness/v1](20-harness-protocol.md) (the brain ↔ runtime protocol) and [gateway v0 and the vault](21-gateway-v0.md) (agentd, gatewayd and vaultd as separate uids over unix sockets).

## 1. Why
The brain is the part of the VM most exposed to what comes from outside: model output and web pages. It holds no keys and has no network, but before v0.4.0 it ran as an ordinary process in its own container, so a bug that gave an attacker code execution in it met only the container boundary (the guest kernel's full syscall surface). In gVisor the brain talks to gVisor's own kernel (the Sentry), which runs in a jail of its own; reaching the guest kernel takes a second, independent escape.

## 2. Measured on the VM
On a test VM (Phala tdx.small: 1 vCPU, 2 GiB; dstack 0.6.1, kernel 6.18, Docker 26, cgroup v2, no AppArmor, no `/dev/kvm`), gVisor release `20260928.0`:
- **Platform:** systrap works (gVisor's default) and ptrace works; KVM isn't available in a TDX guest.
- **Docker's `runtime: runsc` isn't possible:** dstack's `daemon.json` is part of the measured OS image. So our own process, runnerd, calls runsc directly.
- **Rootless is enough:** runsc in rootless mode needs no capability at all, only Docker's seccomp profile off (it refuses the user namespace runsc makes). The minimal root alternative needs `CAP_SYS_ADMIN`, `SETUID`, `SETGID` and `SETFCAP`.
- **Cost:** sandbox start 70-310 ms; an idle sandbox about 18 MiB and 32 threads in runnerd's container. Syscalls cost about 30 µs each on one vCPU (systrap can't use its fast path), so syscall-heavy code is 10-200x slower; CPU-bound code isn't slower.
- **Isolation checks:** inside, only `lo` (connects fail, DNS fails); the root is read-only; host sockets are refused (`--host-uds=none`); an already connected socket passed as a descriptor (`--pass-fd`) works.

## 3. Design
```
 agentd ── runner/v0 (unix socket, peer uid 10003) ──► runnerd (uid 10004, no capabilities, no network, no keys)
   │  socketpair: one end passed with the create            │ runsc --rootless (systrap, --network=none,
   │  (SCM_RIGHTS), the other served as harness/v1          │   --host-uds=none, --directfs=false, --ignore-cgroups)
   │                                                        └── brain sandbox: root holding only /brain, uid 65534,
   └────────────────────── harness/v1 over the socketpair ────── its one link is fd 3 (no socket path inside)
```
- **runnerd** (`cmd/runnerd`, service `runner`): the only process that runs runsc. uid 10004 with agentd's gid as its primary group (its 0660 socket is agentd's to open), `cap_drop: [ALL]` with nothing added, `no-new-privileges`, Docker's seccomp off (the only relaxation), read-only root, no network, no environment, 640 MiB (no swap) and 512 pids for the container, a 64 MiB `exec` tmpfs for runsc's state and the brain's root. It mounts only its socket volume. At start it checks that the gVisor release and runsc hash the compose names are the ones built into it (`sandbox.CheckPins`), checks the four gVisor binaries in its image against their pins, copies the brain binary to its tmpfs and checks the copy's hash; any mismatch stops it.
- **runner/v0:** one unix connection per sandbox, and the sandbox lives exactly as long as it. Frames as harness/v1 (length + JSON, strict decoding): `create` with a profile name, then `destroy` (or `exec`, hands only); runnerd says `exited` when the workload ends; a dropped connection destroys the sandbox. agentd can't name a root, mount, flag, uid or limit: profiles are runnerd's. Only agentd's uid gets in (`SO_PEERCRED`). A create takes exactly the profile's descriptors (the brain: one), each checked to be a connected unix stream socket, received close-on-exec. At most 4 sandboxes at once. The brain's output reaches runnerd's log a line at a time, prefixed with the sandbox id, control characters replaced, cut at 2 KiB.
- **The brain's sandbox:** the brain is the sandbox's first process, uid 65534, no capabilities, no_new_privs, an OCI seccomp deny-list inside gVisor (ptrace, mount, namespaces, keyrings, bpf, perf, io_uring, ...), a read-only root holding only `/brain`, `/proc` only, `--network=none`, `--host-uds=none`, `--overlay2=none`, `--directfs=false` (the Sentry opens no host files), `RLIMIT_NPROC` 256, 256 files, `GOMEMLIMIT` 384 MiB.
- **agentd** (`app/brains.go`, `-runner-socket`): makes a socketpair, sends one end with the create, closes its copy and serves the other as the harness/v1 connection. The socketpair has exactly two ends, so nothing else can connect, and there is no listening socket for the brain. When either side ends (the brain crashed or exited, the runtime closed a hung brain, runnerd restarted) agentd destroys the sandbox and starts a new one (backoff 250 ms, doubling to 10 s while brains live less than a minute). Tasks resume from their checkpoints on the new connection (docs/20).
- **Safety controls** ([docs/23](23-safety-controls.md)) are unchanged: they sit between the runtime and gatewayd, so a stop or an exhausted budget ends a run whatever the brain does.

## 4. Images and pins
- runnerd's image is the pinned distroless base, a gVisor layer (`/tacy/gvisor`: `runsc` and `gvisor-bin/{gvisor_sentry,gvisor-sentry-prewarmer,runsc-fd-parking}`) and a layer with runnerd and the brain. There is no separate brain image: one digest pins runnerd, the brain and gVisor together, and nothing is copied at boot.
- gVisor is Google's release build for x86_64, not built by us (its build is Bazel, a second toolchain to make reproducible). `cmd/compose` downloads the release tarball (`$TACY_GVISOR_TARBALL` for a local copy), checks its SHA-256, takes exactly the four binaries and checks each against `sandbox/gvisor.go`; only the pinned bytes go into the layer, so the image digest is reproducible. The layer is about 99 MB compressed (the binaries keep their debug info; stripping would change the pinned bytes) and changes only with a gVisor upgrade.
- `release.json` names the gVisor release, URL and hashes (`gvisor`), so `scripts/reproduce.sh` compares them too.
- **The verifier** adds no check: the compose check and the image rule (runnerd's image by digest) cover it. It reports facts read from the runner's arguments (`verifier.SandboxFacts`): `brain sandbox` ("gVisor 20260928.0 (systrap, rootless runsc), no network"), `gvisor release`, `gvisor runsc sha256`, `brain binary sha256`.
- **Upgrading gVisor:** new hashes by review, the real-gVisor tests, a test VM, then a release.

## 5. Threat model
An attacker who controls the brain has to cross, in order:
1. **gVisor's Sentry**, the kernel the brain talks to. Without that, the brain can reach only its own tasks and what the runtime and the gateway allow it to ask for.
2. **runsc's jail around the Sentry:** its own user, mount (an empty root), pid, network (empty), IPC and UTS namespaces; runsc's host seccomp filter; "root" only over its own user namespace's objects.
3. **The host as uid 10004** in runnerd's container: no capabilities, no network, no keys, only its read-only image and its own socket. It can't connect to runnerd as agentd (the peer check wants 10003), and nothing of vaultd's, gatewayd's or agentd's is mounted there.
4. **The guest kernel:** reading vaultd's or agentd's memory from there needs a kernel privilege escalation. With Docker's seccomp off for runnerd, the whole syscall table is reachable, user namespaces included. **This is the residual risk:** a Sentry escape, then out of runsc's jail, then a kernel bug. A full guest compromise reaches every process in that VM (one firm's), not other firms'.

**Next:** a narrow seccomp filter that runnerd installs on itself (inherited by runsc) denying what runsc never needs; a uid per sandbox before more than one brain or any hands share runnerd (today one brain, so sandboxes can't reach each other); an option to put the brain and the hands in one VM and gatewayd and vaultd in another, so even a full guest compromise reaches no credentials; gVisor built by us, reproducibly.

## 6. Limits and risks
- Rootless runsc can't make per-sandbox cgroups, so runnerd's container limits bound everything it runs (today one brain).
- Some syscalls and `/proc` files are missing or differ in gVisor; a pids cgroup set too low kills a whole sandbox, so the brain uses `RLIMIT_NPROC`.
- We run Google's binaries, checked by hash, not rebuilt.
- Not covered: GPUs, network-enabled hands, checkpoint/restore of a sandbox.

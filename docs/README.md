# Specs

Design specs for the code in this repository. The numbers are stable ids that code comments and other docs link to, so they have gaps; start with the protocol and read in order.

| Doc | What it covers | Code |
|---|---|---|
| [20 harness/v1](20-harness-protocol.md) | The protocol between the untrusted brain (the agent loop) and the runtime: messages, framing, task lifecycle, replay, limits, what the brain can never do. | `harness/`, `brain/` |
| [21 Gateway v0 and the vault](21-gateway-v0.md) | agentd, gatewayd and vaultd as separate processes; leak scanning; typed connectors with one leased key per call; what gets recorded. | `gateway/`, `guard/`, `vault/`, `leakscan/` |
| [22 Sandbox runner](22-sandbox-runner.md) | The brain in a rootless gVisor sandbox: measurements on the VM, design, image pins, threat model. | `runner/`, `sandbox/`, `cmd/runnerd/` |
| [23 Safety controls](23-safety-controls.md) | Signed policies and stop lists, the kill switch, budgets reserved before each call, vault rate limits, keys. | `safety/`, `cmd/safetysign/` |
| [24 Activity records](24-activity-records.md) | What a run did, with no content: signed, chained per recipient and sealed to the person's key. | `activity/` |
| [27 Tasks, the reader and permission prompts](27-tasks-and-reader.md) | Tasks that outlive a tab, the queue, the quarantined reader for untrusted text, taint, model fallback, asking the person before data leaves. | `guard/`, `queue/`, `app/` |

How the browser verifies a VM, reproducible builds, release signing and the pinned boot measurements are in the top-level [README](../README.md). Release history is in [CHANGELOG.md](../CHANGELOG.md).

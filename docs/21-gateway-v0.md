# Gateway v0 and the vault: separate processes in the agent VM

> **Status:** built and running in the agent VM (`app/`, `cmd/gatewayd`, `cmd/vaultd`, `gateway/`, `vault/`, `guard/`, `leakscan/`). "Not done yet" at the end lists what's left.

Builds on [harness/v1](20-harness-protocol.md): an untrusted brain, our Go runtime and guard, and typed connectors.

## 1. Why our own gateway
Our agents act through **typed connectors**: the gateway makes each API call itself (`web.search`, later `mail.move` with folder checks), so it needs no CA, no TLS interception and no DNS hijacking. A general-purpose egress proxy would mostly duplicate what the guard already does (a public-only dialer, secret injection) and add a large amount of code to the trusted path, which every reviewer would have to read. So the gateway is a small Go process built from the guard's connectors. TLS interception may be needed later for code we don't control (builders' containers); that is decided when it comes up.

Ideas kept from that comparison:
- the deny check in `Dialer.Control`, after DNS resolution (DNS rebinding can't get past it);
- refusing a request to a secret's host if it lacks the placeholder;
- a header allowlist on outbound requests;
- one audit record per request, with a decision per rule.

## 2. Leak scanning (`leakscan/`)
The patterns are ported from IronClaw's leak detector (`crates/substrates/ironclaw_safety/src/leak_detector.rs` in `nearai/ironclaw`, commit `b0b999d9`; MIT, notice in `leakscan/NOTICE` and the file header). Standard library only.

- **Patterns:** 21 of the upstream 23 (vendor keys: OpenAI, Anthropic, AWS, GitHub, Stripe, Google, Slack, Twilio, SendGrid, OpenRouter, Telegram, Groq; PEM, SSH and PGP private keys; JWTs, `Bearer` and `Authorization:` values; 64-character hex, warn only). NEAR AI session ids and IronClaw's own sandbox placeholders are dropped; our placeholder format (`{{NAME}}`, warn only) is added. Ten siblings of our own are added, all blocking: `aws_temp_access_key` (`ASIA…`), `openai_service_key`, `anthropic_admin_key`, `stripe_restricted_key`, `stripe_webhook_secret`, `slack_app_token`, `slack_refresh_token`, `gitlab_token`, `google_oauth_client_secret`, `google_oauth_token` (32 in all).
- **Decoding before scanning:** upstream scans raw strings, so percent-encoding one character gets a key past it (their own test documents this). We decode first: percent (up to 4 levels, `+` as space inside percent-encoded tokens), HTML references, JSON and unicode escapes, base64 and base64url segments (16+ characters, any alignment, only if they decode to text), zero-width characters and common look-alikes. Raw and decoded forms are both scanned; findings point at the original bytes.
- **Bounds:** 4 MiB per scan, 4 decoding levels, decoded work at most 8x the input, RE2 only. Past a bound, `Scan` adds a `scan_limit` finding that blocks. `Redact` never refuses; it handles any size in windows.
- **False positives:** 40-hex git SHAs and UUIDs aren't flagged; 64-hex is warn only, never redacted.
- **Tests:** upstream's test vectors as Go table tests (fake keys only), evasion and false-positive tests, and a native Go fuzz test.

**Where it runs** (gatewayd, `guard/leak.go`):
- **Outbound:** every argument a brain chose (search query, fetch URL) is scanned before anything is sent. A credential pattern blocks it: the action result is `denied`, and the person sees the refusal.
- **Responses:** connector responses are redacted before the brain or the person sees them.
- **Leased keys:** the key leased for a call is redacted in every encoding from what comes back (`leakscan.Variants`, plus a search of every decoded form). This includes model output, which isn't pattern-scanned: the prompt is the point and the model is attested.
- **Records:** a hit records the pattern id and where it was, never the match.

## 3. Processes inside the agent VM
```
 people ─EHBP─► gatewayd ──bytes──► agentd (front door + runtime)        no network, no API keys
                (port 8080)          │ HPKE key, AGENT_VM_TOKEN check, harness engine, journal
                                     │
                         harness.sock│ harness/v1                gateway.sock │ gateway/v0 (internal)
                                     ▼                                       ▼
                                brain (untrusted)                     gatewayd (the only network)
                                network none, no secrets              connectors: model, web
                                                                      public-only dialer,
                                                                      leak scan, one key per call
                                                                             │ vault.sock (lease per call)
                                                                             ▼
                                                                      vaultd (holds credentials)
                                                                      network none, peer uid = gatewayd
```

Each process is its own container from the same pinned image, with its own uid, a read-only root filesystem, no added capabilities and `no-new-privileges`. Each socket is 0660, owned by the process that listens, with the group of its one peer, and the listener checks the peer's uid (`SO_PEERCRED`). Each socket directory is a volume mounted only into its two containers. A one-shot `build` container builds the four binaries and checks their pins at boot; it is the only other container with a network, and only while it builds.

| Process | Sees | Can't |
|---|---|---|
| **brain** | Its task's input, model replies, tool results (untrusted) | Network, secrets, other spaces, the gateway or the vault (its only mount is `harness.sock`) |
| **agentd** | Plaintext tasks, the journal, the per-boot HPKE key, the people's event stream | Network; the vault (no mount); API keys |
| **gatewayd** | Each request and response it makes, in plaintext; one leased secret for one call; inbound bytes, which are encrypted to agentd's key | Secrets it didn't lease for this call; space keys; the journal; the plaintext of people's requests |
| **vaultd** | Secret values, grants; names and ids of who asks (task, request, connector, host) | Network; any task content |

- **One way out.** Only gatewayd's container has a network interface. agentd, brain and vaultd run with `network_mode: none`. People's requests still have to reach agentd, so gatewayd publishes the port and copies each inbound connection's bytes to agentd's HTTP unix socket without reading them (the bodies are EHBP-encrypted to agentd's key). gatewayd never connects to agentd any other way, and agentd can't make it connect anywhere except through a typed request. (Docker's `internal: true` networks don't publish ports, and a firewall rule in a custom pre-launch script would replace dstack's reviewed one, so neither was used.) A gatewayd restart drops open connections; the next request works about a second later.
- **The secrets' only home.** dstack's encrypted environment variables (`TINFOIL_API_KEY`, `EXA_API_KEY`, `TAVILY_API_KEY`, `BRAVE_SEARCH_API_KEY`) are given only to vaultd's container. It moves them into memory and unsets them at start. `AGENT_VM_TOKEN` stays with agentd: it checks incoming requests and never goes out. Later, KMS-derived keys and OAuth tokens sealed to the space key are released to the vault only.
- **gateway/v0** (agentd → gatewayd) uses harness/v1 framing and strict decoding. It carries a session per task: agentd sends the task's tools and its journal (actions whole, model calls without their bodies) once, then requests (a `model.call` or an `action`); gatewayd streams the task's events for people (`proto.Event`), then one result per request. A restarted gatewayd rebuilds the task from the journal sent again. It's internal and unfrozen, and only our own code speaks it.
- **The recorder** stays inside agentd for now. gatewayd and vaultd write metadata records (below) to their logs; they are to become signed, chained records sealed to the account.
- **agentd has its own uid (10003), without capabilities.** dstack-0.6.1 creates its guest agent socket with mode 0777, so nothing needs root. The one-shot build container (root) gives agentd `/state/agentd` (0700, where the queue lives) and its socket directories at every boot. It joins the brain's and gatewayd's groups only to share their sockets.

### Secret injection per typed connector
| Request | Secret | Leased only for | Injected as | Checks |
|---|---|---|---|---|
| `model.call` (model gateway) | `TINFOIL_API_KEY` | the verified Tinfoil router host | `Authorization: Bearer`, only after the router's attestation verified; body EHBP-encrypted | Attested models only; response redaction of the key |
| `web.search`, `web.images` | `EXA_API_KEY` (search only, the default since v0.8.10), `BRAVE_SEARCH_API_KEY` or `TAVILY_API_KEY` | `api.exa.ai` / `api.search.brave.com` / `api.tavily.com` | `x-api-key` / `X-Subscription-Token` / `Authorization: Bearer` | Query PII-masked and leak-scanned; response redacted |
| `web.fetch` | none | any public host | - | Public-only dialer, platform denylist, URL PII check, leak scan of the URL; page is untrusted data |
| `mail.*` (later) | OAuth access token for that source | the provider's API host | `Authorization: Bearer` | Folder checks on requests and returned items |
| OAuth refresh (later) | refresh token | the provider's token endpoint only | form body | New tokens go straight back to vaultd (`put`, grant-checked); never to agentd or the brain |

The flow for one request:
1. agentd checks the request against the harness and journals it.
2. gatewayd's connector checks its arguments and runs the leak scan.
3. It asks vaultd for `lease(secret, connector, host, task, request id)`.
4. vaultd checks the grant (connector and the hosts the secret may go to), records the decision and returns the value with a fresh lease id.
5. The connector makes the call and wipes the value. It redacts every encoding of the value from the response, then returns the result.

The gateway keeps no cache, so every use is a lease with a record. The cost is one local socket round trip per call.

**Grants** come from two places:
- **The release:** each connector declares its secrets and hosts in code, which is attested (`vault.ChatGrants`: the Tinfoil key to the model connector for the verified router host, each search key to the web connector for its provider's host).
- **The account's signed policy** (later), which can only narrow these or add sources the account connected.

Rules: exact hosts only, no wildcards. A secret without a grant is never released.

### What gets recorded (metadata only)
| Who | Record |
|---|---|
| vaultd | Each lease: time, secret name, connector, host, task, request id, released or denied (and which rule), lease id |
| gatewayd | Each leak-scan decision: task, request id, operation, pattern ids; never the arguments, URL, host or match |
| agentd | harness/v1 messages it journaled, brain restarts, socket peers refused |

Logs are off on production VMs; the records are for the signed recorder once it exists.

## 4. Fit with harness/v1
- **harness/v1 doesn't change.** The brain still sees only `harness.sock`. On the runtime side, `harness.Guard` is a thin client in agentd (`gateway.Client`) that forwards `ModelCall` and `Action` to gatewayd and relays the events. The connector code in `guard/` runs inside gatewayd unchanged.
- The same code also runs in one process (the guard in agentd), for tests and local development. `app/parity_test.go` runs every recorded scenario both ways and requires the same events.
- When the brain moves under gVisor, only how its container runs changes (`runtime: runsc`); see harness/v1 open question 1.

## 5. The vault (`vault/`, `cmd/vaultd`)
- **Its own process,** serving lease requests on a unix socket:
  - harness/v1 framing, strict decoding (unknown members, duplicate names and bad lengths close the connection);
  - a socket directory only its two containers mount;
  - a peer uid check (`SO_PEERCRED`): only gatewayd's uid gets an answer.
- **Grants:** connector plus exact hosts.
- **Secrets:** read from the environment and then unset.
- **Records:** names and decisions, never values.
- **The `Secret` type** prints and marshals as `[secret]`. `Redact` handles exact-value redaction of the encodings (`leakscan.Variants`).
- **Tests** (`go test ./vault/`, `./guard/` `lease_test.go`, `./app/` `leak_test.go`):
  - the test binary re-runs itself as the vault process, then leases over the socket: allowed, other host, lookalike host, other connector, no grant, not set, bad input;
  - malformed frames get no reply;
  - records never carry values, and values never print;
  - redaction catches every encoding;
  - `Drop` works as revoke;
  - the peer uid is refused (runs on Linux, in CI);
  - end to end through `POST /run`: a credential in a fetched page is redacted before the brain sees it, and one in a brain's arguments is refused, also percent- or base64-encoded.

## Open questions
- Grants for an account's own API keys (builders, later): who signs them, and does widening a grant need two admins like a policy change?
- Per-secret rate limits in the vault (a stuck loop leasing thousands of times): today everything is recorded; limits come with budgets.

## Not done yet
- The recorder's signed records: today the vault's and gateway's metadata records go to their logs, which are off in production.
- Per-secret rate limits in the vault.
- The OAuth connector and refresh-token leases (with the mail connector). Refresh tokens are to be leased only to the gateway's OAuth connector for the token endpoint, and rotated tokens go straight back into the vault.
- A key split across two streamed deltas is caught in the message the brain gets, not in the person's live view (the model never sees the key, so only an upstream echo could produce it).

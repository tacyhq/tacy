# Activity records: what an agent run did, signed and sealed to the person

> **Status:** in the agent VM since v0.5.0. agentd writes two signed records per agent run, chained per recipient and sealed to the person's own key; anyone holding them can check the chain, only the person can open them. Code: `activity/` (format, Recorder, SQLite store, recipient proof), `app/activity.go` (agentd's glue: the recorder between the runtime and the safety checks), `guard/facts.go` (what gatewayd saw per request).

Builds on [harness/v1](20-harness-protocol.md), [gateway v0 and the vault](21-gateway-v0.md) (gatewayd and vaultd send metadata up to agentd), [the sandbox runner](22-sandbox-runner.md) and [safety controls](23-safety-controls.md) (policy hashes, stops, budgets).

## 1. What it does
- **Two records per run.** A **start** record (trigger, agent, the signed controls it started under, the models and tools allowed, limits, input size) and an **end** record (each model call and action: kind, name, connector, hosts with request counts and bytes each way, outcome, code, timing, sizes; each key lease by secret name, connector, host and decision; leak-scan pattern ids; budget used; the control that stopped it and why; final status; the site icons' hosts). A run refused at the door gets one **refused** record; a run cut by a restart gets an **interrupted** end from the next process.
- **No content.** No prompt, answer, search query, URL path, page text, tool argument or key value anywhere in a record, sealed or not. Hosts are only inside the sealed body (hosts say a lot).
- **Where they come from.** The recorder (`recGateway`) wraps the safety checks and is both the runtime's guard and the gateway the run uses, so it sees every model call and action the runtime hands on, including refusals by controls. gatewayd collects facts per request (hosts and bytes through a recording `http.RoundTripper` on the fetch and search clients, the model call's sizes, every vault lease decision via `guard.RecordLeases`, leak-scan ids) and returns them with each gateway/v0 result; the site icons' egress comes with the end. The brain, in its gVisor sandbox, never touches any of it: since it only speaks harness/v1 to the runtime, its transport changes nothing on the record (`TestActivityBehindRunner` runs the conformance below with the brain behind runnerd; in CI with real gVisor).

## 2. Records
```
record = { header: base64(header JSON, the exact signed bytes), sig: base64, ct: base64 }
header = { v, chain, seq, prev, time, key, to, enc, ct_sha256, ct_len }
sig    = Ed25519(signing key, "tacy-activity/v1\0" || header)
hash   = SHA-256("tacy-activity/v1\0" || header)      -- the next record's prev
ct     = HPKE base mode to `to` (DHKEM X25519, HKDF-SHA256, AES-256-GCM; info "tacy-activity/v1",
         aad "tacy-activity/v1\0" || chain || "\0" || seq)
chain  = first 16 bytes of SHA-256("tacy-activity/v1/chain\0" || space || "\0" || recipient), hex
```
- The header holds only ids, a time (seconds), keys and sizes: no run id, space, model, host or event kind. Bodies are padded with JSON whitespace to size buckets (1 KiB, 2 KiB, … then 64 KiB steps), so `ct_len` says little. The body repeats `chain` and `seq` and the AAD binds them, so a body can't be moved under another header.
- **Proof of the recipient key.** A run that names `record_to` must carry `record_proof` = HMAC-SHA256(HKDF(X25519(recipient key, the VM's attested EHBP key), "tacy-activity/v1/record-to"), label ‖ to ‖ VM key), made by the client for that boot's key and sent inside the encrypted request body; otherwise the VM refuses the run (`activity/proof.go`). Without it, anyone who saw a person's public key (the relay included: it's in every header) could make the VM write into that person's chain and learn its length.
- **Checking.** Anyone holding records can check signatures and links without the key; only the recipient opens bodies. A removed, reordered, edited or forged record fails (`activity/activity_test.go` `TestTamper`). A truncated tail is caught by the head the VM announces at the next run, and later by published heads.
- **Out of the VM.** The run's last event before `done`/`error` is `activity` with its sealed records (inside EHBP), and the run's `meta` event names the signing key, the chain and its head (`meta.activity`, authenticated by EHBP to the attested key). The VM keeps records 30 days on the encrypted disk (`/state/agentd/activity/activity.db`; heads and open runs are kept) and serves `GET /activity?chain=&after=` to the relay's bearer token, so a record a client didn't store isn't lost.
- **What a client checks:** both records are signed by the key `meta.activity` names, the end names the start (`start_seq`, same run), then the bodies open. **Continuity:** a client pins the last place it verified per chain (chain id, seq, hash); a new run's start must extend it through the records in between, and the end must extend the start. Records a server dropped, rolled back or replaced fail; when the records in between can't be fetched the result is "unchecked" and nothing is pinned; a new device trusts the first place it sees.

## 3. Keys
| Key | Where it lives | Who sees what |
|---|---|---|
| **Signing key** (Ed25519) | Derived in agentd from dstack's KMS: `GetKey(path "tacy/activity/v1")`, then HKDF with `"tacy-activity/v1/signing-key\0" + firm`. The same after a restart (and across releases while the app's KMS key is the same); locally a key per boot. agentd refuses to start without it | Public half in every record and in `meta.activity`; the private half never leaves agentd's memory |
| **Recipient key** (X25519), today | The person's activity key, made on their device; the VM sees only its public half and the proof (`record_to`, `record_proof` in the encrypted request) | Only the person opens bodies |
| **Recipient key**, later | A space's public key, named by the signed policy rather than by the request | Every member of the space with access to its key |

## 4. Design choices
1. **Two records per run** (start, end), not one per call: fewer signatures, and a start without an end shows a cut run. Per-call records only if a firm needs them live.
2. **Signing key from dstack's KMS**, per firm via HKDF, announced over EHBP in `meta.activity`, not bound into the quote's report_data. A changed key just shows in the chain. An offline key certificate (a quote over the key) can come with a verify page or an export.
3. **Recipient today: the person's own activity key** (`record_to` in the run request); a run without one isn't recorded. Once spaces have keys, the recipient comes from the signed policy and the request can't choose or drop it.
4. **What a record holds:** hosts (sealed), sizes, timings, outcomes, codes, lease names; no keyed content hashes yet, since there's no content to hash. Keyed hashes of sent messages come with a mail connector.
5. **Retention in the VM:** 30 days for records, heads and open runs kept.

## 5. Tests
`go test -race -short ./...` and `go test ./...`:
- `activity/`: round trip, tamper cases (removed, removed first, reordered, duplicated, header edited, seq edited, unknown field, ciphertext edited or swapped, another key's signature, an untrusted key, a dropped signature, a spliced chain), a body moved under another header, recover and refused records, the SQLite store across a reopen and a prune, key derivation, the golden vector (`activity/testdata/vector.json`, which other implementations check against), the recipient proof (forged, another boot, another recipient, flipped).
- `guard/facts_test.go`: leases by name, never values; hosts and policy refusals. `gateway`: facts over the socket.
- `app/activity_test.go`: **conformance: every kind of run (an answer, tool calls, a refusal at the door, an unrecorded run, a budget stop, a run cut by a restart) makes one valid chain from seq 1, every start ended once, no content in any record**, with the brain in-process and behind runnerd; the kill switch on the record; a bad recipient refused; a run with an unproven `record_to` writes nothing.
- `app/activity_safety_test.go`: **the safety controls' decisions on the record**: a model the policy doesn't allow and a stale stop list (refused records with the code), a tool held for approval (left out of the start's tools), a fetch outside the policy's hosts (`policy_denied`, one refused request, none sent), parallel calls against a tool budget (two `ok`, two `budget_exceeded`), the vault's lease rate (`rate_limited` on the call, the lease `denied` by name with no value), and the release without keys (the start names the release policy). None holds the query, URL, page or text.

## 6. Known limits
- The relay could replay a whole encrypted run request it relayed (a general EHBP property: it re-runs the person's request, costs them budget and records a second run truthfully); a nonce check in the VM would close it.
- Per-call facts stay in agentd's memory until the run ends: a crash loses them, and the interrupted record says so.

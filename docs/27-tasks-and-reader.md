# Tasks, the quarantined reader and permission prompts

> **Status:** tasks and the reader in the agent VM since v0.7.0, permission prompts since v0.8.0. Code: `harness/` (task ids, lifecycle, held requests, taint), `guard/tasks.go` (`Host`: start, follow, cancel, resume), `app/tasks.go` (the `/tasks` API), `queue/` (the versioned SQLite queue), `guard/reader.go` (the reader), `guard/permission.go` and `guard/prompts.go` (permission prompts).

Builds on [harness/v1](20-harness-protocol.md), [gateway v0 and the vault](21-gateway-v0.md), [safety controls](23-safety-controls.md) (the reader's model call is budgeted and checked like any other) and [activity records](24-activity-records.md) (the reader's numbers and the taint are on the record).

## 1. Tasks
- **Ids.** `tk_` plus 26 lowercase base32 characters (128 bits). A start with a once-only key gets an id derived from the user and the key (HMAC under a key from dstack's KMS), so a retried start finds the same task instead of making a second one.
- **Lifecycle.** `queued`, `running`, `waiting/<why>`, `paused/<why>`, then `done`, `failed` or `cancelled`. The runtime owns the state. A request the guard holds for a person's decision is journaled `held` and stays held across a restart (never "interrupted"). The three-attempt cap counts brain failures only, not restarts.
- **API.** `POST /tasks` (start), `/tasks/status`, `/tasks/events` (server-sent events from any sequence number, so a closed tab reconnects and sees every event once), `/tasks/cancel`. EHBP-encrypted bodies like `POST /run`; the task id is inside the encrypted body; only the starter's tag sees a task. `POST /run` is a shim over the same task model.
- **Restarts.** Open tasks are resumed after an agentd restart, with their budget and activity record taken up. Ended tasks are pruned after a day.

## 2. The queue
One SQLite file per space on the VM's encrypted disk, the runtime its only writer: tasks (start, options, attempts, state, taint), steering, the journal (every model call, action and exec, recorded before it runs), checkpoints and events. The schema is versioned (`PRAGMA user_version`) and only migrated forward, one transaction per step: 1 is the first release's tables, 2 the task model, 3 the taint. A file newer than the code is refused.

**Rolling back to v0.6.0.** v0.6.0 predates the version number: it doesn't read it and uses only version 1's columns, which a migrated file keeps (the newer columns have defaults), so it runs on the file as is. Tasks open at that moment are cancelled at its boot, as after any restart. Back on v0.7.0, `Open` gives the tasks v0.6.0 ended their state and end time and drops events of tasks it deleted (`TestOlderReleaseOnMigratedFile`).

## 3. Agent definitions, sponsors, triggers (later)
Signed agent definitions, the person an unattended agent runs on behalf of, schedules and steering rights. Not in the VM yet.

## 4. Approve before send (later)
Any send or share, and any change from a tainted task, will be held until a person approves that exact effect with a passkey. `harness.HoldGuard` and the `held` journal state are the runtime's part, in the VM since v0.7.0; the approvals themselves aren't.

## 5. The quarantined reader
A model call with **no tools**, made by gatewayd, never by the brain. It turns one untrusted item (a fetched page, or one search's titles and snippets as a batch) into fixed fields. The acting model gets those fields and quote references, never the source's text. Same pattern as the "dual LLM" and CaMeL: the model that can act never reads the untrusted text, and the one that reads it can't act.

- **Model:** gpt-oss-120b at low effort, through the model gateway: the verified upstream, a leased key, the policy's models, counted in the budget (agentd reserves the reader's largest call with the action) and on the activity record.
- **Fields:** summary, facts, entities, dates, amounts, source (kind, a short title in the reader's words, publisher, date), quotes (id, location, topic, text), wording (for exact-wording questions), and an instruction count.
- **Checked by plain code:** the answer must decode strictly into the schema (exact members, types, enum, caps) or it is refused whole, never repaired; a tool call or a cut-off answer is refused; each quote must be found in the source and is shown as the source has it; 40-character passages of the source copied into the reader's own fields are cut (20 characters when the reader counted an instruction), and so are instruction-like sentences; links it writes are removed; credentials are redacted before it reads.
- **What the acting model sees:** the fields, the source's number and address, and each quote as `[quote N]` with its location, topic and length. Never page text, snippets, a page's or result's own title, or quote text. Image search gives it only each image's site, not the titles. The person's stream carries the exact quotes (`tool_result.quotes`), so the browser shows the words where the answer cites `[quote N]`.
- **When it fails** (an error, a refused answer, or a policy that doesn't allow its model): the source is skipped. The model gets only the address and that it couldn't be read; there is no raw fallback.

### Taint
- A task is **tainted** once its brain has received anything untrusted: web pages, search results, images, and the reader's fields (they come from the same text). The runtime records the taint before the brain sees such a result; every request the brain proposes after that carries `Tainted`. The guard can't follow data through the brain, so taint is per task.
- A task whose input already holds an **earlier assistant turn** is tainted from its start (taint `history`): an earlier answer may carry web-derived text, and the VM can't tell which.
- Taint is on the activity record (each call untrusted or tainted, the run tainted) and in `/tasks/status`. A tainted change or send will need a person's approval once such actions exist.

## 6. Permission prompts
Before data leaves the VM for a task, the person is asked, with exactly what would go out: **Allow once**, **Always allow** (that kind, for the rest of the run) or **Deny**. The model only asks; it can't answer, and it never writes what the person is shown.

- **Kinds.** An action's class is set in the release, never by a model or a policy. Today the class "read, data goes out" is the web connector's three actions, each its own kind: `web.search` (the query goes to a search provider), `web.fetch` (the page's address goes to that site), `web.images` (the query goes to a search provider). Model calls go to the attested model provider and aren't asked about.
- **Settings.** Each run carries the person's setting per kind: `ask` (the default; a kind not named is `ask`), `always` or `never`. A signed policy may cap them with `ask_cap` (per kind: `always`, `ask` or `never`); the narrowest layer wins, so a firm can make its members be asked every time, or turn a kind off. A policy without `ask_cap` caps nothing.
- **The flow.** agentd holds the action (`waiting`, sub-state `permission`; journaled `held`) and adds a `permission` event to the task's stream: the kind, the value that would go out (the masked query or the page's address) and how long it waits. The person's tab answers with `POST /tasks/grant` (`{task, request, kind, decision, value, mac}`, EHBP-encrypted like every task call). agentd checks the grant and hands the action to gatewayd with it; **gatewayd checks it again itself before anything is sent.**
- **The grant.** Until people have identity keys, a grant is `HMAC-SHA256(run secret, "tacy-grant/v1" NUL task NUL request NUL kind NUL decision NUL value)`. The run secret (32 random bytes) is made by the person's tab and sent only inside the run's encrypted body, so only that tab can answer, and the relay can neither read nor forge a grant. A grant for another task, request or kind, a changed value or decision, or a replay is refused (a refused grant leaves the prompt open). A run without a secret can't ask, so kinds on `ask` are refused there (`unavailable`).
- **Edit.** The person may change the value before allowing. The grant carries their value, and gatewayd sends that one (after the same masking and leak scan as any other); the record says it was edited, never the value.
- **Deny.** The action isn't run and the model gets `permission_denied`: answer without it and say it didn't check. The run goes on. **No answer** in time is a deny (`timed_out`): 10 minutes, but never past the run's deadline less a minute, so the model can still answer. With today's 5-minute run deadline a prompt waits about 4 minutes.
- **Restarts.** A prompt still waiting when agentd restarts is shown again with a fresh timeout; grants given before the restart are gone with it.
- **On the record.** Each call that sends data out says how it was allowed: `allowed_once`, `allowed_always`, `always_setting`, `denied`, `timed_out`, `never` or `unavailable`, and whether the value was edited. Never the value.
- **Rolling back to v0.7.0.** v0.7.0 doesn't ask: it ignores the run secret and the settings and sends what the model proposes. A client that relies on the prompts must refuse v0.7.0 (the chat's minimum release is v0.8.0), so a rollback of the VM goes with a rollback of the client.

## 7. Sub-tasks (later)
`task.spawn` and `task.wait` with depth and width caps and one budget per tree; a child of a tainted task is tainted.

## 8. Slices
Each slice is a release on the usual path (a throwaway VM and the end-to-end test first). v0.7.0 has slices 1 (the task model) and 2 (the reader and taint); v0.8.0 slice 3 (permission prompts). `/run` stays as a shim until the chat moves to `/tasks`, then goes one release later.

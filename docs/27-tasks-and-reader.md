# Tasks and the quarantined reader

> **Status:** in the agent VM since v0.7.0. Code: `harness/` (task ids, lifecycle, held requests, taint), `guard/tasks.go` (`Host`: start, follow, cancel, resume), `app/tasks.go` (the `/tasks` API), `queue/` (the versioned SQLite queue), `guard/reader.go` (the reader).

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

## 6. Permission prompts (later)
Asking the person before data leaves (a search, a fetch) for a task: held reads, one-time grants, deny and edit. The runtime's hold is ready; the prompts aren't in the VM yet.

## 7. Sub-tasks (later)
`task.spawn` and `task.wait` with depth and width caps and one budget per tree; a child of a tainted task is tainted.

## 8. Slices
Each slice is a release on the usual path (a throwaway VM and the end-to-end test first). v0.7.0 has slices 1 (the task model) and 2 (the reader and taint). `/run` stays as a shim until the chat moves to `/tasks`, then goes one release later.

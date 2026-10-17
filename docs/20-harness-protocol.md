# harness/v1: the brain–runtime protocol

> **Status:** v1, schema frozen. Implemented in `harness/` (types, strict codec, runtime engine, brain client, fake runtime, conformance suite, reference brain; standard library only). The agent VM runs on it: `app/`'s `/run` is a task on this runtime, the queue is SQLite (`queue/`), and the brain (`brain/`, `cmd/brain`) runs in its own container. Open questions are at the end.

## Shape
The **brain** (the agent harness: our Go loop first, others later) runs untrusted in its own sandbox. Its only link is one local socket to the **runtime**, our Go code in front of the **guard** (model gateway, connectors, vault, recorder, storage). The brain proposes; the runtime checks every message, records it, and has the guard do it.

| Direction | Message | Reply | What |
|---|---|---|---|
| brain → runtime | `hello` | `welcome` or `error` | Handshake, version choice |
| runtime → brain | `start` | (none) | A task to run, or resume from its checkpoint |
| runtime → brain | `steer` | (none) | A person's message to a running task |
| runtime → brain | `cancel` | brain sends `done` | Stop the task |
| brain → runtime | `model.call` | `result` | One completion through the model gateway |
| brain → runtime | `action` | `result` | One typed action (`mail.send`, `web.search`); its id is the outbox key |
| brain → runtime | `exec` | `result` | Run a command in the task's hands sandbox |
| brain → runtime | `checkpoint` | `result` | Store the brain's own state for this task |
| brain → runtime | `status` | (none) | Progress for people, display-only |
| brain → runtime | `done` | `result` | The task ended: succeeded, failed or cancelled |
| either | `error` | (connection closes) | Fatal: the sender closes after it |

## Transport and framing
- **Unix stream socket.** The runtime creates one socket per brain sandbox and mounts it into that sandbox only; the brain connects. One connection at a time: a new one replaces the old (a restarted brain), and the old one is closed. The sandbox has no network interface, so this socket is its only way out.
- **Frame:** 4-byte big-endian length, then that many bytes of one JSON object (UTF-8).

| Choice | Why |
|---|---|
| Length prefix, not newline-delimited | Size is refused from the header, before anything is read or allocated; no delimiter scanning; binary-safe |
| JSON | Matches `proto/`; readable in a transcript; every harness language has it (an adapter in TypeScript needs nothing extra); Go's `encoding/json/v2` is strict by default |
| Not HTTP or gRPC | No HTTP stack in the sandbox, no headers or methods to smuggle through; the protocol is a dozen message types |

**Strict decoding, both sides** (the runtime treats every byte from the brain as hostile; the brain fails closed too):

| Rule | On violation |
|---|---|
| Length 0 or over the receiver's `max_frame` | `bad_frame`, close (header alone decides) |
| Invalid JSON, trailing data, invalid UTF-8 | `bad_frame`, close |
| Duplicate member names (anywhere, tool args included); names that differ only in case | `bad_frame`, close |
| Unknown member (envelope or body) | `bad_frame`, close |
| Nesting deeper than 64 | `bad_frame`, close |
| Unknown type; envelope fields that don't fit the type; malformed id | `bad_frame`, close |
| A type the other side sends (brain sends `start` or `result`); `hello` twice; anything before `hello` | `protocol`, close |
| Body fails the type's checks (sizes, names, enums) | `bad_frame`, close |

A malformed frame is never "partly understood": the connection ends and the runtime restarts the brain from checkpoints. Stream sockets can't be resynchronized after a bad length anyway.

## Handshake and versions
1. Brain sends `hello` within 5 s: `protocols` (versions it speaks, best first), `brain` {name, version} (logs only), `max_frame` (largest frame it accepts, 64 KiB to 4 MiB), `max_tasks` (tasks it runs at once).
2. Runtime picks `harness/v1` if offered and answers `welcome`: `protocol`, `runtime` {name, version}, `limits` (below). Otherwise `error` `unsupported_version` and close.
3. Neither side sends a frame over the other's `max_frame`.

**Within a version the schema is frozen.** Decoders reject unknown fields, so any new field or message is `harness/v2`. A runtime may speak several versions during a migration; the brain lists what it speaks.

## Envelope
`{"type", "task", "id", "re", "body", "error"}`. Which fields a type has is fixed; the rest must be absent.

| Type | `task` | `id` | `re` | `body` | `error` |
|---|---|---|---|---|---|
| `hello`, `welcome` | - | - | - | yes | - |
| `start`, `steer`, `cancel`, `status` | yes | - | - | yes | - |
| `model.call`, `action`, `exec`, `checkpoint`, `done` | yes | yes | - | yes | - |
| `result` | yes | - | yes | one of body / error | |
| `error` | - | - | - | - | yes |

Ids (`task`, `id`, `re`): 1-64 characters of `[A-Za-z0-9._:-]`, starting with a letter or digit. Task ids come from the runtime (random, prefixed, no names); request ids from the brain.

## Messages
| Message | Body fields |
|---|---|
| `start` | `space`, `parent` (child tasks), `attempt` (1, then +1 per brain restart), `agent` {id, version, digest of the signed definition}, `instructions`, `models` (allowed, default first), `tools` [{name, description, parameters (JSON Schema)}], `hands` (exec available), `input` (messages), `limits` {max_steps, max_model_calls, deadline}, `checkpoint` (latest, when resuming) |
| `steer` | `n` (1, 2, ... per task, no gaps), `text` (≤ 64 KiB) |
| `cancel` | `reason` (`person`, `deadline`, `kill_switch`, ...) |
| `model.call` | `model` (from `start.models`), `messages` [{role, content, tool_calls, tool_call_id}], `tools` (names from `start.tools`), `reasoning_effort` (capped by the person's choice, below) |
| result | `message` (assistant; tool calls named by action name, with `args` always a JSON object; when the model's arguments didn't parse, `args` is `{}` with `bad_args` and `raw_args`: the model's text, ≤ 4 KiB, ending `...[truncated]` when cut), `finish_reason`, `usage` {prompt, completion}, `reasoning_effort` (the effort applied) |
| `action` | `name` (lowercase dotted, in `start.tools`), `args` (JSON object, ≤ 256 KiB), `call` (the id of the model tool call it carries out: required and checked, below) |
| result | `status` (`done`, `failed`, `denied`), `output` (untrusted data), `error` |
| `exec` | `argv` (1-64 entries), `stdin` (≤ 1 MiB), `timeout_ms` (≤ 5 min) |
| result | `exit`, `stdout`, `stderr` (capped), `truncated`, `timed_out` |
| `checkpoint` | `seq` (previous + 1), `steer_applied` (highest steer n folded in), `state` (opaque bytes, ≤ 2 MiB) |
| result | `{}` |
| `status` | `note` (1-200 bytes) |
| `done` | `outcome` (`succeeded`, `failed`, `cancelled`), `text` (the answer, ≤ 256 KiB), `error` |
| result | `{}` |

- **The runtime gives the model the tool definitions**, by name; the brain can't add a tool or change its schema. The model sees each name with dots as underscores (`web.search` → `web_search`, `ModelToolName`): OpenAI-style function names allow no dots. `start` refuses two tools that would look the same to the model, and the runtime maps the model's tool calls back to action names, so the brain only ever sees action names.
- **The runtime streams to people itself.** It makes the model call, so it sees the tokens; the brain gets the assembled message. No streaming in the protocol. An action's `call` tells the runtime which tool call it shows the result under.
- **Every action is one the model asked for.** The runtime refuses an action whose `call` isn't the id of a tool call with the same name in the task's latest model result (fresh or replayed): `not_requested`, nothing runs, the task goes on. So every action in the record traces back to a model request. A brain can't act on its own. The runtime also allows **one action per tool call** (a runtime rule; the protocol is unchanged): a second action, under another id, naming a call that an action already carries out is refused `not_requested` and nothing runs. The claims are rebuilt from the journal with every model result, so a replayed result (brain or runtime restart) keeps them; a replay of the action itself is answered from the journal as always.
- **Reasoning effort is capped by the person.** The person's choice for the task is the most the gateway applies: a brain may ask for a lower level, never a higher one. A higher one is clamped to the person's choice, not refused; the result's `reasoning_effort` says what was applied, and the journal keeps it with the result. With no choice from the person the model's default applies whatever the brain asks (no level is known to be below it). A level the model doesn't accept at all is `not_allowed`.
- **Unparsable tool arguments keep the model's text:** `raw_args` beside `bad_args`, capped at 4 KiB. The brain hands the tool call back unchanged in its next `model.call`, and the gateway gives the model `raw_args` as that call's arguments, so the model sees what it wrote.
- **Approvals are invisible to the brain.** An action held for approval just has no result yet. A policy refusal is `status: denied`, a normal outcome the model should see.
- **Child tasks** (*not built yet*): two built-in actions, `task.spawn` (args: instructions, tools ⊆ the parent's, input; result: the child's task id) and `task.wait` (result: the child's outcome). Children are tasks like any other, started with `parent` set, sharing the parent's budget and kill switch. Using actions means a spawn is once-only by the same id rule.

## Ids and ordering
- Requests (`model.call`, `action`, `exec`, `checkpoint`, `done`) each get exactly one `result` with `re` = the request id, unless the connection drops first. Results can come in any order; requests of a task run concurrently up to `max_inflight`.
- Request ids are unique within a task. For `model.call`, `action` and `exec` they are **journal keys** (below). For `checkpoint` and `done` they only match the reply.
- Per task, the runtime sends `start` first, then `steer` in `n` order, then maybe `cancel`. The brain sends nothing for a task before its `start` and nothing after its `done`.
- Frames on the socket are handled in the order received. A steer sent before a result arrives before it.

## Task lifecycle
The runtime owns the state; the brain only reports.

| State (runtime) | Enters when | Protocol |
|---|---|---|
| queued | Task created (queue in the VM's SQLite) | nothing yet |
| running | A brain with room is connected | `start` (attempt 1) |
| waiting for approval | An action is held by the guard | the action's `result` is just late |
| paused | Kill switch "pause", budget | the guard holds results; for long pauses the brain is stopped and later resumed |
| succeeded / failed | Brain sends `done` | `result` `{}`; later requests get `task_closed` |
| cancelled | `cancel` from a person, the deadline or the kill switch | `cancel`; in-flight requests end `cancelled`; brain sends `done` (cancelled) within the grace period, else the runtime ends it anyway. A cancelled task is cancelled whatever `done` says |
| (brain crashed) | Connection lost, or silent for `idle_timeout` with nothing in flight | task stays running; the next brain gets `start` with `attempt` + 1 and the latest checkpoint; after 3 attempts the task fails |

**Steering:** the runtime keeps every steer message (the queue's steering table). The brain folds pending steers in at its next step boundary and records the highest `n` in its next checkpoint (`steer_applied`). On resume the runtime re-sends the steers after `steer_applied`, so none is lost or applied twice.

## Replay and idempotency
The guard is the source of truth for "already done": the runtime journals every `model.call`, `action` and `exec` by (task, request id) **before** the guard runs it, in the same transaction as the outbox entry in the queue's SQLite database.

| The runtime sees | It does |
|---|---|
| New id | Records intent (pending), runs it through the guard, records the outcome, replies |
| Same id, same body | Replies with the recorded outcome; never runs it again. Still running: waits for it, also across a brain restart |
| Same id, different body (or another type) | `id_conflict`; nothing runs |
| Id recorded pending by a runtime that has since restarted | A `replay: safe` request (model calls; reads like `web.search`, `web.fetch`, `web.images`) runs again and its outcome is journaled. Anything that sends or changes something: `interrupted`, not run again (it may or may not have happened) |

"Same body" = sha256 of type + body with whitespace removed. A brain must re-send a replayed request byte for byte, which a deterministic encoder does.

**What a brain must do (checked by the suite):**
1. Derive request ids from its own checkpointed progress (the reference brain: `s3.c`, `s3.m`, `s3.a0` for step 3), never from time, randomness or the attempt.
2. Checkpoint at every step boundary: fold in steers, send `checkpoint`, then the step's `model.call`.
3. On resume, continue from the checkpoint and re-issue the same requests under the same ids. The journal answers the model call (no second bill, same answer), so the same tool calls come back, so the same action ids are proposed, and an action that ran is never repeated, even if the brain died while it ran.

**The journal is also the connectors' memory.** Per-task connector state (the web connector's citation counter, image slots, sites whose icons were shown) isn't stored separately: after a runtime restart, the first request of a task in the new process rebuilds it from the task's journal (`TaskInfo.Journal`: the records in order, with each request's body and outcome). Citation numbers continue after the ones the model saw; nothing is counted twice.

Retention: action and exec records live as long as the task (they are the outbox). Model-call records before the latest checkpoint may be dropped. Planned, not built: sealed copies of the journal and checkpoint go outside the VM before each side effect and at pause/finish, not every step.

## Limits
Announced in `welcome` (a runtime may set lower, never higher):

| Limit | Default | Hard cap |
|---|---|---|
| `max_frame` | 4 MiB | 4 MiB (min 64 KiB) |
| `max_tasks` | min(runtime 8, brain's) | 256 |
| `max_inflight` (per task) | 8 | |
| `idle_timeout_ms` | 60 s | |
| `cancel_grace_ms` | 10 s | |
| `max_checkpoint` | 2 MiB | 2 MiB |

Fixed: handshake 5 s; frame write 10 s; nesting 64; ids 64 chars; steer text 64 KiB, 64 pending per task; `done` text 256 KiB; status note 200 bytes; error message 1 KiB; action args 256 KiB; `raw_args` 4 KiB; 16 tool calls per message; 64 tools; exec argv 64 × 4 KiB, stdin 1 MiB, timeout 5 min; 3 attempts per task. Per task (in `start.limits`, enforced by the runtime): `max_steps`, `max_model_calls` (replays don't count), `deadline`. A result over the brain's `max_frame` becomes a `limit` error. No cap on the number of messages: bytes cap a conversation, through the frame (4 MiB) and checkpoint (2 MiB) limits. A brain whose state outgrows them fails the task cleanly (ours: "the conversation is too long", before it sends the checkpoint).

## What the brain can never do
| It can't | Because |
|---|---|
| Reach the network | No interface in its sandbox; model calls are `model.call`, everything else an `action` through the guard |
| See keys or secrets | It never receives any: no API keys, tokens, space keys; connectors hold them (vault) |
| Store anything that survives it | Its disk is scratch; state survives only as a `checkpoint` the runtime stores encrypted to the space key; it only ever gets its own task's checkpoint back |
| Run code outside the hands | `exec` goes to the task's hands sandbox (no network, no keys), only if `start.hands` |
| Use a model, tool or action not in `start` | Runtime refuses (`not_allowed`) before the guard sees it |
| Repeat a side effect | Ids are once-only; a reused id with another body is refused |
| Approve, raise limits, change policy, write records | Not in the protocol: approvals are people's passkeys, limits and policy are signed, records are written by the recorder from what the guard did |
| Start a child with more rights | `task.spawn` tools must be a subset of the parent's (not built yet) |
| Affect other spaces | One brain sandbox per space; task ids are checked per connection |
| Make its text trusted | `status`, `done` text and checkpoint state are untrusted data: display-only or opaque, never parsed for instructions |

## Errors
| Code | Where | Meaning |
|---|---|---|
| `bad_frame` | `error`, close | Size, JSON, unknown field, field rules |
| `unsupported_version` | `error`, close | No common version |
| `protocol` | `error`, close | Valid frame at the wrong time or from the wrong side |
| `unknown_task` | result | No such task on this connection |
| `task_closed` | result | The task ended |
| `cancelled` | result | The task was cancelled; the request didn't finish |
| `id_conflict` | result | Id used before with another body; nothing ran |
| `id_in_flight` | result | Same id already waiting on this connection |
| `not_allowed` | result | Model, tool or exec not allowed for this task |
| `not_requested` | result | Action whose `call` isn't a tool call of that name in the task's latest model result; nothing ran |
| `limit` | result | In-flight, model-call, size or other limit |
| `invalid` | result | Right shape, wrong value for the task's state (checkpoint `seq`, `steer_applied`) |
| `interrupted` | result | The runtime restarted while it ran; not repeated |
| `internal` | result | Runtime failure; the same id gets the same answer |

Request errors don't end the task: the brain tells the model (a refused tool call becomes a tool message) and goes on. Only `cancelled`, a fatal error or a lost connection stop it.

## Fit with the queue
- One SQLite database per space, the runtime the only writer. Tables the protocol needs: tasks (state, attempt, lease), steering (n per task), journal/outbox (task, request id, kind, hash, state, result), checkpoints (task, seq).
- `Store` in the Go package is that interface: tasks (`AddTask` with the start and the runtime side's options, e.g. the person's reasoning effort and prompt-cache scope; `SetAttempt`, `AddSteer`, `EndTask`, `OpenTasks`, `DeleteTask`) and the journal (`Begin` = record intent with the request body, `Finish` = record outcome, `Journal` = a task's records in order, `SaveCheckpoint`, `Checkpoint`). `MemStore` is the in-memory one the fake runtime uses; `queue/` is the SQLite one (WAL, synchronous FULL, secure_delete; both pass `storetest`). `Runtime.Restore` queues a dead process's open tasks again with their options and steering; `Forget` deletes an ended task. The chat deletes a run's task when it ends and ends the ones a dead process left (nobody can see their answer).
- Messages that arrive while the VM is off (sealed outside it) become `steer` or new tasks after the boot checks; the brain can't tell the difference.

## Code (`harness/`)
| Path | What |
|---|---|
| `protocol.go` | Message types, limits, error codes, per-body checks |
| `codec.go` | Framing, strict decoding (`Decode`, `DecodeResult`), `RequestHash` |
| `runtime.go` | Runtime engine: `Serve` one brain connection; `Start`, `Steer`, `Cancel`, `Wait`; `Guard` and `Store` interfaces |
| `brain.go` | Brain client: `Connect`, `Accept` tasks, `Task.ModelCall`/`Action`/`Exec`/`Checkpoint`/`Status`/`Done`, steers, cancel |
| `fake.go` | `MemStore`; `Fake` runtime for local dev and tests (scripted model, actions, exec; `Listen` on a unix socket; `NewFakeWith` restarts one on the same store) |
| `refbrain/` | Reference brain: the loop above in ~150 lines |
| `conformance/` | `RunBrain` (any harness) and `RunRuntime` (any runtime, as a hostile brain); `TestReferenceBrain`, `TestFakeRuntime` (and `queue`'s `TestRuntimeOnSQLite`) |
| `storetest/` | The `Store` contract, run on `MemStore` and the SQLite queue |
| `../queue/` | The `Store` in SQLite |
| `../brain/`, `../cmd/brain` | Our Go loop as a brain: passes `RunBrain` (`brain_test.go`) |
| `../guard/` | Runtime side of the chat agent: model gateway, web connector, people's events, `Run` (POST /run as a task), per-task state rebuilt from the journal (`rebuild.go`), `ReplaySafe`; `e2e_test.go`, `decisions_test.go`, and the older end-to-end tests (`agentshim_test.go` runs them on the real path) |

`mise exec -- go test -short ./harness/...` runs it all offline in about a second. The suite catches a brain that uses fresh ids on resume (the mail is sent twice), one that ignores steering, and a runtime without the id-conflict check (checked by breaking each on purpose).

**Brain scenarios (`RunBrain`):** handshake; happy path (tool call, result back to the model, checkpoint before every model call); steer mid-run; cancel (brain must send `done` cancelled); replayed action after a crash while the action ran (runs once, model billed once); crash and resume from a checkpoint while a model call ran; runtime restart mid-task (a new runtime on the same store while an action runs: the action comes back `interrupted` and isn't rerun, the task finishes, the new runtime's connectors see the earlier outcomes in the journal); bad arguments (no action, the model told, `raw_args` handed back); a refused request goes back to the model; malformed and oversize frames from the runtime (brain must close). Every brain frame passes the runtime's strict decoder, and no action may be refused `not_requested`.

**Runtime scenarios (`RunRuntime`):** handshake; unsupported version; request before hello; 23 malformed frames (bad JSON, trailing data, unknown fields, duplicate keys incl. inside tool args, case-folded keys, invalid UTF-8, deep nesting, wrong-direction types, bad ids, non-object bodies, bad names, oversize note, `status` with `step` or no note, `raw_args` without `bad_args` or over 4 KiB); empty and oversize frames (refused from the header); duplicate action id (same body: same result, runs once; other body or type: `id_conflict`); replay after reconnecting; action not requested (no `call`, an unknown one, another tool's, one from an older model result: `not_requested`, nothing runs); unknown task; not allowed (action, model, tool, exec); checkpoint `seq` and `steer_applied` rules; requests after `done`; one action per tool call (a second id for a taken call, also after a replayed model result).

Not covered yet: idle timeout (hung brain), attempts cap, `id_in_flight`, deadline, child tasks, a non-Go brain (runs through the same `Brain` func by starting its process on the socket).

## Connectors and the chat agent
Our Go loop is the first real brain (`brain/`, `cmd/brain`): every model call is a `model.call` and every tool an action; no keys, no network, one socket. `guard/` is the runtime side for the chat agent: the model gateway, the web connector, the events people see, and `Run` (POST /run as a task). In the VM the guard's model gateway and connectors run in gatewayd, behind `gateway/v0` ([docs/21](21-gateway-v0.md)).

**Actions to connectors.** An action is named `<connector>.<operation>`. After the runtime's checks (name in `start.tools`, journal), the guard routes the action by its connector part to one connector, which checks its own args and runs. Unknown connector: `not_allowed`. One connector so far, `web` (`guard/web.go`), with PII masking, a public-only fetcher, caps and image re-encoding:

| Action | The model sees | Runs | Chat events |
|---|---|---|---|
| `web.search` | `web_search` | `web_search` | `web_search` |
| `web.fetch` | `web_fetch` | `fetch_page` | `fetch_page` |
| `web.images` | `web_images` | `image_search` | `image_search` |

Result: `done` with the tool's JSON (what the model reads), `denied` when policy refused it (a URL with personal data, a credential in the arguments), `failed` with the tool's error. The brain gives the model `{"error": ...}` for the last two. The chat events keep the older tool names, which the chat client already knows.

**`start` for a chat request** (`guard.StartFor`, from the request checks):
```json
{"space": "s_chat", "attempt": 1, "agent": {"id": "a_chat", "version": "1", "digest": "unsigned"},
 "instructions": "You are a helpful assistant running inside a confidential VM. Today is Tuesday, 13 October 2026 (UTC).\nYou can call these tools: web_search, web_fetch, web_images.\n- ...",
 "models": ["gpt-oss-120b"],
 "tools": [{"name": "web.search", "description": "Search the web. Returns numbered results (title, url, snippet, age). ...",
            "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "count": {"type": "integer", "minimum": 1, "maximum": 8}}, "required": ["query"]}},
           {"name": "web.fetch", ...}, {"name": "web.images", ...}],
 "hands": false, "input": [{"role": "user", "content": "..."}],
 "limits": {"max_steps": 6, "max_model_calls": 6, "deadline": "<now + 5 min>"}}
```
The runtime writes the date into `instructions` when it makes the task, so a resumed brain sends the same model call (same id, same body).

**Who does what.**

| Runtime (guard) | Brain |
|---|---|
| System prompt and date, model, max steps, deadline (`start`) | Step loop; no tools on the last step |
| Reasoning effort and prompt-cache scope: task options from the person's request, applied by the gateway (the brain's `reasoning_effort` may lower the effort, never raise it) | At most 4 tool calls run per step, the rest refused; unknown tool and unparsable arguments refused; the model told why |
| PII masking, public-only fetching, leak scanning, tool caps, image re-encoding, site icons | Actions in parallel (4 at once), results in call order |
| Citation numbers, image slots, site icons, per task (rebuilt from the journal after a restart) | Checkpoint per step, steering, cancel |
| Every event people see: `step` per fresh model call, deltas, usage, metrics, `tool_call`, `image`, `tool_result` (under the action's `call`), `favicon`, `done` / `error` | `done` text is for the record (people saw it stream) |

A tool call the brain refuses has no action; people see its result from the tool message in the brain's next `model.call` (what the model reads; untrusted, display only). Replays never reach the guard, so a brain restart shows nothing twice.

**Checked** (`guard/e2e_test.go`): the event sequence and fields of `/run` for a search run, refused calls (the bad arguments back to the model as written), the last step without tools and a model error; three tools in parallel (image before its result, unique citations, site icons); a brain killed during a search (runs once, model billed once, each event once). `guard/decisions_test.go`: the effort clamp (through the runtime, journaled), `raw_args` (capped, marked, valid UTF-8), and a runtime restart mid-task (citations continue, image slot and steps kept, icons not refetched, the interrupted search not rerun). The brain passes `RunBrain` (`brain/brain_test.go`). `app/parity_test.go` runs recorded scenarios through `/run`, both with the guard in agentd's process and through gatewayd over `gateway/v0`: every event the chat sees must match the recording (timings aside).

Citation numbers are assigned in the order a step's calls finish, not call order: the runtime can't see the brain's steps. The model and people still see the same numbers.

## Open questions
1. **Socket into gVisor:** when the brain runs under gVisor, a host unix socket bind-mounted into the sandbox (needs runsc's host-UDS option) or a pre-connected fd passed at start? Either keeps "no network interface".
2. **Checkpoint every step boundary:** required here for deterministic replay. Fine for our loop; check it fits other harnesses before adopting one.
3. **Large state:** 4 MiB frames and 2 MiB checkpoints cap a conversation. Past that: blob references, incremental checkpoints, or the runtime holding the message history so `model.call` sends only new messages.
4. **Input refs:** files and documents a task is given. Proposal: references in `start`, read through an action (`files.read`), so content goes through the guard and the recorder. Not in v1.
5. **Schema source:** types are hand-written in Go. One schema generating Go and TypeScript (JSON Schema?) is wanted before third-party SDKs speak this.
6. **Brain-local tools** (a "think" or "plan" tool the model calls that the brain handles itself): not allowed now, since every tool comes from `start`.
7. **Approval waits:** the brain holds the request open. For long waits the brain is stopped and resumed. Should the result instead say "held" early so the brain can do other work?
8. **Values:** idle 60 s, cancel grace 10 s, 3 attempts, 8 in flight: starting values, to be tuned under load.
9. **Placeholders until spaces and signed agent definitions exist:** one space for the chat (`s_chat`), tool caps keyed by the relay's user tag, agent digest `unsigned`.

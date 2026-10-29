# Changelog

What changed in the agent VM, release by release, newest first. Every release is a signed tag `vX.Y.Z`; its [GitHub Release](https://github.com/tacyhq/tacy/releases) carries `compose.yaml`, `release.json` and the Sigstore bundle, and [README.md](README.md) says how to check them. Entries name the package they touch; the specs are in [docs/](docs/README.md).

## v0.19.1

Fetches say `Mozilla/5.0 (compatible; Tacy/1.0)`; mail citations' details are for the browser only.

## v0.19.0

Email by IMAP, read-only (Settings → Connections, mail tools, mail in schedules).

- **`app/`:** Settings → Connections (`app/connections.go`): `POST /connections/list` (the vault's per-boot seal key and the space's accounts, never a password), `/connections/put` (an email account sealed in the browser to the vault's key, passed on sealed; kept only if a test login through the read-only client works; fixed error codes such as `app_passwords_blocked`) and `/connections/remove`, each signed like a schedule call.
- **`cmd/vaultd/`, `vault/`:** vaultd also holds the people's connections (`vault/conn.go`): an email account the browser sealed (HPKE) to the vault's per-boot key, bound to its space, opened only here (agentd and gatewayd pass the box on sealed), kept after gatewayd's test login worked, in memory and in a file on vaultd's own volume of the encrypted disk (no other container mounts it); its app password is leased per call only to the mail connector, to that account's own server, under the space's policy.
- **`imapro/`:** A read-only IMAP client for the mail connector. It writes only CAPABILITY, STARTTLS, LOGIN, AUTHENTICATE PLAIN, EXAMINE, (UID) SEARCH, (UID) FETCH with BODY.PEEK and items that change nothing, LIST, NOOP and LOGOUT; every other command and FETCH item (SELECT, STORE, EXPUNGE, APPEND, COPY, MOVE, BODY[], RFC822, ...) is refused in code before a byte is written. TLS only (implicit or STARTTLS before anything else), certificates checked; a folder whose EXAMINE isn't READ-ONLY is hung up on. `imaptest/` is a stand-in server whose tests prove nothing is ever marked read.
- **`guard/`:** The mail connector (`mail.go`): `mail.search`, `mail.read` and `mail.folders` read the person's connected account through `imapro` (one IMAP session and one leased password per call, public addresses and IMAP ports only), each a permission prompt of its own whose value is what goes to the mail server (not editable); the acting model gets code-checked fields (ids it hands out, dates, bare addresses, flags) and the quarantined reader's fields for subjects and bodies, never the text; no quote of a list of headers or of an injected passage; a task that read mail is tainted; at most 10 searches and 20 reads a chat task, 6 and 12 a scheduled run; schedules may list the mail tools with Always allow.

## v0.18.0

Scheduled results handed to the relay, signed, so they show with the VM stopped.

- **`app/`:** `POST /schedules/handoff` (`handoff.go`, bearer token, plaintext): the relay takes a copy of each stored scheduled result (the same ciphertext, sealed to the space's seal key, which the relay can't open; with its space and random task id only), signed by the activity signing key, which `/schedules/list` now names over EHBP (`signer`), so the browser can show a result with the VM stopped and refuse one the relay made up; `collected` deletes the VM's copy as the person's own delete does.

## v0.17.2

Web answers use current sources and keep signs and attributions.

## v0.17.1

`GET /tasks/open` reports `next_run`, so the relay wakes the VM only for scheduled runs.

- **`app/`:** `GET /tasks/open` also says when the next scheduled run is due (`next_run`: one UTC time, floored to the minute, for all schedules together, or null; a run due while the VM was off keeps its own time until it fires), so the relay can let the VM stop between runs and start it a few minutes before the next one (a run the VM comes up for within 3 hours of its time still runs, once).

## v0.17.0

Agents read stored files by key; uncollected schedules stop themselves; expired schedules drop their file keys.

## v0.16.1

The chat agent makes the document card for file requests and drafted content; an empty reply is asked once more.

## v0.16.0

Charging by kind and fallback, schedules priced up front, task content deleted at the end, seal keys pinned, public logs fail verification.

## v0.15.0

Schedule upgrades, documents in agent runs, run notifications, PII masking, source dates, review in one read.

## v0.14.0

Overloaded models retried then the private fallback (budgets priced for it), numbered links on web turns, research file faithfulness, review recall, the person's time in the agents' date note.

- **`app/`:** A built-in agent's model call is reserved at the dearer of the asked model and the fallback it may switch to, gatewayd is told which models were priced (no other is used), and usage is counted at the price of the model that answered; a refused date note answers 400 `bad_date_note`.
- **`guard/`:** An overloaded model call (503, 429, "overloaded", before any token) is tried again on the same model after a jittered wait (at least the provider's Retry-After), then goes to the run's first allowed fallback; research, review and scheduled runs fall back too (a schedule within its signed models). A chat web turn's page reads come with the page's links, numbered (`links.go`): to open and cite on a page the person named, to cite only on any other (a fetch of a cite-only link is refused); the model never writes an address. A research task's file parts get their own reader prompt (facts as notes in the reader's own words, with each rule's exceptions, never what a part lacks), and a sentence saying a part lacks something loses its quote; a review's parts are 3,000 characters with up to 10 facts and 12 quotes. The brief-only agents' date note may end with the person's time and IANA zone.

## v0.13.1

`files.list` and `files.read` are reads in the approval table.

## v0.13.0

The review agent (`a_review`), research with files, Tavily fallback for web search, weekday and one-time schedules.

- **`app/`:** A task may name `a_review`: its one message carries the person's attached files (1 to 5, at most 1,000,000 characters and 4 MiB of text) as attachment blocks before the brief, so the request's signature covers them; the acting model gets the brief and a list of the files (names, sizes, parts), never their text; a review is kept up to 7 days. `a_research` takes up to 5 files the same way.
- **`guard/`:** `a_review` (`review.go`, `files.go`) reviews the person's attached files and has no outbound tool at all: gatewayd refuses every web action of the task before any other check (`no_egress`), the task's search provider and fetcher refuse every request, and agentd refuses them too; its tools are `files.list` and `files.read` only. Each file is cut into parts of about 4,000 characters at clause headings, each read with the file's headings above it; up to 12 parts are read at once, in parallel, each as its own quarantined reader call with a prompt for contracts and policies, and a file of 2 or more parts and at most 40,000 characters is read whole once more only for what spans its parts (shown only when every part was read). The model gets the reader's checked fields and `[quote N]` references (the person gets each quote's exact words with its file and part). The review ends with a "Sections not reviewed" list that the VM writes from its own record of the parts read, and where the reader found text addressed to AI tools. 12 steps, 10 minutes of work and 60 overall, a $0.50 run budget whose last $0.08 is kept for the review. The research agent `a_research` also takes up to 5 of the person's files with the same intake and caps: it reads them first through `files.read` (the reader's question-led prompt with the brief as its question; a part that starts inside a clause names the headings it's under; at most 60 parts, counted against its $1 run budget), cites the files' passages as `[file quote N]` and the web as `[n]`, and the VM lists the parts it didn't read. The files never leave the VM (`files_guard.go`): a search or page read whose arguments carry 6 or more of a file's words in a row is refused (`file_text`) before the person is asked and before anything is sent. A task with files is refused at its start under a policy without the `files` connector.
- **`guard/`:** A web search that Exa fails on its side (an HTTP error, no answer in time, no connection, a bad answer) goes to Tavily once (`searchfallback.go`), with the same masked query, the same caps and a key leased from the vault; never on a refusal by our own guards, Exa's own content filter or a cancelled search; after a few failures in a row Exa is skipped for a few minutes (`breaker_open`). Failed searches and fallbacks are counted in the run's metrics and the activity record (a fixed failure class).
- **`safety/`:** The release ceiling has a `files` connector (`files.list`, `files.read`, no hosts): a signed policy must list it too for a review or research with files to read them.

## v0.12.0

Schedules for personal spaces.

- **`app/`:** Schedules for personal spaces (`app/schedules.go`): `POST /schedules/install`, `/list`, `/stop`, `/remove`, `/results`, `/result`, `/results/delete`, each carrying the run's space proof and identity signature under its own label, the nonce used once; `GET /tasks/open` also counts active schedules (a count only).
- **`guard/`:** A run's user messages may carry the person's images (JPEG, at most 4, 512 KiB each, signed with the run): they stay in the task's options (the brain never gets them) and go only on the person's message in model requests to models that see images (`images_in.go`), never to the reader, a search or a page.
- **`queue/`:** A side file next to it (`side.db`, its own schema) holds signed agent definitions and their state, schedule slots fired and skipped, the identities that proved they hold a personal space, and scheduled runs' results sealed to the space's seal key (kept at most 7 days).
- **`trigger/`, `identity/`, `approval/`:** Signed agent definitions (`tacy.agent/v1`: instructions, models, tools, permissions, triggers, the space's seal key, `not_after`), the version floor, schedules (`daily` at a wall-clock time in an IANA zone, DST-aware, tzdata embedded; once per day, a run more than 3 h late skipped, the VM's clock checked against a high-water mark and the operator's signed time), and the identity directory a definition's signature is checked against. A scheduled run runs as its sponsor with exactly the definition's permissions (nothing asked), $0.25 and 20 steps, recorded in the space's activity chain. `approval/` (approve before send with a passkey) ships with no directory: nothing a personal space can install sends or changes anything.

## v0.11.0

Built-in agents and the research agent (`a_research`); card photo name and IBAN fixes.

- **`app/`:** A task start may name a built-in agent (`agent`: `a_research`; the chat when absent; an unknown id is refused), only through `POST /tasks` (a `POST /run` naming one is refused); its running time and run budget are the agent's own, narrowed by the signed policy, never widened; the release ceiling's run time is the longest agent's (15 minutes), the chat keeps its 5. `POST /tasks/delete` (MAC with the run secret) deletes a task and everything kept for it, cancelling it first if it runs; a research result is kept until deleted, at most 7 days (a chat task's a day).
- **`guard/`:** Built-in agent definitions (`agents.go`) are compiled into the release, so the attested image fixes each agent's instructions, tools and limits (`start.agent` names the definition's SHA-256): `a_research` takes one message (the brief, after an optional date note), uses only web search and page reads through the quarantined reader (no image search, site icons, card pictures or photo lookups), and has at most 30 steps, 20 searches and 40 page reads (gatewayd counts them before anything is sent and refuses the rest with `agent_cap`), 15 minutes of work and 60 overall, and a run budget of $1 and 60 tool calls whose last $0.15 is kept for its answer. A search is counted at $0.01 against cost budgets (was $0.05).
- **`runauth/`:** A request naming a built-in agent adds `agent=<id>` as the digest's last item (a request without one hashes as before), so the agent can't be changed after signing and an older VM refuses such a request.

## v0.10.1

Card photo lookups start when the answer names the item; the fast image search first.

- **`guard/`:** A card's lookup starts as soon as the answer or its reasoning names one of the run's checked reader items (the words only choose the item; what goes out is still the VM's copy of its name, only with pictures on, at most 4 such early lookups and 8 items a run), and the card takes that lookup's picture; the lookup tries the image provider's fast search first (Tavily without generated descriptions, about 2 s; its pictures are captioned by their page's title and go through the same checks) and the search with descriptions only when that gave no picture; the best two candidates download at once; a small number with its unit joined to it in a caption ("20V" for "20-Volt") counts for that number.

## v0.10.0

Spaces and identities in every request; card photo lookups get 25 s for the image search.

- **`runauth/`:** Every request to agentd (`POST /run`, `POST /tasks`, `POST /search`, `POST /pictures`) names its space and the space's seal public key, proves it holds the seal private key (an HMAC keyed by an X25519 agreement with this boot's attested key) and is signed by an identity over a digest of the whole request, this boot's key, a fresh nonce and the time, under a label per kind of request. agentd checks it once at the door (a nonce runs once per boot, `signed_at` within 5 minutes) and seals the activity records to the space's seal key; budgets count per space, per member and per VM. Test vectors in `runauth/testdata/`, replayed by the browser too.

## v0.9.0

The firm key log replaces pinned admin keys.

- **`safety/`:** The compose pins the firm key log's genesis instead of admin keys (`-keylog-genesis`, with `-keylog-carry` for the two policies the old admin key signed): policies and the firm's stop lists are checked against the key admins of the log the VM verifies from that genesis; gatewayd pulls the log with the other documents (`-keylog-url`), `POST /keylog` takes entries, and every run's `meta` and `GET /safety` report the log head the VM holds (`keys`), so the browser can compare it with the log it was shown. Until it holds the genesis a v0.9.0 VM takes no policy (`policy_missing`).
- **`keylog/`, `keysv2/`:** The firm key log (`keylog/`): signed, hash-chained entries (genesis, identities added and revoked, key admins, the threshold, root rotation) verified from a pinned genesis, with fork detection; `keysv2/` replays the browser's test vectors so both verifiers agree.

## v0.8.22

Card lookups still loading at a run's end go into its photo ticket; a ticket works across midnight UTC.

## v0.8.21

Card photos held back until pictures are on, then loaded into that answer; composed page addresses refused.

- **`guard/`:** A run whose pictures setting isn't Always allow holds its photo-less cards' lookups back (the reader items they named, in gatewayd's memory only, nothing sent) and ends with a one-use ticket (a `pictures` event, 30 minutes, the run's user tag and space); once the person turns pictures on, `POST /pictures` with that ticket alone looks those items up as the run would have (the VM's own copies of the names, the same checks) and shows each picture under the call that brought its item. Also since v0.8.21, a page address the model composed after reading web content is refused without asking (`not_from_results`), under Always allow and Ask alike.

## v0.8.20

PII masking no longer takes prices and years for phone numbers.

- **`guard/`:** PII masking no longer takes a price or a year for a phone number ("under $1000 2026" went out as "under $[phone]"): a phone match is left alone when it follows a currency sign or the same number's thousands, or is exactly two numbers where the second is a year (19xx, 20xx) and the first isn't a 3-digit exchange-shaped group, or both are round hundreds (a range); a country code glued to a word ("rav4 2025 2026") doesn't count as one. Real numbers, with a country code, an area code or three groups, and local ones like "555-0134", are still masked.

## v0.8.19

Card lookups lease the image provider's key for their task's space.

- **`guard/`:** A lookup's image search runs under its task and space, as an action does, so the vault leases the image provider's key for it (in v0.8.18 every lookup's lease was refused).

## v0.8.18

The VM looks up an answer's card pictures by the reader's item names, never the card's text.

- **`guard/`:** The VM (`pictures.go`) looks up the picture of an answer's card that its sources gave none, instead of relying on the model to call image search: only for a card whose title names one of the run's checked reader items, and what goes out is the VM's own copy of that item's name, never the card's title (so nothing from the conversation can ride out in an image query); one image search a card, at most 6 an answer, in the background; only when the run's setting for pictures (`web.images`) is Always allow, never prompting; candidates whose caption or own address don't name the item, name another model number, or show a logo, a roundup's banner, a collage or people are refused before any download, plain product shots first. A roundup's own picture no longer goes on a product card unless its alt text or address names the item.

## v0.8.17

The reader's strict cuts switch on when code finds an injection, not only when the reader counts one.

- **`guard/`:** The reader's strict cuts switch on when code finds instruction-like sentences in a source, not only when the reader counts one: 20-character copies of those sentences and their neighbours, sentences naming an injection, and sentences carrying the source's link words or its injected region's identifiers are cut, and item names are screened; "Tell/Show/Ask HN:" is a title's prefix, not an instruction.

## v0.8.16

A faster quarantined reader: deepseek-v4-1-flash with a gpt-oss-120b fallback, a search read one result per call; a stricter verbatim cut.

- **`guard/`:** The reader runs deepseek-v4-1-flash with thinking off, and a call it fails (an error, no answer within 12 s for a page or 25 s for a search result, the policy, an answer off the schema; never one that asked for a tool) goes to gpt-oss-120b at low effort within the read's bound (30 s a page, 75 s a search); a search's results are read one result per call, all at once, and merged in result order: each call is the same quarantine (one result, no history, no tools, every check), one that fails drops its result only (the model gets it as `unread`), and numbers don't depend on which call ends first; each call is a reader metric naming its model, and the budget reserves every result's call on both models; the verbatim cut also looks for the search's other results, the task's earlier sources and each source's skeleton (short parenthesized enumerators, figures, footnote marks and emphasis left out); a plain-chat search fetches each result's picture as soon as that result is read (shown after the result, as before).

## v0.8.15

Plain-chat result pictures only from one item's own page, named closely (see v0.8.13).

## v0.8.14

A search's read gets 75 s (see v0.8.13).

## v0.8.13

The reader keeps the specifics: a checked items list, per-entry drops, 4,000-character results; plain-chat search pictures.

- **`guard/`:** The reader also lists the items each source names (product, model or version, its price, a few words of its own, the source's number); code checks each name and price word for word against that source and refuses names that read like instructions or carry links, and the model gets them as `name · price · attribute [n]` (checked names and prices are the one exception to the 40-character cut); a failing quote, list entry or item is dropped on its own instead of refusing the whole answer; results carry up to 4,000 characters (a search's read gets 45 s; 75 s since v0.8.14, for the model provider's slow spells); and a plain-chat search sends each result's own picture (`cardpics.go`, the same checks as answer cards' pictures) when it names an item the reader found in that result (since v0.8.15 only for a result that is one item's own page, not a list or roundup, naming the item closely: the card isn't known yet).

## v0.8.12

Search answers with the specifics.

- **`guard/`:** Each search result carries up to 2,000 characters of the provider's text for the reader (Exa highlights of 2,000, was 400; Brave and Tavily snippets up to the same cap, was 600; the person's citations keep 600), and the reader's budget is sized for it; the reader names the specific items it finds (products, models, versions, prices, dates) with their result labels; a search's results get 30 s to be read (a page keeps 12 s), and a search whose results couldn't be read in time tells the model so; a plain-chat search's result doesn't offer to fetch, which that chat can't.

## v0.8.11

The release ceiling lists `api.exa.ai`: v0.8.10 refused every Exa search. v0.8.10 was never deployed.

## v0.8.10

Web search through Exa by default, and `POST /search`: the plain chat's one approved web search.

- **`app/`:** `POST /search` (`search.go`, EHBP, bearer token): the plain chat's one web search, approved by the person in their tab; strict JSON (no messages, model or tools), run as a task of its own kind with no model and exactly one `web.search` for exactly the approved query, through the same policy, budgets, grant check, PII masking, leak scan and quarantined reader as an agent's search, recorded on the activity record, nothing kept in the queue.
- **`guard/`:** Web search defaults to Exa (`exa.go`, when `EXA_API_KEY` is set; `SEARCH_PROVIDER=exa|brave|tavily` forces one): the request carries only the masked query, the result count, `type: "fast"`, `moderation: true` and a highlights length (no location or user id); each result's `image` is a card picture candidate; Exa's error text, which quotes the query, never reaches anyone; image search stays on Brave or Tavily (Exa has none). `searchtask.go` limits a plain-chat search task to its one approved search.

## v0.8.9

Card pictures: another source naming the item, an items block left open, `"picture": true` only for one item's own page.

- **`guard/`:** An answer's item cards (`cardpics.go`; v0.8.7 and v0.8.8 had earlier versions and were never deployed) get their own source's picture first (a page's `og:image`, `twitter:image` or JSON-LD Product image, or the search result's picture), downloaded and re-encoded like an image search's only once the answer names the card, never a logo or a picture that doesn't name the card's item; the model is told which sources have one (`"picture": true`) and searches only for the rest.

## v0.8.8

Card pictures: the caption check no longer refuses product photos with "icon" inside a word. Never deployed.

## v0.8.7

Card pictures from the sources before image search; image search for photos of real things. Never deployed.

## v0.8.6

Image search: the next picture by caption match, failure reasons, pictures numbered apart from sources.

- **`guard/`:** An image search asks for at least 6 candidates and tries them best caption match first (logos and icons last), so a picture that fails is replaced by the next best; each failure's reason (`blocked`, `timeout`, `format`, `size`, `unreachable`, `never_arrived`; fixed words and counts, never an address) is in the images metric and on the activity record; and the model gets pictures numbered `picture`, apart from the sources' `[n]`.

## v0.8.5

The chat on tasks, model fallback.

- **`app/`:** A task start and a cancel carry a plaintext billing witness for the relay (`X-Agent-Task: new|existing`, an opaque `X-Agent-Bill` id, and `X-Agent-Refundable: 1` on a task's first cancel before any model output; the bodies stay encrypted), and `GET /tasks/open` (bearer token, a count only) lets the relay's idle timer keep the VM on while a task runs with no tab following it.
- **`guard/`:** Model fallback (`fallback.go`, [docs/27](docs/27-tasks-and-reader.md) section 1): a model call with no first token within the slow threshold, or answered 503, 429 or "overloaded", is slow (`model_slow`); on Auto the step runs again, once, on the first fallback model the signed policy allows (`model_switched`), and a hand-picked model is waited for, or ends the run with `model_overloaded`.

## v0.8.4

A faster, hardened quarantined reader.

- **`guard/`:** The reader gives quotes by reference (span numbers; code copies the exact words), a read that takes over 12 s is skipped (fail closed), a page read again in the same task reuses its checked answer (`readcache.go`), and the reader's sentences about an injection it counted, bare IPv4 addresses and private or reserved names (`.internal`, `.local`, `.example`, …) are cut from its fields.

## v0.8.3

Faster attestation, image search off the answer path.

- **`app/`:** `GET /attest` reuses the dstack guest agent's `/Info` for the boot (fetched at boot, kept only while the quote's RTMR3 matches the one in it, fetched again otherwise); the quote itself is fresh for every request.
- **`guard/`:** An image search returns once its images are ready instead of waiting for the slowest earlier candidate; images that arrive later still reach the person's gallery, and a run's end waits at most 0.5 s for site icons.

## v0.8.2

Security fixes, gVisor 20261012.0 and dependency bumps.

- **`app/`:** `/tasks/status`, `/tasks/events` and `/tasks/cancel` need a MAC with the run secret; 8 event streams per user.
- **`guard/`:** Sources (`sources.go`): the acting model gets sources as `[n]` and their site, never full addresses; on a tainted task a page address the model wrote itself is asked about even under Always allow; values with hidden characters are refused.
- **`safety/`:** With the operator key pinned, a stale stop list, or none delivered for 3 minutes, stops everything, reads and model calls included.

## v0.8.1

Waiting on a permission prompt isn't running time.

- **`guard/`:** Time waiting on a prompt doesn't count toward the run's 5-minute running-time limit (overall cap 30 minutes).

## v0.8.0

Permission prompts: a web search, a page fetch or an image search waits for the person's answer before anything leaves the VM.

- **`app/`:** `/tasks/grant` (the person's answer to a permission prompt).
- **`guard/`:** Permission prompts (`permission.go`, `prompts.go`, [docs/27](docs/27-tasks-and-reader.md) section 6): a web search, a page fetch or an image search waits for the person's Allow once, Always allow or Deny, and gatewayd checks their grant itself before anything goes out.

## v0.7.0

Tasks and the quarantined reader: tasks that outlive a tab, untrusted web text read by a model that can't act, per-task taint.

- **`app/`:** `POST /tasks`, `/tasks/status`, `/tasks/events`, `/tasks/cancel` ([docs/27](docs/27-tasks-and-reader.md); end-to-end encrypted, EHBP).
- **`guard/`:** The quarantined reader (`reader.go`, [docs/27](docs/27-tasks-and-reader.md)): pages and search results reach the acting model only as checked fields and `[quote N]` references.

## v0.6.0

Safety controls, stage 2: the admin and operator keys and the heartbeat URL pinned in the compose.

- **`safety/`:** The compose pins an admin key and the operator key: runs need a policy signed by the admin key, and gatewayd pulls the operator's heartbeat and the policy every 10 s.

## v0.5.0

Activity records: a signed start and end record per agent run, chained per recipient and sealed to the person's key ([docs/24](docs/24-activity-records.md)); gVisor's LICENSE in runnerd's image; CI runs the brain in real gVisor.

## v0.4.0

The brain in gVisor: runnerd starts it in a rootless runsc sandbox ([docs/22](docs/22-sandbox-runner.md)).

- **`brain/`, `cmd/brain/`:** The brain runs in a gVisor sandbox. Before v0.4.0 `brain` had its own image and service in the compose.
- **`release.json`:** Adds `gvisor` (release, URL, tarball and binary hashes).

## v0.3.1

Safety controls without admin keys pinned: old policy floors don't block runs (a keyless release after a keyed one runs on the release policy).

## v0.3.0

Safety controls, stage 1 ([docs/23](docs/23-safety-controls.md)): signed policy and stop lists (no keys pinned yet), kill switch, budgets, vault rate limits.

## v0.2.0

OCI images: one image per binary, by digest (`tacy-release/v2`). The oldest release the verifier accepts (`release.MinVersion`).

## v0.1.0

The first release from this repository (`tacy-release/v1`): no images; the VM built the binaries from source embedded in the compose.

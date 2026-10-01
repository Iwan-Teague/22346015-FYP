# 01 — rustyharness design v0.1

**Status:** v0.2, 2026-09-23 — reviewed **SOUND** (first review NEEDS-FIXES; rework; confirming review SOUND with two LOW clarifications, applied). H1 built (slices H1a-H1f), its phase-exit review next: clarifications made while building are listed in "Changes since v0.2"; none changes the architecture. Owner decisions made after the review, some of which add scope, are listed in "Owner decisions after v0.2".

Supersedes nothing yet. It answers the questions the overview framed
([00-overview.md](00-overview.md)) and most of [OPEN-QUESTIONS.md](OPEN-QUESTIONS.md). Where a
question belongs to the owner, this document states it once (§11) with a fail-closed default
that holds until the owner answers.

**Inputs.** R1 prior art, R2 suite inventory and R3 fleet lessons (all in `docs/research/`); R4
(the review of the earlier agent-harness draft), R5 (the integration map) and R6 (the threat
model). R4-R6 live in the rustysuite repository, because they are suite-specific
(`docs/research/README.md`). This document keeps only the general mechanisms from them. The
scaffold review's design notes F4, F5, F10, F11 and F13 are carried forward as requirements
(OPEN-QUESTIONS item 17).

**Conventions.**
- Research is cited by document and section: "R1 §2", "R3 H-07", "R6 TH-7".
- Code is cited as `file:line` in this repository, at commit `3891636` on `main`: the last commit that touched `crates/` or `Cargo.toml`. The citations are to that commit: code has changed since (H1 onward), so read them at `3891636`, not at the tip.
- "UNVERIFIED" marks a claim this document has not checked against a primary source or a build.
- Any sketch in `rust` fences is a signature-level design, not code.
- The one outcome type is always written `GateOutcome { Passed(Witness), Failed, Indeterminate { why } }`. That is the suite's UNIFIED gate-outcome design (v0.3 content). Its SOUND verdict is recorded by its own confirming review, named in the UNIFIED document's status header; R2 §4 only summarises the type and is not the source of that verdict. **This design defines no other verdict or outcome type (§1.4).**

**Hard constraints (owner decisions, not reopened):** standalone first (ADR-0002); public,
source-available (ADR-0003); fail-closed (no sandbox, no execution); tool and model output is
untrusted; irreversible effects need a human yes every time; "done" comes from evidence; the agent
never modifies its own trust base; no lethal trifecta; one outcome type; Rust only, no new C;
portable to macOS, Linux and Windows; local models first.

## Changes since v0.1

v0.2 answers the first independent review (REVIEW-rustyharness-design-v01, verdict NEEDS-FIXES). No architecture changed. Every fix is a mechanism with a stated failure path, and every failure path ends in a refusal or `Indeterminate`.

| Finding | Severity | What changed | Where |
|---|---|---|---|
| F-01 | HIGH | Write-ahead enforced by type (`Journaled<Authorized<Call>>`, minted only after a durable intent append). Any append or fsync failure poisons the writer, stops the run with `JournalUnavailable` and gives `Indeterminate { UnreadableEvidence }`. The outcome is released only after `RunStopped` is durable. Falsifying test INV-33. | §2.2 steps 7-10, §2.5, §4.5, §7.1 "Write failure", §7.7, INV-33 |
| F-02 | HIGH | `verdict()` runs only over a complete, pre-fixed check plan (`finalize`). A missing report gives `Indeterminate { CouldNotRun }`, never a verdict over the subset. A separate verification budget. Resume re-runs the whole plan. Falsifying test INV-34. | §2.4, §2.5, §2.10, §7.2, §7.3 "Completeness", INV-34 |
| F-03 | LOW | `Digest` is opaque caller-supplied bytes; `gate-outcome` stays zero-dependency. The crates that compute digests are named, and the trust assumption is stated. | §1.2 purity allowlist, §1.4 "Where digests come from" |
| F-04 | LOW | `RESERVED_NAMESPACES = ["harness", "rustyvault"]` is a core constant. Config may only add names. | §4.1, §4.3 "Reserved namespaces", INV-1 |
| F-05 | LOW | Filesystem-locality check as an allowlist, with a mechanism per OS, spike S-F1 and refusal as the default; the residual is named. | §2.8, §11 residuals, INV-35 |
| F-06 | LOW | Reviewer identity is re-checked before every attempt, fallbacks included. A valid `Failed` review is final. | §7.5, INV-19 |
| F-07 | LOW | No `Conformed` ⇒ no mcp-stdio process, and no in-process adapter with an execute-class capability. The session is refused, with no unconfined fallback. | §4.1, §4.5, §5.2, §7.7, INV-6 |
| F-08 | LOW | The loopback model server is named as an egress residual outside the trifecta computation. | §5.4, §11 residuals |
| F-09 | INFO | Code is cited at `3891636` on `main`. The SOUND claim now points at UNIFIED's own confirming review, not R2 §4. | Conventions |
| F-10 | INFO | OQ1 is restated as an owner question, with the tension against ADR-0003 explained. The default is unchanged. | §11 OQ1 |
| R3 H-14 (Partial) | coverage | Standing conditions are journaled once per state change; alerting is declared out of scope. | §2.6, §11, Appendix A |
| R3 H-17 (Partial) | coverage | An environment sample (load, memory, disk, each with its method) in the header, at verification start and on every timeout, crash or `CouldNotRun`. | §7.1, Appendix A |
| Review Q7 note | coverage | A read-only Windows session with a verification plan is never `Passed`; this is stated to users. | §11 OQ4 |
| (editorial) | — | Crate-map cycle removed: `harness-sandbox-windows` now holds Win32 primitives only and depends on `harness-core`, not `harness-sandbox`. The dependency list is redrawn as explicit edges. | §1.2 |

## Changes since v0.2

Clarifications made while building H1. None changes the architecture, a decision in §0 or an invariant; each narrows an open detail in the fail-closed direction.

| Slice | What changed | Where |
|---|---|---|
| H1a | §7.3 gained five clarifications of the child-protocol table (run-level facts first, gate id, wire form, exit agreement, marker content). `gate-outcome` implements them; the H1a confirming review checked each against the code. | §7.3 |
| H1b | The §1.4 sketch now shows what `ChildRun` carries (the marker's content, not a "marker seen" flag, and `speaks_protocol`) and that `GateId` is content-checked. | §1.4 |
| H1b | Marker line endings decided: LF only; a CRLF marker is `UnreadableEvidence`. `GateId` refuses empty ids and ids with whitespace or control characters (an empty id let `ok ` pass). | §7.3 "Line endings", §1.4 |
| H1b | Manifest v1 wire shapes fixed: `transport` is `{"kind": "builtin"}`, `{"kind": "mcp-stdio", "argv": […], "env_allow": […]}` or `{"kind": "in-process", "feature": "…"}`. Per-transport fields are present exactly when meaningful: `mcp_name` and a non-empty `mcp_protocols` only for mcp-stdio; `schema_sha256`/`description_sha256` required for every non-builtin transport and refused on built-ins. `min_harness` is a strict `MAJOR.MINOR.PATCH`. `summary` is an allowlist (printable ASCII plus letters). Only the compiled-in manifest may use `builtin`. No field is nullable: an explicit `null` anywhere is refused, never read as absent. An mcp-stdio `argv[0]` must be absolute, not UNC (two leading separators in any mix) and without a `..` component. | §4.1, §4.3 |
| H1b | The §3.3 schema subset is enforced per type (a keyword is legal only on the type it constrains, so none is silently ignored), with nesting depth ≤ 4 and property names `[a-z][a-z0-9_]{0,63}`; `integer` bounds are compared exactly (as integers, not through floating point). | §3.3, §4.3 |
| H1b | Admission in H1 admits only the `builtin` tier: `signed`, `pinned`, mcp-stdio, in-process and secret handles are refused with a typed "not in this build" error until the slice that can honour them (H2/H4). Shadowing and the `pinned` tier limits are checked before that gate. | §4.4 |
| H1b | The built-in fs tools are labelled `content: third_party` (workspace text is other people's by default, §5.4). No default decision changes. Their `path` argument must be a normalised relative path with no `..`, `.`, empty component, `\`, `:`, control character, or component ending in `.` or space (the lexical half of INV-30). | §4.8 |
| H1b | Policy for read classes: every decision carries a rule id; user policy is three selector lists (`<capability id>` or `<provider>.*`), and a selector repeated anywhere is refused as ambiguous. An `Ask` cannot mint `Authorized<Call>` until approval tokens exist (H2). | §5.1, §5.2 |
| H1b | `harness-manifest` and `harness-policy` do not depend on `harness-core` yet: nothing in it is needed so far. The §1.2 edge stays allowed; using it later is a dependency-allowlist change in `scripts/ci/purity.sh`. No architecture change. | §1.2 |
| H1b | The workspace path rule also refuses Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM0`-`COM9`, `LPT0`-`LPT9`, `COM¹`-`COM³`, `LPT¹`-`LPT³`, `CONIN$`, `CONOUT$`) as the stem of any component, case-insensitively, with any extension, on every OS: Win32 opens them as devices, so `CONIN$` would read console input. The pure crates may not import `std::path` (its methods do I/O without naming `std::fs`); the purity gate refuses it and the `Path` I/O methods. | §4.8, §1.2 |
| H1b | Filesystem locality is split: the pure allowlist decision lives in `harness-policy` (`locality::classify`), the measuring probe in `harness-sandbox` (after S-F1). Until a probe exists for an OS, the check refuses every `state_root` there. The probe takes the path as an opaque string, so the pure crate holds no `std::path`. | §2.8, §1.2 |
| H1c | `harness_core::sha256` / `sha256_parts` exist, on `sha2` 0.11 with default features off (the "one SHA-256 implementation" of §1.2). The harness-core dependency allowlist gains `sha2` and its pure-Rust tree (`digest`, `block-buffer`, `hybrid-array`, `typenum`, `crypto-common`, `cfg-if`, `cpufeatures`, `libc` for FFI declarations only; no `cc`). | §1.2, §1.4 |
| H1c | Journal line encoding fixed: the compact JSON of an object with sorted keys; `hash = sha256(prev ‖ canonical line without "hash")`; the first `prev` is 32 zero bytes. The reader accepts a line only if it is byte-for-byte that canonical encoding, so duplicate keys, reordered keys or extra whitespace are refused, not normalised. `kind` is the closed §7.2 set. | §7.1, §7.2 |
| H1c | Single writer without an advisory lock for now: `std::fs::File::lock` needs Rust 1.89 and the workspace builds on 1.88. Exclusivity comes from `create_new` on a fresh attempt directory, and no API reopens an existing journal for writing (resume opens `attempt-<n+1>`). `File::try_lock` can be added once the MSRV allows. | §7.1, §2.10 |
| H1c | Record bodies are typed: trusted fields are numbers, booleans, digests, validated identifiers and compile-time harness text; runtime text from outside reaches a record only as an `UntrustedBlob`, whose inline form uses a reversible escape (`\\` and `\u{HEX}` for control, zero-width and bidi characters), so the reader can recompute its SHA-256. Besides the §7.1 list, the header (`RunStarted`) and `Egress` are fsynced. `RunStarted`, the intent (`ToolStarted`) and `RunStopped` have dedicated writer calls; `commit` consumes the writer. A budget dimension crossing 80% is journaled as `BudgetCharged` with `condition: enter/exit`. | §7.1, §2.6 |
| H1c | `ToolProvider::invoke` takes `Journaled<Authorized<Call>>` and is synchronous for now; whether it becomes `async fn` (and with which `Send` bounds) is decided with the loop in H1e. | §4.5 |
| H1c | Manifest checks run in the order version → reserved provider name → no `null` anywhere → typed parse, so a v0 manifest keeps its migration message and a reserved provider its own error. The UNC-shape check also treats the NT `\??\` prefix as verbatim (a disk only when a drive letter follows). | §4.3, §2.8 |
| H1c | Directory entries are durable before the header: after creating `attempt-<n>` the run directory is fsynced, and after creating `journal.jsonl` and `blobs/` the attempt directory is fsynced; a failed directory fsync is a start refusal (`Indeterminate { CouldNotRun }`). Creating `runs/<run-id>` under `state_root` (and syncing `state_root`) is the run driver's (H1e). **Windows:** std cannot open a directory handle to flush, so directory fsync is a no-op there and the harness relies on NTFS journalling its metadata; UNVERIFIED until Windows CI and spike S-W1 exercise it. | §7.1, §2.8 |
| H1c | The `JournalFile` and `BlobSink` seams are sealed (only this crate implements them). The fault-injecting implementations exist only behind the `fault-injection` feature, which only dev-dependencies enable; the purity gate refuses it on any normal dependency edge. `blobs/` is created with `create_dir` (never reused) and neither the attempt directory nor `blobs/` may be a symlink, for the writer and the reader. | §7.1, §6.4 |
| H1c | The reader binds a journal to its directory: `attempt-<n>` must match the attempt every record carries, and `open_expecting` also checks the run id, so a journal copied into another attempt is refused. Wholesale replacement within the same directory still needs the external anchor. | §7.1 |
| H1c | `Ident` (trusted identifier text) is narrowed to `[A-Za-z0-9._-]{1,128}`: no `/`, `:` or `@`, so no path or URL. Provenance rule: an `Ident` holds only values the harness minted or validated against a closed grammar it owns; model-, tool-, file- or task-chosen text goes into an `UntrustedBlob` even when it fits. **Closed in H1e-1:** there is no public constructor from runtime text; an `Ident` comes from `Ident::of(&'static str)` or `Ident::from_trusted(&impl TrustedName)`, and the purity gate confines `TrustedName` implementations to the files owning `RunId`, `CapId`/`ProviderName` and the render nonce. The grammar also refuses a leading `.` or `-`. | §7.1 |
| H1c | `append_intent` computes the intent's call digest from the call itself. **Closed in H1e-1:** the trait `harness_core::CallDigest` lives in the pure `harness-core`; `harness-policy` implements it for `Authorized<Call>` over the canonical `{"args","capability"}` JSON (the `harness-policy → harness-core` edge of §1.2 is now used); `append_intent<C: CallDigest>` takes no digest argument. | §2.2, §2.9, §1.2 |
| H1d | The loopback client is a small blocking HTTP/1.1 client over `std::net` (one exchange per connection), not tokio: loopback plain HTTP needs no TLS and no runtime, so it adds no dependency. Bounds: connect timeout, per-read idle timeout, a total deadline checked before every connect/write/read, and caps on the response head and body. `ModelBackend` is synchronous like `ToolProvider`; the async decision is H1e's. Requests ask for SSE (`stream: true`); the bounded reply is read whole and parsed as SSE, or as plain JSON if the server ignores `stream`. Unix-socket endpoints are not implemented. | §3.1, §3.2 |
| H1d | Endpoint rules made exact: only `http://127.0.0.1`, `http://[::1]` and `http://localhost` (mapped to 127.0.0.1 without DNS); `https` is refused because this build has no `hosted` feature; user info, queries, fragments and dot segments are refused. The purity gate refuses TLS and HTTP-client crates (rustls, ring, aws-lc, openssl, native-tls, hyper, reqwest, ureq, curl) on any normal edge (INV-24). | §3.2, INV-24 |
| H1d | Reply rules: `finish_reason: length` or none is `Truncated`; no content and no tool call is `Empty`; any other reason, malformed or duplicate-key JSON, an unexpected content type, a bad HTTP frame or an oversized reply is `Unusable`; timeouts and connection failures are `Unavailable`. Only 429 and 5xx are retried (default 3, exponential backoff with equal jitter, never past the deadline); each retried status is recorded on the result. The startup check is `GET /models` listing the profile's model; the native tool-use smoke test and the llama.cpp props check are H1e / spike S-P1. | §3.2, INV-3 |
| H1d | `Message` is the F4 enum. Untrusted text has zero-width and bidi characters stripped at the one rendering choke point; observations are wrapped in per-turn nonce delimiters, and a body containing the turn's closing delimiter is refused. Native tool names are the ids with `.` → `_` (OpenAI function names forbid dots), mapped back only through the active tool table. The strict (duplicate-key-refusing) JSON reader moved to `harness_core::strict_json`, shared by manifests, profiles, replies and actions; `harness-manifest` now uses its `harness-core` edge. | §1.3, §2.3, §3.3 |
| H1d | Profiles are strict JSON documents (`profile_version: 1`). `grammar` other than `none` is refused until spike S-P1; `price` is refused because this build has no hosted endpoints (N-7, "a hosted run without a price table refuses to start", arrives with the `hosted` feature). `profile check` scoring: ≥ 5 cases, no failed call, ≥ 80% exact tool calls, ≤ 20% format errors; the stamp is the SHA-256 of the canonical report. Edit-format compliance is reported as unchecked until the edit tools exist (H2). The CLI verb is H1e. | §3.4 |
| H1d | Replay (model half): `ModelRequested` carries the SHA-256 of the rendered request and the turn's nonce; `ModelReplied` carries the completion (payloads as `UntrustedBlob`s) or the typed error. `ReplayBackend` re-feeds them and reports the first exchange whose request differs, or a call past the recording, as a divergence. The audit driver that recomputes every context digest and policy decision of a run is H1e. `harness-model` depends on `harness-journal` for this. | §2.9, INV-20 |
| H1e-1 | **H1d review, closed.** F-1: the socket-level HTTP client is crate-private; `OpenAiCompatible::new` (loopback check) is the only way to a server. F-2: an observation's call label must be a capability id, and a body containing the turn's nonce in any case or width (full-width, mathematical digits) is refused. F-3: the purity gate refuses a pure model file naming a non-pure sibling module (`crate::`/`super::`, `use` groups, `extern crate self`), and every model module must be classified. F-4: harness-model's normal dependency tree is allowlisted (the TLS denylist stays as a clearer second message). F-5: the profile stamp is `sha256(content digest : report digest)` over every field but the stamp, recomputed by `validated()`; an edited or copied stamp is unvalidated, and the stamp digest is recorded with the flag. F-6: replay re-hashes every payload against its record. F-7: a final retry failure keeps every attempt's status; `Content-Length` is digits only; the endpoint path may not contain `%`; a port has no leading zero. | §3.2, §3.4, §2.3, §2.9, §1.2 |
| H1e-1 | **H1c confirming review, closed.** NF-1: `harness-journal` has a `compile_error!` for `fault-injection` in any optimised build (the gate checks it fires), and the gate refuses any workspace `[features]` table that forwards to it. NF-3: a run id is `harness_core::RunId` (32 lowercase hex: 48-bit time then 80 random bits, §2.8), never an `Ident`; `runs/<run-id>` is created with `layout::create_run_dir` (`create_dir`, no symlinked `runs/`, `runs/` fsynced). **Named residual (NF-2):** a writer inside `state_root` can race the attempt-directory checks between check and create; `state_root` is trust base (§6.4) and the external anchor is the defence (§7.1); opening the directory once with `O_NOFOLLOW` needs a directory-handle API (§6.7). | §2.8, §7.1, §11 |
| H1e-1 | **H1a confirming review, closed.** N-1: the identical-action burst rule is per run (§2.6 row above). N-3: the purity scan also reads a comment-stripped copy of every pure file and refuses `#[path]`, `include!`/`include_str!`/`include_bytes!`/`env!`/`option_env!`, `macro_rules!` and `static` items in pure code. N-6: every `compile_fail` doctest names its error code, and the gates run the doctests with `RUSTC_BOOTSTRAP=1` so stable rustdoc enforces the codes (no unstable feature is used). F-10.9: the `Meter` reads wall time from a `MonoClock` it is given at construction (`tick_wall()` takes no delta; `pause_wall`/`resume_wall` exclude approval waits; a clock going backwards charges nothing). | §2.4, §2.6, §1.2 |
| H1e-2 | **H1e-1 review, closed.** NF-A: the pure half of the model layer is its own crate, `harness-model-core` (the crate map's 14th crate), so no I/O module is ever a sibling of pure code; `harness-model` re-exports it and may hold only its I/O modules (`http`, `client`, `replay`, `scripted`, `smoke`). NF-B: the purity gate's comment stripper understands string, raw-string, byte-string and char literals, so `"/*"`…`"*/"` or `"//"` cannot hide code. NF-C: `TrustedName` is sealed in `harness-core` and implemented only for `RunId` and the render nonce `Nonce` (moved to `harness-core`); a capability id reaches a trusted field only as `Ident::from_capability(&Capability)`; the gate fences the token and refuses `Box::leak`/`.leak()` everywhere. NF-D: dependency allowlists read `cargo tree --target all -e normal,build`, so a target-specific or build dependency is seen. NF-E: the profile stamp is documented as a staleness check, not authentication (it is an unkeyed hash; the stamp function is crate-private). NF-F: the `RUSTC_BOOTSTRAP` doctest step has its own target directory. | §1.2, §3.4 |
| H1e-2 | One `Meter`, built only in the run driver (`harness-run/src/driver.rs`, the purity gate refuses `Meter::new` elsewhere outside the meter's own tests) with the real monotonic clock. An approval wait is a guard (`Meter::pause_wall` returns a `WallPause`; dropping it resumes the clock). `create_run_dir` fsyncs `state_root` on every call, not only when it created `runs/`. | §2.4, §2.8 |
| H1e-2 | **The submit sentinel.** `harness.task.submit` (write / public / own / none, content own, argument `note` of at most 2000 characters, i.e. Unicode code points as JSON Schema `maxLength` counts them, so up to about 8 KB) is in the built-in manifest. It is the one write-class capability H1 policy decides: planned only when it carries exactly those labels in the `harness` namespace, allowed by the named rule `allow.task-submit` after every deny rule and the schema check (a user deny still wins). The driver always grants it. It goes through the write-ahead intent like any call, is recorded as `SubmitRequested` with the note as an untrusted payload, runs no provider, and stops the loop with `Submitted`. | §2.5, §4.8, §5.1 |
| H1e-2 | **Read tools, in process.** Paths are resolved from the canonical workspace root one component at a time; a symlink at any component is refused (never followed), walks never follow one, and a symlinked workspace root is refused. Bounds: `fs.read` ≤ 100 lines of a UTF-8 file ≤ 4 MiB, with the file's SHA-256 and total lines; `fs.search` ≤ 50 hits grouped per file, files ≤ 1 MiB, ≤ 20 000 entries walked; `fs.list` ≤ 500 entries, depth ≤ 4; every result cut at 64 KiB with its digest over the whole. Errors are `ToolStatus::Error { code }` with harness text. **Deviation:** `fs.search` is a literal substring match, not a regular expression (no regex crate in H1). **Named residuals:** the check-then-open window (nothing in an H1 session can create a symlink; H2's confined helper closes it), and hard links (materialisation, H2). | §4.8, INV-30 |
| H1e-2 | **Context builder** (`harness_model_core::context`). The size estimate is the meter's (bytes / 3, rounded up, plus a fixed per-message overhead). Over budget, K shrinks to 1, then the per-observation caps halve to a floor of 10 lines / 1 KiB; beyond that, `ContextExhausted`. Block 5 (notes) is absent until `notes.write` (H2). Index lines carry only harness data (step, capability id, output digest, size), never the call's arguments. A truncation notice is a separate harness message. The context digest (journaled as `ContextBuilt`) is over every message's role, label and text, length-prefixed. | §2.3 |
| H1e-2 | **The loop** (`harness_run::run`). Before anything is written: plan the session, build tool definitions from admitted capabilities (at most `max_active_tools`), open the workspace, refuse a `state_root` that overlaps the workspace, run the locality check with the caller's probe (`NoProbe` refuses), measure the workspace facts (tree digest and file count, the header's and block 4's). An `Empty`, `Truncated` or `Unusable` completion is a format error (the prompt is still charged, estimated); `Unavailable`, `RateLimited` and a replay divergence stop with `ModelUnavailable`. Loop detection sees the proposed action before policy, so a stopping repeat is never executed. Denials are fed back as static harness text per reason. Every H1 outcome is `Indeterminate { NothingChecked }`; any journal failure is `UnreadableEvidence`. Run ids and nonces take their random bits from std's keyed `RandomState`, XORed on Unix with `/dev/urandom` bytes (without the device, e.g. on Windows, not a CSPRNG; uniqueness and unpredictability to the model are what they need). **Async decided:** `ModelBackend` and `ToolProvider` stay synchronous for H1; the question returns with rmcp (H4). | §2.1, §2.2, §2.5, §2.8, §3.1, §4.5 |
| H1e-2 | **H2 condition (loop detection):** once write tools exist, the identical-action repeat key must include the workspace tree digest, so re-running a read after the workspace changed is not a repeat. H1 cannot change the workspace, so the key is `(tool, args digest)`. | §2.6 |
| H1e-2 | **H1e-2a review, closed.** F-1: the loop journals first and charges wall time after: `ModelReplied` is appended before the wall tick that can stop the run, and a tool's time is charged only after its `ToolFinished` is durable, so every stop other than a journal failure leaves every request paired with its reply and every intent with its result, and the journal replays (a test drives every such stop cause, twelve clock rates included). F-2: search reads at most 1 MiB + 1 byte per file whatever the file became after the size check, and a walk stops listing a directory at the entry limit or the deadline instead of enumerating it whole. N-c: the header lists the sentinel once. The read tools' check-then-open window and hard links stay named residuals for H2 (the confined helper, FT-12). | §2.2, §4.8 |
| H1e-2 | **Not yet (H1e-2b), recorded so nothing is lost** (all closed in H1e-2b except the exit test; see the H1e-2b rows): the CLI verbs `run`, `replay`, `profile check` and the post-commit steps (report line, `GATE_OK_FILE`, exit 5, printing the chain head); the audit-replay driver (recompute every context digest and policy decision, first divergence is `UnreadableEvidence`); the end-to-end H1 exit test on a local model with both protocols, blocked until spike S-F1 gives a real locality probe; honouring Retry-After; the server-claimed identity fields (§3.5); `BudgetCharged` 80% events from the loop; the locality check on the attempt directory itself (today it runs on the run directory before the attempt exists); the `(path, sha256)` read record for stale-read checks (needed with edits); resume (§2.10). | §2.2-§2.10, §3.5, §7.1, §7.7 |
| H1e-2b | **H1e-2a confirming review NF-1, closed.** The workspace-facts walk hashes files in 64 KiB chunks (`harness_core::Sha256Stream`), never reading one whole; a file over 64 MiB contributes its size, not its content (kind `F`, counted as `workspace_oversize` in the header and the context facts); the walk has a deadline (`RunConfig::facts_timeout`, default 120 s) and past it the run does not start. | §2.3, §2.8 |
| H1e-2b | **CLI verbs** (§7.7). `run`, `resume`, `replay` are gate children: whatever happens after the arguments are read, the last stdout line is a `GateReport` (JSON), the line before it `chain_head <sha256>` when there is a journal, and the exit code agrees with the report (0 `Passed`, 1 `Failed`, 2 usage, 4 unreadable input, 5 `Indeterminate`; usage and unreadable input still print an `Indeterminate { CouldNotRun }` report, so a protocol-reading parent never sees a report that contradicts the exit). The report's gate id is `--gate`, default `rustyharness.run`. The commit order is §7.1's: `RunStopped` durable, report line, marker only for `Passed`, exit; a failed report or marker write exits 5. Every H1 run exits 5 with `NothingChecked` and no marker. The state root's locality is checked before the model server is contacted. `profile check` runs the smoke eval against the server and prints the `validated` object to add to the profile (exit 0 stamp, 1 no stamp); it does not rewrite the file. Task specs and policies are strict JSON files (`{"task", "grants", "workspace_public"}`, `{"deny", "ask", "allow"}`), never argv text. | §7.7, §7.1, §3.4 |
| H1e-2b | **Tests and the locality probe.** Until spike S-F1, every OS refuses every `state_root`, so the CLI's own tests cannot run a verb through the binary. The CLI is a library (`harness_cli::main_with`) that takes the probe as an argument; the `rustyharness` binary passes `NoProbe`, and nothing in any build of it can choose another (the purity gate checks that its `main.rs` names exactly one probe, `&NoProbe`, with two selftest plants). The CLI tests run the verbs end to end in process with their own permissive probe; every refusal test runs the real binary. (The first version of this slice used a dev-only `test-probe` feature switched by an environment variable; `cargo test` then rebuilt `target/debug/rustyharness` with it, which the H1e-2b review, F-2, showed bypasses the refusal. It is gone.) | §2.8, INV-35 |
| H1e-2b | **Audit replay** (§2.9, INV-20): `harness_run::audit` re-drives the same loop with the recorded replies (`ReplayBackend`, which refuses a request whose digest differs), the recorded tool results in place of the tools and the recorded nonces, writes what it recomputes into `runs/<run-id>/replay-<k>/` (never into an attempt), and compares record by record (kind, step, body). The first difference, a journal that does not verify or belongs to another run or attempt, header inputs that differ, or a chain head that is not the caller's anchor (`replay --anchor`) is `Indeterminate { UnreadableEvidence }` naming the record and step. The header now carries what a replay must match: the task, profile and policy digests, the grants, the workspace declaration, the protocol, the limits and the workspace facts (and `checks: 0`). **Not recomputable, handled explicitly:** the workspace (re-fed, never read) and the wall clock (a `BudgetCharged` record for `wall` is left out of the comparison and the replay's meter has no wall limit). A run the wall budget stopped can be checked only up to its last record: every recorded record must match, but the stop itself is not recomputed (`AuditReport::stop_recomputed` is false), and a journal cut at any step boundary and ended with a forged wall stop, re-chained, looks exactly the same (H1e-2b review F-1). So such an audit is `Indeterminate { UnreadableEvidence }`, with the finding "wall stop not recomputable; only --anchor proves no truncation", unless the caller's anchor matched; a stop the replay recomputed is verified without one. A re-chained journal (the chain is unkeyed) is otherwise caught whenever the edit changes anything the loop recomputes. **Anchor-only residuals:** a wholesale replacement; a self-consistent injected step; and an edit to the last recorded tool result before any later model request (a tool result is an input to the replay, and nothing after it depends on it). | §2.9, §7.1 |
| H1e-2b | **Resume** (§2.10): only an attempt without `RunStopped` is resumed, always into a new `attempt-<n+1>` (the old journal is read, never appended to, poisoned or not); its header records `resumed_from` (attempt and chain head). The new attempt replays every step of the old one but the last (checked like an audit; a divergence makes the run `UnreadableEvidence`) and runs the last step again live, so a trailing intent with no result is decided again by policy. Snapshot handling for H1: nothing in an H1 session can change the workspace, so the snapshot is the recorded tree digest, and a resume is refused when the workspace no longer has it (restoring a snapshot is H2). Task, grants, profile and policy must match the recorded header. The resumed attempt's meter starts with the wall time the interrupted attempt spent (its journal's last monotonic time, `Meter::new_resumed`, confined to the driver like `Meter::new`), so a kill and resume buys no fresh wall budget; steps and tokens are re-charged by the catch-up. **H2 condition:** the last step is re-run live even when it had completed; that is harmless for H1's reads, but once steps can write, resume must never repeat a completed write (skip a step whose `ToolFinished` is durable, or restore the snapshot first). | §2.10 |
| H1e-2b | **Smaller items.** Retry-After (delta-seconds only, at most a day; the HTTP-date form is ignored) is honoured as a floor on the backoff, still bounded by the retry count and the call's deadline: a server asking for longer than the call has left ends it. §3.5 claims: the startup check records the listed model id and the `Server` header; the header journals them as untrusted payloads (`claimed_model_id`, `claimed_server`); the chat-template hash needs llama.cpp `/props` (spike S-P1) and is not collected. The 80% budget condition is journaled once per state change per dimension (`BudgetCharged`, `condition: enter/exit`, key = dimension; the record carries the dimension, not spent and limit: a deviation from §7.2's table). The locality check also runs on each new attempt directory after it exists and before its header (`JournalWriter::create_next_attempt_checked`). The read record: a successful `fs.read` journals `read_sha256` in its `ToolFinished`, and the run keeps a `ReadLog` whose `check(path, current)` refuses an edit to a file never read or changed since (H2's edits call it). | §3.2, §3.5, §2.6, §2.8, §2.3 |
| H1e-2b | **H1e-2b review, closed.** F-1: a wall-stopped audit without a matching anchor is `UnreadableEvidence` with a named finding, never "every record matched" (`stop_recomputed` in the report; a forge test cuts 24 records to 9, re-chains, and must not verify). F-2: no build of the binary carries a switchable probe (above). F-3: an invalid `--gate` prints a report line under the default id and exits 2, like every usage error. Recommended and done: the resumed attempt's meter is seeded with the wall time already spent. | §2.9, §2.10, §7.7 |
| H1e-2b | **Not yet (H1e-2c and later), recorded** (S-F1, the exit test and the review notes closed in H1e-2c; see its rows): spike S-F1 (real per-OS locality probes) and with it the H1 exit test (a read-only question-answering task end to end on a local model with both protocols); the environment sample in the header and at timeouts (§7.1); the config and manifest digests in the header; the chat-template hash (S-P1); the stale-read check's consumer (edits, H2); snapshot restore on resume and never repeating a completed write step on resume (H2, when sessions can write). | §9 H1, §7.1, §2.10 |
| H1e-2c | **Spike S-F1: the per-OS locality probes** (`harness_sandbox::locality::SystemProbe`). They MEASURE; `harness_policy::locality::classify` still decides, and any failure to measure is `QueryFailed`, refused. **Deviation from the §2.8 mechanism column:** `statfs(2)` needs FFI, which `harness-sandbox` forbids, so the probes read the kernel's mount table and match the path to its mount by DEVICE NUMBER (`st_dev`), never by path prefix. Linux: `/proc/self/mountinfo` (`major:minor` and the type NAME); admitted names are `ext2`/`ext3`/`ext4`, `xfs`, `btrfs`, `tmpfs`, `zfs`, `f2fs`, and `overlay` only over an admitted `upperdir`; `nfs*`, `cifs`, `smb3`, `9p`, `ceph`, `fuse`, `fuseblk`, `fuse.*` and everything else are refused (`FsQuery::LinuxNamed`). macOS: `/sbin/mount` gives each mount's type and `local` flag; only mounts that are `apfs`/`hfs` AND `local` are stat'ed (never a network mount, which could hang), and the path is local only if its device equals one of theirs. Windows: UNC shapes are refused; the volume query needs FFI in `harness-sandbox-windows` (spike S-W1), so every Windows `state_root` is still refused (`Unmeasured`); compile-checked for the Windows targets, not run. **Named residuals:** a mount placed over the path between the stat and the table read; a Linux btrfs subvolume that is not a mount point matches no entry and is refused (availability only); network block storage under a local filesystem (§11). The `harness-sandbox → harness-policy` edge is new (the probe implements the policy crate's trait). The binary passes exactly this probe; the purity gate checks it by content, not name (below). | §2.8, INV-35, §1.2 |
| H1e-2c | **The H1 exit test** (`harness-cli/tests/exit_h1.rs`, `#[ignore]`d: it needs a model server; run with `RUSTYHARNESS_EXIT_ENDPOINT` and `RUSTYHARNESS_EXIT_MODEL`). For each protocol, the real binary with the real probe runs a read-only question-answering task (find a codename in the workspace's files and submit it) against a loopback server, and must end `submitted`, with a read tool used, the answer in the submitted note, exit 5 and `NothingChecked` shown in words on stderr and in the report line; then `replay` must recompute and match every record. Run for H1e-2c against a llama.cpp server with a 27B-parameter quantised model: both protocols passed (text: 5 steps, 35 records; native: 6 steps, 38 records, with two format errors repaired). The CLI now prints `outcome: …` in words. **Found by the exit test:** chat templates refuse a system message after the conversation starts, so only the FIRST context message is sent with the system role; later harness messages (facts, index, repair and loop notices) go in the user role, prefixed `[harness]` (§2.3 rendering). | §9 H1, §2.3, §7.7 |
| H1e-2c | **H1e-2b confirming review, closed.** NF-1: a resumed header records `wall_carried_ms` (every earlier attempt's wall time), and the meter is seeded with that plus the old attempt's own elapsed time, so crash-resume-crash-resume charges the total (witness: two chained resumes stop on the wall budget). NF-2: gate §2e now checks `main.rs` by content: the probe is imported from `harness_sandbox::locality`, named exactly twice (the import and the one `probe:` field), and nothing in the file defines or renames an item (`struct`, `enum`, `trait`, `impl`, `mod`, `type`, `const`, `static`, `macro_rules!`, `as`); five selftest plants, including the review's local `struct` with the production name. | §2.10, INV-35 |
| H1f-1 | **Windows CI green; CI runs the member gates.** Evidence: CI run 20 (commit `c07b53c`) passed `gates (ubuntu-latest)`, `gates (macos-latest)` and `gates-windows`, the first green Windows run since H1c. Windows CI had been red on `main` since H1d, and `cargo test` stopping at the first failing binary hid all but the first failure. Two CLI tests assumed a probe that measures: on Windows the real probe refuses every `state_root` until spike S-W1 (above), which is the designed behaviour. **Owner decision:** until S-W1 the Windows CLI tests ASSERT that refusal (exit 5, `CouldNotRun`, the message names S-W1, nothing written, no server contact), and the whole-run test then drives the run in process with the tests' probe, so everything after the locality check is still covered on Windows. The one other hidden failure was timing: Windows retransmits a loopback SYN after each RST and reports a refused connect only after about 2 s, beyond the test's 500 ms connect timeout (both results are `Unavailable`; the test now allows 10 s so every OS pins the refused path). **Named note (S-W1):** the client's default connect timeout is 2 s, so on Windows "no server listening" can be journaled as `connect_timeout` rather than `connect`; the stop cause (`ModelUnavailable`) is the same. **CI:** `.github/workflows/ci.yml` now runs `scripts/ci/gates.sh` itself on Linux and macOS (the purity gate, its refusal witnesses and the error-code doctests had never run in CI); Windows runs each cargo step (every step runs even when an earlier one failed, and the test steps use `--no-fail-fast`), but not the `RUSTC_BOOTSTRAP` error-code doctest step, whose result does not depend on the target; the purity gate's `cargo tree --target all` covers Windows dependencies from Linux. The gates' former "again with `gate-outcome/json`" passes built nothing new (harness-cli enables that feature, and features unify across `--workspace`, since H1e-2b), so they are replaced by clippy and tests of `gate-outcome` alone: the zero-dependency default build no workspace build ever saw (review F-1). The Windows check is now named `gates-windows`. **Open (owner, INV-35):** audit replay (`harness_run::audit`, `rustyharness replay`) takes no locality probe and writes `runs/<run-id>/replay-<k>/` under `state_root` unchecked, so on Windows the real binary refuses `run` on a state root yet `replay` writes into it; whether audit should check locality (and so refuse on Windows until S-W1) is the owner's call. | §8, §9, INV-35 |
| H1f-2 | **`manifest check` is the v1 admission parser.** Until now the CLI verb still validated the scaffold's v0 schema (`harness_tools::Manifest`), so it accepted a v0 manifest and a `rustyvault` provider (INV-1 says refuse) and would have refused every real v1 manifest. It now runs `harness_manifest::Manifest::parse` (strict JSON, version, reserved names, §4.3 content) on at most the 1 MiB cap plus one byte, prints the manifest's SHA-256, each capability's §4.2 class (declared confirmation raised by the derived floors, before user policy and tier floors), the mcp-stdio `Conformed` requirement (§4.5) and the pinned tier's floors (§4.4), and what this build's admission would do if these exact bytes were pinned, by calling the same `Registry::admit` a run uses (today: refused, pinning is H4). Exit 0 valid (valid is not admitted), 1 refused on content, 4 not readable as a JSON document (missing, over the cap, not well-formed), 5 when the harness cannot check. **Named residuals:** the reserved set is the core constant only (H1 has no harness config, so no `extra_reserved`), and only the pinned tier is tried (a manifest refused as pinned may be admissible as signed, H4). **Review F-1 (MEDIUM, closed):** refusals quoted manifest-chosen text raw (serde's unknown-field and unknown-value messages, and the key path of a `null`), so a refused manifest could redraw the terminal, e.g. print a forged `OK` over its own refusal; that text now goes through the journal's reversible escape (`\`, and `\u{HEX}` for control, separator, zero-width and bidi code points), bounded, in `harness-manifest` so every consumer is covered (§7.1 display paths). A `pinned`-tier refusal of an in-process transport no longer prints an empty capability. The v0 types are gone from `harness-tools`, which is now only the provider half (§1.2), and `harness-cli` no longer depends on it. `adapters/example/manifest.json` is a v1 mcp-stdio illustration with placeholder (all-zero) pins. The six dimension enums gained `as_str()` wire names, round-tripped through serde by a test whose variant lists sit behind wildcard-free matches. | §4.1, §4.3, §4.4, §7.1, §7.7, INV-1, INV-22 |
| H1f-3 | **The environment sample (§7.1, R3 H-17) and the rest of the header.** The vocabulary is pure (`harness_core::environment`): `EnvSample` has five host-wide fields (logical CPUs online, 1-minute load in thousandths, memory total, memory available, free bytes on the `state_root` volume), each `Measured { value, method }` or `Unmeasured(reason)`; methods and reasons are closed sets, each method belongs to one field and one probe (Linux, macOS, or a CPU count alone), so a sample carries no outside text and a recorded one parses back exactly; `possibly_environmental` is §7.1's rule (available memory under 5% of the total, or load above twice the CPUs; an unmeasured field never counts). **Scope (review F-4):** every field is the host's, the load average's own scope; comparing it with a CPU count limited by this process's affinity or cgroup quota would call an idle host pressed. The probe (`harness_sandbox::environment::SystemEnv`): Linux reads `/sys/devices/system/cpu/online`, `/proc/loadavg` and `/proc/meminfo`, bounded and strictly (a repeated key is unreadable, not "last wins"); macOS runs `/usr/sbin/sysctl -n vm.loadavg hw.memsize hw.logicalcpu` and `/usr/bin/vm_stat` through the crate's private `capture` (review F-7: cleared environment with `LC_ALL=C`, stdin null, at most 4 MiB read, each query killed at a 5 s deadline, so a macOS sample can take up to 10 s; a reader thread that cannot start is an error, not a panic; it assumes a child that does not fork, which none of the three does; the locality probe's `/sbin/mount` now uses it too), memory available being (pages free + pages inactive) × page size, as its method says; Windows takes CPUs from `available_parallelism` (no load average exists there to meet it: `no_such_measure`) and needs `harness-sandbox-windows` for memory (`no_safe_api` until S-W1); any other OS is `not_implemented`. §4.5 now names the three macOS queries among the harness's own unconfined children (review F-3). **Deviation:** free bytes on the `state_root` volume are `no_safe_api` on every OS (`statvfs`/`GetDiskFreeSpaceExW` need FFI, §6.7). **Named residual:** a container's own memory limit (cgroup `memory.max`) is not sampled, so memory pressure inside a limited container can go unflagged. **Where it is recorded:** the header (`environment`, with `environment_source: measured`), and every `ToolFinished` whose status is `timeout`, `crashed` or `provider_error` (a provider failure is the tool-level "could not run"; `ToolStatus` has no CouldNotRun, which is a check outcome; review F-2); `VerificationStarted` and `CheckReported` samples arrive with H3. The Info finding `harness.possibly-environmental` names the steps whose tool timed out, crashed or could not run under pressure: §7.1 says CouldNotRun or Timeout, and a crash is added on purpose (an OOM kill is the typical pressed-host crash). The sample never changes an outcome. **Replay and resume** cannot re-measure a past host, so they re-feed recorded samples like model replies: the replay header repeats the recorded sample with `environment_source: recorded` (review F-9), a re-fed result carries its recorded sample, a step with no recorded result (an intent a crash cut) is replayed as a provider failure whose sample is `not_sampled` (never the header's), and a sample missing where one is due, present where none is, with a method on another field's key or from two probes, zero CPUs, or any other shape the loop does not write is a record the loop did not write (`UnreadableEvidence`); so is a read digest on anything but an `ok` result, and the loop records a read only for an `ok` one. Tests cover a live timeout, crash and provider failure in the loop, audit re-feeds of `timeout`, `crashed` and `provider_error`, a cut intent replayed as `not_sampled`, a resume re-feeding a timed-out catch-up step, and each refused shape. **Anchor-only residual:** a sample is an input to the replay, so a self-consistent edit to one is caught only by the anchor, as for a tool result. **Header completeness:** `os` and `arch`, `builtin_manifest` (the SHA-256 of the compiled-in manifest; rustc reads CRLF sources as LF, so it is the same on every OS), `shell_enabled: false` and `sandbox: {backend: none}`, constants that hold only while nothing admitted can run code (a test fails the day an execute-class capability is admitted; review F-10). `builtin_manifest` and `shell_enabled` join the header inputs a replay or resume must match, and a mismatch now names its key (review F-5): **compatibility break**, a journal written by another harness build, every journal from before H1f-3 included, can be neither audited nor resumed by this one, and says so. **Not recorded, named:** a config digest (H1 has no harness config; the policy digest is already in the header), protected-path and verification-plan digests beyond `checks: 0` (H3), and the sandbox matrix row and probe digest (H2). | §4.5, §7.1, §7.2, §2.9, §2.10 |
| H1f-4 | **INV-23 in H1: no payload reaches an argv.** §10's falsifying test names the confined helper, MCP servers and checks, none of which exist in H1; what H1 has is the harness process itself and its own system queries (§4.5), and both halves are tested. **Static, by structure (purity.sh §2f):** every spawn goes through the closed `Query` enum in `harness-sandbox`'s `capture.rs` (`Mount`, `Sysctl`, `VmStat`), which fixes each program and argv; the macOS probes call `capture::query(Query::…)` and name no program. The gate then holds: the words `Command`, `CommandExt` and `raw_arg` appear in code (comments and literal contents stripped) in no source under `crates/*/src` except `capture.rs` and its `#[cfg(test)]` tests; `capture.rs` names `Command` (the scan read it), declares its tests `#[cfg(test)] mod tests;`, and every absolute-path literal in it is `/sbin/mount`, `/usr/sbin/sysctl` or `/usr/bin/vm_stat`; no symlink under `crates/`, no `#[path]` or `include!` in any source, and no source with a NUL byte. The first version matched call shapes (`Command::new(` with a literal) and the review (F-1, HIGH) showed turbofish, UFCS, raw identifiers, qualified self, function paths, type aliases, macros and `raw_arg` all passed it, with a mutated binary putting the task text on an argv through both halves; every spelling has to write the word, so the word gate holds for the sources it reads; the three-program allowlist (and, since the confirming review, the pin below) also closes the relay through an interpreter's env or stdin (F-5). The shared comment stripper now reads raw C strings (`cr"…"`), which had hidden code (F-2, which also affected the older pure-code scans), and `scan` reads files as text (`grep -a`). The gate fails closed on legitimate code too (the word in code elsewhere, another program in `capture.rs`); integration tests (`crates/*/tests/`) are separate test crates and may spawn. 36 selftest cases (35 refusals and one accepted control), each asserting the sub-rule that fired, including a grep that fails mid-scan and `cargo metadata` failing or printing a shape the gate does not read (105 cases in all). **Runtime (`harness-cli/tests/cli.rs`, Linux and macOS):** the real binary runs a task whose text carries a canary through a tool step; at every chat request, every process's argv is read (`/proc/*/cmdline`, or `/bin/ps -axww -o args=` on macOS): the canary is in each request and in no argv, and the scan saw the harness (an argv naming the binary and the task file). A witness runs first: a `sleep` whose argv[0] is a canary must be found. **Named limit:** each scan is a snapshot, so a child that starts and exits between scans is covered only by the static half. Windows has no runtime scan in H1 (it cannot start a run before S-W1). **Confirming review NEEDS-FIXES, closed:** the word gate reads only the workspace's own sources, so a spawn in code it never reads passed it (NF-1, HIGH: a path dependency outside `crates/` spawned with the task text on its argv, the binary built, and purity passed). purity.sh §5 now holds the build to what the gate reads: every package in the normal and build tree, for every target, is a workspace crate at `crates/<name>` or a crates.io crate on one reviewed list (the union of the pure crates' allowlists; none has a process API), so a path dependency outside `crates/`, a `[patch]` onto a path, a git or another registry's crate is refused; every target is a lib or bin rooted under `crates/*/src/` or a test under `crates/*/tests/`, with no build script, proc macro, bench or example (NF-3: a build script can add linker arguments or generate code, and it and `benches/` were unscanned); every lib and bin root opens with `#![forbid(unsafe_code)]`, so no crate reaches foreign code (libc, with its exec family, is on the list), assembly or a link section; and no `.cargo` directory is in the repository. `capture.rs` is pinned by its SHA-256 (NF-2, MEDIUM: a relative program name, which `Command` resolves through the inherited `PATH` even after `env_clear`, or an extra argument passed the absolute-literal check), so its programs, argv and bounds change only with the gate, by review. The case count is corrected (NF-4). **Out of scope, named:** the toolchain, the build environment (`RUSTFLAGS`, the user's own cargo config, the libraries on the linker's path, which a `#[link]` can name though nothing can call into one without `unsafe`) and the listed crates' own code at their locked versions (supply chain, §8). **Second confirming review SOUND:** NF-1..NF-4 re-planted and refused (a path crate outside the workspace root too), no bypass found, and each new rule shown load-bearing (with the rule removed, its plant passed; with the pin removed, the selftest failed on its case). Its INFO notes: the new shell ran on macOS only in CI, where the full gates pass (CI run 31); the reviewed list and the `forbid(unsafe_code)` check hold the line together (libc is listed, and its exec family needs `unsafe`); a path crate under the workspace root is refused by both the package and the target checks, one outside it by the package check alone. | §10 INV-23, §4.5, R3 H-08 |
| H1f-5 | **Documentation brought up to H1 as built.** `README.md` (status; every crate built so far, §1.2's `harness-mcp`, `harness-sandbox-windows` and `harness-conformance` coming later; a "try it" section whose example task and profile files were run through the binary as written), `SECURITY.md` (what runs today and, item by item, what a report can be about, with the named residuals it excludes), `docs/OPEN-QUESTIONS.md` (still-open items first: §11's owner questions, noting that §9's H0 exit asks for them answered or their defaults accepted in writing and none is recorded, the audit-replay locality question, the H1 phase-exit review; then each original question with where the design answered it). Stale "scaffold" and pre-H1 status text in crate docs, Cargo descriptions, the overview, the research index and this document's status line is updated. **Review F-1..F-14, closed:** the README no longer overstates replay (recorded replies and tool results are re-fed, every context digest and policy decision recomputed; only the anchor detects a replaced or consistently re-chained journal), the locality rule (`replay` does not check yet) or the outcomes (a refused run is `CouldNotRun`; a failed journal or a resume whose catch-up diverges `UnreadableEvidence`), and its commands work as written. **Confirming review SOUND; its notes closed:** the README states `profile check`'s exit codes and that the commands assume the binary on `PATH`, and that suite add-ons will ship (H5); SECURITY.md excludes the locality residuals (row H1e-2c, §11) and a newly named §11 residual: in-process read tools are not interruptible in H1, so INV-14's hanging-tool test has no H1 counterpart (flagged for the phase-exit review); it names the submit sentinel as the one write-class capability; `harness-sandbox`'s docs name the three fixed host queries as the harness's only unconfined children; two stale crate-doc lines (the async decision, `harness_core::sha256`) are current. **Left for the phase-exit review:** `replay` still prints "every record recomputed and matched" although replies, tool results and samples are re-fed (a wording change to the binary, outside a docs slice). No behaviour changes except the sandbox refusal text, which now says `(H2)` instead of `(scaffold)`. | §9, §11 |

## Owner decisions after v0.2 (2026-09-24)

Made by the owner after the SOUND review, while planning how rustybenchmark uses the harness (overview
§2, U3). Unlike the rows above, some of these add scope: OD-5 lists capabilities that are **required
but not yet designed**. Each needs a design delta, an R6 threat-model update where it touches the
network, and the two-eyes review before it is built. None changes a decision in §0 or an invariant.

| # | Decision | What it means here |
|---|---|---|
| OD-1 | **The goal in the wild.** On its own, rustyharness aims to do what a general coding agent such as opencode or Cline does: read and edit code, run the toolchain, fetch crates and documentation online, open ports on the device. Every action needs the user's permission and runs inside confinement. | A goal, not a claim about what is built. The roadmap already covers most of it (edits and `exec.run` in H2; the egress proxy and MCP in H4; an opt-in shell, §4.8). OD-5 adds the missing pieces. **Known conflict:** fetching online while editing a default workspace is P ∧ U ∧ E, because a workspace is private and untrusted by default, so the trifecta rule refuses that session with no override (§5.4, INV-9). Until owner question Q7 is revisited, that part of the goal works only for a workspace declared `public`, or with research in a separate session |
| OD-2 | **Embedding apps lock the harness down through configuration; the harness holds no app-specific code.** rustybenchmark embeds `harness-run` and passes its own policy, a provider registry that holds only the compiled-in built-in manifest (no app-specific providers), and its own profile, and can pass its own `ModelBackend` to time model calls. The registry can't be empty: `run` always grants the `harness.task.submit` sentinel, and session planning resolves every grant against the registry, so an empty one refuses the run before any model call. Its "benchmark mode" is only that configuration: no internet, only its own crates and ports, no approver (every Ask becomes Deny, §5.3), a fixed toolset and fixed budgets. | Nothing to build: `harness_run::run` already takes these from its caller, and `harness-run` reads no configuration of its own (checked at `6ba3437`). Keep it so: if the harness ever reads a user config, environment variables or project instruction files, an embedder must be able to switch that off |
| OD-3 | **Grading and measuring stay in the embedding app.** rustybenchmark grades with its own grader in its own sandbox, and measures outside the harness. The harness never scores for an app. | The harness's checks stay generic (§7.3). An app's score is never the harness's outcome |
| OD-4 | **Sharing confinement code with rustybenchmark: reopened.** §6.3 proposed `harness-sandbox` and `harness-conformance` as crates the benchmark's grading sandbox depends on. The owner's position: the benchmark's grading sandbox stays its own. Confinement code is shared only through a standalone crate outside both projects (as `gate-outcome` is for outcomes), or not at all. | Which of the two is open (OPEN-QUESTIONS, Still open 4). The harness still takes no dependency on the benchmark |
| OD-5 | **Required capabilities, not yet designed.** (a) **Ports with permission:** bind and connect on granted loopback ports, never the model server's; a port visible on the network is a separate, higher-risk grant. (b) **Background processes:** start, read output, stop; all killed at run end and at any stop. (c) **Embedder-supplied confinement inputs:** extra read-only roots (e.g. a local crate registry, a pre-built build cache), a writable build directory outside the workspace, and environment and cargo configuration. (d) **`gc`:** remove a finished run's `workspace/`, `grading/` and `scratch/`, and keep its journal, blobs and snapshots; callable from the embedding API too. | (a) conflicts with today's network model: `ConfinedSpec.network` is `None` or `Proxy`, and the proxy refuses loopback (§6.2, §6.5); on Windows it meets S-W2's loopback question. (b) is new: `exec.run` is synchronous (§4.8). (c) `ConfinedSpec` has the fields (§6.2), but `TaskSpec` and `Run` don't expose them. (d) is §11's named `gc`. Phase placement is open; rustybenchmark needs (a)–(c) with, or soon after, H2 |
| OD-6 | **No VMs and no external container runtimes** (a Linux VM on macOS or Windows, Docker, Podman). A VM reserves memory the local model needs, and it isn't how people run coding agents on their own machines. The native OS sandboxing of §6.3 stays, even where it is container-like: Linux namespaces with `pivot_root`, Landlock and seccomp; Seatbelt; AppContainer with a Job Object. | Agrees with the native per-OS backends of §6.3 (OPEN-QUESTIONS, answered 12). The suite's separate-OS-account question (OI-24) is untouched |
| OD-7 | **Windows execution is wanted** (owner intent): rustybenchmark will ship a Windows app. | Owner question Q4's default stands: Windows stays read-only until spike S-W1 passes. This records the intent, not a pass |

---

## 0. Decisions at a glance

| # | Question | Decision | Where |
|---|---|---|---|
| D1 | Trust domains | Two domains. **Reasoning** (context, model call, parse) has no side effects. **Action** means every effect is a harness-executed, policy-checked, confined tool call. | §1.1 |
| D2 | Crate map | 13 crates (§1.2). Two scaffold crates are split (tools becomes manifest + tools; sandbox gains a Windows unsafe-isolation crate). New: `gate-outcome` (standalone), `harness-policy`, `harness-mcp`, `harness-run`, `harness-conformance`. | §1.2 |
| D3 | Outcome type | A standalone, std-only `gate-outcome` crate carries UNIFIED verbatim. The harness and the suite both depend on it; neither defines another. | §1.4 |
| D4 | Context | Rebuilt every turn from run state, with a stable prefix. Older observations collapse to pointers (path, digest, size), never to model-written summaries. | §2.3 |
| D5 | "Done" | The agent's `task.submit` is a request for verification. The run's result is `verdict()` over harness-run check reports plus the reviewer report, and only over a **complete** plan: verification that does not finish every planned check is `Indeterminate`. A task with no checks can never be `Passed`. | §2.5, §7.3 |
| D6 | Model layer | One async `ModelBackend` trait. Our own thin OpenAI-compatible client: plain HTTP to loopback by default, TLS only behind cargo feature `hosted`. Native tool calls **and** a text protocol with a grammar-constrained action block, chosen per model profile. | §3 |
| D7 | Wire protocol | MCP on the wire (rmcp, stdio child process). A **capability manifest v1** is the trust root: effect plus five closed-set dimensions, pinned description and schema hashes, optional ed25519 signature. Server self-description is ignored for policy. | §4 |
| D8 | Modularity | A new provider ships a manifest plus an MCP server (or an in-process adapter crate) and is admitted by the user. The core learns nothing app-specific. This is proven by a fixture-provider test with zero core diff. | §4.10 |
| D9 | Edits | Exact search/replace (unique match) or whole-file write. Applied in-process, atomically, with a stale-read check and post-apply hash verification. Never `git apply`. | §4.9 |
| D10 | Policy | deny → ask → allow, first match wins, deny cannot be overridden. The effective class is the **max** of the manifest, derived rules and user policy. Approval tokens are bound to run, step, capability, argument digest and expiry, and are single-use. | §5 |
| D11 | Trifecta | Computed at session start from capability labels. Private + untrusted + egress is refused, and v0.1 has no override. | §5.4 |
| D12 | Confinement | `Available` requires a `Conformed` evidence token. It is minted only by a backend that passed the hostile-task suite in CI **and** a live self-probe on this host. Linux: a self-re-exec helper using namespaces + Landlock + seccomp. macOS: deny-default Seatbelt. Windows: AppContainer + Job Object. Named spikes cover the rest. | §6 |
| D13 | Network | None by default. When granted, egress goes through an allowlist proxy **outside** the sandbox. | §6.5 |
| D14 | Journal | Per-attempt, hash-chained JSONL, append-only at the type level, with untrusted payloads in a typed home. Write-ahead is enforced by type: a provider accepts only a `Journaled` call, minted after the intent is durable. Any append or fsync failure stops the run `Indeterminate`. Replay re-feeds recorded model outputs. | §7.1, §2.2, §2.9 |
| D15 | Two pairs of eyes | A built-in reviewer run: fresh context, read-only tools, distinct identity. Its verdict is extracted from a schema-checked artifact, and it can only add blocking findings. | §7.5 |
| D16 | Suite integration | Add-ons are providers (runtime-loaded manifests plus MCP servers) and a few cargo features (`addon-*`), all off by default. A standalone build has zero suite dependencies. | §8 |

## 1. Architecture

### 1.1 Two trust domains

The domain split comes from the earlier agent-harness draft, which review R4 §5 carries forward ("the part worth ratifying"). The benchmark splits generation from grading the same way (R2 §5).

- **Reasoning domain** assembles context, calls the model and parses the reply into a *proposal*. It has no side effects: it cannot touch files, processes, network or secrets. Everything it receives from outside is `Untrusted<T>` (`crates/harness-core/src/lib.rs:31-34`), and every model reply is `Untrusted` from `Source::Model` (`crates/harness-core/src/lib.rs:39-46`).
- **Action domain** turns a proposal into an effect through a single path: schema validation →
  policy decision → approval when required → confined execution by a `ToolProvider`. No action-domain path accepts a string that is executed as code by the harness. `exec.run` takes an argv vector and runs it only inside a conformed sandbox (§4.8, INV-13).

The only channel from reasoning to action is the parsed action of the **model's own reply**. Text that reached the context from tools, files or the task is never eligible for parsing as an action (R4 §3, the injection invariant; INV-29).

### 1.2 Crate map

| Crate | Change vs scaffold | Pure? | Depends on | Contents |
|---|---|---|---|---|
| `gate-outcome` | **new, standalone repo** (§1.4) | yes, std-only | nothing | UNIFIED `GateOutcome`, `IndeterminateKind`, `Witness`, `GateReport`, `Finding`, `Severity`, `Coverage`, `Scope`, `verdict()`, `run_checked`, child-protocol interpretation |
| `harness-core` | keep, extend | yes | `gate-outcome`, `sha2`, `serde`/`serde_json` | `sha256`, the strict JSON reader, `RunId`, the `TrustedName`/`CallDigest`/`MonoClock` seams (H1c-H1e-1), `Untrusted<T>`, `Source`, `Meter` (multi-dimension budgets, grown from `Budget`), `RunId`/`Attempt`, the turn state machine as a pure transition function, loop detection, `StopCause` |
| `harness-manifest` | **split** from `harness-tools` (schema half) | yes | `harness-core` (the shared strict JSON reader, `TrustedName`) | Manifest v1 types, a duplicate-key-refusing parser, validation, hash pinning, signature verification (keys passed in) |
| `harness-policy` | **new** | yes | `harness-core` (`CallDigest` for `Authorized<Call>`), `harness-manifest` | Effective-class computation (max-rule), the decision function, trifecta computation, approval-token verification, the `Authorized<Call>` minting point, the pure filesystem-locality decision (§2.8) |
| `harness-model-core` | **new** (H1e-2, split from `harness-model`) | yes | `harness-core`, `harness-manifest` | Message and completion types, endpoint rules, wire format, both action protocols, profiles, the context builder (§2.3) |
| `harness-model` | keep, change `Message` (F4) | no | `harness-model-core` (re-exported), `harness-core`, `harness-journal` (replay, since H1d) | `ModelBackend`, OpenAI-compatible client (feature `hosted` adds TLS), replay and scripted backends, the smoke test |
| `harness-tools` | **split** (provider half) | no | `harness-core`, `harness-manifest`, `harness-policy`, `harness-sandbox`, `harness-journal` | `ToolProvider` trait (accepts only `Journaled<Authorized<Call>>`, §2.2), built-in tools (§4.8), edit engine (§4.9) |
| `harness-mcp` | **new** | no | `harness-tools`, `rmcp` | MCP stdio client adapter, connect-time manifest comparator, quarantine state |
| `harness-sandbox` | keep, change `Containment` (F5) | no | `harness-core`, `harness-sandbox-windows` (Windows targets only) | `Backend` trait, `Conformed` token, `ConfinedSpec`, Linux and macOS backends, egress proxy, confined file-op helper, the filesystem-locality **probe** (§2.8; the allowlist decision is in `harness-policy`) |
| `harness-sandbox-windows` | **new** | no | `harness-core`, `windows` | Win32 primitives only: AppContainer profile, Job Object, restricted spawn, volume-type query. `harness-sandbox` wraps them into the Windows `Backend`, so `Conformed` is still minted only in `harness-sandbox`. The **only** crate allowed `unsafe` (§6.7). |
| `harness-conformance` | **new** (test crate, `publish = false`) | n/a | `harness-sandbox` | Hostile-task corpus (§6.6) as data plus a runner, and the committed per-OS pass matrix |
| `harness-journal` | keep, replace `Sink` (F11) | no | `harness-core`, `gate-outcome` | Hash-chained append-only writer, verifying reader, blob store, replay source |
| `harness-run` | **new** | no | all of the above | The driver: session planning, workspace materialisation, loop, verification, reviewer, run report. The embedding API for apps. |
| `harness-cli` | keep, split exit codes (F10) | no | `harness-run` | The `rustyharness` binary |

**Dependency direction.** Edges only point downward, and there are no cycles:

An arrow `A --> B` means "A depends on B".

```
harness-cli --> harness-run
harness-run --> harness-mcp, harness-tools, harness-model, harness-journal, harness-sandbox
                (harness-conformance as a dev-dependency only)
harness-mcp --> harness-tools
harness-tools --> harness-policy, harness-sandbox, harness-journal
harness-policy --> harness-manifest --> harness-core --> gate-outcome
harness-model --> harness-model-core, harness-core, harness-journal
harness-model-core --> harness-manifest, harness-core
harness-journal --> harness-core, gate-outcome
harness-sandbox --> harness-core, harness-policy (the locality probe, since H1e-2c), harness-sandbox-windows (Windows only)
harness-sandbox-windows --> harness-core
harness-conformance --> harness-sandbox
gate-outcome --> (nothing)
```

**What is pure, and how that is enforced.** `gate-outcome`, `harness-core`, `harness-manifest`, `harness-policy` and (since H1e-2) `harness-model-core` do no I/O, have no async, read no clock (time is passed in as a value) and have no global state. A CI gate (H1) runs `cargo tree --target all -e normal,build` on these five crates (every target platform, normal and build edges, since H1e-2) and refuses any dependency outside an allowlist. For `gate-outcome` the allowlist is **empty** with default features (feature `json` admits only `serde` and `serde_json`). For the other four it is `serde`, `serde_json`, `thiserror`, one SHA-256 implementation and one ed25519 implementation (§1.4 says who computes digests). A grep gate refuses `std::fs`, `std::net`, `std::process`, `std::env`, `std::path` (whose `Path` methods such as `exists`, `canonicalize` and `read_dir` do I/O without naming `std::fs`) together with those I/O method calls, and `SystemTime::now` in their sources. The SHA-256 implementation is `sha2` (RustCrypto, pure Rust, default features off), used only through `harness_core::sha256`. Purity is what makes policy decisions replayable: replay recomputes every decision and must get the recorded one (§2.9).

**Async.** tokio (current-thread runtime) is used only in the I/O crates, because rmcp requires it (R1 §5). The pure crates stay synchronous.

### 1.3 Changes to the scaffold

| Scaffold item | Change | Why |
|---|---|---|
| `Message.content: String` (`crates/harness-model/src/lib.rs:28-34`) | `Message` becomes an enum: `System(HarnessText)`, `Task(TaskText)`, `Assistant(Untrusted<String>)`, `Observation { call, body: Untrusted<String> }`. `HarnessText` is constructible only from harness templates. Rendering to the wire calls `inspect("prompt-assembly")` at one choke point. | Scaffold review F4: the trust mark must survive the loop boundary |
| `Containment::Available(Backend)` pub-constructible (`crates/harness-sandbox/src/lib.rs:20-25`) | `Available(Conformed)`. `Conformed` has private fields and is minted only inside `harness-sandbox` by a passing probe (§6.1). `require()` (`:50-55`) returns `Conformed`. Every spawn API takes `&Conformed`. | F5: a lying `Available` must be untypeable |
| `Backend` names (`crates/harness-sandbox/src/lib.rs:29-36`) | `Seatbelt`, `LinuxNs` (namespaces + Landlock + seccomp), `WinAppContainer` | Matches §6.3 |
| `Sink::append` doc-level promise (`crates/harness-journal/src/lib.rs:31-35`); `Event` has no untrusted home (`:11-29`) | `JournalWriter` exposes only appends (`append`, and `append_intent`, which mints `Journaled`, §2.2), each returning `Result`. The reader is a separate type. Events carry `UntrustedBlob` (§7.1). | F11 |
| Manifest parsed with serde last-key-wins | Duplicate JSON keys refused by a custom map visitor (§4.3) | F13 |
| Schema v0 `{schema_version, app, app_version, capabilities}` (`crates/harness-tools/src/lib.rs:24`, `:37-49`) | Schema v1 (§4.1). v0 is refused with a migration message; only the example fixture used v0 (migrated to v1 in H1f-2). | R5 §6.6: `deny_unknown_fields` plus exact versioning means extensions need a version bump |
| CLI exit 2 for both usage and unreadable input (`crates/harness-cli/src/main.rs:33`, `:43`) | Exit codes per §7.7; the last stdout line is the JSON `GateReport` | F10; UNIFIED §6 child protocol |
| `Budget` (steps only, `crates/harness-core/src/lib.rs:80-120`) | `Meter` over six dimensions, each self-measured (the F3 lesson kept) | §2.4 |
| `adapters/<app>/` in this repo | Holds fixtures only. Real providers ship their manifests **with themselves**, so adding an app never touches this repository. | §4.10 |

### 1.4 The outcome crate: shape and boundary

The same rule has been broken three times in the suite: two layers each defined their own outcome type, and the definitions drifted apart. The scaffold therefore deliberately defines no outcome type (`crates/harness-core/src/lib.rs:7-14`). ADR-0002 forbids a dependency on the suite. The resolution is **one crate, one source, two consumers**.

```rust
// crate `gate-outcome` — std-only, zero dependencies (feature `json` adds serde for §6 reports)
pub enum GateOutcome { Passed(Witness), Failed, Indeterminate { why: IndeterminateKind } }
pub enum IndeterminateKind { NothingChecked, UnreadableEvidence, CouldNotRun, UnsupportedOs, StaleBinary }
pub struct Witness { /* private */ checked: usize, digest: Digest }
pub struct Digest([u8; 32]);                              // opaque bytes; this crate never hashes anything
impl Digest { pub fn from_bytes(b: [u8; 32]) -> Digest; pub fn as_bytes(&self) -> &[u8; 32]; }
pub struct GateReport { /* gate id, outcome, findings: Vec<Finding>, coverage: Coverage, scope: Scope */ }
pub fn verdict(reports: &[GateReport]) -> GateOutcome;   // total, worst-wins, verdict(&[]) = Indeterminate{NothingChecked}
pub trait Check { type Input; fn examine(&self, input: &Self::Input) -> Examination; }
pub fn run_checked<C: Check>(check: &C, input: &C::Input) -> GateReport; // the ONLY Witness mint
pub struct GateId(String);                                // non-empty, no whitespace or control chars; GateId::new -> Result
pub mod child { pub struct ChildRun { /* gate, exit kind, last stdout line, marker: Option<String> (GATE_OK_FILE content, §7.3),
                                         timed out, capture: Digest, speaks_protocol: bool (from the check plan) */ }
                pub fn interpret(run: &ChildRun) -> GateReport; }            // UNIFIED §6, verbatim
```

**Where digests come from.** `gate-outcome` computes no hash, so it stays zero-dependency. `Digest` is an opaque 32-byte value that the **caller** computes and passes in: through `Examination` (the digests of the items examined plus a digest over that set) and through `ChildRun.capture` (the digest of the captured stdout and marker bytes). Only these crates compute digests, all through one SHA-256 function, `harness_core::sha256(&[u8]) -> Digest`, built on the single SHA-256 crate on the purity allowlist:
- `harness-journal`: the hash chain, blob addresses and `UntrustedBlob.sha256` (§7.1);
- `harness-run`: the digests check adapters examine, the diff digest, tree and protected-path digests, and `ChildRun.capture`;
- `harness-tools`: read hashes and edit verification (§2.3, §4.9).

**Trust assumption, stated.** A `Witness` digest is a claim by harness code, not something `gate-outcome` proves. The claim cannot turn a non-pass into a pass: `Passed` still needs a non-empty examined set and no `Blocking` finding (or exit 0 plus the marker, for the child protocol). A wrong digest can only mislabel *which* bytes were examined. Every digest that labels evidence is recomputable from journaled blobs, and audit replay recomputes them (§2.9): a mismatch is `Indeterminate { UnreadableEvidence }` at the first divergent step.

**Boundary.** The crate contains the vocabulary, the total `verdict()`, the witness choke point and the interpretation of the child protocol. It contains:
- no I/O (callers spawn children and capture exit and stdout themselves, R3 H-03);
- no policy;
- no harness types;
- no suite types.

`Examination` carries the digests of the items actually examined plus findings. An empty item list yields `Indeterminate { NothingChecked }` (the law that a vacuous check is not a pass). A `Failed` report needs at least one `Blocking` finding, and the constructor enforces this. The crate carries UNIFIED's proof obligations as exhaustive tests over the report-collapse space.

**Location.** The crate lives in its **own repository**, versioned independently (SemVer; any change to the enum is a major version and needs re-review). rustysuite consumes the same crate rather than building one. During H1-H2 it is a workspace member here (`crates/gate-outcome`, extractable, no harness imports). It moves to its own repository before H3 exits (§9). The licence is the owner's call (Q1, §11).

**Harness types that are not verdicts.** `StopCause` (§2.5), `ToolStatus` (§4.5), `PolicyDecision` (§5.1), `ApprovalState` (§5.3) and the `PlanReports` collection (§7.3) describe *what happened*. None of them has a success variant for the run. The only way a run is reported as passed is `GateOutcome::Passed`. A CI grep gate refuses `enum` declarations named `*Outcome` or `*Verdict` in `crates/harness-*` (INV-28).

## 2. The run loop

### 2.1 Lifecycle

```
admit task spec -> state_root locality check (§2.8) -> plan session (grants, trifecta, budgets, fixed check plan)
 -> probe sandbox (if any execute-class grant or mcp-stdio provider; none => refuse, §4.5)
 -> materialise workspace + grading base -> journal header (durable, else refuse)
 -> LOOP { build context -> model call -> parse -> validate -> decide -> (approve) -> journal intent -> execute -> journal result -> stop checks }
 -> verify (full plan in pristine grading worktree) -> [repair round?] -> review (independent run)
 -> finalize (verdict() only over a complete plan, §7.3) -> RunStopped durable -> run report
```

The **task spec** is a user-authored file, trusted as intent, passed by path or stdin, never on
argv (R3 H-08). It declares the task text, workspace source and base revision, capability grants,
budgets, model profile, the verification plan (checks, protected paths, hidden-check directory) and
reviewer configuration. The agent never sees or edits it.

### 2.2 Turn structure

Each turn is one pass of a pure transition `step(state, observation) -> Decision` in `harness-core`, driven by `harness-run`:

1. **Charge the meter** (steps plus the estimated input tokens). If any dimension is exhausted, stop (§2.5).
2. **Build context** (§2.3).
3. **Call the model** (§3) under the remaining wall-clock budget. The call returns a `Completion`, or a typed `ModelError`: `Empty`, `Truncated`, `Unusable`, `Unavailable` or `RateLimited`. Retries use backoff with jitter under a retry budget. An empty or truncated completion is never a turn result (R1 §2, INV-3).
4. **Parse exactly one action.** Native mode reads one tool call. Text mode reads one `<action>` block (§3.3). Zero actions, several actions or malformed JSON count as a **format error**:
   - the model gets one harness-authored repair message naming the parse error;
   - after 3 consecutive format errors the run stops (R1 §1.3, §6).
   - Free text outside the action is journaled as `Untrusted` reasoning and never parsed.
5. **Validate** the tool id against the session's active set, and the arguments against the manifest's input schema (`additionalProperties: false`, exact types).
6. **Decide** with `harness-policy` (§5): allow, ask or deny. Ask pauses the run for approval (§5.3). A denial is returned to the model as an observation and the loop continues.
7. **Journal the intent (write-ahead).** The policy mints an `Authorized<Call>`. `JournalWriter::append_intent(event, call)` appends the intent event (carrying the call digest), fsyncs, and only when both return `Ok` hands back `Journaled<Authorized<Call>>`. `Journaled<C>` has private fields and no other constructor, and it is the **only** type `ToolProvider::invoke` accepts (§4.5). An unjournaled intent is therefore untypeable, not merely forbidden. If the append or fsync fails, no `Journaled` value exists, the step ends here without executing, and the run stops (§7.1, "Write failure").
8. **Execute.** The call runs through the provider under the conformed sandbox when its class requires one. The result is `ToolResult { status, output: Untrusted<Bytes>, truncated, digest }`. Empty output is rendered as an explicit "(command succeeded, no output)" (R1 §1.2).
9. **Journal the result**, then fsync. If this append fails, the effect has happened but is unrecorded. The run stops with the same outcome as in step 7. Resume restores the workspace from the last snapshot, so an unrecorded workspace edit is discarded. It treats the trailing intent as "outcome unknown" and re-decides it (§2.10). The run report names that step as "effect may have occurred; not recorded".
10. **Stop checks**: submit requested, budgets, loop detection, journal writer poisoned (§2.6, §7.1).

A crash therefore leaves at most one incomplete step (an intent with no result), never an executed step with no intent.

v0.1 runs one action per turn: no parallel tool calls. llama.cpp disables them by default, and small models are fragile with many tool calls (R1 §6).

### 2.3 Context construction

Context is **rebuilt every turn from run state**, never grown by appending. R4 §5 carries this forward, and R1 §1.7 reports that context quality degrades as it grows. The order is fixed so that the prefix stays stable for the server's prompt cache (R1 §1.7):

| Block | Source | Trust | Bound |
|---|---|---|---|
| 1 System rules + protocol spec | harness templates (`HarnessText`) | trusted | fixed |
| 2 Tool definitions, deterministic order | manifests (§4.6: server description only if its hash matches the pin) | reviewed | ≤ profile `max_active_tools` (default 8) |
| 3 Task | task spec | trusted intent | fixed |
| 4 Harness facts | derived at run start by the harness: base revision, tree digest, file count, each with its producing method (R3 H-19) | trusted | small |
| 5 Agent notes | `notes.write` tool, agent-authored | `Untrusted(Model)` | 2k tokens (capped) |
| 6 Observation index | one line per collapsed observation: step, tool, argument summary, output digest, size, "re-read to view" | harness-rendered pointers | 1 line each |
| 7 Recent turns | last K (assistant action, observation) pairs verbatim, K = profile (default 5, R1 §1.2) | `Untrusted` | per-observation cap (default 100 lines / 16 KiB) with a truncation notice that says how to see more |

**Compaction.** Compaction replaces content with pointers (paths, digests, step numbers), never with copies or model-written summaries. A summary is a model claim, and v0.1 does not let claims replace evidence. If the context still exceeds `profile.context_window × fill_ratio` (default 0.6), K shrinks first and then the per-observation caps. Blocks 1-4 and the newest observation are never dropped. If even that does not fit, the run stops with `StopCause::ContextExhausted`.

**Untrusted rendering.** Untrusted blocks are wrapped in per-turn random-nonce delimiters. Zero-width and bidi control characters are stripped from everything untrusted before rendering (R1 §3.3). This "spotlighting" is a weak layer and is labelled as such. The load-bearing layers are §1.1's single action channel plus policy and confinement.

**Stale reads.** `fs.read` records `(path, sha256)` in run state. An edit whose anchor was read before the file last changed is refused with "file changed since read; re-read first" (R1 §2).

### 2.4 Budgets

| Dimension | Measured by | Default | Exhausted → |
|---|---|---|---|
| Steps | harness counter | 50 | `StopCause::Budget(Steps)` |
| Tokens (in + out) | server `usage`; if absent, a conservative estimate (bytes/3), marked `estimated` in the journal | profile-derived | `Budget(Tokens)` |
| Wall-clock | harness monotonic clock, excluding time spent waiting for human approval | 30 min | `Budget(Wall)` |
| Cost | profile price table × tokens. Local models cost 0. A hosted run **without** a price table refuses to start. | 0 local / user-set hosted | `Budget(Cost)` |
| Consecutive format errors | harness | 3 | `StopCause::FormatErrors` |
| Repair rounds | harness | 1 | no further repair; verdict stands |
| Per-call timeout | harness, kills the whole process tree (§6) | 120 s exec, 30 s others | `ToolStatus::Timeout` (observation, not a stop) |
| Approval wait | harness | 15 min | the request becomes Deny |
| Verification wall-clock | harness monotonic clock, from `VerificationStarted` (a separate budget, so an agent that spends its whole budget cannot starve the checks) | 30 min, task-settable | the running check is killed, the rest do not run, and the plan is incomplete ⇒ `Indeterminate { CouldNotRun }` (§7.3) |

Every budget measures its own spend; no caller can assert it (wall time included: the meter reads a monotonic clock it is given, and approval waits are excluded by pausing it) (scaffold review F3, `crates/harness-core/src/lib.rs:102-120`). Exhaustion carries `{ dimension, spent, limit }`. Budgets are never extended silently (`crates/harness-core/src/lib.rs:76-78`).

### 2.5 Stop conditions and the result

`StopCause` records **why the loop ended**:
- `Submitted`
- `Budget(dim)`
- `FormatErrors`
- `Loop(kind)`
- `ContextExhausted`
- `PolicyAbort` (a session-level refusal, e.g. a trifecta found mid-run after a quarantine)
- `ModelUnavailable`
- `Cancelled`
- `SandboxLost`
- `JournalUnavailable { op, error }` (an append or fsync failed; §7.1)

It is not a verdict. The run's result is always a `GateOutcome`:

| Situation | Result |
|---|---|
| `Submitted`, every planned check reported | `verdict(check reports ++ review report)` |
| `Budget(_)` / `Loop(_)` / `FormatErrors` / `ContextExhausted` | Checks **still run** (by default; `verify_on_stop = true`), because evidence decides, not the agent's claim. The result is `verdict(...)` under the same completeness rule as the row above, so a finished-but-unclaimed task can pass and a claimed-but-broken one cannot. |
| `Cancelled`, `SandboxLost`, `PolicyAbort`, `ModelUnavailable` before any check | `Indeterminate { CouldNotRun }` |
| **Verification interrupted**: any stop, crash, cancel, verification-budget exhaustion or sandbox loss after verification started and before every planned check (reviewer included) has a report | `Indeterminate { CouldNotRun }`, never `verdict()` over the reports that did arrive (§7.3, "Completeness"; INV-34) |
| `JournalUnavailable` at any point after the header is durable, including the final `RunStopped` append | `Indeterminate { UnreadableEvidence }`. Verification does not start, or stops, because check reports that cannot be journaled cannot be audited (§7.1; INV-33). |
| Journal header cannot be written | the run refuses to start; nothing has executed: `Indeterminate { CouldNotRun }` |
| Task spec has no checks | `Indeterminate { NothingChecked }`, always, whatever the agent says (INV-18) |

The **sentinel** is the `task.submit` tool call (the analogue of mini-SWE-agent's `COMPLETE_TASK_AND_SUBMIT`, R1 §1.3). It carries a short deliverable note, which is untrusted. It only moves the run into the verification phase.

### 2.6 Loop detection (pure, in `harness-core`)

| Detector | Rule (defaults) | Action |
|---|---|---|
| Identical action | same `(tool, args digest)` 3 times within the last 6 steps | 1st hit: a harness notice in context. Any later hit of the **same key, in this burst or any later one**, is `Loop(Repeat)`: the notice is once per key per run, and episodes do not reset (burst rule, H1e-1) |
| Edit churn | more than 8 successful edits to one file | `Loop(EditChurn)` (R1 §1.7 "doom loops") |
| No progress | 10 steps with no new observation digest and no workspace tree-digest change | `Loop(NoProgress)` |
| Denial hammering | 3 policy denials of the same capability | `Loop(Denied)`, and the capability is removed from the active set for the rest of the run |

**Standing conditions are signalled once per state change** (R3 H-14). A detector notice fires once per detector state, not once per step. The same goes for `Quarantined`, `SandboxUnavailable` and a budget dimension crossing 80%: each is journaled once when the condition begins and once when it ends, with the count of affected attempts in between, not once per attempt. Turning these typed events into alerts (paging, dashboards) is out of scope: the harness is a library and a CLI. It emits the typed events through the journal and the embedding API, and a supervisor decides whom to tell (§11).

### 2.7 Repair policy

- **Format repair:** as in §2.2 step 4.
- **Verification repair:** if the checks fail and `repair_rounds > 0` (default 1, Aider's two-attempt protocol, R1 §1.4), the model receives a harness message containing the **visible** checks' diagnostics (untrusted), and the loop resumes on the remaining budget.
  Hidden checks contribute only "hidden check `<id>` failed", never content or source (the benchmark's repair mode shows diagnostics, never the oracle, R2 §5). After the last round the verdict stands.
- **Model retries** (transport errors) are separate from repair rounds and have their own budget (§3.2).

### 2.8 Per-run isolated state

```
<state_root>/                      # outside every workspace; 0700; read-denied to sandboxes (§6.4)
  runs/<run-id>/attempt-<n>/
    journal.jsonl                  # §7.1, single writer, exclusive lock
    blobs/<sha256>                 # content-addressed large payloads
    workspace/                     # agent-writable tree (fresh single-commit repo, §7.6)
    grading/                       # pristine grading worktree, rebuilt per verification
    scratch/                       # agent-writable temp
    snapshots/                     # tree-digest snapshots after each write step (path+digest, incl. empty dirs)
  index/                           # derived, rebuildable by scanning runs/; never authoritative
```

- **Run identity.** `run-id` is time-ordered and random (128 bits). `attempt-<n>` is a monotonic counter under that id. All output paths are derived from identity, so a relaunch cannot address an earlier attempt's directories (R3 H-12).
- **No shared database.** Concurrent runs share no writable state (R1 §2, R3 H-09).
- **Concurrency.** A semaphore per model endpoint limits parallel runs, default 1 for loopback endpoints (R3 H-10). Launches beyond the limit queue; they never storm the server.
- **Refusals.** A `state_root` inside a workspace is refused at startup. So is a `state_root` that is not **positively identified as a local filesystem**. The single-writer lock and the fsync durability of §7.1 do not hold reliably on network filesystems.

**Filesystem-locality check.** Split in two (see Changes since v0.2): a probe in `harness-sandbox` measures the filesystem (`LocalityProbe::query(path) -> FsQuery`), and the pure allowlist decision `harness_policy::locality::classify(&FsQuery) -> Result<LocalFs, LocalityRefused>` decides; `locality::check(probe, path)` runs both. It is an **allowlist**, not a network-FS denylist, so an unrecognised filesystem is refused rather than assumed local. It runs on the canonicalised `state_root` at startup and again on each new `attempt-<n>` directory, so a mount placed under `state_root` is caught:

| OS | Mechanism | Admitted | Refused |
|---|---|---|---|
| Linux | `statfs(2)` `f_type` via `rustix` (safe API) | a committed list of local magic numbers (ext4, xfs, btrfs, tmpfs, zfs, f2fs; overlayfs only when its `upperdir`, read from `/proc/self/mountinfo`, is itself on an admitted type) | everything else, explicitly including NFS, SMB/CIFS, 9p, Ceph and every FUSE filesystem (sshfs and similar are FUSE) |
| macOS | `statfs(2)`: the `MNT_LOCAL` flag **and** `f_fstypename` ∈ {`apfs`, `hfs`} (UNVERIFIED that `rustix` exposes both without `unsafe`; otherwise the call lives in an audited crate under §6.7's rules) | local APFS/HFS+ | no `MNT_LOCAL` (smbfs, nfs, afpfs, webdav), or any other type name |
| Windows | UNC and `\\?\UNC\` paths refused by shape before any call; then `GetVolumePathNameW` + `GetDriveTypeW` + `GetVolumeInformationW` in `harness-sandbox-windows` | `DRIVE_FIXED` with NTFS or ReFS | `DRIVE_REMOTE`, `DRIVE_REMOVABLE`, `DRIVE_UNKNOWN`, any other filesystem name, or a failed call |

A refusal happens before the journal header is written. The run does not start (`Indeterminate { CouldNotRun }`, exit 5), and the message names the detected type plus the fix: point `state_root` at a local disk. The default `state_root` sits in the user's local data directory, so an ordinary install never meets the refusal. There is no override flag. **Spike S-F1** confirms each OS's mechanism against a local, an SMB and an NFS mount in CI. Until S-F1 passes on an OS, that OS admits only the rows above, and a failed or unexpected query result is a refusal. What the check cannot see is named in §11 (a local filesystem on network block storage).

### 2.9 Replay

Inference is not deterministic even at temperature 0 (R1 §1.7), so **replay means re-feeding recorded model outputs**. A `ReplayBackend` implements `ModelBackend` from a journal. There are two modes:
- **audit:** tool results are also re-fed. The harness recomputes every context digest and every policy decision. Any divergence from the journal is reported as `Indeterminate { UnreadableEvidence }` with the first divergent step. This works because context building and policy are pure (§1.2).
- **reproduce:** tool calls re-execute in a fresh sandbox and workspace. Output digests are compared, and each difference is a finding. This is a diagnostic, never a verdict on the original run.

### 2.10 Resume

Resume opens a new attempt from the last fully journaled step: the chain is verified (§7.1), the
workspace is restored from that step's snapshot, and a trailing intent with no result is
re-decided, not re-executed blindly (policy re-runs; approval is re-asked where required).

Two further rules:
- **Verification is all-or-nothing across a resume.** Suppose the old attempt's journal holds a `VerificationStarted` with no matching `VerificationFinished` (a crash or kill mid-verification). Its check reports are never reused. The new attempt rebuilds the grading worktree and re-runs the **full** plan (§7.3). The adjacent window (`VerificationFinished` durable but `RunStopped` absent) is handled the same way: the new attempt re-runs the full plan, and reports are never reused across attempts, whatever state the old journal is in (review r65 L-02).
- **Resume after a journal failure** opens a new journal file for the new attempt; it never appends to the poisoned one. If the new journal's header cannot be written either, the resume refuses (`Indeterminate { CouldNotRun }`).

## 3. Model layer

### 3.1 The trait

```rust
pub trait ModelBackend {
    fn identity(&self) -> ModelIdentity;                        // recorded in the journal header
    async fn complete(&self, req: &ModelRequest, deadline: Instant) -> Result<Completion, ModelError>;
}
pub struct Completion { pub content: Untrusted<String>, pub tool_calls: Vec<Untrusted<RawToolCall>>,
                        pub finish: FinishReason /* Stop, ToolCalls; Length/absent => ModelError */,
                        pub usage: Usage /* measured or estimated */ }
```

Implementations: `OpenAiCompatible` (loopback HTTP by default), `Replay` (§2.9), `Scripted` (tests). Suite add-ons may add a mesh transport (§8). Nothing else in the harness knows which backend is in use.

### 3.2 The client

We write our own thin client for `/v1/chat/completions` and `/v1/models`, with SSE streaming. It is an HTTP/1.1 client over tokio, roughly 1-2k lines, with no hyper and no reqwest. Local-first needs no TLS, and every popular Rust LLM client pulls in C through TLS (R1 §5).

**Endpoint rules:**
- The default build connects only to loopback (`127.0.0.1`, `::1`, `localhost`) or to a unix-socket endpoint.
- Plain HTTP to any other address is **refused**, because prompts would cross the LAN in cleartext.
- Non-loopback endpoints need the `hosted` cargo feature (TLS: this is where rustls and its C provider enter, the "C tax", recorded in `deny.toml` review) plus per-run opt-in config, or a suite transport add-on.
- The hosted API key is held by the harness process, used only in the request header, and journaled as a handle name only (§5.5).

**Failure handling.** `finish_reason` is checked every time; `length`, an absent reason or an
empty body is a typed error, never an empty success (R1 §2, principle #12). 429 and 5xx retry with
exponential backoff and jitter under a retry budget (default 3 per turn), each attempt recorded
(R3 H-10). The fallback chain is configurable but **never crosses privacy classes**: a loopback
profile never falls back to a hosted one.

**Startup checks** fail closed with a plain-language fix (R1 §6): `/v1/models` must answer and
list the model; with `protocol = native`, a one-call tool-use smoke test runs, and on failure the
harness switches to the text protocol and journals it (a format choice, not a security one); for
llama.cpp, template and `--jinja` status come from the server's props endpoint (UNVERIFIED; S-P1).

### 3.3 Two action protocols

- **Native:** the OpenAI `tools` parameter carries the active tools' JSON Schemas, with `tool_choice: "required"` where the profile says it works (llama.cpp issue noted in R1 §6).
- **Text:** tool definitions are rendered into the system block. The model reasons in free text and emits exactly one block:

  ```
  <action>{"tool":"harness.fs.read","args":{"path":"src/lib.rs","start":1,"lines":100}}</action>
  ```

  Where the server supports it, **only the action block** is grammar-constrained, via a lazy grammar triggered by `<action>` and generated from the active tools' schemas. Reasoning stays unconstrained, because constraining it costs accuracy (R1 §6, "Let Me Speak Freely").
  Lazy-grammar availability through the OpenAI-compatible API is **UNVERIFIED** (spike S-P1). A server that cannot constrain is parsed without a grammar: safety never depends on the grammar, because validation is harness-side (§2.2 step 5); the grammar only buys reliability.

Action schemas are kept shallow: no `oneOf`, no recursion, and only the keywords `type`, `properties`, `required`, `enum`, `maxLength`, `minimum`/`maximum`, `items` and `additionalProperties: false`. Grammar engines cover JSON Schema unevenly (R1 §6, JSONSchemaBench). A manifest schema that uses other keywords is refused (§4.3).

### 3.4 Per-model profiles

A profile is a data file: `context_window`, `fill_ratio`, `protocol` (native or text),
`tool_choice_required_ok`, `grammar` (none, gbnf_lazy or json_schema), `max_active_tools` (5-8;
default 6 for models under 30B), `edit_format` (replace or whole), `recent_turns` K, sampling
defaults, a KV-quantization safety note, and a price table (hosted only).

**Rules:**
- An unknown model gets a conservative default profile: text protocol, 5 tools, replace edits, K = 4.
- `rustyharness profile check` runs a fixed smoke eval (tool-call validity, edit-format compliance, format-error rate) and stamps the profile with its result digest.
- An unvalidated profile runs, with `profile_validated: false` recorded in every journal header.
- rustybenchmark may generate profiles (R1 §9), but that is an input, not a dependency.

**Active tools.** The session's active set is the granted capabilities, capped at `max_active_tools`. If more are granted, the task spec must pick. v0.1 has no dynamic tool retrieval (§11 non-goals). R1 §1.7 reports that fewer tools help small models.

### 3.5 Model identity

`ModelIdentity` is written into the journal header and into every run report:
- endpoint class (loopback, LAN add-on, hosted);
- profile id and profile SHA-256;
- the user-declared weights digest, if given;
- sampling parameters.

The **server-claimed** fields are stored as `Untrusted` and labelled "claimed": model id, server software and version, and chat-template hash. A server can lie about what it serves, so identity is recorded as a claim plus what the harness controls. That is what a benchmark row key needs (R2 §5, rustybenchmark agentic board).

## 4. Tools and modularity

The owner's key question is: how do future apps slot in without the harness being redesigned? The answer:
- The core reasons only over **closed-set capability dimensions**, never over app names (`crates/harness-tools/src/lib.rs:63-76` already orders effect classes).
- Every provider declares its capabilities in a manifest that the harness verifies and pins.
- The wire is MCP, so any standard MCP server can be a provider.
- The manifest, not the server, is what policy trusts (R1 §4.4, R6 TH-3).

### 4.1 Capability manifest v1

The manifest is JSON (the scaffold's format). A detached `manifest.json.sig` is optional (§4.4).

| Field | Type / closed set | Rule | Justification |
|---|---|---|---|
| `schema_version` | integer, must be in the harness's supported set (v0.1: `{1}`) | mismatch refused, naming both versions | R5 §6.6 |
| `provider` | name `[a-z0-9_-]{1,64}` (the scaffold grammar, `crates/harness-tools/src/lib.rs:120-154`) | the namespace. Reserved names (a core constant plus additive config) refused (§4.3). Must be admitted (§4.4). | Renamed from `app`: providers are not only apps (ADR-0002) |
| `provider_version` | ≤ 32 bytes | recorded | scaffold |
| `min_harness` | SemVer | a harness older than this refuses | R1 §4.4 |
| `transport` | `builtin`, `mcp-stdio { argv, env_allow }` or `in-process { feature }` | `mcp-stdio` servers are spawned **confined**, only with `Conformed`; without it the session is refused (§4.5) | §4.5 |
| `mcp_protocols` | list of MCP protocol versions | highest common version chosen; none in common → refused | R1 §4.1 |
| `capabilities[].id` | `<provider>.<verb...>`, scaffold grammar, ≤ 128 | must be under the provider's own namespace | scaffold |
| `capabilities[].mcp_name` | string | the server's tool name mapped to this id (1:1, no fallback) | R5 §6.4: a binding that does not resolve fails the load |
| `capabilities[].summary` | ≤ 512 bytes, printable ASCII + UTF-8 letters, no control, zero-width or bidi characters | shown to **humans** in approvals | scaffold + R1 §3.3 |
| `capabilities[].effect` | `read` < `write` < `execute` < `irreversible` | unchanged ordinal | `crates/harness-tools/src/lib.rs:63-76` |
| `capabilities[].sensitivity` | `public` < `operational` < `personal` < `restricted` | what the result or effect touches | R5 §5.1: a `read` of personal data is not harmless |
| `capabilities[].blast_radius` | `own` < `host` < `shared` | `own` = the provider's own state; `host` = machine-wide; `shared` = state other people or machines rely on (remote repositories, published content, trust shared across machines) | R5 §5.2: a local config write and a trust rewrite must not share one policy |
| `capabilities[].egress` | `none` < `lan` < `internet` | whether invoking it sends data off-host | R5 §5.3: egress must be declared and measurable |
| `capabilities[].content` | `own` or `third_party` | whether results can carry text authored outside the user's control (web, messages, other people's files) | trifecta label (R1 §3.3, §4.4) |
| `capabilities[].confirmation` | `none` < `user_confirm` < `protected_action` | a floor, never a ceiling (max-rule) | R5 §5.4; rustyfin precedent (R2 §5) |
| `capabilities[].input_schema` | JSON Schema, the subset in §3.3, `additionalProperties: false` mandatory | refused otherwise | R2 (a)1: exact-argument validation |
| `capabilities[].schema_sha256` / `description_sha256` | hex | the server-presented schema and description must hash-match at connect time | rug-pull defence (R1 §4.1, §4.4) |
| `capabilities[].secrets` | list of secret **handle names** | resolved at the tool boundary (§5.5) | R1 §3.4 |
| `capabilities[].limits` | optional `{ timeout_ms, max_result_bytes }` | can only **tighten** the harness defaults | R2 §5 (rustyfin per-tool caps); max-rule keeps it safe |

Deliberately **not** fields: a free-form `risk_tier` (it would duplicate the ordered dimensions and invite contradictions, R5 §5.5) and a free-form `subject`/target. The closed `blast_radius` has no "third party" variant, so an action against someone else's systems cannot be declared at all (R5 §5.5, §6.2).

### 4.2 Effective class and the max-rule

`harness-policy` computes each capability's **effective** confirmation as the maximum of three things:

1. **The declared `confirmation`.**
2. **Derived floors:** `irreversible` or `shared` → `protected_action`; `egress = internet` or
   `sensitivity ≥ personal` → `user_confirm`; `execute` → requires `Conformed`.
3. **User policy** from the harness config.

A manifest can only make things **more** restrictive. A lying manifest that understates is bounded by the derived floors of its other fields. A manifest that lies on every field is a review problem, and §4.4's tiers limit what an unreviewed manifest may claim (R6 TH-4).

### 4.3 Validation (content, not presence)

Parsing refuses the following. Each has a test (R3 H-01, H-02):
- duplicate JSON keys, at any depth (F13);
- unknown fields (`deny_unknown_fields`, as today, `crates/harness-tools/src/lib.rs:39`);
- a schema version outside the supported set;
- reserved provider names, before any per-capability check (see "Reserved namespaces" below);
- ids outside the provider namespace;
- duplicate ids;
- an empty capability list;
- any `mcp_name` mapped twice;
- input schemas using keywords outside the subset, or missing `additionalProperties: false`;
- descriptions or summaries containing control, zero-width or bidi characters. These are **refused, not stripped**, because stripping would change the bytes that `description_sha256` pins.

**Reserved namespaces are a core constant** (R5 §6.3: "Reserved-ness is a core constant, not configuration"):

```rust
// harness-manifest
pub const RESERVED_NAMESPACES: &[&str] = &["harness", "rustyvault"];
```

- `harness` is the built-ins' namespace. Only the manifest compiled into the binary may use it.
- `rustyvault` is the suite's secret-custody service. No manifest may declare that namespace, whoever signs it. Secret custody reaches the harness only as a `SecretStore` add-on (§5.5, §8), never as a provider whose verbs could appear in an approval prompt an agent can trigger.
- The effective reserved set is `RESERVED_NAMESPACES ∪ config.extra_reserved`. User or add-on config may **add** names. It cannot remove one: the config field is an additive list, there is no syntax for removal, and the union is computed in `harness-manifest`, where the constant lives.
- Changing the constant is a code change to this repository, reviewed like any other. Today the scaffold refuses `rustyvault.*` ids only through the foreign-namespace rule (its test at `crates/harness-tools/src/lib.rs:245-249`). v1 refuses the provider **name** itself.

### 4.4 Trust tiers, admission, signing, pinning

**Admission.** A provider is usable only if the user's harness config (trust base, §6.4) lists it: namespace plus either a trusted signing key or a pinned manifest SHA-256. Anything not admitted is refused (R5 §6.5). Two admitted providers with the same namespace are refused (the shadowing defence, R1 §4.1).

**Tiers:**

| Tier | How admitted | May declare | Always |
|---|---|---|---|
| `builtin` | ships in the binary (`harness.*`) | anything; reviewed with the harness | subject to the same policy as any provider |
| `signed` | manifest signed (ed25519 over the exact file bytes) by a key in the user's `trusted_keys` | any dimension values | pinned hashes enforced |
| `pinned` | unsigned; the user approved this exact manifest SHA-256 via `rustyharness provider add` | `sensitivity ≤ operational`, `blast_radius ≤ host` | sandboxed, `confirmation ≥ user_confirm`, never in a session with `personal`/`restricted` capabilities (R1 §4.4) |

**Signing.** Signing keys belong to whoever publishes providers: a standalone user, a third party, or rustysuite for its apps. Who holds the suite's key is decided in the suite. The ed25519 implementation must pass the current `deny.toml` licence list unchanged (candidate `ed25519-compact`, MIT, pure Rust: UNVERIFIED). Widening the licence list is an owner-visible change.

**Pinning.** At connect time the harness compares `tools/list` against the manifest:
- a tool not in the manifest → dropped and journaled;
- a manifest tool the server lacks → unavailable;
- `description_sha256` or `schema_sha256` mismatch → the capability is **quarantined**. Invocations refuse until the user re-pins **outside the run** (`rustyharness provider repin`). A quarantine found mid-session re-runs the trifecta check (§5.4) (INV-7).

### 4.5 The adapter trait

```rust
pub trait ToolProvider {
    fn namespace(&self) -> &Namespace;
    async fn presented(&mut self) -> Result<Vec<PresentedTool>, ProviderError>; // what the provider claims (compared, never trusted)
    async fn invoke(&mut self, call: Journaled<Authorized<Call>>, ctx: &InvokeCtx) -> Result<ToolResult, ToolError>;
}
pub struct Authorized<C> { /* private; minted only by harness-policy::decide */ }
pub struct Journaled<C> { /* private; minted only by harness-journal::JournalWriter::append_intent after a durable append (§2.2 step 7) */ }
pub struct InvokeCtx<'a> { pub conformed: Option<&'a Conformed>, pub deadline: Instant, pub secrets: SecretHandles<'a>, pub step: StepId }
pub enum ToolStatus { Ok, Error { code: u16 }, Timeout, Crashed { signal: Option<i32> }, Refused { reason: RefusalKind } }
```

`Authorized<Call>` cannot be constructed outside `harness-policy`, and `Journaled<_>` cannot be constructed outside `harness-journal`. So no provider can be driven by an unvalidated call, or by one whose intent is not durably journaled. This is the same pattern as the scaffold's `require()` doc: "there is no API that runs a command without a [`Backend`] in hand" (`crates/harness-sandbox/src/lib.rs:48-49`).

**Three implementations:**
1. **builtin:** in-process Rust, `harness.*` (§4.8).
2. **mcp-stdio** (`harness-mcp`, over rmcp 3.4 with the stdio and child-process features, no compiled C per R1 §5). The server binary runs **inside the sandbox** under a `ConfinedSpec` derived from its manifest. Egress is granted only if some capability declares it, and then only through the proxy (§6.5). Its environment is `env_allow` only.
3. **in-process adapter:** a Rust crate behind a cargo feature, for trusted providers that need zero IPC. It still ships a manifest and is still policy-checked. The only thing it skips is process isolation, so it is allowed only for `builtin` or `signed` tiers.

**No `Conformed`, no provider process** (INV-6). `harness-mcp` starts an mcp-stdio server only through `Backend::spawn(spec, &Conformed)`. It has no other spawn path, and `McpProvider::connect(manifest, &Conformed)` cannot be called without the token. At session planning (§2.1), if the task grants any capability of an mcp-stdio provider and `require()` fails, the **session is refused** before anything starts. The refusal is typed and names the provider, the outcome is `Indeterminate { UnsupportedOs }` or `{ CouldNotRun }` per §6.1, and the exit code is 3. The provider is never started unconfined, never run in-process instead, and never silently dropped from a task that asked for it. The same rule covers an in-process adapter that declares **any** execute-class capability: its crate code runs in the harness process, so without `Conformed` the whole provider is not loaded, not just that capability. The harness's own unconfined children are limited to the `__confine` helper (§6.3), argv-only git over harness-built trees with hooks disabled (§7.6), and, on macOS, three read-only system queries run by absolute path with a fixed argv through a bounded capture (cleared environment with `LC_ALL=C`, stdin null, capped output, a deadline): `/sbin/mount` for the locality probe (§2.8) and `/usr/sbin/sysctl` and `/usr/bin/vm_stat` for the environment sample (§7.1). No payload reaches any of them (INV-23).

Remote MCP over Streamable HTTP is feature `mcp-http`, off, and not in v0.1 (it needs TLS; §11).

### 4.6 MCP mapping

MCP is the wire, and the manifest is the trust root (R1 §4.4; R6 TH-3):
- The model sees tool **descriptions only when their hash matches the pin**, and **names only as manifest ids** (`provider.verb`). Server tool names are internal.
- MCP annotations such as `readOnlyHint` are ignored for policy. The spec itself calls them untrusted (R1 §4.1).
- MCP features the harness does not use are refused at negotiation and never served: sampling, elicitation to the model, and resources the manifest does not declare. A server that asks the host to run the model (sampling) gets an error. That would be a channel from provider content into model output with no policy.
- Any suite-specific metadata travels in MCP's sanctioned `_meta` namespace, so suite servers remain valid MCP servers for any client (R1 §4.4 item 6).

### 4.7 Versioning and negotiation

- **Manifest schema:** the harness declares a supported set. A manifest names exactly one version. Any change to the manifest schema is a version bump, never a relaxed `deny_unknown_fields` (R5 §9: relaxing turns a new `sensitivity: restricted` into a silent `read`). A newer harness may support `{1, 2}`; an older one refuses v2 with a message naming both versions.
- **MCP protocol:** negotiated per request by rmcp. The harness refuses any version not listed in `mcp_protocols`.
- **Action protocol (§3.3):** versioned in the system block (`protocol: rh-action/1`). A reply in another dialect is a format error.

### 4.8 Built-in tools

The built-in tools are themselves declared by a `harness` manifest. They take the same policy path with no special cases, and they exist only when the task grants a workspace (R4 §4 item 1: grants are per task, deny by default).

| Id | Effect / sensitivity / blast / egress | Behaviour |
|---|---|---|
| `harness.fs.read` | read / operational / own / none | Path inside the workspace plus a line window (default 100 lines, R1 §1.2). Returns content + SHA-256 + total lines. Records the read hash (§2.3). |
| `harness.fs.search` | read / operational / own / none | Regex over the workspace (pure-Rust `regex` + `ignore`, UNVERIFIED C-free until `cargo tree`). At most 50 hits, summarised per file (R1 §1.2). |
| `harness.fs.list` | read / operational / own / none | Directory listing, bounded depth and count |
| `harness.edit.replace` | write / operational / own / none | §4.9 |
| `harness.edit.write` | write / operational / own / none | Whole file. Creating: must not exist. Overwriting: must have been read in this run and be ≤ 400 lines (R1 §1.5). |
| `harness.exec.run` | execute / operational / own / none | argv vector plus working directory inside the workspace. Program resolved against the task's **exec allowlist** (absolute paths pinned, like Codex `host_executable`, R1 §3.1). stdin null. Timeout. Runs only under `Conformed`. |
| `harness.notes.write` | write / public / own / none | Replaces the agent's notes (2k-token cap). Content is `Untrusted(Model)`. |
| `harness.task.submit` | write / public / own / none | The sentinel (§2.5) |

**Exec allowlist.**
- Shells (`sh`, `bash`, `zsh`, `cmd`, `powershell`, `pwsh`) are **not** in any default allowlist. Adding one is explicit user config, and it stamps `shell_enabled: true` in the journal header.
- Even then, the sandbox is the control, not the argv validator: a build script is arbitrary code whatever the argv says (R4 §3).
- The allowlist supports Codex-style prefix rules with `match`/`not_match` examples, checked as unit tests when the config loads (R1 §3.1).

**File-operation confinement:**
- In sessions **with** any execute-class grant, built-in file tools run through the confined file-op helper under the same backend (§6.1). An agent-created symlink cannot make the unconfined harness process read outside the workspace; the kernel enforces the view.
- In sessions **without** execute grants (H1, and Windows before W1), the harness reads in-process. The workspace was materialised by the harness with outward symlinks refused, and nothing in the session can create new ones (INV-30).

### 4.9 Edit format and verification

`harness.edit.replace { path, old, new, count = 1 }` works like this:

1. **Preconditions:**
   - the path is inside the workspace and not protected (§7.6);
   - the file was read in this run, and its current hash equals the last-read hash (else the stale-read refusal, §2.3);
   - `old != new`;
   - `old` is not empty.
2. **Match:** exact bytes. The number of matches must equal `count`.
   - Zero matches → an error with the nearest matching line numbers, plus a line-ending hint when the file uses CRLF and `old` uses LF.
   - More matches than expected → an error listing the match line numbers.
   - Either way nothing changes (R1 §1.5: exact-unique str_replace had the "highest reliability").
3. **Apply in-process:** write to a temporary file in the same directory, fsync, then rename (atomic). Permissions and line endings are preserved.
4. **Verify after applying:** re-read the file. The SHA-256 must equal the in-memory expected splice **and** differ from the pre-edit hash, or the edit is reported as failed. This check exists because of the silent no-op class (`git apply` in a subdirectory exiting 0, R1 §2; R3 C2).
5. **Journal:** before and after digests, plus the tree snapshot (§2.8).
6. **Optional syntax check:** a per-language check from the task's `post_edit` list (e.g. `rustfmt --check <file>`), run in the sandbox. A failure rolls the edit back and is returned as the observation (SWE-agent's lint-guarded edit, +3 pp, R1 §1.2).

There is **no** `git apply`, no unified-diff format and no shell-out for edits in v0.1 (R1 §1.5, §8 #7). The format is chosen per profile between `replace` and `whole`.

### 4.10 How a provider adds itself (no core change)

1. The provider author writes `manifest.json` (§4.1) and an MCP stdio server, or an in-process adapter crate.
2. The user runs `rustyharness provider add <dir>`. The harness validates the manifest (§4.3) and shows a plain-language table of every capability with its effective class (§4.2). Adding the provider requires the user's explicit yes. The harness then records the admission (namespace + key or pin) in the user config, **outside any run** (the trust base, §6.4).
3. Task specs grant capabilities by id. Policy, confinement, the trifecta rule and journaling apply automatically from the dimensions.

**The test that proves it** (INV-31): a fixture provider with verbs and a namespace unknown to the harness codebase integrates end to end in CI (admit → grant → invoke → journal → policy). The CI job asserts that `git diff` over `crates/` is empty.

rustysuite apps are one set of such providers. Their manifests and servers ship with the apps or with the suite add-on, not in this repository.

## 5. Policy and approval

### 5.1 Decision order

`decide(call, effective_class, session, user_policy) -> PolicyDecision { Allow | Ask(Tier) | Deny(Reason) }` is pure, and every decision carries the id of the rule that produced it. The evaluation order is:

1. **Deny rules** (user policy, session trifecta, quarantine, missing `Conformed` for execute): first match wins and **cannot be overridden** by any later rule, flag or approval (R1 §3.4).
2. **Ask rules** (effective confirmation ≥ `user_confirm`).
3. **Allow rules.**
4. **Default: Deny.**

### 5.2 Default policy

| Effective class | Default |
|---|---|
| `read`, sensitivity ≤ operational, content `own` | allow |
| `read`, content `third_party` | allow; the result is `Untrusted` like everything else, and the session is labelled "untrusted" for the trifecta |
| sensitivity `personal` | ask (`user_confirm`), and only if the session was granted personal data; result caps apply |
| sensitivity `restricted` | **deny**. No v0.1 session may hold restricted capabilities (Q3; ADR-0002 item 3). |
| `write`, blast `own`, built-in workspace edits | allow: the sandbox plus snapshots make them undoable, and fewer prompts is safer (R1 §3.4, −84% prompts) |
| `write`, provider-declared | ask (`user_confirm`) unless user policy allows |
| `execute` | allow only with `Conformed`, else deny (INV-6) |
| any capability of an mcp-stdio provider, or of an in-process adapter declaring any execute-class capability | only with `Conformed`, else the session is refused at planning (§4.5, INV-6) |
| egress `lan`/`internet` | ask; plus the trifecta check; plus the proxy (§6.5) |
| `irreversible` or blast `shared` | **ask every time** (`protected_action`); never cached, never scoped to the run |
| **no approver present** (non-interactive, CI, embedded without a UI) | every Ask becomes Deny |

These defaults answer OPEN-QUESTIONS item 9 (where the admin assistant ends): irreversible or shared-scope operations are **never** automatic. What is otherwise automatic follows the table.

### 5.3 Approval flow and tokens

When the decision is Ask, `harness-run` sends an `ApprovalRequest` to the configured approver: the CLI prompt, or an embedding UI through the `harness-run` API. The request shows:
- the capability `summary`;
- its effective class **in plain words** (e.g. "will send data to the internet", "cannot be undone");
- the rendered arguments, escaped;
- the step.

The approver answers yes or no. A yes mints:

```rust
struct Approval { run: RunId, attempt: u32, step: StepId, capability: CapId, args_sha256: [u8; 32],
                  tier: Tier, expires_at: Mono, nonce: [u8; 16], approver: PrincipalId, mac: [u8; 32] }
```

The pattern is lifted from rustyfin (clean-room, no code dependency; answers OPEN-QUESTIONS 14): a confirmation token bound to user, session, tool, argument hash and expiry, 15-minute TTL (R2 §5).

**Token rules:**
- The `mac` is an HMAC under a per-run key held only in harness memory, so a token forged on disk or in context is worthless. Tokens never enter model context.
- **Binding:** a different step, capability or argument digest, an expired token, or a reused nonce is refused. Consumed nonces are journaled, so reuse is detectable in replay (INV-16).
- **Tiers:** `protected_action` tokens are single-use. A `user_confirm` approval may be marked by the approver "for identical calls in this run", which covers the same capability with the same argument digest only; the scope is recorded.
- A pending approval that times out is a **Deny** (fail-closed), never an auto-approve.
- The denial reason goes back to the model as an observation.

### 5.4 The trifecta rule

At session start, and again whenever the active set changes (quarantine, capability removal), `harness-policy` computes three labels over the active set **plus the workspace**:
- **P (private):** any capability with sensitivity ≥ `personal`, **or** the workspace. Workspaces are private by default. The user may declare a workspace `public` in the task spec.
- **U (untrusted):** any capability with content `third_party`, **or** the workspace. Workspace content is third-party by default: repositories contain other people's text.
- **E (egress):** any capability with egress ≠ `none`, including MCP servers granted proxy egress.

**P ∧ U ∧ E ⇒ the session is refused**, with a typed error naming one capability per label. v0.1 has no override (INV-9).

Consequences:
- A default coding session has **no egress**. Builds are offline with vendored dependencies (the benchmark's `--offline --locked` precedent, R2 §5).
- Web research is a separate session with no private workspace. Its output is handed to the human, not piped into a private session.
- A plan-then-execute or dual-LLM path, which would allow some combinations (CaMeL, R1 §3.3), is future work (Q7).

**Hosted models** are handled as a disclosure rule, not a trifecta label. The provider is not attacker-readable, but everything in context goes to it. A hosted profile may be used only if the session's maximum sensitivity is ≤ `operational`, unless the user's config opts a specific sensitivity in (Q2). `restricted` never goes to a hosted model.

**The loopback model server is outside the trifecta computation.** The whole context goes to it every turn. The E label counts only capability egress, so the P ∧ U ∧ E guarantee **assumes** the model server process has no egress of its own. The harness cannot measure or constrain that: the server is a user process the harness neither starts nor confines, and it is part of the user's trust base. The harness does three things. It records the endpoint class and the server's claims in `ModelIdentity` (§3.5). It never gives a sandbox a route to the server (§6.5). It names this as a residual (§11). It claims no more.

### 5.5 Secrets

- **Never in context:** no secret value is rendered into a prompt. Capabilities name **handles** (`secrets: ["github_token"]`). The harness resolves them at invoke time and hands them to the provider process only, through its environment or a descriptor, per `transport`. They never reach the model (R1 §3.4, §8 #17).
- **Never in child environments by default:** children get a built environment, not an inherited one. It contains an allowlist (`PATH` = pinned toolchain dirs, `HOME` = scratch, `TMPDIR`, `LANG`, toolchain variables the task declares) plus only the handles their capability declares (R3 H-07).
- **Detective redaction:** tool outputs are scanned for the exact bytes of every secret resolved in this run, plus planted canaries, before they become observations. A hit is replaced and journaled as an event. Redaction is labelled **detective-only** (R3 H-16); the preventive controls are the two rules above.
- **Secret stores:** one `SecretStore` trait. Built-in `FileStore` (mode 0600 in the harness config directory, read-denied to every sandbox, §6.4) is always available; built-in `KeychainStore` (macOS Keychain, Windows Credential Manager, Linux Secret Service) is optional, pending spike S-K1 on C-freedom of the per-OS crates (UNVERIFIED); add-on stores such as a suite secret-custody client (§8) are off by default, and whether the suite ever enables one is decided in the suite.
- **Model API key:** read by the harness process from the store at startup, used only in HTTP headers, and never journaled (a handle name only).

## 6. Confinement

### 6.1 Fail-closed trait with evidence-gated availability

```rust
pub struct Conformed { /* private */ backend: BackendKind, matrix_row: &'static str, probe_digest: Digest }
pub trait Backend {
    fn probe(&self) -> Result<Conformed, Unavailable>;          // the ONLY mint of Conformed
    fn spawn(&self, spec: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError>;
}
pub enum Containment { Available(Conformed), Unavailable(Unavailable) }
pub fn require() -> Result<Conformed, Refused>;                  // every exec path goes through here
```

`probe()` mints `Conformed` only if **both** of the following hold (scaffold review F5):
1. **CI conformance:** the committed pass matrix (`harness-conformance`, §6.6) says this backend on this OS family passed the **full** hostile-task suite in CI at this harness version. The matrix is compiled into the binary as a constant.
2. **Live self-probe:** a fast subset of the suite runs on this host now and every probe is **refused**:
   - network connect;
   - write outside the workspace;
   - read of a planted home canary;
   - env canary absent;
   - launching a process outside the sandbox.

   This catches hosts where a kernel feature is off, a sysctl differs, or the OS removed a primitive.

If either fails, the result is `Unavailable` with a typed reason and a plain-language fix. The run then continues read-only, or refuses if the task needs execution. There is no degraded or "run it anyway" tier: a weaker combination is acceptable only if it passes the same full suite, in which case it is simply another backend (R3 H-05, INV-6, INV-15).

`Unavailable` maps to `Indeterminate { UnsupportedOs }` when no backend exists for the platform, and to `Indeterminate { CouldNotRun }` when a backend exists but failed on this host (UNIFIED kinds; R4 §3).

### 6.2 What a confined child gets

`ConfinedSpec` holds: `argv` (a vector, never a shell string); `cwd` inside the workspace; `env`
(built, §5.5); `read_only` roots (toolchains, base tree); `read_write` roots (workspace, scratch);
`protected` read-only overlays inside the workspace (§7.6); `network` (`None` or
`Proxy(allowlist id)`); `limits` (wall, CPU, memory, processes, file size); stdin null.

Everything not granted is denied. That always includes the user's **home directory** (only
explicitly granted subpaths, such as a toolchain directory, are readable), `state_root`, the harness
config and trust base, other runs' directories, and OS credential stores.

### 6.3 Per-OS backends

The design commits to **the conformance suite, not to a primitive**. The primitives below are the chosen first attempt; a spike that fails swaps the primitive, never the bar.

| OS | Backend (decided first attempt) | Rationale | Spike (exit = full §6.6 suite green in CI) |
|---|---|---|---|
| Linux | `LinuxNs`: the harness re-execs itself as a helper (`rustyharness __confine`; spec passed over an inherited pipe, never argv). The helper does:<br>1. `unshare` user, mount, net, pid, ipc, uts namespaces;<br>2. builds a minimal root (tmpfs + read-only binds of system and toolchain paths + read-write binds of workspace and scratch + read-only re-binds of protected paths); home is **not mounted**;<br>3. `pivot_root`;<br>4. Landlock ruleset with the same allowlists (defence in depth);<br>5. rlimits (plus cgroup v2 limits if a delegated subtree exists);<br>6. a seccomp deny set (namespace creation, `mount`, `ptrace`, `bpf`, `keyctl`, `kexec_*`, module loading, `perf_event_open`, `userfaultfd`), applied last;<br>7. exec.<br>The PID namespace gives whole-tree kill. | No bubblewrap binary (external C, R1 §3.2). The empty netns plus an absent home mount cover Codex's objection that Landlock alone cannot isolate unix sockets (R1 §3.1): abstract sockets are per-netns, and path sockets outside the mount view do not exist. Crates: `landlock`, `seccompiler` (pure Rust, R1 §5), `nix` or `rustix`. Whether all of this is reachable without `unsafe` is **UNVERIFIED**. | **S-L1:** helper on stock Ubuntu LTS, Debian, Fedora; also measure `sandlock-core` 0.8.8 as an alternative (R1 §5). Hosts with unprivileged user namespaces disabled → `Unavailable` with a fix message; no fallback. |
| macOS | `Seatbelt`: `/usr/bin/sandbox-exec` (absolute path) with a generated profile file in a harness-private temp dir. The profile is **`(deny default)`** with explicit allows: process-exec of allowlisted toolchain paths, file-read of system and toolchain paths plus the workspace, file-write of workspace, scratch and temp, the minimal mach services the toolchain needs, and network only to the proxy endpoint when granted. `$HOME` is denied except granted subpaths. | An `(allow default)` profile, the benchmark's current shape, leaves mach and LaunchServices channels open; launching an app outside the sandbox via `open` is the class we must refuse (UNVERIFIED as an exploit here; FT-17 is the witness). Deny-default is the shape Claude Code and Codex are reported to use (UNVERIFIED). | **S-M1:** derive the minimal allow set for cargo/rustc, python and node toolchains; FT-17 and FT-18 must refuse. If Apple removes `sandbox-exec`, `probe()` fails and macOS execution refuses until an exit path lands (Q8). |
| Windows | `WinAppContainer`: a per-run AppContainer profile with **no** network capabilities; ACL grants for workspace, scratch and toolchain (read); a Job Object with `KILL_ON_JOB_CLOSE`, an active-process limit and a memory limit; the process is created with the job attached. | AppContainer is kernel-enforced and default-deny for files, registry and network. A Job Object is **not** a boundary, only the resource and tree-kill half (R4 §2 C5). Codex judged AppContainer insufficient for developer workflows (R1 §3.1); the named fallback is a Codex-style write-restricted token + ACLs. | **S-W1:** cargo/rustc inside AppContainer with workspace + toolchain ACLs; if it fails, try the restricted-token fallback; if both fail, Windows ships **without execution** (read-only sessions work). **S-W2:** proxy reachability from AppContainer (loopback needs an exemption, UNVERIFIED); until it passes, Windows sessions get no egress. |

**Shared with rustybenchmark (reopened by the owner, 2026-09-24, OD-4).** The benchmark's grading sandbox needs the same contract. v0.2 proposed this backend family (`harness-sandbox` + `harness-conformance`, same author, same licence under ADR-0003) as the shared crate the benchmark depends on. The owner's position: the benchmark's grading sandbox stays its own, and confinement code is shared only through a standalone crate outside both projects, or not at all; which is open (OPEN-QUESTIONS, Still open 4). The harness takes no dependency on the benchmark's crates either way.

### 6.4 The trust base is outside the agent's reach

The **trust base** is the harness config (policy, admitted providers, trusted keys, exec
allowlists), provider manifests, the MCP server list and binaries, hooks (none in v0.1), the task
spec, the verification plan and hidden checks, `state_root` (journals, snapshots, blobs; the
approval key never touches disk) and the harness binary itself.

None of these paths is mounted or granted in any `ConfinedSpec`, not even for reading. Inside the workspace, the **protected paths** of the verification plan (`.git`, tests-under-evaluation, gate scripts, CI config, lockfiles, `deny.toml` and whatever the task declares) are read-only overlays (§7.6).

Changes to the trust base happen only through `rustyharness` subcommands run by the user outside any run, never through a tool. Config-write-as-RCE is the reason (CVE-2025-53773, CVE-2025-54135, R1 §3.3; INV-12).

### 6.5 Network: allowlist proxy outside the sandbox

The default is **no network** inside any sandbox: empty netns, Seatbelt `(deny network*)`, no AppContainer network capability. When a session has an egress-granted capability (after the trifecta check, §5.4), the harness starts `harness-sandbox::egress`, an HTTP CONNECT and HTTP proxy **in the harness process**, outside the sandbox (R1 §3.1).

**Proxy rules:** an exact host allowlist from the task grant (`*` refused); DNS resolved by the
proxy, and loopback, private, link-local and ULA destinations refused, including hostnames that
*resolve* to them (connect to the resolved address, no re-resolution); a journal event per request
(host, port, bytes each way, decision); empty allowlist ⇒ everything refused (R1 §3.1).

**Reaching the proxy:**
- Linux: the proxy listens on a unix socket bind-mounted into the sandbox, and a tiny forwarder in the helper exposes it as `127.0.0.1:<port>` inside the netns (`HTTP(S)_PROXY` set).
- macOS: the profile allows outbound only to the proxy's loopback port (SBPL syntax UNVERIFIED, S-M1).
- Windows: S-W2.

The model server is **not** reachable from any sandbox. Model calls are made by the harness process (the benchmark's precedent, R2 §5).

### 6.6 The hostile-task conformance suite

`harness-conformance` holds the corpus **as data**: tiny projects plus the expected refusal observations. It runs through the same `spawn` seam as real tools. Tasks FT-1..FT-8 generalise the benchmark sandbox's escape set so both sandboxes can share one corpus; FT-9 onward are harness-specific.

| # | Hostile task | Must observe (behaviour, not a printed string) |
|---|---|---|
| FT-1 | test binary opens TCP to a routable address | connect fails; no packet leaves (checked outside) |
| FT-2 | build script opens the same socket | build-time code is equally confined |
| FT-3 | write to `$HOME/canary` and to a sibling run dir | both fail; files absent afterwards |
| FT-4 | read a planted `~/.ssh`-shaped canary; probe env for a planted secret | read denied; variable absent |
| FT-5 | bounded fork bomb | killed by limit; host survives; no orphans afterwards |
| FT-6 | memory bomb | killed by limit; host survives |
| FT-7 | disk fill in workspace | killed by file-size cap |
| FT-8 | busy loop | killed at wall clock by the harness |
| FT-9 | write to a protected path (test file, `.git/config`) | denied; digest unchanged |
| FT-10 | read or write the harness config, `state_root` or journal | denied (not even readable) |
| FT-11 | connect to a planted unix socket listener outside the workspace | fails |
| FT-12 | symlink in workspace pointing outside, followed by a built-in file tool and by `exec` | both denied (the kernel view, §4.8) |
| FT-13 | direct connect to an allowlisted host's IP, bypassing the proxy | fails; only proxy traffic succeeds |
| FT-14 | proxy request to a hostname resolving to a private address | refused by the proxy; journaled |
| FT-15 | DNS lookup of a planted name (DNS exfiltration) | no resolver reachable |
| FT-16 | orphan: child double-forks and ignores SIGTERM | gone after the kill (PID ns / Job Object / group kill) |
| FT-17 | macOS: launch an app outside the sandbox via LaunchServices (`open`) | refused |
| FT-18 | macOS: mach-lookup of keychain or pasteboard services; Linux: keyring syscalls; Windows: Credential Manager read | refused |

**CI:** each OS runner executes the full suite against its native backend. The resulting per-OS matrix row is committed; a backend without a passing row cannot mint `Conformed` (§6.1).

### 6.7 `unsafe` isolation

The workspace forbids `unsafe` (`Cargo.toml:21`). `harness-sandbox-windows` is the one planned exception, because every Win32 call through the `windows` crate is `unsafe`. It opts out of the workspace lint to `deny(unsafe_code)`; each site needs `#[allow]` plus a
`// SAFETY:` justification; a CI gate counts the sites (a ratchet: the count may only fall without
review); and only `harness-sandbox` may depend on it.

If S-L1 shows that Linux needs `unsafe` (e.g. `pre_exec` rather than the helper re-exec), the same pattern applies with a `harness-sandbox-linux` crate. The helper design exists to avoid that.

## 7. Evidence and journal

### 7.1 The journal

**Format.** One `journal.jsonl` per attempt. Each line is:

```json
{"seq":N, "prev":"<sha256 of line N-1>", "t_mono_ms":..., "t_wall":"...", "run":"...", "attempt":n, "step":k, "kind":"...", "body":{...}, "hash":"<sha256(prev||canonical(line without hash))>"}
```

**Header (line 0):** harness version; config, policy and manifest SHA-256s; `ModelIdentity`
(§3.5) and profile hash; sandbox backend, matrix row and probe digest; OS; `shell_enabled`;
protected-path digests; verification plan digest; and an **environment sample**. This header is what makes a trajectory comparable, so harness regressions stay visible between releases (R1 §2, principle #13).

**Environment sample** (R3 H-17: environment is data, and environmental failures stay distinct). Each sample records:
- CPU count and the 1-minute load average;
- memory total and memory available;
- free bytes on the `state_root` volume;
- for each field, its **producing method** (e.g. `/proc/loadavg`, `/proc/meminfo`, `sysctl vm.loadavg`, `GlobalMemoryStatusEx`).

When to sample:
- in the header;
- at `VerificationStarted`;
- on every `ToolFinished` or `CheckReported` whose status is `Timeout`, `Crashed` or `CouldNotRun`.

A field the platform cannot supply through a safe API is recorded as `unmeasured` with the reason, never as zero. Windows sampling lives in `harness-sandbox-windows` (§6.7), or the field is `unmeasured`. The sample never changes an outcome. When a `CouldNotRun` or `Timeout` coincides with memory available under 5% or load above twice the CPU count, the run report adds an `Info` finding `possibly-environmental`. A human can then tell host pressure from a broken check without re-running.

**Type-level append-only (F11).** `JournalWriter` owns the file (opened for append, with an exclusive advisory lock, single writer). Its only operations are `append(Event) -> Result<Seq, JournalError>` and `append_intent(Event, C) -> Result<Journaled<C>, JournalError>`. There is no seek, truncate, remove or rewrite in its API. `JournalReader` is a separate type that verifies the chain on open.

**Detection and durability.** A mutated or reordered middle line fails verification
(`UnreadableEvidence`, INV-11); a torn final line (a crash) is reported as such and resume starts
from the last good line (§2.10). The writer fsyncs after every intent event (before execution, §2.2 step 7), after every result event, and after `VerificationStarted`, each `CheckReported`, `VerificationFinished` and `RunStopped`.

**Write failure (fail-closed; INV-33).** A run whose evidence cannot be recorded can neither proceed nor pass:
- **What counts as failure.** Any `Err` from a write or an fsync (disk full, EIO, a read-only remount, an error taking the exclusive lock), a short write, or a writer whose in-memory `seq` and chain head no longer match what it last made durable.
- **Poisoning.** On any failure, `JournalWriter` becomes **poisoned**, and every later `append` returns `Err` without touching the file. A failed fsync is never retried on the same file, because the page-cache state after a failed fsync is not portable to rely on.
- **No execution.** A poisoned writer mints no `Journaled` value, so no provider can be invoked (§2.2 step 7, §4.5).
- **No egress.** The egress proxy appends its per-request `Egress` event **before** forwarding. If that append fails, the request is refused.
- **The run stops.** `harness-run` checks the poison flag before every step and before every check. It stops with `StopCause::JournalUnavailable`, and the outcome is `Indeterminate { UnreadableEvidence }` (§2.5). Verification does not start, or stops where it is.
- **Commit point.** The run's outcome is released only after `RunStopped` (carrying that outcome) is appended and fsynced. The order is: `RunStopped` durable, then the last stdout line (the `GateReport`), then the `GATE_OK_FILE` marker (only for `Passed`), then exit. If the `RunStopped` append fails, `harness-run` replaces whatever `verdict()` returned with `Indeterminate { UnreadableEvidence }`. Downgrading needs no witness; only `Passed` does. It writes no marker and exits 5. A `Passed` outcome therefore exists only for a run whose whole record is durable. If the stdout write or the marker write fails after a durable `Passed` `RunStopped`, the process exits 5, never 0: the CLI never gives a green exit without the marker it promised (review r65 L-01).
- **Where the failure is reported.** It goes to stderr and to the run report. It cannot go to the broken journal.
- **Testing.** `JournalWriter` is generic over a small `JournalFile` seam (`write_all`, `sync_data`). The real implementation wraps `std::fs::File`, and the fault-injecting implementation used by INV-33 fails the Nth write or fsync.

**Anchoring.** The final chain head is printed in the run report. Detecting wholesale replacement of a journal needs that head recorded elsewhere. In the suite, it goes into the suite's own evidence records (§8); standalone, it is the user's to keep (residual).

**Untrusted payload home.** Any body that carries outside content uses:

```rust
struct UntrustedBlob { source: Source, sha256: Digest, len: u64, inline: Option<String /* ≤ 4 KiB, escaped */>, blob: Option<BlobRef> }
```

The JSON form carries `"untrusted": true`. Display paths escape control, bidi and ANSI sequences, so a journal viewer is not an injection sink (the scaffold's "logs are a sink too", `crates/harness-core/src/lib.rs:67-74`).

### 7.2 Event schema

| Kind | Body (untrusted parts in *italics*) |
|---|---|
| `RunStarted` | header fields (above) |
| `ContextBuilt` | context digest, token estimate, included pointer ids, dropped blocks |
| `ModelRequested` / `ModelReplied` | request digest; *content*, *raw tool calls*, finish reason, usage (measured/estimated), retry attempts |
| `ActionParsed` / `FormatError` | tool id, args digest, *args*; parse error |
| `PolicyDecided` | call digest, effective class, decision, rule id |
| `ApprovalRequested` / `ApprovalGranted` / `ApprovalDenied` / `ApprovalExpired` | capability, args digest, tier, approver id, nonce (never the MAC) |
| `ToolStarted` / `ToolFinished` | capability, `ToolStatus`, *output*, digest, truncated, duration |
| `EditApplied` | path, before and after digests, snapshot id |
| `Egress` | host, port, bytes, decision |
| `Redacted` | which handle or canary matched (never the value), location |
| `Quarantined` / `SandboxUnavailable` | capability and drift kind; typed reason (journaled on entry and exit of the condition, §2.6) |
| `LoopDetected` / `BudgetCharged` | detector; dimension, spent, limit (charged per step, aggregated) |
| `SubmitRequested` | *deliverable note* |
| `VerificationStarted` / `VerificationFinished` | plan digest, the ordered planned check ids (reviewer slot included), diff blob ref and digest, environment sample; `Finished` carries the report count and whether the plan is complete |
| `CheckReported` | `GateReport` per check (JSON per `gate-outcome`), keyed by planned check id |
| `ReviewerRefused` | attempt index, candidate profile id, reason (e.g. `SameIdentity`) |
| `ReviewReported` | reviewer run id, reviewer `ModelIdentity`, `GateReport` |
| `RunStopped` | `StopCause`, the run's `GateOutcome`, deliverable digest, chain head |

### 7.3 How verdicts are extracted

The **verification plan** (task spec, trust base) is a list of checks. Each check is an argv plus metadata:
- `visible` or `hidden`;
- `protocol`: `unified` or a built-in adapter id;
- a timeout.

**Where checks run.** The harness runs each check itself, in the sandbox, against the **pristine grading worktree** (§7.6) with `Stdio::null()` stdin, and captures exit status and stdout directly, with no pipeline in the measurement path (R3 H-03). The captured run goes to `gate_outcome::child::interpret`, which applies UNIFIED §6 verbatim:

| Child behaviour | `GateReport` |
|---|---|
| last stdout line parses as a JSON `GateReport` | that report |
| last line looks like a report but does not parse | `Indeterminate { UnreadableEvidence }` |
| exit 0 **and** success marker written to the per-check `GATE_OK_FILE` | `Passed(Witness)` (minted inside `gate-outcome`) |
| exit 0 **without** marker | `Indeterminate { NothingChecked }`, never a pass |
| exit 1 | `Failed` + a synthesized `Blocking` finding |
| any other exit, signal, timeout, missing program | `Indeterminate { CouldNotRun }` |
| no conformed sandbox for the check | `Indeterminate { UnsupportedOs }` or `{ CouldNotRun }` (§6.1) |

Clarifications of this table (recorded during H1; `gate-outcome` implements them):
- **Run-level facts first.** A timeout or a signal is `CouldNotRun` even when the last line is a well-formed passing report.
- **Gate id.** A report whose `gate` differs from the check the harness launched is `Indeterminate { UnreadableEvidence }`: contradictory evidence, never re-attributed.
- **Wire form.** The report line is exactly the JSON that `GateReport`'s `Serialize` writes. Unknown fields at any level are refused (`UnreadableEvidence`). The parent re-checks the report laws and INV-18 (`checked: 0` gives `NothingChecked`) and never upgrades a declared non-pass.
- **Exit agreement.** A declared `Passed` needs exit 0 and a declared `Failed` needs exit 1. A declared `Indeterminate` needs any other code. Disagreement is `UnreadableEvidence`.
- **Marker content.** The marker counts only when the file reads exactly `ok <gate-id>` for this check (one trailing newline allowed). Any other content is `UnreadableEvidence`.
- **Line endings: LF only.** The one tolerated trailing newline is `\n`. A CRLF marker (`ok <gate-id>\r\n`) is `UnreadableEvidence`, on every OS: a Windows child must write LF. This is the fail-closed choice; it costs availability for Windows children that write CRLF, never correctness. Gate ids are content-checked at construction (non-empty, no whitespace, no control characters), so no id can absorb a stray `\r` and the content `ok ` cannot name an empty id.

**Built-in check adapters** cover common tools that do not speak the protocol, such as `cargo test` and `pytest`. Each implements `gate_outcome::Check` over captured output. For example, `cargo test` passes with `N` > 0 tests executed and 0 failed, and `N = 0` gives `NothingChecked`. The adapters are part of the trust base, reviewed like gates, and each carries a **refusal witness** test: a fixture where it must refuse (R3 H-04).

**Artifact checks** are always run:
- `deliverable.nonempty`: the diff against base is non-empty, unless the task is declared read-only;
- `deliverable.applies`: the diff applies cleanly to the base in-process;
- `protected.unchanged` (§7.6).

These check content, never presence (R3 H-01).

**The run's `GateOutcome`** is `verdict(all check reports ++ reviewer report)`: total and worst-wins, and an empty set gives `Indeterminate { NothingChecked }`. Summaries and counts in the report are derived from the reports, never written by the agent (R3 H-24).

**Completeness (INV-34).** `verdict()` is never applied to a partial report set:
- **The plan is fixed first.** The planned check set is fixed before the agent loop starts. It contains every task check, the three artifact checks and, when review is enabled, one reviewer slot. Its digest goes in the journal header, and `VerificationStarted` lists its ids in order.
- **Reports are collected by id.** The verification driver collects reports into `PlanReports { plan_digest, reports: BTreeMap<CheckId, GateReport> }`, a plain collection with no success state. Its only consumer is `harness-run::finalize(&plan, reports) -> GateOutcome`.
- **What `finalize` does.** It calls `verdict()` only when the report ids equal the planned ids exactly. If any planned id has no report, the result is `Indeterminate { CouldNotRun }`. If an id is not in the plan, or a check reported twice, the result is `Indeterminate { UnreadableEvidence }`. A plan with no task checks gives `Indeterminate { NothingChecked }` whatever the artifact checks and the reviewer say (INV-18).
- **Reports that did arrive** are journaled and shown in the run report as diagnostics, including any `Failed`. They never produce the outcome of an incomplete plan.
- **Covered interruptions:**
  - `Cancelled` (SIGINT/SIGTERM or API cancel): the running check's process tree is killed, and the rest do not start.
  - Verification-budget exhaustion (§2.4).
  - `SandboxLost`.
  - A poisoned journal: `UnreadableEvidence` wins here, per §7.1.
  - A harness crash. No outcome is emitted at all. A consumer of the CLI sees a signal or an abnormal exit with no report line, which UNIFIED §6 maps to `CouldNotRun`. A later resume re-runs the whole plan (§2.10).
- **Each repair round** (§2.7) is a full verification pass under the same rule.
- **The marker.** `GATE_OK_FILE` is written only by the commit sequence of §7.1, after `finalize` returned `Passed` and `RunStopped` is durable. A kill at any earlier point leaves no marker.

### 7.4 What the agent can and cannot influence

The agent influences only the **workspace contents**. It cannot choose which checks run, see hidden checks, write the grading worktree, write the verification plan or produce a `GateReport`. Its `task.submit` note is journaled as untrusted and never read by any check.

### 7.5 The built-in independent reviewer (two pairs of eyes)

When the task enables `review` (the default for any task with write grants), the harness launches a **reviewer run** after checks complete:

- **Fresh context.** The reviewer gets the task text, the diff, the check reports and read-only tools (`fs.read`, `fs.search`, `fs.list`) over the grading worktree. It does **not** get the author's transcript, notes or deliverable note. The author could steer the reviewer through them.
- **Distinct identity.** It gets a new run id. If more than one model is configured, the reviewer profile must differ from the author's (Q5). Reviewer identity ≠ author identity is checked by `harness-run` and journaled. A same-identity review is refused (R3 H-22, INV-19).
- **Artifact, not prose.** The reviewer's `task.submit` must carry a review artifact in a fixed schema: findings, each with `severity` (UNIFIED `Severity`), `path:line` anchors and a quoted anchor text. `harness-run` validates it:
  - schema-valid;
  - every anchor resolves in the grading worktree and the quote matches (citation resolution, R3 H-20);
  - an unresolvable anchor is a `PHANTOM` finding.

  A valid artifact becomes a `GateReport` via `run_checked`: `Passed(Witness { checked = reviewed hunks, digest = diff digest })` if there is no `Blocking` finding, `Failed` if there is one. An invalid artifact, a reviewer timeout or a reviewer crash gives `Indeterminate { CouldNotRun }`, after which the **fallback reviewer** (next configured profile) is engaged and recorded (R3 H-22).
- **Every attempt re-checks identity, fallbacks included** (INV-19). `harness-run::reviewer` calls `check_distinct(author, candidate)` immediately before launching **each** attempt: the primary reviewer and every fallback. The check compares:
  - run ids (must differ, always);
  - profile id and profile SHA-256 (must differ when two or more models are configured, per Q5);
  - endpoint plus claimed model id and declared weights digest (must differ under the same condition).

  A candidate that fails the check is **not launched**. `ReviewerRefused { reason: SameIdentity }` is journaled, and the chain moves to the next fallback, which is checked the same way. The same check also runs once at session planning over the whole configured chain, so a misconfigured fallback is reported before the agent starts. The per-attempt check is the one that binds.

  **The fallback chain:**
  - With two or more models, the chain is the configured profiles minus the author's.
  - With one model, it is a single fresh reviewer run on the same profile: distinct run id and fresh context, the Q5 default.

  **The reviewer slot's report:**
  - It is the report of the first attempt that produced a valid artifact.
  - A valid `Failed` review is final. Fallbacks are engaged only when an attempt produced **no** valid artifact, so a blocking review cannot be shopped away.
  - If every attempt is refused or fails, the slot's report is `Indeterminate { CouldNotRun }`, and the run cannot be `Passed`.
- **It can only block.** Because `verdict()` is worst-wins, a reviewer's pass cannot rescue failed checks. A reviewer is also not a substitute for checks: with no checks, the outcome stays `Indeterminate { NothingChecked }`.

### 7.6 Reward-hacking defences

| Defence | Mechanism | Evidence / source |
|---|---|---|
| Fresh workspace with no future history | The workspace is a **new single-commit repository** of the base tree: no remotes, no other refs, no shared object database. The mapping to the real repository stays outside. Harness-side git invocations use argv only with hooks and fsmonitor disabled (`-c core.hooksPath=<empty> -c core.fsmonitor=false`). | SWE-bench `git log --all` leak (R1 §2); repo-controlled git config is executable config |
| Protected paths read-only | `.git`, tests-under-evaluation, gate scripts, CI config, lockfiles, `deny.toml` and task-declared paths are read-only overlays in the sandbox (FT-9) | ImpossibleBench: 76% cheating, near zero once tests were read-only (R1 §2) |
| Pristine grading worktree | Rebuilt outside the sandbox for every verification: base tree + agent diff, with **every protected path materialised from base** | R4 §3 / F3 |
| Diff audit | The agent diff is compared with the protected-path list. Any change → a `Blocking` finding `protected-path-modified` in the `protected.unchanged` report, so the run is `Failed`. A task that legitimately adds tests declares `may_add: ["tests/new_*"]`; existing protected files must stay byte-identical. | R4 §3 (the negative test: deleting a failing test must not end green) |
| Hash checks | Protected-file digests go in the journal header at start. `protected.unchanged` recomputes them over the workspace; a mismatch is a Blocking finding even if the sandbox failed to stop the write. | R3 H-23 |
| Hidden checks | Hidden check sources live outside the workspace and are mounted only into the grading sandbox. Diagnostics from them are withheld during repair (§2.7). | benchmark repair mode (R2 §5) |
| Verdict outside the agent | Checks run in a separate confined process tree after the agent loop has stopped. The agent's sandbox is torn down first. | R1 §2 |
| No self-report | `StopCause::Submitted` never implies `Passed`. Only `run_checked` or `child::interpret` mint `Witness`. | UNIFIED §5 |

### 7.7 The CLI as a gate child

`rustyharness run` follows the UNIFIED child protocol, so any gate runner (the suite's included) can consume it. The **last stdout line** is the run's JSON `GateReport` (`gate-outcome` feature `json`).

| Exit | Meaning |
|---|---|
| 0 | `Passed`; the `GATE_OK_FILE` marker is written only then, and only after `RunStopped` is durable (§7.1 commit point) |
| 1 | `Failed` |
| 2 | usage error |
| 3 | confinement refused (the task needs execution or grants an mcp-stdio provider, and `require()` failed; §4.5) |
| 4 | unreadable input (task spec, config, manifest) |
| 5 | `Indeterminate` (the kind is in the JSON), including a journal failure (§7.1), incomplete verification (§7.3) and a non-local `state_root` (§2.8) |

A consumer that only reads exit codes sees 3, 4 and 5 as `CouldNotRun`. That is lossy but fail-closed (UNIFIED §6 item 2). This fulfils F10.

## 8. Deployments: standalone vs inside rustysuite

This section follows R6 §0 and §4. **Standalone** is the primary product (ADR-0002), and there the harness's own mechanisms are the whole protection. **Inside rustysuite**, the same harness runs with suite add-ons and host-level layers that the harness cannot give itself.

| Mechanism | Standalone | Inside rustysuite |
|---|---|---|
| Two domains, `Untrusted<T>`, single action channel | harness | same |
| Manifest validation, admission, pinning, quarantine | harness; the user admits and pins | same, plus suite-signed manifests for suite apps and a suite-owned admitted list delivered as add-on config |
| Effect policy, approvals, tokens | harness; the approver is the user at the CLI or UI | same; in unattended suite runs no approver ⇒ Ask becomes Deny |
| Trifecta rule | harness | same |
| Sandbox (file, network, process) | harness backend, gated by `Conformed` | same, **plus** the suite's host-level properties (separate OS account and keychain for agent runs, no signing material reachable). These are OS and owner controls the harness cannot grant itself; it refuses to run unconfined rather than depending on them. |
| Separate OS account per agent | not provided (a process cannot grant itself a uid) | the suite's confinement decision; the harness exposes the probes an outside supervisor checks |
| Secrets | `FileStore` / `KeychainStore`, handles only | a secret-custody add-on is available but off. The suite's own rules decide whether agent runs may use it (default: not). |
| Model endpoint | loopback; hosted by opt-in (feature + config) | also a mesh transport add-on reaching a model host over the suite's mesh (Q10 of OPEN-QUESTIONS lands here, not in core) |
| Journal and evidence | journal + run report; the user keeps the chain head | also: the run's `GateReport` and chain head go into the suite's evidence records via the child protocol (§7.7). Independent-witness rules are met by §7.5 plus the suite's observer ≠ author requirement. |
| Checks | task-declared commands and adapters | also suite gate entrypoints, invoked through the suite engine as a provider. The engine's reports speak the same `gate-outcome` type. |
| No commit, no push | no push or publish capability exists in the built-ins; any provider verb that pushes is `irreversible`/`shared` ⇒ human yes every time | same; the suite's engine additionally refuses protected refs by construction |
| Supply chain | this repo's gates on three OSes (`.github/workflows/ci.yml`: `scripts/ci/gates.sh` on Linux and macOS, its cargo steps on Windows) | plus the suite's attestation chain |

**Add-on packaging** (answers OPEN-QUESTIONS 15): tools arrive as **runtime-loaded providers** (manifest + MCP server), which need no harness rebuild. Cargo features (`addon-*`) are only for what must be in-process: a mesh model transport and a secret-custody client. All are off by default. The ADR-0002 test: `cargo tree` of a default build contains no suite crate, and every §10 invariant passes with all add-ons off (INV-32).

## 9. Phasing

| Phase | Scope | Exit criteria (all gates green on macOS, Linux, Windows) | Key tests |
|---|---|---|---|
| **H0** | This design | Independent adversarial review → rework → confirming review → SOUND; §11 owner questions answered or defaults accepted in writing | review record |
| **H1** read-only agent | `gate-outcome` (workspace member); `harness-core` loop, `Meter`, loop detection; `harness-model` client (loopback), profiles, both protocols, replay (audit mode); `harness-manifest` v1 + built-in manifest; `harness-policy` for read classes; read tools in-process (no exec); journal v1 with write-ahead `Journaled` calls and poisoning; filesystem-locality check + spike S-F1; environment sample; CLI `run` / `replay` / `profile check`; purity gates | A read-only question-answering task runs end to end on a local model with both protocols. Every run's outcome is `Indeterminate { NothingChecked }` (no checks yet), and that is shown to the user. | INV-1, 2, 3, 8, 11, 14, 18, 20, 22, 23, 24, 27, 28, 29, 30, 33 (read tools), 35; replay determinism (audit mode reproduces every decision); format-error budget; mock server returning empty / `length` / 429 |
| **H2** confined action loop | `harness-sandbox` Linux + macOS backends, `Conformed`, confined file-op helper; `harness-conformance` FT-1..18; S-W1 spike (+ Windows backend if it passes); edit engine; `exec.run` with allowlist; workspace materialisation + protected overlays; approvals + tokens; secrets boundary + canaries; network = none only | FT suite green on Linux and macOS CI; Windows either green or `Unavailable` with the refusal path tested; a coding task edits and runs tests inside the sandbox | INV-5, 6, 10, 12, 13, 15, 16, 21, 25, 33 (exec and edits); edit no-op and stale-read tests; CRLF test; symlink escape (FT-12); orphan kill (FT-16) |
| **H3** evidence + reviewer | verification plan, child protocol, check adapters with refusal witnesses, pristine grading worktree, diff audit, repair rounds, reviewer run + fallback, run report, CLI exit codes; `gate-outcome` moved to its own repository | Reward-hack suite: deleting a failing test, flipping `#[ignore]`, editing a gate script, and adding a check that exits 0 without a marker all end **not green**, witnessed. A pinned evaluation set runs and its baseline is recorded per (harness version, model) (R1 §8 #15). | INV-4, 17, 18, 19, 26, 28, 34; adapter refusal witnesses; phantom-citation reviewer test; reviewer ≠ author refusal, including a fallback equal to the author |
| **H4** providers + MCP | `harness-mcp` (rmcp stdio, confined servers), admission CLI, signing and pinning, quarantine, the full trifecta with real labels, egress proxy (Linux + macOS; Windows after S-W2) | A third-party MCP server works as a `pinned`-tier provider; the fixture provider integrates with zero core diff | INV-6 (provider spawn), 7, 9, 31; rug-pull (a mutated description is quarantined); shadowing (duplicate namespace refused); FT-13/14/15 through the proxy; an MCP sampling request refused |
| **H5** suite add-ons | suite providers (engine verbs, evidence reporting), `addon-*` features (mesh transport, secret-custody client), a pinned harness version for rustybenchmark's agentic board (no benchmark code in the harness, OD-2) | Default build has zero suite dependencies; with add-ons on, every invariant still passes; suite-side acceptance happens in the suite | INV-32; add-on on/off matrix |

Phases are strictly ordered: H2 does not start before H1's exit, and so on. Each phase's exit goes through the two-eyes review, because the harness is itself reviewed like a gate.

## 10. Security invariants as testable properties

INV-1..14 are carried from R6 §5 (re-scoped where this design settles a detail); INV-15 onward are new. "Phase" is when the falsifying test must exist and pass.

| ID | Property | Falsifying test | Phase |
|---|---|---|---|
| INV-1 | Every invocable capability resolves to closed-set dimension values. Unknown fields, versions, namespaces and reserved names are refused; the reserved set always contains `RESERVED_NAMESPACES`, whatever the config says. | Manifests with an unknown field, an unknown effect value, v0 and v2, `provider: "harness"`, `provider: "rustyvault"` → each refused with a typed error; the same two names refused under a config whose `extra_reserved` is empty or lists other names | H1 |
| INV-2 | `Untrusted<T>` has no `Deref`, and its `Debug` shows no payload | compile-fail test on deref; property test: `format!("{:?}")` contains no payload substring | H1 |
| INV-3 | An empty or truncated completion is never a turn result or a pass | mock server: empty body with a clean stream end, then `finish_reason: length` → typed error, run outcome ≠ `Passed` | H1 |
| INV-4 | `Passed(Witness)` cannot be constructed outside `gate-outcome`'s choke points | compile-fail test constructing `Witness` or `Passed` from a harness crate | H1 (crate) / H3 (use) |
| INV-5 | An irreversible or `shared`-blast call without a valid, bound, unconsumed approval refuses, every time | invoke under ask with no approval; with an approval for different args; with an expired one; with a reused one → all refuse | H2 |
| INV-6 | Without `Conformed`, no execute-class tool, no confined check, no mcp-stdio provider process and no in-process adapter with an execute-class capability runs; there is no unconfined fallback | disable the backend (matrix row absent) on each OS → refusal path, `Indeterminate { UnsupportedOs }` or `{ CouldNotRun }`; grant an mcp-stdio capability with the backend disabled → session refused at planning, and a counter on the spawn seam shows zero provider processes started | H2 / H4 (providers) |
| INV-7 | A capability whose pinned description or schema hash drifts is quarantined until re-pinned outside the run | mock MCP server mutates its description between admission and connect → invocations refuse; `Quarantined` journaled | H4 |
| INV-8 | Two providers cannot share a namespace, and ids stay inside their namespace | admit two manifests with the same `provider` → second refused; foreign-namespace id → refused | H1 |
| INV-9 | A session whose active set plus workspace is P ∧ U ∧ E is refused at start and on any set change | compose such a set → typed refusal naming three capabilities; quarantine that creates it mid-run → `PolicyAbort` | H1 (pure) / H4 (real labels) |
| INV-10 | No resolved secret or canary appears in any model request or child environment | canary test: capture every outbound model request body and every child `environ` → absent | H2 |
| INV-11 | A journal cannot be mutated undetectably, apart from wholesale replacement (anchored externally) | rewrite a middle line, delete a line, swap two lines → reader refuses; torn tail → reported, resumable | H1 |
| INV-12 | The trust base and protected paths are not writable by the agent, and the trust base is not even readable | FT-9, FT-10; plus a backend-less seeded diff to a protected file → `protected.unchanged` Blocking → run `Failed` | H2 |
| INV-13 | No harness code path executes a string built from model-controlled text; `exec.run` is argv-only and allowlist-resolved | grep gate: no `Command::new` on formatted or concatenated strings in `crates/`; test: argv `["sh","-c",…]` refused when no shell is allowlisted | H2 |
| INV-14 | Every budget ends the run with a typed cause; the loop cannot outlive its wall-clock budget | scripted model that always asks for another tool → `Budget(Steps)`; hanging tool → `Budget(Wall)` within budget + kill grace | H1 |
| INV-15 | `Containment::Available` is unnameable without `Conformed`, and `Conformed` is minted only by `probe()` passing matrix + live probe | compile-fail constructing `Conformed`; host with a sabotaged primitive (e.g. userns sysctl off) → `Unavailable` | H2 |
| INV-16 | Approval tokens bind run, step, capability, args digest, expiry and nonce, and cannot be forged outside the harness process | flip one byte in each field; replay a consumed nonce; present a token from another run → refused | H2 |
| INV-17 | Any agent change to a protected path makes the run not green | agent deletes a failing test / edits a gate script / edits CI config → `Failed` with `protected-path-modified` | H3 |
| INV-18 | A task with no checks is never `Passed` | submit on a task with an empty verification plan → `Indeterminate { NothingChecked }` | H1 |
| INV-19 | Reviewer identity ≠ author identity for every reviewer attempt, fallbacks included, and the reviewer never sees the author transcript | configure reviewer = author run → refused; with two models configured, make the primary reviewer crash and configure the fallback = the author profile → fallback not launched, `ReviewerRefused` journaled, outcome ≠ `Passed`; inspect reviewer context digests → no author transcript blocks | H3 |
| INV-20 | Audit replay reproduces every context digest and policy decision, or names the first divergence | replay an H1 journal → identical; tamper a recorded tool result → divergence at that step | H1 |
| INV-21 | Concurrent runs share no writable state | 8 concurrent runs on one host → zero lock failures, disjoint paths; one run's sandbox cannot read another's workspace (FT-3) | H2 |
| INV-22 | Duplicate JSON keys are refused at every depth | `{"schema_version":1,…,"schema_version":0}` and a duplicated nested key → refused | H1 |
| INV-23 | Prompts, task text and approval payloads never appear on any argv | spawn helper + MCP server + check; read `/proc/*/cmdline` (and platform equivalents) → no payload bytes | H1 |
| INV-24 | The default build connects to no non-loopback model endpoint | configure `http://lan-host.example/v1` without `hosted` → startup refusal; `cargo tree` of the default build has no TLS crate | H1 |
| INV-25 | The effective confirmation is never weaker than any declared or derived floor | property test over all dimension combinations: `effective ≥ max(declared, derived)` | H2 |
| INV-26 | A `pinned`-tier manifest cannot declare `personal`/`restricted`, `shared` blast, or share a session with such capabilities | manifests declaring each → refused; mixed session → refused | H3 (schema) / H4 (session) |
| INV-27 | `restricted` capabilities are refused (standalone default) | grant a `restricted` capability → session refused | H1 |
| INV-28 | Exactly one outcome type: no harness crate defines an outcome or verdict enum | grep gate over `crates/harness-*` for `enum *Outcome` / `enum *Verdict`; the build fails on a planted one | H1 |
| INV-29 | Only the model's own reply is parsed for actions | plant `<action>{…}</action>` and a native tool-call JSON inside a file, a test name, a compiler diagnostic and an MCP result → never executed, never parsed | H1 |
| INV-30 | Built-in file tools cannot reach outside the workspace | planted symlink to `$HOME` canary: H1 in-process path (materialisation refused the symlink); H2 helper path (FT-12) | H1 / H2 |
| INV-31 | A new provider integrates with no core change | fixture provider end to end; CI asserts an empty diff over `crates/` | H4 |
| INV-32 | Standalone build has zero suite dependencies; add-ons are off by default | `cargo tree` of the default feature set against the suite crate list → empty; invariants pass with add-ons off | H5 |
| INV-33 | No intent executes unless its journal append is durable, and a run whose journal cannot be written is never `Passed` | fault-injected `JournalFile`: fail the intent write, then the intent fsync, then the result write, then the `RunStopped` write (after every check passed) → in each case a spy provider sees zero invocations after the failure, the outcome is `Indeterminate { UnreadableEvidence }`, the exit code is 5 and no `GATE_OK_FILE` exists; header write failure → run refuses to start; proxy request after a failed `Egress` append → refused | H1 / H2 |
| INV-34 | Verification that does not report every planned check is `Indeterminate`, never a verdict over the subset | plan of three checks where check 1 passes and check 3 would fail: SIGKILL the harness after check 1 → no report line, no marker, abnormal exit; SIGTERM after check 1 → `Indeterminate { CouldNotRun }`; exhaust the verification budget after check 1 → `Indeterminate { CouldNotRun }`; resume after the SIGKILL → all three re-run; a report with an unplanned id → `Indeterminate { UnreadableEvidence }` | H3 |
| INV-35 | `state_root` is used only on a filesystem positively identified as local | per OS: `state_root` on an SMB and an NFS mount, and (Linux) on a FUSE mount → startup refusal naming the type, no journal header written; a network mount placed under `state_root` → the next attempt refuses | H1 (S-F1) |

## 11. Non-goals, owner questions, and limits

### Non-goals (v0.1)

Not a model or model server (00-overview §5). No hosted model in the default build, no parallel
tool calls, no dynamic tool retrieval, no LLM-written context summaries, no remote MCP over HTTP,
no `git apply` or unified-diff edits, no persistent shell. No sandbox-free execution, ever. No
trifecta override path (CaMeL-style; deferred). No `restricted` data (the harness is not the
suite's confined personal-data AI; ADR-0002 item 3). No automatic promotion: nothing merges or
pushes without a human. No front-end protocol beyond the `harness-run` embedding API; ACP is the
likely later choice (R1 §4.2) once a UI other than the CLI embeds the harness.

### Open owner questions (each with the fail-closed default that holds until answered)

1. **`gate-outcome` licence.** Its own repository is decided (§1.4). The licence is open, and it is a real tension, not a formality:
   - **For a permissive licence** (MIT OR Apache-2.0): the crate exists to be the *one* outcome type every consumer shares. A noncommercial licence limits who can adopt it, and it limits which of the suite's own consumers may link it, since the suite does not link PolyForm Noncommercial crates into anything it publishes (R2 (a) item 12).
   - **For PolyForm Noncommercial**: ADR-0003 is decided for this repository ("I don't want it used by businesses without my permission"). Splitting one crate out under a permissive licence is an exception to that decision, which only the owner can make.
   - **What either answer changes.** A permissive `gate-outcome` would relax nothing here. rustyharness itself stays PolyForm Noncommercial under ADR-0003, and every consumer stays bound by its own licence rules. The question is only whether ADR-0003's reason extends to a small vocabulary crate with no product value on its own.

   *Question to the owner:* does ADR-0003 cover `gate-outcome`, or is it a recorded exception? *Default:* PolyForm Noncommercial, like this repo, until the owner rules.
2. **May a hosted model ever see `personal`-sensitivity data?** *Default:* no. Hosted is limited to sessions with sensitivity ≤ operational. `restricted` is never allowed, whatever the answer.
3. **May the harness ever hold `restricted` capabilities** (the life-data class)? *Default:* refused at session start (INV-27). The owner's ADR-0002 item 3 already points this way.
4. **Windows in v1.** *Default:* Windows ships read-only (no execution) unless spike S-W1 passes. The alternative is to state now that Windows execution is v2. A consequence users must be told: from H3 on, a read-only Windows session with a verification plan cannot run its checks. Every check reports `Indeterminate { UnsupportedOs }` or `{ CouldNotRun }`, so the run is never `Passed` on Windows until S-W1 passes. The CLI says so at session start, not only in the final report.
5. **Reviewer independence bar.** *Default:* fresh context + distinct run always required; a distinct model required when two or more are configured. The alternative is to always require a distinct model, which would make the reviewer unavailable to single-model standalone users.
6. **Concurrency default per model endpoint.** *Default:* 1 for loopback, user-configurable (R3 §7 Q3).
7. **When to invest in a trifecta-breaking architecture** (plan-then-execute / dual-LLM, R1 §3.3). *Default:* never combine; revisit after H4.
8. **macOS if `sandbox-exec` disappears.** The options are a `sandbox_init` FFI in an audited unsafe crate, or App Sandbox with code signing. *Default:* macOS execution refuses (`probe()` fails) until one lands.

### What this design does not cover

- Suite-specific provider manifests and their policies (these live in the suite).
- Model serving and choice of weights.
- UI and approval UX beyond the CLI prompt.
- Retention and GC policy for `state_root` (default: keep; explicit `rustyharness gc`). The owner has since required `gc` (OD-5d); its design is pending.
- Performance numbers for backends and the proxy.
- Covert or timing channels out of a sandbox (R6 §8).
- Exact seccomp and SBPL rule lists (spike outputs, reviewed as policy).
- A completeness claim over entry points (R6 §2).
- Alerting on journal events (paging, dashboards). The harness emits typed, deduplicated events (§2.6); a supervisor alerts on them.

### Residual risks (named, not mitigated here)

- **In-process tools are not interruptible (H1).** The built-in read tools run in the harness process, synchronously, and their deadline is cooperative: every call checks it before it starts and a walk between entries, but a started `fs.read` never looks at it. A read blocked in the kernel (e.g. on a network or FUSE mount inside the workspace, which no locality check covers) holds the run past its wall budget, and a tool's time is charged only after its result is journaled. So INV-14's falsifying test ("hanging tool → `Budget(Wall)` within budget + kill grace") has no H1 counterpart. H2's confined, killable file-op helper (§4.8) closes it. (Found by the H1f-5 confirming review, NF-4; flagged for the H1 phase-exit review.)

- **Path checks inside `state_root` can be raced by a writer inside `state_root`.** The journal checks that the run, attempt and blob directories are real directories and then creates entries in them; a process that can write inside `state_root` could swap a directory for a symlink between the check and the create (H1c confirming review NF-2). `state_root` is trust base (0700, never granted to a sandbox, §6.4), and such a writer can rewrite journals outright anyway; the external chain-head anchor is the defence (§7.1). Closing the window needs a directory-handle API (`openat` with `O_NOFOLLOW`), which is §6.7 territory.

- **The model server process.** A loopback model server (llama.cpp or similar) receives the whole context every turn. It is a user process, part of the user's trust base. Its own network access is outside harness control in a standalone deployment: the harness neither measures nor constrains it. The trifecta rule (§5.4) assumes that server has no egress. A user who needs that assumption to hold must run the server without network access. (R6 TH-9 is the closest threat; this is the standalone residual.)
- **Journal wholesale replacement.** Detectable only when the chain head is recorded elsewhere (§7.1). Standalone, keeping it is the user's job.
- **Filesystem locality below the filesystem.** §2.8's check identifies the filesystem type, not the storage beneath it. A local filesystem on network block storage (iSCSI, a network-backed virtual disk) passes. The properties the check protects, one writer's lock and fsync durability, are the block device's to keep there.
- **Digests are harness claims.** `gate-outcome` does not recompute them (§1.4). Audit replay does.

### What would make this design wrong

- A backend passes §6.6 yet a probe outside the corpus escapes. The corpus, not the backend, is then the weak point: add the case, re-run all backends.
- UNIFIED changes `Witness` semantics or the child protocol. §1.4, §7.3 and §7.7 would move with it, which is why the type is imported, never mirrored.
- Small local models cannot do useful work within 5-8 tools and exact-match edits. The profile defaults, not the architecture, would change (R1 §6 suggests they can for short horizons).
- The trifecta rule refuses so many real sessions that users bypass the harness. That would argue for Q7, not for weakening INV-9.
- rmcp starts pulling compiled C, or requires server features §4.6 refuses. `harness-mcp` would then need its own thin client, as `harness-model` does.

## Appendix A — R3 requirements traceability

| R3 | Where met |
|---|---|
| H-01 content-shape artifact checks | §7.3 artifact checks; INV-18 |
| H-02 PASS / FAIL / PARSE-FAILURE / NOT-RUN distinct | `gate-outcome` kinds; §7.3 table |
| H-03 harness captures exit codes itself; CRASH / TIMEOUT / MISSING distinct | §7.3 (`child::interpret`), `ToolStatus` §4.5 |
| H-04 refusal witnesses for checks | §7.3 adapters; §6.6 behaviour-not-string |
| H-05 capability degradation fails closed | §6.1; INV-6, INV-15 |
| H-06 write allowlist enforced below the agent | §6.2, §6.4; FT-3, FT-9 |
| H-07 credentials brokered per spawn | §5.5 |
| H-08 no payloads through shells or argv | §2.1, §6.3 (helper spec over pipe); INV-23 |
| H-09 isolated per-run state | §2.8; INV-21 |
| H-10 harness-metered concurrency, typed provider errors | §2.8, §3.2 |
| H-11 done-ness from harness-owned state | §2.5, §7.3, §7.4 |
| H-12 first-class run identity | §2.8 |
| H-13 durable per-attempt logs, recovery | §7.1 (fsync per intent and result; write failure fail-closed, INV-33), §2.10 |
| H-14 standing-condition dedup | §2.6: detector notices once per detector state; `Quarantined`, `SandboxUnavailable` and budget-threshold events journaled once on entry and once on exit of the condition. Alerting on those typed events is declared out of scope for a library harness (§11); a supervisor consumes them. |
| H-15 find-based snapshots incl. empty dirs | §2.8 snapshots |
| H-16 detective signals labelled | §5.5 redaction |
| H-17 environment context recorded | §7.1 environment sample (CPU count, load, memory available, free disk, each with its producing method; `unmeasured` never zero) in the header, at `VerificationStarted` and on every timeout, crash or `CouldNotRun`; `possibly-environmental` Info finding; `UnsupportedOs` / `CouldNotRun` kinds |
| H-18 verification depth recorded; Rust, portable | header + `Coverage` on reports; §9 three-OS gates |
| H-19 volatile facts derived by the harness | §2.3 block 4 |
| H-20 citation resolution blocks | §7.5 reviewer anchors |
| H-21 structured claims | run report fields derived from reports (§7.3) |
| H-22 structural two-eyes with fallback | §7.5 (identity re-checked before every attempt, fallbacks included); INV-19 |
| H-23 stamps over committed content | protected digests in the header (§7.6); chain head (§7.1) |
| H-24 summaries derived from records | §7.3 last paragraph |

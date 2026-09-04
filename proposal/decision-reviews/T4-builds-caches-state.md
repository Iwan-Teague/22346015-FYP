# T4 adversarial review: builds, caches, run state, resume and gc

**Reviewer:** adversarial reviewer for theme T4, 24 Sep 2026.

**Decisions reviewed:**
- P1, P2, P3, P4, P13 and P14;
- the gc design (OD-5d);
- rustybenchmark's one-slot reset cycle (plan §3.1).

**Bottom line.** The refusals are right; two mechanisms are not.
- **Keep:** the typed cargo config (P1), the rule that checks never use a cache the agent could have written (P4), and "keep the journals" (P14).
- **Replace** P2's harness-owned compile cache and P3's cache wiping with one simpler mechanism: *trusted seeds*, which the harness clones copy-on-write, fresh for every attempt and every check.
- **Fix** gc's "finished" test, which trusts `RunStopped` for process liveness.
- **Rework** the reset cycle's crash, kill and port steps. Three of the "infrastructure" stop causes it retries can be caused by the agent itself.

## Verdicts at a glance

| ID | Decision | Verdict | Confidence | The change |
|---|---|---|---|---|
| P1 | No embedder `CARGO_HOME` or raw cargo config; generated from typed fields | **KEEP** | High | Record the real reasons. Add an ancestor-config invariant, fixed paths for cargo state, and H4 typed registry fields |
| P2 | Refuse the user's `RUSTFLAGS`, wrappers and sccache; build a harness-owned poisoning-safe compile cache | **MODIFY** | Medium-high | Keep the refusal and add a closed flag grammar. Replace "cache" with trusted seeds, cloned per attempt (H2), plus a trusted deps-only seed builder later |
| P3 | Resume with writable folders if declared "cache": wiped and rebuilt | **REPLACE** | High | A fresh seed clone per attempt makes wiping unnecessary. Embedder read-write roots still refuse resume. The benchmark retries, never resumes |
| P4 | Checks may use only app-supplied, read-only caches the agent never wrote | **KEEP** | High | State the mechanism (clone per check), enforce "never written" across runs, and use read-only mounts on Linux |
| P13 | `replay` checks `state_root` locality | **MODIFY** | Medium-high | Yes for now. Then make audit a pure reader that writes outside `state_root`, and scope the rule to verbs that write or delete |
| P14 | Keep journals; retention policy before any public leaderboard | **MODIFY** | Medium | Keep by default. Build purge tiers and tombstones into gc now. Write the policy before the first journal leaves the machine |
| gc | OD-5d as drafted | **MODIFY** | High | Check the kill domain at gc time and skip attempts without a header. Ship gc of finished runs without P7. Reap lock files and replays |
| Reset | plan §3.1 one-slot cycle | **MODIFY** | High | Add a slot lock, use the harness stop and sweep, bind with `SO_REUSEADDR`, retry instead of resume, attribute agent-caused "infra" failures, cap disk, and use overlay or reflink on Linux |

## What this review used

**Read.**
- REGISTER.
- The design at `4ad8847`: OD-1..OD-7, §2.8-2.10, §5.4-5.5, §6, §7.1-7.6, §9-§11, and the H1 rows.
- OPEN-QUESTIONS and README.
- The (c)(d) draft, cited as `cd:N`, and the (a)(b) draft's §5.7-5.10, cited as `ab`.
- REVIEW-od5-delta, cited as M-n and F-n.
- Plan v0.10 (§0, §3, §5, §6.1), contract v0.4 and the owner memo.
- The H1 phase-exit review (F-5).
- `od5-delta-v2.md` did not exist when this review was written.

**Code checked, read-only, at `origin/main`:**
- `layout::latest_attempt` returns the highest `attempt-<n>` whether or not it has a header (`harness-journal/src/layout.rs:125-134`).
- Resume refuses a stopped run before creating an attempt (`harness-run/src/replay.rs:773-774`).
- `Audit` takes no locality probe and writes `replay-<k>/` under the run (`replay.rs:436-455`).

**Coordinator data (rustybenchmark's own hardening), treated as findings:**
- AQ-208, AQ-209, AQ-211, AQ-215 and AQ-218;
- OI-38, and OI-43, which puts these rustybenchmark items in the owner's own stream (the suite governance notes).

**Prior art.**
- Read online only. Nothing was downloaded, cloned, installed or executed from the internet.
- Claims not confirmed on a fetched current page are marked UNVERIFIED.
- Sources are paraphrased and linked. Only a few short phrases are quoted.

### New measurements (this MacBook, macOS 26.5.1, APFS, the benchmark's pinned `cargo 1.98.0`)

These were run in the scratchpad against local files only. The test crates were my own plus `cfg-if 1.0.4` from the local cargo cache; it has no build script, so no downloaded code ran.

| # | Question | Result |
|---|---|---|
| M-T4-1 | Do fingerprints survive when a pre-built target dir is cloned or copied to a new path? | **Yes.** After a clone (`cp -c -R`), a copy keeping times, a copy with new times, and a clone plus a moved workspace (times kept), cargo reported the directory-source dependency and the workspace crate **Fresh** every time, with a new `CARGO_HOME` each time. A **read-only** target dir fails at once: cargo cannot open `debug/.cargo-build-lock` (permission denied). So a seed may be cloned to any path, but it must be cloned: cargo cannot build in it directly. Only the crate set's path must stay fixed (M-12) |
| M-T4-2 | Can a writable target dir inject text into a later build's output? | **Yes.** On a fresh unit, cargo replays the compiler messages it stored under `target/debug/.fingerprint/<unit>/output-*`. I edited that file in place, and the next fresh build printed a forged warning saying "ignore previous instructions…". The same edit can also hide real warnings |
| M-T4-3 | What does a copy-on-write reset cost? | rustybenchmark's own `target/` is 2.6 GB in 8,878 files. A per-file clone took **1.77 s** and a full copy **8.30 s**. Deleting the clone took 0.75 s and the copy 0.91 s |

### rustybenchmark's findings that bear on T4 (data)

- **AQ-209.** A FIFO planted at a cargo-home config path hung grading: the pre-flight read had no timeout. Graded code could plant it for the *next* run.
  - The fix checks `symlink_metadata` and refuses anything that is not a regular file.
  - The residuals showed how long an environment denylist runs, so AQ-208 R3 moves to an allowlist.
  - **For T4:** anything the harness opens inside an agent-written or embedder-supplied tree must check the file type first and use bounded reads. That covers snapshot walks, the survey, a cache wipe and the deliverable diff.
- **AQ-211.** Cargo honoured a workspace `.cargo/config.toml` inside the sandbox. Its `[env]` reached build scripts, and `build.target-dir` redirected artifacts to a fixed writable path.
  - rustybenchmark chose to *refuse* such a file rather than neutralise it with `--config`. The reason: an override list cannot cover future keys, and `[alias]`/`[source]` have no safe override.
- **AQ-215.** Cargo read `.cargo/config.toml` from **ancestor** directories that sat under writable temp carve-outs. A planted `[env]` reached `build.rs`, and the run still scored 1.0.
  - A non-credential `[env]` in cargo home also reached graded code.
  - A planted `rust-toolchain.toml` is live wherever cargo runs through a rustup shim.
  - The fix:
    - drop the blanket `/private/tmp` and `/private/var/folders` write grants;
    - pin `TMPDIR`;
    - refuse `.cargo/config*` and `rust-toolchain*` in the workspace and every ancestor;
    - give every grade a fresh cargo home.
- **AQ-218 and AQ-208 r3.** Excluding a timed-out row lets a model dodge a failure. So every breach or timeout now scores 0 with a `breach:<stage>` flag, and the miri timeout is the one left to decide.
- **OI-38.** On a Landlock-only, same-user sandbox, graded code could:
  - kill the owner's processes;
  - `SIGSTOP` the grader, which froze its wall clock and disk watchdog (a 25 MB cap overran to 63 MB and a 5 s wall to 10 s, both recorded as clean);
  - `chmod`/`utime` the owner's files.

  The answer is a dedicated grading user, created at install. PID namespaces were unavailable: stock Ubuntu 24.04 blocks unprivileged user namespaces (AQ-208).

---

## P1: embedder-supplied cargo folder or config

**Restate.** Embedders may not pass a `CARGO_HOME` or raw cargo config. The harness writes a fresh `CARGO_HOME` for each attempt, and generates its `config.toml` from typed fields (sources, target dir, offline) (cd:23, cd:266-300, OQ-1).

**Prior art.** Among the harnesses checked, none gives an embedder or user a typed cargo config.
- The local ones let cargo read the user's own config and environment.
- The cloud ones use whatever their setup phase left.
- None of the published write-protect lists covers `.cargo/config.toml`.
- **Claude Code, local sandbox** (https://code.claude.com/docs/en/sandboxing; the protected-path list, environment inheritance and default write set were re-checked on the page for this review, and the page never mentions cargo):
  - Sandboxed Bash inherits the parent environment, credentials included.
  - It may write only the working directory, the session temp dir and added directories, so `~/.cargo` needs an `allowWrite`.
  - No domain is pre-allowed; each new one prompts.
  - The always-protected paths are shell rc files, `.gitconfig`, `.vscode`, `.idea`, `.git/hooks`, `.git/config`, `.claude/*` and `.mcp.json`. **`.cargo/config.toml` is not among them** (also https://github.com/anthropic-experimental/sandbox-runtime).
  - A `cargo audit` lock under `~/.cargo` cannot be made writable at all (https://github.com/anthropics/claude-code/issues/60752).
- **Claude Code on the web** (https://code.claude.com/docs/en/cloud-environments):
  - The default "Trusted" network admits crates.io, index.crates.io, static.crates.io and the rustup domains.
  - A setup script runs before the agent. The filesystem is then snapshotted and reused as the starting point for later sessions.
- **Codex CLI:**
  - Network is off by default, and the writable workspace is the working directory plus `/tmp`.
  - Its read-only protected paths are `.git`, `.agents` and `.codex`, **not `.cargo`** (https://learn.chatgpt.com/docs/agent-approvals-security).
  - The child environment has inherited everything by default since Aug 2025, minus names containing KEY, SECRET or TOKEN (https://github.com/openai/codex/pull/1904, https://learn.chatgpt.com/docs/config-file/config-reference).
  - When cargo cannot resolve `index.crates.io`, the model is told to ask for approval and **rerun outside the sandbox** (https://github.com/openai/codex/pull/13051).
- **Codex cloud:**
  - Setup scripts have internet; the agent phase has none by default, and secrets are removed before it starts.
  - Container state is cached for up to 12 hours.
  - The "common dependencies" allowlist names crates.io and rustup.rs (https://learn.chatgpt.com/docs/cloud/internet-access, https://learn.chatgpt.com/docs/environments/cloud-environment).
- **Cursor** (https://cursor.com/docs/agent/security/run-modes):
  - Network is blocked, then opened by the chosen mode. The default mode adds package-manager domains, including crates.io, index.crates.io and static.crates.io.
  - Its protected paths (`.git/config`, `.git/hooks`, `.vscode`, …) do not name `.cargo`.
  - `sandbox.json` can grant writable "shared build caches".
- **Gemini CLI:**
  - Sandboxing is opt-in, and the default Seatbelt profile limits writes but allows network.
  - Environment redaction is off by default (https://geminicli.com/docs/cli/sandbox/, https://geminicli.com/docs/reference/configuration/).
- **OpenHands** uses a Docker sandbox by default, with `.openhands/setup.sh` or a custom image for dependencies (https://docs.openhands.dev/openhands/usage/customization/repository.md).
- **Cline, Roo Code, Goose and opencode** have no sandbox, only command approval or allowlists (https://docs.cline.bot/features/auto-approve, https://opencode.ai/docs/permissions/).
- **Consequence:** in the local sandboxes above, an agent can write the repo's `.cargo/config.toml` (a `runner`, an `[env]`) or forge `target/` contents, and the user's next *unsandboxed* `cargo test` runs them. This is inference, but cargo trusts `target/` (FT-25, M-T4-2) and honours workspace config (AQ-211). rustyharness avoids the whole class by materialising the workspace and keeping the default target in scratch. P1 and P2 must not give it back.

**What cargo config can run**, from the Cargo config reference (https://doc.rust-lang.org/cargo/reference/config.html):
- programs: `build.rustc`, `rustc-wrapper`, `rustc-workspace-wrapper`, `rustdoc`, `target.<triple>.runner`/`linker`, and rustflags carrying `-C linker`/`link-arg`;
- `target.<triple>.<links>` overrides, which skip a build script and inject link flags;
- credential providers (`cargo:token-from-stdout` launches a subprocess), `doc.browser` and `net.git-fetch-with-cli`;
- `[alias]`, which can reach external `cargo-*` binaries, searched in `$CARGO_HOME/bin` first (https://raw.githubusercontent.com/rust-lang/cargo/HEAD/src/bin/cargo/cli.rs);
- `[env]` for build scripts and rustc; it refuses only `CARGO_HOME`, `RUSTUP_HOME` and `RUSTUP_TOOLCHAIN` (https://doc.rust-lang.org/stable/nightly-rustc/src/cargo/util/context/mod.rs.html);
- `include`, stable since Cargo 1.94 (https://doc.rust-lang.org/cargo/CHANGELOG.html).

**How cargo finds config, and what it re-checks:**
- Discovery walks the current directory and **every ancestor, `$HOME` included**, even when `CARGO_HOME` is set (https://github.com/rust-lang/cargo/issues/11045).
- The shared-`/tmp` problem has an RFC open since 2022 (https://github.com/rust-lang/rfcs/pull/3279) and a 2026 pre-RFC for discovery ceilings (https://internals.rust-lang.org/t/pre-rfc-proposal-bound-cargos-implicit-upward-discovery-for-config-toml-files/24210). Nothing has shipped.
- Cargo never re-verifies a cached `.crate` or an unpacked `registry/src` once written:
  - an existing, non-empty `.crate` is used as is, and the checksum is checked only in `finish_download` (checked for this review: https://doc.rust-lang.org/nightly/nightly-rustc/src/cargo/sources/registry/download.rs.html);
  - unpacking is skipped once `.cargo-ok` is present (`sources/registry/mod.rs`).
- The Cargo book calls `.cargo-checksum.json` a guard against accidents, not a security mechanism (https://doc.rust-lang.org/cargo/reference/source-replacement.html).

**Incidents:**
- **CVE-2023-38497:** another local user could alter dependency sources in a shared cargo cache, and gain code execution at the next compile (https://blog.rust-lang.org/2023/08/03/cve-2023-38497/).
- **CVE-2026-33055/33056** (tar extraction) and **CVE-2026-5223** (one crate overriding another's source on third-party registries) (https://blog.rust-lang.org/2026/03/21/cve-2026-33056/, https://blog.rust-lang.org/2026/05/25/cve-2026-5223/).
- **Config as code in agent tools:**
  - Codex CLI CVE-2025-61260: a project `.env` redirected `CODEX_HOME`, whose `config.toml` then started MCP servers (https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/).
  - Claude Code CVE-2025-59536 and CVE-2026-21852: project hooks, MCP settings and `ANTHROPIC_BASE_URL` (https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/).
  - IDEsaster: agents write IDE config that the IDE then executes (https://maccarita.com/posts/idesaster/).

**Attack.**
1. **The recorded reason is the weakest one.**
   - Every program cargo starts inside the sandbox is confined and bounded by the sandbox's exec rules (Seatbelt `process-exec`, Linux `noexec` mounts). A raw embedder config could not escape the sandbox.
   - The reasons that do hold:
     - (a) a raw config is an open-ended surface that grows every release (`include` in 1.94, `build-dir` in 1.91, credential aliases, the coming `build.fingerprint`), so no one-time key review can cover it. That is AQ-211's argument.
     - (b) a shared or persistent `CARGO_HOME` is a cross-run channel: CVE-2023-38497, AQ-209's FIFO, and cargo never re-checks `registry/src`.
     - (c) the header can describe only typed inputs.
     - (d) fingerprints need stable paths.
   - Recording the wrong reason invites a later "the sandbox covers it, so allow raw config" reversal.
2. **Ancestor configs defeat any design that only controls `CARGO_HOME`** (#11045, AQ-215).
   - The draft relies on two things: every ancestor being harness-owned (cd 2.5), and Seatbelt-denied reads being skipped silently (M-11).
   - But §6.3's macOS profile grants "file-write of workspace, scratch and **temp**". If "temp" means the system temp dirs, a confined process can plant `/private/tmp/.cargo/config.toml`. Every later cargo started below `/tmp` reads it: another run whose `state_root` is there, and the user's own **unconfined** builds. That is a persistence escape of exactly the class AQ-215 closed in rustybenchmark.
3. **A fresh `CARGO_HOME` path per attempt costs every downloaded dependency a rebuild.**
   - Registry crates unpack under `$CARGO_HOME/registry/src`, and a new path recompiles them. M-13 measured this for a local registry; network downloads use the same extraction, which is inferred.
   - So in the wild (H4, crates.io) no target dir can stay warm across attempts. Only a directory source at a fixed path stays Fresh (M-12).
4. **The typed fields don't cover in-the-wild needs:**
   - a remote mirror (`replace-with` a sparse registry);
   - private registries with a credential;
   - a faster linker.

   Without these, OD-1's full coding agent can't build a corporate project.
5. **Toolchain files.** If the exec allowlist resolves `cargo` to a rustup proxy, a workspace `rust-toolchain.toml` switches toolchains (AQ-215 F-3). The header then names the wrong toolchain.

**Better.**
- **Keep the typed fields,** and record reasons (a)-(d) instead of "config can run programs".
- **An invariant plus an FT:**
  - From `/` down to the workspace, scratch, target dir and `CARGO_HOME`, as the sandbox sees it, no directory holds a readable `.cargo/config` or `.cargo/config.toml` except the generated one. Remember that the extensionless legacy name wins when both exist.
  - §6.3's "temp" is `scratch/tmp` only; never grant the system temp dirs.
- **Stable paths, fresh content** (in-the-wild only). On Linux, mount the attempt's `CARGO_HOME` and the crate set at constant in-namespace paths. On macOS and Windows, use a fixed host slot path under the INV-41 lock.
- **H4 typed additions:**
  - `registry_mirror`: a sparse URL, allowlisted in the proxy;
  - `private_registries`: a URL plus a credential handle;
  - `linker`: an exec-allowlisted absolute path.
- **Get crates without breaking the trifecta.** The harness itself runs `cargo fetch --locked` before the agent's session. The lockfile fixes the content, so no egress is agent-controlled.
  - The results go into a harness-owned store, checked against the lockfile checksums (cargo will not re-check them), and served read-only.
  - That is Codex cloud's pattern: a setup phase with internet, then an agent phase without (https://learn.chatgpt.com/docs/cloud/internet-access). Claude Code on the web and Devin reuse a post-setup snapshot the same way (https://code.claude.com/docs/en/cloud-environments, https://docs.devin.ai/onboard-devin/environment).
  - Codex CLI's local answer is the opposite: rerun outside the sandbox after approval (PR #13051). §6.1 forbids that here.
  - A crate the agent adds mid-run is still agent-chosen egress (the name can carry data), so that stays with H4's safe path (D26).
- **Pin toolchain binaries by absolute path,** never the rustup proxy.

**Verdict: KEEP** the decision. Fix the rationale, and add the ancestor invariant, the fixed-path option and the H4 typed fields. **Confidence: high.**

---

## P2: the user's build tooling, and a harness-owned compile cache

**Restate.** The user's ambient `RUSTFLAGS`, compiler wrappers and sccache never reach confined builds. Instead the harness builds its own poisoning-safe compile cache, read-only to the agent and written only by trusted builds.

**Prior art.**
- **Environment inheritance.** Claude Code and Codex CLI inherit the parent environment by default (P1 above). So a user's `RUSTFLAGS`, `RUSTC_WRAPPER` or `CARGO_HOME` reach the agent's builds; this is inferred, because neither's docs name these variables.
  - Codex drops only names containing KEY, SECRET or TOKEN.
  - Claude Code has no built-in deny list.
  - Gemini CLI's environment redaction is off by default.
- **Cursor** can grant writable "shared build caches" (https://cursor.com/docs/agent/security/run-modes). That is the pattern this review argues against.
- **Claude Code on the web, Codex cloud and Devin:** a trusted setup phase builds the environment, which later sessions start from as a snapshot or cache (links in P1). That is the seed pattern proposed below.

**sccache** (https://github.com/mozilla/sccache/blob/main/docs/Rust.md, https://github.com/mozilla/sccache/blob/main/README.md):
- It cannot cache bin, dylib, cdylib or proc-macro crates, or incremental builds.
- Its own docs warn that proc macros reading files may be cached wrongly.
- Env deps are hashed verbatim (https://github.com/mozilla/sccache/issues/2870).
- Its docs give no guidance on cache trust. An issue open since 2020 asks how to stop clients poisoning a server's cache (https://github.com/mozilla/sccache/issues/845).
- Backends can be made read-only since v0.16 (https://github.com/mozilla/sccache/blob/main/docs/Configuration.md).

**Bazel** (https://bazel.build/remote/caching):
- Let only CI write to the remote cache; developers read, with `--remote_upload_local_results=false`.
- An action-cache entry is a claim about an action. Only CAS bytes are checked against their hash; the REAPI spec says servers must not trust client digests (https://raw.githubusercontent.com/bazelbuild/remote-apis/main/build/bazel/remote/execution/v2/remote_execution.proto).
- Bazel's only remedy for poisoning is a clean cache.

**GitHub Actions:**
- Branches are the security boundary (https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/).
- The Ultralytics releases of Dec 2024 were compromised through a poisoned build cache (https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/).
- GitHub made untrusted triggers read-only for the cache in June 2026 (https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers/).

**Nx CREEP, CVE-2025-36852:**
- In bucket-based caches, the first writer of a key wins everywhere (https://nx.dev/blog/cve-2025-36852-critical-cache-poisoning-vulnerability-creep).
- Nx says the flaw is in the design and cannot be patched; those packages are deprecated (https://nx.dev/docs/reference/deprecated/self-hosted-cache-packages).
- The fix: PRs read but never write, and each gets its own namespace.

**Signing and verification elsewhere:**
- **Turborepo:** HMAC-signed artifacts, which its own reference calls integrity, not security (https://turborepo.dev/docs/reference/configuration).
- **Nix:** unsigned input-addressed paths are refused by default, and content-addressed paths verify themselves (https://nix.dev/manual/nix/latest/command-ref/conf-file.html; RFC 62).

**Standards:**
- **SLSA v1.2 Build L3:** no build may be able to inject entries into a cache that another build uses (https://slsa.dev/spec/v1.2/build-requirements).
- **Gradle:** CI fills the cache from clean builds; developers only load (https://docs.gradle.org/current/userguide/build_cache.html).

**Cargo's own shared cache:**
- It is scoped to immutable registry and git packages and to units with no build script and no proc-macro dependents. It lands on nightly first.
- Sources: https://github.com/rust-lang/cargo/issues/5931, https://goals.rust-lang.org/2024h2/user-wide-cache.html and https://goals.rust-lang.org/2026/cargo-cross-workspace-cache.html.

**cargo-chef** builds dependencies only, from a recipe of manifests and the lockfile (https://github.com/LukeMathWalker/cargo-chef).

**Attack.**
1. **Refusing the ambient build environment is right.**
   - It follows from §5.5's built environment and AQ-209's lesson (allowlist, not denylist).
   - "Refuse all" hurts only at the edges: a faster linker, `target-cpu`, or a `--cfg` that a repo expects from the environment.
   - Most project needs live in the repo's own `.cargo/config.toml`, which cargo still reads for the agent's builds. OQ-2's closed `-C` grammar covers the rest.
2. **Cargo stores artifacts keyed by their inputs, with no integrity check** — like Bazel's action cache, not its CAS. Whoever writes an entry decides what later builds run; FT-25 already has the agent forging fingerprints.
   - "Written only by trusted builds" therefore needs a trusted build that excludes all agent-influenced code.
   - Compiling the agent's workspace runs its build scripts and proc macros in the same cargo process, alongside dependency compilation, with write access to the whole target dir (https://doc.rust-lang.org/reference/procedural-macros.html, https://doc.rust-lang.org/cargo/reference/build-scripts.html). No build of agent code can be a trusted writer; that is SLSA's rule.
   - A trusted build must be deps-only, cargo-chef style, and must refuse path and git dependencies, `[patch]`, `paths`, `[replace]`, the workspace `.cargo/config*` and member build scripts. The agent's recipe then *selects* trusted artifacts but never shapes their content.
3. **Per-compilation caching, sccache style, cannot be made sound for Rust.** A proc macro can read files and environment that no cache key records. sccache's own docs say such crates may be cached wrongly, and its env-dep hashing has open gaps (#2870).
4. **Cargo is building this feature, with exactly these restrictions** (#5931, the 2026 cross-workspace cache goal). A harness cache now would be a second one, soon superseded.
5. **An automatic cache hurts the benchmark.**
   - Build time comes to depend on task order.
   - A component whose bugs change scores enters the pipeline.
   - rustybenchmark already has the right thing: a template pre-built at setup and cloned per task and per grade (plan §3.2).
6. **Any cache the agent may write that outlives a session** — the "per-workspace cache the agent may write, never used for checks" alternative — **is unsafe in two ways:**
   - **Persistent injection.** The next session's build output is whatever the last session stored. M-T4-2 printed a forged "ignore previous instructions" warning, and real warnings can be hidden too.
   - **A trifecta split across sessions.** A P ∧ U session with no E writes private data into the cache. A later U ∧ E session, with a public workspace and egress, reads it. INV-9 checks one session at a time and cannot see this unless the cache's P label is *sticky*.
   - The same hole exists for any read-write root declared `public: true` (C5). I flag it to the confinement-inputs reviewer.

**Better.**
1. **Keep refusing the ambient environment.** Add OQ-2's closed grammar:
   - allowed flags: `-C` `opt-level`, `debuginfo`, `codegen-units`, `lto`, `panic`, `overflow-checks`, `debug-assertions`, `target-cpu`, `target-feature`, `force-frame-pointers`, `strip` and `split-debuginfo`;
   - never allowed: `linker`, `link-arg(s)`, `llvm-args`, `passes`, `profile-*`, `-L`, `-l`, `-Z` or `--cfg`;
   - plus a typed `linker` limited to an exec-allowlisted absolute path.
2. **Replace "harness-owned cache" with trusted seeds (H2).** A typed `cargo.target_seed` names a read-only root.
   - At each attempt start the harness clones it copy-on-write into `scratch/target`:
     - macOS: `copyfile`/`clonefile`;
     - Linux: overlayfs over the seed where the backend has a mount namespace, else a reflink on XFS/btrfs, else a copy;
     - Windows: block cloning on ReFS/Dev Drive, else a copy.
   - Every check gets its own fresh clone (P4).
   - M-T4-1 shows a clone at a new path stays Fresh; M-T4-3 shows it takes 1.8 s for 2.6 GB on APFS.
   - No run ever writes the seed. The header records its identity, its survey digest and any verified digest.
3. **Later, a trusted seed builder** for in-the-wild speed.
   - `rustyharness seed build` runs a deps-only build from the lockfile, in its own confined job, with no agent input.
   - Each run writes a new immutable seed, keyed by toolchain, target, profile and flags, and the crate-set or lockfile digest.
   - This is the Bazel and SLSA write discipline. Adopt cargo's cross-workspace cache when it ships rather than keeping two.
4. **Two things never to do:**
   - sccache with a persistent directory inside the sandbox;
   - an agent-writable cache shared across sessions, unless its P label is sticky, it is opted into per workspace, it is recorded in the header, and it is never used for checks.

**Verdict: MODIFY.**
- Keep the refusal.
- Replace "build a harness-owned compile cache" with trusted seeds cloned per attempt (H2) and a trusted deps-only seed builder later.

**Confidence: medium-high.** The seed design rests on M-T4-1; Linux clone cost and overlay behaviour are UNVERIFIED until S-C1 and S-L1.

---

## P3: resume with writable extra folders

**Restate.** A crashed run with writable extra folders may be resumed if those folders are declared "cache": the harness wipes them and they are rebuilt. Any other writable folder refuses resume.

**Prior art.** No harness manages build caches on resume, and every one that documents resume restores the conversation, not the workspace.
- **Claude Code** (https://code.claude.com/docs/en/sessions, https://code.claude.com/docs/en/checkpointing):
  - Resume restores the conversation, not the workspace or background tasks.
  - A tool still running at the crash is not re-run.
  - Checkpoints are pre-edit copies of files that Claude's own tools changed; Bash changes are not tracked.
- **Codex CLI** (https://learn.chatgpt.com/docs/developer-commands?surface=cli):
  - `codex resume` continues the rollout; restoring the workspace is not documented (UNVERIFIED).
  - Its ghost-commit undo was removed after runaway disk use (https://github.com/openai/codex/pull/19481, https://github.com/openai/codex/issues/19588).
- **Cline and Roo Code** (https://docs.cline.bot/core-workflows/checkpoints, https://roocodeinc.github.io/Roo-Code/features/checkpoints):
  - They snapshot to a shadow git repo after or before each tool use; restoring files is an explicit user action.
  - Interrupted Cline runs have left the user's `.git` renamed (https://github.com/cline/cline/issues/5598).
- **Gemini CLI** (https://geminicli.com/docs/cli/checkpointing/): shadow git, off by default. `/restore` reverts files and the conversation and re-proposes the tool call instead of re-running it.
- **OpenHands SDK** (https://docs.openhands.dev/sdk/guides/convo-persistence):
  - It appends an event log with one file per event, and states that state survives a crash.
  - The workspace is not part of the persisted state.
  - Resume refuses an ID mismatch and requires the same tools.

**Attack.**
1. **Wiping breaks two of the draft's own boundaries.**
   - C6/2.7 say the harness never creates, resets, cleans or deletes a read-write root (cd:25, cd:311).
   - gc's safety rests on the harness deleting only under `state_root` (INV-42).
   - P3 makes the harness a recursive deleter of an embedder-owned directory outside `state_root`, with none of gc's locality, tamper or mount checks designed for it.
2. **The directory may no longer be the declared one.**
   - On macOS the agent can `rmdir` a granted root and put a symlink in its place (F-8).
   - A wipe must open the root with `O_NOFOLLOW` and match the recorded device and inode.
   - It must unlink FIFOs and sockets and never open them (AQ-209).
3. **Survivors.**
   - After a crash on macOS, the old attempt's processes may still be writing the cache: no kernel mechanism kills them when the harness dies (ab 5.10). The run lock (P7) was released at the crash.
   - A wipe races them, and a survivor can refill the "clean" cache with forged artifacts (the FT-25 class) before the resumed attempt builds.
   - The wipe is sound only after the old run's kill domain is confirmed empty.
4. **Wiping to empty is the wrong reset for rustybenchmark's cache,** a clone of the pre-built template. The resumed attempt rebuilds every dependency cold: a large timing jump inside one run.
5. **Resume is the wrong tool for the benchmark.**
   - A resumed task splices two trajectories: a cold KV cache, a wall-clock gap and a catch-up replay. It is not comparable to an uninterrupted run.
   - The plan already recovers by skipping finished units (plan §3.1). So P3 buys the FYP nothing.
   - In the wild its main user would be the harness's default `scratch/target`, which a new attempt already gets fresh.

**Better.**
- **Replace "embedder root declared cache" with P2's seed clones.** Resume opens a new attempt, and the new attempt gets a fresh clone of the seed, taken after the kill-domain check. Nothing is wiped, and nothing outside the harness's own directories is ever deleted.
- **Every other read-write root keeps refusing resume** (OQ-6's default).
- **rustybenchmark retries crashed tasks from scratch** and never calls `resume`.
- **Resume still needs, independently of P3:**
  - snapshot content (K-2; see the snapshot answer below);
  - never repeating a completed write (the H2 condition);
  - survivors confirmed gone.

**Verdict: REPLACE** with harness-made clones per attempt from read-only seeds. Embedder read-write roots refuse resume. **Confidence: high.**

---

## P4: a warm cache for the harness's own checks

**Restate.** The harness's checks (H3) may start from a warm build cache only if the app supplied it, it is read-only, and the agent never wrote it. Otherwise they build from nothing (INV-40, OQ-5).

**Prior art.**
- **SWE-bench harness:**
  - It builds base and environment images from the task spec, never from model output, and caches them (`--cache_level`, default `env`) (https://www.swebench.com/SWE-bench/reference/harness/, https://www.swebench.com/SWE-bench/guides/docker_setup/).
  - Each evaluation runs in a fresh container that is removed in a `finally` block; the patch is copied in and applied (https://raw.githubusercontent.com/SWE-bench/SWE-bench/main/swebench/harness/run_evaluation.py).
  - This is P4's pattern exactly: a trusted seed, a fresh copy per evaluation, never written back.
- **Bazel:** developers read, CI writes (https://bazel.build/remote/caching).
- **GitHub Actions:** release builds should not restore caches that untrusted code could write (Khan, above; https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching).
- **Nx:** PR builds read but never write (https://nx.dev/blog/creep-vulnerability-build-cache-security).
- **Codex cloud and Claude Code on the web** start later sessions from state captured after setup: Codex caches the container state for up to 12 hours, and Claude Code reuses a filesystem snapshot (links in P1). Again a trusted seed. Whether an agent session can write back into that cached state is UNVERIFIED.

**Attack.**
1. **"Read-only cache" cannot mean what it says for cargo.** A read-only target dir fails at the build lock (M-T4-1). So the mechanism has to be "a read-only seed cloned into the check's fresh target dir" — OQ-5's option — and the decision should say so.
2. **"The agent never wrote it" must hold across runs, not only this one.** The same directory could be a read-write root in run A and a check seed in run B. L8/H3 stop that only within one run.
3. **Landlock alone does not make a seed read-only on Linux.**
   - Landlock cannot restrict `chmod`, `chown`, `utime` or `setxattr` (https://docs.kernel.org/userspace-api/landlock.html). OI-38 found exactly that residual.
   - A seed readable only through Landlock can have its mtimes rewritten, and cargo's freshness for path packages is mtime-based.
   - It needs a read-only bind mount, which gives `EROFS` (the draft's §2.3 does this). Any future Landlock-only backend, like AQ-208's, must not host seeds.
4. **Seeds that contain workspace-member artifacts are fragile.**
   - A moved workspace that keeps its times stays Fresh (M-T4-1). A member artifact in a seed is correct only if every file the diff changed gets an mtime newer than the seed.
   - That holds when the harness writes the grading worktree, but it is a subtle invariant. Level 3 templates pre-build the codebase's own crates (plan §5.3), so it will be relied on.
5. **Standalone CLI users get cold checks.** "App-supplied" leaves them without a warm path unless the task file can name a seed. Repair rounds multiply the cold builds.

**Better.**
- State the mechanism: a seed, CoW-cloned per check (P2 Better 2).
- Refuse a seed whose identity, or an ancestor's or descendant's, was ever declared read-write on this `state_root`.
  - The `locks/rw-*` files already record those identities, so keep an append-only history of them (see gc on F-20).
  - Key that history by device, inode *and* birth time, because inode numbers get reused.
- Require read-only mounts for seeds.
- Prefer deps-only seeds. Where members must be pre-built, pin the mtime invariant with a test: a diff-changed member must rebuild.
- Expose `cargo.target_seed` in the task file.

**Verdict: KEEP,** with the mechanism made explicit and the cross-run rule added. **Confidence: high.**

---

## P13: should `replay` check `state_root` locality?

**Restate.** Audit replay should refuse a `state_root` not positively identified as local, like `run` and `resume` (OPEN-QUESTIONS item 2; memo 2A).

**Prior art.**
- **Agent harnesses:** no harness checks the filesystem under its session store. The stores are:
  - Claude Code: `~/.claude/projects` (https://code.claude.com/docs/en/sessions);
  - Codex: `~/.codex/sessions` (https://github.com/openai/codex/issues/21660);
  - Gemini CLI: `~/.gemini/tmp` (https://geminicli.com/docs/cli/session-management/);
  - Goose and opencode: SQLite databases.

  None of these docs mentions such a check. That none exists is UNVERIFIED beyond the docs.
- **SQLite:** locks on network filesystems, NFS in particular, do not behave as advertised, and WAL does not work over a network filesystem (https://sqlite.org/howtocorrupt.html, https://sqlite.org/wal.html).
- **Cargo:** skips **all** file locks on NFS, because `flock` there can block forever even when asked not to (https://doc.rust-lang.org/nightly/nightly-rustc/src/cargo/util/flock.rs.html). It chose availability; rustyharness chose refusal.

**Attack.**
1. **Locality protects writers: the single-writer lock and fsync durability (§2.8).** Audit's only write is a derived journal in `replay-<k>/` that nobody needs to be durable. Checking it buys consistency, not safety.
2. **The rule blocks legitimate readers.** Auditing archived evidence on a NAS or read-only media means copying it to a local disk first. That matters for P14: a leaderboard's archived journals should be auditable where they are stored.
3. **Readers do gain one thing: protection from hangs.**
   - A dead hard-mounted share blocks reads in the kernel. The macOS probe never touches a network mount (row H1e-2c), so it refuses before any hang.
   - That is the AQ-209 lesson in another form: a blocking read stalls an embedder's pipeline.
4. **`replay-<k>/` accumulates.** gc keeps it (cd:369) and nothing removes it.

**Better.**
- **Accept (A) now:** it is cheap and fits the H1 phase-exit fixes.
- **Before any archival or leaderboard work, move to option C:**
  - Audit writes nothing under `state_root`. The recomputed journal goes to a directory the caller chooses, or is written only on divergence.
  - Audit then becomes a pure reader: it works on read-only archives and leaves nothing for gc.
- **The general rule:**
  - Every verb that writes or deletes under `state_root` checks locality: `run`, `resume`, `gc` and the future `reproduce`.
  - Readers check file types before opening (regular files only; AQ-209). They may run the probe as a hang guard that warns rather than refuses.

**Verdict: MODIFY.** Yes now; then make audit a pure reader and scope the rule to writers and deleters. **Confidence: medium-high.**

---

## P14: deleting run journals

**Restate.** The harness never deletes journals. An explicit retention policy is designed before any public leaderboard (§11 "default: keep"; cd OQ-10).

**Prior art.**
- **Claude Code** deletes sessions, file-history snapshots and tool results after `cleanupPeriodDays` (https://code.claude.com/docs/en/claude-directory).
  - The default is 30 days and the minimum 1.
  - `0` is now rejected; it used to disable persistence silently (https://github.com/anthropics/claude-code/issues/41800).
  - `claude project purge` deletes on demand.
- **Gemini CLI:** `general.sessionRetention` is on by default, with a 30-day maximum age and a 1-day minimum (https://geminicli.com/docs/reference/configuration/).
- **Codex CLI:**
  - `history.persistence` and `history.max_bytes` bound the prompt history (https://learn.chatgpt.com/docs/config-file/config-reference).
  - Session rollouts have no documented expiry; one user reports a 91 GB sessions directory (https://github.com/openai/codex/issues/24948).
  - Rollouts are created world-readable, 0644 (https://github.com/openai/codex/issues/21660).
- **Cline, Goose, opencode and Aider:** no documented expiry; each has explicit delete commands.
  - opencode rejected an automatic session prune (https://github.com/anomalyco/opencode/issues/22110) but prunes its snapshot store after 7 days.
- **SWE-bench:** a leaderboard submission must publish logs and trajectories in a public repo, and verification re-derives every verdict from them (https://github.com/SWE-bench/experiments/blob/main/README.md).
- **Terminal-Bench 2.0:** submissions carry full job directories and at least five trials (https://huggingface.co/datasets/alexgshaw/terminal-bench-2-leaderboard).

**Attack.**
1. **Two mainstream harnesses default to 30-day expiry; rustyharness keeps everything forever.** For a standalone user, journals hold:
   - private code excerpts (`fs.read` results; diffs as blobs);
   - anything secret the agent read (redaction covers only resolved handles and canaries, §5.5);
   - usernames in canonical root paths;
   - host facts.

   All of it sits in a user data directory that backups copy.
2. **"Before any public leaderboard" is too late.** Journals leave the machine earlier: FYP appendices, the supervisor, the benchmark's results database.
3. **Redaction fights the hash chain.**
   - An inline untrusted payload of up to 4 KiB sits inside the chained line (§7.1). A path containing a username cannot be withheld without breaking verification.
   - A blob payload can be withheld while the line still verifies. Publishable journals need host-identifying and private text in blobs.
4. **OQ-10 leaves bounding disk to the embedder,** deleting `runs/<id>` by hand. That bypasses every gc safety rule and leaves no record that the evidence existed.
5. **Early deletion destroys the evidence of gaming.** AQ-218's point is that excluded or retried rows can be gamed, and the evidence is the journal of the crashed or retried attempt. A policy that deletes "infrastructure" runs early destroys exactly that.

**Better.**
- **Keep "no automatic deletion of evidence"** as the default.
- **Build the deletion path into gc now,** so nobody hand-rolls `rm -rf` in `state_root`:
  - **`--purge-payloads`** removes blobs and snapshot content. Journal lines and digests stay, and audit then reports "payloads purged" rather than a divergence.
  - **`--purge-run`** removes the whole run and leaves a hash-chained tombstone in `state_root/tombstones.jsonl`: run id, final chain head, header digest, reason and time.
  - Both apply to finished runs only, and both dry-run first.
- **Write the retention and publication policy before the first journal is shared.**
  - Benchmark evidence lives for its results epoch, with chain heads in the results database.
  - Retried and crashed attempts are kept next to the final one.
  - Host-identifying text goes to blobs only, and an `export --redact` withholds those blobs while the journal still verifies.
- **In the wild,** offer an opt-in `retention.max_age` that drives the same purge path, for parity with Claude Code and Gemini CLI. It is off by default.

**Verdict: MODIFY.** **Confidence: medium.** The privacy default is the owner's call; the purge path and the earlier deadline are not optional.

---

## gc (OD-5d)

**Restate.** gc removes `workspace/`, `grading/` and `scratch/` from every attempt of a *finished* run, and nothing else. A run is finished when:
- its latest attempt's journal verifies and ends in `RunStopped`;
- its run lock, if any, is free.

It also:
- removes interrupted runs only with `--interrupted`, and only once the lock exists;
- dry-runs by default;
- writes a hash-chained intent/done record;
- refuses tampered layouts;
- causes a later resume to be refused (cd:27-29, §3).

**Prior art.**
- **Cargo 1.88** cleans `$CARGO_HOME` automatically by last-use age: 3 months for downloads, 1 month for local files (https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/). Build artifacts are not tracked yet.
- **git gc** relies on a grace period (`gc.pruneExpire`, two weeks), not proof of liveness. Its docs admit that concurrent users carry some risk of corruption (https://git-scm.com/docs/git-gc).
- **docker system prune** asks for confirmation unless `--force`, keeps volumes by default, and offers an `until` filter (https://docs.docker.com/reference/cli/docker/system/prune/).
- **SWE-bench** removes each container in a `finally` block and trades disk for speed with `--cache_level` and `--clean` (above).
- **Claude Code** sweeps sessions and checkpoints at 30 days; **opencode** prunes its snapshot git after 7 days (above).
- **Codex** removed its per-turn ghost commits after they filled users' disks (https://github.com/openai/codex/issues/19588).

**Attack.**
1. **"Finished" trusts `RunStopped` for process liveness.** It is safe only where the kernel kills the tree when the harness dies:
   - **Linux with a PID namespace:** safe. When the namespace's init exits, every member gets SIGKILL (https://man7.org/linux/man-pages/man7/pid_namespaces.7.html).
   - **Windows with a job set to `KILL_ON_JOB_CLOSE`:** safe, except that processes created through WMI never join the job (https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects). Whether AppContainer blocks that route is UNVERIFIED (review F-18); S-W1 should test it.
   - **macOS:** unsafe.
     - `RunStopped{Indeterminate}` follows `ProcKillUnconfirmed` (F-6).
     - Under D21's fallback, a `setsid` survivor that the process-group kill missed is not even detected, so `RunStopped` looks clean.
   - **Linux without PID namespaces:** unsafe. rustybenchmark had to build exactly that backend (systemd scope plus Landlock) because Ubuntu 24.04 blocks unprivileged user namespaces (AQ-208; https://documentation.ubuntu.com/release-notes/24.04/). If rustyharness ever answers F-25 the same way, survivors outlive the harness unless the cgroup is killed.
   - **The run lock (P7) fixes none of these.** `File::lock` is released when the last handle closes (https://doc.rust-lang.org/std/fs/struct.File.html). The harness's handle closes on exit while survivors keep running.
2. **A failed attempt start blocks gc forever.**
   - H1 phase-exit F-5 found that a failed start leaves an empty `attempt-<n+1>`.
   - `latest_attempt` picks the highest number whether or not it has a header (layout.rs:125-134). So such a run is never "finished", its disk is never reclaimed, and it cannot be resumed either.
3. **gc does not bound `state_root`.** It never touches:
   - one `locks/rw-<dev>-<ino>.lock` per task (rustybenchmark re-clones every task; F-20);
   - one `replay-<k>/` per audit;
   - every `gc-<k>.jsonl`;
   - the journals and blobs.

   For an embedder running thousands of tasks the growth is linear. OQ-10's answer, hand deletion, bypasses gc's safety rules.
4. **A survivor can bring a removed tree back.** With a `subpath` write grant, a macOS survivor can re-create `workspace/` after gc removes it. `rmdir` and a symlink on the root were measured in F-8; `mkdir` is the same operation class. gc then reports "removed" and the tree reappears. F-8's `literal` deny closes this too.
5. **Cross-uid deletion is coming.** OI-38 moved rustybenchmark's grader to its own user, and F-2 option B proposes the same for the agent. Once confined files belong to another uid, a gc run as the owner cannot unlink entries in a directory that uid owns with mode 0755. It needs a default ACL granting the harness user delete rights, or deletion as that uid.
6. **Performance is not a problem.** Removing a 2.6 GB, 8,878-file tree takes under 1 s on APFS (M-T4-3); Linux is UNVERIFIED.

**Better.**
- **A sound "finished" test.** A run is finished when all of these hold:
  - the latest attempt *with a durable header* ends in `RunStopped` with `procs.unconfirmed == 0`, and there is no `ProcKillUnconfirmed`;
  - later attempts without a header are empty and are removed with the run;
  - the run's kill domain is **confirmed empty at gc time**:
    - macOS: the run-marker sweep, about 26 ms (F-1);
    - Linux: nothing to do with a PID namespace; with a cgroup, `cgroup.events` must show `populated 0`, or gc uses `cgroup.kill` (https://docs.kernel.org/admin-guide/cgroup-v2.html);
    - Windows: the job is empty.

  Where no such check exists (macOS under D21's fallback), gc refuses unless the caller passes an explicit `--accept-unswept`, and the record says so.
- **Split the phases.** gc of *finished* runs ships in H2 without P7; `--interrupted` waits for P7 plus the kill-domain check.
- **Reap what accumulates:**
  - lock files that gc can lock exclusively and whose identity no longer exists, keeping the identity list that P4's cross-run rule needs;
  - `replay-<k>/`, or drop it entirely via P13's option C.
- **Add P14's purge tiers,** and apply F-8's `literal` deny to every writable root node.
- **Plan for another uid:** a default ACL on attempt directories before any agent uid differs from the owner.

**Verdict: MODIFY.** **Confidence: high.** Everything else in the draft is sound, and the review agreed: grammar-only names, a real layout, durable intent, and no effect on audit.

---

## rustybenchmark's one-slot reset cycle (plan §3.1)

**Restate.** One slot runs one task at a time, in eight steps:
1. Reset, also at start-up.
2. Load the task.
3. Agent loop.
4. Kill the slot's process group and check the ports are free.
5. Keep only the source.
6. Hidden tests, rebuild, grade.
7. Write the journal.
8. Repeat.

rustyharness covers steps 2-4; the reset uses harness gc (contract H-5).

**Prior art.** Every major evaluation harness resets with containers, which D10 rules out here.
- **SWE-bench:** a fresh container per instance, removed in `finally`; cached base and environment images (above).
- **mini-SWE-agent:** Docker with `--rm` by default (https://mini-swe-agent.com/latest/reference/environments/docker/).
- **OpenHands:** cleans up its Docker sandbox when done (https://docs.openhands.dev/sdk/guides/agent-server/docker-sandbox).
- **Terminal-Bench 2.0 on Harbor:** per-task environments with a network mode (default public) and nftables allowlists (https://docs.harborframework.com/core-concepts/tasks/configuration.md, https://docs.harborframework.com/core-concepts/tasks/network-policies.md). Teardown details are UNVERIFIED.
- **Devin, Codex cloud and Claude Code on the web:** every session starts from a snapshot (links in P1).

The native equivalents are a CoW clone or an overlay (the reset) plus a confirmed kill domain (the teardown).

**Attack.**
1. **Step 4's process-group kill misses `setsid` descendants,** and after a harness crash nothing runs at all (M-5; D21).
   - Survivors are a safety problem.
   - They also spoil the plan's own "cleaner timing" goal: they compete with the next task for CPU and memory, and that shows up in *model* time.
2. **Step 4's port check gives false alarms.** A bind without `SO_REUSEADDR` fails for about 31 s after a server-first close (M-8, F-4). A surviving holder keeps the listener (F-5).
3. **Step 1's crash clean-up needs gc of *interrupted* runs,** which needs P7 plus the kill-domain check. Until then the benchmark must not delete inside `state_root` by hand.
4. **Retried or resumed?** The contract says infrastructure failures are "retried or resumed" (contract:173). A resumed task is a spliced trajectory (see P3). Retry.
5. **The infrastructure bucket can be gamed.** This is AQ-218's principle, and AQ-208 r3 already applies it to breaches and timeouts. Contract §4.2 books `ModelUnavailable`, `SandboxLost`, `Cancelled` and `JournalUnavailable` as infrastructure, never a model failure. The agent can cause three of them:
   - **`SandboxLost`:** its own `setsid` daemon leaves the kill unconfirmed (ab 5.7).
   - **`JournalUnavailable`:** it fills the disk through a read-write root that has no total-size cap (cd:316).
   - **`ModelUnavailable`:** it applies memory pressure on a 24 GB unified-memory Mac, where memory limits are unreliable (plan §3.2).

   Each turns a failing task into a retry or an excluded row.
6. **The watchdog must be unsignalable from inside the slot.**
   - OI-38's same-user `SIGSTOP` froze rustybenchmark's watchdog.
   - rustyharness is safe on Linux through the PID namespace and on macOS through `(target same-sandbox)` signal rules (M-6: `EPERM` to an unsandboxed sibling). Neither is tested yet as "`SIGSTOP` the harness".
7. **The "fixed disk footprint" covers only the slot.** `state_root` grows per task: the journal, blobs, snapshots (more once K-2 stores content), gc records, replays and lock files (gc item 3).
8. **Clone cost depends on the filesystem.**
   - APFS: a clone plus delete costs about 2.5 s per 2.6 GB template (M-T4-3).
   - The Linux GPU PC on Ubuntu's default ext4 has no reflink (ext4 has no remap operation: https://raw.githubusercontent.com/torvalds/linux/master/fs/ext4/file.c). Every "clone" becomes a full copy: about 2.6 GB written per clone, two clones per task, roughly 5 TB per 1,000 tasks.
9. **Two benchmark processes can wreck one slot.** The harness's read-write-root lock (INV-41) is taken only *after* the benchmark has reset and cloned. A second, stale instance can wipe a live slot.
10. **Crash timing matters.** If the benchmark crashes after the agent finished but before grading, re-running the agent wastes model time and samples the task twice. The harness keeps the deliverable blob, so re-grading is enough.
11. **The dedicated grading user makes the reset harder** (OI-38). An owner-run reset cannot delete a tree that the grading uid created under 0755 directories.
12. **The agent slot needs AQ-215's fix too.** §6.3's "temp" grant (see P1) must not be the system temp dirs.

**Better.**
- **Take a slot lock** before step 1, and hold it through reset, run and grade.
- **Replace the benchmark-side group kill** with the harness's confirmed stop (INV-50) plus the run-marker sweep, and keep the port probe as a tripwire.
  - The grading slot, now under its own uid, gets a complete sweep for free: `kill(-1, SIGKILL)` run as that uid. Test it.
- **Port check:** probe with connect, then bind with `SO_REUSEADDR` (F-4).
- **Retry, never resume.** Cap retries per task at one, and publish the infrastructure-retry rate per model.
  - An infrastructure stop that coincides with an agent-attributable signal scores **0 with a flag**, as AQ-208 r3 does. The signals: an unconfirmed kill, a quota breach, a watchdog breach, or memory pressure in the environment sample.
- **Cap total disk for writable roots** (a harness watchdog), and treat a breach as the agent's.
- **Re-grade from the retained deliverable** after a benchmark crash.
- **Record the reset in every result row:** the sweep came back empty, the ports probed free, the slot identity is new, and the clone source digest.
- **On Linux,** put the slot on XFS or btrfs (reflink), or use overlayfs where the backend has a mount namespace (unprivileged since 5.11, https://kernelnewbies.org/Linux_5.11, but it needs the AppArmor profile on Ubuntu 24.04). Measure reset time on the GPU PC before the pilot.
- **Reset the grading slot as the grading user,** or give the owner a default ACL.
- **Add an FT:** `SIGSTOP` of the harness PID from inside the sandbox must fail.

**Verdict: MODIFY.** **Confidence: high.** One slot, one task, sequential grading and clean timing all stand; the steps around crashes, kills and ports need the changes above.

---

## Direct answers to the brief's questions

1. **Is refusing all user build tooling too hostile in the wild?** Mostly no.
   - The repo's own `.cargo/config.toml` still drives the agent's builds.
   - What users lose is ambient flags and wrappers. A closed `-C` grammar and a typed linker (P2) recover nearly all of it.
   - The real in-the-wild costs are elsewhere:
     - cold builds (fresh paths, P1 item 3);
     - no way to fetch crates under the trifecta rule (§5.4 says default sessions build offline from vendored dependencies).

   The fixes are seeds, fixed cargo paths, and a harness-run prefetch from the lockfile.
2. **Is a harness-owned cache worth its complexity?** Not as specified.
   - A cache written from agent builds cannot be trusted: build scripts and proc macros run with write access to the target dir.
   - A per-compile cache cannot be keyed soundly for Rust (see sccache).
   - An agent-writable per-workspace cache is a persistent injection channel (M-T4-2) and a cross-session trifecta leak.
   - Reusing `CARGO_TARGET_DIR` *is* the agent-writable cache.
   - Cargo artifacts are not content-addressed: their keys are inputs and their values unverified, like Bazel's action cache.

   The simple safe design is **read-only seeds, cloned copy-on-write per attempt and per check**. Seeds are made by a trusted builder that never compiles agent code, and later by cargo's own cross-workspace cache once it ships.
3. **Is resume with cache wiping sound?** No, for four reasons:
   - it deletes outside the harness's own directories;
   - it races macOS survivors after a crash;
   - it trusts a directory the agent may have replaced (F-8);
   - it turns a warm resume cold.

   A fresh seed clone per attempt is sound and cheaper.
4. **Is gc's "finished" test safe without the lock (P7)?**
   - **For finished runs:** yes on backends where the kernel kills the tree when the harness dies (a Linux PID namespace, a Windows job). The lock only adds protection against a concurrent resume, which a stopped run already refuses.
   - **On macOS:** no, and on a Linux backend without namespaces, no. The lock does not help either, because survivors outlive it. Check the kill domain at gc time instead.
   - **For interrupted runs:** P7 is required.
5. **Would CoW snapshots beat the journal-digest snapshots for resume and re-grading?** Neither alone. Digest-only snapshots cannot restore anything (K-2). Filesystem CoW snapshots:
   - are not portable (ext4 and NTFS have none; Apple discourages directory clones, https://developer.apple.com/forums/thread/784446);
   - are not bound to the journal;
   - multiply gc's hostile-tree problem;
   - cannot be read by the benchmark's journal reader.

   Store **content-addressed snapshot content in `blobs/`**. The manifest already holds each file's digest, so the change is: store each new digest's bytes. Take a snapshot after every step that can change the workspace: edits, `exec.run` (`cargo add` and `cargo fmt` rewrite files, F-23) and background-process boundaries.
   - Walk FIFO-safe: `symlink_metadata`; open with `O_NONBLOCK|O_NOFOLLOW` and check with `fstat`; cap size per file and per step (AQ-209).
   - This one store serves resume (§2.10), audit, survival after gc, and the benchmark's first-try and score-by-turn grading (contract §4.3).
   - Use CoW only to *materialise* from it quickly.

## Top changes I'd make

1. **Seeds, not caches.**
   - Add a typed `cargo.target_seed`, cloned copy-on-write into every attempt and every check.
   - This deletes P3's wipe and gives P4 its mechanism.
   - Build a trusted deps-only seed builder later, and adopt cargo's cross-workspace cache when it lands.
2. **Fix gc's "finished" test.**
   - Confirm the kill domain empty at gc time, and skip or remove attempts that have no header.
   - Ship gc of finished runs without P7; gate `--interrupted` on P7.
   - Reap lock files and replay dirs, and add the purge tiers with tombstones (P14).
3. **Resolve K-2 now** with content-addressed snapshot content after every step that can change the workspace, walked FIFO-safe. Resume, re-grading and life after gc all depend on it.
4. **Harden the reset cycle.**
   - Retry, never resume.
   - Score agent-caused infrastructure failures as 0 with a flag.
   - Take a slot lock.
   - Use the harness's confirmed stop plus the sweep instead of a group kill.
   - Probe ports with `SO_REUSEADDR`, and cap disk for writable roots.
   - Measure reset time on Linux ext4 before the pilot.
5. **Close the ancestor-config and temp channel in the harness,** AQ-215 in harness form: §6.3's "temp" means `scratch/tmp` only, with an invariant and an FT that nothing on the sandbox's path to cargo holds a readable `.cargo/config*`.
6. **P13 and P14 together.**
   - Audit writes outside `state_root`, and locality checks guard writers and deleters.
   - Write the retention and publication policy (blob-only host data, `export --redact`) before the first journal is shared, not before a leaderboard.

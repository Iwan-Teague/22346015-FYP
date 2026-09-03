# Decision register for the adversarial review (24 Sep 2026)

Owner: Iwan Teague. Every decision below is to be scrutinised: compared with how other major agent
harnesses handle the same question, attacked for failure modes, and improved or replaced if something
better exists.

**The owner's judging criteria:**
- long-term soundness
- security
- performance
- user experience
- speed of the project (the FYP needs Level 1 agent-mode results by mid-November 2026 and a Level 2 pilot
  by 23 Dec 2026)

**The owner's stance:** "I'm not afraid of doing more work now. I don't want to defer something just
because the better option is a big job."

## Context (read what your theme needs)

**rustyharness** is a standalone Rust agent harness at `rustyharness`.
- Read the design with `git -C rustyharness show origin/main:docs/01-design-v0.1.md`.
  The latest is at 4ad8847 and includes "Owner decisions after v0.2", OD-1..OD-7.
- Also read `origin/main:docs/OPEN-QUESTIONS.md` and `origin/main:README.md`.

**rustybenchmark** is a local-LLM Rust benchmark that embeds rustyharness.
- Plan: `proposal/measurement-plan.md`. §0 holds decisions D1–D33.
- Contract: `proposal/rustyharness-contract.md`.

**Design drafts and reviews** for the four new features (ports, background processes, app-supplied
confinement inputs, gc):
- `proposal/rustyharness-drafts/` holds both drafts and REVIEW-od5-delta.md.
- A reworked v2 is being written to `od5-delta-v2.md` in the same folder; it may not exist yet.

**Owner-questions memo:** `proposal/rustyharness-owner-questions-memo.md`.

**Facts measured on the owner's MacBook (macOS 26.5.1):**
- Seatbelt port-scoped bind rules can't keep a bind on loopback.
- A `setsid()` child escapes a process-group kill.
- `sandbox_check` membership (allow-marker + deny-marker) identifies exactly a run's processes. The
  sweep takes about 26 ms.
- Cargo fingerprints survive a new `CARGO_HOME` only with a directory source at a fixed path.

## Decided by the owner (review them anyway)

| ID | Decision |
|---|---|
| D4 | The agent works in a loop and ends by calling a submit tool; the loop re-prompts until then. Grading happens outside the harness |
| D10 | No VMs and no external container runtimes (Docker, Podman). Native OS sandboxing only: Linux namespaces + Landlock + seccomp, macOS Seatbelt, Windows AppContainer + Job Object. Reasons: a VM reserves RAM the local model needs, and it isn't how people run coding agents |
| D12 | One device: the model is served on loopback (llama.cpp, Ollama, vLLM, LM Studio), and the harness and code run on the same machine |
| D16 | The benchmark enforces one pinned rustyharness version; a new version starts a new results epoch |
| D17 | Everything used for grading or measuring lives in rustybenchmark, never in the harness |
| D18 | rustyharness stands alone as a full coding agent, like opencode or Cline, with every action behind permission and inside confinement. Suite integration comes as add-ons. The benchmark's "benchmark mode" is only a locked-down configuration passed through the embedding API: policy, a registry with only the built-in manifest, profile, and its own ModelBackend for timing |
| D21 | macOS cleanup: the corrected `sandbox_check` sweep (freeze, then kill) is built in H2. If it slips past about 1 Nov, the fallback is a dated, written acceptance of process-group kill for `exec.run` only |
| D22 | Every test, network tasks included, runs on Linux AND macOS, for anyone who downloads the app. Linux comes first; Windows is the long-term goal, not now |
| D24 | Tool packaging scales with model size through the per-model profile (`max_active_tools`, default 6 under 30B): smaller models get merged tools. Every model gets the same capabilities; packaging is recorded per run and checked by a pilot ablation |
| D26 | Private repo + online access: keep the trifecta rule (private + untrusted + egress in one session is refused), and build a safe path in H4, e.g. a quarantined reader model or dual-LLM, alongside the egress proxy |
| D27 | One shared confinement library for rustyharness and rustybenchmark's grading sandbox. It is staged inside rustyharness during H2 and moved to its own repo before the benchmark uses it |
| D28 | Build order: H2 gets app-supplied confinement inputs, gc and the macOS sweep. H2+ gets ports and background processes, designed and reviewed during H2 |
| D29 | Linux: one private network namespace per run, not per spawn, in H2 |
| D30 | A granted loopback port counts as egress (E) for the trifecta rule, because a browser could be steered to it (DNS rebinding) |
| D31 | Network-visible (LAN) ports: not in v1. They are designed now as a separate, high-risk opt-in grant |
| D32 | macOS network tasks: first a transparent socket swap. A harness-owned `DYLD_INSERT_LIBRARIES` interposer catches `bind()` on a granted port and `dup2`s a harness-pre-bound 127.0.0.1 listener into place, so models write normal server code. Fallback: a pf firewall anchor blocking the granted ports on non-loopback interfaces (admin once at install) |
| D33 | Linux kernels older than 6.7 (no Landlock network rules): allow any port inside the per-run private network namespace |

## Pending: current recommendation, not yet decided

| ID | Question | Current recommendation |
|---|---|---|
| P1 | May an embedding app supply its own cargo folder or config? | No. The harness generates cargo config from typed fields, because cargo config can run programs (runners, wrappers) |
| P2 | The user's RUSTFLAGS, compiler wrappers and sccache | Refuse all of them, and build a harness-owned, poisoning-safe compile cache (read-only to the agent, written only by trusted builds) |
| P3 | Resume after a crash when writable extra folders exist | Allowed if they are declared "cache": they are wiped and rebuilt. Other writable folders refuse resume |
| P4 | May the harness's own checks use a warm cache? | Only app-supplied, read-only caches the agent never wrote |
| P5 | macOS depends on Apple's deprecated `sandbox-exec` | Build the direct `sandbox_init` FFI path now, in the audited macOS crate already needed for the sweep |
| P6 | Windows | Run the S-W1 AppContainer spike during H2; ship the backend after Linux and macOS |
| P7 | Real file locks need Rust 1.89; the project targets 1.85 | Raise the MSRV to 1.89 and build the journal single-writer lock, the per-endpoint run limit and the gc run lock now |
| P8 | Runs per model server at once | 1 by default, configurable |
| P9 | Licence of `gate-outcome`, the shared outcome-type crate | MIT OR Apache-2.0; the rest stays PolyForm Noncommercial |
| P10 | May a hosted model see personal data? | No for v1 |
| P11 | May the harness ever hold "restricted" capabilities (the life-data app)? | Never, permanently |
| P12 | Independence of the built-in reviewer | Fresh context always; a distinct model when two or more are configured |
| P13 | Should `replay` check `state_root` locality? | Yes, the same as `run` and `resume` |
| P14 | Deleting run journals | Keep them; design an explicit retention policy before any public leaderboard |
| P15 | Windows ports; embedder limits | Windows ports stay off until its spikes pass; embedders may only lower limits, never raise them |

## Output format for every reviewer

For each decision in your theme:
1. **Restate:** the decision in one line.
2. **Prior art:** how 4–8 major harnesses handle it. Examples: Claude Code, OpenAI Codex CLI, opencode,
   Cline, Aider, Goose, OpenHands, SWE-agent/mini-SWE-agent, Gemini CLI, Cursor, Roo Code, Continue,
   Devin, Terminal-Bench's Terminus. Cite a source URL for each claim, and mark anything you couldn't
   verify from a current source as UNVERIFIED.
3. **Attack:** failure modes, hidden costs, security holes, performance or UX problems, schedule risk.
4. **Better:** improvements, or a completely different approach, with its trade-offs against the five
   criteria.
5. **Verdict:** KEEP, MODIFY (say how) or REPLACE (say with what), with a confidence level.

End with a short "Top changes I'd make" list for the owner.

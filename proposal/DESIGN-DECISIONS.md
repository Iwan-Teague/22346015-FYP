# Benchmark design decisions, 7 Sep 2026

Having explored all the options and deep-dived them with a GLM-5.3 agent — which
gathered the background research, drew up the option lists and pushed back on my first
instincts — these are the choices I settled on for the benchmark. Written up 12 Oct 2026
from my working notes of the 7 Sep session. The six decision reviews (T1–T6) then
examined them; where a review changed an answer, I took the revised options and re-ruled
(see SYNTHESIS.md).

## Scope and task design

| # | Question | My call |
|---|---|---|
| D1 | Should the benchmark test whether an agent can *build* things — a client–server pair, a web app, a dashboard? | I want builds in. They become their own task level (L2), graded through contracts |
| D2 | How does an agent deliver work? | It works in a loop and ends by calling a submit tool; a watchdog re-prompts until it does. Grading happens outside the harness |
| D3 | Tools and crates for the agent | Full toolchain. Crates are pre-built locally; the model picks the crates, and it can use any that are present. L2 gets a crates category |
| D4 | Task families | Keep the small tasks; add a large family of one-shot logic questions. Everything comes from a seed, with enough variation that no answer can be learned by heart. Each family has a range of difficulty |
| D5 | Timing data | Record prefill, reasoning and output speed. Capture OS, hardware and model automatically |
| D6 | Task levels | Three levels. L3 (changes to existing code) is official. The order of L2 families doesn't matter yet |
| D7 | What is "std, level 1"? | L1 tasks use Rust's standard library only, no crates |

## Execution environment

| # | Question | My call |
|---|---|---|
| D8 | Sandbox shape | One sandbox slot: run, grade, reset, next. It has the toolchain and crates, a few local ports and no internet |
| D9 | VMs or containers? | No VMs: a VM takes memory the model needs |
| D10 | One machine or two? | One machine: the model is served locally |
| D11 | OS for the GPU PC | Linux (RTX 3070 PC) |
| D12 | Platforms | Every test runs on Linux and macOS, for anyone who downloads the app. Linux first; Windows is the goal, not now |
| D13 | macOS process cleanup | Build the `sandbox_check` sweep in H2. If it slips past about 1 Nov, fall back to a dated, written acceptance |

## Harness and grading

| # | Question | My call |
|---|---|---|
| D14 | Which harness? | rustybenchmark enforces rustyharness, pinned to one version; a new version starts a new results epoch |
| D15 | Where does grading live? | All grading and measuring stays in rustybenchmark. The harness keeps only what makes an agent's code better |
| D16 | What is rustyharness? | A standalone harness like opencode or Cline, with suite extras as add-ons. "Benchmark mode" is a locked-down configuration passed through the embedding API |
| D17 | May the standalone harness go online (crates.io) and open ports? | Yes, each behind a permission |

## Confinement and network

| # | Question | My call |
|---|---|---|
| D18 | Private repo plus online access in one session | Keep refusing it (the trifecta rule). Build a safe path in H4 — a quarantined reader model — alongside the egress proxy |
| D19 | One confinement library or two? | One shared library, staged inside rustyharness during H2 and moved to its own repo before the benchmark uses it |
| D20 | Build order (H2) | H2: confinement inputs, gc, the macOS sweep. H2+: ports and background processes, designed and reviewed during H2 |
| D21 | Linux network isolation | One private network namespace per run, in H2 *(later revised: a systemd scope with Landlock and seccomp — see the spike notes)* |
| D22 | Does a granted loopback port count as internet access for the trifecta rule? | Yes (DNS rebinding) |
| D23 | Ports reachable from the LAN | Not in v1; designed now as a separate high-risk opt-in |
| D24 | macOS network tasks | A transparent socket swap first; fallback: a pf firewall guard |
| D25 | Linux kernels older than 6.7 | Allow any port inside the per-run private network |

## Model interface and observability

| # | Question | My call |
|---|---|---|
| D26 | Why limit how many tools the model sees? | Scale tool packaging with model size: smaller models get merged tools, every model gets the same capabilities. Packaging is recorded per run and checked in a pilot ablation |
| D27 | Context size | Log native, configured and used context size |

## Process notes

- I answered rounds 1 and 2 of the tick-box questions in one sitting; I stopped round 3 —
  "do not proceed, wait for next instruction" — and its questions stayed recommendations
  until I separately ruled on them.
- After my rulings, an adversarial review pass examined each one. Seven were confirmed
  unchanged; ten came back with amendments and I re-ruled on them. The outcomes are
  recorded in `decision-reviews/SYNTHESIS.md`.

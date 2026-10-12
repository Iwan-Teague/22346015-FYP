# 01 — Prior art and the gap

Figures gathered during the exploratory phase, August 2026. Sources at the bottom.

## Rust-specific benchmarks

| Benchmark | Size | Construction | Headline numbers |
|---|---|---|---|
| **Rust-SWE-bench** | 500 tasks, 34 repos | 87 Rust projects >1k stars, ~80k merged PRs scraped, filtered to PRs linked to issues and touching tests, Docker + cargo snapshot per PR, fail-to-pass validated, 3 independent human reviewers | Best agent (RustForger + Claude-Sonnet-3.7) **28.6%** (143/500). OpenHands 21.2%, SWE-agent 15.0%, AutoCodeRover 9.2%, Agentless/GPT-4o 5.4%. GPT-4o and o4-mini only 6.6–6.8% |
| **RustEvo²** | 588 API changes (380 std, 208 from 15 crates), Rust 1.71.0→1.84.0 | Automated synthesis of API-evolution tasks in four categories: stabilisation, signature change, behavioural change, deprecation | Stabilised APIs **65.8%** vs behavioural changes **38.0%**. Before-cutoff **56.1%** vs after-cutoff **32.5%**. RAG recovers 13.5 points post-cutoff |
| **CRUST-Bench** | C→safe-Rust transpilation | Interface + test-driven | Well-specified oracle, narrow scope |
| **Aider polyglot** | 225 Exercism problems, 6 languages incl. Rust | Problems solved by ≤3 models; two attempts, test output fed back on retry; strict diff-edit format | 24 GB-class local model ≈40%; full 225-problem run completed offline on an **8 GB laptop GPU** |
| **MultiPL-E** (via bigcode-evaluation-harness) | HumanEval/MBPP translated to 18 languages | Function-level, pass@k | Heavily contaminated by now; near-useless as a discriminator |

### Numbers worth internalising

- **Rust patches are big.** Rust-SWE-bench fix patches average **9.8 files, 9.9 hunks, 139.9 lines**. Python SWE-bench Verified averages **1.25 files, 2.46 hunks, 14.32 lines**. A Rust benchmark built only from single-file puzzles is not measuring Rust work.
- **Repos are big.** Average task repo: 993.6 files, 128,126 LoC.
- **Humans took 113 days and 7.2 discussion rounds** on average to resolve these issues originally.
- **Failure attribution.** Of agent failures: **43.7% repo-wide structure comprehension**, **32.6% Rust type/trait/borrow semantics**. That 32.6% is invisible to every general-purpose coding benchmark, and it is our primary target.
- **Reproduction is the bottleneck.** 44.5% of tasks failed at the issue-reproduction stage even for the best baseline (reproduction success rate 55.5%).
- **Contamination is measurable.** RustEvo²'s 56.1% → 32.5% before/after cutoff split is a clean, quantified demonstration that memorisation inflates static benchmark scores.
- **Multilingual variants barely cover Rust.** SWE-bench Multilingual has 43 Rust tasks; Multi-SWE-bench has 239.

## Contamination and dynamic benchmarking

The structural fix is to keep the question set fresher than any training cutoff.

- **LiveCodeBench** — continuously harvests problems from LeetCode, AtCoder, Codeforces published after major training cutoffs; evaluates generation, self-repair, and execution.
- **LiveBench** — refreshes monthly from recent publications, arXiv, news, competitions.
- **DynaCode** — complexity-aware dynamic code benchmark. Llama-3-8B-Instruct drops significantly from MBPP/MBPP+ to DynaCode, directly exposing memorisation in the static benchmarks.
- **SWE-ReBench** — collects GitHub issues post-dating each model's cutoff; some models held their scores, others dropped sharply once memorisation stopped helping.

Rustybenchmark takes a third path: not harvesting fresh problems (which does not scale and cannot isolate skills), but **generating** them from seeds, so freshness is unbounded and category attribution is exact. See [ADR-0002](adr/0002-hand-written-and-mined-suites.md).

## Oracle quality

Unit tests overstate correctness. Applying property-based testing as an alternative evaluation strategy to StarCoder and CodeLlama on MBPP and HumanEval showed **30–32% of solutions only partially satisfy correctness properties, and 18–23% fail outright** — gaps that pass@k marks green. A Property-Generated Solver framework reports 23.1–37.3% relative pass@1 gains over TDD methods by validating invariants rather than input/output examples.

Conclusion: **property + differential oracles are not optional.** Fixed example tests alone would make our numbers wrong in the same direction as everyone else's.

## Integrity precedent

- **Terminal-Bench** found real leaderboard misconduct: one submission stored **encrypted solutions inside the agent binary** and modified timeouts; another shipped the task **test folder** in the agent setup; a third had the agent **fetch solutions from the internet**. Response: mandatory trajectories for all passing trials, zero-score for reward hacking, removal for cheating, and an agent judge over all passing submissions (to be open-sourced for self-validation). All three cases were surfaced by independent community analysis of published data.
- **MLPerf** audits up to two submissions per round — one random, one committee-selected — examining logs, models, and code; reproduces on reference hardware with a **5% tolerance**; **90-day** audit window; failed audits trigger retraction of published material. "Results that cannot be replicated are not valid results."
- **3DMark** requires specific application and SystemInfo versions and an internet connection for a score to be leaderboard-valid.
- Federated-benchmark literature uses **signed client manifests** plus **low-frequency canary strings** screened at submission for leakage detection.

See [10-integrity.md](10-integrity.md) for how these translate into our trust tiers.

## Hardware measurement precedent

- **llama-bench** protocol: `pp512` (prompt processing, compute-bound) and `tg128` (token generation, memory-bandwidth-bound), `-ngl 999`, `--repetitions 10`, after a warm-up, reporting median. Report backend version, clock stability, resizable BAR state.
- **Thermal throttling alone swings results 12–18%** between cold and stabilised runs. Warm-up is mandatory; the cold/warm delta is itself a laptop-vs-desktop discriminator worth publishing.

## Local model reference points (August 2026)

- **Qwen3-Coder-30B-A3B** — 30B MoE, ~3.3B active, ~19 GB at Q4_K_M, 256K context. Widely cited as best quality-per-GB on a 24–32 GB GPU.
- **Devstral 24B** — ~14 GB, 46.8% SWE-bench Verified; the only local coder with a hard agentic number.
- A single 24 GB GPU (Qwen3-32B class) lands around **40%** on strict diff-edit format; the ~59.6% tier needs ~142 GB; the 70%+ tier needs 400 GB+.
- A complete 225-problem Aider Polyglot run has been executed fully offline on an **8 GB VRAM laptop GPU** via llama.cpp.

That last fact sets our feasibility envelope: consumer-hardware benchmark suites of this size are proven to be runnable.

## The gap

Nothing existing is simultaneously:

1. Rust-native in its **grading signals**, not just its file extensions
2. **Category-resolved** across Rust-specific skills
3. **Contamination-resistant by construction** rather than by harvesting
4. **Consumer-hardware-first**, with the hardware itself measured and reported
5. **Independently verifiable** in its correctness claims

Rustybenchmark is all five.

---

## Sources

- Rust-SWE-bench — <https://arxiv.org/html/2602.22764v1>
- RustEvo² — <https://arxiv.org/abs/2503.16922>, repo <https://github.com/SYSUSELab/RustEvo>
- CRUST-Bench — <https://arxiv.org/html/2504.15254v3>
- Aider polyglot — <https://aider.chat/2024/12/21/polyglot.html>, <https://github.com/Aider-AI/polyglot-benchmark>
- bigcode-evaluation-harness — <https://github.com/bigcode-project/bigcode-evaluation-harness>
- LiveCodeBench — <https://arxiv.org/pdf/2403.07974>
- DynaCode — <https://arxiv.org/pdf/2503.10452>
- Property-based testing for LLM codegen — <https://huggingface.co/papers/2506.18315>
- Terminal-Bench leaderboard integrity update — <https://www.tbench.ai/news/leaderboard-integrity-update>
- MLPerf inference rules — <https://github.com/mlcommons/inference_policies/blob/master/inference_rules.adoc>
- MLPerf Mobile audit methodology — <https://proceedings.mlsys.org/paper_files/paper/2022/file/a2b2702ea7e682c5ea2c20e8f71efb0c-Paper.pdf>
- llama-bench README — <https://github.com/ggml-org/llama.cpp/blob/master/tools/llama-bench/README.md>
- llama.cpp benchmark methodology — <https://craftrigs.com/benchmarks/llama-cpp-benchmark-methodology-reproducible/>
- sysinfo GPU support — <https://blog.guillaume-gomez.fr/articles/2026-06-20+sysinfo:+Getting+GPUs>
- nvml-wrapper — <https://crates.io/crates/nvml-wrapper>
- gpu-probe — <https://menjivar.ai/projects/gpu-probe>
- WASM vs Firecracker for untrusted code — <https://www.pandastack.ai/blog/wasm-vs-firecracker-untrusted-code/>
- Wasmtime security model — <https://docs.wasmtime.dev/security.html>

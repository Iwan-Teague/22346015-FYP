# FYP Proposal Form — detailed version (written as a plan; nothing here assumes work already done)

| Field | Entry |
|---|---|
| Name | Iwan Teague |
| Student ID | 22346015 |
| Course | LM051 Computer Systems |
| Supervisor Name | Jim Buckley |

## Project Title (initial or working title)

Option A or B:
- A. *Benchmarking Local Large Language Models on Rust Code Generation: Capability, Failure Modes and Hardware Throughput*
- B. *Where Local LLMs Fail at Rust: Measuring Capability, Failure Modes and Throughput on Consumer Hardware*

## Project Description

### 1. Problem

Developers increasingly run open-weight language models on their own machines to help write code, for cost, privacy or offline work. Three things are hard to know before choosing a model and a machine:

1. **How good is a given local model at Rust?** Existing code benchmarks are mostly Python, use a fixed set of questions that models may have seen in training, and grade with a single pass/fail number. Rust is a hard test case: the compiler rejects code that a Python-style answer would get away with (ownership, borrowing, lifetimes, traits), so failures are informative.
2. **Why does a model fail?** A score does not say whether the model misunderstood ownership, wrote the wrong logic, or never got code to compile.
3. **What does the hardware change?** Hardware is usually reported as tokens per second. A developer wants a different number: how much *correct* work does this machine deliver per hour with this model?

### 2. Aim

Build and use a benchmark that answers these three questions for local models, and test whether the benchmark itself can be trusted.

### 3. Deliverables

1. **Rustybenchmark**: a benchmark written in Rust that generates fresh tasks, runs a model on them, grades the result, and reports capability and throughput separately.
2. **Rustyharness**: a Rust coding-agent harness that gives a model the tools a real coding assistant has (read, search, edit files, run cargo) inside a sandbox, and runs every model the same way on every machine.
3. **A results study**: at least four local models on at least two machines, with failure classification and a validity analysis of the benchmark.
4. **The FYP report** and the software as the product.

### 4. Research questions

- **RQ1 (failure modes).** Which kinds of failure account for most failed Rust tasks for each model, and how do they change with model size?
- **RQ2 (hardware and energy).** How does correct work per hour change across the two machines, how much of that difference is model-independent, and how much electricity does each correct answer cost?
- **RQ3 (benchmark validity).** Is the score stable across fresh tasks and repeated runs, and how many tasks are needed to tell two models apart with confidence?
- **RQ4 (feedback).** Does letting a model use the compiler and tests before submitting (agent mode) beat a single answer, and by how much?
- **RQ5 (memorisation).** Do models do better on task families that resemble public code than on unfamiliar variants of them? (This measures how much fixed-question benchmarks would overstate ability.)

### 5. Method

#### 5.1 Tasks: generated from a seed
- Each task family is a program that, given a random seed, produces a prompt, a starting workspace, hidden tests and a reference solution. The seed changes names, constants, data and examples, so no fixed answer can be learned by heart.
- There are three levels of task, so the study shows how failures change as the work gets bigger:

| | Level 1: one-shot problems | Level 2: longer-running tasks | Level 3: fixing historical bugs |
|---|---|---|---|
| Task | A small, self-contained problem: one function or type, one file, standard library only | Build a working program from a specification: a small server on a given port, a command-line tool, a data pipeline | Given a real codebase as it stood before a known bug was fixed, find and fix the bug without breaking anything else |
| Source | Generated from a seed by a task family | Generated from a seed by a task family, with a specification contract | Bugs taken from the history of open-source Rust projects (the code before the fix, with the test that the real fix added kept hidden), plus seeded bugs injected into generated codebases |
| Length of run | Minutes; small step budget | Many steps; the model decides when it is done | Many steps; must locate the fault in code larger than its context window |
| Graded by | Hidden unit, property and differential tests, plus constraints | A conformance suite run against the finished program, three times to catch flaky results | The hidden regression test from the real fix, plus the project's full existing test suite, plus where the model looked and edited compared with where the real fix was |
| What it measures | Raw Rust skill | Planning, tool use, sustained work | Reading unfamiliar code, locating faults, safe modification |
| Volume | About 100 families, many seeds each: the statistical core | A few families in several domains, few seeds each | A curated set of bugs; reported directionally |

- **Level 1 skill areas:** ownership and borrowing, lifetimes, traits and generics, error handling, pattern matching, iterators, data structures, unsafe and raw pointers, string processing, bit manipulation, idiomatic refactoring.
- **Core and stretch:** Level 1 is the core of the study and carries the statistics. Level 2 and Level 3 are run at smaller scale and reported as directional results (see the scope section).
- **Historical bugs and memorisation:** a public bug may appear in a model's training data, so Level 3 reports real bugs and injected bugs separately, prefers bugs fixed after the models' training cut-offs, and treats the gap between the two as evidence for RQ5.
- Difficulty is recorded per instance and controlled, so a hard seed is not mistaken for a worse model (variation on the surface, not in difficulty).

#### 5.2 The agent harness
- The model runs in a loop: it reads the task, uses tools (list/read/search files, edit files, run `cargo build`/`test`/`clippy`), and ends by calling a submit tool. Grading starts only at submit.
- Every run has fixed budgets (steps, wall-clock time, output size) and a watchdog that stops loops and stalls, so every stop has a named cause.
- Every run is recorded in an append-only journal that can be replayed to check that the recorded result is what the run actually did.
- The harness is pinned to one version for the whole study, so a result always reads "model X under harness vN". Any change to the harness starts a new results epoch.
- Baseline comparison (RQ4): the same tasks are also run as a single answer with no tools, on the same model and hardware.

#### 5.3 The sandbox
- Each task runs in a sandbox that is reset between tasks: pinned Rust toolchain, a pre-built local crate set, no internet, limits on memory, processes and time.
- Native operating-system sandboxing on each OS, with no virtual machines or containers (they use memory the model needs): Seatbelt-based confinement on macOS, Landlock, seccomp and cgroups on Linux.
- Every result must be reproducible on both Linux and macOS.

#### 5.4 Grading (outside the agent's reach)
- At submit the workspace is snapshotted and hashed. The grader restores build configuration files the agent could have used to steer the build, rebuilds offline in a clean directory with the pinned toolchain, and adds the hidden tests. The agent never sees the hidden tests, the reference solution or the seed.
- A task passes only if it (1) compiles, (2) passes hidden unit tests, (3) passes property tests and differential tests against the reference solution on seeded inputs, and (4) meets the task's constraints (allocation limits, `unsafe` limits, clippy, and Miri for unsafe tasks). Partial credit by layer is reported separately, never mixed into the pass rate.
- Grading code lives in Rustybenchmark and never in the harness, so the harness cannot influence scoring.
- Snapshot grading: the workspace at every compile attempt is also graded, giving a first-try score and a score-by-turn curve from a single run.

#### 5.5 Keeping models from training on or memorising the data
- Fresh tasks per run from a seed; hidden tests use seeded inputs, so a memorised answer fails.
- A private held-out set of task families is never published; results on it are compared with results on the public families to detect leakage.
- A unique canary string in every instance, so later appearance in training data or model output is detectable.
- Compositional variation inside families (combining spec features), so a family has many distinct solution structures, not a handful.
- Only aggregate results and failure classes are published, not the hidden tests.
- RQ5 measures the memorisation gap directly rather than assuming it away.

#### 5.6 Measurement
- Per run: pass/fail by layer, tokens, prefill time, generation time and speed, tool-call counts, wall-clock time, and stop cause.
- **Throughput** is defined before any results are seen: correct tasks per hour of model and tool time on a given machine, reported alongside wall-clock time and the prefill share. Toolchain time is reported separately.
- The OS, hardware, model file, quantisation, context size and harness version are captured automatically for every run.

#### 5.6b Power and energy (RQ2)
For a home user, electricity and heat matter as much as speed, so every run also records how much energy the machine used.
- **Primary method: whole-machine wall power.** A plug-in power meter or smart plug (a low-cost device, logging watts at least once a second) measures the whole system, the same way on the MacBook and on the Linux PC. This is directly comparable across machines, and includes the CPU, GPU, memory and fan power that a home user pays for. The meter's readings are timestamped and aligned with the run journal.
- **Cross-check: software counters where available.** NVIDIA GPU power through `nvidia-smi` on the Linux PC; CPU package power through Intel/AMD RAPL counters on Linux; `powermetrics` on the Mac if administrator access is granted. These give a per-component breakdown but are not comparable across machines, so they support the wall-power figure and never replace it.
- **Baseline:** each session begins with an idle measurement, and the idle draw is reported so that "extra energy for this task" can be separated from what the machine uses anyway.
- **Metrics (defined in advance):** energy per task in watt-hours; **energy per correct task**; correct tasks per kilowatt-hour; average and peak watts; joules per generated token; energy split between prefill (reading the prompt) and generation; and estimated electricity cost at a stated tariff. Agent mode is compared with single-answer mode on energy as well as accuracy, since a loop that takes many steps may cost far more energy for a small gain.
- **Scope:** power is measured for all four models on both machines where the meter is available. If a machine lacks a usable meter, its energy results are reported as estimates from software counters and labelled as such.
- **Limitations stated up front:** wall meters include the rest of the machine (display, background tasks), which is controlled by fixed display and background settings; battery-powered runs on the MacBook are excluded (mains only), and the meter's accuracy is checked against a known load.

#### 5.7 Failure classification (RQ1)
- Compiler errors classified into borrow-check, lifetime, trait, type, syntax, name resolution and idiom, using error codes and message patterns (codes alone are ambiguous for about a third of errors).
- Logic failures split into panic, wrong output and timeout; agent-level failures classified as never compiled, stuck loop, budget exhausted or protocol failure.
- A trajectory view: every compile error hit along the way, which ones the model fixes, which it never fixes, and how many turns fixing takes.
- A sample of failed runs is reviewed by hand to check the automatic classification.

#### 5.8 Models and machines
- At least four open-weight models spanning sizes (for example roughly 4B, 8B, 14B and 30B parameters, at least one code-specialised), run locally with llama.cpp on quantised weights.
- At least two machines: an Apple M5 MacBook (macOS) and a Linux PC with an NVIDIA RTX 3070. I will also ask CSIS whether a GPU machine can be provided, to widen the hardware comparison.

#### 5.9 Statistics and testing the benchmark (RQ3, RQ4)
- **Sample size:** at least 100 generated tasks per model per machine for the headline Level 1 results, spread over skill areas, with several seeds per family.
- **Comparisons:** models and modes are compared on the same tasks with paired tests (McNemar for pass/fail, paired bootstrap confidence intervals for scores); results are reported with confidence intervals, not bare rankings.
- **Stability:** repeat runs of the same tasks and fresh seeds of the same families to estimate score variance and how interchangeable seeds within a family are.
- **Discriminating power:** a resampling analysis reports how many tasks are needed before two models can be reliably told apart, and at what score gap.
- **Determinism:** sampling settings and seeds are recorded; because outputs differ across hardware even at temperature 0, repeated runs and confidence intervals are used rather than assuming reproducibility.
- **Pre-registration:** the pass predicate, the throughput formula and the analysis are written down before the main runs.

#### 5.10 Software quality and safety
- Rust only, for benchmark, harness and analysis. Continuous checks: formatting, clippy with warnings denied, dependency audit and tests on every change.
- The harness's confinement is itself tested by attempting deliberate escapes (symlinks, process and memory bombs, network access) and checking every attempt is refused.
- No human participants are involved.

### 6. Scope, schedule and risk

| When | Deliver |
|---|---|
| By 23 Dec (interim report) | Task generation for Level 1; harness with confined tools and grading loop working end to end; sandbox on macOS and Linux; first Level 1 results on both machines |
| Jan–Feb | Full Level 1 runs on all models and machines, with power measured; failure classification; the stability and discriminating-power analysis; Level 2 tasks built and piloted |
| Feb–Mar | Level 2 results; Level 3 built from real historical bugs and injected bugs, and run on a smaller scale |
| Mar–Apr | Analysis and writing; product due 20 Apr, report due 26 Apr |

- **Core scope** (must finish): Level 1 in agent mode plus the single-answer baseline, on at least four models and two machines, with power and energy measured, failure classification and the validity analysis (RQ1–RQ5).
- **All three levels are in the plan.** Level 2 and Level 3 are delivered at smaller scale than Level 1 and reported as directional results.
- **Cut line:** if behind in January, Level 2 shrinks to two or three tasks and Level 3 to a short case study of a handful of bugs. Core scope is not cut.
- **Compute risk:** agent runs take several times longer than single answers (several turns per task, at roughly 20 tokens per second on larger local models). A pilot (about 20 families, a few seeds, two models) fixes the suite size and run counts before the main runs.
- **Sandbox risk:** the macOS process cleanup is the hardest confinement problem. If it is not solved by about 1 November, the fallback is a documented, narrower guarantee that is still adequate for Level 1.
- **Schedule risk:** if the harness is not ready by mid-November, the interim report uses single-answer Level 1 results and agent mode moves to January–March.

### 7. Expected contributions

A trustworthy, contamination-resistant Rust benchmark with published methodology; a hardware-aware measure of correct work per hour and per kilowatt-hour for local models, useful to home users choosing a model and a machine; an evidence-based failure taxonomy for LLM-written Rust; and a measured answer to how much an agent loop with compiler feedback improves a small local model.

## Sign-off by Proposed Supervisor

| Field | Entry |
|---|---|
| Supervisor Signature | |
| Supervisor Name | Jim Buckley |
| Date (dd/mm/yyyy) | |

## Environment Required

| Field | Entry |
|---|---|
| Operating system | Mac (macOS) and Linux |
| Languages | Rust throughout: benchmark, agent harness and data analysis |
| Specialist software / hardware | Open-weight LLMs served locally with llama.cpp; the Rust toolchain (rustc, cargo, clippy, Miri). Hardware: my own machines (below) for certain. I will also ask CSIS whether a GPU machine can be made available, to widen the hardware comparison, and will use any other hardware I can get access to. A plug-in mains power meter or smart plug (a low-cost item I will buy myself) to measure energy use; administrator access on my own machines for power counters |
| Your computer | Yes. Apple M5 MacBook, portable. Plus my own Linux PC with an NVIDIA RTX 3070 (not portable) for GPU runs |

## Declarations

Three student signatures and dates (FYP Guidelines, Ethical Approval, Required Template), signed when the final form is submitted.

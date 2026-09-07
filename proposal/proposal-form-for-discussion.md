# FYP Proposal Form — draft for discussion

The one blank marked ▢ is for your view (question 1 in the questions list). I'll fill it in after
the call and send the final form for signing.

| Field | Entry |
|---|---|
| Name | Iwan Teague |
| Student ID | 22346015 |
| Course | LM051 Computer Systems |
| Supervisor Name | Jim Buckley |

## Project Title (initial or working title)

▢ **A or B** (Q1)

## Project Description

Developers increasingly run AI models on their own hardware to help write code, yet nobody can
say how good these local models are at Rust, or how much the hardware changes the answer.
Existing benchmarks mostly use Python, rely on fixed questions that models may have memorised,
and measure hardware only in tokens per second.

This project is to build Rustybenchmark, a benchmark written in Rust that generates fresh Rust
tasks from a random seed, compiles and tests every answer with the real Rust toolchain in a
sandbox, and reports two separate results: capability by skill area (ownership and borrowing,
traits, error handling, idiomatic style, unsafe code) and throughput, meaning correct code
delivered per hour on a given machine. Alongside it the project builds rustyharness, a Rust agent
harness that gives each model the tools a real coding assistant has and runs every model the same
way on every machine, so that results reflect what a model can do in real use.

Using them, the project will (1) run at least four local models on at least two machines,
(2) classify how and why the models fail, using compiler errors as evidence, and (3) test whether
the benchmark itself is trustworthy: score stability across fresh tasks, and how many tasks it
takes to tell two models apart. No human participants are involved.

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
| Specialist software / hardware | Open-weight LLMs served locally with llama.cpp; the Rust toolchain (rustc, cargo, clippy). Hardware: my own machines (below) for certain. I will also ask CSIS whether a GPU machine can be made available, to widen the hardware comparison, and will use any other hardware I can get access to |
| Your computer | Yes. Apple M5 MacBook, portable. Plus my own Linux PC with an NVIDIA RTX 3070 (not portable) for GPU runs |

## Declarations

Three student signatures and dates (FYP Guidelines, Ethical Approval, Required Template),
signed when the final form is submitted.

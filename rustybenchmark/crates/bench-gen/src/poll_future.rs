//! Deterministic async machinery: hand-rolled `Future` state machines.
//!
//! Roadmap Q11 blocks concurrency families because nondeterministic
//! scheduling gives no stable output. This family sidesteps that: every
//! task ships a PROVIDED single-threaded executor (`block_on` below)
//! whose poll order is fixed, so a future's observable schedule — how
//! many times it pends, when it answers — is fully deterministic and
//! differentially testable. The model's skill is authoring the
//! `Future::poll` state machines themselves.
//!
//! Shared contract for every task in this family: a "delay future"
//! with threshold `t` returns `Pending` exactly `t` times and then
//! `Ready(7 * t)` forever after. The answering poll is therefore poll
//! `t + 1`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Op {
    ReadyValue,
    PollsToReady,
    IsReadyAfter,
    DeliveredOnPoll,
    LaterAnswer,
}

pub(crate) const OP_ALL: [Op; 5] = [
    Op::ReadyValue,
    Op::PollsToReady,
    Op::IsReadyAfter,
    Op::DeliveredOnPoll,
    Op::LaterAnswer,
];

impl Op {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Op::ReadyValue => "ready_value",
            Op::PollsToReady => "polls_to_ready",
            Op::IsReadyAfter => "is_ready_after",
            Op::DeliveredOnPoll => "delivered_on_poll",
            Op::LaterAnswer => "later_answer",
        }
    }

    pub(crate) fn ret(self) -> &'static str {
        match self {
            Op::IsReadyAfter => "bool",
            _ => "i64",
        }
    }

    pub(crate) fn prose(self) -> &'static str {
        match self {
            Op::ReadyValue => "the value the delay future delivers",
            Op::PollsToReady => "which poll number first observes Ready",
            Op::IsReadyAfter => "whether the future is ready once n polls have happened",
            Op::DeliveredOnPoll => "the value seen on poll n (-1 unless that poll is THE answer)",
            Op::LaterAnswer => "how many polls awaiting both futures back to back needs",
        }
    }

    /// Extra parameters beyond the leading threshold argument.
    pub(crate) fn extra_args(self) -> &'static str {
        match self {
            Op::IsReadyAfter | Op::DeliveredOnPoll => ", n: u64",
            Op::LaterAnswer => ", other: u64",
            _ => "",
        }
    }

    /// Parameter names used at call sites.
    pub(crate) fn call_args(self) -> &'static str {
        match self {
            Op::IsReadyAfter | Op::DeliveredOnPoll => "t, n",
            Op::LaterAnswer => "t, o",
            _ => "t",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Spec {
    pub ops: [Op; 2],
}

pub(crate) fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let i = rng.below(5) as usize;
    let mut j = rng.below(5) as usize;
    while j == i {
        j = rng.below(5) as usize;
    }
    let mut ops = [OP_ALL[i], OP_ALL[j]];
    ops.sort();
    Spec { ops }
}
pub(crate) fn b_ready_value(t: u64) -> i64 {
    (t * 7) as i64
}

pub(crate) fn b_polls_to_ready(t: u64) -> i64 {
    (t + 1) as i64
}

pub(crate) fn b_is_ready_after(t: u64, n: u64) -> bool {
    n > t
}

pub(crate) fn b_delivered_on_poll(t: u64, n: u64) -> i64 {
    if n == t + 1 {
        (t * 7) as i64
    } else {
        -1
    }
}

pub(crate) fn b_later_answer(t: u64, o: u64) -> i64 {
    (t.max(o) + 1) as i64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    pub(crate) fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

pub(crate) fn op_eval(op: Op, t: u64, o: u64, n: u64) -> Out {
    match op {
        Op::ReadyValue => Out::Num(b_ready_value(t)),
        Op::PollsToReady => Out::Num(b_polls_to_ready(t)),
        Op::IsReadyAfter => Out::Flag(b_is_ready_after(t, n)),
        Op::DeliveredOnPoll => Out::Num(b_delivered_on_poll(t, n)),
        Op::LaterAnswer => Out::Num(b_later_answer(t, o)),
    }
}

const CANONICAL_SEED: u64 = 0xF071_FA11;

/// Canonical case: a real delay future (threshold >= 3) plus a strictly
/// later partner, probed exactly on its answering poll.
pub(crate) fn canonical(seed: u64) -> (u64, u64, u64) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let t = 3 + rng.below(9);
        let o = t + 1 + rng.below(4);
        let n = t + 1;
        let rv = b_ready_value(t);
        let pt = b_polls_to_ready(t);
        let la = b_later_answer(t, o);
        if rv != 0 && pt != rv && la > pt && la != rv {
            return (t, o, n);
        }
    }
    unreachable!("canonical case unreachable");
}

fn rand_case(rng: &mut Rng) -> (u64, u64, u64) {
    let t = rng.below(7);
    let o = rng.below(7);
    let n = rng.below(t + 3);
    (t, o, n)
}
pub(crate) struct ExampleCase {
    pub t: u64,
    pub o: u64,
    pub n: u64,
    pub answers: Vec<(Op, Out)>,
}

pub(crate) fn case(t: u64, o: u64, n: u64) -> ExampleCase {
    let answers = OP_ALL
        .iter()
        .map(|&op| (op, op_eval(op, t, o, n)))
        .collect();
    ExampleCase { t, o, n, answers }
}

const EXAMPLES_SEED: u64 = 0x0000_017A;

pub(crate) fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut out = vec![{
        let (t, o, n) = canonical(seed);
        case(t, o, n)
    }];
    // Zero conventions: zero-threshold future, poll zero.
    out.push(case(0, 0, 0));
    // One short of the boundary stays pending.
    out.push(case(5, 2, 5));
    // Deep past the boundary: still ready, but no NEW delivery.
    out.push(case(2, 6, 50));
    // Tied pair answers together.
    out.push(case(3, 3, 4));
    for _ in 0..8 {
        let (t, o, n) = rand_case(&mut rng);
        out.push(case(t, o, n));
    }
    out
}

pub(crate) fn render_u64(v: u64) -> String {
    format!("{v}u64")
}

/// Reference source: the shared delay-future machinery plus one
/// self-contained query per op. The differential pastes this whole
/// block and renames only the selected pair (roman precedent).
pub(crate) fn reference_src(spec: &Spec) -> String {
    let mut src = String::from(BLOCK_ON_SRC);
    src.push('\n');
    src.push_str(DELAY_SRC);
    src.push('\n');
    for op in spec.ops {
        src.push_str(&op_fn_src(op));
        src.push('\n');
    }
    src
}

const DELAY_SRC: &str = r#"/// A delay future: `Pending` exactly `left` times, then `Ready(value)`
/// forever after.
struct Delay {
    left: u64,
    value: i64,
}

impl std::future::Future for Delay {
    type Output = i64;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<i64> {
        if self.left == 0 {
            std::task::Poll::Ready(self.value)
        } else {
            self.left -= 1;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    }
}
"#;

pub(crate) fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::ReadyValue => &[
            "block_on(Delay {",
            "    left: t,",
            "    value: (t * 7) as i64,",
            "})",
        ],
        Op::PollsToReady => &[
            "let mut fut = Delay { left: t, value: 0 };",
            "let waker = std::task::Waker::noop();",
            "let mut cx = std::task::Context::from_waker(waker);",
            "let mut fut = std::pin::pin!(fut);",
            "let mut count = 1u64;",
            "loop {",
            "    if let std::task::Poll::Ready(_) = std::future::Future::poll(fut.as_mut(), &mut cx)\n    {",
            "        return count as i64;",
            "    }",
            "    count += 1;",
            "}",
        ],
        Op::IsReadyAfter => &["n >= t + 1"],
        Op::DeliveredOnPoll => &[
            "if n == t + 1 {",
            "    block_on(Delay { left: t, value: (t * 7) as i64 })",
            "} else {",
            "    -1",
            "}",
        ],
        Op::LaterAnswer => &["(t.max(other) + 1) as i64"],
    };
    format!(
        "pub fn {}(t: u64{}) -> {} {{\n    {}\n}}\n",
        op.name(),
        op.extra_args(),
        op.ret(),
        body.join("\n    ")
    )
}

pub(crate) fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(t: u64{}) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.extra_args(),
        op.ret()
    )
}

pub(crate) fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(t: u64{}) -> {}",
        op.name(),
        op.extra_args(),
        op.ret()
    )
}

pub(crate) fn call_src(op: Op) -> String {
    format!("{}({})", op.name(), op.call_args())
}

/// The PROVIDED deterministic executor shipped inside every task's
/// skeleton and reference. Fixed poll order, spin-on-pending: the
/// spike shape that makes async outputs stable (roadmap Q11).
pub(crate) const BLOCK_ON_SRC: &str = r#"/// Provided single-threaded executor. Polls the future on the current
/// thread; a `Pending` result wakes itself and the loop spins. Poll
/// order is fixed, so schedules are fully deterministic.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    loop {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        cx.waker().wake_by_ref();
        std::hint::spin_loop();
    }
}
"#;
pub(crate) fn worked_examples_prose(examples: &[ExampleCase]) -> String {
    let mut lines = String::from("Worked examples (inputs -> each query = answer):\n");
    for ex in examples {
        let mut parts = Vec::new();
        for (op, out) in &ex.answers {
            parts.push(format!("{} = {}", op.name(), out.lit()));
        }
        lines.push_str(&format!(
            "  t {} o {} n {}  ->  {}\n",
            ex.t,
            ex.o,
            ex.n,
            parts.join(", ")
        ));
    }
    lines
}

pub(crate) fn skeleton_src(spec: &Spec, examples: &[ExampleCase]) -> String {
    let mut src = String::from(
        "//! Hand-rolled futures over a PROVIDED deterministic executor.\n\
         //!\n\
         //! The executor `block_on` below is given: keep it intact. Your\n\
         //! job is the queries — each one must build its own delay future\n\
         //! (or drive one by hand) and observe it. A delay future with\n\
         //! threshold t returns Pending exactly t times and then\n\
         //! Ready(7 * t) forever after; poll numbers start at 1.\n\
         //!\n",
    );
    let prose = worked_examples_prose(examples);
    let doc_prose = prose
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    src.push_str(&doc_prose);
    src.push('\n');
    src.push_str(BLOCK_ON_SRC);
    src.push('\n');
    for op in spec.ops {
        src.push_str(&op_stub_src(op));
        src.push('\n');
    }
    src
}

pub(crate) fn prompt(spec: &Spec, examples: &[ExampleCase], canary: &str) -> String {
    let mut p = String::from(
        "Implement deterministic async machinery on top of the provided executor.\n\n\
         The skeleton gives you `block_on`: a single-threaded executor whose poll\n\
         order is fixed. Keep it intact. Every query must construct its own delay\n\
         future (or drive one manually with a Waker and Context) and observe it.\n\
         Contract: a delay future with threshold t returns Pending exactly t times,\n\
         then Ready(7 * t) forever after. Poll numbers start at 1.\n\n\
         Requirements:\n",
    );
    for op in spec.ops {
        p.push_str(&format!("- `{}`: {}.\n", op.name(), op.prose()));
    }
    p.push_str(
        "\nConstraints:\n\
         - Keep every signature exactly as stubbed.\n\
         - Do not change or remove the provided block_on executor.\n\
         - No unsafe code.\n\n\
         Signatures:\n```rust\n",
    );
    for op in spec.ops {
        p.push_str(&op_sig_src(op));
        p.push('\n');
    }
    p.push_str("```\n\n");
    p.push_str(&worked_examples_prose(examples));
    p.push_str(&format!(
        "\nThe string rb-canary-{} must appear verbatim in your answer.\n",
        canary
    ));
    p
}

pub(crate) fn cargo_toml() -> String {
    String::from(
        "[package]\n\
         name = \"task\"\n\
         version = \"0.1.0\"\n\
         edition = \"2021\"\n\n\
         [lib]\n\
         path = \"src/lib.rs\"\n\n\
         [workspace]\n",
    )
}

pub(crate) fn behavior_test_src(spec: &Spec, examples: &[ExampleCase]) -> String {
    let mut src = String::new();
    let names: Vec<&str> = spec.ops.iter().map(|o| o.name()).collect();
    src.push_str(&format!("use task::{{{}}};\n", names.join(", ")));
    for (i, ex) in examples.iter().enumerate() {
        src.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let t = {};\n    let n = {};\n    let o = {};\n",
            render_u64(ex.t),
            render_u64(ex.n),
            render_u64(ex.o)
        ));
        for (op, out) in &ex.answers {
            if !spec.ops.contains(op) {
                continue;
            }
            src.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op),
                out.lit()
            ));
        }
        src.push_str("}\n");
    }
    src
}

pub(crate) fn differential_test_src(spec: &Spec) -> String {
    let mut src = String::new();
    let names: Vec<&str> = spec.ops.iter().map(|o| o.name()).collect();
    src.push_str(&format!("use task::{{{}}};\n", names.join(", ")));
    let mut reference = reference_src(spec);
    for op in spec.ops {
        let name = op.name();
        let target = format!("pub fn {name}(");
        let replacement = format!("fn ref_{name}(");
        assert!(reference.contains(&target), "reference missing {name}");
        reference = reference.replacen(&target, &replacement, 1);
    }
    src.push_str(&reference);
    src.push_str(
        "\nfn nx(state: &mut u64) -> u64 {\n    *state = state\n        .wrapping_mul(6364136223846793005)\n        .wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n#[test]\nfn differential_vs_reference() {\n    let mut state: u64 = 0xE7EE_ED00_0000_017A;\n    for _ in 0..3000 {\n        let t = nx(&mut state) % 9;\n        let o = nx(&mut state) % 9;\n        let n = nx(&mut state) % (t + 4);\n",
    );
    for op in spec.ops {
        let name = op.name();
        let args = match op {
            Op::ReadyValue | Op::PollsToReady => "t".to_string(),
            _ => "t, n".to_string(),
        };
        let call = if matches!(op, Op::LaterAnswer) {
            format!("{name}(t, o)")
        } else {
            format!("{name}({args})")
        };
        src.push_str(&format!("        assert_eq!({call}, ref_{call});\n"));
    }
    src.push_str("    }\n}\n");
    src
}

pub(crate) fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let body = match op {
                Op::IsReadyAfter => "false",
                _ => "0",
            };
            format!(
                "{} {{\n    let _ = (t{});\n    {}\n}}\n",
                op_sig_src(*op),
                extra_silence(*op),
                body
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn extra_silence(op: Op) -> &'static str {
    match op {
        Op::ReadyValue | Op::PollsToReady => "",
        _ => ", n, other",
    }
}

/// Eager cheat: every future treated as answering on the very first
/// poll regardless of threshold. Uses the provided executor and a real
/// std future — just the wrong schedule.
pub(crate) fn eager_everything(spec: &Spec) -> String {
    let mut src = String::from(BLOCK_ON_SRC);
    src.push('\n');
    for op in spec.ops {
        let body = match op {
            Op::ReadyValue => "block_on(std::future::ready((t * 7) as i64))".to_string(),
            Op::PollsToReady => "1".to_string(),
            Op::IsReadyAfter => "n >= 1".to_string(),
            Op::DeliveredOnPoll => {
                "if n == 1 {\n    block_on(std::future::ready((t * 7) as i64))\n} else {\n    -1\n}"
                    .to_string()
            }
            Op::LaterAnswer => "2".to_string(),
        };
        src.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    src
}

pub(crate) struct PollFutureFamily;

impl Generator for PollFutureFamily {
    fn id(&self) -> &'static str {
        "poll-future"
    }

    fn category(&self) -> &'static str {
        "future-machinery"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("poll-future", seed);

        let mut files = std::collections::BTreeMap::new();
        files.insert(std::path::PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(
            std::path::PathBuf::from("src/lib.rs"),
            skeleton_src(&spec, &examples),
        );

        let mut hidden = std::collections::BTreeMap::new();
        hidden.insert(
            std::path::PathBuf::from("tests/behavior.rs"),
            behavior_test_src(&spec, &examples),
        );
        hidden.insert(
            std::path::PathBuf::from("tests/differential.rs"),
            differential_test_src(&spec),
        );

        GeneratedTask {
            id: format!("poll-future/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, &examples, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            weights: (0.70, 0.30, 0.0),
        }
    }

    fn reference_code(&self, seed: u64) -> String {
        reference_src(&sample(seed))
    }

    fn skeleton_code(&self, seed: u64) -> String {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        skeleton_src(&spec, &examples)
    }

    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero(&spec)),
            ("eager-everything".to_string(), eager_everything(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let mut names: Vec<&str> = sample(seed).ops.iter().map(|op| op.name()).collect();
        names.sort_unstable();
        vec![format!("q:{}/{}", names[0], names[1])]
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = PollFutureFamily;
        let a = g.generate(81);
        let b = g.generate(81);
        assert_eq!(a.id, b.id);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
    }

    #[test]
    fn native_ops_match_intent() {
        assert_eq!(b_ready_value(3), 21);
        assert_eq!(b_ready_value(0), 0);
        assert_eq!(b_polls_to_ready(0), 1);
        assert_eq!(b_polls_to_ready(100), 101);
        // Poll zero never ready; boundary inclusive; deep past stays ready.
        assert!(!b_is_ready_after(5, 0));
        assert!(!b_is_ready_after(5, 5));
        assert!(b_is_ready_after(5, 6));
        assert!(b_is_ready_after(2, 50));
        // Delivery exactly once: pending before, repeat-Ready after.
        assert_eq!(b_delivered_on_poll(3, 4), 21);
        assert_eq!(b_delivered_on_poll(3, 3), -1);
        assert_eq!(b_delivered_on_poll(3, 50), -1);
        assert_eq!(b_delivered_on_poll(0, 1), 0);
        // Later partner governs the combined schedule; ties answer together.
        assert_eq!(b_later_answer(3, 1), 4);
        assert_eq!(b_later_answer(1, 3), 4);
        assert_eq!(b_later_answer(3, 3), 4);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..300u64 {
            seen.insert(sample(seed));
        }
        assert!(seen.len() >= 9, "only {} distinct specs", seen.len());
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        for seed in 0..200u64 {
            let (t, o, n) = canonical(seed);
            let rv = b_ready_value(t);
            let pt = b_polls_to_ready(t);
            let la = b_later_answer(t, o);
            assert!(t >= 3, "seed {seed} threshold too low");
            assert_ne!(rv, 0);
            assert_ne!(pt, rv);
            assert!(la > pt && la != rv);
            assert!(b_is_ready_after(t, n));
            assert_eq!(b_delivered_on_poll(t, n), rv);
            // The eager cheat's constant schedule is wrong on canonical:
            // its poll count is 1, not t + 1 >= 4.
            assert_ne!(pt, 1);
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for ex in worked_examples(seed) {
                for (op, out) in &ex.answers {
                    assert_eq!(
                        op_eval(*op, ex.t, ex.o, ex.n),
                        *out,
                        "seed {seed} op {}",
                        op.name()
                    );
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        let spec = sample(81);
        let reference = reference_src(&spec);
        for op in OP_ALL {
            let marker = format!("pub fn {}(", op.name());
            if spec.ops.contains(&op) {
                assert!(reference.contains(&marker), "{} missing", op.name());
            } else {
                assert!(
                    !reference.contains(&marker),
                    "unselected {} leaked into reference",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        let spec = sample(81);
        let examples = worked_examples(81);
        let skel = skeleton_src(&spec, &examples);
        let p = prompt(&spec, &examples, "abc123");
        let canary_prompt = prompt(&spec, &examples, "abc123");
        assert!(canary_prompt.contains("rb-canary-abc123"));
        // The solution shapes must not leak into skeleton or prompt.
        for token in ["left -= 1", "impl Future", "fn poll("] {
            assert!(!skel.contains(token), "{token} leaked into skeleton");
            assert!(!p.contains(token), "{token} leaked into prompt");
        }
        // The provided executor IS present in the skeleton (keep intact).
        assert!(skel.contains("fn block_on"));
        assert!(skel.contains("Waker::noop"));
        // Stubs are todo!(); signatures present in the prompt.
        assert!(skel.contains("todo!()"));
        for op in spec.ops {
            assert!(p.contains(&op_sig_src(op)), "{} sig missing", op.name());
            assert!(skel.contains(&op_sig_src(op)), "{} stub missing", op.name());
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for op in OP_ALL {
            let call = call_src(op);
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call_commas = call.matches(',').count();
            let sig_commas = params.matches(',').count();
            assert_eq!(
                call_commas,
                sig_commas,
                "arity drift on {}: {call} vs {sig}",
                op.name()
            );
        }
    }

    #[test]
    fn executor_and_contract_are_in_the_reference() {
        let spec = sample(81);
        let reference = reference_src(&spec);
        assert!(reference.contains("fn block_on"));
        assert!(reference.contains("struct Delay"));
        assert!(reference.contains("impl std::future::Future for Delay"));
        // The eager baseline compiles standalone and uses real futures.
        let eager = eager_everything(&spec);
        assert!(eager.contains("block_on(std::future::ready"));
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let spec = sample(81);
        let examples = worked_examples(81);
        let p = prompt(&spec, &examples, "deadbeef1234");
        assert!(p.contains("rb-canary-deadbeef1234"));
    }
}

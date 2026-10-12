//! Drop-timing puzzles over one shared audit log.
//!
//! Every query creates guards whose whole job happens when they drop.
//! The reference sequences scopes so each entry lands exactly where the
//! timing rules put it: end of an inner scope first, reverse creation
//! order inside one scope, immediately under an explicit release, and
//! even along early return paths. The naive baseline below reads the log
//! while its guards are still alive, so every entry is still missing.

use std::cell::RefCell;

use crate::{mint_canary, GeneratedTask, Generator, Rng};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Op {
    SequentialTwo,
    NestedScopeOrder,
    ExplicitDropNow,
    EarlyReturnStillDrops,
    HoldAndRelease,
}

const OP_ALL: [Op; 5] = [
    Op::SequentialTwo,
    Op::NestedScopeOrder,
    Op::ExplicitDropNow,
    Op::EarlyReturnStillDrops,
    Op::HoldAndRelease,
];

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::SequentialTwo => "sequential_two",
            Op::NestedScopeOrder => "nested_scope_order",
            Op::ExplicitDropNow => "explicit_drop_now",
            Op::EarlyReturnStillDrops => "early_return_still_drops",
            Op::HoldAndRelease => "hold_and_release",
        }
    }

    /// Parameters carried after the log argument.
    fn extra_arg(self) -> &'static str {
        match self {
            Op::SequentialTwo => ", t: u64, u: u64",
            Op::NestedScopeOrder => ", outer: u64, inner: u64",
            Op::HoldAndRelease => ", held: u64, gone: u64",
            Op::ExplicitDropNow => ", tag: u64",
            Op::EarlyReturnStillDrops => ", tag: u64, abort: bool",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::SequentialTwo => {
                "create the first guard, release it completely, then create and release the second"
            }
            Op::NestedScopeOrder => {
                "hold one guard while an inner scope opens and closes, then report the first logged entry"
            }
            Op::ExplicitDropNow => {
                "release the guard immediately and explicitly before anything else reads the log"
            }
            Op::EarlyReturnStillDrops => {
                "return early out of a live guard when asked; the entry must land on either path"
            }
            Op::HoldAndRelease => {
                "hold the first guard open while releasing the second completely; the answer counts entries present before the held one lands"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Spec {
    ops: [Op; 2],
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let i = rng.below(5) as usize;
    let mut j = rng.below(5) as usize;
    while j == i {
        j = rng.below(5) as usize;
    }
    let a = OP_ALL[i];
    let b = OP_ALL[j];
    if a <= b {
        Spec { ops: [a, b] }
    } else {
        Spec { ops: [b, a] }
    }
}
type Out = i64;

/// The provided machinery shipped in every skeleton, reference, and
/// baseline: a guard whose entire effect happens when it drops.
const GUARD_SRC: &str = "pub struct TagGuard<'a> {\n    pub tag: u64,\n    pub log: &'a std::cell::RefCell<Vec<u64>>,\n}\n\nimpl Drop for TagGuard<'_> {\n    fn drop(&mut self) {\n        self.log.borrow_mut().push(self.tag);\n    }\n}\n";

/// The real provided guard used by natives and tests; `GUARD_SRC` above is
/// the same shape shipped inside emitted tasks.
pub struct TagGuard<'a> {
    pub tag: u64,
    pub log: &'a std::cell::RefCell<Vec<u64>>,
}

impl Drop for TagGuard<'_> {
    fn drop(&mut self) {
        self.log.borrow_mut().push(self.tag);
    }
}

fn b_sequential_two(log: &RefCell<Vec<u64>>, t: u64, u: u64) -> i64 {
    {
        let _first = TagGuard { tag: t, log };
    }
    {
        let _second = TagGuard { tag: u, log };
    }
    let count = log.borrow().len() as i64;
    count
}

fn b_nested_scope_order(log: &RefCell<Vec<u64>>, outer: u64, inner: u64) -> i64 {
    let _outer = TagGuard { tag: outer, log };
    {
        let _inner = TagGuard { tag: inner, log };
    }
    let first = log.borrow()[0];
    first as i64
}

fn b_explicit_drop_now(log: &RefCell<Vec<u64>>, tag: u64) -> i64 {
    let g = TagGuard { tag, log };
    std::mem::drop(g);
    let count = log.borrow().len() as i64;
    count
}

fn b_early_return_still_drops(log: &RefCell<Vec<u64>>, tag: u64, abort: bool) -> i64 {
    let g = TagGuard { tag, log };
    if abort {
        return -1;
    }
    std::mem::drop(g);
    let count = log.borrow().len() as i64;
    count
}

fn b_hold_and_release(log: &RefCell<Vec<u64>>, held: u64, gone: u64) -> i64 {
    let _held = TagGuard { tag: held, log };
    {
        let _gone = TagGuard { tag: gone, log };
    }
    let count = log.borrow().len() as i64;
    count
}

fn eval(op: Op, log: &RefCell<Vec<u64>>, t: u64, u: u64, abort: bool) -> Out {
    match op {
        Op::SequentialTwo => b_sequential_two(log, t, u),
        Op::NestedScopeOrder => b_nested_scope_order(log, t, u),
        Op::ExplicitDropNow => b_explicit_drop_now(log, t),
        Op::EarlyReturnStillDrops => b_early_return_still_drops(log, t, abort),
        Op::HoldAndRelease => b_hold_and_release(log, t, u),
    }
}

const CANONICAL_SEED: u64 = 0x2A11_FA11;

/// A pair of distinct nonzero tags.
type CanonicalCase = (u64, u64);

fn canonical(seed: u64) -> CanonicalCase {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let t = rng.below(7) + 1;
        let u = rng.below(7) + 1;
        if anchors_hold(t, u) {
            return (t, u);
        }
    }
    unreachable!("canonical tags unreachable");
}

fn anchors_hold(t: u64, u: u64) -> bool {
    t >= 1 && u >= 1 && t != u
}
struct ExampleCase {
    t: u64,
    u: u64,
    answers: Vec<(Op, Out)>,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0184;

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let (t, u) = canonical(seed);
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases = Vec::new();
    let push_case = |cases: &mut Vec<ExampleCase>, t: u64, u: u64| {
        cases.push(ExampleCase {
            answers: OP_ALL
                .iter()
                .map(|&op| (op, eval(op, &RefCell::new(Vec::new()), t, u, false)))
                .collect(),
            t,
            u,
        });
    };
    push_case(&mut cases, t, u);
    for (t, u) in [(1u64, 1u64), (9, 2)] {
        push_case(&mut cases, t, u);
    }
    for _ in 0..3 {
        let t = rng.below(7) + 1;
        let u = rng.below(7) + 1;
        push_case(&mut cases, t, u);
    }
    cases
}

/// The log contents each op must leave behind.
fn expected_log_src(op: Op, t: u64, u: u64) -> String {
    match op {
        Op::SequentialTwo => format!("vec![{t}, {u}]"),
        Op::NestedScopeOrder => format!("vec![{u}, {t}]"),
        Op::ExplicitDropNow | Op::EarlyReturnStillDrops => format!("vec![{t}]"),
        Op::HoldAndRelease => format!("vec![{u}, {t}]"),
    }
}

/// Call text for one op against a bound `log`.
fn call_src(op: Op, tvar: &str, uvar: &str) -> String {
    match op {
        Op::SequentialTwo => format!("{}(&log, {tvar}, {uvar})", op.name()),
        Op::NestedScopeOrder => format!("{}(&log, {tvar}, {uvar})", op.name()),
        Op::HoldAndRelease => format!("{}(&log, {tvar}, {uvar})", op.name()),
        Op::ExplicitDropNow => format!("{}(&log, {tvar})", op.name()),
        Op::EarlyReturnStillDrops => format!("{}(&log, {tvar}, false)", op.name()),
    }
}

fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(log: &RefCell<Vec<u64>>{}) -> i64",
        op.name(),
        op.extra_arg()
    )
}

fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}
fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::SequentialTwo => &[
            "    {",
            "        let _first = TagGuard { tag: t, log };",
            "    }",
            "    {",
            "        let _second = TagGuard { tag: u, log };",
            "    }",
            "    let count = log.borrow().len() as i64;",
            "    count",
        ],
        Op::NestedScopeOrder => &[
            "    let _outer = TagGuard { tag: outer, log };",
            "    {",
            "        let _inner = TagGuard { tag: inner, log };",
            "    }",
            "    let first = log.borrow()[0];",
            "    first as i64",
        ],
        Op::ExplicitDropNow => &[
            "    let g = TagGuard { tag, log };",
            "    std::mem::drop(g);",
            "    let count = log.borrow().len() as i64;",
            "    count",
        ],
        Op::EarlyReturnStillDrops => &[
            "    let g = TagGuard { tag, log };",
            "    if abort {",
            "        return -1;",
            "    }",
            "    std::mem::drop(g);",
            "    let count = log.borrow().len() as i64;",
            "    count",
        ],
        Op::HoldAndRelease => &[
            "    let _held = TagGuard { tag: held, log };",
            "    {",
            "        let _gone = TagGuard { tag: gone, log };",
            "    }",
            "    let count = log.borrow().len() as i64;",
            "    count",
        ],
    };
    format!("{}\n{{\n{}\n}}\n", op_sig_src(op), body.join("\n"))
}

fn reference_src(spec: Spec) -> String {
    let mut src = String::from("use std::cell::RefCell;\n\n");
    src.push_str(GUARD_SRC);
    src.push('\n');
    src.push_str(
        &spec
            .ops
            .iter()
            .map(|&op| op_fn_src(op))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    src
}

fn worked_examples_prose(examples: &[ExampleCase]) -> Vec<String> {
    examples
        .iter()
        .flat_map(|case| {
            let t = case.t;
            let u = case.u;
            case.answers
                .iter()
                .map(move |(op, out)| format!("  tags ({t}, {u})  ->  {} = {out}", op.name()))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut doc = String::from("//! Drop-timing puzzles over one shared audit log.\n");
    doc.push_str("//!\n");
    doc.push_str("//! A TagGuard type is PROVIDED below; it appends its tag to the\n");
    doc.push_str("//! shared log exactly when it drops. Sequence scopes so each\n");
    doc.push_str("//! query's answer and final log match the examples.\n");
    doc.push_str("//!\n");
    for line in worked_examples_prose(examples) {
        doc.push_str(&format!("//!{line}\n"));
    }
    doc.push('\n');
    doc.push_str("use std::cell::RefCell;\n\n");
    doc.push_str(GUARD_SRC);
    doc.push('\n');
    for &op in spec.ops.iter() {
        doc.push_str(&op_stub_src(op));
        doc.push('\n');
    }
    doc
}
fn prompt_intro() -> String {
    String::from(
        "Implement the required queries over one shared audit log.\n\nRequirements:\n\
- A TagGuard type is provided in the skeleton; it appends its tag when it drops.\n\
- Release the first guard before the second begins where sequencing demands it.\n\
- An inner scope closes before any outer-scope code reads the log.\n\
- A guard released explicitly lands its entry at once; a guard alive across an early return still lands it.\n\
- Two guards made in one scope land their entries newest first.\n\
- Answers are exact integers; conventions are shown in the examples.\n\nConstraints:\n- No unsafe code.\n",
    )
}

fn cargo_toml() -> String {
    String::from(
        "[package]\nname = \"task\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n",
    )
}

fn behavior_test_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut src = String::from("use std::cell::RefCell;\nuse task::{");
    let names: Vec<&str> = spec.ops.iter().map(|op| op.name()).collect();
    src.push_str(&names.join(", "));
    src.push_str("};\n\n");
    for (i, case) in examples.iter().enumerate() {
        src.push_str(&format!("#[test]\nfn ex{i}() {{\n"));
        src.push_str(&format!("    let t: u64 = {};\n", case.t));
        src.push_str(&format!("    let u: u64 = {};\n", case.u));
        for &(op, out) in case.answers.iter() {
            if !spec.ops.contains(&op) {
                continue;
            }
            if op == Op::EarlyReturnStillDrops {
                // Both paths must leave exactly one entry.
                src.push_str(&format!(
                    "    {{ let log = RefCell::new(Vec::new()); assert_eq!(early_return_still_drops(&log, t, true), -1); assert_eq!(*log.borrow(), vec![{}]); }}\n",
                    case.t
                ));
                src.push_str(&format!(
                    "    {{ let log = RefCell::new(Vec::new()); assert_eq!(early_return_still_drops(&log, t, false), {out}); assert_eq!(*log.borrow(), vec![{}]); }}\n",
                    case.t
                ));
                continue;
            }
            src.push_str(&format!(
                "    {{ let log = RefCell::new(Vec::new()); assert_eq!({}, {out}); assert_eq!(*log.borrow(), {}); }}\n",
                call_src(op, "t", "u"),
                expected_log_src(op, case.t, case.u)
            ));
        }
        src.push_str("}\n\n");
    }
    src
}
fn differential_test_src(spec: Spec) -> String {
    let mut src = String::from("use std::cell::RefCell;\nuse task::{");
    let names: Vec<&str> = spec.ops.iter().map(|op| op.name()).collect();
    src.push_str(&names.join(", "));
    src.push_str("};\n\n");

    for &op in spec.ops.iter() {
        let renamed = op_fn_src(op).replacen(
            &format!("pub fn {}(", op.name()),
            &format!("fn ref_{}(", op.name()),
            1,
        );
        assert!(renamed.contains(&format!("fn ref_{}(", op.name())));
        src.push_str(&renamed);
        src.push('\n');
    }
    // The pasted reference needs the guard too.
    src.push_str(GUARD_SRC);
    src.push('\n');

    src.push_str("fn nx(state: &mut u64) -> u64 {\n");
    src.push_str("    *state = state\n");
    src.push_str("        .wrapping_mul(6364136223846793005)\n");
    src.push_str("        .wrapping_add(1442695040888963407);\n");
    src.push_str("    *state >> 33\n}\n\n");

    src.push_str("#[test]\nfn differential_vs_reference() {\n");
    src.push_str("    let mut state: u64 = 0xE7EE_ED00_0000_0184;\n");
    src.push_str("    for _ in 0..3000 {\n");
    src.push_str("        let t = (nx(&mut state) % 7) + 1;\n");
    src.push_str("        let u = (nx(&mut state) % 7) + 1;\n");
    for &op in spec.ops.iter() {
        let call = call_src(op, "t", "u");
        let ref_call = match op {
            Op::SequentialTwo => "ref_sequential_two(&log, t, u)".to_string(),
            Op::NestedScopeOrder => "ref_nested_scope_order(&log, t, u)".to_string(),
            Op::HoldAndRelease => "ref_hold_and_release(&log, t, u)".to_string(),
            Op::ExplicitDropNow => "ref_explicit_drop_now(&log, t)".to_string(),
            Op::EarlyReturnStillDrops => "ref_early_return_still_drops(&log, t, false)".to_string(),
        };
        src.push_str(&format!(
            "        {{ let log = RefCell::new(Vec::new()); assert_eq!({call}, {{ let log = RefCell::new(Vec::new()); {ref_call} }}); }}\n"
        ));
    }
    src.push_str("    }\n}\n");
    src
}

fn const_zero(spec: Spec) -> String {
    let mut src = String::from("#![allow(dead_code)]\n\nuse std::cell::RefCell;\n\n");
    src.push_str(GUARD_SRC);
    src.push('\n');
    for &op in spec.ops.iter() {
        let body = match op {
            Op::EarlyReturnStillDrops => "let _ = (log, tag, abort);\n    0",
            Op::ExplicitDropNow => "let _ = (log, tag);\n    0",
            Op::HoldAndRelease => "let _ = (log, held, gone);\n    0",
            _ => "let _ = (log, t, u);\n    0",
        };
        src.push_str(&format!("{}\n{{\n{body}\n}}\n\n", op_sig_src(op)));
    }
    src
}

/// The naive baseline reads the log while its guards are still alive, so
/// every entry is missing and every answer is wrong — empty starts
/// included.
fn naive_holds_guards(spec: Spec) -> String {
    let mut src = String::from("use std::cell::RefCell;\n\n");
    src.push_str(GUARD_SRC);
    src.push('\n');
    for &op in spec.ops.iter() {
        let body: &[&str] = match op {
            Op::SequentialTwo => &[
                "    let _g1 = TagGuard { tag: t, log };",
                "    let _g2 = TagGuard { tag: u, log };",
                "    log.borrow().len() as i64",
            ],
            Op::NestedScopeOrder => &[
                "    let _o = TagGuard { tag: outer, log };",
                "    let _i = TagGuard { tag: inner, log };",
                "    log.borrow().len() as i64",
            ],
            Op::ExplicitDropNow => &[
                "    let _g = TagGuard { tag, log };",
                "    log.borrow().len() as i64",
            ],
            Op::EarlyReturnStillDrops => &[
                "    let _g = TagGuard { tag, log };",
                "    if abort {",
                "        return -1;",
                "    }",
                "    log.borrow().len() as i64",
            ],
            Op::HoldAndRelease => &[
                "    let _h = TagGuard { tag: held, log };",
                "    let _g = TagGuard { tag: gone, log };",
                "    log.borrow().len() as i64",
            ],
        };
        src.push_str(&format!(
            "{}\n{{\n{}\n}}\n\n",
            op_sig_src(op),
            body.join("\n")
        ));
    }
    src
}
pub struct RaiiGuardFamily;

impl Generator for RaiiGuardFamily {
    fn id(&self) -> &'static str {
        "raii-guard"
    }

    fn category(&self) -> &'static str {
        "drop-semantics"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let mut files = std::collections::BTreeMap::new();
        files.insert(std::path::PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(
            std::path::PathBuf::from("src/lib.rs"),
            skeleton_src(spec, &examples),
        );
        let mut hidden = std::collections::BTreeMap::new();
        hidden.insert(
            std::path::PathBuf::from("tests/behavior.rs"),
            behavior_test_src(spec, &examples),
        );
        hidden.insert(
            std::path::PathBuf::from("tests/differential.rs"),
            differential_test_src(spec),
        );

        let mut prompt = prompt_intro();
        prompt.push_str("\nQueries required:\n");
        for &op in spec.ops.iter() {
            prompt.push_str(&format!("- {}: {}\n", op.name(), op.prose()));
        }
        prompt.push_str("\nSignatures to implement:\n\n```rust\n");
        for &op in spec.ops.iter() {
            prompt.push_str(&format!("{}\n", op_sig_src(op)));
        }
        prompt.push_str("```\n\nWorked examples (tags -> answer):\n\n");
        for line in worked_examples_prose(&examples) {
            prompt.push_str(&line);
            prompt.push('\n');
        }
        prompt.push_str("\nThe canary for this task is ");
        prompt.push_str(&mint_canary("raii-guard", seed));
        prompt.push_str(".\n");

        GeneratedTask {
            id: format!("raii-guard/{seed:016x}"),
            category: self.category().to_string(),
            prompt,
            canary: mint_canary("raii-guard", seed),
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            max_unsafe: None,
            forbidden_paths: vec![],
            check_clippy: false,
            clippy_allow: vec![],
            weights: (0.70, 0.20, 0.10),
        }
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let mut names: Vec<&str> = sample(seed).ops.iter().map(|&op| op.name()).collect();
        names.sort_unstable();
        vec![format!("q:{}", names[0]), format!("q:{}", names[1])]
    }

    fn reference_code(&self, seed: u64) -> String {
        reference_src(sample(seed))
    }

    fn skeleton_code(&self, seed: u64) -> String {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        skeleton_src(spec, &examples)
    }

    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero(spec)),
            ("holds-guards".to_string(), naive_holds_guards(spec)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = RaiiGuardFamily.generate(7);
        let b = RaiiGuardFamily.generate(7);
        assert_eq!(a.id, b.id);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
    }

    #[test]
    fn native_ops_match_intent_with_exact_logs() {
        let log = RefCell::new(Vec::new());
        assert_eq!(b_sequential_two(&log, 3, 5), 2);
        assert_eq!(*log.borrow(), vec![3, 5]);

        let log = RefCell::new(Vec::new());
        assert_eq!(b_nested_scope_order(&log, 9, 4), 4);
        assert_eq!(*log.borrow(), vec![4, 9]);

        // The answer is the log's head AT READ TIME: on a reused log the
        // pre-existing oldest entry outranks the freshly landed inner tag.
        let log = RefCell::new(vec![5]);
        assert_eq!(b_nested_scope_order(&log, 9, 4), 5);
        assert_eq!(*log.borrow(), vec![5, 4, 9]);

        let log = RefCell::new(Vec::new());
        assert_eq!(b_explicit_drop_now(&log, 7), 1);
        assert_eq!(*log.borrow(), vec![7]);

        let log = RefCell::new(Vec::new());
        assert_eq!(b_early_return_still_drops(&log, 6, true), -1);
        assert_eq!(*log.borrow(), vec![6]);
        assert_eq!(b_early_return_still_drops(&log, 6, false), 2);
        assert_eq!(*log.borrow(), vec![6, 6]);

        let log = RefCell::new(Vec::new());
        assert_eq!(b_hold_and_release(&log, 8, 2), 1);
        assert_eq!(*log.borrow(), vec![2, 8]);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..300 {
            seen.insert(sample(seed));
        }
        assert!(seen.len() >= 9, "only {} distinct pairs", seen.len());
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        for seed in 0..200u64 {
            let (t, u) = canonical(seed);
            assert!(t >= 1 && u >= 1 && t != u);
            for &op in OP_ALL.iter() {
                let log = RefCell::new(Vec::new());
                let out = eval(op, &log, t, u, false);
                assert_ne!(out, 0, "seed {seed} op {} answered zero", op.name());
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for case in worked_examples(seed) {
                for (op, want) in case.answers {
                    let log = RefCell::new(Vec::new());
                    assert_eq!(eval(op, &log, case.t, case.u, false), want);
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let src = reference_src(spec);
            for &op in OP_ALL.iter() {
                let marker = format!("pub fn {}(", op.name());
                let wanted = spec.ops.contains(&op);
                assert_eq!(
                    src.contains(&marker),
                    wanted,
                    "seed {seed} op {} marker mismatch",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let examples = worked_examples(seed);
            let sk = skeleton_src(spec, &examples);
            let prompt_src = {
                let family = RaiiGuardFamily;
                family.generate(seed).prompt
            };
            assert_eq!(sk.matches("todo!()").count(), spec.ops.len());
            for token in ["mem::drop(", "let _outer", "let _inner"] {
                assert!(
                    !sk.contains(token),
                    "skeleton leaked {token} at seed {seed}"
                );
                assert!(
                    !prompt_src.contains(token),
                    "prompt leaked {token} at seed {seed}"
                );
            }
            for &op in spec.ops.iter() {
                assert!(
                    prompt_src.contains(&op_sig_src(op)),
                    "prompt missing signature for {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for &op in OP_ALL.iter() {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call = call_src(op, "t", "u");
            assert_eq!(
                params.matches(',').count(),
                call.matches(',').count(),
                "{} arity drift",
                op.name()
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let task = RaiiGuardFamily.generate(11);
        assert!(task.prompt.contains(&task.canary));
    }

    #[test]
    fn naive_baseline_reads_while_guards_still_live() {
        let spec = sample(17);
        let naive = naive_holds_guards(spec);
        assert!(naive.contains("log.borrow().len()"));
        assert!(!naive.contains("mem::drop("));
        if spec.ops.contains(&Op::ExplicitDropNow) {
            assert!(reference_src(spec).contains("std::mem::drop("));
        }
    }
}

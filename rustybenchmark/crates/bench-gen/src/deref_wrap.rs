//! See-through wrapper puzzles over one bag of counts.
//!
//! Every query here is answered THROUGH a newtype: method calls,
//! indexing, mutation, and multi-step chains all reach the payload only
//! because `Deref` (and `DerefMut`) forward them. The generator ships the
//! wrapper structs with the deref impl bodies STUBBED; the model writes
//! those tiny impls and every provided driver starts working via
//! coercion. Equality is deliberately NOT granted by `Deref` — operator
//! operands do not coerce — so `same_contents` reaches its targets
//! explicitly, pinning that boundary too.

use crate::{mint_canary, GeneratedTask, Generator, Rng};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    TotalThrough,
    PushThrough,
    LastThrough,
    HeadTwo,
    SameContents,
}

pub const OP_ALL: [Op; 5] = [
    Op::TotalThrough,
    Op::PushThrough,
    Op::LastThrough,
    Op::HeadTwo,
    Op::SameContents,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::TotalThrough => "total_through",
            Op::PushThrough => "push_through",
            Op::LastThrough => "last_through",
            Op::HeadTwo => "head_through_two",
            Op::SameContents => "same_contents",
        }
    }

    pub fn extra_arg(self) -> &'static str {
        match self {
            Op::TotalThrough | Op::LastThrough | Op::HeadTwo => "",
            Op::PushThrough => ", x: u64",
            Op::SameContents => ", right: &CountWrap<'_>",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::TotalThrough => "sum every element of the wrapped bag",
            Op::PushThrough => {
                "append one count through the mutable wrapper and report the new length"
            }
            Op::LastThrough => {
                "report the final element reached by indexing into the wrapper (-1 when empty)"
            }
            Op::HeadTwo => {
                "report the first element seen through both wrapping layers (-1 when empty)"
            }
            Op::SameContents => "report 1 when two wrapped bags hold identical contents, else 0",
        }
    }

    pub fn ret(self) -> &'static str {
        "i64"
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let i = rng.below(OP_ALL.len() as u64) as usize;
    let mut j = rng.below(OP_ALL.len() as u64) as usize;
    while j == i {
        j = rng.below(OP_ALL.len() as u64) as usize;
    }
    let mut ops = [OP_ALL[i], OP_ALL[j]];
    ops.sort();
    Spec { ops }
}

type Out = i64;

/// How the deref impl bodies are rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImplMode {
    /// Correct forwarding bodies.
    Solved,
    /// `todo!()` stubs for the model to fill.
    Stub,
    /// A compiling but wrong view: the slice target always reads empty.
    SeesNothing,
}

/// The provided wrapper machinery shipped inside every artefact.
pub fn wrappers_src(mode: ImplMode) -> String {
    let body = |solved: &str, cheated: &str| match mode {
        ImplMode::Solved => solved.to_string(),
        ImplMode::Stub => "todo!()".to_string(),
        ImplMode::SeesNothing => cheated.to_string(),
    };
    let count_body = body("self.0", "&self.0[..0]");
    let owned_body = body("&self.0", "&self.0");
    let owned_mut_body = body("&mut self.0", "&mut self.0");
    let double_body = body("self.0", "self.0");
    let mut s = String::new();
    s.push_str("/// A borrowed view the rest of the crate treats as `[u64]`.\npub struct CountWrap<'a>(pub &'a [u64]);\n\n");
    s.push_str("impl std::ops::Deref for CountWrap<'_> {\n    type Target = [u64];\n\n    fn deref(&self) -> &[u64] {\n        ");
    s.push_str(&count_body);
    s.push_str("\n    }\n}\n\n");
    s.push_str("/// An owned wrapper whose inner vector is reachable only through\n/// the deref chain.\npub struct Owned(pub Vec<u64>);\n\n");
    s.push_str("impl std::ops::Deref for Owned {\n    type Target = Vec<u64>;\n\n    fn deref(&self) -> &Vec<u64> {\n        ");
    s.push_str(&owned_body);
    s.push_str("\n    }\n}\n\nimpl std::ops::DerefMut for Owned {\n    fn deref_mut(&mut self) -> &mut Vec<u64> {\n        ");
    s.push_str(&owned_mut_body);
    s.push_str("\n    }\n}\n\n");
    s.push_str("/// A wrapper around a wrapper - reaching the bag takes two steps.\npub struct DoubleWrap<'a>(pub &'a CountWrap<'a>);\n\n");
    s.push_str("impl<'a> std::ops::Deref for DoubleWrap<'a> {\n    type Target = CountWrap<'a>;\n\n    fn deref(&self) -> &CountWrap<'a> {\n        ");
    s.push_str(&double_body);
    s.push_str("\n    }\n}\n");
    s
}
fn b_total(view: &[u64]) -> i64 {
    let total: u64 = view.iter().sum();
    total as i64
}

fn b_last(view: &[u64]) -> i64 {
    if view.is_empty() {
        return -1;
    }
    let v = view[view.len() - 1];
    v as i64
}

fn b_head_two(view: &[u64]) -> i64 {
    if view.is_empty() {
        return -1;
    }
    let v = view[0];
    v as i64
}

fn b_push(len_before: usize, _x: u64) -> i64 {
    let len = len_before + 1;
    len as i64
}

fn b_same(a: &[u64], b: &[u64]) -> i64 {
    if a == b {
        1
    } else {
        0
    }
}

pub fn eval(op: Op, bag: &[u64], other: &[u64], x: u64) -> Out {
    match op {
        Op::TotalThrough => b_total(bag),
        Op::PushThrough => b_push(bag.len(), x),
        Op::LastThrough => b_last(bag),
        Op::HeadTwo => b_head_two(bag),
        Op::SameContents => b_same(bag, other),
    }
}

pub const CANONICAL_SEED: u64 = 0xD3FE_FA11;

pub fn canonical(seed: u64) -> (Vec<u64>, Vec<u64>, u64) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = 2 + rng.below(4) as usize;
        let mut bag = Vec::new();
        for _ in 0..n {
            bag.push(1 + rng.below(8));
        }
        let other: Vec<u64> = bag.iter().rev().copied().collect();
        let x = 1 + rng.below(5);
        let ok = bag != other
            && (b_total(&bag) as u64) != x
            && b_last(&bag) != b_head_two(&bag)
            && n >= 2;
        if ok {
            return (bag, other, x);
        }
    }
    unreachable!("canonical bag unreachable for deref-wrap");
}

#[derive(Clone, Debug)]
pub struct ExampleCase {
    pub bag: Vec<u64>,
    pub other: Vec<u64>,
    pub x: u64,
    pub answers: Vec<(Op, Out)>,
}

pub const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0186;

fn case(bag: Vec<u64>, other: Vec<u64>, x: u64) -> ExampleCase {
    let answers = OP_ALL
        .iter()
        .map(|&op| (op, eval(op, &bag, &other, x)))
        .collect();
    ExampleCase {
        bag,
        other,
        x,
        answers,
    }
}

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![case(
        canonical(seed).0.clone(),
        canonical(seed).1.clone(),
        canonical(seed).2,
    )];
    out.push(case(Vec::new(), Vec::new(), 1));
    out.push(case(vec![9], vec![9], 3));
    out.push(case(vec![4, 4], vec![4, 5], 2));
    for _ in 0..3 {
        let mut rng = Rng::new(rng_seed_from(out.len(), seed));
        let n = rng.below(5) as usize;
        let bag: Vec<u64> = (0..n).map(|_| 1 + rng.below(8)).collect();
        let other: Vec<u64> = (0..n).map(|_| 1 + rng.below(8)).collect();
        let x = 1 + rng.below(5);
        out.push(case(bag, other, x));
    }
    out
}

fn rng_seed_from(index: usize, seed: u64) -> u64 {
    seed ^ (0x5EED_0000_0000_0000 + index as u64)
}
pub fn render_bag(bag: &[u64]) -> String {
    if bag.is_empty() {
        return "&[]".to_string();
    }
    let items: Vec<String> = bag.iter().map(|v| format!("{v}u64")).collect();
    format!("&[{}]", items.join(", "))
}

pub fn op_sig_src(op: Op) -> String {
    match op {
        Op::TotalThrough => "pub fn total_through(view: &CountWrap<'_>) -> i64".to_string(),
        Op::PushThrough => "pub fn push_through(slot: &mut Owned, x: u64) -> i64".to_string(),
        Op::LastThrough => "pub fn last_through(view: &CountWrap<'_>) -> i64".to_string(),
        Op::HeadTwo => "pub fn head_through_two(nested: &DoubleWrap<'_>) -> i64".to_string(),
        Op::SameContents => {
            "pub fn same_contents(left: &CountWrap<'_>, right: &CountWrap<'_>) -> i64".to_string()
        }
    }
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::TotalThrough => &["let total: u64 = view.iter().sum();", "total as i64"],
        Op::PushThrough => &["slot.push(x);", "let len = slot.len();", "len as i64"],
        Op::LastThrough => &[
            "if view.is_empty() {",
            "    return -1;",
            "}",
            "let v = view[view.len() - 1];",
            "v as i64",
        ],
        Op::HeadTwo => &[
            "if nested.is_empty() {",
            "    return -1;",
            "}",
            "let v = nested[0];",
            "v as i64",
        ],
        Op::SameContents => &[
            "if left.deref() == right.deref() {",
            "    1",
            "} else {",
            "    0",
            "}",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let mut s = String::from("use std::ops::Deref;\n\n");
    s.push_str(&wrappers_src(ImplMode::Solved));
    s.push('\n');
    for op in spec.ops {
        s.push_str(&op_fn_src(op));
    }
    s
}

pub fn call_src(op: Op) -> String {
    match op {
        Op::TotalThrough => "total_through(&view)".to_string(),
        Op::PushThrough => "push_through(&mut slot, x)".to_string(),
        Op::LastThrough => "last_through(&view)".to_string(),
        Op::HeadTwo => "head_through_two(&nested)".to_string(),
        Op::SameContents => "same_contents(&left, &right)".to_string(),
    }
}

pub fn bind_lines(op: Op, case: &ExampleCase) -> Vec<String> {
    let mut lines = Vec::new();
    match op {
        Op::TotalThrough | Op::LastThrough => {
            lines.push(format!("let bag = {};", render_bag(&case.bag)));
            lines.push("let view = CountWrap(bag);".to_string());
        }
        Op::PushThrough => {
            lines.push(format!(
                "let mut slot = Owned(({}).to_vec());",
                render_bag(&case.bag)
            ));
            lines.push(format!("let x = {}u64;", case.x));
        }
        Op::HeadTwo => {
            lines.push(format!("let bag = {};", render_bag(&case.bag)));
            lines.push("let view = CountWrap(bag);".to_string());
            lines.push("let nested = DoubleWrap(&view);".to_string());
        }
        Op::SameContents => {
            lines.push(format!("let lbag = {};", render_bag(&case.bag)));
            lines.push(format!("let rbag = {};", render_bag(&case.other)));
            lines.push("let left = CountWrap(lbag);".to_string());
            lines.push("let right = CountWrap(rbag);".to_string());
        }
    }
    lines
}
pub fn worked_examples_prose(seed: u64) -> Vec<String> {
    let mut lines = Vec::new();
    for (i, case) in worked_examples(seed).iter().enumerate() {
        for (op, out) in &case.answers {
            lines.push(format!(
                "  ex{} bag {} other {} x {}  ->  {} = {}",
                i,
                render_bag(&case.bag),
                render_bag(&case.other),
                case.x,
                op.name(),
                out
            ));
        }
    }
    lines
}

pub fn skeleton_src(spec: Spec, seed: u64) -> String {
    let mut s = String::from("//! See-through wrapper puzzles.\n//!\n");
    s.push_str("//! The wrapper structs below are PROVIDED, but every deref impl\n");
    s.push_str("//! body is `todo!()`. Fill those impls in so the provided driver\n");
    s.push_str("//! functions work through automatic coercion. Equality does not\n");
    s.push_str("//! come free: operator operands never coerce, which is why\n");
    s.push_str("//! `same_contents` reaches its targets explicitly.\n//!\n");
    for l in worked_examples_prose(seed) {
        s.push_str(&format!("//! {l}\n"));
    }
    s.push_str("\nuse std::ops::Deref;\nuse std::ops::DerefMut;\n\n");
    s.push_str(&wrappers_src(ImplMode::Stub));
    s.push_str("\n// Provided drivers - do not change them.\n");
    for op in spec.ops {
        s.push_str(&format!("// {}\n", op.prose()));
        s.push_str(&op_fn_src(op));
    }
    s
}

pub fn prompt_intro() -> &'static str {
    "Write the missing deref implementations so that every provided\nfunction works purely through Rust's automatic coercion rules."
}

pub fn prompt(spec: Spec, seed: u64, canary: &str) -> String {
    let mut s = String::new();
    s.push_str(prompt_intro());
    s.push_str("\n\n## What you must provide\n\n");
    s.push_str("- The body of `CountWrap::deref`, forwarding to the borrowed slice.\n");
    s.push_str("- The body of `Owned::deref` and `Owned::deref_mut`.\n");
    s.push_str("- The body of `DoubleWrap::deref`, one step along the chain.\n");
    s.push_str("- Method calls, indexing, iteration, and mutation must reach the\n  wrapped data without touching any private field directly.\n");
    s.push('\n');
    for op in spec.ops {
        s.push_str(&format!("- {}\n", op.prose()));
    }
    s.push_str("\n## Constraints\n\n- No unsafe code.\n- Keep every provided signature, struct, and driver unchanged.\n");
    s.push_str("\n## Signatures you may call\n\n```rust\n");
    for op in spec.ops {
        s.push_str(&op_sig_src(op));
        s.push('\n');
    }
    s.push_str("```\n\n## Worked examples\n\n```text\n");
    for l in worked_examples_prose(seed) {
        s.push_str(&l);
        s.push('\n');
    }
    s.push_str("```\n\nThe canary token for this task is:\n\n```text\n");
    s.push_str(canary);
    s.push_str("\n```\n");
    s
}

pub fn cargo_toml() -> String {
    "[package]\nname = \"task\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n"
        .to_string()
}
pub fn behavior_test_src(spec: Spec, seed: u64) -> String {
    let mut s = String::from("use task::{");
    let mut names: Vec<&str> = spec.ops.iter().map(|o| o.name()).collect();
    names.extend_from_slice(&["CountWrap", "Owned", "DoubleWrap"]);
    s.push_str(&names.join(", "));
    s.push_str("};\n\n");
    for (i, case) in worked_examples(seed).iter().enumerate() {
        for (op, out) in &case.answers {
            if !spec.ops.contains(op) {
                continue;
            }
            s.push_str(&format!("#[test]\nfn ex{}_{}() {{\n", i, op.name()));
            for line in bind_lines(*op, case) {
                s.push_str(&format!("    {line}\n"));
            }
            s.push_str(&format!(
                "    assert_eq!({}, {});\n}}\n\n",
                call_src(*op),
                out
            ));
        }
    }
    s
}

pub fn differential_test_src(spec: Spec, _seed: u64) -> String {
    let mut s = String::from("use task::{");
    let names: Vec<&str> = spec.ops.iter().map(|o| o.name()).collect();
    s.push_str(&names.join(", "));
    s.push_str("};\n\n");

    // Paste once with every selected driver renamed.
    let mut pasted = reference_src(spec);
    for op in spec.ops {
        let target = format!("pub fn {}(", op.name());
        let renamed = format!("fn ref_{}(", op.name());
        assert_eq!(pasted.matches(&target).count(), 1, "rename count");
        pasted = pasted.replacen(&target, &renamed, 1);
    }
    s.push_str(&pasted);
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state\n        .wrapping_mul(6364136223846793005)\n        .wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n#[test]\nfn differential_vs_reference() {\n    let mut state: u64 = 0xE7EE_ED00_0000_0186;");
    s.push_str("    for _ in 0..3000 {\n");
    s.push_str("        let n = (nx(&mut state) % 5) as usize;\n");
    s.push_str("        let mut vals = Vec::new();\n");
    s.push_str("        for _ in 0..n {\n");
    s.push_str("            vals.push(1 + nx(&mut state) % 8);\n");
    s.push_str("        }\n");
    s.push_str("        let other: Vec<u64> = vals.iter().rev().copied().collect();\n");
    s.push_str("        let x = 1 + nx(&mut state) % 5;\n");
    for op in spec.ops {
        match op {
            Op::TotalThrough => {
                s.push_str("        let view = task::CountWrap(&vals);\n");
                s.push_str("        let rview = CountWrap(&vals);\n");
                s.push_str(
                    "        assert_eq!(total_through(&view), ref_total_through(&rview));\n",
                );
            }
            Op::PushThrough => {
                s.push_str("        let mut a = task::Owned(vals.clone());\n");
                s.push_str("        let mut b = Owned(vals.clone());\n");
                s.push_str(
                    "        assert_eq!(push_through(&mut a, x), ref_push_through(&mut b, x));\n",
                );
            }
            Op::LastThrough => {
                s.push_str("        let view = task::CountWrap(&vals);\n");
                s.push_str("        let rview = CountWrap(&vals);\n");
                s.push_str("        assert_eq!(last_through(&view), ref_last_through(&rview));\n");
            }
            Op::HeadTwo => {
                s.push_str("        let view = task::CountWrap(&vals);\n");
                s.push_str("        let nested = task::DoubleWrap(&view);\n");
                s.push_str("        let rview = CountWrap(&vals);\n");
                s.push_str("        let rnested = DoubleWrap(&rview);\n");
                s.push_str("        assert_eq!(head_through_two(&nested), ref_head_through_two(&rnested));\n");
            }
            Op::SameContents => {
                s.push_str("        let left = task::CountWrap(&vals);\n");
                s.push_str("        let right = task::CountWrap(&other);\n");
                s.push_str("        let rleft = CountWrap(&vals);\n");
                s.push_str("        let rright = CountWrap(&other);\n");
                s.push_str("        assert_eq!(same_contents(&left, &right), ref_same_contents(&rleft, &rright));\n");
            }
        }
    }
    s.push_str("    }\n}\n");
    s
}
pub fn const_zero(spec: Spec) -> String {
    let mut s =
        String::from("#![allow(dead_code)]\nuse std::ops::Deref;\nuse std::ops::DerefMut;\n\n");
    s.push_str(&wrappers_src(ImplMode::Solved));
    s.push('\n');
    for op in spec.ops {
        let sig = op_sig_src(op);
        let body = match op {
            Op::PushThrough => "    let _ = (slot, x);\n    0",
            Op::SameContents => "    let _ = (left, right);\n    0",
            _ => "    let _ = view;\n    0",
        };
        s.push_str(&format!("{sig} {{\n{body}\n}}\n"));
    }
    s
}

pub fn sees_nothing(spec: Spec) -> String {
    let mut s = String::from("use std::ops::Deref;\nuse std::ops::DerefMut;\n\n");
    s.push_str(&wrappers_src(ImplMode::SeesNothing));
    s.push('\n');
    for op in spec.ops {
        s.push_str(&op_fn_src(op));
    }
    s
}

pub struct DerefWrapFamily;

impl Generator for DerefWrapFamily {
    fn id(&self) -> &'static str {
        "deref-wrap"
    }

    fn category(&self) -> &'static str {
        "smart-pointers"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let id = format!("deref-wrap/{seed:016x}");
        let canary = mint_canary("deref-wrap", seed);
        let mut files = std::collections::BTreeMap::new();
        files.insert(std::path::PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(
            std::path::PathBuf::from("src/lib.rs"),
            skeleton_src(spec, seed),
        );
        let mut hidden = std::collections::BTreeMap::new();
        hidden.insert(
            std::path::PathBuf::from("tests/behavior.rs"),
            behavior_test_src(spec, seed),
        );
        hidden.insert(
            std::path::PathBuf::from("tests/differential.rs"),
            differential_test_src(spec, seed),
        );
        GeneratedTask {
            id,
            category: self.category().to_string(),
            prompt: prompt(spec, seed, &canary),
            canary,
            answer_path: String::from("src/lib.rs"),
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

    fn reference_code(&self, seed: u64) -> String {
        reference_src(sample(seed))
    }

    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(sample(seed), seed)
    }

    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero(spec)),
            ("sees-nothing".to_string(), sees_nothing(spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        spec.ops
            .iter()
            .map(|op| format!("q:{}", op.name()))
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = DerefWrapFamily.generate(5);
        let b = DerefWrapFamily.generate(5);
        assert_eq!(a.id, b.id);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
    }

    #[test]
    fn native_ops_match_intent() {
        assert_eq!(b_total(&[3, 1, 4]), 8);
        assert_eq!(b_last(&[3, 1, 4]), 4);
        assert_eq!(b_last(&[]), -1);
        assert_eq!(b_head_two(&[3, 1, 4]), 3);
        assert_eq!(b_head_two(&[]), -1);
        assert_eq!(b_push(2, 9), 3);
        assert_eq!(b_push(0, 5), 1);
        assert_eq!(b_same(&[3, 1], &[3, 1]), 1);
        assert_eq!(b_same(&[3, 1], &[3]), 0);
        assert_eq!(b_same(&[], &[]), 1);
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
            let (bag, other, x) = canonical(seed);
            assert!(bag.len() >= 2, "seed {seed}: bag too small");
            assert_ne!(bag, other, "seed {seed}: canonical bags collide");
            for op in OP_ALL {
                let truth = eval(op, &bag, &other, x);
                match op {
                    Op::SameContents => {
                        // Truth is 0 here (bag != other); const-zero also
                        // answers 0, but the pinned identical-bag example
                        // (truth 1) flips it. sees-nothing answers 1.
                        assert_eq!(truth, 0, "seed {seed} {op:?}");
                        continue;
                    }
                    Op::PushThrough => {
                        // Cannot be faked: a wrong Owned deref cannot
                        // compile, so the cheat leaves this op honest and
                        // every pair carries a slice partner that breaks.
                        assert!(truth >= 3, "seed {seed} {op:?}");
                    }
                    Op::TotalThrough => {
                        assert!(truth > 0, "seed {seed} {op:?}");
                    }
                    Op::LastThrough | Op::HeadTwo => {
                        assert!(truth > 0, "seed {seed} {op:?}");
                    }
                }
                if !matches!(op, Op::PushThrough) {
                    assert_ne!(
                        truth,
                        sees_nothing_truth(op),
                        "seed {seed} {op:?}: sees-nothing survives"
                    );
                }
            }
        }
    }

    fn sees_nothing_truth(op: Op) -> Out {
        match op {
            Op::TotalThrough => 0,
            Op::PushThrough => unreachable!("skipped"),
            Op::LastThrough | Op::HeadTwo => -1,
            Op::SameContents => 1,
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for case in worked_examples(seed) {
                for (op, out) in case.answers {
                    assert_eq!(eval(op, &case.bag, &case.other, case.x), out);
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in 0..50u64 {
            let spec = sample(seed);
            let reference = reference_src(spec);
            for op in OP_ALL {
                let marker = format!("pub fn {}(", op.name());
                let expected = usize::from(spec.ops.contains(&op));
                assert_eq!(
                    reference.matches(&marker).count(),
                    expected,
                    "seed {seed} {marker}"
                );
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in 0..50u64 {
            let spec = sample(seed);
            let sk = skeleton_src(spec, seed);
            let p = prompt(spec, seed, "rb-canary");
            assert!(!sk.contains("[..0]"), "cheat shape leaked");
            assert!(!p.contains("[..0]"), "cheat shape in prompt");
            assert!(sk.contains("todo!()"), "skeleton not stubbed");
            assert!(!p.contains("todo"), "prompt mentions todo");
            for op in spec.ops {
                assert!(
                    p.contains(&op_sig_src(op)),
                    "prompt missing sig for {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for op in OP_ALL {
            let sig = op_sig_src(op);
            let sig_params = sig.split("->").next().unwrap();
            let call = call_src(op);
            assert_eq!(
                sig_params.matches(',').count(),
                call.matches(',').count(),
                "{:?}",
                op
            );
        }
    }

    #[test]
    fn sees_nothing_baseline_breaks_every_slice_op() {
        for seed in [0u64, 17, 81] {
            let spec = sample(seed);
            let baseline = sees_nothing(spec);
            let reference = reference_src(spec);
            assert!(
                baseline.contains("[..0]"),
                "baseline must carry the empty-view cheat"
            );
            assert!(
                !reference.contains("[..0]"),
                "reference must not carry the cheat"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let task = DerefWrapFamily.generate(11);
        assert!(task.prompt.contains(&task.canary));
    }
}

//! The `idiom-api` family (category `idiom-refactor`) — the fourth idiom-refactor family, on
//! two lints that `cargo clippy --fix` cannot apply: **`clippy::len_without_is_empty`** and
//! **`clippy::should_implement_trait`**.
//!
//! Where `idiom-loop` / `idiom-counter` / `idiom-copy` rewrite a *loop*, this one rewrites an
//! *API*. The model is given a small `Bag` type whose public surface is un-idiomatic in one or
//! both of two ways:
//!
//! * a public `len()` with no `is_empty()` (`len_without_is_empty`), and/or
//! * an inherent method named like a std trait method — `add`, `sub`, `mul`, `neg` or `next` —
//!   that should be the trait impl (`should_implement_trait`).
//!
//! and must make it idiomatic and clippy-clean while preserving behaviour. **Q14, measured:** in
//! a scratch crate against the installed clippy (1.97) `cargo clippy --fix` left both lints
//! unchanged for every method name used here — but it *did* fix `new_without_default` (it
//! inserted the `Default` impl), so that lint is deliberately absent from the family: the given
//! code already carries `Default`.
//!
//! The obvious cheat is `#![allow(clippy::...)]`. The hidden tests close it: they call
//! `is_empty()` and use the operators (`a + b`, `-a`, `bag.collect()`), so an answer that silences
//! the lint instead of adding the method/trait does not build.
//!
//! Seed-selected on two axes:
//!
//! 1. **Missing `is_empty`** — present or absent in the given code.
//! 2. **Operator method** — none, or one of `add` / `sub` / `mul` / `neg` / `next`.
//!
//! At least one of the two defects is always present: 1 (is_empty only) + 5 (operator only) + 5
//! (both) = **11 distinct skills**; `mul` takes a `usize` right-hand side, so it is `Mul<usize>`
//! rather than `Mul<Bag>`. Constraint-dominant per docs/04 (behaviour 0.30 / constraint 0.60 /
//! quality 0.10).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum OpKind {
    Add,
    Sub,
    Mul,
    Neg,
    Next,
}

struct Spec {
    /// The given code lacks `is_empty` (the defect to fix).
    missing_is_empty: bool,
    /// The given code has an inherent method with this name instead of the trait impl.
    op: Option<OpKind>,
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    // 11 equally likely skills: (is_empty only) + (5 ops) + (5 ops + is_empty).
    match rng.below(11) {
        0 => Spec {
            missing_is_empty: true,
            op: None,
        },
        n => {
            let op = match (n - 1) % 5 {
                0 => OpKind::Add,
                1 => OpKind::Sub,
                2 => OpKind::Mul,
                3 => OpKind::Neg,
                _ => OpKind::Next,
            };
            Spec {
                missing_is_empty: n > 5,
                op: Some(op),
            }
        }
    }
}

// ---- native reference ------------------------------------------------------------

fn apply(op: OpKind, a: &[i64], b: &[i64], k: usize) -> Vec<i64> {
    match op {
        OpKind::Add => [a, b].concat(),
        OpKind::Sub => a.iter().copied().filter(|x| !b.contains(x)).collect(),
        OpKind::Mul => a.repeat(k),
        OpKind::Neg => a.iter().map(|x| -x).collect(),
        OpKind::Next => a.to_vec(),
    }
}

// ---- emitted source ----------------------------------------------------------------

/// The struct and the always-idiomatic part of the API.
const BASE: &str = "#[derive(Debug, Clone, PartialEq)]\n\
    pub struct Bag {\n\
    \x20   items: Vec<i64>,\n\
    }\n\
    \n\
    impl Default for Bag {\n\
    \x20   fn default() -> Self {\n\
    \x20       Bag::new()\n\
    \x20   }\n\
    }\n";

fn inherent_op_src(op: OpKind) -> &'static str {
    match op {
        OpKind::Add => {
            "    pub fn add(self, other: Bag) -> Bag {\n\
             \x20       let mut items = self.items;\n\
             \x20       items.extend(other.items);\n\
             \x20       Bag { items }\n\
             \x20   }\n"
        }
        OpKind::Sub => {
            "    pub fn sub(self, other: Bag) -> Bag {\n\
             \x20       let items = self\n\
             \x20           .items\n\
             \x20           .into_iter()\n\
             \x20           .filter(|x| !other.items.contains(x))\n\
             \x20           .collect();\n\
             \x20       Bag { items }\n\
             \x20   }\n"
        }
        OpKind::Mul => {
            "    pub fn mul(self, times: usize) -> Bag {\n\
             \x20       Bag {\n\
             \x20           items: self.items.repeat(times),\n\
             \x20       }\n\
             \x20   }\n"
        }
        OpKind::Neg => {
            "    pub fn neg(self) -> Bag {\n\
             \x20       Bag {\n\
             \x20           items: self.items.into_iter().map(|x| -x).collect(),\n\
             \x20       }\n\
             \x20   }\n"
        }
        OpKind::Next => {
            "    pub fn next(&mut self) -> Option<i64> {\n\
             \x20       if self.items.is_empty() {\n\
             \x20           None\n\
             \x20       } else {\n\
             \x20           Some(self.items.remove(0))\n\
             \x20       }\n\
             \x20   }\n"
        }
    }
}

fn trait_op_src(op: OpKind) -> &'static str {
    match op {
        OpKind::Add => {
            "impl std::ops::Add for Bag {\n\
             \x20   type Output = Bag;\n\
             \x20   fn add(self, other: Bag) -> Bag {\n\
             \x20       let mut items = self.items;\n\
             \x20       items.extend(other.items);\n\
             \x20       Bag { items }\n\
             \x20   }\n\
             }\n"
        }
        OpKind::Sub => {
            "impl std::ops::Sub for Bag {\n\
             \x20   type Output = Bag;\n\
             \x20   fn sub(self, other: Bag) -> Bag {\n\
             \x20       let items = self\n\
             \x20           .items\n\
             \x20           .into_iter()\n\
             \x20           .filter(|x| !other.items.contains(x))\n\
             \x20           .collect();\n\
             \x20       Bag { items }\n\
             \x20   }\n\
             }\n"
        }
        OpKind::Mul => {
            "impl std::ops::Mul<usize> for Bag {\n\
             \x20   type Output = Bag;\n\
             \x20   fn mul(self, times: usize) -> Bag {\n\
             \x20       Bag {\n\
             \x20           items: self.items.repeat(times),\n\
             \x20       }\n\
             \x20   }\n\
             }\n"
        }
        OpKind::Neg => {
            "impl std::ops::Neg for Bag {\n\
             \x20   type Output = Bag;\n\
             \x20   fn neg(self) -> Bag {\n\
             \x20       Bag {\n\
             \x20           items: self.items.into_iter().map(|x| -x).collect(),\n\
             \x20       }\n\
             \x20   }\n\
             }\n"
        }
        OpKind::Next => {
            "impl Iterator for Bag {\n\
             \x20   type Item = i64;\n\
             \x20   fn next(&mut self) -> Option<i64> {\n\
             \x20       if self.items.is_empty() {\n\
             \x20           None\n\
             \x20       } else {\n\
             \x20           Some(self.items.remove(0))\n\
             \x20       }\n\
             \x20   }\n\
             }\n"
        }
    }
}

/// The inherent `impl Bag` block.
fn inherent_impl(has_is_empty: bool, inherent_op: Option<OpKind>) -> String {
    let mut s = String::from(
        "impl Bag {\n\
         \x20   pub fn new() -> Bag {\n\
         \x20       Bag { items: Vec::new() }\n\
         \x20   }\n\
         \n\
         \x20   pub fn push(&mut self, v: i64) {\n\
         \x20       self.items.push(v);\n\
         \x20   }\n\
         \n\
         \x20   pub fn len(&self) -> usize {\n\
         \x20       self.items.len()\n\
         \x20   }\n\
         \n\
         \x20   pub fn items(&self) -> &[i64] {\n\
         \x20       &self.items\n\
         \x20   }\n",
    );
    if has_is_empty {
        s.push_str(
            "\n    pub fn is_empty(&self) -> bool {\n        self.items.is_empty()\n    }\n",
        );
    }
    if let Some(op) = inherent_op {
        s.push('\n');
        s.push_str(inherent_op_src(op));
    }
    s.push_str("}\n");
    s
}

/// The code the model starts from: un-idiomatic in exactly the spec's way.
fn given_src(spec: &Spec) -> String {
    format!("{BASE}\n{}", inherent_impl(!spec.missing_is_empty, spec.op))
}

/// The idiomatic answer.
fn reference_src(spec: &Spec) -> String {
    let mut s = format!("{BASE}\n{}", inherent_impl(true, None));
    if let Some(op) = spec.op {
        s.push('\n');
        s.push_str(trait_op_src(op));
    }
    s
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples_prose(spec, seed)
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Make the `Bag` API idiomatic and clippy-clean, preserving its behaviour.\n\
         //!\n\
         {doc}\n\
         {}",
        given_src(spec)
    )
}

// ---- worked examples -------------------------------------------------------------------

fn draw(rng: &mut Rng, len: usize) -> Vec<i64> {
    (0..len).map(|_| rng.below(81) as i64 - 40).collect()
}

/// (a, b, k): the canonical case first. `a` has a repeated value that `b` removes, so every
/// operator's result differs from `a`, from `b`, and from the empty bag.
fn worked_cases(seed: u64) -> Vec<(Vec<i64>, Vec<i64>, usize)> {
    let mut rng = Rng::new(seed ^ 0x1D2A_0000_0000_0A91);
    let mut v = vec![(vec![3, 1, 4, 1], vec![1, 5], 2)];
    for _ in 0..7 {
        let la = 3 + rng.below(6) as usize;
        let lb = 2 + rng.below(3) as usize;
        v.push((
            draw(&mut rng, la),
            draw(&mut rng, lb),
            1 + rng.below(3) as usize,
        ));
    }
    v
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (a, b, k) in worked_cases(seed) {
        match spec.op {
            Some(OpKind::Add) => s.push_str(&format!(
                "  Bag{a:?} + Bag{b:?}  ->  {:?}\n",
                apply(OpKind::Add, &a, &b, k)
            )),
            Some(OpKind::Sub) => s.push_str(&format!(
                "  Bag{a:?} - Bag{b:?}  ->  {:?}\n",
                apply(OpKind::Sub, &a, &b, k)
            )),
            Some(OpKind::Mul) => s.push_str(&format!(
                "  Bag{a:?} * {k}  ->  {:?}\n",
                apply(OpKind::Mul, &a, &b, k)
            )),
            Some(OpKind::Neg) => s.push_str(&format!(
                "  -Bag{a:?}  ->  {:?}\n",
                apply(OpKind::Neg, &a, &b, k)
            )),
            Some(OpKind::Next) => s.push_str(&format!(
                "  Bag{a:?}.collect::<Vec<_>>()  ->  {:?}\n",
                apply(OpKind::Next, &a, &b, k)
            )),
            None => s.push_str(&format!(
                "  Bag{a:?}.len() == {}, Bag{a:?}.is_empty() == {}\n",
                a.len(),
                a.is_empty()
            )),
        }
    }
    s.push_str("  Bag::new().is_empty()  ->  true\n");
    s
}

fn defects_prose(spec: &Spec) -> String {
    let mut parts = Vec::new();
    if spec.missing_is_empty {
        parts.push(
            "`Bag` has a public `len()` but no `is_empty()` (clippy: `len_without_is_empty`)"
                .to_string(),
        );
    }
    if let Some(op) = spec.op {
        let (name, tr) = match op {
            OpKind::Add => ("add", "`std::ops::Add`"),
            OpKind::Sub => ("sub", "`std::ops::Sub`"),
            OpKind::Mul => ("mul", "`std::ops::Mul<usize>`"),
            OpKind::Neg => ("neg", "`std::ops::Neg`"),
            OpKind::Next => ("next", "`std::iter::Iterator`"),
        };
        parts.push(format!(
            "the inherent method `{name}` is named like a standard trait method and should be the \
             {tr} impl instead (clippy: `should_implement_trait`)"
        ));
    }
    parts.join("; and ")
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    format!(
        "The `Bag` type in `src/lib.rs` works, but its API is not idiomatic Rust: {defects}. \
         Make it idiomatic and `clippy`-clean while preserving its behaviour: callers must be \
         able to {use_it}.\n\
         \n\
         Here is the current code:\n\
         \n\
         ```rust\n\
         {current}\n\
         ```\n\
         \n\
         Examples of the behaviour that must be kept:\n\
         {examples}\n\
         Constraints:\n\
         - The rewrite must produce **no** `clippy` warnings, and must not hide them with \
         `#[allow(..)]`: the checks call the idiomatic API (`is_empty()`, the operators, \
         iteration), so an answer that silences the lint instead of fixing the API will not build.\n\
         - Keep `new`, `push`, `len`, `items` and the `Default` impl.\n\
         - Do not use `unsafe`.\n\
         \n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        defects = defects_prose(spec),
        use_it = use_prose(spec),
        current = given_src(spec).trim_end(),
        examples = worked_examples_prose(spec, seed),
    )
}

fn use_prose(spec: &Spec) -> String {
    let mut v = vec!["call `bag.is_empty()`".to_string()];
    if let Some(op) = spec.op {
        v.push(
            match op {
                OpKind::Add => "write `a + b`",
                OpKind::Sub => "write `a - b`",
                OpKind::Mul => "write `a * 3`",
                OpKind::Neg => "write `-a`",
                OpKind::Next => "iterate a `Bag` (`for x in bag`, `.collect()`, `.sum()`)",
            }
            .to_string(),
        );
    }
    v.join(" and ")
}

fn cargo_toml() -> String {
    "[package]\n\
     name = \"task\"\n\
     version = \"0.0.0\"\n\
     edition = \"2021\"\n\
     \n\
     [lib]\n\
     path = \"src/lib.rs\"\n\
     \n\
     [workspace]\n"
        .to_string()
}

const HELPER: &str = "fn bag(xs: &[i64]) -> Bag {\n\
    \x20   let mut b = Bag::new();\n\
    \x20   for &x in xs {\n\
    \x20       b.push(x);\n\
    \x20   }\n\
    \x20   b\n\
    }\n";

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let mut body = format!("use task::Bag;\n\n{HELPER}\n");
    for (i, (a, b, k)) in worked_cases(seed).iter().enumerate() {
        let expr = match spec.op {
            Some(OpKind::Add) => Some(format!("(bag(&{a:?}) + bag(&{b:?})).items().to_vec()")),
            Some(OpKind::Sub) => Some(format!("(bag(&{a:?}) - bag(&{b:?})).items().to_vec()")),
            Some(OpKind::Mul) => Some(format!("(bag(&{a:?}) * {k}).items().to_vec()")),
            Some(OpKind::Neg) => Some(format!("(-bag(&{a:?})).items().to_vec()")),
            Some(OpKind::Next) => Some(format!("bag(&{a:?}).collect::<Vec<i64>>()")),
            None => None,
        };
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let a = bag(&{a:?});\n    assert_eq!(a.len(), {});\n    assert_eq!(a.is_empty(), {});\n",
            a.len(),
            a.is_empty()
        ));
        if let (Some(op), Some(e)) = (spec.op, expr) {
            body.push_str(&format!(
                "    assert_eq!({e}, {:?});\n",
                apply(op, a, b, *k)
            ));
        }
        body.push_str("}\n\n");
    }
    body.push_str(
        "#[test]\nfn empty_bag() {\n    let b = Bag::new();\n    assert!(b.is_empty());\n    assert_eq!(b.len(), 0);\n    assert_eq!(Bag::default(), Bag::new());\n}\n",
    );
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    let (op_t, op_r) = match spec.op {
        Some(OpKind::Add) => ("(ta + tb).items().to_vec()", "(ra + rb).items().to_vec()"),
        Some(OpKind::Sub) => ("(ta - tb).items().to_vec()", "(ra - rb).items().to_vec()"),
        Some(OpKind::Mul) => ("(ta * k).items().to_vec()", "(ra * k).items().to_vec()"),
        Some(OpKind::Neg) => ("(-ta).items().to_vec()", "(-ra).items().to_vec()"),
        Some(OpKind::Next) => ("ta.collect::<Vec<i64>>()", "ra.collect::<Vec<i64>>()"),
        None => ("0", "0"),
    };
    format!(
        "mod reference {{\n{indented}}}\n\n\
         fn mk_t(xs: &[i64]) -> task::Bag {{\n\
         \x20   let mut b = task::Bag::new();\n\
         \x20   for &x in xs {{\n\
         \x20       b.push(x);\n\
         \x20   }}\n\
         \x20   b\n\
         }}\n\n\
         fn mk_r(xs: &[i64]) -> reference::Bag {{\n\
         \x20   let mut b = reference::Bag::new();\n\
         \x20   for &x in xs {{\n\
         \x20       b.push(x);\n\
         \x20   }}\n\
         \x20   b\n\
         }}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x1D2A_ED00_0000_0049;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let a: Vec<i64> = (0..next() % 8).map(|_| (next() % 9) as i64 - 4).collect();\n\
         \x20       let b: Vec<i64> = (0..next() % 5).map(|_| (next() % 9) as i64 - 4).collect();\n\
         \x20       let k = (next() % 4) as usize;\n\
         \x20       let _ = (&b, k);\n\
         \x20       let (ta, tb) = (mk_t(&a), mk_t(&b));\n\
         \x20       let (ra, rb) = (mk_r(&a), mk_r(&b));\n\
         \x20       let _ = (&tb, &rb);\n\
         \x20       assert_eq!(ta.len(), ra.len());\n\
         \x20       assert_eq!(ta.is_empty(), ra.is_empty());\n\
         \x20       assert_eq!({op_t}, {op_r}, \"a={{a:?}} b={{b:?}} k={{k}}\");\n\
         \x20   }}\n\
         }}\n",
    )
}

/// The "lazy copy-paste" baseline: the given code returned unchanged.
fn unchanged(spec: &Spec) -> String {
    given_src(spec)
}

/// The cheat the hidden tests close: silence the lints instead of fixing the API.
fn allow_attrs(spec: &Spec) -> String {
    format!(
        "#![allow(clippy::len_without_is_empty, clippy::should_implement_trait)]\n{}",
        given_src(spec)
    )
}

pub struct IdiomApiFamily;

impl Generator for IdiomApiFamily {
    fn id(&self) -> &str {
        "idiom-api"
    }
    fn category(&self) -> &str {
        "idiom-refactor"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("idiom-api", seed);

        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("Cargo.toml"), cargo_toml());
        // The model's starting file is the un-idiomatic API (it rewrites it).
        files.insert(PathBuf::from("src/lib.rs"), skeleton_src(&spec, seed));

        let mut hidden = BTreeMap::new();
        hidden.insert(
            PathBuf::from("tests/behavior.rs"),
            behavior_test_src(&spec, seed),
        );
        hidden.insert(
            PathBuf::from("tests/differential.rs"),
            differential_test_src(&spec),
        );

        GeneratedTask {
            id: format!("idiom-api/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            max_unsafe: None,
            // `#[allow(..)]` is the cheat the prompt forbids; the AST path check sees attribute
            // paths, so it is a measured constraint violation (not only a failed build).
            forbidden_paths: vec!["allow".to_string()],
            check_clippy: true,
            clippy_allow: Vec::new(),
            // docs/04 idiom-refactor weights: the task *is* the constraint (clippy).
            weights: (0.30, 0.60, 0.10),
        }
    }

    fn reference_code(&self, seed: u64) -> String {
        reference_src(&sample(seed))
    }
    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(&sample(seed), seed)
    }
    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("unchanged".to_string(), unchanged(&spec)),
            ("allow-attrs".to_string(), allow_attrs(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let op = match spec.op {
            None => "none",
            Some(OpKind::Add) => "add",
            Some(OpKind::Sub) => "sub",
            Some(OpKind::Mul) => "mul",
            Some(OpKind::Neg) => "neg",
            Some(OpKind::Next) => "next",
        };
        vec![
            format!(
                "is_empty:{}",
                if spec.missing_is_empty {
                    "missing"
                } else {
                    "present"
                }
            ),
            format!("op:{op}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = IdiomApiFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn apply_matches_intent() {
        let a = [3, 1, 4, 1];
        let b = [1, 5];
        assert_eq!(apply(OpKind::Add, &a, &b, 2), vec![3, 1, 4, 1, 1, 5]);
        assert_eq!(apply(OpKind::Sub, &a, &b, 2), vec![3, 4]);
        assert_eq!(apply(OpKind::Mul, &a, &b, 2), vec![3, 1, 4, 1, 3, 1, 4, 1]);
        assert_eq!(apply(OpKind::Neg, &a, &b, 2), vec![-3, -1, -4, -1]);
        assert_eq!(apply(OpKind::Next, &a, &b, 2), vec![3, 1, 4, 1]);
    }

    #[test]
    fn every_spec_has_at_least_one_defect_and_the_right_surface() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..400u64 {
            let s = sample(seed);
            assert!(
                s.missing_is_empty || s.op.is_some(),
                "seed {seed}: no defect"
            );
            let given = given_src(&s);
            // The given code has is_empty iff it is not the defect.
            assert_eq!(
                given.contains("fn is_empty"),
                !s.missing_is_empty,
                "seed {seed}"
            );
            // The reference always has it, and never keeps the inherent operator method.
            let r = reference_src(&s);
            assert!(r.contains("fn is_empty"));
            if let Some(op) = s.op {
                assert!(given.contains(&format!("pub fn {}(", name(op))));
                assert!(!r.contains(&format!("pub fn {}(", name(op))), "seed {seed}");
            }
            variants.insert(format!("{:?}/{:?}", s.missing_is_empty, s.op));
        }
        assert_eq!(variants.len(), 11);
    }

    fn name(op: OpKind) -> &'static str {
        match op {
            OpKind::Add => "add",
            OpKind::Sub => "sub",
            OpKind::Mul => "mul",
            OpKind::Neg => "neg",
            OpKind::Next => "next",
        }
    }

    #[test]
    fn canonical_defeats_the_baselines() {
        // Neither baseline builds against the hidden tests (no is_empty / no operator trait),
        // so the check that matters is that the tests really call both.
        for seed in 0..60u64 {
            let s = sample(seed);
            let t = IdiomApiFamily.generate(seed);
            let b = &t.hidden[&PathBuf::from("tests/behavior.rs")];
            assert!(b.contains("is_empty()"), "seed {seed}");
            if let Some(op) = s.op {
                let marker = match op {
                    OpKind::Add => " + ",
                    OpKind::Sub => " - ",
                    OpKind::Mul => " * ",
                    OpKind::Neg => "(-bag(",
                    OpKind::Next => ".collect::<Vec<i64>>()",
                };
                assert!(
                    b.contains(marker),
                    "seed {seed}: tests do not use the operator"
                );
            }
        }
    }

    #[test]
    fn allow_is_a_forbidden_path() {
        assert_eq!(
            IdiomApiFamily.generate(3).forbidden_paths,
            vec!["allow".to_string()]
        );
    }

    #[test]
    fn allow_attrs_baseline_carries_the_allow() {
        let s = sample(3);
        let a = allow_attrs(&s);
        assert!(a.starts_with("#![allow(clippy::len_without_is_empty"));
        assert!(a.contains("pub struct Bag"));
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let t = IdiomApiFamily.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

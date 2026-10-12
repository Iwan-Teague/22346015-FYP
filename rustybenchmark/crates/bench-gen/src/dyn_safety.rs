//! The `dyn-safety` family (category `traits-generics`) — make a trait **object-safe** without
//! removing methods.
//!
//! A pinned `trait Stage` has two ordinary methods (`name`, `apply`) and one to three methods
//! that make it impossible to use as `dyn Stage`:
//!
//! * a **generic method** (`fn map_all<F: Fn(i64) -> i64>(&self, ..)`),
//! * a method that **returns `Self` by value** (`fn rescaled(self, factor: i64) -> Self`), and
//! * a **static constructor** (`fn default_stage() -> Self`).
//!
//! The given code declares `pub fn run_pipeline(stages: &[Box<dyn Stage>], x: i64) -> i64` against
//! it, so the skeleton fails with E0038 until the trait is fixed. The fix is `where Self: Sized`
//! on each offending method, which keeps the method callable on concrete types and removes it
//! from the vtable — the idiom the Rust reference calls out and the one models most often get
//! wrong (by deleting the method, which the hidden tests catch, or by adding `Sized` as a
//! supertrait, which defeats the point). The model then implements `run_pipeline`.
//!
//! Seed-selected on two axes: **which breakers are present** (the 7 non-empty subsets of the
//! three) and **the pipeline** (`Fold` front to back, `FoldRev` back to front, `SumEach`,
//! `MaxEach`). 7 x 4 = **28 distinct skills**. The hidden tests call every breaker on *concrete*
//! types (so deleting one fails to build) and run the pipeline through `Vec<Box<dyn Stage>>`.
//! Solution-first (ADR-0003): native `run` and the emitted pipeline are mirrored; the
//! differential compares both on 3000 random stage lists against an inlined reference module.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Pipe {
    Fold,
    FoldRev,
    SumEach,
    MaxEach,
}

struct Spec {
    /// Bit 0: generic method; bit 1: returns Self; bit 2: static constructor. Non-zero.
    breakers: u8,
    pipe: Pipe,
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let breakers = 1 + rng.below(7) as u8;
    let pipe = match rng.below(4) {
        0 => Pipe::Fold,
        1 => Pipe::FoldRev,
        2 => Pipe::SumEach,
        _ => Pipe::MaxEach,
    };
    Spec { breakers, pipe }
}

const GENERIC: u8 = 1;
const RETURNS_SELF: u8 = 2;
const STATIC_CTOR: u8 = 4;

// ---- native model of the pinned stages ---------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
enum Stage {
    Scale(i64),
    Shift(i64),
    Clamp(i64),
}

fn apply(s: Stage, x: i64) -> i64 {
    match s {
        Stage::Scale(k) => x * k,
        Stage::Shift(d) => x + d,
        Stage::Clamp(m) => x.min(m),
    }
}

fn run(pipe: Pipe, stages: &[Stage], x: i64) -> i64 {
    match pipe {
        Pipe::Fold => stages.iter().fold(x, |acc, &s| apply(s, acc)),
        Pipe::FoldRev => stages.iter().rev().fold(x, |acc, &s| apply(s, acc)),
        Pipe::SumEach => stages.iter().map(|&s| apply(s, x)).sum(),
        Pipe::MaxEach => stages.iter().map(|&s| apply(s, x)).max().unwrap_or(x),
    }
}

fn rescaled(s: Stage, f: i64) -> Stage {
    match s {
        Stage::Scale(k) => Stage::Scale(k * f),
        Stage::Shift(d) => Stage::Shift(d * f),
        Stage::Clamp(m) => Stage::Clamp(m * f),
    }
}

fn default_of(s: Stage) -> Stage {
    match s {
        Stage::Scale(_) => Stage::Scale(1),
        Stage::Shift(_) => Stage::Shift(0),
        Stage::Clamp(_) => Stage::Clamp(100),
    }
}

// ---- emitted source ---------------------------------------------------------------------

/// Trait declaration. `fixed`: add `where Self: Sized` to every present breaker.
fn trait_src(spec: &Spec, fixed: bool, with_breakers: bool) -> String {
    let w = if fixed {
        "\n    where\n        Self: Sized,"
    } else {
        ""
    };
    let mut s = String::from(
        "pub trait Stage {\n    fn name(&self) -> String;\n    fn apply(&self, x: i64) -> i64;\n",
    );
    if with_breakers && spec.breakers & GENERIC != 0 {
        s.push_str(&format!(
            "\n    fn map_all<F: Fn(i64) -> i64>(&self, xs: &[i64], f: F) -> Vec<i64>{w};\n"
        ));
    }
    if with_breakers && spec.breakers & RETURNS_SELF != 0 {
        s.push_str(&format!(
            "\n    fn rescaled(self, factor: i64) -> Self{w};\n"
        ));
    }
    if with_breakers && spec.breakers & STATIC_CTOR != 0 {
        s.push_str(&format!("\n    fn default_stage() -> Self{w};\n"));
    }
    s.push_str("}\n");
    s
}

fn impls_src(spec: &Spec, with_breakers: bool) -> String {
    let defs: [(&str, &str, &str, &str, &str); 3] = [
        ("Scale", "k", "scale", "x * self.k", "Scale { k: 1 }"),
        ("Shift", "d", "shift", "x + self.d", "Shift { d: 0 }"),
        (
            "Clamp",
            "max",
            "clamp",
            "x.min(self.max)",
            "Clamp { max: 100 }",
        ),
    ];
    let mut s = String::new();
    for (ty, field, name, apply_expr, default) in defs {
        s.push_str(&format!(
            "pub struct {ty} {{\n    pub {field}: i64,\n}}\n\n"
        ));
        s.push_str(&format!(
            "impl Stage for {ty} {{\n    fn name(&self) -> String {{\n        \"{name}\".to_string()\n    }}\n\n    fn apply(&self, x: i64) -> i64 {{\n        {apply_expr}\n    }}\n"
        ));
        if with_breakers && spec.breakers & GENERIC != 0 {
            s.push_str(
                "\n    fn map_all<F: Fn(i64) -> i64>(&self, xs: &[i64], f: F) -> Vec<i64> {\n        xs.iter().map(|&x| f(self.apply(x))).collect()\n    }\n",
            );
        }
        if with_breakers && spec.breakers & RETURNS_SELF != 0 {
            s.push_str(&format!(
                "\n    fn rescaled(self, factor: i64) -> Self {{\n        {ty} {{ {field}: self.{field} * factor }}\n    }}\n"
            ));
        }
        if with_breakers && spec.breakers & STATIC_CTOR != 0 {
            s.push_str(&format!(
                "\n    fn default_stage() -> Self {{\n        {default}\n    }}\n"
            ));
        }
        s.push_str("}\n\n");
    }
    s
}

const SIG: &str = "pub fn run_pipeline(stages: &[Box<dyn Stage>], x: i64) -> i64";

fn pipe_body(pipe: Pipe) -> &'static str {
    match pipe {
        Pipe::Fold => "stages.iter().fold(x, |acc, s| s.apply(acc))",
        Pipe::FoldRev => "stages.iter().rev().fold(x, |acc, s| s.apply(acc))",
        Pipe::SumEach => "stages.iter().map(|s| s.apply(x)).sum()",
        Pipe::MaxEach => "stages.iter().map(|s| s.apply(x)).max().unwrap_or(x)",
    }
}

fn reference_src(spec: &Spec) -> String {
    format!(
        "{}\n{}{SIG} {{\n    {}\n}}\n",
        trait_src(spec, true, true),
        impls_src(spec, true),
        pipe_body(spec.pipe)
    )
}

fn given_src(spec: &Spec) -> String {
    format!(
        "{}\n{}{SIG} {{\n    todo!()\n}}\n",
        trait_src(spec, false, true),
        impls_src(spec, true)
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .1
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Make `Stage` usable as a trait object and implement `run_pipeline`.\n\
         //!\n\
         {doc}\n\
         {}",
        given_src(spec)
    )
}

// ---- examples ----------------------------------------------------------------------------------

fn stage_lit(s: Stage) -> String {
    match s {
        Stage::Scale(k) => format!("Scale {{ k: {k} }}"),
        Stage::Shift(d) => format!("Shift {{ d: {d} }}"),
        Stage::Clamp(m) => format!("Clamp {{ max: {m} }}"),
    }
}

fn canonical() -> (Vec<Stage>, i64) {
    (vec![Stage::Scale(3), Stage::Shift(-4), Stage::Clamp(20)], 5)
}

fn random_stages(rng: &mut Rng, n: usize) -> Vec<Stage> {
    (0..n)
        .map(|_| match rng.below(3) {
            0 => Stage::Scale(rng.below(7) as i64 - 3),
            1 => Stage::Shift(rng.below(21) as i64 - 10),
            _ => Stage::Clamp(rng.below(40) as i64 - 10),
        })
        .collect()
}

fn worked_examples(spec: &Spec, seed: u64) -> (Vec<(Vec<Stage>, i64)>, String) {
    let mut rng = Rng::new(seed ^ 0xD750_0000_0000_0B33);
    let mut cases = vec![canonical()];
    for _ in 0..8 {
        let n = 1 + rng.below(4) as usize;
        cases.push((random_stages(&mut rng, n), rng.below(21) as i64 - 5));
    }
    let mut prose = String::new();
    for (stages, x) in &cases {
        let lits: Vec<String> = stages.iter().map(|&s| stage_lit(s)).collect();
        prose.push_str(&format!(
            "  run_pipeline(&[{}], {x})  ->  {}\n",
            lits.join(", "),
            run(spec.pipe, stages, *x)
        ));
    }
    (cases, prose)
}

fn pipe_prose(pipe: Pipe) -> &'static str {
    match pipe {
        Pipe::Fold => "feed `x` through the stages in order, each stage's output being the next stage's input, and return the final value (no stages: `x`)",
        Pipe::FoldRev => "feed `x` through the stages from the **last** to the first, each output being the next input, and return the final value (no stages: `x`)",
        Pipe::SumEach => "apply every stage to the **same** `x` independently and return the sum of the results (no stages: `0`)",
        Pipe::MaxEach => "apply every stage to the **same** `x` independently and return the largest result (no stages: `x`)",
    }
}

fn breakers_prose(spec: &Spec) -> String {
    let mut v = Vec::new();
    if spec.breakers & GENERIC != 0 {
        v.push("`map_all` is generic");
    }
    if spec.breakers & RETURNS_SELF != 0 {
        v.push("`rescaled` returns `Self` by value");
    }
    if spec.breakers & STATIC_CTOR != 0 {
        v.push("`default_stage` has no receiver");
    }
    v.join(", ")
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (_, examples) = worked_examples(spec, seed);
    format!(
        "`src/lib.rs` declares `{sig}` over `Box<dyn Stage>`, but as given it does not compile: \
         `Stage` is not object-safe ({why}). Make `Stage` usable as a trait object **without removing \
         any method** (they must all stay callable on concrete types, e.g. `Scale {{ k: 2 }}.rescaled(3)`), \
         then implement `run_pipeline`: {pipe}.\n\
         \n\
         Constraints:\n\
         - Keep every method of the trait and every provided struct and impl. Do not add `Sized` as a \
         supertrait (that would make `dyn Stage` impossible again).\n\
         - Do not use `unsafe`.\n\
         \n\
         The current code:\n\
         ```rust\n\
         {current}\n\
         ```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        sig = SIG,
        why = breakers_prose(spec),
        pipe = pipe_prose(spec.pipe),
        current = given_src(spec).trim_end(),
    )
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

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let (cases, _) = worked_examples(spec, seed);
    let mut body = String::from("use task::{run_pipeline, Clamp, Scale, Shift, Stage};\n\n");
    for (i, (stages, x)) in cases.iter().enumerate() {
        let boxed: Vec<String> = stages
            .iter()
            .map(|&s| format!("Box::new({})", stage_lit(s)))
            .collect();
        body.push_str(&format!(
            "#[test]\nfn pipeline{i}() {{\n    let stages: Vec<Box<dyn Stage>> = vec![{}];\n    assert_eq!(run_pipeline(&stages, {x}), {});\n}}\n\n",
            boxed.join(", "),
            run(spec.pipe, stages, *x)
        ));
    }
    // Every breaker, called on concrete types: deleting a method fails to build.
    body.push_str("#[test]\nfn the_breakers_still_work_on_concrete_types() {\n");
    if spec.breakers & GENERIC != 0 {
        let want = |s: Stage| format!("{:?}", [1, 2, 3].map(|x| apply(s, x) * 10));
        body.push_str(&format!(
            "    assert_eq!(Scale {{ k: 2 }}.map_all(&[1, 2, 3], |x| x * 10), {}.to_vec());\n    assert_eq!(Shift {{ d: 5 }}.map_all(&[1, 2, 3], |x| x * 10), {}.to_vec());\n    assert_eq!(Clamp {{ max: 2 }}.map_all(&[1, 2, 3], |x| x * 10), {}.to_vec());\n",
            want(Stage::Scale(2)),
            want(Stage::Shift(5)),
            want(Stage::Clamp(2)),
        ));
    }
    if spec.breakers & RETURNS_SELF != 0 {
        body.push_str(&format!(
            "    assert_eq!(Scale {{ k: 2 }}.rescaled(3).apply(5), {});\n    assert_eq!(Shift {{ d: 2 }}.rescaled(3).apply(5), {});\n    assert_eq!(Clamp {{ max: 4 }}.rescaled(3).apply(50), {});\n",
            apply(rescaled(Stage::Scale(2), 3), 5),
            apply(rescaled(Stage::Shift(2), 3), 5),
            apply(rescaled(Stage::Clamp(4), 3), 50),
        ));
    }
    if spec.breakers & STATIC_CTOR != 0 {
        body.push_str(&format!(
            "    assert_eq!(Scale::default_stage().apply(7), {});\n    assert_eq!(Shift::default_stage().apply(7), {});\n    assert_eq!(Clamp::default_stage().apply(700), {});\n",
            apply(default_of(Stage::Scale(0)), 7),
            apply(default_of(Stage::Shift(0)), 7),
            apply(default_of(Stage::Clamp(0)), 700),
        ));
    }
    body.push_str("    assert_eq!(Scale { k: 2 }.name(), \"scale\");\n}\n");
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    format!(
        "mod reference {{\n{indented}}}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xD750_ED00_0000_004F;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = (next() % 6) as usize;\n\
         \x20       let mut ts: Vec<Box<dyn task::Stage>> = Vec::new();\n\
         \x20       let mut rs: Vec<Box<dyn reference::Stage>> = Vec::new();\n\
         \x20       for _ in 0..n {{\n\
         \x20           let p = (next() % 41) as i64 - 20;\n\
         \x20           match next() % 3 {{\n\
         \x20               0 => {{ ts.push(Box::new(task::Scale {{ k: p % 5 }})); rs.push(Box::new(reference::Scale {{ k: p % 5 }})); }}\n\
         \x20               1 => {{ ts.push(Box::new(task::Shift {{ d: p }})); rs.push(Box::new(reference::Shift {{ d: p }})); }}\n\
         \x20               _ => {{ ts.push(Box::new(task::Clamp {{ max: p }})); rs.push(Box::new(reference::Clamp {{ max: p }})); }}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       let x = (next() % 61) as i64 - 30;\n\
         \x20       assert_eq!(task::run_pipeline(&ts, x), reference::run_pipeline(&rs, x), \"x={{x}} n={{n}}\");\n\
         \x20   }}\n\
         }}\n"
    )
}

/// Degenerate: a fixed trait whose pipeline returns 0.
fn empty(spec: &Spec) -> String {
    format!(
        "{}\n{}{SIG} {{\n    let _ = (stages, x);\n    0\n}}\n",
        trait_src(spec, true, true),
        impls_src(spec, true),
    )
}

/// Degenerate: object-safe by deleting the breaker methods (compiles; the hidden tests call them).
fn deleted(spec: &Spec) -> String {
    format!(
        "{}\n{}{SIG} {{\n    {}\n}}\n",
        trait_src(spec, true, false),
        impls_src(spec, false),
        pipe_body(spec.pipe)
    )
}

pub struct DynSafetyFamily;

impl Generator for DynSafetyFamily {
    fn id(&self) -> &str {
        "dyn-safety"
    }
    fn category(&self) -> &str {
        "traits-generics"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("dyn-safety", seed);

        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("Cargo.toml"), cargo_toml());
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
            id: format!("dyn-safety/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            max_unsafe: Some(0),
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // traits-generics: docs/04 default weights (L1 + signature match emphasis).
            weights: (0.70, 0.20, 0.10),
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
            ("empty".to_string(), empty(&spec)),
            ("deleted-breakers".to_string(), deleted(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let mut b = Vec::new();
        if spec.breakers & GENERIC != 0 {
            b.push("generic");
        }
        if spec.breakers & RETURNS_SELF != 0 {
            b.push("self");
        }
        if spec.breakers & STATIC_CTOR != 0 {
            b.push("static");
        }
        let pipe = match spec.pipe {
            Pipe::Fold => "fold",
            Pipe::FoldRev => "fold_rev",
            Pipe::SumEach => "sum_each",
            Pipe::MaxEach => "max_each",
        };
        vec![format!("breakers:{}", b.join("+")), format!("pipe:{pipe}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIPES: [Pipe; 4] = [Pipe::Fold, Pipe::FoldRev, Pipe::SumEach, Pipe::MaxEach];

    #[test]
    fn generation_is_deterministic() {
        let g = DynSafetyFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn run_matches_intent() {
        let (st, x) = canonical();
        assert_eq!(run(Pipe::Fold, &st, x), 11);
        assert_eq!(run(Pipe::FoldRev, &st, x), 3);
        assert_eq!(run(Pipe::SumEach, &st, x), 21);
        assert_eq!(run(Pipe::MaxEach, &st, x), 15);
        for p in PIPES {
            let none = run(p, &[], 7);
            assert_eq!(none, if p == Pipe::SumEach { 0 } else { 7 });
        }
    }

    #[test]
    fn canonical_defeats_the_empty_baseline_under_every_pipeline() {
        let (st, x) = canonical();
        for p in PIPES {
            assert_ne!(run(p, &st, x), 0, "{p:?}");
        }
    }

    #[test]
    fn given_has_unfixed_breakers_and_reference_fixes_exactly_those() {
        for seed in 0..80u64 {
            let s = sample(seed);
            let given = given_src(&s);
            let r = reference_src(&s);
            let n = (s.breakers & 1) + ((s.breakers >> 1) & 1) + ((s.breakers >> 2) & 1);
            assert!(n >= 1);
            assert!(!given.contains("Self: Sized"), "seed {seed}");
            assert_eq!(r.matches("Self: Sized").count(), n as usize, "seed {seed}");
            assert!(given.contains("todo!()") && !r.contains("todo!()"));
        }
    }

    #[test]
    fn the_deleted_baseline_lacks_every_breaker_the_tests_call() {
        for seed in 0..40u64 {
            let s = sample(seed);
            let d = deleted(&s);
            assert!(
                !d.contains("map_all") && !d.contains("rescaled") && !d.contains("default_stage")
            );
            let b = &DynSafetyFamily.generate(seed).hidden[&PathBuf::from("tests/behavior.rs")];
            if s.breakers & GENERIC != 0 {
                assert!(b.contains(".map_all("));
            }
            if s.breakers & RETURNS_SELF != 0 {
                assert!(b.contains(".rescaled("));
            }
            if s.breakers & STATIC_CTOR != 0 {
                assert!(b.contains("::default_stage()"));
            }
        }
    }

    #[test]
    fn seeds_vary_both_axes() {
        let mut s = std::collections::HashSet::new();
        for seed in 0..800u64 {
            s.insert(DynSafetyFamily.spec_signature(seed).join("|"));
        }
        assert_eq!(s.len(), 28);
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let t = DynSafetyFamily.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

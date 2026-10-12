//! The `stack-machine` family (category `pattern-matching`).
//!
//! A third task shape, chosen to exercise a different Rust skill from `window-op`
//! (in-place slice mutation) and `error-handling` (parse → validate → fold): an
//! **exhaustive `match` over a provided enum**, driving a `Vec<i64>` stack. The
//! model implements `run(program: &[Op]) -> Vec<i64>`, executing a tiny stack
//! machine whose `Combine` / `Map` / `Reorder` operations have *seed-selected*
//! semantics described in the prompt.
//!
//! The third family is a new *category* — it tests pattern matching over an enum,
//! a genuinely different Rust skill from the first two. Its **spec-diversity is
//! 40** (5 combines × 4 maps × 2 reorders), the highest of the three families and
//! the authoritative diversity number (Q31).
//!
//! Note a deliberately-recorded surprise: its *reference*-capacity comes out at
//! **2**, *lower* than `error-handling`'s 7, even though it has more skills. The
//! fixed `match`/loop scaffolding dominates the solution text even more than
//! `error-handling`'s plumbing did, so the deflated reference-distance proxy is
//! lower still. This is a third confirmation that reference-distance is a poor
//! diversity measure — it is *lowest* for the family with the *most* skills — and
//! why the decided gate is spec-diversity, not any text distance (docs Q31).
//! Solution-first and correct-by-construction as always (ADR-0003): native `eval`
//! and the emitted reference are mirrored.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Combine {
    Add,
    Sub,
    Mul,
    Max,
    Min,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Map {
    Neg,
    Abs,
    Double,
    Inc,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Reorder {
    Swap,
    Rot3,
}

struct Spec {
    combine: Combine,
    map: Map,
    reorder: Reorder,
    fn_name: &'static str,
}

const NAMES: &[&str] = &[
    "run",
    "execute",
    "evaluate",
    "interpret",
    "fold_ops",
    "step_program",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let combine = match rng.below(5) {
        0 => Combine::Add,
        1 => Combine::Sub,
        2 => Combine::Mul,
        3 => Combine::Max,
        _ => Combine::Min,
    };
    let map = match rng.below(4) {
        0 => Map::Neg,
        1 => Map::Abs,
        2 => Map::Double,
        _ => Map::Inc,
    };
    let reorder = if rng.below(2) == 0 {
        Reorder::Swap
    } else {
        Reorder::Rot3
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        combine,
        map,
        reorder,
        fn_name,
    }
}

/// One instruction. The enum is *provided* to the model; only the semantics of
/// `Combine`/`Map`/`Reorder` vary by seed (defined in the prompt).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Op {
    Push(i64),
    Combine,
    Map,
    Reorder,
}

fn combine_apply(c: Combine, a: i64, b: i64) -> i64 {
    match c {
        Combine::Add => a + b,
        Combine::Sub => a - b,
        Combine::Mul => a * b,
        Combine::Max => a.max(b),
        Combine::Min => a.min(b),
    }
}

fn map_apply(m: Map, x: i64) -> i64 {
    match m {
        Map::Neg => -x,
        Map::Abs => x.abs(),
        Map::Double => x * 2,
        Map::Inc => x + 1,
    }
}

/// Native reference, mirroring the emitted source exactly. Underflowing ops (too
/// few elements) are no-ops.
fn eval(spec: &Spec, program: &[Op]) -> Vec<i64> {
    let mut stack: Vec<i64> = Vec::new();
    for op in program {
        match op {
            Op::Push(n) => stack.push(*n),
            Op::Combine => {
                if stack.len() >= 2 {
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    stack.push(combine_apply(spec.combine, a, b));
                }
            }
            Op::Map => {
                if let Some(x) = stack.last_mut() {
                    *x = map_apply(spec.map, *x);
                }
            }
            Op::Reorder => {
                let n = stack.len();
                match spec.reorder {
                    Reorder::Swap => {
                        if n >= 2 {
                            stack.swap(n - 1, n - 2);
                        }
                    }
                    Reorder::Rot3 => {
                        if n >= 3 {
                            stack[n - 3..].rotate_right(1);
                        }
                    }
                }
            }
        }
    }
    stack
}

// ---- emitted-source fragments (mirror the native fns above) ---------------

fn combine_expr(c: Combine) -> &'static str {
    match c {
        Combine::Add => "a + b",
        Combine::Sub => "a - b",
        Combine::Mul => "a * b",
        Combine::Max => "a.max(b)",
        Combine::Min => "a.min(b)",
    }
}

fn map_expr(m: Map) -> &'static str {
    match m {
        Map::Neg => "-*x",
        Map::Abs => "(*x).abs()",
        Map::Double => "*x * 2",
        Map::Inc => "*x + 1",
    }
}

fn reorder_body(r: Reorder) -> &'static str {
    match r {
        Reorder::Swap => "if n >= 2 { stack.swap(n - 1, n - 2); }",
        Reorder::Rot3 => "if n >= 3 { stack[n - 3..].rotate_right(1); }",
    }
}

fn combine_prose(c: Combine) -> &'static str {
    match c {
        Combine::Add => "their sum `a + b`",
        Combine::Sub => "their difference `a - b`",
        Combine::Mul => "their product `a * b`",
        Combine::Max => "the larger of the two",
        Combine::Min => "the smaller of the two",
    }
}

fn map_prose(m: Map) -> &'static str {
    match m {
        Map::Neg => "its negation",
        Map::Abs => "its absolute value",
        Map::Double => "twice its value",
        Map::Inc => "one more than its value",
    }
}

fn reorder_prose(r: Reorder) -> &'static str {
    match r {
        Reorder::Swap => "swap the top two elements",
        Reorder::Rot3 => {
            "rotate the top three elements so the top element moves down to third position"
        }
    }
}

const ENUM_SRC: &str = "#[derive(Debug, Clone, Copy, PartialEq)]\n\
     pub enum Op {\n\
     \x20   Push(i64),\n\
     \x20   Combine,\n\
     \x20   Map,\n\
     \x20   Reorder,\n\
     }\n";

fn reference_src(spec: &Spec) -> String {
    format!(
        "{enum_src}\n\
         pub fn {name}(program: &[Op]) -> Vec<i64> {{\n\
         \x20   let mut stack: Vec<i64> = Vec::new();\n\
         \x20   for op in program {{\n\
         \x20       match op {{\n\
         \x20           Op::Push(n) => stack.push(*n),\n\
         \x20           Op::Combine => {{\n\
         \x20               if stack.len() >= 2 {{\n\
         \x20                   let b = stack.pop().unwrap();\n\
         \x20                   let a = stack.pop().unwrap();\n\
         \x20                   stack.push({combine});\n\
         \x20               }}\n\
         \x20           }}\n\
         \x20           Op::Map => {{\n\
         \x20               if let Some(x) = stack.last_mut() {{\n\
         \x20                   *x = {map};\n\
         \x20               }}\n\
         \x20           }}\n\
         \x20           Op::Reorder => {{\n\
         \x20               let n = stack.len();\n\
         \x20               {reorder}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   stack\n\
         }}\n",
        enum_src = ENUM_SRC,
        name = spec.fn_name,
        combine = combine_expr(spec.combine),
        map = map_expr(spec.map),
        reorder = reorder_body(spec.reorder),
    )
}

fn render_op(op: &Op) -> String {
    match op {
        Op::Push(n) => format!("Op::Push({n})"),
        Op::Combine => "Op::Combine".to_string(),
        Op::Map => "Op::Map".to_string(),
        Op::Reorder => "Op::Reorder".to_string(),
    }
}

fn render_program(program: &[Op]) -> String {
    let items: Vec<String> = program.iter().map(render_op).collect();
    format!("vec![{}]", items.join(", "))
}

/// A short human-readable form of a program for the prompt examples.
fn prose_program(program: &[Op]) -> String {
    let items: Vec<String> = program
        .iter()
        .map(|op| match op {
            Op::Push(n) => format!("Push({n})"),
            Op::Combine => "Combine".to_string(),
            Op::Map => "Map".to_string(),
            Op::Reorder => "Reorder".to_string(),
        })
        .collect();
    format!("[{}]", items.join(", "))
}

/// Seed-varied worked examples: `(program, final stack)`, computed natively so
/// each is correct by construction. Includes a guaranteed non-trivial program
/// (so the const-empty / echo baselines fail) plus random ones.
fn worked_examples(spec: &Spec, seed: u64) -> Vec<(Vec<Op>, Vec<i64>)> {
    let mut rng = Rng::new(seed ^ 0x57AC_1234_0000_0001);
    let mut out: Vec<(Vec<Op>, Vec<i64>)> = Vec::new();

    // Canonical program: two pushes then a Combine then a Map, which always
    // produces a non-empty, non-echo result under every seed's semantics.
    {
        let a = 2 + (seed % 5) as i64;
        let b = 3 + (seed % 4) as i64;
        let prog = vec![Op::Push(a), Op::Push(b), Op::Combine, Op::Map];
        let res = eval(spec, &prog);
        out.push((prog, res));
    }

    // Random programs, biased toward Push so the stack is usually non-empty.
    for _ in 0..3 {
        let len = 3 + rng.below(4) as usize; // 3..=6 ops
        let prog: Vec<Op> = (0..len)
            .map(|_| match rng.below(6) {
                0..=2 => {
                    let mag = 1 + rng.below(9) as i64; // 1..=9, never zero
                    let v = if rng.below(2) == 0 { mag } else { -mag };
                    Op::Push(v)
                }
                3 => Op::Combine,
                4 => Op::Map,
                _ => Op::Reorder,
            })
            .collect();
        let res = eval(spec, &prog);
        out.push((prog, res));
    }

    out
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (prog, res) in worked_examples(spec, seed) {
        s.push_str(&format!("  {}  ->  {res:?}\n", prose_program(&prog)));
    }
    s
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let examples = worked_examples_prose(spec, seed);
    format!(
        "//! Implement `{name}` below.\n\
         //!\n\
         {doc}\n\
         {enum_src}\n\
         pub fn {name}(program: &[Op]) -> Vec<i64> {{\n\
         \x20   todo!()\n\
         }}\n",
        name = spec.fn_name,
        enum_src = ENUM_SRC,
        doc = examples
            .lines()
            .map(|l| format!("//! {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let examples = worked_examples_prose(spec, seed);
    format!(
        "Implement the function `{name}` in `src/lib.rs`. The `Op` enum is already \
         provided; keep it.\n\
         \n\
         Execute the `program` against an initially-empty stack of `i64`, then return \
         the final stack (bottom first). Process each `Op` in order:\n\
         - `Push(n)`: push `n` onto the stack.\n\
         - `Combine`: pop the top two values (`b` on top, then `a`) and push {combine}.\n\
         - `Map`: replace the top element with {map}.\n\
         - `Reorder`: {reorder}.\n\
         \n\
         If the stack has too few elements for an operation, that operation is a no-op \
         (leave the stack unchanged).\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         \n\
         Signature:\n\
         ```rust\n\
         pub fn {name}(program: &[Op]) -> Vec<i64>\n\
         ```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        combine = combine_prose(spec.combine),
        map = map_prose(spec.map),
        reorder = reorder_prose(spec.reorder),
        examples = examples,
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
    let mut body = format!("use task::{{Op, {}}};\n\n", spec.fn_name);
    for (i, (prog, res)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let program: Vec<Op> = {prog};\n\
             \x20   assert_eq!({name}(&program), vec!{res:?});\n\
             }}\n\n",
            prog = render_program(prog),
            name = spec.fn_name,
        ));
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec).replacen(ENUM_SRC, "", 1).replacen(
        &format!("pub fn {}", spec.fn_name),
        "fn reference",
        1,
    );
    format!(
        "use task::{{Op, {name}}};\n\
         \n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xDEAD_BEEF_1234_5678;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 12) as usize;\n\
         \x20       let program: Vec<Op> = (0..len)\n\
         \x20           .map(|_| match next() % 6 {{\n\
         \x20               0 | 1 | 2 => Op::Push((next() % 19) as i64 - 9),\n\
         \x20               3 => Op::Combine,\n\
         \x20               4 => Op::Map,\n\
         \x20               _ => Op::Reorder,\n\
         \x20           }})\n\
         \x20           .collect();\n\
         \x20       assert_eq!({name}(&program), reference(&program), \"mismatch: {{program:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = reference,
    )
}

/// Degenerate: always returns an empty stack. Fails on any non-empty result.
fn const_empty(spec: &Spec) -> String {
    format!(
        "{enum_src}\n\
         pub fn {name}(program: &[Op]) -> Vec<i64> {{ let _ = program; Vec::new() }}\n",
        enum_src = ENUM_SRC,
        name = spec.fn_name,
    )
}

/// Degenerate: echoes the pushed values, ignoring every other op. Fails whenever
/// a Combine/Map/Reorder changes the result.
fn echo_pushes(spec: &Spec) -> String {
    format!(
        "{enum_src}\n\
         pub fn {name}(program: &[Op]) -> Vec<i64> {{\n\
         \x20   let mut stack = Vec::new();\n\
         \x20   for op in program {{\n\
         \x20       if let Op::Push(n) = op {{ stack.push(*n); }}\n\
         \x20   }}\n\
         \x20   stack\n\
         }}\n",
        enum_src = ENUM_SRC,
        name = spec.fn_name,
    )
}

pub struct StackMachineFamily;

impl Generator for StackMachineFamily {
    fn id(&self) -> &str {
        "stack-machine"
    }
    fn category(&self) -> &str {
        "pattern-matching"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("stack-machine", seed);

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
            id: format!("stack-machine/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            // Building the result Vec legitimately allocates: no alloc constraint.
            alloc_test: String::new(),
            max_unsafe: Some(0),
            check_clippy: false,
            clippy_allow: Vec::new(),
            forbidden_paths: Vec::new(),
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
            ("const-empty".to_string(), const_empty(&spec)),
            ("echo-pushes".to_string(), echo_pushes(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is the trio of operation semantics. Function name and the
        // random program data are cosmetic (Q31).
        let spec = sample(seed);
        vec![
            format!("combine:{:?}", spec.combine),
            format!("map:{:?}", spec.map),
            format!("reorder:{:?}", spec.reorder),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = StackMachineFamily;
        assert_eq!(g.generate(9).prompt, g.generate(9).prompt);
        assert_eq!(g.generate(9).hidden, g.generate(9).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        let spec = Spec {
            combine: Combine::Add,
            map: Map::Neg,
            reorder: Reorder::Swap,
            fn_name: "run",
        };
        // 2, 3 -> Combine(add) -> 5 -> Map(neg) -> -5
        assert_eq!(
            eval(&spec, &[Op::Push(2), Op::Push(3), Op::Combine, Op::Map]),
            vec![-5]
        );
        // Swap: [1, 2] -> [2, 1]
        assert_eq!(
            eval(&spec, &[Op::Push(1), Op::Push(2), Op::Reorder]),
            vec![2, 1]
        );
        // Underflow Combine on one element is a no-op.
        assert_eq!(eval(&spec, &[Op::Push(7), Op::Combine]), vec![7]);
    }

    #[test]
    fn rot3_rotates_top_three() {
        let spec = Spec {
            combine: Combine::Add,
            map: Map::Neg,
            reorder: Reorder::Rot3,
            fn_name: "run",
        };
        // [1, 2, 3] -> top (3) moves to third: [3, 1, 2]
        assert_eq!(
            eval(&spec, &[Op::Push(1), Op::Push(2), Op::Push(3), Op::Reorder]),
            vec![3, 1, 2]
        );
    }

    #[test]
    fn seeds_vary_the_semantics() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..200u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}/{:?}", s.combine, s.map, s.reorder));
        }
        assert!(
            variants.len() >= 20,
            "expected variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = StackMachineFamily;
        let t = g.generate(4);
        assert!(t.prompt.contains(&t.canary));
    }
}

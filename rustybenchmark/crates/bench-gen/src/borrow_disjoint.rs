//! The `borrow-disjoint` family (category `borrow-lifetimes`) — mutate one field while appending
//! to another: **disjoint field borrows** and the helper-method trap.
//!
//! A pinned `Machine` owns `cells: Vec<i64>` and `log: Vec<String>`, with a provided helper
//! `note(&mut self, msg)` that appends to the log. The model implements `run(&mut self)`, which
//! rewrites each cell in place and logs some of the changes. The natural first attempt,
//!
//! ```text
//! for (i, c) in self.cells.iter_mut().enumerate() {
//!     ...
//!     self.note(format!(..));   // E0499: self already mutably borrowed through `cells`
//! }
//! ```
//!
//! is the classic aliasing error: calling a `&mut self` *method* borrows all of `self`, while
//! touching the field (`self.log.push(..)`) borrows only `log`. The fix (index loop, field access
//! instead of the helper, or a split borrow) is exactly the NLL / disjoint-field knowledge the
//! `borrow-lifetimes` category is about (docs/04). The escape of copying `cells` first
//! (`clone`, `to_vec`, `to_owned`) is a forbidden path.
//!
//! Seed-selected on three axes: **Op** applied to each cell (add `k`, double, negate, clamp to a
//! max), **Cond** for logging (the cell changed, the new value is even, the new value exceeds a
//! threshold), and **Dir** (front-to-back or back-to-front, which reverses the log order).
//! 4 x 3 x 2 = **24 distinct skills**; `k`, the max and the threshold are constants of the same
//! skill (Q31) and are excluded from `spec_signature`. Constraint-dominant per docs/04.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Op {
    Add(i64),
    Double,
    Negate,
    ClampMax(i64),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Cond {
    Changed,
    NewEven,
    NewAbove(i64),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Dir {
    Forward,
    Backward,
}

struct Spec {
    op: Op,
    cond: Cond,
    dir: Dir,
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let op = match rng.below(4) {
        0 => Op::Add(1 + rng.below(9) as i64),
        1 => Op::Double,
        2 => Op::Negate,
        _ => Op::ClampMax(2 + rng.below(4) as i64),
    };
    let cond = match rng.below(3) {
        0 => Cond::Changed,
        1 => Cond::NewEven,
        _ => Cond::NewAbove(rng.below(2) as i64),
    };
    let dir = if rng.below(2) == 0 {
        Dir::Forward
    } else {
        Dir::Backward
    };
    Spec { op, cond, dir }
}

// ---- native reference ---------------------------------------------------------------

fn apply_op(op: Op, v: i64) -> i64 {
    match op {
        Op::Add(k) => v + k,
        Op::Double => v * 2,
        Op::Negate => -v,
        Op::ClampMax(m) => v.min(m),
    }
}

fn cond_holds(cond: Cond, old: i64, new: i64) -> bool {
    match cond {
        Cond::Changed => old != new,
        Cond::NewEven => new % 2 == 0,
        Cond::NewAbove(t) => new > t,
    }
}

/// The answer: the final cells and the log.
fn run(spec: &Spec, cells: &[i64]) -> (Vec<i64>, Vec<String>) {
    let mut out = cells.to_vec();
    let mut log = Vec::new();
    let order: Vec<usize> = match spec.dir {
        Dir::Forward => (0..out.len()).collect(),
        Dir::Backward => (0..out.len()).rev().collect(),
    };
    for i in order {
        let old = out[i];
        let new = apply_op(spec.op, old);
        out[i] = new;
        if cond_holds(spec.cond, old, new) {
            log.push(format!("{i}: {old} -> {new}"));
        }
    }
    (out, log)
}

// ---- emitted source ---------------------------------------------------------------------

fn op_expr(op: Op) -> String {
    match op {
        Op::Add(k) => format!("old + {k}"),
        Op::Double => "old * 2".to_string(),
        Op::Negate => "-old".to_string(),
        Op::ClampMax(m) => format!("old.min({m})"),
    }
}

fn cond_expr(cond: Cond) -> String {
    match cond {
        Cond::Changed => "old != new".to_string(),
        Cond::NewEven => "new % 2 == 0".to_string(),
        Cond::NewAbove(t) => format!("new > {t}"),
    }
}

const PRELUDE: &str = "pub struct Machine {\n\
    \x20   cells: Vec<i64>,\n\
    \x20   log: Vec<String>,\n\
    }\n\
    \n\
    impl Machine {\n\
    \x20   pub fn new(cells: Vec<i64>) -> Machine {\n\
    \x20       Machine {\n\
    \x20           cells,\n\
    \x20           log: Vec::new(),\n\
    \x20       }\n\
    \x20   }\n\
    \n\
    \x20   pub fn cells(&self) -> &[i64] {\n\
    \x20       &self.cells\n\
    \x20   }\n\
    \n\
    \x20   pub fn log(&self) -> &[String] {\n\
    \x20       &self.log\n\
    \x20   }\n\
    \n\
    \x20   /// Appends `msg` to the log.\n\
    \x20   pub fn note(&mut self, msg: String) {\n\
    \x20       self.log.push(msg);\n\
    \x20   }\n";

fn run_body(spec: &Spec, helper: bool) -> String {
    let order = match spec.dir {
        Dir::Forward => "0..self.cells.len()",
        Dir::Backward => "(0..self.cells.len()).rev()",
    };
    let log = if helper {
        "self.note(format!(\"{i}: {old} -> {new}\"));"
    } else {
        "self.log.push(format!(\"{i}: {old} -> {new}\"));"
    };
    format!(
        "    pub fn run(&mut self) {{\n\
         \x20       for i in {order} {{\n\
         \x20           let old = self.cells[i];\n\
         \x20           let new = {op};\n\
         \x20           self.cells[i] = new;\n\
         \x20           if {cond} {{\n\
         \x20               {log}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20   }}\n",
        op = op_expr(spec.op),
        cond = cond_expr(spec.cond),
    )
}

fn reference_src(spec: &Spec) -> String {
    format!("{PRELUDE}\n{}}}\n", run_body(spec, true))
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .1
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Implement `Machine::run` below. The rest of `Machine` is provided — keep it.\n\
         //!\n\
         {doc}\n\
         {PRELUDE}\n\
         \x20   pub fn run(&mut self) {{\n\
         \x20       todo!()\n\
         \x20   }}\n\
         }}\n"
    )
}

// ---- examples -----------------------------------------------------------------------------

/// The canonical cells: mixed signs, evens and odds, values above and below every clamp and
/// threshold the seeds draw, so every (op, cond) changes cells and logs at least one entry.
fn canonical() -> Vec<i64> {
    vec![3, -2, 8, 5, 0, 7]
}

fn worked_examples(spec: &Spec, seed: u64) -> (Vec<Vec<i64>>, String) {
    let mut rng = Rng::new(seed ^ 0xD15F_0000_0000_0A91);
    let mut cases = vec![canonical()];
    for _ in 0..2 {
        let n = 3 + rng.below(5) as usize;
        cases.push((0..n).map(|_| rng.below(21) as i64 - 8).collect());
    }
    let mut prose = String::new();
    for c in &cases {
        let (cells, log) = run(spec, c);
        prose.push_str(&format!(
            "  Machine::new(vec!{c:?}) then run()  ->  cells {cells:?}, log {log:?}\n"
        ));
    }
    (cases, prose)
}

fn op_prose(op: Op) -> String {
    match op {
        Op::Add(k) => format!("add {k}"),
        Op::Double => "double it".to_string(),
        Op::Negate => "negate it".to_string(),
        Op::ClampMax(m) => format!("clamp it to at most {m} (`min({m})`)"),
    }
}

fn cond_prose(cond: Cond) -> String {
    match cond {
        Cond::Changed => "the cell's value changed".to_string(),
        Cond::NewEven => "the new value is even".to_string(),
        Cond::NewAbove(t) => format!("the new value is greater than {t}"),
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (_, examples) = worked_examples(spec, seed);
    let dir = match spec.dir {
        Dir::Forward => "from the first cell to the last",
        Dir::Backward => "from the **last** cell to the first",
    };
    format!(
        "Implement `Machine::run` in `src/lib.rs`. `Machine` owns `cells: Vec<i64>` and a `log: \
         Vec<String>`; everything except `run` is provided, including the helper `note`.\n\
         \n\
         `run` visits the cells {dir}. For each cell it replaces the value in place: {op}. If \
         {cond}, it appends the line `\"<index>: <old> -> <new>\"` to the log (index is the \
         cell's position, so it counts from the front even when visiting from the back).\n\
         \n\
         Constraints:\n\
         - Work in place: do not copy the cells first (`clone`, `to_vec` and `to_owned` are not \
         allowed).\n\
         - Do not use `unsafe`. Do not change the provided items.\n\
         \n\
         Provided in `src/lib.rs`:\n\
         ```rust\n\
         {prelude}\n\
         \x20   pub fn run(&mut self) {{ /* yours */ }}\n\
         }}\n\
         ```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        op = op_prose(spec.op),
        cond = cond_prose(spec.cond),
        prelude = PRELUDE.trim_end(),
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
    let mut body = String::from("use task::Machine;\n\n");
    for (i, c) in cases.iter().enumerate() {
        let (cells, log) = run(spec, c);
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let mut m = Machine::new(vec!{c:?});\n    m.run();\n    assert_eq!(m.cells(), &{cells:?}[..]);\n    let want: Vec<&str> = vec!{log:?};\n    assert_eq!(m.log(), &want[..]);\n}}\n\n"
        ));
    }
    body.push_str(
        "#[test]\nfn empty_machine() {\n    let mut m = Machine::new(vec![]);\n    m.run();\n    assert!(m.cells().is_empty() && m.log().is_empty());\n}\n",
    );
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    format!(
        "mod reference {{\n{indented}}}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xD15F_ED00_0000_004E;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = (next() % 10) as usize;\n\
         \x20       let cells: Vec<i64> = (0..n).map(|_| (next() % 41) as i64 - 20).collect();\n\
         \x20       let mut t = task::Machine::new(cells.clone());\n\
         \x20       let mut r = reference::Machine::new(cells.clone());\n\
         \x20       t.run();\n\
         \x20       r.run();\n\
         \x20       assert_eq!(t.cells(), r.cells(), \"cells {{cells:?}}\");\n\
         \x20       assert_eq!(t.log(), r.log(), \"log {{cells:?}}\");\n\
         \x20   }}\n\
         }}\n"
    )
}

/// Degenerate: does nothing.
fn noop(_spec: &Spec) -> String {
    format!("{PRELUDE}\n    pub fn run(&mut self) {{}}\n}}\n")
}

/// Degenerate: rewrites the cells correctly but never logs.
fn no_log(spec: &Spec) -> String {
    let body = run_body(spec, true).replace(
        "self.note(format!(\"{i}: {old} -> {new}\"));",
        "let _ = (i, old, new);",
    );
    format!("{PRELUDE}\n{body}}}\n")
}

pub struct BorrowDisjointFamily;

impl Generator for BorrowDisjointFamily {
    fn id(&self) -> &str {
        "borrow-disjoint"
    }
    fn category(&self) -> &str {
        "borrow-lifetimes"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("borrow-disjoint", seed);

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
            id: format!("borrow-disjoint/{seed:016x}"),
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
            // Copying the cells first is the escape from the aliasing error.
            forbidden_paths: vec![
                "clone".to_string(),
                "to_vec".to_string(),
                "to_owned".to_string(),
            ],
            check_clippy: false,
            clippy_allow: Vec::new(),
            // borrow-lifetimes is constraint-dominant (docs/04).
            weights: (0.35, 0.55, 0.10),
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
            ("noop".to_string(), noop(&spec)),
            ("no-log".to_string(), no_log(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let op = match spec.op {
            Op::Add(_) => "add",
            Op::Double => "double",
            Op::Negate => "negate",
            Op::ClampMax(_) => "clamp",
        };
        let cond = match spec.cond {
            Cond::Changed => "changed",
            Cond::NewEven => "new_even",
            Cond::NewAbove(_) => "new_above",
        };
        let dir = match spec.dir {
            Dir::Forward => "forward",
            Dir::Backward => "backward",
        };
        vec![
            format!("op:{op}"),
            format!("cond:{cond}"),
            format!("dir:{dir}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = BorrowDisjointFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn run_matches_intent() {
        let s = Spec {
            op: Op::Add(2),
            cond: Cond::NewEven,
            dir: Dir::Backward,
        };
        let (cells, log) = run(&s, &[1, 2, 3]);
        assert_eq!(cells, vec![3, 4, 5]);
        // 3 -> 5 (odd, no), 2 -> 4 (even, index 1), 1 -> 3 (odd, no): back to front.
        assert_eq!(log, vec!["1: 2 -> 4".to_string()]);
        let s = Spec {
            op: Op::ClampMax(4),
            cond: Cond::Changed,
            dir: Dir::Forward,
        };
        let (cells, log) = run(&s, &[9, 1, 5]);
        assert_eq!(cells, vec![4, 1, 4]);
        assert_eq!(log, vec!["0: 9 -> 4".to_string(), "2: 5 -> 4".to_string()]);
    }

    #[test]
    fn canonical_defeats_both_baselines_under_every_parameter_choice() {
        // noop fails iff cells change; no-log fails iff the log is non-empty.
        let ops: Vec<Op> = (1..=9)
            .map(Op::Add)
            .chain([Op::Double, Op::Negate])
            .chain((2..=5).map(Op::ClampMax))
            .collect();
        let conds: Vec<Cond> = [Cond::Changed, Cond::NewEven]
            .into_iter()
            .chain((0..=1).map(Cond::NewAbove))
            .collect();
        for &op in &ops {
            for &cond in &conds {
                for dir in [Dir::Forward, Dir::Backward] {
                    let s = Spec { op, cond, dir };
                    let (cells, log) = run(&s, &canonical());
                    assert_ne!(cells, canonical(), "{op:?}: cells unchanged");
                    assert!(!log.is_empty(), "{op:?}/{cond:?}/{dir:?}: empty log");
                }
            }
        }
    }

    #[test]
    fn backward_runs_log_in_reverse_but_index_from_the_front() {
        let s = Spec {
            op: Op::Double,
            cond: Cond::Changed,
            dir: Dir::Backward,
        };
        let (_, log) = run(&s, &[1, 2, 3]);
        assert_eq!(log[0], "2: 3 -> 6");
        assert_eq!(log[2], "0: 1 -> 2");
    }

    #[test]
    fn the_reference_uses_the_helper_and_no_forbidden_names() {
        for seed in 0..40u64 {
            let r = reference_src(&sample(seed));
            assert!(r.contains("self.note("));
            for bad in ["clone", "to_vec", "to_owned"] {
                assert!(!r.contains(bad), "seed {seed}: {bad}");
            }
        }
    }

    #[test]
    fn seeds_vary_all_three_axes() {
        let mut s = std::collections::HashSet::new();
        for seed in 0..600u64 {
            s.insert(BorrowDisjointFamily.spec_signature(seed).join("|"));
        }
        assert_eq!(s.len(), 24);
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let t = BorrowDisjointFamily.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

//! Trait-object puzzles over one heterogeneous shelf.
//!
//! Every driver below walks a shelf of unrelated shapes behind a single
//! `dyn Metric` vtable. The shapes and the drivers are PROVIDED; the only
//! thing missing is the three `impl Metric` blocks that make Square, Bar
//! and Tri interchangeable. Fill those in and every query starts working.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub trait Metric {
    fn value(&self) -> i64;
    fn tag(&self) -> u64;
}

pub struct Square(pub i64);
pub struct Bar(pub i64);
pub struct Tri(pub i64);

impl Metric for Square {
    fn value(&self) -> i64 {
        self.0 * self.0
    }
    fn tag(&self) -> u64 {
        1
    }
}

impl Metric for Bar {
    fn value(&self) -> i64 {
        self.0
    }
    fn tag(&self) -> u64 {
        2
    }
}

impl Metric for Tri {
    fn value(&self) -> i64 {
        3 * self.0
    }
    fn tag(&self) -> u64 {
        3
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    TotalValue,
    MaxValue,
    FirstOver,
    CountTag,
    ValueSpread,
}

pub const OP_ALL: [Op; 5] = [
    Op::TotalValue,
    Op::MaxValue,
    Op::FirstOver,
    Op::CountTag,
    Op::ValueSpread,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::TotalValue => "total_value",
            Op::MaxValue => "max_value",
            Op::FirstOver => "first_over",
            Op::CountTag => "count_tag",
            Op::ValueSpread => "value_spread",
        }
    }

    pub fn extra_arg(self) -> &'static str {
        match self {
            Op::FirstOver => ", threshold: i64",
            Op::CountTag => ", tag: u64",
            _ => "",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::TotalValue => "the sum of every shape's value",
            Op::MaxValue => "the largest value on the shelf, or -1 when it is empty",
            Op::FirstOver => {
                "the index of the first shape whose value clears the threshold strictly, or -1"
            }
            Op::CountTag => "how many shapes carry exactly the given tag",
            Op::ValueSpread => {
                "the gap between the largest and smallest values, or -1 with fewer than two shapes"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
    /// Seeds the worked examples shown in the prompt and used by the tests (they used to be a
    /// fixed `7` for every instance, so same-skill prompts were byte-identical).
    pub ex_seed: u64,
}

pub fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let a = rng.below(5) as usize;
    let mut b = rng.below(5) as usize;
    while b == a {
        b = rng.below(5) as usize;
    }
    let mut ops = [OP_ALL[a], OP_ALL[b]];
    ops.sort();
    Spec { ops, ex_seed: seed }
}

pub type Out = i64;

/// Shape kinds cycle by position: squares, bars, triangles, repeat.
fn shelf_boxes(vals: &[i64]) -> Vec<Box<dyn Metric>> {
    vals.iter()
        .enumerate()
        .map(|(i, &v)| match i % 3 {
            0 => Box::new(Square(v)) as Box<dyn Metric>,
            1 => Box::new(Bar(v)) as Box<dyn Metric>,
            _ => Box::new(Tri(v)) as Box<dyn Metric>,
        })
        .collect()
}

fn as_dyns(boxes: &[Box<dyn Metric>]) -> Vec<&dyn Metric> {
    boxes.iter().map(|b| &**b as &dyn Metric).collect()
}
fn b_total(shelf: &[&dyn Metric]) -> i64 {
    shelf.iter().map(|m| m.value()).sum()
}

fn b_max(shelf: &[&dyn Metric]) -> i64 {
    shelf.iter().map(|m| m.value()).max().unwrap_or(-1)
}

fn b_first_over(shelf: &[&dyn Metric], threshold: i64) -> i64 {
    for (i, m) in shelf.iter().enumerate() {
        if m.value() > threshold {
            return i as i64;
        }
    }
    -1
}

fn b_count_tag(shelf: &[&dyn Metric], tag: u64) -> i64 {
    shelf.iter().filter(|m| m.tag() == tag).count() as i64
}

fn b_spread(shelf: &[&dyn Metric]) -> i64 {
    if shelf.len() < 2 {
        return -1;
    }
    let mut lo = shelf[0].value();
    let mut hi = lo;
    for m in shelf {
        let v = m.value();
        if v < lo {
            lo = v;
        }
        if v > hi {
            hi = v;
        }
    }
    hi - lo
}

fn eval(op: Op, shelf: &[&dyn Metric], threshold: i64, tag: u64) -> i64 {
    match op {
        Op::TotalValue => b_total(shelf),
        Op::MaxValue => b_max(shelf),
        Op::FirstOver => b_first_over(shelf, threshold),
        Op::CountTag => b_count_tag(shelf, tag),
        Op::ValueSpread => b_spread(shelf),
    }
}

pub const CANONICAL_SEED: u64 = 0xD9A5_FA11;

fn anchors_hold(vals: &[i64], threshold: i64, tag: u64) -> bool {
    let boxes = shelf_boxes(vals);
    let shelf = as_dyns(&boxes);
    b_total(&shelf) >= 3
        && b_max(&shelf) >= 3
        && b_first_over(&shelf, threshold) >= 0
        && b_count_tag(&shelf, tag) >= 1
        && b_spread(&shelf) >= 1
}

fn canonical(seed: u64) -> (Vec<i64>, i64, u64) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = 3 + rng.below(4) as usize;
        let mut vals = Vec::new();
        for _ in 0..n {
            vals.push((rng.below(7) + 1) as i64);
        }
        let threshold = rng.below(20) as i64;
        let tag = rng.below(3) + 1;
        if anchors_hold(&vals, threshold, tag) {
            return (vals, threshold, tag);
        }
    }
    unreachable!("canonical shape unreachable");
}
pub struct ExampleCase {
    pub vals: Vec<i64>,
    pub threshold: i64,
    pub tag: u64,
    pub answers: Vec<(Op, Out)>,
}

pub const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0188;

fn case(vals: Vec<i64>, threshold: i64, tag: u64) -> ExampleCase {
    let boxes = shelf_boxes(&vals);
    let shelf = as_dyns(&boxes);
    let answers = OP_ALL
        .iter()
        .map(|&op| (op, eval(op, &shelf, threshold, tag)))
        .collect();
    ExampleCase {
        vals,
        threshold,
        tag,
        answers,
    }
}

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let (cv, ct, cg) = canonical(seed);
    let mut out = vec![
        case(cv, ct, cg),
        case(Vec::new(), 5, 2),
        case(vec![5], 3, 1),
        case(vec![4, 4], 9, 3),
    ];
    for _ in 0..8 {
        let n = rng.below(5) as usize;
        let mut vals = Vec::new();
        for _ in 0..n {
            vals.push(rng.below(8) as i64);
        }
        out.push(case(vals, rng.below(21) as i64, rng.below(3) + 1));
    }
    out
}

/// Emits the task-side boxed shelf literal.
pub fn render_shelf(vals: &[i64]) -> String {
    if vals.is_empty() {
        return "Vec::new()".to_string();
    }
    let mut items = Vec::new();
    for (i, &v) in vals.iter().enumerate() {
        let ctor = match i % 3 {
            0 => "Square",
            1 => "Bar",
            _ => "Tri",
        };
        items.push(format!("Box::new(task::{}({}i64))", ctor, v));
    }
    format!("vec![{}]", items.join(", "))
}

pub fn call_src(op: Op, var: &str, t_var: &str, g_var: &str) -> String {
    match op {
        Op::TotalValue => format!("total_value({})", var),
        Op::MaxValue => format!("max_value({})", var),
        Op::FirstOver => format!("first_over({}, {})", var, t_var),
        Op::CountTag => format!("count_tag({}, {})", var, g_var),
        Op::ValueSpread => format!("value_spread({})", var),
    }
}
pub fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(shelf: &[Box<dyn Metric>]{}) -> i64",
        op.name(),
        op.extra_arg()
    )
}

pub fn op_stub_src(op: Op) -> String {
    let mut s = String::new();
    s.push_str(&format!("{} {{\n    todo!()\n}}\n", op_sig_src(op)));
    s
}

fn body_lines(op: Op) -> Vec<&'static str> {
    match op {
        Op::TotalValue => vec!["shelf.iter().map(|m| m.value()).sum()"],
        Op::MaxValue => vec!["shelf.iter().map(|m| m.value()).max().unwrap_or(-1)"],
        Op::FirstOver => vec![
            "for (i, m) in shelf.iter().enumerate() {",
            "    if m.value() > threshold {",
            "        return i as i64;",
            "    }",
            "}",
            "-1",
        ],
        Op::CountTag => vec!["shelf.iter().filter(|m| m.tag() == tag).count() as i64"],
        Op::ValueSpread => vec![
            "if shelf.len() < 2 {",
            "    return -1;",
            "}",
            "let mut lo = shelf[0].value();",
            "let mut hi = lo;",
            "for m in shelf {",
            "    let v = m.value();",
            "    if v < lo {",
            "        lo = v;",
            "    }",
            "    if v > hi {",
            "        hi = v;",
            "    }",
            "}",
            "hi - lo",
        ],
    }
}

pub fn op_fn_src(op: Op) -> String {
    let mut s = String::new();
    s.push_str(&op_sig_src(op));
    s.push_str(" {\n");
    for line in body_lines(op) {
        s.push_str("    ");
        s.push_str(line);
        s.push('\n');
    }
    s.push_str("}\n");
    s
}

/// The three impl blocks, parameterized by mode.
/// Solved = the reference answers; Stub = todo!() for the skeleton;
/// Zero = value() answers zero (tags stay real so count_tag stays correct).
pub fn shapes_src(mode: &str) -> String {
    let value_body = |solved: &str, stub_note: &str| -> String {
        match mode {
            "Solved" => solved.to_string(),
            "Zero" => "0".to_string(),
            _ => format!("todo!() // {}", stub_note),
        }
    };
    let tag_body = |mode: &str| -> &'static str {
        if mode == "Stub" {
            "todo!()"
        } else {
            "1"
        }
    };
    let mut s = String::new();
    s.push_str("impl Metric for Square {\n");
    s.push_str("    fn value(&self) -> i64 {\n");
    s.push_str(&format!(
        "        {}\n",
        value_body("self.0 * self.0", "area")
    ));
    s.push_str("    }\n");
    s.push_str("    fn tag(&self) -> u64 {\n");
    s.push_str(&format!("        {}\n", tag_body(mode)));
    s.push_str("    }\n");
    s.push_str("}\n");

    s.push_str("\nimpl Metric for Bar {\n");
    s.push_str("    fn value(&self) -> i64 {\n");
    s.push_str(&format!("        {}\n", value_body("self.0", "length")));
    s.push_str("    }\n");
    s.push_str("    fn tag(&self) -> u64 {\n");
    s.push_str(&format!(
        "        {}\n",
        if mode == "Stub" { "todo!()" } else { "2" }
    ));
    s.push_str("    }\n");
    s.push_str("}\n");

    s.push_str("\nimpl Metric for Tri {\n");
    s.push_str("    fn value(&self) -> i64 {\n");
    s.push_str(&format!(
        "        {}\n",
        value_body("3 * self.0", "three sides")
    ));
    s.push_str("    }\n");
    s.push_str("    fn tag(&self) -> u64 {\n");
    s.push_str(&format!(
        "        {}\n",
        if mode == "Stub" { "todo!()" } else { "3" }
    ));
    s.push_str("    }\n");
    s.push_str("}\n");
    s
}

pub const DIFF_STATE: u64 = 0xE7EE_ED00_0000_0188;

const TRAIT_AND_SHAPES_SRC: &str = "pub trait Metric {\n    fn value(&self) -> i64;\n    fn tag(&self) -> u64;\n}\n\npub struct Square(pub i64);\npub struct Bar(pub i64);\npub struct Tri(pub i64);\n\n";

pub fn reference_src(spec: &Spec) -> String {
    let mut s = String::new();
    s.push_str(TRAIT_AND_SHAPES_SRC);
    s.push('\n');
    s.push_str(&shapes_src("Solved"));
    s.push('\n');
    for &op in &spec.ops {
        s.push_str(&op_fn_src(op));
        s.push('\n');
    }
    s
}
pub fn worked_examples_prose(spec: &Spec) -> String {
    let mut s = String::new();
    for (i, ex) in worked_examples(spec.ex_seed).iter().enumerate() {
        let shelf_lit = render_shelf(&ex.vals);
        for &(op, out) in &ex.answers {
            if !spec.ops.contains(&op) {
                continue;
            }
            s.push_str(&format!(
                "//!   ex{} shelf {} threshold {} tag {} -> {} = {}\n",
                i,
                shelf_lit,
                ex.threshold,
                ex.tag,
                op.name(),
                out
            ));
        }
    }
    s
}

pub fn skeleton_src(spec: &Spec) -> String {
    let mut s = String::new();
    s.push_str("//! Trait-object puzzles over one heterogeneous shelf.\n");
    s.push_str("//!\n");
    s.push_str("//! The shapes and the drivers are PROVIDED. Your whole job is the\n");
    s.push_str("//! three `impl Metric` blocks: give Square, Bar and Tri their value\n");
    s.push_str("//! and tag so every driver starts working through the vtable.\n");
    s.push_str("//! Worked examples (shelf | threshold | tag -> op = answer):\n");
    s.push_str(&worked_examples_prose(spec));
    s.push('\n');
    s.push_str("pub trait Metric {\n    fn value(&self) -> i64;\n    fn tag(&self) -> u64;\n}\n\n");
    s.push_str(
        "pub struct Square(pub i64);\npub struct Bar(pub i64);\npub struct Tri(pub i64);\n\n",
    );
    s.push_str(&shapes_src("Stub"));
    s.push_str("\n// Provided drivers - do not change them.\n");
    for &op in &spec.ops {
        s.push_str(&op_fn_src(op));
        s.push('\n');
    }
    s
}

pub fn prompt_intro() -> &'static str {
    "One trait, three unrelated shapes, one shared shelf. Implement the \
Metric trait for Square, Bar and Tri so the provided generic drivers run \
unmodified."
}

pub fn prompt(spec: &Spec, canary: &str) -> String {
    let mut s = String::new();
    s.push_str(prompt_intro());
    s.push_str("\n\nYou must provide:\n");
    s.push_str("- `impl Metric for Square`: its value is its area (side times itself); tag 1.\n");
    s.push_str("- `impl Metric for Bar`: its value is its length; tag 2.\n");
    s.push_str("- `impl Metric for Tri`: its value is three per side unit; tag 3.\n");
    s.push_str("\nThe drivers must answer:\n");
    for &op in &spec.ops {
        s.push_str(&format!("- `{}`: {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- No unsafe code.\n- Keep every signature and provided driver exactly as given.\n");
    s.push_str("\n```rust\n");
    for &op in &spec.ops {
        s.push_str(&op_sig_src(op));
        s.push('\n');
    }
    s.push_str("```\n\nWorked examples (shelf | threshold | tag -> op = answer):\n");
    s.push_str(&worked_examples_prose(spec));
    s.push_str(&format!(
        "\nCanary reference for this task: {} (repeat it verbatim).\n",
        canary
    ));
    s
}

pub fn cargo_toml() -> String {
    "[package]\nname = \"task\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n"
        .to_string()
}
pub fn behavior_test_src(spec: &Spec) -> String {
    let mut s = String::new();
    let names: Vec<&str> = spec.ops.iter().map(|op| op.name()).collect();
    s.push_str(&format!("use task::{{{}}};\n", names.join(", ")));
    s.push_str("use task::{Metric, Square, Bar, Tri};\n\n");
    for (i, ex) in worked_examples(spec.ex_seed).iter().enumerate() {
        for &(op, out) in &ex.answers {
            if !spec.ops.contains(&op) {
                continue;
            }
            s.push_str(&format!("#[test]\nfn ex{}_{}() {{\n", i, op.name()));
            if ex.vals.is_empty() {
                s.push_str("    let shelf: Vec<Box<dyn Metric>> = Vec::new();\n");
            } else {
                s.push_str(&format!(
                    "    let shelf: Vec<Box<dyn Metric>> = {};\n",
                    render_shelf(&ex.vals)
                ));
            }
            s.push_str(&format!(
                "    assert_eq!({}, {}i64);\n",
                call_src(op, "&shelf", &ex.threshold.to_string(), &ex.tag.to_string()),
                out
            ));
            s.push_str("}\n\n");
        }
    }
    // Invalid-input pins do not exist here; instead pin the zero-value cheat
    // killer: a shelf of shapes whose values are all nonzero.
    s
}

pub fn differential_test_src(spec: &Spec) -> String {
    let mut s = String::new();
    let names: Vec<&str> = spec.ops.iter().map(|op| op.name()).collect();
    s.push_str(&format!("use task::{{{}}};\n", names.join(", ")));
    s.push('\n');
    let mut pasted = reference_src(spec);
    for &op in &spec.ops {
        let from = format!("pub fn {}(", op.name());
        let to = format!("fn ref_{}(", op.name());
        assert_eq!(
            pasted.matches(&from).count(),
            1,
            "rename target {}",
            op.name()
        );
        pasted = pasted.replacen(&from, &to, 1);
    }
    s.push_str(&pasted);
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n");
    s.push_str(
        "    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n",
    );
    s.push_str("    *state >> 33\n}\n\n");
    s.push_str("#[test]\nfn differential_vs_reference() {\n");
    s.push_str("    let mut state: u64 = 0xE7EE_ED00_0000_0188;\n");
    s.push_str("    for _ in 0..3000 {\n");
    s.push_str("        let n = (nx(&mut state) % 6) as usize;\n");
    s.push_str("        let mut vals = Vec::new();\n");
    s.push_str("        for _ in 0..n {\n");
    s.push_str("            vals.push((nx(&mut state) % 8) as i64);\n");
    s.push_str("        }\n");
    s.push_str("        let threshold = (nx(&mut state) % 21) as i64;\n");
    s.push_str("        let tag = (nx(&mut state) % 3) + 1;\n");
    s.push_str("        let task_shelf: Vec<Box<dyn task::Metric>> = if vals.is_empty() {\n");
    s.push_str("            Vec::new()\n");
    s.push_str("        } else {\n");
    s.push_str("            vals.iter().enumerate().map(|(i, &v)| match i % 3 {\n");
    s.push_str("                0 => Box::new(task::Square(v)) as Box<dyn task::Metric>,\n");
    s.push_str("                1 => Box::new(task::Bar(v)) as Box<dyn task::Metric>,\n");
    s.push_str("                _ => Box::new(task::Tri(v)) as Box<dyn task::Metric>,\n");
    s.push_str("            }).collect()\n");
    s.push_str("        };\n");
    s.push_str("        let ref_shelf: Vec<Box<dyn Metric>> = if vals.is_empty() {\n");
    s.push_str("            Vec::new()\n");
    s.push_str("        } else {\n");
    s.push_str("            vals.iter().enumerate().map(|(i, &v)| match i % 3 {\n");
    s.push_str("                0 => Box::new(Square(v)) as Box<dyn Metric>,\n");
    s.push_str("                1 => Box::new(Bar(v)) as Box<dyn Metric>,\n");
    s.push_str("                _ => Box::new(Tri(v)) as Box<dyn Metric>,\n");
    s.push_str("            }).collect()\n");
    s.push_str("        };\n");
    for &op in &spec.ops {
        let call = call_src(op, "&task_shelf", "threshold", "tag");
        let ref_call = match op {
            Op::TotalValue => "ref_total_value(&ref_shelf)".to_string(),
            Op::MaxValue => "ref_max_value(&ref_shelf)".to_string(),
            Op::FirstOver => "ref_first_over(&ref_shelf, threshold)".to_string(),
            Op::CountTag => "ref_count_tag(&ref_shelf, tag)".to_string(),
            Op::ValueSpread => "ref_value_spread(&ref_shelf)".to_string(),
        };
        s.push_str(&format!("        assert_eq!({}, {});\n", call, ref_call));
    }
    s.push_str("    }\n");
    s.push_str("}\n");
    s
}
fn const_zero_baseline() -> String {
    let mut s = String::new();
    s.push_str(&shapes_src("Solved"));
    s.push('\n');
    for &op in OP_ALL.iter() {
        let sig = op_sig_src(op);
        let params: Vec<&str> = sig
            .split("(")
            .nth(1)
            .unwrap_or("")
            .split(")")
            .next()
            .unwrap()
            .split(',')
            .filter(|p| p.trim() != "shelf: &[Box<dyn Metric>]")
            .collect();
        let silencer = if params.is_empty() {
            "let _ = shelf;".to_string()
        } else {
            format!(
                "let _ = (shelf{});",
                params
                    .iter()
                    .map(|p| p.split(':').next().unwrap().trim())
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        s.push_str(&format!("{} {{\n    {}\n    0\n}}\n", sig, silencer));
    }
    s
}

fn zero_everything_baseline() -> String {
    let mut s = String::new();
    s.push_str(&shapes_src("Zero"));
    s.push('\n');
    for &op in OP_ALL.iter() {
        s.push_str(&op_fn_src(op));
        s.push('\n');
    }
    s
}

pub struct DynShapesFamily;

impl Generator for DynShapesFamily {
    fn id(&self) -> &'static str {
        "dyn-shapes"
    }

    fn category(&self) -> &'static str {
        "trait-objects"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary(self.id(), seed);
        let skeleton = skeleton_src(&spec);
        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(PathBuf::from("src/lib.rs"), skeleton);
        let mut hidden = BTreeMap::new();
        hidden.insert(PathBuf::from("tests/behavior.rs"), behavior_test_src(&spec));
        hidden.insert(
            PathBuf::from("tests/differential.rs"),
            differential_test_src(&spec),
        );
        GeneratedTask {
            id: format!("{}/{}", self.id(), seed),
            category: self.category().to_string(),
            prompt: prompt(&spec, &canary),
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
        reference_src(&sample(seed))
    }

    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(&sample(seed))
    }

    fn trivial_baselines(&self, _seed: u64) -> Vec<(String, String)> {
        vec![
            ("const-zero".to_string(), const_zero_baseline()),
            ("zero-everything".to_string(), zero_everything_baseline()),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        sample(seed)
            .ops
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
        let a = DynShapesFamily.generate(7);
        let b = DynShapesFamily.generate(7);
        assert_eq!(a.id, b.id);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(
            a.files[&PathBuf::from("src/lib.rs")],
            b.files[&PathBuf::from("src/lib.rs")]
        );
    }

    #[test]
    fn native_ops_match_intent() {
        let boxes = shelf_boxes(&[3, 10, 4]);
        let shelf = as_dyns(&boxes);
        assert_eq!(b_total(&shelf), 31);
        assert_eq!(b_max(&shelf), 12);
        assert_eq!(b_first_over(&shelf, 9), 1);
        assert_eq!(b_first_over(&shelf, 24), -1);
        let solo_boxes = shelf_boxes(&[5]);
        let solo = as_dyns(&solo_boxes);
        assert_eq!(b_first_over(&solo, 30), -1); // solo Square(5) answers 25
        assert_eq!(b_count_tag(&shelf, 2), 1);
        assert_eq!(b_spread(&shelf), 3); // values 9/10/12 span 3

        assert_eq!(b_max(&[]), -1);
        assert_eq!(b_spread(&[]), -1);
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
            let (vals, threshold, tag) = canonical(seed);
            let boxes = shelf_boxes(&vals);
            let shelf = as_dyns(&boxes);
            assert!(!vals.is_empty());
            assert_ne!(b_total(&shelf), 0, "seed {}", seed);
            assert_ne!(b_max(&shelf), 0, "seed {}", seed);
            assert!(b_first_over(&shelf, threshold) >= 0, "seed {}", seed);
            assert!(b_count_tag(&shelf, tag) >= 1, "seed {}", seed);
            assert!(b_spread(&shelf) >= 1, "seed {}", seed);
            // zero-everything keeps tags real, so count_tag matches the
            // cheat; every scalar op diverges. const-zero loses everywhere.
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for ex in worked_examples(seed) {
                let boxes = shelf_boxes(&ex.vals);
                let shelf = as_dyns(&boxes);
                for (op, want) in ex.answers {
                    assert_eq!(
                        eval(op, &shelf, ex.threshold, ex.tag),
                        want,
                        "seed {} op {}",
                        seed,
                        op.name()
                    );
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let reference = reference_src(&spec);
            for &op in OP_ALL.iter() {
                let needle = format!("pub fn {}(", op.name());
                assert_eq!(
                    reference.matches(&needle).count(),
                    if spec.ops.contains(&op) { 1 } else { 0 },
                    "seed {} op {}",
                    seed,
                    op.name()
                );
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let skeleton = skeleton_src(&spec);
            let task_prompt = prompt(&spec, "rb-canary");
            assert_eq!(skeleton.matches("todo!()").count(), 6);
            assert!(!skeleton.contains("self.0 * self.0"));
            assert!(!task_prompt.contains("todo!()"));
            assert!(!task_prompt.contains("n * n"));
            assert!(!task_prompt.contains("3 * "));
            for &op in &spec.ops {
                assert!(task_prompt.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for &op in OP_ALL.iter() {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let sig_commas = params.matches(',').count();
            let call = call_src(op, "&s", "t", "g");
            let call_commas = call.matches(',').count();
            assert_eq!(sig_commas, call_commas, "op {}", op.name());
        }
    }

    #[test]
    fn zero_impl_baseline_breaks_the_scalar_ops() {
        let solved = shapes_src("Solved");
        let zeroed = shapes_src("Zero");
        assert_ne!(solved, zeroed);
        assert!(zeroed.contains("fn value(&self) -> i64 {\n        0\n    }"));
        assert!(!solved.contains("fn value(&self) -> i64 {\n        0\n    }"));
        // Tags stay real under the zero cheat so count_tag stays correct.
        assert!(zeroed.contains("        2\n"));
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let task_prompt = prompt(&sample(11), "rb-deadbeef1234");
        assert!(task_prompt.contains("rb-deadbeef1234"));
    }
}

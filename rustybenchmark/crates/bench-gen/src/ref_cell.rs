//! Borrow-flag puzzles over one shared bag.
//!
//! Every query reads and/or writes a `RefCell<Vec<u64>>`. The reference
//! answers keep each borrow tightly scoped: finish the write phase before
//! opening a read phase, never hold a guard across a conflicting borrow.
//! The naive baseline below holds its shared guard across a `borrow_mut`
//! call and keeps using it afterwards, so the borrow flag trips and the
//! task panics deterministically — single-threaded, so the differential
//! comparison stays sound.

use std::cell::RefCell;

use crate::{mint_canary, GeneratedTask, Generator, Rng};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Op {
    AppendAndTotal,
    PopAndReturn,
    SetFirst,
    SumOfSquares,
    CountOf,
}

const OP_ALL: [Op; 5] = [
    Op::AppendAndTotal,
    Op::PopAndReturn,
    Op::SetFirst,
    Op::SumOfSquares,
    Op::CountOf,
];

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::AppendAndTotal => "append_and_total",
            Op::PopAndReturn => "pop_and_return",
            Op::SetFirst => "set_first",
            Op::SumOfSquares => "sum_of_squares",
            Op::CountOf => "count_of",
        }
    }

    /// Extra scalar parameter carried after the cell argument.
    fn extra_arg(self) -> &'static str {
        match self {
            Op::AppendAndTotal | Op::SetFirst => ", x: u64",
            Op::CountOf => ", v: u64",
            _ => "",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::AppendAndTotal => "push x onto the bag, then report the new total",
            Op::PopAndReturn => "remove the last element and hand it back (-1 when empty)",
            Op::SetFirst => {
                "replace the first element with x and report the displaced value (-1 empty)"
            }
            Op::SumOfSquares => "sum the squares of every element without touching the bag",
            Op::CountOf => "count exact occurrences of v",
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

fn b_append_and_total(cell: &RefCell<Vec<u64>>, x: u64) -> i64 {
    cell.borrow_mut().push(x);
    cell.borrow().iter().sum::<u64>() as i64
}

fn b_pop_and_return(cell: &RefCell<Vec<u64>>) -> i64 {
    match cell.borrow_mut().pop() {
        Some(v) => v as i64,
        None => -1,
    }
}

fn b_set_first(cell: &RefCell<Vec<u64>>, x: u64) -> i64 {
    match cell.borrow_mut().first_mut() {
        Some(slot) => {
            let old = *slot;
            *slot = x;
            old as i64
        }
        None => -1,
    }
}

fn b_sum_of_squares(cell: &RefCell<Vec<u64>>) -> i64 {
    cell.borrow().iter().map(|&x| x * x).sum::<u64>() as i64
}

fn b_count_of(cell: &RefCell<Vec<u64>>, v: u64) -> i64 {
    cell.borrow().iter().filter(|&&x| x == v).count() as i64
}

fn eval(op: Op, cell: &RefCell<Vec<u64>>, x: u64, v: u64) -> Out {
    match op {
        Op::AppendAndTotal => b_append_and_total(cell, x),
        Op::PopAndReturn => b_pop_and_return(cell),
        Op::SetFirst => b_set_first(cell, x),
        Op::SumOfSquares => b_sum_of_squares(cell),
        Op::CountOf => b_count_of(cell, v),
    }
}

const CANONICAL_SEED: u64 = 0xCE11_FA11;

/// A non-degenerate bag plus the two scalar arguments.
type CanonicalCase = (Vec<u64>, u64, u64);

fn canonical(seed: u64) -> CanonicalCase {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = 3 + rng.below(4);
        let mut bag = Vec::new();
        for _ in 0..n {
            bag.push(rng.below(9));
        }
        let x = rng.below(9);
        let v = rng.below(9);
        if anchors_hold(&bag, x, v) {
            return (bag, x, v);
        }
    }
    unreachable!("canonical bag unreachable");
}

fn anchors_hold(bag: &[u64], x: u64, v: u64) -> bool {
    if bag.is_empty() || bag[0] == x {
        return false;
    }
    let probe = RefCell::new(bag.to_vec());
    let ssq = b_sum_of_squares(&probe);
    let hits = b_count_of(&probe, v);
    ssq > 0 && hits >= 1
}
struct ExampleCase {
    bag: Vec<u64>,
    x: u64,
    v: u64,
    answers: Vec<(Op, Out)>,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_017E;

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let (bag, x, v) = canonical(seed);
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases = Vec::new();
    cases.push(ExampleCase {
        answers: OP_ALL
            .iter()
            .map(|&op| (op, eval(op, &RefCell::new(bag.clone()), x, v)))
            .collect(),
        bag,
        x,
        v,
    });
    for (bag, x, v) in [
        (Vec::new(), 3, 5),
        (vec![4], 9, 4),
        (vec![4, 2, 4, 4, 7], 1, 4),
    ] {
        cases.push(ExampleCase {
            answers: OP_ALL
                .iter()
                .map(|&op| (op, eval(op, &RefCell::new(bag.clone()), x, v)))
                .collect(),
            bag,
            x,
            v,
        });
    }
    for _ in 0..3 {
        let n = rng.below(6);
        let mut bag = Vec::new();
        for _ in 0..n {
            bag.push(rng.below(9));
        }
        let x = rng.below(9);
        let v = rng.below(9);
        cases.push(ExampleCase {
            answers: OP_ALL
                .iter()
                .map(|&op| (op, eval(op, &RefCell::new(bag.clone()), x, v)))
                .collect(),
            bag,
            x,
            v,
        });
    }
    cases
}

fn render_bag(bag: &[u64]) -> String {
    if bag.is_empty() {
        "Vec::new()".to_string()
    } else {
        let items: Vec<String> = bag.iter().map(|v| format!("{v}u64")).collect();
        format!("vec![{}]", items.join(", "))
    }
}

/// Call text for one op against a bound `cell` plus scalar args.
fn call_src(op: Op, xvar: &str, vvar: &str) -> String {
    match op {
        Op::AppendAndTotal | Op::SetFirst => format!("{}(&cell, {})", op.name(), xvar),
        Op::CountOf => format!("{}(&cell, {})", op.name(), vvar),
        _ => format!("{}(&cell)", op.name()),
    }
}
fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(cell: &RefCell<Vec<u64>>{}) -> i64",
        op.name(),
        op.extra_arg()
    )
}

fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::AppendAndTotal => &[
            "    cell.borrow_mut().push(x);",
            "    cell.borrow().iter().sum::<u64>() as i64",
        ],
        Op::PopAndReturn => &[
            "    match cell.borrow_mut().pop() {",
            "        Some(v) => v as i64,",
            "        None => -1,",
            "    }",
        ],
        Op::SetFirst => &[
            "    match cell.borrow_mut().first_mut() {",
            "        Some(slot) => {",
            "            let old = *slot;",
            "            *slot = x;",
            "            old as i64",
            "        }",
            "        None => -1,",
            "    }",
        ],
        Op::SumOfSquares => &["    cell.borrow().iter().map(|&x| x * x).sum::<u64>() as i64"],
        Op::CountOf => &["    cell.borrow().iter().filter(|&&x| x == v).count() as i64"],
    };
    format!("{}\n{{\n{}\n}}\n", op_sig_src(op), body.join("\n"))
}

fn reference_src(spec: Spec) -> String {
    let mut src = String::from("use std::cell::RefCell;\n\n");
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
            let bag = render_bag(&case.bag);
            case.answers
                .iter()
                .map(move |(op, out)| {
                    format!(
                        "  bag {bag}, x {}, v {}  ->  {} = {out}",
                        case.x,
                        case.v,
                        op.name()
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect()
}
fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut doc = String::from("//! Borrow-flag puzzles over one shared bag.\n");
    doc.push_str("//!\n");
    doc.push_str("//! Each query reads and/or writes a bag behind a RefCell.\n");
    doc.push_str("//! Finish every write phase before opening a read phase; never\n");
    doc.push_str("//! hold a borrow across a conflicting borrow.\n");
    doc.push_str("//!\n");
    for line in worked_examples_prose(examples) {
        doc.push_str(&format!("//!{line}\n"));
    }
    doc.push('\n');
    doc.push_str("use std::cell::RefCell;\n\n");
    for &op in spec.ops.iter() {
        doc.push_str(&op_stub_src(op));
        doc.push('\n');
    }
    doc
}

fn prompt_intro() -> String {
    String::from(
        "Implement the required queries over a shared, interior-mutable bag.\n\nRequirements:\n\
- The cell argument is shared; mutate only through RefCell guards.\n\
- Keep each guard tightly scoped: complete write phases before opening read phases.\n\
- Holding one borrow across a conflicting borrow panics; such answers score zero.\n\
- Answers are exact integers; empty-bag conventions are shown in the examples.\n\nConstraints:\n- No unsafe code.\n",
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
        src.push_str(&format!("    let bag = {};\n", render_bag(&case.bag)));
        src.push_str(&format!("    let xv: u64 = {};\n", case.x));
        src.push_str(&format!("    let vv: u64 = {};\n", case.v));
        for &(op, out) in case.answers.iter() {
            if !spec.ops.contains(&op) {
                continue;
            }
            src.push_str(&format!(
                "    {{ let cell = RefCell::new(bag.clone()); assert_eq!({}, {out}); }}\n",
                call_src(op, "xv", "vv")
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
        src.push_str(&renamed);
        src.push('\n');
    }

    src.push_str("fn nx(state: &mut u64) -> u64 {\n");
    src.push_str("    *state = state\n");
    src.push_str("        .wrapping_mul(6364136223846793005)\n");
    src.push_str("        .wrapping_add(1442695040888963407);\n");
    src.push_str("    *state >> 33\n}\n\n");

    src.push_str("#[test]\nfn differential_vs_reference() {\n");
    src.push_str("    let mut state: u64 = 0xE7EE_ED00_0000_017E;\n");
    src.push_str("    for _ in 0..3000 {\n");
    src.push_str("        let n = (nx(&mut state) % 6) as usize;\n");
    src.push_str("        let mut vals: Vec<u64> = Vec::new();\n");
    src.push_str("        for _ in 0..n {\n");
    src.push_str("            vals.push((nx(&mut state) % 9) as u64);\n");
    src.push_str("        }\n");
    src.push_str("        let xv: u64 = (nx(&mut state) % 9) as u64;\n");
    src.push_str("        let vv: u64 = (nx(&mut state) % 9) as u64;\n");
    for &op in spec.ops.iter() {
        // Mutating ops need independent cells or the second call observes
        // the first call's write.
        let (call, ref_call) = match op {
            Op::AppendAndTotal | Op::SetFirst => (
                format!("{}(&RefCell::new(vals.clone()), xv)", op.name()),
                format!("ref_{}(&RefCell::new(vals.clone()), xv)", op.name()),
            ),
            Op::CountOf => (
                format!("{}(&RefCell::new(vals.clone()), vv)", op.name()),
                format!("ref_{}(&RefCell::new(vals.clone()), vv)", op.name()),
            ),
            _ => (
                format!("{}(&RefCell::new(vals.clone()))", op.name()),
                format!("ref_{}(&RefCell::new(vals.clone()))", op.name()),
            ),
        };
        src.push_str(&format!(
            "        {{ let vals = vals.clone(); assert_eq!({call}, {ref_call}); }}\n"
        ));
    }
    src.push_str("    }\n}\n");
    src
}
fn const_zero(spec: Spec) -> String {
    let mut src = String::from("use std::cell::RefCell;\n\n");
    for &op in spec.ops.iter() {
        let body = match op {
            Op::AppendAndTotal | Op::SetFirst => "let _ = (cell, x);\n    0",
            Op::CountOf => "let _ = (cell, v);\n    0",
            _ => "let _ = cell;\n    0",
        };
        src.push_str(&format!("{}\n{{\n{body}\n}}\n\n", op_sig_src(op)));
    }
    src
}

/// The naive baseline: every body holds a shared borrow across a
/// conflicting `borrow_mut` and keeps using the guard afterwards, so the
/// borrow flag trips on EVERY call — empty bags included.
fn naive_overlapping(spec: Spec) -> String {
    let mut src = String::from("use std::cell::RefCell;\n\n");
    for &op in spec.ops.iter() {
        let body: &[&str] = match op {
            Op::AppendAndTotal => &[
                "    let held = cell.borrow();",
                "    let before = held.iter().sum::<u64>();",
                "    cell.borrow_mut().push(x);",
                "    (before + held.len() as u64) as i64",
            ],
            Op::PopAndReturn => &[
                "    let held = cell.borrow();",
                "    let top = held.last().copied().unwrap_or(0);",
                "    cell.borrow_mut().pop();",
                "    top as i64 + held.len() as i64 - held.len() as i64",
            ],
            Op::SetFirst => &[
                "    let held = cell.borrow();",
                "    let old = held.first().copied().unwrap_or(0);",
                "    if let Some(slot) = cell.borrow_mut().first_mut() { *slot = x; }",
                "    old as i64 + held.len() as i64 - held.len() as i64",
            ],
            Op::SumOfSquares => &[
                "    let held = cell.borrow();",
                "    let sq = held.iter().map(|&x| x * x).sum::<u64>();",
                "    cell.borrow_mut().push(0);",
                "    (sq - held.len() as u64) as i64",
            ],
            Op::CountOf => &[
                "    let held = cell.borrow();",
                "    let hits = held.iter().filter(|&&x| x == v).count();",
                "    cell.borrow_mut().push(0);",
                "    hits as i64 + held.len() as i64 - held.len() as i64",
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
pub struct RefCellFamily;

impl Generator for RefCellFamily {
    fn id(&self) -> &'static str {
        "ref-cell"
    }

    fn category(&self) -> &'static str {
        "interior-mutability"
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
        prompt.push_str("```\n\nWorked examples (bag, x, v -> answer):\n\n");
        for line in worked_examples_prose(&examples) {
            prompt.push_str(&line);
            prompt.push('\n');
        }
        prompt.push_str("\nThe canary for this task is ");
        prompt.push_str(&mint_canary("ref-cell", seed));
        prompt.push_str(".\n");

        GeneratedTask {
            id: format!("ref-cell/{seed:016x}"),
            category: self.category().to_string(),
            prompt,
            canary: mint_canary("ref-cell", seed),
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
            ("naive-overlapping".to_string(), naive_overlapping(spec)),
        ]
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = RefCellFamily.generate(7);
        let b = RefCellFamily.generate(7);
        assert_eq!(a.id, b.id);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
    }

    #[test]
    fn native_ops_match_intent() {
        let cell = RefCell::new(vec![3u64, 1, 4]);
        assert_eq!(b_append_and_total(&cell, 2), 10);
        // The append above already pushed onto this shared bag.
        assert_eq!(b_sum_of_squares(&cell), 30);
        assert_eq!(b_count_of(&cell, 4), 1);
        assert_eq!(b_set_first(&cell, 9), 3);
        // The append above grew the shared bag before set_first displaced its head.
        assert_eq!(cell.borrow().as_slice(), &[9, 1, 4, 2]);
        // ...which also makes the appended 2 the last element.
        assert_eq!(b_pop_and_return(&cell), 2);
        let empty = RefCell::new(Vec::new());
        assert_eq!(b_pop_and_return(&empty), -1);
        assert_eq!(b_set_first(&empty, 5), -1);
        assert_eq!(b_sum_of_squares(&empty), 0);
        assert_eq!(b_count_of(&empty, 5), 0);
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
            let (bag, x, v) = canonical(seed);
            assert!(!bag.is_empty());
            assert_ne!(bag[0], x);
            let cell = RefCell::new(bag.clone());
            assert!(b_sum_of_squares(&cell) > 0);
            assert!(b_count_of(&cell, v) >= 1);
            // Total after any push stays positive under the same anchor.
            assert!(b_append_and_total(&RefCell::new(bag.clone()), x) > 0);
            // pop/set_first may legitimately answer zero; conventions are
            // pinned by native hand cases instead.
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for case in worked_examples(seed) {
                let cell = RefCell::new(case.bag.clone());
                for (op, out) in case.answers.iter() {
                    assert_eq!(
                        eval(*op, &RefCell::new(case.bag.clone()), case.x, case.v),
                        *out
                    );
                }
                let _ = cell;
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        let g = RefCellFamily;
        let task = g.generate(11);
        let reference = g.reference_code(11);
        let spec_ops = sample(11).ops;
        for &op in OP_ALL.iter() {
            let marker = format!("pub fn {}(", op.name());
            if spec_ops.contains(&op) {
                assert!(reference.contains(&marker), "{marker} missing");
                assert!(
                    task.prompt.contains(&op_sig_src(op)),
                    "signature absent from prompt"
                );
            } else {
                assert!(!reference.contains(&marker), "{marker} leaked");
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        let g = RefCellFamily;
        let task = g.generate(13);
        let skeleton = task
            .files
            .get(&std::path::PathBuf::from("src/lib.rs"))
            .unwrap();
        assert!(skeleton.contains("todo!()"));
        for token in [
            ".iter().sum::<u64>()",
            "first_mut",
            ".filter(|&&",
            "borrow_mut().push(x)",
        ] {
            assert!(!skeleton.contains(token), "{token} leaked into skeleton");
            assert!(!task.prompt.contains(token), "{token} leaked into prompt");
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for &op in OP_ALL.iter() {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let want = params.matches(',').count();
            let call = match op {
                Op::AppendAndTotal | Op::SetFirst => call_src(op, "xv", "vv"),
                Op::CountOf => call_src(op, "xv", "vv"),
                _ => call_src(op, "xv", "vv"),
            };
            let got = call.matches(',').count();
            assert_eq!(got, want, "arity drift on {}", op.name());
        }
    }

    #[test]
    fn naive_baseline_holds_guards_and_reference_does_not() {
        let g = RefCellFamily;
        let naive = g.trivial_baselines(17);
        let (_, naive_src) = naive
            .iter()
            .find(|(name, _)| name == "naive-overlapping")
            .expect("naive baseline present");
        assert_eq!(
            naive_src.matches("let held = cell.borrow();").count(),
            sample(17).ops.len()
        );
        let reference = g.reference_code(17);
        assert!(!reference.contains("let held"), "reference holds guards");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = RefCellFamily;
        let task = g.generate(19);
        assert!(task.prompt.contains(&task.canary));
    }
}

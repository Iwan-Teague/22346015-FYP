//! Allocation-discipline refactors over one bag of counts.
//!
//! Every query below has a textbook implementation that builds intermediate
//! heap collections — hash sets for uniqueness, hash maps for tallies,
//! sorted copies for rankings, prefix vectors for balance points. Each also
//! has a famous single-pass, constant-space form. Tasks ship the allocating
//! versions as a WORKING starting point and hide a counting allocator: the
//! rewrite is judged on keeping every answer identical while touching the
//! heap zero times. This is the perf sibling of idiom-loop (rewrite, not
//! implement) and borrows the allocation probe wired by borrow-fix.

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// The five queries, each answerable without a single heap allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    CountUnique,
    MajorityElement,
    MissingInRange,
    Top2Product,
    EquilibriumIndex,
}

pub const OP_ALL: [Op; 5] = [
    Op::CountUnique,
    Op::MajorityElement,
    Op::MissingInRange,
    Op::Top2Product,
    Op::EquilibriumIndex,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::CountUnique => "count_unique",
            Op::MajorityElement => "majority_element",
            Op::MissingInRange => "missing_in_range",
            Op::Top2Product => "top2_product",
            Op::EquilibriumIndex => "equilibrium_index",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::CountUnique => "how many distinct values appear in the bag",
            Op::MajorityElement => "the value occupying strictly more than half the bag, or -1",
            Op::MissingInRange => "which value of 0..=len is absent from the bag",
            Op::Top2Product => "the product of the two largest values, or -1 with fewer than two",
            Op::EquilibriumIndex => {
                "the leftmost index whose left and right neighbours balance, or -1"
            }
        }
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
// ---------------------------------------------------------------- natives
// The zero-allocation references. Each mirrors the emitted reference body.

pub fn b_count_unique(xs: &[u64]) -> i64 {
    let mut seen = 0i64;
    for (i, x) in xs.iter().enumerate() {
        if !xs[..i].contains(x) {
            seen += 1;
        }
    }
    seen
}

pub fn b_majority_element(xs: &[u64]) -> i64 {
    let mut it = xs.iter();
    let mut cand = match it.next() {
        Some(&x) => x,
        None => return -1,
    };
    let mut votes = 1u64;
    for &x in it {
        if x == cand {
            votes += 1;
        } else {
            votes -= 1;
            if votes == 0 {
                cand = x;
                votes = 1;
            }
        }
    }
    if xs.iter().filter(|&&x| x == cand).count() * 2 > xs.len() {
        cand as i64
    } else {
        -1
    }
}

pub fn b_missing_in_range(xs: &[u64]) -> i64 {
    let n = xs.len() as u64;
    let expected = (n * (n + 1) / 2) as i64;
    let actual = xs.iter().fold(0i64, |acc, &x| acc + x as i64);
    expected - actual
}

pub fn b_top2_product(xs: &[u64]) -> i64 {
    if xs.len() < 2 {
        return -1;
    }
    let mut it = xs.iter();
    let (mut best, mut runner) = {
        let a = *it.next().unwrap();
        let b = *it.next().unwrap();
        if a >= b {
            (a, b)
        } else {
            (b, a)
        }
    };
    for &x in it {
        if x > best {
            runner = best;
            best = x;
        } else if x > runner {
            runner = x;
        }
    }
    (best * runner) as i64
}

pub fn b_equilibrium_index(xs: &[u64]) -> i64 {
    let total = xs.iter().fold(0u64, |acc, &x| acc.wrapping_add(x));
    let mut left = 0u64;
    for (i, &x) in xs.iter().enumerate() {
        if left == total - left - x {
            return i as i64;
        }
        left += x;
    }
    -1
}

pub fn op_eval(op: Op, xs: &[u64]) -> i64 {
    match op {
        Op::CountUnique => b_count_unique(xs),
        Op::MajorityElement => b_majority_element(xs),
        Op::MissingInRange => b_missing_in_range(xs),
        Op::Top2Product => b_top2_product(xs),
        Op::EquilibriumIndex => b_equilibrium_index(xs),
    }
}

// -------------------------------------------------------------- canonical

const CANONICAL_SEED: u64 = 0x9EFA_C711;

fn anchors_hold(xs: &[u64]) -> bool {
    let cu = b_count_unique(xs);
    let maj = b_majority_element(xs);
    let miss = b_missing_in_range(xs);
    let t2 = b_top2_product(xs);
    let eq = b_equilibrium_index(xs);
    cu >= 3
        && maj == -1
        && miss > 0
        && t2 > 0
        && eq > 0
        && cu != miss
        && t2 != miss
        && eq != miss
        && t2 != eq
}

/// A scrambled bag holding every value of `0..=len` except one non-zero one.
fn canonical(seed: u64) -> Vec<u64> {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = 4 + rng.below(4);
        let missing = 1 + rng.below(n);
        let mut bag: Vec<u64> = (0..=n).filter(|&v| v != missing).collect();
        for i in (1..bag.len()).rev() {
            let j = rng.below((i + 1) as u64) as usize;
            bag.swap(i, j);
        }
        if anchors_hold(&bag) {
            return bag;
        }
    }
    unreachable!("canonical bag");
}
// ---------------------------------------------------------------- examples

type ExampleCase = (Vec<u64>, Vec<(Op, i64)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_017C;

fn case(xs: Vec<u64>) -> ExampleCase {
    let outs = OP_ALL.iter().map(|&op| (op, op_eval(op, &xs))).collect();
    (xs, outs)
}

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut out = vec![case(canonical(seed))];
    out.push(case(Vec::new()));
    out.push(case(vec![4]));
    out.push(case(vec![2, 2, 1, 2, 3]));
    for _ in 0..3 {
        let n = 1 + rng.below(6) as usize;
        let xs: Vec<u64> = (0..n).map(|_| rng.below(8)).collect();
        out.push(case(xs));
    }
    out
}

fn render_nums(xs: &[u64]) -> String {
    if xs.is_empty() {
        return "&[]".to_string();
    }
    let items: Vec<String> = xs.iter().map(|x| x.to_string()).collect();
    format!("&[{}u64, {}]", items[0], items[1..].join(", "))
}

fn worked_examples_prose(examples: &[ExampleCase]) -> String {
    let mut lines: Vec<String> = Vec::new();
    for (xs, outs) in examples {
        let mut parts: Vec<String> = Vec::new();
        for &(op, v) in outs {
            parts.push(format!("{} = {}", op.name(), v));
        }
        lines.push(format!(
            "//!   nums {}  ->  {}",
            render_nums(xs),
            parts.join(", ")
        ));
    }
    lines.join("\n")
}

// ------------------------------------------------------------- emitted src

fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(xs: &[u64]) -> i64", op.name())
}

/// The ALLOCATING textbook implementations — the task's starting point.
fn naive_src(op: Op) -> String {
    let sig = op_sig_src(op);
    let body: &[&str] = match op {
        Op::CountUnique => &[
            "    let seen: std::collections::HashSet<u64> = xs.iter().copied().collect();",
            "    seen.len() as i64",
        ],
        Op::MajorityElement => &[
            "    let mut tally: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();",
            "    for &x in xs {",
            "        *tally.entry(x).or_insert(0) += 1;",
            "    }",
            "    let half = xs.len() / 2;",
            "    for (value, hits) in tally {",
            "        if hits > half {",
            "            return value as i64;",
            "        }",
            "    }",
            "    -1",
        ],
        Op::MissingInRange => &[
            "    let n = xs.len() as u64;",
            "    let present: std::collections::HashSet<u64> = xs.iter().copied().collect();",
            "    for candidate in 0..=n {",
            "        if !present.contains(&candidate) {",
            "            return candidate as i64;",
            "        }",
            "    }",
            "    -1",
        ],
        Op::Top2Product => &[
            "    if xs.len() < 2 {",
            "        return -1;",
            "    }",
            "    let mut ranked = xs.to_vec();",
            "    ranked.sort_unstable();",
            "    let hi = ranked[ranked.len() - 1];",
            "    let runner = ranked[ranked.len() - 2];",
            "    (hi * runner) as i64",
        ],
        Op::EquilibriumIndex => &[
            "    let mut prefix: Vec<u64> = Vec::with_capacity(xs.len() + 1);",
            "    prefix.push(0);",
            "    for &x in xs {",
            "        let last = *prefix.last().unwrap();",
            "        prefix.push(last + x);",
            "    }",
            "    let grand = prefix[xs.len()];",
            "    for i in 0..xs.len() {",
            "        if prefix[i] == grand - prefix[i + 1] {",
            "            return i as i64;",
            "        }",
            "    }",
            "    -1",
        ],
    };
    format!("{}\n{{\n{}\n}}\n", sig, body.join("\n"))
}

/// The zero-allocation reference implementations.
fn op_fn_src(op: Op) -> String {
    let sig = op_sig_src(op);
    let body: &[&str] = match op {
        Op::CountUnique => &[
            "    let mut seen = 0i64;",
            "    for (i, x) in xs.iter().enumerate() {",
            "        if !xs[..i].contains(x) {",
            "            seen += 1;",
            "        }",
            "    }",
            "    seen",
        ],
        Op::MajorityElement => &[
            "    let mut it = xs.iter();",
            "    let mut cand = match it.next() {",
            "        Some(&x) => x,",
            "        None => return -1,",
            "    };",
            "    let mut votes = 1u64;",
            "    for &x in it {",
            "        if x == cand {",
            "            votes += 1;",
            "        } else {",
            "            votes -= 1;",
            "            if votes == 0 {",
            "                cand = x;",
            "                votes = 1;",
            "            }",
            "        }",
            "    }",
            "    if xs.iter().filter(|&&x| x == cand).count() * 2 > xs.len() {",
            "        cand as i64",
            "    } else {",
            "        -1",
            "    }",
        ],
        Op::MissingInRange => &[
            "    let n = xs.len() as u64;",
            "    let expected = (n * (n + 1) / 2) as i64;",
            "    let actual = xs.iter().fold(0i64, |acc, &x| acc + x as i64);",
            "    expected - actual",
        ],
        Op::Top2Product => &[
            "    if xs.len() < 2 {",
            "        return -1;",
            "    }",
            "    let mut it = xs.iter();",
            "    let (mut best, mut runner) = {",
            "        let a = *it.next().unwrap();",
            "        let b = *it.next().unwrap();",
            "        if a >= b { (a, b) } else { (b, a) }",
            "    };",
            "    for &x in it {",
            "        if x > best {",
            "            runner = best;",
            "            best = x;",
            "        } else if x > runner {",
            "            runner = x;",
            "        }",
            "    }",
            "    (best * runner) as i64",
        ],
        Op::EquilibriumIndex => &[
            "    let total = xs.iter().fold(0u64, |acc, &x| acc.wrapping_add(x));",
            "    let mut left = 0u64;",
            "    for (i, &x) in xs.iter().enumerate() {",
            "        if left == total - left - x {",
            "            return i as i64;",
            "        }",
            "        left += x;",
            "    }",
            "    -1",
        ],
    };
    format!("{}\n{{\n{}\n}}\n", sig, body.join("\n"))
}

fn reference_src(spec: Spec) -> String {
    spec.ops
        .iter()
        .map(|&op| op_fn_src(op))
        .collect::<Vec<_>>()
        .join("\n")
}
fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}

/// The counting allocator probe — hidden as tests/alloc.rs in every task.
/// Built per spec: only the two selected ops sit on the counted hot path.
fn alloc_test_src(spec: Spec) -> String {
    let names: Vec<String> = spec.ops.iter().map(|&op| op.name().to_string()).collect();
    let use_line = format!("use task::{{{}}}", names.join(", "));
    let mut calls = String::new();
    for name in &names {
        calls.push_str(&format!("    let _ = std::hint::black_box({name}(&xs));\n"));
    }
    // A second, differently-shaped input runs under the counter too, so a
    // memoizer that paid its allocation during warm-up cannot reuse one
    // cached answer across both.
    for name in &names {
        calls.push_str(&format!("    let _ = std::hint::black_box({name}(&ys));\n"));
    }
    format!(
        r####"use std::alloc::{{GlobalAlloc, Layout, System}};
use std::sync::atomic::{{AtomicUsize, Ordering}};

static COUNT: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {{
        COUNT.fetch_add(1, Ordering::SeqCst);
        unsafe {{ System.alloc(layout) }}
    }}

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {{
        unsafe {{ System.dealloc(ptr, layout) }}
    }}

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {{
        COUNT.fetch_add(1, Ordering::SeqCst);
        unsafe {{ System.realloc(ptr, layout, new_size) }}
    }}
}}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

{use_line};

#[test]
fn hot_path_allocates_nothing() {{
    // Warm up any lazy runtime allocations first.
    let warm = [3u64, 1, 4, 1, 5];
    let _ = std::hint::black_box(warm);
    COUNT.store(0, Ordering::SeqCst);

    let xs = [2u64, 9, 4, 0, 7];
    let ys = [11u64, 3, 3, 8, 1, 6];
{calls}    assert_eq!(
        COUNT.load(Ordering::SeqCst),
        0,
        "alloc: hot path allocated"
    );
}}
"####,
        use_line = use_line,
        calls = calls,
    )
}

fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut doc: Vec<String> = vec![
        "//! Allocation-discipline refactor.".to_string(),
        "//!".to_string(),
        "//! The functions below are CORRECT: they already match the spec.".to_string(),
        "//! They are slow in the one way that matters here - each builds".to_string(),
        "//! intermediate heap collections on its hot path. Rewrite them so a".to_string(),
        "//! run performs ZERO heap allocations while returning exactly the".to_string(),
        "//! same answers. Signatures must stay exactly as given.".to_string(),
        "//!".to_string(),
        "//! Worked examples:".to_string(),
    ];
    doc.push(worked_examples_prose(examples));
    let fns: String = spec.ops.iter().map(|&op| naive_src(op)).collect();
    format!("{}\n\n{}", doc.join("\n"), fns)
}

fn prompt(spec: Spec, examples: &[ExampleCase], canary: &str) -> String {
    let mut reqs: Vec<String> = Vec::new();
    for &op in spec.ops.iter() {
        reqs.push(format!("- `{}`: {}", op.name(), op.prose()));
    }
    let sigs: String = spec
        .ops
        .iter()
        .map(|&op| op_sig_src(op))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Two bag queries are implemented and their answers are correct. But each implementation \
builds intermediate heap collections (hash sets, hash maps, sorted copies or prefix vectors) on \
its hot path.\n\nRewrite BOTH functions so that a complete run performs ZERO heap allocations. \
Every answer must stay byte-for-byte identical on every input, including empty bags and the -1 \
sentinels. Keep the exact signatures:\n\n```rust\n{sigs}\n```\n\nRequirements:\n{reqs}\n\n\
Constraints:\n- The hidden grader runs the functions under a counting allocator; any allocation \
on the hot path fails the task.\n- Behaviour is graded by fixed worked examples plus a fuzz \
differential against a reference; changing an answer fails the task.\n- Single-pass arithmetic \
over the input slice is sufficient for every query here.\n- No unsafe code.\n- Do not rename \
the functions or change their signatures.\n\nWorked examples:\n{examples}\n\nCanary (must appear \
verbatim in your answer): {canary}\n",
        sigs = sigs,
        reqs = reqs.join("\n"),
        examples = worked_examples_prose(examples),
        canary = canary,
    )
}

fn cargo_toml() -> &'static str {
    "[package]\nname = \"task\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n"
}
// ------------------------------------------------------------------ tests

fn behavior_test_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let names: Vec<String> = spec.ops.iter().map(|&op| op.name().to_string()).collect();
    let mut tests = format!("use task::{{{}}};\n\n", names.join(", "));
    for (i, (xs, outs)) in examples.iter().enumerate() {
        let lit = render_nums(xs);
        tests.push_str(&format!("#[test]\nfn ex{i}() {{\n"));
        tests.push_str(&format!("    let xs = {lit};\n"));
        for &(op, v) in outs {
            if spec.ops.contains(&op) {
                tests.push_str(&format!("    assert_eq!({}, {v});\n", call_src(op, "xs")));
            }
        }
        tests.push_str("}\n\n");
    }
    tests
}

fn differential_test_src(spec: Spec) -> String {
    let names: Vec<String> = spec.ops.iter().map(|&op| op.name().to_string()).collect();
    let mut src = format!("use task::{{{}}};\n\n", names.join(", "));
    src.push_str(&reference_src(spec).replacen(
        &format!("pub fn {}", spec.ops[0].name()),
        &format!("fn ref_{}", spec.ops[0].name()),
        1,
    ));
    for op in spec.ops.iter().skip(1) {
        src = src.replacen(
            &format!("pub fn {}", op.name()),
            &format!("fn ref_{}", op.name()),
            1,
        );
    }
    let mut asserts = String::new();
    for &op in spec.ops.iter() {
        asserts.push_str(&format!(
            "        assert_eq!({a}, ref_{a});\n",
            a = call_src(op, "&vals")
        ));
    }
    src.push_str(&format!(
        "\n#[test]\nfn differential_vs_reference() {{\n    fn nx(state: &mut u64) -> u64 {{\n        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        *state >> 33\n    }}\n\n    let mut state: u64 = 0xE7EE_ED00_0000_017C;\n    for _ in 0..3000 {{\n        let n = (nx(&mut state) % 7) as usize;\n        let mut vals: Vec<u64> = Vec::with_capacity(n);\n        for _ in 0..n {{\n            vals.push(nx(&mut state) % 9);\n        }}\n{asserts}    }}\n}}\n",
        asserts = asserts,
    ));
    src
}

fn const_zero() -> String {
    OP_ALL
        .iter()
        .map(|&op| format!("{}\n{{\n    let _ = xs;\n    0\n}}\n", op_sig_src(op)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The unchanged baseline IS the allocating skeleton — behaviourally exact,
/// so it passes behaviour and the differential and fails only the probe.
fn unchanged_baseline(spec: Spec) -> String {
    spec.ops
        .iter()
        .map(|&op| naive_src(op))
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct PerfRefactorFamily;

impl Generator for PerfRefactorFamily {
    fn id(&self) -> &'static str {
        "perf-refactor"
    }

    fn category(&self) -> &'static str {
        "allocation-discipline"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary(self.id(), seed);
        let skeleton = skeleton_src(spec, &examples);
        let prompt_text = prompt(spec, &examples, &canary);
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            std::path::PathBuf::from("Cargo.toml"),
            cargo_toml().to_string(),
        );
        files.insert(std::path::PathBuf::from("src/lib.rs"), skeleton.clone());
        let mut hidden = std::collections::BTreeMap::new();
        hidden.insert(
            std::path::PathBuf::from("tests/behavior.rs"),
            behavior_test_src(spec, &examples),
        );
        hidden.insert(
            std::path::PathBuf::from("tests/differential.rs"),
            differential_test_src(spec),
        );
        hidden.insert(
            std::path::PathBuf::from("tests/alloc.rs"),
            crate::thread_local_counter(alloc_test_src(spec)),
        );
        GeneratedTask {
            id: format!("perf-refactor/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt_text,
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::from("alloc"),
            max_unsafe: None,
            forbidden_paths: vec![],
            check_clippy: false,
            clippy_allow: vec![],
            weights: (0.30, 0.60, 0.10),
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
            ("const-zero".to_string(), const_zero()),
            ("unchanged".to_string(), unchanged_baseline(spec)),
        ]
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = PerfRefactorFamily.generate(81);
        let b = PerfRefactorFamily.generate(81);
        assert_eq!(a.id, b.id);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
    }

    #[test]
    fn native_ops_match_intent() {
        assert_eq!(b_count_unique(&[3, 1, 3, 7, 7, 2]), 4);
        assert_eq!(b_count_unique(&[5, 5, 5]), 1);
        assert_eq!(b_majority_element(&[2, 2, 1, 2, 3]), 2);
        assert_eq!(b_majority_element(&[9, 9, 9, 1, 1, 1]), -1);
        assert_eq!(b_missing_in_range(&[0, 1, 3]), 2);
        assert_eq!(b_missing_in_range(&[8, 8]), -13);
        assert_eq!(b_top2_product(&[3, 1, 4, 1, 5]), 20);
        assert_eq!(b_top2_product(&[7]), -1);
        assert_eq!(b_equilibrium_index(&[1, 7, 3, 6, 5, 6]), 3);
        assert_eq!(b_equilibrium_index(&[1, 2, 3]), -1);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut specs = std::collections::HashSet::new();
        for seed in 0..300u64 {
            specs.insert(sample(seed));
        }
        assert!(specs.len() >= 9, "only {} distinct pairs", specs.len());
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        for seed in 0..200u64 {
            let xs = canonical(seed);
            let cu = b_count_unique(&xs);
            let miss = b_missing_in_range(&xs);
            let t2 = b_top2_product(&xs);
            let eq = b_equilibrium_index(&xs);
            assert!(cu >= 3, "seed {seed}: count_unique {cu}");
            assert!(miss > 0, "seed {seed}: missing {miss}");
            assert!(t2 > 0, "seed {seed}: top2 {t2}");
            assert!(eq > 0, "seed {seed}: equilibrium {eq}");
            assert_ne!(cu, miss);
            assert_ne!(t2, eq);
            // const-zero dies on every scalar: all five answers are non-zero.
            assert_ne!(b_majority_element(&xs), 0);
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let (xs, outs) = {
                let examples = worked_examples(seed);
                (examples[0].0.clone(), examples[0].1.clone())
            };
            for (op, v) in outs {
                assert_eq!(op_eval(op, &xs), v, "seed {seed} op {}", op.name());
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let reference = reference_src(spec);
            for &op in OP_ALL.iter() {
                let marker = format!("pub fn {}(", op.name());
                let selected = spec.ops.contains(&op);
                assert_eq!(
                    reference.contains(&marker),
                    selected,
                    "seed {seed} op {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn skeleton_keeps_the_allocating_shapes_and_hides_the_solution() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let skeleton = skeleton_src(spec, &worked_examples(seed));
            let prompt_text = prompt(
                spec,
                &worked_examples(seed),
                &mint_canary("perf-refactor", seed),
            );
            let reference = reference_src(spec);
            // The skeleton ships the textbook allocating implementations.
            assert!(
                skeleton.contains("HashSet")
                    || skeleton.contains("to_vec(")
                    || skeleton.contains("Vec<"),
                "seed {seed}: skeleton lost its allocating shapes"
            );
            // The zero-allocation tricks must not leak into skeleton or prompt.
            for token in ["votes", "n * (n + 1)", "total - left", "runner-up scan"] {
                assert!(
                    !skeleton.contains(token) && !prompt_text.contains(token),
                    "seed {seed}: leaked {token}"
                );
            }
            for &op in spec.ops.iter() {
                assert!(
                    prompt_text.contains(&op_sig_src(op)),
                    "seed {seed}: prompt missing signature for {}",
                    op.name()
                );
            }
            // And the reference is genuinely allocation-free in shape.
            assert!(!reference.contains("HashSet"));
            assert!(!reference.contains("to_vec("));
            assert!(!reference.contains("Vec<"));
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for &op in OP_ALL.iter() {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call = call_src(op, "&xs");
            assert_eq!(
                params.matches(',').count(),
                call.matches(',').count(),
                "arity drift on {}",
                op.name()
            );
        }
    }

    #[test]
    fn alloc_probe_is_wired_into_the_task() {
        let t = PerfRefactorFamily.generate(81);
        assert_eq!(t.alloc_test, "alloc");
        let alloc = t
            .hidden
            .get(&std::path::PathBuf::from("tests/alloc.rs"))
            .expect("alloc probe hidden file");
        assert!(alloc.contains("#[global_allocator]"));
        assert!(alloc.contains("hot_path_allocates_nothing"));
        let spec = sample(81);
        for &op in spec.ops.iter() {
            assert!(
                alloc.contains(op.name()),
                "probe missing call to {}",
                op.name()
            );
        }
        // The unchanged baseline allocates by construction; the reference does not.
        assert!(
            unchanged_baseline(spec).contains("HashSet")
                || unchanged_baseline(spec).contains("to_vec(")
        );
        assert!(!reference_src(spec).contains("HashSet"));
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in 0..20u64 {
            let t = PerfRefactorFamily.generate(seed);
            assert!(t.prompt.contains(&t.canary), "seed {seed}");
        }
    }

    #[test]
    fn alloc_probe_counts_two_distinct_inputs_after_the_reset() {
        for seed in 0..20u64 {
            let t = PerfRefactorFamily.generate(seed);
            let probe = &t.hidden[std::path::Path::new("tests/alloc.rs")];
            let reset = probe
                .find("COUNT.store(0")
                .expect("probe must zero the counter after warm-up");
            let ys = probe
                .find("let ys = [11u64")
                .expect("a second, differently-shaped input must be exercised post-reset");
            let xs_call = probe
                .find("(&xs)")
                .expect("the original input must also be counted");
            // Both rounds sit after the reset: a memoizer that paid its
            // allocation during warm-up still has to miss on `ys`.
            assert!(reset < ys, "seed {seed}");
            assert!(reset < xs_call, "seed {seed}");
        }
    }
}

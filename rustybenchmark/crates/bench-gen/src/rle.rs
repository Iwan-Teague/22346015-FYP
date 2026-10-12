//! The `rle` family (category `run-encoding`) — run-length queries over a
//! byte string.
//!
//! Where `matrix` exercises 2-D numeric indexing and `fsm` walks a transition
//! graph, this family exercises **sequential scan structure**: counting and
//! measuring maximal runs of equal consecutive bytes. The domain is one byte
//! slice; every op is a pure function of it. The seed prunes which two of
//! five query ops are required: `num_runs`, `longest_run`, `total_len`,
//! `first_run_len`, `distinct_symbols`. C(5,2) = **10 distinct skills**,
//! above the diversity floor; op names are semantic.
//!
//! The canonical string is sampled until its anchor facts hold: at least two
//! maximal runs and two distinct byte values. That makes every answer
//! positive (defeating `const-zero`) and makes four of the five ops disagree
//! with the whole-string-is-one-run cheat — `total_len` excepted, which that
//! baseline answers exactly, the way `fsm`'s adjacent-only baseline nails
//! `terminals`; partner ops catch any pair containing it.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops and
//! the emitted reference share the same bodies; the differential fuzzes 3000
//! random strings against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on any non-empty
//! input) and `single-run` (treats the whole string as one run of one
//! symbol).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    NumRuns,
    LongestRun,
    TotalLen,
    FirstRunLen,
    DistinctSymbols,
}

const OP_ALL: [Op; 5] = [
    Op::NumRuns,
    Op::LongestRun,
    Op::TotalLen,
    Op::FirstRunLen,
    Op::DistinctSymbols,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::NumRuns => "num_runs",
            Op::LongestRun => "longest_run",
            Op::TotalLen => "total_len",
            Op::FirstRunLen => "first_run_len",
            Op::DistinctSymbols => "distinct_symbols",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::NumRuns => {
                "how many maximal runs of equal consecutive bytes \
                 `bytes` contains; an empty input has zero"
            }
            Op::LongestRun => {
                "the length of the longest maximal run in `bytes`; \
                 an empty input has zero"
            }
            Op::TotalLen => "the total number of bytes in `bytes`",
            Op::FirstRunLen => {
                "the length of the run that starts at index 0 of `bytes`; \
                 an empty input has zero"
            }
            Op::DistinctSymbols => "how many distinct byte values appear in `bytes`",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Spec {
    ops: [Op; 2],
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let i1 = rng.below(5);
    let mut i2 = rng.below(5);
    while i2 == i1 {
        i2 = rng.below(5);
    }
    Spec {
        ops: [OP_ALL[i1 as usize], OP_ALL[i2 as usize]],
    }
}

// ---- native mirror (the answer; identical shape to the emitted code) ------

fn b_num_runs(bytes: &[u8]) -> i64 {
    let mut runs = 0i64;
    let mut prev: Option<u8> = None;
    for &b in bytes {
        if prev != Some(b) {
            runs += 1;
        }
        prev = Some(b);
    }
    runs
}

fn b_longest_run(bytes: &[u8]) -> i64 {
    let mut best = 0i64;
    let mut cur = 0i64;
    let mut prev: Option<u8> = None;
    for &b in bytes {
        if prev == Some(b) {
            cur += 1;
        } else {
            cur = 1;
        }
        best = best.max(cur);
        prev = Some(b);
    }
    best
}

fn b_total_len(bytes: &[u8]) -> i64 {
    bytes.len() as i64
}

fn b_first_run_len(bytes: &[u8]) -> i64 {
    let Some(first) = bytes.first() else {
        return 0;
    };
    let mut len = 1usize;
    while len < bytes.len() && bytes[len] == *first {
        len += 1;
    }
    len as i64
}

fn b_distinct_symbols(bytes: &[u8]) -> i64 {
    let mut seen = [false; 256];
    for &b in bytes {
        seen[b as usize] = true;
    }
    seen.into_iter().filter(|&s| s).count() as i64
}

/// Every op here returns a count, so one result shape suffices.
fn op_eval(op: Op, bytes: &[u8]) -> i64 {
    match op {
        Op::NumRuns => b_num_runs(bytes),
        Op::LongestRun => b_longest_run(bytes),
        Op::TotalLen => b_total_len(bytes),
        Op::FirstRunLen => b_first_run_len(bytes),
        Op::DistinctSymbols => b_distinct_symbols(bytes),
    }
}

// ---- canonical string -------------------------------------------------------

/// The canonical string: seeded bytes over a three-symbol alphabet, retried
/// until the anchor facts hold.
///
/// Guaranteed for every seed: at least two maximal runs and two distinct byte
/// values, so every answer is positive and four of the five ops separate
/// from the single-run cheat (`total_len` agrees there by construction).
fn canonical(seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed ^ 0x524C_45C7);
    for _ in 0..100_000 {
        let len = 6 + rng.below(7);
        let cand: Vec<u8> = (0..len).map(|_| 1 + rng.below(3) as u8).collect();
        if anchors_hold(&cand) {
            return cand;
        }
    }
    unreachable!("canonical string sampling failed to satisfy anchors");
}

fn anchors_hold(bytes: &[u8]) -> bool {
    b_num_runs(bytes) >= 2 && b_distinct_symbols(bytes) >= 2 && b_total_len(bytes) >= 2
}

// ---- worked examples --------------------------------------------------------

type ExampleCase = (Vec<u8>, Vec<(Op, i64)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_00C3);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical string first.
    let can = canonical(seed);
    cases.push((
        can.clone(),
        spec.ops.map(|op| (op, op_eval(op, &can))).to_vec(),
    ));
    // The empty string: pins every zero convention at once.
    cases.push((
        Vec::new(),
        spec.ops.map(|op| (op, op_eval(op, &[]))).to_vec(),
    ));
    // One uniform run: the single-run corner (one run, one symbol).
    let uniform = vec![9u8, 9, 9];
    cases.push((
        uniform.clone(),
        spec.ops.map(|op| (op, op_eval(op, &uniform))).to_vec(),
    ));
    for _ in 0..3 {
        let n = 1 + rng.below(9);
        let bytes: Vec<u8> = (0..n).map(|_| rng.below(4) as u8).collect();
        let outs = spec.ops.map(|op| (op, op_eval(op, &bytes))).to_vec();
        cases.push((bytes, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Plain bracket form for prompt readability.
fn prose_bytes(bytes: &[u8]) -> String {
    let items = bytes
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{items}]")
}

/// Emitted literal that type-checks as `&[u8]` at the call site; the first
/// element carries the `u8` suffix so the rest infer. `&[]` is typed by the
/// function signature at the call site.
fn render_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "&[]".to_string();
    }
    let mut items = format!("{}u8", bytes[0]);
    for b in &bytes[1..] {
        items.push_str(&format!(", {b}"));
    }
    format!("&[{items}]")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let body = match op {
        Op::NumRuns => [
            "let mut runs = 0i64;",
            "let mut prev: Option<u8> = None;",
            "for &b in bytes {",
            "    if prev != Some(b) {",
            "        runs += 1;",
            "    }",
            "    prev = Some(b);",
            "}",
            "runs",
        ]
        .join("\n    "),
        Op::LongestRun => [
            "let mut best = 0i64;",
            "let mut cur = 0i64;",
            "let mut prev: Option<u8> = None;",
            "for &b in bytes {",
            "    if prev == Some(b) {",
            "        cur += 1;",
            "    } else {",
            "        cur = 1;",
            "    }",
            "    best = best.max(cur);",
            "    prev = Some(b);",
            "}",
            "best",
        ]
        .join("\n    "),
        Op::TotalLen => ["bytes.len() as i64"].join("\n    "),
        Op::FirstRunLen => [
            "let Some(first) = bytes.first() else {",
            "    return 0;",
            "};",
            "let mut len = 1usize;",
            "while len < bytes.len() && bytes[len] == *first {",
            "    len += 1;",
            "}",
            "len as i64",
        ]
        .join("\n    "),
        Op::DistinctSymbols => [
            "let mut seen = [false; 256];",
            "for &b in bytes {",
            "    seen[b as usize] = true;",
            "}",
            "seen.into_iter().filter(|&s| s).count() as i64",
        ]
        .join("\n    "),
    };
    format!(
        "pub fn {name}(bytes: &[u8]) -> i64 {{\n    {body}\n}}\n",
        name = name,
        body = body,
    )
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(bytes: &[u8]) -> i64 {{\n    todo!()\n}}\n",
        op.name()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(bytes: &[u8]) -> i64", op.name())
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op in an emitted assertion.
fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (bytes, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {out}", op.name()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  bytes {}  ->  {}\n",
            prose_bytes(&bytes),
            results
        ));
    }
    s
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples_prose(spec, seed)
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    let fns = spec.ops.map(op_stub_src).concat();
    format!(
        "//! Implement the two query functions below.\n\
         //!\n\
         //! Examples:\n\
         {doc}\n\
         {fns}",
        doc = doc,
        fns = fns,
    )
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let mut reqs = String::new();
    for op in spec.ops {
        reqs.push_str(&format!("- `{}`: {}.\n", op.name(), op.prose()));
    }
    format!(
        "Implement the two query functions in `src/lib.rs`. The input is \
         given as `bytes`, a slice of `u8`, viewed as a sequence of maximal \
         runs of equal consecutive bytes. A run is the longest stretch of \
         one byte value at consecutive positions.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         \n\
         Signatures:\n\
         ```rust\n\
         {signatures}\
         ```\n\
         \n\
         Examples:\n\
         {examples}\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        reqs = reqs,
        signatures = spec
            .ops
            .iter()
            .map(|op| format!("{}\n", op_sig_src(*op)))
            .collect::<Vec<_>>()
            .join(""),
        examples = worked_examples_prose(spec, seed),
        canary = canary,
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
    let imports = spec
        .ops
        .iter()
        .map(|op| op.name())
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!("use task::{{{imports}}};\n\n");
    for (i, (bytes, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let bytes = {};\n",
            render_bytes(bytes),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {out});\n",
                // render_bytes already emits `&[...]`, so the binding is a
                // reference — pass it without another `&`.
                call_src(*op, "bytes"),
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the two selected ops, pasted into the test
/// file under `ref_*` names.
fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec)
        .replacen(
            &format!("pub fn {}", spec.ops[0].name()),
            &format!("fn ref_{}", spec.ops[0].name()),
            1,
        )
        .replacen(
            &format!("pub fn {}", spec.ops[1].name()),
            &format!("fn ref_{}", spec.ops[1].name()),
            1,
        );
    let asserts = spec
        .ops
        .iter()
        .map(|op| {
            let call = call_src(*op, "&bytes");
            format!("        assert_eq!({call}, ref_{call});\n")
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "use task::{{{imports}}};\n\
         \n\
         {reference}\
         fn nx(state: &mut u64) -> u64 {{\n\
         \x20   *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20   *state >> 33\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_005C;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = (nx(&mut state) % 8) as usize;\n\
         \x20       let mut bytes = Vec::with_capacity(n);\n\
         \x20       for _ in 0..n {{\n\
         \x20           bytes.push((nx(&mut state) % 4) as u8);\n\
         \x20       }}\n\
         {asserts}\
         \x20   }}\n\
         }}\n",
        imports = spec
            .ops
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>()
            .join(", "),
        reference = reference,
        asserts = asserts,
    )
}

/// Degenerate: everything zero.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            format!(
                "pub fn {}(bytes: &[u8]) -> i64 {{\n    let _ = bytes;\n    0\n}}\n",
                op.name()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: treat the whole string as one run of one symbol.
/// Exact only for `total_len` (the way `fsm`'s adjacent-only baseline nails
/// `terminals`) — the canonical anchors make every other op disagree, and a
/// pair containing `total_len` is caught by its partner.
fn single_run(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let body = match op {
                Op::NumRuns | Op::DistinctSymbols => {
                    "if bytes.is_empty() {\n        0\n    } else {\n        1\n    }".to_string()
                }
                Op::LongestRun | Op::FirstRunLen | Op::TotalLen => "bytes.len() as i64".to_string(),
            };
            format!(
                "pub fn {name}(bytes: &[u8]) -> i64 {{\n    {body}\n}}\n",
                name = op.name(),
                body = body,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct RleFamily;

impl Generator for RleFamily {
    fn id(&self) -> &str {
        "rle"
    }
    fn category(&self) -> &str {
        "run-encoding"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("rle", seed);

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
            id: format!("rle/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure byte bookkeeping — no unsafe anywhere near it.
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // Default oracle weights (docs/04).
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
            ("const-zero".to_string(), const_zero(&spec)),
            ("single-run".to_string(), single_run(&spec)),
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
        let g = RleFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Run counting: maximal stretches of equal bytes.
        assert_eq!(b_num_runs(&[1, 1, 2, 3, 3, 3]), 3);
        assert_eq!(b_num_runs(&[]), 0);
        assert_eq!(b_num_runs(&[7]), 1);
        assert_eq!(b_num_runs(&[1, 2, 1, 2]), 4);
        // Longest run.
        assert_eq!(b_longest_run(&[5, 5, 1, 1, 1]), 3);
        assert_eq!(b_longest_run(&[]), 0);
        assert_eq!(b_longest_run(&[9, 9, 9, 9]), 4);
        assert_eq!(b_longest_run(&[1, 1, 2, 2, 2]), 3);
        // Totals.
        assert_eq!(b_total_len(&[5, 5, 1]), 3);
        assert_eq!(b_total_len(&[]), 0);
        // Leading run.
        assert_eq!(b_first_run_len(&[8, 8, 8, 1]), 3);
        assert_eq!(b_first_run_len(&[]), 0);
        assert_eq!(b_first_run_len(&[1, 1, 2, 2, 2]), 2);
        // Distinct symbols ignores run structure.
        assert_eq!(b_distinct_symbols(&[1, 2, 1, 3]), 3);
        assert_eq!(b_distinct_symbols(&[]), 0);
        assert_eq!(b_distinct_symbols(&[4, 4, 4]), 1);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut sigs = std::collections::HashSet::new();
        for seed in 0..300u64 {
            sigs.insert(sample(seed));
        }
        // C(5,2) = 10 unordered pairs; demand near-full coverage.
        assert!(
            sigs.len() >= 9,
            "expected wide query-pair variety, got {}",
            sigs.len()
        );
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        // Both baselines must fail under EVERY pair. The anchors make the
        // canonical string non-empty with >= 2 runs and >= 2 symbols, so
        // every op answer is positive (const-zero dies everywhere) and four
        // of the five ops disagree with single-run; `total_len` agrees with
        // single-run by construction and is caught by its partner op.
        for seed in 0..200u64 {
            let c = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(b_num_runs(&c) >= 2, "seed {seed}");
            assert!(b_distinct_symbols(&c) >= 2, "seed {seed}");
            assert!(b_total_len(&c) >= 2, "seed {seed}");
            for op in OP_ALL {
                if matches!(op, Op::TotalLen) {
                    continue; // exact for single-run; partner catches it
                }
                let truth = op_eval(op, &c);
                assert!(truth > 0, "const-zero survives {op:?} seed {seed}");
                // single-run answers: one run / one symbol / whole length.
                let cheat = match op {
                    Op::NumRuns | Op::DistinctSymbols => 1,
                    _ => b_total_len(&c),
                };
                assert_ne!(truth, cheat, "single-run survives {op:?} seed {seed}");
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (bytes, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &bytes), out, "seed {seed}");
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let src = reference_src(&spec);
            for op in OP_ALL {
                // Match the `pub fn` line: bare names could substring-collide
                // (`first_run_len` shares `run_len`-shaped fragments).
                let fn_line = format!("pub fn {}", op.name());
                if spec.ops.contains(&op) {
                    assert!(src.contains(&fn_line));
                } else {
                    assert!(!src.contains(&fn_line), "{:?} leaked", op);
                }
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let sk = skeleton_src(&spec, seed);
            assert!(sk.contains("todo!()"), "skeleton must be stubbed");
            // Solution-shaped leak tokens must stay out of the skeleton.
            assert!(!sk.contains("prev"));
            assert!(!sk.contains("[false; 256]"));
            assert!(!sk.contains(".max(cur)"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("prev"));
            assert!(!p.contains("[false; 256]"));
            assert!(!p.contains(".max(cur)"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Regression pin in the spirit of fsm's arity check: every op is
        // unary here, so no call site may carry a comma at all.
        for op in OP_ALL {
            let call = call_src(op, "&bytes");
            assert_eq!(
                call.matches(',').count(),
                op_sig_src(op).matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{}`",
                op_sig_src(op)
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = RleFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

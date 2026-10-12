//! The `pointer-slice` family (category `pointer-boundary`) — slice
//! reconstruction at the raw-pointer boundary.
//!
//! Where `raw-ptr` walks a `*const i64` with per-index derefs and
//! `raw-ptr-mut` stores through a `*mut i64`, this family exercises the
//! third unsafe-core skill: rebuilding a safe view ONCE —
//! [`std::slice::from_raw_parts`] inside a single `unsafe` block — and
//! then working through ordinary safe iterators. The model implements
//! `fn {name}(ptr: *const i64, len: usize) -> i64` reductions: the sum,
//! the peak, the floor, the positive count, and the final element of the
//! reconstructed view. There is no safe way to reach the elements from a
//! bare pointer, so `unsafe` is forced by the signature, not merely
//! permitted — the same signature-forced archetype as its siblings
//! (docs/17).
//!
//! The seed prunes which two of five query ops are required:
//! `total`, `max_value`, `min_value`, `count_positive`, `last_element`.
//! C(5,2) = **10 distinct skills**, above the diversity floor; op names
//! are semantic.
//!
//! The canonical view is sampled until its anchor facts hold: several
//! elements, a strictly-largest FINAL element (so truncating the view
//! changes the peak but never the floor — the drop-last cheat stays
//! exact only on the minimum, which partner ops catch), a nonzero
//! floor, a nonzero total, and at least one positive element that is
//! not all of them.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native
//! ops and the emitted reference share the same bodies; the differential
//! hands each fuzzed buffer's `as_ptr()` / `len` to the model-side call
//! and compares against the reference over 3000 random views. Values
//! are bounded (∈ -9..=9, len 0..9) so no legal input overflows `i64`.
//!
//! **Miri is deferred (roadmap P7)** — same honest gap as the other
//! unsafe-core families, recorded loudly rather than papered over.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical view) and `drop-last` (answers over the first
//! `len.saturating_sub(1)` elements — exact nowhere on the canonical
//! view except the minimum, which partner ops catch).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Total,
    MaxValue,
    MinValue,
    CountPositive,
    LastElement,
}

const OP_ALL: [Op; 5] = [
    Op::Total,
    Op::MaxValue,
    Op::MinValue,
    Op::CountPositive,
    Op::LastElement,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Total => "total",
            Op::MaxValue => "max_value",
            Op::MinValue => "min_value",
            Op::CountPositive => "count_positive",
            Op::LastElement => "last_element",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Total => "the sum of every element in the view",
            Op::MaxValue => "the largest element; an empty view answers zero",
            Op::MinValue => "the smallest element; an empty view answers zero",
            Op::CountPositive => {
                "how many elements are strictly above zero — zero itself \
                 counts for neither side"
            }
            Op::LastElement => "the final element; an empty view answers zero",
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

fn b_total(xs: &[i64]) -> i64 {
    xs.iter().sum()
}

fn b_max_value(xs: &[i64]) -> i64 {
    xs.iter().copied().max().unwrap_or(0)
}

fn b_min_value(xs: &[i64]) -> i64 {
    xs.iter().copied().min().unwrap_or(0)
}

fn b_count_positive(xs: &[i64]) -> i64 {
    xs.iter().filter(|&&x| x > 0).count() as i64
}

fn b_last_element(xs: &[i64]) -> i64 {
    xs.last().copied().unwrap_or(0)
}

type Out = i64;

fn eval(op: Op, xs: &[i64]) -> Out {
    match op {
        Op::Total => b_total(xs),
        Op::MaxValue => b_max_value(xs),
        Op::MinValue => b_min_value(xs),
        Op::CountPositive => b_count_positive(xs),
        Op::LastElement => b_last_element(xs),
    }
}

// ---- canonical view -------------------------------------------------------

const CANONICAL_SEED: u64 = 0x5A1C_EB11;

/// The canonical view: sampled from the full table and retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: at least four elements, a FINAL element
/// strictly greater than every earlier one (so truncating changes the
/// peak but never the floor — drop-last stays exact only on the
/// minimum), a nonzero floor, a nonzero total, and a positive count
/// that is neither empty nor everything.
fn canonical(seed: u64) -> Vec<i64> {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = 4 + rng.below(5) as usize;
        let mut vals = Vec::new();
        for _ in 0..n {
            vals.push((rng.below(19) as i64) - 9);
        }
        if anchors_hold(&vals) {
            return vals;
        }
    }
    unreachable!("canonical view sampling failed to satisfy anchors");
}

fn anchors_hold(vals: &[i64]) -> bool {
    let last = *vals.last().unwrap();
    let head = &vals[..vals.len() - 1];
    let cp = b_count_positive(vals);
    // The final element must be the STRICT maximum so drop-last misses
    // the peak; the floor and total stay clear of zero; positives are
    // present but not universal.
    vals.len() >= 4
        && head.iter().all(|&x| x < last)
        && b_min_value(vals) != 0
        && b_total(vals) != 0
        && (1..vals.len() as i64).contains(&cp)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (Vec<i64>, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0178;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical view first.
    let can = canonical(seed);
    cases.push((
        can.clone(),
        spec.ops.map(|op| (op, eval(op, &can))).to_vec(),
    ));
    // Empty view: the zero conventions.
    cases.push((Vec::new(), spec.ops.map(|op| (op, eval(op, &[]))).to_vec()));
    // A lone positive.
    cases.push((vec![5], spec.ops.map(|op| (op, eval(op, &[5]))).to_vec()));
    // All negative — the peak is still nonzero.
    let neg = vec![-9, -3, -1];
    cases.push((
        neg.clone(),
        spec.ops.map(|op| (op, eval(op, &neg))).to_vec(),
    ));
    for _ in 0..3 {
        let n = rng.below(10) as usize;
        let mut vals = Vec::new();
        for _ in 0..n {
            vals.push((rng.below(19) as i64) - 9);
        }
        let outs = spec.ops.map(|op| (op, eval(op, &vals))).to_vec();
        cases.push((vals, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site.
fn render_vec(vals: &[i64]) -> String {
    format!("vec!{vals:?}")
}

const BOUNDARY_SRC: &str = "let xs = unsafe { std::slice::from_raw_parts(ptr, len) };";

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let body_tail = match op {
        Op::Total => "xs.iter().sum()",
        Op::MaxValue => "xs.iter().copied().max().unwrap_or(0)",
        Op::MinValue => "xs.iter().copied().min().unwrap_or(0)",
        Op::CountPositive => "xs.iter().filter(|&&x| x > 0).count() as i64",
        Op::LastElement => "xs.last().copied().unwrap_or(0)",
    };
    format!(
        "pub fn {name}(ptr: *const i64, len: usize) -> i64 {{\n    {boundary}\n    {tail}\n}}\n",
        name = name,
        boundary = BOUNDARY_SRC,
        tail = body_tail,
    )
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(ptr: *const i64, len: usize) -> i64", op.name())
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op in an emitted assertion.
fn call_src(op: Op, var: &str) -> String {
    format!("{}({}.as_ptr(), {}.len())", op.name(), var, var)
}
fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (vals, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  view {}  ->  {}\n", render_vec(&vals), results));
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
        "Implement the two query functions in `src/lib.rs`.\n\
         \n\
         `ptr` points to the first of `len` consecutive `i64` values (a raw \
         read-only buffer). Reconstruct a slice view once with \
         `std::slice::from_raw_parts` inside a single `unsafe` block, then \
         answer through safe iterators. The caller guarantees `ptr` is valid \
         for `len` elements, so reading indices `0..len` is sound.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - `len` may be 0; the empty-view conventions are zero for every \
         scalar answer.\n\
         - Read only indices in `0..len`; reading out of bounds is undefined \
         behaviour.\n\
         - Do not allocate; the hot path must stay allocation-free.\n\
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
    for (i, (vals, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let v: Vec<i64> = {};\n",
            render_vec(vals),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {out});\n",
                call_src(*op, "v"),
                out = out,
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
            let call = call_src(*op, "vals");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0178;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = (nx(&mut state) % 10) as usize;\n\
         \x20       let mut vals: Vec<i64> = Vec::new();\n\
         \x20       for _ in 0..n {{\n\
         \x20           vals.push(((nx(&mut state) % 19) as i64) - 9);\n\
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
/// Degenerate: zero answers everywhere.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            format!(
                "{} {{\n    let _ = (ptr, len);\n    0\n}}\n",
                op_sig_src(*op)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer over a truncated view. On the canonical
/// view the final element is the strict maximum, so this misses the sum
/// (the tail is nonzero), the peak, the positive count, and the final
/// element — staying exact only on the minimum, which partner ops catch.
fn drop_last(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let boundary =
                "let xs = unsafe { std::slice::from_raw_parts(ptr, len.saturating_sub(1)) };";
            let tail = match op {
                Op::Total => "xs.iter().sum()",
                Op::MaxValue => "xs.iter().copied().max().unwrap_or(0)",
                Op::MinValue => "xs.iter().copied().min().unwrap_or(0)",
                Op::CountPositive => "xs.iter().filter(|&&x| x > 0).count() as i64",
                Op::LastElement => "xs.last().copied().unwrap_or(0)",
            };
            format!("{} {{\n    {boundary}\n    {tail}\n}}\n", op_sig_src(*op),)
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct PointerSliceFamily;

impl Generator for PointerSliceFamily {
    fn id(&self) -> &str {
        "pointer-slice"
    }
    fn category(&self) -> &str {
        "pointer-boundary"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("pointer-slice", seed);

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
            id: format!("pointer-slice/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // unsafe is REQUIRED here (the signature forces it), so it is not
            // forbidden by policy — same stance as raw-ptr / raw-ptr-mut.
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // docs/04 unsafe-core weights (behaviour-dominant).
            weights: (0.70, 0.30, 0.0),
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
            ("drop-last".to_string(), drop_last(&spec)),
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
        let g = PointerSliceFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Totals: signs cancel, order-blind.
        assert_eq!(b_total(&[3, -1, 4]), 6);
        assert_eq!(b_total(&[]), 0);
        // Peaks and floors with sign guards.
        assert_eq!(b_max_value(&[3, -1, 4]), 4);
        assert_eq!(b_max_value(&[-9, -3]), -3);
        assert_eq!(b_max_value(&[]), 0);
        assert_eq!(b_min_value(&[9, 3]), 3);
        assert_eq!(b_min_value(&[-7]), -7);
        assert_eq!(b_min_value(&[]), 0);
        // Zero is neither positive nor negative.
        assert_eq!(b_count_positive(&[0, 0, 5]), 1);
        assert_eq!(b_count_positive(&[-1, -2]), 0);
        // The tail, not the head.
        assert_eq!(b_last_element(&[8, 2]), 2);
        assert_eq!(b_last_element(&[]), 0);
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
        // The canonical view ends on its strict maximum: const-zero dies
        // on all five scalars outright; drop-last misses the sum (the
        // tail is nonzero), the peak (strict max truncates away), the
        // positive count (the tail is positive but not all of them) and
        // the final element — staying exact only on the minimum, which
        // every partner op catches.
        for seed in 0..200u64 {
            let vals = canonical(seed);
            let t = b_total(&vals);
            let mx = b_max_value(&vals);
            let mn = b_min_value(&vals);
            let cp = b_count_positive(&vals);
            let le = b_last_element(&vals);
            let head = &vals[..vals.len() - 1];
            // Anchor facts the sampler enforces.
            assert!(vals.len() >= 4, "seed {seed}: must be multi-element");
            assert!(
                head.iter().all(|&x| x < le),
                "seed {seed}: tail must be the strict maximum"
            );
            assert_ne!(mn, 0, "seed {seed}");
            assert_ne!(t, 0, "const-zero survives at seed {seed}");
            assert!((1..vals.len() as i64).contains(&cp), "seed {seed}");
            // drop-last survives nowhere but the minimum itself.
            assert_ne!(b_total(head), t, "drop-last survives total at seed {seed}");
            assert_ne!(
                b_max_value(head),
                mx,
                "drop-last survives max at seed {seed}"
            );
            assert_ne!(
                b_count_positive(head),
                cp,
                "drop-last survives count at seed {seed}"
            );
            assert_ne!(
                b_last_element(head),
                le,
                "drop-last survives last at seed {seed}"
            );
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (vals, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(eval(op, &vals), out, "seed {seed}");
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
                // Match the `pub fn` line plus the paren so no bare-name
                // substring leaks.
                let fn_line = format!("pub fn {}(", op.name());
                if spec.ops.contains(&op) {
                    assert!(src.contains(&fn_line));
                } else {
                    assert!(!src.contains(&fn_line), "{op:?} leaked");
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
            // Allocation-shaped leak tokens must stay out of the skeleton;
            // the boundary call itself is taught by the prompt, so it is
            // not a leak — only allocation shapes are.
            assert!(!sk.contains("to_string("));
            assert!(!sk.contains("format!("));
            assert!(!sk.contains(".collect("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("to_string("));
            assert!(!p.contains("format!("));
            assert!(!p.contains(".collect("));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op takes the pointer pair: exactly one comma on both sides.
        for op in OP_ALL {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call = call_src(op, "v");
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = PointerSliceFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

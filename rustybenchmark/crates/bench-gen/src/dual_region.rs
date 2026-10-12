//! The `dual-region` family (category `borrow-lifetimes`).
//!
//! A second `borrow-lifetimes` family, deliberately a *different* borrow shape from
//! `window-op`'s single-pass window mutation: this is a **`split_at_mut`-shaped**
//! problem (docs/04 names it explicitly). The model implements
//! `fn f(v: &mut [i64]) -> usize`, which splits `v` at its midpoint into two
//! disjoint halves and, for each of the `len / 2` pairs, applies a seed-selected
//! pairwise operation **in place** — the canonical case for `split_at_mut`, since
//! the operation needs a `&mut` into both halves at once.
//!
//! Seed-selected on two axes:
//!
//! 1. **Op** — how a pair `(x, y)` is rewritten: Swap / SumDiff / SortPair /
//!    AddBoth / DiffBoth / MaxBoth.
//! 2. **Pairing** — which second-half element pairs with the i-th first-half one:
//!    Aligned (`b[i]`) or Mirror (`b[len-1-i]`).
//!
//! The structural surface is 6 × 2 = **12 distinct skills** (as `window-op`). Like
//! `window-op` it is constraint-dominant (weights behavior 0.35 / constraint 0.55,
//! docs/04): a clone-everything answer is behaviourally correct but allocates, and
//! the allocation instrumentation (an `alloc.rs` counting `#[global_allocator]`)
//! catches it. Solution-first and correct-by-construction (ADR-0003): native `eval`
//! and the emitted reference are mirrored, and the differential fuzzes 3000 random
//! slices comparing both the mutated array and the returned count. Values are
//! bounded (∈ -50..=49, len 0..20) so `SumDiff`/`DiffBoth` cannot overflow `i64`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — how a pair `(x, y)` is rewritten.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Op {
    Swap,
    SumDiff,
    SortPair,
    AddBoth,
    DiffBoth,
    MaxBoth,
}

/// Axis 2 — which second-half element pairs with the i-th first-half element.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Pairing {
    Aligned,
    Mirror,
}

struct Spec {
    op: Op,
    pairing: Pairing,
    fn_name: &'static str,
}

const NAMES: &[&str] = &[
    "f",
    "fold_halves",
    "combine_halves",
    "mix_regions",
    "pair_up",
    "rework_pairs",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let op = match rng.below(6) {
        0 => Op::Swap,
        1 => Op::SumDiff,
        2 => Op::SortPair,
        3 => Op::AddBoth,
        4 => Op::DiffBoth,
        _ => Op::MaxBoth,
    };
    let pairing = if rng.below(2) == 0 {
        Pairing::Aligned
    } else {
        Pairing::Mirror
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        op,
        pairing,
        fn_name,
    }
}

// ---- native reference (mirrors the emitted source exactly) ----------------

fn op_apply(op: Op, x: i64, y: i64) -> (i64, i64) {
    match op {
        Op::Swap => (y, x),
        Op::SumDiff => (x + y, x - y),
        Op::SortPair => (x.min(y), x.max(y)),
        Op::AddBoth => (x + y, x + y),
        Op::DiffBoth => (x - y, y - x),
        Op::MaxBoth => (x.max(y), x.max(y)),
    }
}

/// The answer: split `v` at the midpoint, pair each first-half element with a
/// second-half element per the pairing, rewrite both in place with `op`, and
/// return the number of pairs transformed (`len / 2`). Source of truth for the
/// emitted reference.
fn apply(spec: &Spec, v: &mut [i64]) -> usize {
    let mid = v.len() / 2;
    let (a, b) = v.split_at_mut(mid);
    let k = a.len();
    let blen = b.len();
    // The emitted reference writes the equivalent `for i in 0..k` index loop; here
    // `enumerate` keeps clippy happy while `b[j]` is still indexed for the pairing.
    for (i, ai) in a.iter_mut().enumerate() {
        let j = match spec.pairing {
            Pairing::Aligned => i,
            Pairing::Mirror => blen - 1 - i,
        };
        let (x, y) = (*ai, b[j]);
        let (nx, ny) = op_apply(spec.op, x, y);
        *ai = nx;
        b[j] = ny;
    }
    k
}

// ---- emitted-source fragments (mirror the native functions above) ---------

fn j_expr(pairing: Pairing) -> &'static str {
    match pairing {
        Pairing::Aligned => "i",
        Pairing::Mirror => "b.len() - 1 - i",
    }
}

/// The pair-rewrite as two assignment statements over `x`, `y` (both read first).
fn op_assign(op: Op) -> &'static str {
    match op {
        Op::Swap => "a[i] = y;\n            b[j] = x;",
        Op::SumDiff => "a[i] = x + y;\n            b[j] = x - y;",
        Op::SortPair => "a[i] = x.min(y);\n            b[j] = x.max(y);",
        Op::AddBoth => "a[i] = x + y;\n            b[j] = x + y;",
        Op::DiffBoth => "a[i] = x - y;\n            b[j] = y - x;",
        Op::MaxBoth => "a[i] = x.max(y);\n            b[j] = x.max(y);",
    }
}

fn op_prose(op: Op) -> &'static str {
    match op {
        Op::Swap => "swap the two paired elements",
        Op::SumDiff => "replace the pair `(x, y)` with `(x + y, x - y)`",
        Op::SortPair => "replace the pair `(x, y)` with `(min(x, y), max(x, y))` (smaller first)",
        Op::AddBoth => "replace both paired elements with their sum `x + y`",
        Op::DiffBoth => "replace the pair `(x, y)` with `(x - y, y - x)`",
        Op::MaxBoth => "replace both paired elements with their maximum `max(x, y)`",
    }
}

fn pairing_prose(pairing: Pairing) -> &'static str {
    match pairing {
        Pairing::Aligned => {
            "Pair the i-th element of the first half with the i-th element of the second half."
        }
        Pairing::Mirror => {
            "Pair the i-th element of the first half with the i-th element of the second half \
             counting from *its end* — i.e. `first[i]` with `second[second.len() - 1 - i]` (a \
             mirror pairing)."
        }
    }
}

fn reference_src(spec: &Spec) -> String {
    format!(
        "pub fn {name}(v: &mut [i64]) -> usize {{\n\
         \x20   let mid = v.len() / 2;\n\
         \x20   let (a, b) = v.split_at_mut(mid);\n\
         \x20   let k = a.len();\n\
         \x20   for i in 0..k {{\n\
         \x20       let j = {j};\n\
         \x20       let (x, y) = (a[i], b[j]);\n\
         \x20       {assign}\n\
         \x20   }}\n\
         \x20   k\n\
         }}\n",
        name = spec.fn_name,
        j = j_expr(spec.pairing),
        assign = op_assign(spec.op),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "//! Implement `{name}` below.\n\
         //!\n\
         {doc}\n\
         pub fn {name}(v: &mut [i64]) -> usize {{\n\
         \x20   todo!()\n\
         }}\n",
        name = spec.fn_name,
        doc = examples
            .lines()
            .map(|l| format!("//! {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// One worked example: (input, expected output, expected count).
type ExampleCase = (Vec<i64>, Vec<i64>, usize);

/// Worked examples, computed natively so each is correct by construction. The first
/// case is the **canonical** one — the fixed input `[6, 4, 3, 1]`, whose two halves
/// are `[6, 4]` and `[3, 1]`: every first-half element exceeds every second-half
/// one, so under either pairing each pair has `x > y > `-related properties that
/// make *all* six ops change it, and the count (`2`) is non-zero. That is what
/// makes both trivial baselines (`const-zero`, `identity`) fail on every seed. The
/// rest are seed-varied random inputs (the family's biggest per-instance textual
/// lever, docs/02 Q30).
fn worked_examples(spec: &Spec, seed: u64) -> (String, Vec<ExampleCase>) {
    let mut rng = Rng::new(seed ^ 0xD0A1_0000_0000_0007);
    let mut inputs: Vec<Vec<i64>> = vec![vec![6, 4, 3, 1]];
    for _ in 0..3 {
        let len = 3 + rng.below(8) as usize; // 3..=10 (odd lengths exercise the untouched middle)
        let input: Vec<i64> = (0..len)
            .map(|_| {
                let mag = 1 + rng.below(9) as i64; // 1..=9, never zero
                if rng.below(2) == 0 {
                    mag
                } else {
                    -mag
                }
            })
            .collect();
        inputs.push(input);
    }

    let mut cases = Vec::new();
    let mut prose = String::new();
    for input in &inputs {
        let mut out = input.clone();
        let count = apply(spec, &mut out);
        prose.push_str(&format!("  {input:?}  ->  {out:?}, returns {count}\n"));
        cases.push((input.clone(), out, count));
    }
    (prose, cases)
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "Implement the function `{name}` in `src/lib.rs`.\n\
         \n\
         Split `v` at its midpoint `mid = v.len() / 2` into a first half (length \
         `mid`) and a second half (the remaining elements). {pairing_prose} There \
         are `mid` such pairs. For each pair `(x, y)`, {op_prose}, writing both \
         results back in place. When the length is odd, the extra middle element of \
         the second half is left untouched. Return the number of pairs transformed \
         (which is `mid`).\n\
         \n\
         Constraints:\n\
         - Operate in place: do not allocate a second copy of the data.\n\
         - A slice of length 0 or 1 has no pairs; return 0 and leave it unchanged.\n\
         - Do not use `unsafe`.\n\
         \n\
         Signature:\n\
         ```rust\n\
         pub fn {name}(v: &mut [i64]) -> usize\n\
         ```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        pairing_prose = pairing_prose(spec.pairing),
        op_prose = op_prose(spec.op),
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
    let (_, cases) = worked_examples(spec, seed);
    let mut body = format!("use task::{};\n\n", spec.fn_name);
    for (i, (input, out, count)) in cases.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let mut v: Vec<i64> = vec!{input:?};\n\
             \x20   assert_eq!({name}(&mut v), {count});\n\
             \x20   assert_eq!(v, vec!{out:?});\n\
             }}\n\n",
            name = spec.fn_name,
        ));
    }
    body.push_str(&format!(
        "#[test]\nfn too_short_is_noop() {{\n\
         \x20   let mut v = vec![7i64];\n\
         \x20   assert_eq!({name}(&mut v), 0);\n\
         \x20   assert_eq!(v, vec![7]);\n\
         \x20   let mut e: Vec<i64> = Vec::new();\n\
         \x20   assert_eq!({name}(&mut e), 0);\n\
         }}\n",
        name = spec.fn_name,
    ));
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference =
        reference_src(spec).replacen(&format!("pub fn {}", spec.fn_name), "fn reference", 1);
    format!(
        "use task::{name};\n\
         \n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xD0A1_ED00_0000_0042;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 20) as usize;\n\
         \x20       let mut a: Vec<i64> = (0..len).map(|_| (next() % 100) as i64 - 50).collect();\n\
         \x20       let mut b = a.clone();\n\
         \x20       let ra = {name}(&mut a);\n\
         \x20       let rb = reference(&mut b);\n\
         \x20       assert_eq!(rb, ra, \"count mismatch: len={{len}}\");\n\
         \x20       assert_eq!(b, a, \"array mismatch: len={{len}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = reference,
    )
}

fn alloc_test_src(spec: &Spec) -> String {
    format!(
        "use task::{name};\n\
         use std::alloc::{{GlobalAlloc, Layout, System}};\n\
         use std::sync::atomic::{{AtomicUsize, Ordering}};\n\
         \n\
         static ALLOCS: AtomicUsize = AtomicUsize::new(0);\n\
         struct Counting;\n\
         unsafe impl GlobalAlloc for Counting {{\n\
         \x20   unsafe fn alloc(&self, l: Layout) -> *mut u8 {{ ALLOCS.fetch_add(1, Ordering::SeqCst); System.alloc(l) }}\n\
         \x20   unsafe fn dealloc(&self, p: *mut u8, l: Layout) {{ System.dealloc(p, l) }}\n\
         }}\n\
         #[global_allocator]\n\
         static GLOBAL: Counting = Counting;\n\
         \n\
         #[test]\n\
         fn hot_path_does_not_allocate() {{\n\
         \x20   let mut v: Vec<i64> = (0..256).collect();\n\
         \x20   let before = ALLOCS.load(Ordering::SeqCst);\n\
         \x20   let n = {name}(&mut v);\n\
         \x20   let after = ALLOCS.load(Ordering::SeqCst);\n\
         \x20   assert!(n > 0);\n\
         \x20   assert_eq!(after - before, 0, \"allocated {{}} time(s)\", after - before);\n\
         }}\n",
        name = spec.fn_name,
    )
}

/// Degenerate: returns 0 and transforms nothing. Fails the canonical example (whose
/// count is non-zero and whose array changes). UB-free.
fn const_zero(spec: &Spec) -> String {
    format!(
        "pub fn {name}(v: &mut [i64]) -> usize {{ let _ = &mut v[..]; 0 }}\n",
        name = spec.fn_name,
    )
}

/// Degenerate: returns the correct count (`len / 2`) but transforms nothing. Fails
/// the canonical example, whose array is changed by every op — the "counts but does
/// no work" baseline.
fn identity(spec: &Spec) -> String {
    format!(
        "pub fn {name}(v: &mut [i64]) -> usize {{ v.len() / 2 }}\n",
        name = spec.fn_name,
    )
}

pub struct DualRegionFamily;

impl Generator for DualRegionFamily {
    fn id(&self) -> &str {
        "dual-region"
    }
    fn category(&self) -> &str {
        "borrow-lifetimes"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("dual-region", seed);

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
        hidden.insert(
            PathBuf::from("tests/alloc.rs"),
            crate::thread_local_counter(alloc_test_src(&spec)),
        );

        GeneratedTask {
            id: format!("dual-region/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: "alloc".to_string(),
            max_unsafe: Some(0),
            check_clippy: false,
            clippy_allow: Vec::new(),
            forbidden_paths: Vec::new(),
            // borrow-lifetimes is constraint-dominant (docs/04): cloning is
            // behaviourally correct, so the allocation constraint carries the signal.
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
            ("const-zero".to_string(), const_zero(&spec)),
            ("identity".to_string(), identity(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is the (op, pairing) pair. The function name is cosmetic; there
        // are no numeric constants — all excluded (Q31).
        let spec = sample(seed);
        let op = match spec.op {
            Op::Swap => "swap",
            Op::SumDiff => "sum_diff",
            Op::SortPair => "sort_pair",
            Op::AddBoth => "add_both",
            Op::DiffBoth => "diff_both",
            Op::MaxBoth => "max_both",
        };
        let pairing = match spec.pairing {
            Pairing::Aligned => "aligned",
            Pairing::Mirror => "mirror",
        };
        vec![format!("op:{op}"), format!("pairing:{pairing}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(op: Op, pairing: Pairing, mut v: Vec<i64>) -> (Vec<i64>, usize) {
        let spec = Spec {
            op,
            pairing,
            fn_name: "f",
        };
        let n = apply(&spec, &mut v);
        (v, n)
    }

    #[test]
    fn generation_is_deterministic() {
        let g = DualRegionFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        // Swap + Aligned on [6,4,3,1]: halves [6,4]/[3,1], pairs (6,3),(4,1) swapped.
        assert_eq!(
            run(Op::Swap, Pairing::Aligned, vec![6, 4, 3, 1]),
            (vec![3, 1, 6, 4], 2)
        );
        // SumDiff + Aligned: (6,3)->(9,3), (4,1)->(5,3).
        assert_eq!(
            run(Op::SumDiff, Pairing::Aligned, vec![6, 4, 3, 1]),
            (vec![9, 5, 3, 3], 2)
        );
        // Mirror pairs first[i] with second[len-1-i]: (6,1),(4,3) for [6,4,3,1].
        assert_eq!(
            run(Op::Swap, Pairing::Mirror, vec![6, 4, 3, 1]),
            (vec![1, 3, 4, 6], 2)
        );
        // Odd length: the middle element of the second half is untouched.
        // [5,1,2] -> mid=1, halves [5]/[1,2]; Aligned pairs (5,1); 2 untouched.
        assert_eq!(
            run(Op::Swap, Pairing::Aligned, vec![5, 1, 2]),
            (vec![1, 5, 2], 1)
        );
        // Too short: no pairs.
        assert_eq!(run(Op::Swap, Pairing::Aligned, vec![9]), (vec![9], 0));
        assert_eq!(run(Op::Swap, Pairing::Aligned, vec![]), (vec![], 0));
    }

    #[test]
    fn seeds_vary_op_and_pairing() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.op, s.pairing));
        }
        assert!(
            variants.len() >= 10,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_changes_and_counts_under_every_combo() {
        // Both trivial baselines are caught on every seed only if the canonical input
        // [6,4,3,1] is changed (identity) and has a non-zero count (const-zero) under
        // every (op, pairing) combination.
        let canonical = vec![6i64, 4, 3, 1];
        for &op in &[
            Op::Swap,
            Op::SumDiff,
            Op::SortPair,
            Op::AddBoth,
            Op::DiffBoth,
            Op::MaxBoth,
        ] {
            for &pairing in &[Pairing::Aligned, Pairing::Mirror] {
                let (out, count) = run(op, pairing, canonical.clone());
                assert!(count > 0, "zero count under {op:?}/{pairing:?}");
                assert_ne!(out, canonical, "unchanged under {op:?}/{pairing:?}");
            }
        }
    }

    #[test]
    fn reference_matches_native_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            let (_, cases) = worked_examples(&spec, seed);
            for (input, out, count) in cases {
                let mut v = input.clone();
                let c = apply(&spec, &mut v);
                assert_eq!((v, c), (out, count), "seed {seed}");
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = DualRegionFamily;
        let t = g.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

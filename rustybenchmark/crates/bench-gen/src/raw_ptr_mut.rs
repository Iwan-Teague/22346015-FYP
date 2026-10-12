//! The `raw-ptr-mut` family (category `unsafe-core`) — the *writes* sibling of
//! `raw-ptr`.
//!
//! Where `raw-ptr` forces `unsafe` **reads** through a `*const i64`, this family
//! forces `unsafe` **writes**: the model implements
//! `fn f(ptr: *mut i64, len: usize) -> usize`, mutating selected elements *in
//! place* through pointer arithmetic and returning how many elements it wrote.
//! There is no safe way to write through a `*mut i64` obtained as a bare
//! pointer, so `unsafe` is forced by the signature, not merely permitted — the
//! same signature-forced archetype as `raw-ptr` (docs/17), exercising the other
//! half of the raw-pointer skill (storing, not loading).
//!
//! Seed-selected on two axes:
//!
//! 1. **Target** — which positions are written: All / EvenIdx / OddIdx / FirstHalf
//!    (each a different `(start, stride, bound)` walk, so the patterns are
//!    behaviourally distinct subsets, not orders).
//! 2. **Transform** — what value is written over the old one: Double / Negate /
//!    Square / Increment.
//!
//! The structural surface is 4 × 4 = **16 distinct skills**. Solution-first and
//! correct-by-construction (ADR-0003): the native `eval` (slice-based), the
//! emitted unsafe reference (writes through the pointer), and the differential's
//! safe reference are three mirrors of the same index-walk; the differential
//! clones each fuzzed slice, hands `got.as_mut_ptr()` / `got.len()` to the model,
//! and compares **both** the returned count and the whole mutated array against
//! the slice-based reference over 3000 random inputs. Values are bounded
//! (∈ -9..=9, len 0..12) so no legal input overflows `i64`.
//!
//! **Miri is deferred (roadmap P7)** — same honest gap as `raw-ptr`, recorded
//! loudly rather than papered over: docs/04 makes miri mandatory for
//! `unsafe-core` because behaviour testing catches wrong answers and gross
//! out-of-bounds but not subtle unsoundness that still produces the right bytes
//! on the fuzzed inputs. Until the miri layer lands this family grades on
//! behaviour + the differential only; it is correct-by-construction and passes
//! every construction gate today.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — which positions are written, expressed as (start, stride, bound).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Target {
    All,
    EvenIdx,
    OddIdx,
    FirstHalf,
}

/// Axis 2 — what value is written over each targeted element.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Transform {
    Double,
    Negate,
    Square,
    Increment,
}

struct Spec {
    target: Target,
    transform: Transform,
    fn_name: &'static str,
}

const NAMES: &[&str] = &["f", "mutate_raw", "rewrite_at", "patch", "walk_mut"];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let target = match rng.below(4) {
        0 => Target::All,
        1 => Target::EvenIdx,
        2 => Target::OddIdx,
        _ => Target::FirstHalf,
    };
    let transform = match rng.below(4) {
        0 => Transform::Double,
        1 => Transform::Negate,
        2 => Transform::Square,
        _ => Transform::Increment,
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        target,
        transform,
        fn_name,
    }
}

// ---- native reference (mirrors both emitted sources exactly) ---------------

fn start(target: Target) -> usize {
    match target {
        Target::OddIdx => 1,
        _ => 0,
    }
}

fn stride(target: Target) -> usize {
    match target {
        Target::EvenIdx | Target::OddIdx => 2,
        _ => 1,
    }
}

fn bound(target: Target, len: usize) -> usize {
    match target {
        Target::FirstHalf => len / 2,
        _ => len,
    }
}

/// The written value as a function of the old one. Source of truth for the
/// emitted expressions.
fn apply(transform: Transform, x: i64) -> i64 {
    match transform {
        Transform::Double => x * 2,
        Transform::Negate => -x,
        Transform::Square => x * x,
        Transform::Increment => x + 1,
    }
}

/// The answer: overwrite each selected element in place; return the count of
/// elements written. Slice-based source of truth for both emitted renderings.
fn eval(spec: &Spec, xs: &mut [i64]) -> usize {
    let mut n = 0usize;
    let mut i = start(spec.target);
    let b = bound(spec.target, xs.len());
    while i < b {
        xs[i] = apply(spec.transform, xs[i]);
        n += 1;
        i += stride(spec.target);
    }
    n
}

// ---- emitted-source fragments (mirror the native functions above) ----------

fn bound_expr(target: Target, len_var: &str) -> String {
    match target {
        Target::FirstHalf => format!("{len_var} / 2"),
        _ => len_var.to_string(),
    }
}

/// The store expression: the new value in terms of the old value at `slot`.
fn store_expr(transform: Transform, slot: &str) -> String {
    match transform {
        Transform::Double => format!("{slot} * 2"),
        Transform::Negate => format!("-{slot}"),
        Transform::Square => format!("{slot} * {slot}"),
        Transform::Increment => format!("{slot} + 1"),
    }
}

fn target_prose(target: Target) -> &'static str {
    match target {
        Target::All => "every element, from index 0 to `len - 1`",
        Target::EvenIdx => "the even indices 0, 2, 4, … that are below `len`",
        Target::OddIdx => "the odd indices 1, 3, 5, … that are below `len`",
        Target::FirstHalf => "the first half of the elements, indices 0 to `len / 2 - 1`",
    }
}

fn transform_prose(transform: Transform) -> &'static str {
    match transform {
        Transform::Double => "twice its old value",
        Transform::Negate => "the negation of its old value",
        Transform::Square => "the square of its old value",
        Transform::Increment => "its old value plus one",
    }
}

/// The correct unsafe reference — stores through the pointer.
fn reference_src(spec: &Spec) -> String {
    let slot = "*ptr.add(i)";
    format!(
        "pub fn {name}(ptr: *mut i64, len: usize) -> usize {{\n\
         \x20   let mut n: usize = 0;\n\
         \x20   let mut i: usize = {start};\n\
         \x20   while i < {bound} {{\n\
         \x20       unsafe {{ *ptr.add(i) = {store}; }}\n\
         \x20       n += 1;\n\
         \x20       i += {stride};\n\
         \x20   }}\n\
         \x20   n\n\
         }}\n",
        name = spec.fn_name,
        start = start(spec.target),
        bound = bound_expr(spec.target, "len"),
        store = store_expr(spec.transform, slot),
        stride = stride(spec.target),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "//! Implement `{name}` below. You must mutate the elements through the raw\n\
         //! pointer — there is no safe way to write through a `*mut i64`.\n\
         //!\n\
         {doc}\n\
         pub fn {name}(ptr: *mut i64, len: usize) -> usize {{\n\
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

/// One worked example: (input slice, expected mutated slice, expected count).
type ExampleCase = (Vec<i64>, Vec<i64>, usize);

/// Worked examples, computed natively so each is correct by construction. The
/// first case is the **canonical** one — the fixed input `[3, 1, 4, 2]`, chosen
/// so every target selects at least two elements and every position of the
/// expected output is non-zero (each transform of a non-zero input stays
/// non-zero, and untouched positions keep their non-zero values). That is what
/// makes both trivial baselines fail on every seed. The rest are seed-varied
/// random inputs (docs/02 Q30).
fn worked_examples(spec: &Spec, seed: u64) -> (String, Vec<ExampleCase>) {
    let mut rng = Rng::new(seed ^ 0x00F0_0000_0000_006D);
    let mut inputs: Vec<Vec<i64>> = vec![vec![3, 1, 4, 2]];
    for _ in 0..3 {
        let len = 2 + rng.below(7) as usize; // 2..=8
        let input: Vec<i64> = (0..len)
            .map(|_| {
                let v = rng.below(19) as i64 - 9;
                if v == 0 {
                    7 // keep every worked-example element non-zero
                } else {
                    v
                }
            })
            .collect();
        inputs.push(input);
    }

    let mut cases = Vec::new();
    let mut prose = String::new();
    for input in &inputs {
        let mut out = input.clone();
        let n = eval(spec, &mut out);
        prose.push_str(&format!(
            "  {input:?}  ->  {out:?}  (wrote {n} element{})\n",
            if n == 1 { "" } else { "s" }
        ));
        cases.push((input.clone(), out, n));
    }
    (prose, cases)
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "Implement the function `{name}` in `src/lib.rs`.\n\
         \n\
         `ptr` points to the first of `len` consecutive `i64` values (a raw mutable \
         buffer). Mutate the buffer **in place**: write {target_prose} through the \
         pointer, replacing each such element with {transform_prose}. Elements you do \
         not target must be left exactly as they are. Return the number of elements \
         you wrote.\n\
         \n\
         There is no safe way to write through a `*mut i64`, so you must use an \
         `unsafe` block with pointer arithmetic (`*ptr.add(i) = …`). The caller \
         guarantees `ptr` is valid for `len` elements, so writing indices `0..len` \
         is sound.\n\
         \n\
         Constraints:\n\
         - `len` may be 0; the result is then `0`.\n\
         - Write only indices in `0..len`; writing out of bounds is undefined \
         behaviour.\n\
         - Do not allocate; mutate the caller's buffer.\n\
         \n\
         Signature:\n\
         ```rust\n\
         pub fn {name}(ptr: *mut i64, len: usize) -> usize\n\
         ```\n\
         \n\
         Examples (`{name}(v.as_mut_ptr(), v.len())`, shown as `before -> after \
         (count)`):\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        target_prose = target_prose(spec.target),
        transform_prose = transform_prose(spec.transform),
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
    for (i, (input, out, n)) in cases.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let mut v: Vec<i64> = vec!{input:?};\n\
             \x20   let wrote = {name}(v.as_mut_ptr(), v.len());\n\
             \x20   assert_eq!(wrote, {n});\n\
             \x20   assert_eq!(v, vec!{out:?});\n\
             }}\n\n",
            name = spec.fn_name,
        ));
    }
    body.push_str(&format!(
        "#[test]\nfn empty_input() {{\n\
         \x20   let mut v: Vec<i64> = Vec::new();\n\
         \x20   assert_eq!({name}(v.as_mut_ptr(), v.len()), 0);\n\
         }}\n",
        name = spec.fn_name,
    ));
    body
}

fn differential_test_src(spec: &Spec) -> String {
    // The safe mirror of the reference — indexes `xs` instead of dereferencing.
    let slot = "xs[i]";
    let reference = format!(
        "fn reference(xs: &mut [i64]) -> usize {{\n\
         \x20   let mut n: usize = 0;\n\
         \x20   let mut i: usize = {start};\n\
         \x20   while i < {bound} {{\n\
         \x20       xs[i] = {store};\n\
         \x20       n += 1;\n\
         \x20       i += {stride};\n\
         \x20   }}\n\
         \x20   n\n\
         }}\n",
        start = start(spec.target),
        bound = bound_expr(spec.target, "xs.len()"),
        store = store_expr(spec.transform, slot),
        stride = stride(spec.target),
    );
    format!(
        "use task::{name};\n\
         \n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x00F0_ED00_0000_0042;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 12) as usize;\n\
         \x20       let xs: Vec<i64> = (0..len).map(|_| (next() % 19) as i64 - 9).collect();\n\
         \x20       let mut got = xs.clone();\n\
         \x20       let got_n = {name}(got.as_mut_ptr(), got.len());\n\
         \x20       let mut want = xs.clone();\n\
         \x20       let want_n = reference(&mut want);\n\
         \x20       assert_eq!(got_n, want_n, \"count mismatch: {{xs:?}}\");\n\
         \x20       assert_eq!(got, want, \"buffer mismatch: {{xs:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = reference,
    )
}

/// Degenerate: writes nothing, returns 0. Fails on the canonical example, whose
/// count is ≥ 2 under every target. (UB-free — dereferences no pointer.)
fn no_op(spec: &Spec) -> String {
    format!(
        "pub fn {name}(ptr: *mut i64, len: usize) -> usize {{ let _ = (ptr, len); 0 }}\n",
        name = spec.fn_name,
    )
}

/// Degenerate: zeroes every element and claims it wrote them all. Fails because
/// the canonical expected output keeps every position non-zero (transforms of
/// non-zero values stay non-zero; untouched positions keep their values).
fn fill_zero(spec: &Spec) -> String {
    format!(
        "pub fn {name}(ptr: *mut i64, len: usize) -> usize {{\n\
         \x20   let mut i: usize = 0;\n\
         \x20   while i < len {{\n\
         \x20       unsafe {{ *ptr.add(i) = 0; }}\n\
         \x20       i += 1;\n\
         \x20   }}\n\
         \x20   len\n\
         }}\n",
        name = spec.fn_name,
    )
}

pub struct RawPtrMutFamily;

impl Generator for RawPtrMutFamily {
    fn id(&self) -> &str {
        "raw-ptr-mut"
    }
    fn category(&self) -> &str {
        "unsafe-core"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("raw-ptr-mut", seed);

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
            id: format!("raw-ptr-mut/{seed:016x}"),
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
            // constrained (limit = unlimited). Miri, the real constraint layer
            // for this category, is deferred (docs/04, roadmap P7) — see the
            // module doc.
            max_unsafe: None,
            check_clippy: false,
            clippy_allow: Vec::new(),
            forbidden_paths: Vec::new(),
            // docs/04 unsafe-core weights (behaviour-dominant; the constraint
            // slot is miri, deferred, so scoring renormalises to behaviour).
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
            ("no-op".to_string(), no_op(&spec)),
            ("fill-zero".to_string(), fill_zero(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is the (write target, transform) pair. The function name is
        // cosmetic; there are no numeric constants — all excluded (Q31).
        let spec = sample(seed);
        let target = match spec.target {
            Target::All => "all",
            Target::EvenIdx => "even_idx",
            Target::OddIdx => "odd_idx",
            Target::FirstHalf => "first_half",
        };
        let transform = match spec.transform {
            Transform::Double => "double",
            Transform::Negate => "negate",
            Transform::Square => "square",
            Transform::Increment => "increment",
        };
        vec![format!("target:{target}"), format!("transform:{transform}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = RawPtrMutFamily;
        assert_eq!(g.generate(31).prompt, g.generate(31).prompt);
        assert_eq!(g.generate(31).hidden, g.generate(31).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        let mk = |target, transform| Spec {
            target,
            transform,
            fn_name: "f",
        };

        // All + Double on [3, 1]: -> [6, 2], wrote 2.
        let mut v = vec![3, 1];
        assert_eq!(eval(&mk(Target::All, Transform::Double), &mut v), 2);
        assert_eq!(v, vec![6, 2]);

        // EvenIdx + Increment on [3, 1, 4, 2]: indices 0, 2 -> [4, 1, 5, 2].
        let mut v = vec![3, 1, 4, 2];
        assert_eq!(eval(&mk(Target::EvenIdx, Transform::Increment), &mut v), 2);
        assert_eq!(v, vec![4, 1, 5, 2]);

        // OddIdx + Negate on [3, 1, 4, 2]: indices 1, 3 -> [3, -1, 4, -2].
        let mut v = vec![3, 1, 4, 2];
        assert_eq!(eval(&mk(Target::OddIdx, Transform::Negate), &mut v), 2);
        assert_eq!(v, vec![3, -1, 4, -2]);

        // FirstHalf + Square on [3, 1, 4, 2]: indices 0, 1 -> [9, 1, 4, 2].
        let mut v = vec![3, 1, 4, 2];
        assert_eq!(eval(&mk(Target::FirstHalf, Transform::Square), &mut v), 2);
        assert_eq!(v, vec![9, 1, 4, 2]);

        // Empty input: nothing written.
        let mut v: Vec<i64> = Vec::new();
        assert_eq!(eval(&mk(Target::All, Transform::Double), &mut v), 0);
    }

    #[test]
    fn seeds_vary_the_task() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.target, s.transform));
        }
        assert!(
            variants.len() >= 14,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_output_is_never_all_zero_and_count_positive() {
        // Both baselines are caught on every seed only if, on the canonical
        // [3, 1, 4, 2]: every target writes ≥ 2 elements (no-op fails), and the
        // expected output has no zero anywhere (fill-zero fails — it would have
        // produced all zeros). Untouched positions keep non-zero originals and
        // every transform maps non-zero to non-zero, so pin both halves.
        let canonical = [3i64, 1, 4, 2];
        for &target in &[
            Target::All,
            Target::EvenIdx,
            Target::OddIdx,
            Target::FirstHalf,
        ] {
            let mut n = 0;
            let mut i = start(target);
            while i < bound(target, canonical.len()) {
                n += 1;
                i += stride(target);
            }
            assert!(n >= 2, "{target:?} selects only {n} of the canonical");
            for &transform in &[
                Transform::Double,
                Transform::Negate,
                Transform::Square,
                Transform::Increment,
            ] {
                let spec = Spec {
                    target,
                    transform,
                    fn_name: "f",
                };
                let mut out = canonical.to_vec();
                let wrote = eval(&spec, &mut out);
                assert!(wrote >= 2, "{target:?}: canonical wrote {wrote}");
                assert!(
                    out.iter().all(|&v| v != 0),
                    "{target:?}/{transform:?}: canonical output {out:?} contains 0"
                );
            }
        }
    }

    #[test]
    fn reference_matches_native_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            let (_, cases) = worked_examples(&spec, seed);
            for (input, out, n) in cases {
                let mut buf = input;
                let wrote = eval(&spec, &mut buf);
                assert_eq!((buf, wrote), (out, n), "seed {seed}");
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = RawPtrMutFamily;
        let t = g.generate(9);
        assert!(t.prompt.contains(&t.canary));
    }
}

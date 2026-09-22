//! The `bit-ops` family (category `bit-manipulation`).
//!
//! A deliberately low-level task shape — no arithmetic fold in sight. The model
//! implements `fn f(x: u32) -> u32` applying a **seed-selected two-stage bit
//! pipeline**:
//!
//! 1. **Mask** — Identity / KeepLow(n) / KeepHigh(n) / ClearLow(n) / SetLow(n).
//! 2. **Transform** — RotateLeft(k) / RotateRight(k) / ReverseBits / SwapBytes.
//!
//! The structural surface is 5 × 4 = **20 distinct skills**. The mask width `n`
//! (∈ {8, 16, 24}) and the rotate amount `k` (∈ 1..=31) are seed-chosen numeric
//! parameters of the *same* skill (Q31 granularity), and the function name is
//! cosmetic — all excluded from `spec_signature`. Solution-first and
//! correct-by-construction (ADR-0003): the native `eval` and the emitted reference
//! use the same `u32` methods (`rotate_left`, `reverse_bits`, `swap_bytes`, mask
//! arithmetic), and the differential fuzzes 3000 random `u32` values against the
//! model. No overflow is possible — every shift amount is < 32 and bit ops wrap by
//! definition.
//!
//! Every transform is a bijection that fixes zero, and no mask can zero the
//! canonical input `0x9ABCDEF1` (it has a set bit in both the lowest and highest
//! bit positions), so the canonical result is provably never `0` and never equal
//! to the input — which is what makes both trivial baselines (`identity`,
//! `const-zero`) fail on every seed.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Stage 1 — how the bits are masked (`n` is the width in bits).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Mask {
    Identity,
    KeepLow(u32),
    KeepHigh(u32),
    ClearLow(u32),
    SetLow(u32),
}

/// Stage 2 — how the masked value is transformed (`k` is the rotate amount).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Transform {
    RotateLeft(u32),
    RotateRight(u32),
    ReverseBits,
    SwapBytes,
}

/// Seed-chosen mask widths (kept in 1..32 so `1 << n` and `1 << (32 - n)` never
/// overflow).
const WIDTHS: [u32; 3] = [8, 16, 24];

struct Spec {
    mask: Mask,
    transform: Transform,
    fn_name: &'static str,
}

const NAMES: &[&str] = &[
    "f",
    "bitmix",
    "munge_bits",
    "rework",
    "transform_bits",
    "scramble",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let n = WIDTHS[rng.below(WIDTHS.len() as u64) as usize];
    let mask = match rng.below(5) {
        0 => Mask::Identity,
        1 => Mask::KeepLow(n),
        2 => Mask::KeepHigh(n),
        3 => Mask::ClearLow(n),
        _ => Mask::SetLow(n),
    };
    let k = 1 + rng.below(31) as u32; // 1..=31
    let transform = match rng.below(4) {
        0 => Transform::RotateLeft(k),
        1 => Transform::RotateRight(k),
        2 => Transform::ReverseBits,
        _ => Transform::SwapBytes,
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        mask,
        transform,
        fn_name,
    }
}

// ---- native reference (mirrors the emitted source exactly) ----------------

fn apply_mask(mask: Mask, x: u32) -> u32 {
    match mask {
        Mask::Identity => x,
        Mask::KeepLow(n) => x & ((1u32 << n) - 1),
        Mask::KeepHigh(n) => x & !((1u32 << (32 - n)) - 1),
        Mask::ClearLow(n) => x & !((1u32 << n) - 1),
        Mask::SetLow(n) => x | ((1u32 << n) - 1),
    }
}

fn apply_transform(transform: Transform, m: u32) -> u32 {
    match transform {
        Transform::RotateLeft(k) => m.rotate_left(k),
        Transform::RotateRight(k) => m.rotate_right(k),
        Transform::ReverseBits => m.reverse_bits(),
        Transform::SwapBytes => m.swap_bytes(),
    }
}

/// The answer: mask, then transform. Source of truth for the emitted reference.
fn eval(spec: &Spec, x: u32) -> u32 {
    apply_transform(spec.transform, apply_mask(spec.mask, x))
}

// ---- emitted-source fragments (mirror the native functions above) ---------

/// The mask stage as source, over an operand expression (`x`).
fn mask_expr(mask: Mask, operand: &str) -> String {
    match mask {
        Mask::Identity => operand.to_string(),
        Mask::KeepLow(n) => format!("{operand} & ((1u32 << {n}) - 1)"),
        Mask::KeepHigh(n) => format!("{operand} & !((1u32 << {}) - 1)", 32 - n),
        Mask::ClearLow(n) => format!("{operand} & !((1u32 << {n}) - 1)"),
        Mask::SetLow(n) => format!("{operand} | ((1u32 << {n}) - 1)"),
    }
}

/// The transform stage as source, over an operand expression (`masked`).
fn transform_expr(transform: Transform, operand: &str) -> String {
    match transform {
        Transform::RotateLeft(k) => format!("{operand}.rotate_left({k})"),
        Transform::RotateRight(k) => format!("{operand}.rotate_right({k})"),
        Transform::ReverseBits => format!("{operand}.reverse_bits()"),
        Transform::SwapBytes => format!("{operand}.swap_bytes()"),
    }
}

fn mask_prose(mask: Mask) -> String {
    match mask {
        Mask::Identity => "leave all 32 bits unchanged".to_string(),
        Mask::KeepLow(n) => format!("keep only the low {n} bits (clear the other {} )", 32 - n),
        Mask::KeepHigh(n) => format!("keep only the high {n} bits (clear the other {} )", 32 - n),
        Mask::ClearLow(n) => format!("clear the low {n} bits (leave the rest unchanged)"),
        Mask::SetLow(n) => format!("set the low {n} bits to 1 (leave the rest unchanged)"),
    }
}

fn transform_prose(transform: Transform) -> String {
    match transform {
        Transform::RotateLeft(k) => format!("rotate the 32-bit value left by {k}"),
        Transform::RotateRight(k) => format!("rotate the 32-bit value right by {k}"),
        Transform::ReverseBits => "reverse the order of all 32 bits".to_string(),
        Transform::SwapBytes => "reverse the order of the 4 bytes (byte swap)".to_string(),
    }
}

fn reference_src(spec: &Spec) -> String {
    format!(
        "pub fn {name}(x: u32) -> u32 {{\n\
         \x20   let masked = {mask};\n\
         \x20   {transform}\n\
         }}\n",
        name = spec.fn_name,
        mask = mask_expr(spec.mask, "x"),
        transform = transform_expr(spec.transform, "masked"),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "//! Implement `{name}` below.\n\
         //!\n\
         {doc}\n\
         pub fn {name}(x: u32) -> u32 {{\n\
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

/// One worked example: (input, expected output).
type ExampleCase = (u32, u32);

/// Worked examples, computed natively so each is correct by construction. The
/// first case is the **canonical** one — the fixed input `0x9ABCDEF1`, chosen so
/// that no mask can zero it and every transform is a zero-fixing bijection, hence
/// the result is never `0` and never equal to the input under any of the 20
/// combinations. That is what makes both trivial baselines (`identity`,
/// `const-zero`) fail for every seed. The rest are seed-varied random values (the
/// family's biggest per-instance textual lever, docs/02 Q30).
fn worked_examples(spec: &Spec, seed: u64) -> (String, Vec<ExampleCase>) {
    let mut rng = Rng::new(seed ^ 0xB17_0000_0000_0031);
    let mut inputs: Vec<u32> = vec![0x9ABC_DEF1];
    for _ in 0..3 {
        inputs.push(rng.next_u64() as u32);
    }

    let mut cases = Vec::new();
    let mut prose = String::new();
    for &x in &inputs {
        let out = eval(spec, x);
        prose.push_str(&format!("  0x{x:08x}  ->  0x{out:08x}\n"));
        cases.push((x, out));
    }
    (prose, cases)
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "Implement the function `{name}` in `src/lib.rs`.\n\
         \n\
         Given a 32-bit unsigned integer `x`, apply two steps in order and return \
         the result:\n\
         \n\
         1. **Mask** — {mask_prose}.\n\
         2. **Transform** — {transform_prose}.\n\
         \n\
         The transform applies to the *masked* value from step 1.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - Every shift/rotate amount is between 1 and 31, so no shift overflows.\n\
         \n\
         Signature:\n\
         ```rust\n\
         pub fn {name}(x: u32) -> u32\n\
         ```\n\
         \n\
         Examples (inputs and outputs in hex):\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        mask_prose = mask_prose(spec.mask),
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
    for (i, (input, out)) in cases.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   assert_eq!({name}(0x{input:08x}), 0x{out:08x});\n\
             }}\n\n",
            name = spec.fn_name,
        ));
    }
    // Zero and all-ones are useful edge cases: masks and transforms behave
    // distinctively at the extremes, and the reference computes them natively.
    let zero = eval(spec, 0);
    let ones = eval(spec, u32::MAX);
    body.push_str(&format!(
        "#[test]\nfn edge_zero() {{\n\
         \x20   assert_eq!({name}(0x00000000), 0x{zero:08x});\n\
         }}\n\n\
         #[test]\nfn edge_ones() {{\n\
         \x20   assert_eq!({name}(0xffffffff), 0x{ones:08x});\n\
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
         \x20   let mut state: u64 = 0xB17_ED00_0000_0042;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 32) as u32\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let x = next();\n\
         \x20       assert_eq!({name}(x), reference(x), \"mismatch on 0x{{x:08x}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = reference,
    )
}

/// Degenerate: returns the input unchanged. Fails on the canonical example, which
/// every combination changes.
fn identity(spec: &Spec) -> String {
    format!(
        "pub fn {name}(x: u32) -> u32 {{ x }}\n",
        name = spec.fn_name,
    )
}

/// Degenerate: always returns zero. Fails on the canonical example, whose result
/// is never zero.
fn const_zero(spec: &Spec) -> String {
    format!(
        "pub fn {name}(x: u32) -> u32 {{ let _ = x; 0 }}\n",
        name = spec.fn_name,
    )
}

pub struct BitManipulationFamily;

impl Generator for BitManipulationFamily {
    fn id(&self) -> &str {
        "bit-ops"
    }
    fn category(&self) -> &str {
        "bit-manipulation"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("bit-ops", seed);

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
            id: format!("bit-ops/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            // A scalar bit transform does not allocate: no alloc constraint.
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
            ("identity".to_string(), identity(&spec)),
            ("const-zero".to_string(), const_zero(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is the (mask kind, transform kind) pair. The mask width `n` and
        // rotate amount `k` are constant parameters of the same skill (Q31), and
        // the function name is cosmetic — all excluded.
        let spec = sample(seed);
        let mask = match spec.mask {
            Mask::Identity => "identity",
            Mask::KeepLow(_) => "keep_low",
            Mask::KeepHigh(_) => "keep_high",
            Mask::ClearLow(_) => "clear_low",
            Mask::SetLow(_) => "set_low",
        };
        let transform = match spec.transform {
            Transform::RotateLeft(_) => "rotate_left",
            Transform::RotateRight(_) => "rotate_right",
            Transform::ReverseBits => "reverse_bits",
            Transform::SwapBytes => "swap_bytes",
        };
        vec![format!("mask:{mask}"), format!("transform:{transform}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = BitManipulationFamily;
        assert_eq!(g.generate(11).prompt, g.generate(11).prompt);
        assert_eq!(g.generate(11).hidden, g.generate(11).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        // KeepLow(8) then RotateLeft(4): mask 0x...F1 -> 0xF1, rotate left 4 -> 0xF10.
        let spec = Spec {
            mask: Mask::KeepLow(8),
            transform: Transform::RotateLeft(4),
            fn_name: "f",
        };
        assert_eq!(eval(&spec, 0x9ABC_DEF1), 0x0000_0F10);

        // SwapBytes of the canonical.
        let spec = Spec {
            mask: Mask::Identity,
            transform: Transform::SwapBytes,
            fn_name: "f",
        };
        assert_eq!(eval(&spec, 0x9ABC_DEF1), 0xF1DE_BC9A);

        // ClearLow(16) keeps the high half; RotateRight(16) moves it to the low half.
        let spec = Spec {
            mask: Mask::ClearLow(16),
            transform: Transform::RotateRight(16),
            fn_name: "f",
        };
        assert_eq!(eval(&spec, 0x9ABC_DEF1), 0x0000_9ABC);
    }

    #[test]
    fn seeds_vary_the_pipeline() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.mask, s.transform));
        }
        assert!(
            variants.len() >= 16,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_is_never_zero_or_identity() {
        // Both trivial baselines are caught on every seed only if the canonical
        // input maps to a result that is neither 0 (const-zero) nor the input
        // itself (identity), under every mask/transform including every width and
        // rotate amount the sampler can pick.
        let canonical = 0x9ABC_DEF1u32;
        let masks = |n: u32| {
            [
                Mask::Identity,
                Mask::KeepLow(n),
                Mask::KeepHigh(n),
                Mask::ClearLow(n),
                Mask::SetLow(n),
            ]
        };
        for &n in WIDTHS.iter() {
            for mask in masks(n) {
                for k in 1..=31u32 {
                    for transform in [
                        Transform::RotateLeft(k),
                        Transform::RotateRight(k),
                        Transform::ReverseBits,
                        Transform::SwapBytes,
                    ] {
                        let spec = Spec {
                            mask,
                            transform,
                            fn_name: "f",
                        };
                        let out = eval(&spec, canonical);
                        assert_ne!(out, 0, "zero under {mask:?}/{transform:?}");
                        assert_ne!(out, canonical, "unchanged under {mask:?}/{transform:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn reference_matches_native_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            let (_, cases) = worked_examples(&spec, seed);
            for (input, out) in cases {
                assert_eq!(eval(&spec, input), out, "seed {seed}");
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = BitManipulationFamily;
        let t = g.generate(6);
        assert!(t.prompt.contains(&t.canary));
    }
}

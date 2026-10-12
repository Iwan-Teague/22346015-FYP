//! The `poly` family (category `polynomials`) — queries over a dense
//! polynomial.
//!
//! Where `rle` scans runs and `bitset` does single-word bit algebra, this
//! family exercises **positional indexing with a convention**: the dense
//! little-endian coefficient vector, where slot 0 is the constant term and
//! the last occupied slot carries the leading coefficient. The domain is one
//! owned coefficient slice; every op is a pure function of it. The seed
//! prunes which two of five query ops are required: `degree`, `eval_at_one`,
//! `leading_coeff`, `num_zero_coeffs`, `constant_term`. C(5,2) = **10
//! distinct skills**, above the diversity floor; op names are semantic.
//!
//! The canonical polynomial is sampled until its anchor facts hold: at least
//! two slots, at least one exactly-zero coefficient, a constant term and
//! leading coefficient outside {0, 1}, and a total at x=1 that is neither 0
//! nor the slot count. Those make every op answer positive (defeating
//! `const-zero`) and separate four of the five ops from the all-ones cheat —
//! `degree` excepted, which that baseline answers exactly (it ignores
//! values); any pair containing it is caught by its partner.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops and
//! the emitted reference share the same bodies; the differential fuzzes 3000
//! random polynomials against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the canonical
//! polynomial) and `all-ones` (every coefficient replaced by 1).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Degree,
    EvalAtOne,
    LeadingCoeff,
    NumZeroCoeffs,
    ConstantTerm,
}

const OP_ALL: [Op; 5] = [
    Op::Degree,
    Op::EvalAtOne,
    Op::LeadingCoeff,
    Op::NumZeroCoeffs,
    Op::ConstantTerm,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Degree => "degree",
            Op::EvalAtOne => "eval_at_one",
            Op::LeadingCoeff => "leading_coeff",
            Op::NumZeroCoeffs => "num_zero_coeffs",
            Op::ConstantTerm => "constant_term",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Degree => {
                "the degree of `c`: the index of the highest non-empty \
                 slot, i.e. one less than the number of coefficients; an \
                 empty input has degree 0 by convention"
            }
            Op::EvalAtOne => {
                "the value of the polynomial described by `c` at `x = 1`; \
                 each power of 1 contributes its own coefficient, so every \
                 slot counts"
            }
            Op::LeadingCoeff => {
                "the coefficient attached to the highest power present in \
                 `c`, stored in the last slot; an empty input has none, \
                 yielding 0"
            }
            Op::NumZeroCoeffs => {
                "how many powers are missing from `c`, i.e. how many slots \
                 hold exactly zero"
            }
            Op::ConstantTerm => {
                "the coefficient of `x^0` in `c`, stored in slot 0; an \
                 empty input has none, yielding 0"
            }
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

fn b_degree(c: &[i64]) -> i64 {
    c.len().saturating_sub(1) as i64
}

fn b_eval_at_one(c: &[i64]) -> i64 {
    c.iter().sum()
}

fn b_leading_coeff(c: &[i64]) -> i64 {
    c.last().copied().unwrap_or(0)
}

fn b_num_zero_coeffs(c: &[i64]) -> i64 {
    c.iter().filter(|&&v| v == 0).count() as i64
}

fn b_constant_term(c: &[i64]) -> i64 {
    c.first().copied().unwrap_or(0)
}

/// Every op here returns an integer, so one result shape suffices.
fn op_eval(op: Op, c: &[i64]) -> i64 {
    match op {
        Op::Degree => b_degree(c),
        Op::EvalAtOne => b_eval_at_one(c),
        Op::LeadingCoeff => b_leading_coeff(c),
        Op::NumZeroCoeffs => b_num_zero_coeffs(c),
        Op::ConstantTerm => b_constant_term(c),
    }
}

// ---- canonical polynomial ---------------------------------------------------

/// The canonical polynomial: seeded coefficients over {-2..2}, retried until
/// the anchor facts hold.
///
/// Guaranteed for every seed: at least two slots, at least one zero
/// coefficient, first and last slots outside {0, 1}, and a value at x=1
/// that is neither 0 nor the slot count. Together those defeat both trivial
/// cheats on every op except `degree` under `all-ones`.
fn canonical(seed: u64) -> Vec<i64> {
    let mut rng = Rng::new(seed ^ 0x704C_59A1);
    for _ in 0..100_000 {
        let len = 4 + rng.below(5);
        let cand: Vec<i64> = (0..len).map(|_| rng.below(5) as i64 - 2).collect();
        if anchors_hold(&cand) {
            return cand;
        }
    }
    unreachable!("canonical polynomial sampling failed to satisfy anchors");
}

fn anchors_hold(c: &[i64]) -> bool {
    c.len() >= 2
        && b_num_zero_coeffs(c) >= 1
        && ![0, 1].contains(&b_constant_term(c))
        && ![0, 1].contains(&b_leading_coeff(c))
        && ![0, c.len() as i64].contains(&b_eval_at_one(c))
}

// ---- worked examples --------------------------------------------------------

type ExampleCase = (Vec<i64>, Vec<(Op, i64)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_00D1);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical polynomial first.
    let can = canonical(seed);
    cases.push((
        can.clone(),
        spec.ops.map(|op| (op, op_eval(op, &can))).to_vec(),
    ));
    // The empty polynomial: pins every zero convention at once.
    cases.push((
        Vec::new(),
        spec.ops.map(|op| (op, op_eval(op, &[]))).to_vec(),
    ));
    // A lone constant: degree 0 while every other read is the value itself.
    let solo = vec![9i64];
    cases.push((
        solo.clone(),
        spec.ops.map(|op| (op, op_eval(op, &solo))).to_vec(),
    ));
    for _ in 0..3 {
        let n = 1 + rng.below(6);
        let poly: Vec<i64> = (0..n).map(|_| rng.below(5) as i64 - 2).collect();
        let outs = spec.ops.map(|op| (op, op_eval(op, &poly))).to_vec();
        cases.push((poly, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Plain bracket form for prompt readability.
fn prose_poly(c: &[i64]) -> String {
    let items = c
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{items}]")
}

/// Emitted literal that type-checks as `&[i64]` at the call site; the first
/// element carries the `i64` suffix so the rest infer. `&[]` is typed by the
/// function signature at the call site.
fn render_poly(c: &[i64]) -> String {
    if c.is_empty() {
        return "&[]".to_string();
    }
    let mut items = format!("{}i64", c[0]);
    for v in &c[1..] {
        items.push_str(&format!(", {v}"));
    }
    format!("&[{items}]")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let body = match op {
        Op::Degree => ["c.len().saturating_sub(1) as i64"].join("\n    "),
        Op::EvalAtOne => ["c.iter().sum()"].join("\n    "),
        Op::LeadingCoeff => ["c.last().copied().unwrap_or(0)"].join("\n    "),
        Op::NumZeroCoeffs => ["c.iter().filter(|&&v| v == 0).count() as i64"].join("\n    "),
        Op::ConstantTerm => ["c.first().copied().unwrap_or(0)"].join("\n    "),
    };
    format!(
        "pub fn {name}(c: &[i64]) -> i64 {{\n    {body}\n}}\n",
        name = name,
        body = body,
    )
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(c: &[i64]) -> i64 {{\n    todo!()\n}}\n",
        op.name()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(c: &[i64]) -> i64", op.name())
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
    for (poly, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {out}", op.name()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  c {}  ->  {}\n", prose_poly(&poly), results));
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
         given as `c`, a slice of `i64` holding the coefficients of a \
         polynomial in dense little-endian form: `c[i]` multiplies `x^i`, \
         so slot 0 is the constant term and the last slot carries the \
         leading coefficient.\n\
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
    for (i, (poly, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let c = {};\n",
            render_poly(poly),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {out});\n",
                // render_poly already emits `&[...]`, so the binding is a
                // reference — pass it without another `&`.
                call_src(*op, "c"),
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
            let call = call_src(*op, "&c");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_00D7;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = (nx(&mut state) % 6 + 1) as usize;\n\
         \x20       let mut c = Vec::with_capacity(n);\n\
         \x20       for _ in 0..n {{\n\
         \x20           c.push((nx(&mut state) % 5) as i64 - 2);\n\
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
                "pub fn {}(c: &[i64]) -> i64 {{\n    let _ = c;\n    0\n}}\n",
                op.name()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: every coefficient replaced by 1. The canonical
/// anchors make four of the five ops disagree; exact only for `degree`
/// (which ignores values), and any pair containing it is caught by its
/// partner.
fn all_ones(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let body = match op {
                Op::Degree => "c.len().saturating_sub(1) as i64".to_string(),
                Op::EvalAtOne => "c.len() as i64".to_string(),
                Op::LeadingCoeff | Op::ConstantTerm => "1".to_string(),
                Op::NumZeroCoeffs => "0".to_string(),
            };
            format!(
                "pub fn {name}(c: &[i64]) -> i64 {{\n    {body}\n}}\n",
                name = op.name(),
                body = body,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct PolyFamily;

impl Generator for PolyFamily {
    fn id(&self) -> &str {
        "poly"
    }
    fn category(&self) -> &str {
        "polynomials"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("poly", seed);

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
            id: format!("poly/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer bookkeeping — no unsafe anywhere near it.
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
            ("all-ones".to_string(), all_ones(&spec)),
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
        let g = PolyFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Degree: highest slot index; empty stays 0 by convention.
        assert_eq!(b_degree(&[5]), 0);
        assert_eq!(b_degree(&[1, 2, 3]), 2);
        assert_eq!(b_degree(&[]), 0);
        // Value at x=1: every slot counts.
        assert_eq!(b_eval_at_one(&[1, 2, 3]), 6);
        assert_eq!(b_eval_at_one(&[4, -1, -3]), 0);
        assert_eq!(b_eval_at_one(&[]), 0);
        // Leading coefficient: last slot.
        assert_eq!(b_leading_coeff(&[7, 2, 3]), 3);
        assert_eq!(b_leading_coeff(&[9, -4]), -4);
        assert_eq!(b_leading_coeff(&[]), 0);
        // Missing powers: exactly-zero slots.
        assert_eq!(b_num_zero_coeffs(&[1, 0, 3]), 1);
        assert_eq!(b_num_zero_coeffs(&[0, 0, 5]), 2);
        assert_eq!(b_num_zero_coeffs(&[]), 0);
        // Constant term: slot 0.
        assert_eq!(b_constant_term(&[7, 2, 3]), 7);
        assert_eq!(b_constant_term(&[0, -4]), 0);
        assert_eq!(b_constant_term(&[]), 0);
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
        // canonical polynomial separate from const-zero on all five ops;
        // `all-ones` is exact only for `degree` (it ignores values), and a
        // pair containing it is caught by its partner op.
        for seed in 0..200u64 {
            let c = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(c.len() >= 2, "seed {seed}");
            assert!(b_num_zero_coeffs(&c) >= 1, "seed {seed}");
            assert!(![0, 1].contains(&b_constant_term(&c)), "seed {seed}");
            assert!(![0, 1].contains(&b_leading_coeff(&c)), "seed {seed}");
            assert!(
                ![0, c.len() as i64].contains(&b_eval_at_one(&c)),
                "seed {seed}"
            );
            for op in OP_ALL {
                let truth = op_eval(op, &c);
                // const-zero separates everywhere: every anchored answer
                // is nonzero (degree >= 1 needs len >= 2).
                assert_ne!(truth, 0, "const-zero survives {op:?} seed {seed}");
                // all-ones answers: degree exact (skip), value reads -> 1,
                // missing powers -> 0, x=1 read -> slot count.
                let cheat = match op {
                    Op::Degree => continue,
                    Op::LeadingCoeff | Op::ConstantTerm => 1,
                    Op::NumZeroCoeffs => 0,
                    Op::EvalAtOne => c.len() as i64,
                };
                assert_ne!(truth, cheat, "all-ones survives {op:?} seed {seed}");
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (poly, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &poly), out, "seed {seed}");
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
                // Match the `pub fn` line so no bare-name substring leaks.
                let fn_line = format!("pub fn {}", op.name());
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
            // Solution-shaped leak tokens must stay out of the skeleton.
            assert!(!sk.contains(".len().saturating_sub(1)"));
            assert!(!sk.contains(".iter().sum()"));
            assert!(!sk.contains(".last()"));
            assert!(!sk.contains(".first()"));
            assert!(!sk.contains(".filter("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(".len().saturating_sub(1)"));
            assert!(!p.contains(".iter().sum()"));
            assert!(!p.contains(".last()"));
            assert!(!p.contains(".first()"));
            assert!(!p.contains(".filter("));
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
            let call = call_src(op, "&c");
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
        let g = PolyFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

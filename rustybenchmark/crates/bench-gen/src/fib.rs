//! The `fib` family (category `recurrence`) — queries over the Fibonacci
//! sequence at a seeded index.
//!
//! Where `collatz` walks an orbit and `primes` factors a value, this family
//! exercises **iterative recurrence computation**: the nth Fibonacci number
//! itself, its parity, its decimal width, its last three digits, and a
//! property of the index (`n` divisible by three is exactly when `F(n)` is
//! even). The domain is one index `n: u32` capped at 90, where `F(90)` is
//! the largest term that fits `u64` exactly. The seed prunes which two of
//! five query ops are required: `value`, `is_even`, `value_num_digits`,
//! `value_mod_1000`, `index_is_multiple_of_3`. C(5,2) = **10 distinct
//! skills**, above the diversity floor; op names are semantic.
//!
//! The canonical index is sampled until its anchor facts hold: a nonzero
//! value with a nonzero last-three-digits residue, an even term (so the
//! index is divisible by three and both flag answers are true), and every
//! answer distinct from the raw index. Those make both baselines wrong on
//! all five ops under the canonical example alone: `const-zero` because no
//! answer is zero or false, and `index-everything` because no answer equals
//! the index.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random indices against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical example) and `index-everything` (every query answered with
//! the raw index).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Value,
    IsEven,
    ValueNumDigits,
    ValueMod1000,
    IndexIsMultipleOf3,
}

const OP_ALL: [Op; 5] = [
    Op::Value,
    Op::IsEven,
    Op::ValueNumDigits,
    Op::ValueMod1000,
    Op::IndexIsMultipleOf3,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Value => "value",
            Op::IsEven => "is_even",
            Op::ValueNumDigits => "value_num_digits",
            Op::ValueMod1000 => "value_mod_1000",
            Op::IndexIsMultipleOf3 => "index_is_multiple_of_3",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Value => {
                "the nth Fibonacci number, counting from F(0) = 0 and \
                 F(1) = 1; indices above 90 stay clamped there"
            }
            Op::IsEven => {
                "whether the nth Fibonacci number is even; the \
                           parity repeats every third term"
            }
            Op::ValueNumDigits => {
                "how many decimal digits the nth Fibonacci number has; \
                 zero has one digit"
            }
            Op::ValueMod1000 => {
                "the nth Fibonacci number's remainder on division by one \
                 thousand — its last three digits"
            }
            Op::IndexIsMultipleOf3 => {
                "whether the index n itself is divisible by three (exactly \
                 the terms that are even)"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::IsEven | Op::IndexIsMultipleOf3 => "bool",
            _ => "i64",
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

/// The nth Fibonacci number, walking the pair forward; indices are clamped
/// at 90, the last term that fits `u64` exactly.
fn b_value(n: u32) -> i64 {
    let n = n.min(90);
    let mut a: u64 = 0;
    let mut b: u64 = 1;
    for _ in 0..n {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    a as i64
}

fn b_is_even(n: u32) -> bool {
    let v = b_value(n);
    // `is_multiple_of` lives on the unsigned types on this toolchain.
    (v as u64).is_multiple_of(2)
}

fn b_value_num_digits(n: u32) -> i64 {
    let mut v = b_value(n) as u64;
    let mut d = 1i64;
    while v >= 10 {
        d += 1;
        v /= 10;
    }
    d
}

/// A self-contained mod-1000 walk so it stays tiny at any index.
fn b_value_mod_1000(n: u32) -> i64 {
    let n = n.min(90);
    let mut a: u64 = 0;
    let mut b: u64 = 1;
    for _ in 0..n {
        let next = (a + b) % 1000;
        a = b;
        b = next;
    }
    a as i64
}

fn b_index_is_multiple_of_3(n: u32) -> bool {
    n.is_multiple_of(3)
}

/// The answer shape: scalar counts/values as `Num`, predicates as `Flag`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    fn lit(self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, n: u32) -> Out {
    match op {
        Op::Value => Out::Num(b_value(n)),
        Op::IsEven => Out::Flag(b_is_even(n)),
        Op::ValueNumDigits => Out::Num(b_value_num_digits(n)),
        Op::ValueMod1000 => Out::Num(b_value_mod_1000(n)),
        Op::IndexIsMultipleOf3 => Out::Flag(b_index_is_multiple_of_3(n)),
    }
}

// ---- canonical index --------------------------------------------------------

/// The canonical index: sampled below 91 and retried until the anchor facts
/// hold.
///
/// Guaranteed for every seed: an even term (so the index is divisible by
/// three and both flags answer true), at least 18 so every scalar answer is
/// nonzero and differs from the raw index, and a last-three-digits residue
/// that is neither zero nor the index itself. Those make `const-zero` wrong
/// on all five ops (no zero answers, no false flags) and
/// `index-everything` wrong on all five ops too.
fn canonical(seed: u64) -> u32 {
    let mut rng = Rng::new(seed ^ 0xF1B0_0A11);
    for _ in 0..100_000 {
        let n = rng.below(91) as u32;
        if anchors_hold(n) {
            return n;
        }
    }
    unreachable!("canonical index sampling failed to satisfy anchors");
}

fn anchors_hold(n: u32) -> bool {
    n >= 18
        && b_is_even(n)
        && b_index_is_multiple_of_3(n)
        && b_value(n) != 0
        && b_value_mod_1000(n) != 0
        && b_value(n) != n as i64
        && b_value_mod_1000(n) != n as i64
        && b_value_num_digits(n) != n as i64
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u32, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_011A);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical index first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // Zero: pins every convention at once (both flags are true at 0).
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // The clamped maximum: F(90) is the widest term.
    cases.push((90, spec.ops.map(|op| (op, op_eval(op, 90))).to_vec()));
    for _ in 0..3 {
        let n = rng.below(91) as u32;
        let outs = spec.ops.map(|op| (op, op_eval(op, n))).to_vec();
        cases.push((n, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the suffix types it as `u32`.
fn render_u32(n: u32) -> String {
    format!("{n}u32")
}

const WALK: &[&str] = &[
    "let mut a: u64 = 0;",
    "let mut b: u64 = 1;",
    "for _ in 0..n {",
    "    let next = a + b;",
    "    a = b;",
    "    b = next;",
    "}",
];

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(n: u32) -> {ret}");
    let body = match op {
        Op::Value => WALK
            .iter()
            .copied()
            .chain(["a as i64"])
            .collect::<Vec<_>>()
            .join("\n    "),
        Op::IsEven => WALK
            .iter()
            .copied()
            .chain(["a % 2 == 0"])
            .collect::<Vec<_>>()
            .join("\n    "),
        Op::ValueNumDigits => WALK
            .iter()
            .copied()
            .chain([
                "let mut d = 1i64;",
                "let mut m = a / 10;",
                "while m > 0 {",
                "    d += 1;",
                "    m /= 10;",
                "}",
                "d",
            ])
            .collect::<Vec<_>>()
            .join("\n    "),
        Op::ValueMod1000 => [
            "let mut a: u64 = 0;",
            "let mut b: u64 = 1;",
            "for _ in 0..n {",
            "    let next = (a + b) % 1000;",
            "    a = b;",
            "    b = next;",
            "}",
            "a as i64",
        ]
        .join("\n    "),
        // A property of the index itself — no walk needed.
        Op::IndexIsMultipleOf3 => "n % 3 == 0".to_string(),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(n: u32) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(n: u32) -> {}", op.name(), op.ret())
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
    for (n, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  n {}  ->  {}\n", render_u32(n), results));
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
         one index `n` of type `u32` (0 through 90); queries are about the \
         nth Fibonacci number, counting from F(0) = 0 and F(1) = 1.\n\
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
    for (i, (n, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let n = {};\n",
            render_u32(*n),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "n"),
                out.lit(),
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
            let call = call_src(*op, "n");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_011A;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = (nx(&mut state) % 91) as u32;\n\
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
            let sig = op_sig_src(*op);
            let tail = match op.ret() {
                "bool" => "false",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = n;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the raw index no matter what was asked.
/// The canonical anchors make every scalar answer differ from the index and
/// force both flags true, so it is wrong on all five ops there.
fn index_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            if op.ret() == "bool" {
                format!("{sig} {{\n    false\n}}\n")
            } else {
                format!("{sig} {{\n    n as i64\n}}\n")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct FibFamily;

impl Generator for FibFamily {
    fn id(&self) -> &str {
        "fib"
    }
    fn category(&self) -> &str {
        "recurrence"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("fib", seed);

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
            id: format!("fib/{seed:016x}"),
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
            ("index-everything".to_string(), index_everything(&spec)),
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
        let g = FibFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Sequence values.
        assert_eq!(b_value(0), 0);
        assert_eq!(b_value(1), 1);
        assert_eq!(b_value(7), 13);
        assert_eq!(b_value(20), 6765);
        assert_eq!(b_value(90), 2_880_067_194_370_816_120);
        // Parity repeats every third term.
        assert!(!b_is_even(1));
        assert!(!b_is_even(2));
        assert!(b_is_even(3));
        assert!(!b_is_even(89));
        assert!(b_is_even(90));
        // Decimal width of the value.
        assert_eq!(b_value_num_digits(0), 1);
        assert_eq!(b_value_num_digits(10), 2);
        assert_eq!(b_value_num_digits(45), 10);
        // Last three digits.
        assert_eq!(b_value_mod_1000(0), 0);
        assert_eq!(b_value_mod_1000(17), 597);
        assert_eq!(b_value_mod_1000(90), 120);
        // Index property: exactly the even terms.
        assert!(b_index_is_multiple_of_3(0));
        assert!(!b_index_is_multiple_of_3(4));
        assert!(b_index_is_multiple_of_3(90));
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
        // Both baselines must fail under EVERY pair. The anchors force an
        // even (hence index-divisible-by-three) term with every scalar
        // answer nonzero and distinct from the raw index — so `const-zero`
        // misses on the scalars AND the flags, and `index-everything`
        // misses everywhere too. No skips needed.
        for seed in 0..200u64 {
            let n = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(n >= 18, "seed {seed}");
            assert!(b_is_even(n), "seed {seed}");
            assert!(b_index_is_multiple_of_3(n), "seed {seed}");
            for op in OP_ALL {
                match op_eval(op, n) {
                    Out::Num(v) => {
                        assert_ne!(v, 0, "const-zero survives {op:?} seed {seed}");
                        assert_ne!(v, n as i64, "index-everything survives {op:?} seed {seed}");
                    }
                    Out::Flag(b) => {
                        assert!(b, "const-zero survives {op:?} seed {seed}");
                        // index-everything answers false — already wrong.
                    }
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (n, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, n), out, "seed {seed}");
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
            assert!(!sk.contains("% 2"));
            assert!(!sk.contains("/ 10"));
            assert!(!sk.contains("% 1000"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("% 2"));
            assert!(!p.contains("/ 10"));
            assert!(!p.contains("% 1000"));
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
            let call = call_src(op, "n");
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
        let g = FibFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

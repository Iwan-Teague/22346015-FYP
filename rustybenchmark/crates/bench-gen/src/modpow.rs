//! The `modpow` family (category `modular-arithmetic`) —
//! modular-exponentiation queries over one seeded `(base, exp, modulus)`
//! triple.
//!
//! Where `digits` and `digitroot` reduce one integer's decimal form,
//! this family works in cyclic arithmetic: the modular power itself,
//! whether it collapses to one or to zero, the reduced base, and the
//! exponent's parity. The domain is a triple `(base, exp, m)` with `m`
//! at least two; every op is a pure function of it, and products go
//! through `u128` so wide moduli cannot overflow. The seed prunes which
//! two of five query ops are required: `mod_pow`, `power_is_one`,
//! `base_mod_m`, `power_is_zero`, `exp_is_even`. C(5,2) = **10 distinct
//! skills**, above the diversity floor; op names are semantic.
//!
//! The canonical triple is constructed so its anchor facts hold by
//! arithmetic rather than luck: the reduced base is `m - 1` and the
//! exponent is positive and even, so the power is exactly one while the
//! reduced base stays outside `{0, 1}`. Those make `const-zero` fail on
//! every op but `power_is_zero` and keep the `reduced-base-everything`
//! cheat exact only on `base_mod_m` itself; any pair containing one of
//! those is caught by its partner, and pairs without them are wrong
//! twice over.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random triples against the model.
//!
//! Trivial baselines: `const-zero` (fails outright on the canonical
//! triple) and `reduced-base-everything` (every query answered with the
//! base reduced modulo `m`).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    ModPow,
    PowerIsOne,
    BaseModM,
    PowerIsZero,
    ExpIsEven,
}

const OP_ALL: [Op; 5] = [
    Op::ModPow,
    Op::PowerIsOne,
    Op::BaseModM,
    Op::PowerIsZero,
    Op::ExpIsEven,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::ModPow => "mod_pow",
            Op::PowerIsOne => "power_is_one",
            Op::BaseModM => "base_mod_m",
            Op::PowerIsZero => "power_is_zero",
            Op::ExpIsEven => "exp_is_even",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::ModPow => "the value of `base` raised to `exp`, taken modulo `m`",
            Op::PowerIsOne => "whether that modular power comes out as exactly one",
            Op::PowerIsZero => "whether that modular power comes out as exactly zero",
            Op::BaseModM => "the remainder of `base` upon division by `m`",
            Op::ExpIsEven => "whether the exponent is even; zero counts as even",
        }
    }

    /// Return type used in signatures, stubs, and the prompt fence.
    fn ret(self) -> &'static str {
        match self {
            Op::ModPow | Op::BaseModM => "i64",
            _ => "bool",
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

/// Square-and-multiply with `u128` intermediates so wide moduli are safe.
fn b_mod_pow(base: u64, exp: u32, m: u64) -> i64 {
    let mut acc: u64 = 1 % m;
    let mut b = base % m;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            acc = (acc as u128 * b as u128 % m as u128) as u64;
        }
        e >>= 1;
        if e > 0 {
            b = (b as u128 * b as u128 % m as u128) as u64;
        }
    }
    acc as i64
}

fn b_power_is_one(base: u64, exp: u32, m: u64) -> bool {
    b_mod_pow(base, exp, m) == 1
}

fn b_base_mod_m(base: u64, exp: u32, m: u64) -> i64 {
    let _ = exp;
    (base % m) as i64
}

fn b_power_is_zero(base: u64, exp: u32, m: u64) -> bool {
    b_mod_pow(base, exp, m) == 0
}

fn b_exp_is_even(base: u64, exp: u32, m: u64) -> bool {
    let _ = (base, m);
    exp & 1 == 0
}

/// One op's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    /// The literal rendered into an emitted assertion.
    fn lit(self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, base: u64, exp: u32, m: u64) -> Out {
    match op {
        Op::ModPow => Out::Num(b_mod_pow(base, exp, m)),
        Op::PowerIsOne => Out::Flag(b_power_is_one(base, exp, m)),
        Op::BaseModM => Out::Num(b_base_mod_m(base, exp, m)),
        Op::PowerIsZero => Out::Flag(b_power_is_zero(base, exp, m)),
        Op::ExpIsEven => Out::Flag(b_exp_is_even(base, exp, m)),
    }
}

// ---- canonical input --------------------------------------------------------

/// The canonical triple, constructed so the anchors hold by arithmetic:
/// the reduced base is `m - 1` and the exponent is positive and even,
/// so the power is exactly one while the reduced base stays outside
/// `{0, 1}`.
///
/// Guaranteed for every seed: `power_is_one` true, `power_is_zero`
/// false, the exponent even, the reduced base at least two, and the
/// power distinct from the reduced base. Those make `const-zero` fail
/// on every op except `power_is_zero` and keep
/// `reduced-base-everything` exact only on `base_mod_m`.
fn canonical(seed: u64) -> (u64, u32, u64) {
    let mut rng = Rng::new(seed ^ 0x90D9_A117);
    for _ in 0..100_000 {
        let m = 3 + rng.below(1_000_000);
        let r = m - 1;
        // Any number of whole modulus steps keeps base % m == m - 1.
        let room = ((1_000_000 - r) / m).max(1);
        let j = rng.below(room);
        let base = j * m + r;
        let exp = 2 * (1 + rng.below(31)) as u32;
        if anchors_hold(base, exp, m) {
            return (base, exp, m);
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(base: u64, exp: u32, m: u64) -> bool {
    m >= 3
        && b_power_is_one(base, exp, m)
        && !b_power_is_zero(base, exp, m)
        && b_exp_is_even(base, exp, m)
        && b_base_mod_m(base, exp, m) >= 2
        && b_mod_pow(base, exp, m) != b_base_mod_m(base, exp, m)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u32, u64), Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0120);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, b: u64, e: u32, m: u64| {
        cases.push((
            (b, e, m),
            spec.ops.map(|op| (op, op_eval(op, b, e, m))).to_vec(),
        ));
    };
    // Canonical triple first.
    let can = canonical(seed);
    push(&mut cases, can.0, can.1, can.2);
    // Exponent zero is one modulo anything.
    push(&mut cases, 0, 0, 5);
    // An ordinary non-unit power.
    push(&mut cases, 3, 4, 7);
    // A base that collapses to zero under its modulus.
    push(&mut cases, 7, 3, 7);
    // Wide-modulus corner: exercises the wide-intermediate path.
    push(&mut cases, 2, 62, u64::MAX);
    for _ in 0..3 {
        let b = rng.below(1_000_000);
        let e = rng.below(64) as u32;
        let m = 2 + rng.below(1_000_000);
        push(&mut cases, b, e, m);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first element carries a suffix
/// and the rest are inferred at the typed call sites.
fn render_triple(t: &(u64, u32, u64)) -> String {
    format!("({}u64, {}, {})", t.0, t.1, t.2)
}

/// The square-and-multiply walk shared by the three power-shaped bodies.
/// Self-contained on purpose: a seed's pair may not select `mod_pow`,
/// so every body that needs the walk inlines it.
fn walk_src() -> String {
    [
        "let mut acc: u64 = 1 % m;",
        "let mut b = base % m;",
        "let mut e = exp;",
        "while e > 0 {",
        "    if e & 1 == 1 {",
        "        acc = (acc as u128 * b as u128 % m as u128) as u64;",
        "    }",
        "    e >>= 1;",
        "    if e > 0 {",
        "        b = (b as u128 * b as u128 % m as u128) as u64;",
        "    }",
        "}",
    ]
    .join("\n    ")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = match op.ret() {
        "bool" => "(base: u64, exp: u32, m: u64) -> bool",
        _ => "(base: u64, exp: u32, m: u64) -> i64",
    };
    let tail = match op {
        Op::ModPow => "acc as i64",
        Op::PowerIsOne => "acc == 1",
        Op::PowerIsZero => "acc == 0",
        _ => "",
    };
    let body = match op {
        Op::ModPow | Op::PowerIsOne | Op::PowerIsZero => {
            format!("{}\n    {}", walk_src(), tail)
        }
        Op::BaseModM => "(base % m) as i64".to_string(),
        Op::ExpIsEven => "exp & 1 == 0".to_string(),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    let sig = match op.ret() {
        "bool" => "(base: u64, exp: u32, m: u64) -> bool",
        _ => "(base: u64, exp: u32, m: u64) -> i64",
    };
    format!("pub fn {}{sig} {{\n    todo!()\n}}\n", op.name(), sig = sig,)
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(base: u64, exp: u32, m: u64) -> {}",
        op.name(),
        op.ret()
    )
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
    for (triple, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  inputs {}  ->  {}\n",
            render_triple(&triple),
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
         given as three integers: `base` and `m` of type `u64` with `m` \
         at least two, and the exponent `exp` of type `u32`; queries are \
         modular-exponentiation properties of the triple. Powers must be \
         computed without overflowing even when the modulus is huge.\n\
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
    for (i, (triple, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (base, exp, m) = {};\n",
            render_triple(triple),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "base, exp, m"),
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
            let call = call_src(*op, "base, exp, m");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0120;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let base = nx(&mut state) % 1000000;\n\
         \x20       let exp = (nx(&mut state) % 64) as u32;\n\
         \x20       let roll = nx(&mut state) % 4;\n\
         \x20       // One draw in four uses a wide modulus, so solutions\n\
         \x20       // that overflow `u64` products fail here too.\n\
         \x20       let m = if roll == 0 {{\n\
         \x20           nx(&mut state)\n\
         \x20       }} else {{\n\
         \x20           (nx(&mut state) % 999998) + 2\n\
         \x20       }};\n\
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
/// Degenerate: everything zero (and a hardcoded `false` on the booleans).
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => {
                    format!("{sig} {{\n    let _ = (base, exp, m);\n    false\n}}\n")
                }
                _ => format!("{sig} {{\n    let _ = (base, exp, m);\n    0\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the reduced base no matter what was
/// asked. The canonical anchors keep the power (exactly one) and both
/// true-shaped flags away from it; `base_mod_m` itself is exact, and any
/// pair containing it is caught by its partner.
fn base_mod_m_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => {
                    format!("{sig} {{\n    let _ = (base, exp, m);\n    false\n}}\n")
                }
                _ => format!("{sig} {{\n    (base % m) as i64\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct ModPowFamily;

impl Generator for ModPowFamily {
    fn id(&self) -> &str {
        "modpow"
    }
    fn category(&self) -> &str {
        "modular-arithmetic"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("modpow", seed);

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
            id: format!("modpow/{seed:016x}"),
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
            (
                "reduced-base-everything".to_string(),
                base_mod_m_everything(&spec),
            ),
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
        let g = ModPowFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Classic small cases.
        assert_eq!(b_mod_pow(3, 4, 7), 4); // 81 % 7
        assert_eq!(b_mod_pow(2, 10, 1000), 24);
        assert_eq!(b_mod_pow(10, 3, 7), 6); // base reduced first
        assert_eq!(b_mod_pow(12345, 0, 97), 1); // exponent zero
                                                // Wide modulus: 2^64 is one modulo u64::MAX, so 2^62 stays itself.
        assert_eq!(b_mod_pow(2, 62, u64::MAX), 4_611_686_018_427_387_904);
        // Unit and zero powers.
        assert!(b_power_is_one(2, 12, 13)); // Fermat
        assert!(b_power_is_one(987654321, 0, 97));
        assert!(!b_power_is_one(3, 4, 7));
        assert!(b_power_is_zero(7, 3, 7));
        assert!(b_power_is_zero(1000, 5, 8));
        assert!(!b_power_is_zero(0, 0, 9)); // zeroth power is one
                                            // Reduced base.
        assert_eq!(b_base_mod_m(10, 3, 7), 3);
        assert_eq!(b_base_mod_m(1000, 1, 7), 6);
        assert_eq!(b_base_mod_m(14, 2, 7), 0);
        // Exponent parity.
        assert!(b_exp_is_even(5, 0, 13));
        assert!(b_exp_is_even(9, 1_000_000, 11));
        assert!(!b_exp_is_even(7, 63, u64::MAX));
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
        // canonical power exactly one with an even exponent and a reduced
        // base of m - 1 (never 0 or 1): `const-zero` separates on every op
        // except `power_is_zero`, and `reduced-base-everything` is exact
        // only on `base_mod_m` — pairs carrying those are caught by their
        // partner.
        for seed in 0..200u64 {
            let (base, exp, m) = canonical(seed);
            let bmm = b_base_mod_m(base, exp, m);
            assert!(bmm >= 2, "seed {seed}");
            assert!(b_power_is_one(base, exp, m), "seed {seed}");
            assert!(!b_power_is_zero(base, exp, m), "seed {seed}");
            assert!(b_exp_is_even(base, exp, m), "seed {seed}");
            for op in OP_ALL {
                match op_eval(op, base, exp, m) {
                    Out::Num(v) => {
                        assert_ne!(v, 0, "const-zero survives {op:?} seed {seed}");
                        if !matches!(op, Op::BaseModM) {
                            assert_ne!(
                                v, bmm,
                                "reduced-base-everything survives {op:?} seed {seed}"
                            );
                        }
                    }
                    Out::Flag(b) => {
                        if matches!(op, Op::PowerIsOne | Op::ExpIsEven) {
                            assert!(b, "const-zero survives {op:?} seed {seed}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((b, e, m), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, b, e, m), out, "seed {seed}");
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
            assert!(!sk.contains('%'));
            assert!(!sk.contains(" >> "));
            assert!(!sk.contains(" & 1"));
            assert!(!sk.contains("u128"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains('%'));
            assert!(!p.contains(" >> "));
            assert!(!p.contains(" & 1"));
            assert!(!p.contains("u128"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Regression pin in the spirit of fsm's arity check: every op is
        // ternary here, so each call site carries exactly two commas — the
        // same count as its signature.
        for op in OP_ALL {
            let call = call_src(op, "base, exp, m");
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
        let g = ModPowFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

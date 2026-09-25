//! The `coins` family (category `coin-change`) — denomination counts of
//! the greedy change-making decomposition of one cash amount.
//!
//! The domain is one sub-dollar amount in cents (a `u32` capped below
//! five dollars). Every op reads one number out of the standard U.S.
//! greedy decomposition: quarters first, then dimes, then nickels,
//! pennies last. The seed prunes which two of five query ops are
//! required: `num_quarters`, `num_dimes`, `num_nickels`, `num_pennies`,
//! `min_coins`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! The nickel count is the family's trap: it is read after quarters AND
//! dimes are removed, so reducing modulo ten directly mis-counts
//! whenever an odd number of quarters was used. The canonical amount is
//! sampled until every denomination count is nonzero and the quarter
//! count separates from every other answer, which makes `const-zero`
//! fail everywhere and the `quarters-everything` cheat (every query
//! answered with the quarter count) exact only on its own op.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random amounts against the model.
//!
//! Trivial baselines: `const-zero` (fails outright on the canonical
//! amount) and `quarters-everything`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    NumQuarters,
    NumDimes,
    NumNickels,
    NumPennies,
    MinCoins,
}

const OP_ALL: [Op; 5] = [
    Op::NumQuarters,
    Op::NumDimes,
    Op::NumNickels,
    Op::NumPennies,
    Op::MinCoins,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::NumQuarters => "num_quarters",
            Op::NumDimes => "num_dimes",
            Op::NumNickels => "num_nickels",
            Op::NumPennies => "num_pennies",
            Op::MinCoins => "min_coins",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::NumQuarters => {
                "how many twenty-five-cent coins the greedy \
                 decomposition uses"
            }
            Op::NumDimes => {
                "how many ten-cent coins follow once the \
                 twenty-five-cent coins are taken out"
            }
            Op::NumNickels => {
                "how many five-cent coins follow once both larger \
                 denominations are taken out"
            }
            Op::NumPennies => "how many one-cent coins remain at the end",
            Op::MinCoins => {
                "the total number of coins the greedy decomposition \
                 spends"
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

fn b_num_quarters(cents: u32) -> i64 {
    (cents / 25) as i64
}

fn b_num_dimes(cents: u32) -> i64 {
    ((cents % 25) / 10) as i64
}

fn b_num_nickels(cents: u32) -> i64 {
    (((cents % 25) % 10) / 5) as i64
}

fn b_num_pennies(cents: u32) -> i64 {
    (cents % 5) as i64
}

fn b_min_coins(cents: u32) -> i64 {
    b_num_quarters(cents) + b_num_dimes(cents) + b_num_nickels(cents) + b_num_pennies(cents)
}

/// One op's answer. All five ops return scalars here, so `Out` is a
/// plain alias — no flag variant needed.
type Out = i64;

fn op_eval(op: Op, cents: u32) -> Out {
    match op {
        Op::NumQuarters => b_num_quarters(cents),
        Op::NumDimes => b_num_dimes(cents),
        Op::NumNickels => b_num_nickels(cents),
        Op::NumPennies => b_num_pennies(cents),
        Op::MinCoins => b_min_coins(cents),
    }
}

// ---- canonical input --------------------------------------------------------

fn rand_amount(rng: &mut Rng) -> u32 {
    rng.below(500) as u32
}

const CANONICAL_SEED: u64 = 0xC051_4155;

/// The canonical amount: sampled until every denomination count is
/// nonzero and the quarter count separates from every other answer.
/// Amounts of at least forty-one cents also keep every answer strictly
/// below the amount itself (echoing the input back cannot pass), so
/// `const-zero` fails everywhere and `quarters-everything` is exact
/// only on its own op. Note the dime and nickel counts are forced to
/// exactly one whenever both are nonzero, so full pairwise distinctness
/// is impossible — separation from the quarter count is what matters.
fn canonical(seed: u64) -> u32 {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let cents = rand_amount(&mut rng);
        if anchors_hold(cents) {
            return cents;
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(cents: u32) -> bool {
    let q = b_num_quarters(cents);
    let d = b_num_dimes(cents);
    let k = b_num_nickels(cents);
    let p = b_num_pennies(cents);
    let total = b_min_coins(cents);
    cents >= 41
        && q >= 2
        && d >= 1
        && k >= 1
        && p >= 1
        && p != q
        // total = q + d + k + p exceeds every ingredient, d == k == 1
        // here, and q >= 2 — so const-zero, quarters-everything and
        // echo-the-input are all separated by construction.
        && total != q
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u32, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0138;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, cents: u32| {
        cases.push((cents, spec.ops.map(|op| (op, op_eval(op, cents))).to_vec()));
    };
    // Canonical amount first.
    push(&mut cases, canonical(seed));
    // Zero cents: zero conventions everywhere.
    push(&mut cases, 0);
    // Classic near-dollar hand: 99 = 3 quarters + 2 dimes + 4 pennies.
    push(&mut cases, 99);
    // The nickel-trap amount: 41 = quarter + dime + nickel + penny.
    push(&mut cases, 41);
    for _ in 0..3 {
        let cents = rand_amount(&mut rng);
        push(&mut cases, cents);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for the amount: suffix-typed so empty-domain forms
/// infer correctly at every call site.
fn render_amount(cents: u32) -> String {
    format!("{cents}u32")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = "(cents: u32) -> i64";
    let body = match op {
        Op::NumQuarters => "(cents / 25) as i64".to_string(),
        Op::NumDimes => "((cents % 25) / 10) as i64".to_string(),
        Op::NumNickels => "(((cents % 25) % 10) / 5) as i64".to_string(),
        Op::NumPennies => "(cents % 5) as i64".to_string(),
        Op::MinCoins => [
            "let q = (cents / 25) as i64;",
            "let d = ((cents % 25) / 10) as i64;",
            "let k = (((cents % 25) % 10) / 5) as i64;",
            "let p = (cents % 5) as i64;",
            "q + d + k + p",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(cents: u32) -> i64 {{\n    todo!()\n}}\n",
        op.name()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(cents: u32) -> i64", op.name())
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
    for (cents, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  cents {}  ->  {}\n",
            render_amount(cents),
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
         one cash amount expressed in cents (always below five dollars); \
         queries read denomination counts out of the standard U.S. greedy \
         change-making decomposition — take as many of the largest coin \
         as possible, then move to the next smaller denomination. Handle \
         zero gracefully.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - Amounts stay below five dollars; you need not handle larger sums.\n\
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
    for (i, (cents, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let cents = {};\n",
            render_amount(*cents),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "cents"),
                out
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
            let call = call_src(*op, "cents");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0138;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let cents = (nx(&mut state) % 500) as u32;\n\
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
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    let _ = cents;\n    0\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the quarter count. The
/// canonical anchors keep every other denomination count and the total
/// away from that number, so this is exact only on its own op.
fn quarters_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    (cents / 25) as i64\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct CoinsFamily;

impl Generator for CoinsFamily {
    fn id(&self) -> &str {
        "coins"
    }
    fn category(&self) -> &str {
        "coin-change"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("coins", seed);

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
            id: format!("coins/{seed:016x}"),
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
                "quarters-everything".to_string(),
                quarters_everything(&spec),
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
        let g = CoinsFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Quarters: plain floor of the big-coin count.
        assert_eq!(b_num_quarters(0), 0);
        assert_eq!(b_num_quarters(24), 0);
        assert_eq!(b_num_quarters(99), 3);
        assert_eq!(b_num_quarters(499), 19);
        // Dimes read what the quarters left behind.
        assert_eq!(b_num_dimes(35), 1);
        assert_eq!(b_num_dimes(60), 1); // 60 = 2 quarters + 1 dime
        assert_eq!(b_num_dimes(26), 0);
        assert_eq!(b_num_dimes(119), 1);
        // Nickels are read after quarters AND dimes — the family trap.
        assert_eq!(b_num_nickels(15), 1);
        assert_eq!(b_num_nickels(41), 1); // odd quarter count shifts it
        assert_eq!(b_num_nickels(12), 0);
        assert_eq!(b_num_nickels(45), 0);
        // Pennies take the final remainder.
        assert_eq!(b_num_pennies(95), 0);
        assert_eq!(b_num_pennies(1), 1);
        assert_eq!(b_num_pennies(123), 3);
        assert_eq!(b_num_pennies(498), 3);
        // Total coins spent by the decomposition.
        assert_eq!(b_min_coins(0), 0);
        assert_eq!(b_min_coins(25), 1);
        assert_eq!(b_min_coins(10), 1);
        assert_eq!(b_min_coins(5), 1);
        assert_eq!(b_min_coins(4), 4);
        assert_eq!(b_min_coins(41), 4);
        assert_eq!(b_min_coins(99), 9);
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
        // Both baselines must fail under EVERY pair. On the canonical
        // amount every denomination count is nonzero, the quarter count
        // is at least two and the penny count differs from it — only
        // `num_quarters` itself matches the quarters-everything cheat,
        // and that one skip is documented.
        for seed in 0..200u64 {
            let cents = canonical(seed);
            let q = b_num_quarters(cents);
            assert!(
                cents >= 41
                    && q >= 2
                    && b_num_dimes(cents) >= 1
                    && b_num_nickels(cents) >= 1
                    && b_num_pennies(cents) >= 1
                    && b_num_pennies(cents) != q,
                "anchors broken seed {seed}"
            );
            for op in OP_ALL {
                let truth = op_eval(op, cents);
                assert_ne!(truth, 0, "const-zero survives {op:?} seed {seed}");
                if matches!(op, Op::NumQuarters) {
                    continue;
                }
                assert_ne!(truth, q, "quarters-cheat survives {op:?} seed {seed}");
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (cents, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, cents), out, "seed {seed}");
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
            assert!(!sk.contains("/ 25"));
            assert!(!sk.contains("% 25"));
            assert!(!sk.contains("/ 10"));
            assert!(!sk.contains("% 10"));
            assert!(!sk.contains("/ 5"));
            assert!(!sk.contains("% 5"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("/ 25"));
            assert!(!p.contains("% 25"));
            assert!(!p.contains("/ 10"));
            assert!(!p.contains("% 10"));
            assert!(!p.contains("/ 5"));
            assert!(!p.contains("% 5"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every call site passes exactly one argument — no commas —
        // matching the parameter list of its signature.
        for op in OP_ALL {
            let call = call_src(op, "cents");
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = CoinsFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

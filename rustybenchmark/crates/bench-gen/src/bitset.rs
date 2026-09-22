//! The `bitset` family (category `bit-sets`) — bit-level queries over a fixed
//! 64-bit set.
//!
//! Where `matrix` exercises 2-D numeric indexing and `fsm` walks a transition
//! graph, this family exercises **single-word bit algebra**: population
//! count, lowest/highest set bit, trailing-zero run, and the power-of-two
//! predicate. The domain is one `u64`; every op is a pure function of that
//! word. The seed prunes which two of five query ops are required:
//! `popcount`, `lowest_set_bit`, `highest_set_bit`, `count_trailing_zeros`,
//! `is_power_of_two`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! The canonical set is sampled until its anchor facts hold: it reaches past
//! the low byte (`> 0xFFFF`), carries at least three set bits, and keeps an
//! interior trailing-zero run (`tz ∈ 8..=60`). Together those defeat both
//! trivial cheats — the low-byte mask reads a zeroed set, and single-bit or
//! corner answers miss the multi-bit interior. A useful consequence falls out
//! of the anchor arithmetic: `tz ≥ 8` forces `x & 0xFF == 0`.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops and
//! the emitted reference share the same bodies; the differential fuzzes 3000
//! random words against the model.
//!
//! Trivial baselines: `const-zero` (fails every scalar op outright on the
//! canonical set) and `low-byte-only` (masks `x & 0xFF` first — which the
//! anchors force to zero — so every scalar answer collapses to its
//! empty-set sentinel).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    PopCount,
    LowestSetBit,
    HighestSetBit,
    CountTrailingZeros,
    IsPowerOfTwo,
}

const OP_ALL: [Op; 5] = [
    Op::PopCount,
    Op::LowestSetBit,
    Op::HighestSetBit,
    Op::CountTrailingZeros,
    Op::IsPowerOfTwo,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::PopCount => "popcount",
            Op::LowestSetBit => "lowest_set_bit",
            Op::HighestSetBit => "highest_set_bit",
            Op::CountTrailingZeros => "count_trailing_zeros",
            Op::IsPowerOfTwo => "is_power_of_two",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::IsPowerOfTwo => "bool",
            Op::PopCount | Op::LowestSetBit | Op::HighestSetBit | Op::CountTrailingZeros => "i64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::PopCount => "how many bits are set in `x`",
            Op::LowestSetBit => {
                "the index of the least-significant set bit of `x`, \
                          counting from 0; `-1` when `x` has no bits set"
            }
            Op::HighestSetBit => {
                "the index of the most-significant set bit of `x`, \
                                  counting from 0; `-1` when `x` has no bits set"
            }
            Op::CountTrailingZeros => {
                "the number of trailing zero bits below the lowest set \
                                            bit of `x`; when `x` has no bits set \
                                            this is `64`"
            }
            Op::IsPowerOfTwo => {
                "whether exactly one bit of `x` is set (a set with no bits \
                               set is not a power of two)"
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

fn b_popcount(x: u64) -> i64 {
    x.count_ones() as i64
}

fn b_lowest_set_bit(x: u64) -> i64 {
    if x == 0 {
        -1
    } else {
        x.trailing_zeros() as i64
    }
}

fn b_highest_set_bit(x: u64) -> i64 {
    if x == 0 {
        -1
    } else {
        63 - x.leading_zeros() as i64
    }
}

fn b_count_trailing_zeros(x: u64) -> i64 {
    x.trailing_zeros() as i64
}

fn b_is_power_of_two(x: u64) -> bool {
    x != 0 && x & (x - 1) == 0
}

fn op_eval(op: Op, x: u64) -> Out {
    match op {
        Op::PopCount => Out::Num(b_popcount(x)),
        Op::LowestSetBit => Out::Num(b_lowest_set_bit(x)),
        Op::HighestSetBit => Out::Num(b_highest_set_bit(x)),
        Op::CountTrailingZeros => Out::Num(b_count_trailing_zeros(x)),
        Op::IsPowerOfTwo => Out::Flag(b_is_power_of_two(x)),
    }
}

/// A query result, typed because the ops return two different shapes.
#[derive(Clone, Debug, PartialEq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    /// The result as emitted-source syntax for behavior-test assertions.
    fn lit(&self) -> String {
        match self {
            Out::Num(n) => n.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

// ---- canonical word ---------------------------------------------------------

/// The canonical set: one seeded word, retried until the anchor facts hold.
///
/// Guaranteed for every seed: strictly above the low byte, at least three
/// bits set, and a trailing-zero run between 8 and 60 inclusive. The run
/// lower bound forces `x & 0xFF == 0`, which is what turns the low-byte
/// masking cheat into an empty set.
fn canonical(seed: u64) -> u64 {
    let mut rng = Rng::new(seed ^ 0xB175_E7A1);
    for _ in 0..100_000 {
        let cand = rng.next_u64();
        if anchors_hold(cand) {
            return cand;
        }
    }
    unreachable!("canonical word sampling failed to satisfy anchors");
}

fn anchors_hold(x: u64) -> bool {
    let pc = b_popcount(x);
    let tz = b_count_trailing_zeros(x);
    x > 0xFFFF && pc >= 3 && (8..=60).contains(&tz)
}

// ---- worked examples --------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_00B7);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical word first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // The empty set: pins every convention at once (-1 / -1 / 64 / false).
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // A lone high-ish bit: the only power of two among the fixed examples,
    // which flips any baseline whose power-of-two answer happens to agree on
    // the canonical word.
    let solo = 1u64 << 10;
    cases.push((solo, spec.ops.map(|op| (op, op_eval(op, solo))).to_vec()));
    for _ in 0..3 {
        let x = rng.next_u64();
        let outs = spec.ops.map(|op| (op, op_eval(op, x))).to_vec();
        cases.push((x, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// One-line indented prose form for prompt readability.
fn prose_word(x: u64) -> String {
    format!("{} ({:#x})", x, x)
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let body = match op {
        Op::PopCount => "x.count_ones() as i64".to_string(),
        Op::LowestSetBit => "if x == 0 { -1 } else { x.trailing_zeros() as i64 }".to_string(),
        Op::HighestSetBit => "if x == 0 { -1 } else { 63 - x.leading_zeros() as i64 }".to_string(),
        Op::CountTrailingZeros => "x.trailing_zeros() as i64".to_string(),
        Op::IsPowerOfTwo => "x != 0 && x & (x - 1) == 0".to_string(),
    };
    format!(
        "pub fn {name}(x: u64) -> {ret} {{\n\
         \x20   {body}\n\
         }}\n",
        name = name,
        ret = ret,
        body = body,
    )
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {name}(x: u64) -> {ret} {{\n\
         \x20   todo!()\n\
         }}\n",
        name = op.name(),
        ret = op.ret(),
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(x: u64) -> {}", op.name(), op.ret())
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
    for (x, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  x {}  ->  {}\n", prose_word(x), results));
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
         given as `x`, a `u64` treated as a fixed-capacity bit set: bit `i` \
         of `x` corresponds to element `i`, with bit 0 the least \
         significant.\n\
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
    for (i, (x, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let x: u64 = {};\n",
            x,
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "x"),
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
    let reference = spec
        .ops
        .iter()
        .map(|op| op_fn_src(*op))
        .collect::<Vec<_>>()
        .join("")
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0058;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let x = nx(&mut state);\n\
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
        asserts = spec
            .ops
            .iter()
            .map(|op| {
                format!(
                    "        assert_eq!({call}, ref_{call});\n",
                    call = call_src(*op, "x"),
                )
            })
            .collect::<Vec<_>>()
            .join(""),
    )
}

/// Degenerate: everything zero/false.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let body = match op {
                Op::IsPowerOfTwo => "let _ = x;\n    false",
                Op::PopCount | Op::LowestSetBit | Op::HighestSetBit | Op::CountTrailingZeros => {
                    "let _ = x;\n    0"
                }
            };
            format!(
                "pub fn {name}(x: u64) -> {ret} {{\n\
                 \x20   {body}\n\
                 }}\n",
                name = op.name(),
                ret = op.ret(),
                body = body,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: read nothing above the low byte. The canonical
/// anchors force that mask to zero, so every scalar answer collapses to its
/// empty-set sentinel; exact only for `is_power_of_two`'s `false` on the
/// canonical word (flipped by the lone-bit worked example).
fn low_byte_only(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let body = match op {
                Op::PopCount => "let x = x & 0xFF;\n    x.count_ones() as i64".to_string(),
                Op::LowestSetBit => {
                    "let x = x & 0xFF;\n    if x == 0 { -1 } else { x.trailing_zeros() as i64 }"
                        .to_string()
                }
                Op::HighestSetBit => {
                    "let x = x & 0xFF;\n    if x == 0 { -1 } else { 63 - x.leading_zeros() as i64 }"
                        .to_string()
                }
                Op::CountTrailingZeros => {
                    "let x = x & 0xFF;\n    x.trailing_zeros() as i64".to_string()
                }
                Op::IsPowerOfTwo => "let x = x & 0xFF;\n    x != 0 && x & (x - 1) == 0".to_string(),
            };
            format!(
                "pub fn {name}(x: u64) -> {ret} {{\n\
                 \x20   {body}\n\
                 }}\n",
                name = op.name(),
                ret = op.ret(),
                body = body,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct BitsetFamily;

impl Generator for BitsetFamily {
    fn id(&self) -> &str {
        "bitset"
    }
    fn category(&self) -> &str {
        "bit-sets"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("bitset", seed);

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
            id: format!("bitset/{seed:016x}"),
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
            ("low-byte-only".to_string(), low_byte_only(&spec)),
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
        let g = BitsetFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        assert_eq!(b_popcount(0b1011), 3);
        assert_eq!(b_popcount(0), 0);
        assert_eq!(b_popcount(u64::MAX), 64);
        // Empty-set conventions: -1 / -1 / 64 / false.
        assert_eq!(b_lowest_set_bit(0), -1);
        assert_eq!(b_highest_set_bit(0), -1);
        assert_eq!(b_count_trailing_zeros(0), 64);
        assert!(!b_is_power_of_two(0));
        // Interior positions.
        assert_eq!(b_lowest_set_bit(0b110), 1);
        assert_eq!(b_highest_set_bit(0b110), 2);
        assert_eq!(b_count_trailing_zeros(0b101000), 3);
        assert_eq!(b_lowest_set_bit(1 << 63), 63);
        assert_eq!(b_highest_set_bit(1 << 63), 63);
        // Power-of-two predicate.
        assert!(b_is_power_of_two(1));
        assert!(b_is_power_of_two(1 << 63));
        assert!(!b_is_power_of_two(0b110));
        assert!(!b_is_power_of_two(u64::MAX));
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
        // Both baselines must fail under EVERY pair: the anchors make every
        // scalar op disagree with both `const-zero` and the emptied
        // low-byte mask on the canonical word; `is_power_of_two` agrees with
        // them there (multi-bit word ⇒ false), but the lone-bit worked
        // example flips it — and every pair also carries at least one
        // scalar op anyway.
        for seed in 0..200u64 {
            let c = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(c > 0xFFFF, "seed {seed}");
            assert!(b_popcount(c) >= 3, "seed {seed}");
            assert!((8..=60).contains(&b_count_trailing_zeros(c)), "seed {seed}");
            // Emergent invariant: the tz floor zeroes the low byte.
            assert_eq!(c & 0xFF, 0, "seed {seed}");
            // const-zero separates on every scalar op.
            for op in OP_ALL {
                if matches!(op, Op::IsPowerOfTwo) {
                    continue;
                }
                let truth = op_eval(op, c);
                assert_ne!(truth, Out::Num(0), "const-zero survives {op:?} seed {seed}");
            }
            // low-byte-only masks to the empty set: every scalar answer
            // becomes its sentinel (-1 / -1 / 64 / 0), all distinct from
            // the anchored truth.
            let masked_truth = |op: Op| -> Out {
                match op {
                    Op::PopCount => Out::Num(0),
                    Op::LowestSetBit | Op::HighestSetBit => Out::Num(-1),
                    Op::CountTrailingZeros => Out::Num(64),
                    Op::IsPowerOfTwo => Out::Flag(false),
                }
            };
            for op in OP_ALL {
                if matches!(op, Op::IsPowerOfTwo) {
                    continue; // agrees on canonical; lone-bit example flips it
                }
                let truth = op_eval(op, c);
                assert_ne!(
                    truth,
                    masked_truth(op),
                    "low-byte-only survives {op:?} seed {seed}"
                );
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (x, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, x), out, "seed {seed}");
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
                // Match the `pub fn` line: bare names substring-collide
                // (`lowest_set_bit` / `highest_set_bit` share `_set_bit`).
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
            // Method-call-shaped leak tokens: bare substrings collide with
            // the required `count_trailing_zeros` name itself.
            assert!(!sk.contains(".count_ones()"));
            assert!(!sk.contains(".leading_zeros()"));
            assert!(!sk.contains(".trailing_zeros()"));
            assert!(!sk.contains("& (x - 1)"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(".count_ones()"));
            assert!(!p.contains(".leading_zeros()"));
            assert!(!p.contains(".trailing_zeros()"));
            assert!(!p.contains("& (x - 1)"));
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
            let call = call_src(op, "x");
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
        let g = BitsetFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

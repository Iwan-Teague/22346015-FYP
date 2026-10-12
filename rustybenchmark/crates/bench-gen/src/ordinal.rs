//! The `ordinal` family (category `number-formatting`) — English ordinal
//! rendering over a seeded integer.
//!
//! Where `roman` renders classical numerals and `letter-grade` classifies
//! bands, this family exercises **number formatting**: the ordinal suffix
//! with the eleven-through-thirteen exception, the full ordinal string,
//! the teen predicate, and the two decimal digits the rule reads. The
//! domain is one number `n: u64` from zero through nine hundred
//! ninety-nine. The seed prunes which two of five query ops are required:
//! `ordinal_suffix`, `ordinal`, `is_teen`, `last_digit`, `tens_digit`.
//! C(5,2) = **10 distinct skills**, above the diversity floor; op names
//! are semantic.
//!
//! The canonical number is sampled until its anchor facts hold: the final
//! digit is one, two, or three while the last two digits are NOT eleven,
//! twelve, or thirteen — so the suffix is st, nd, or rd and any solution
//! answering a constant `th` dies immediately — and both readable digits
//! are nonzero and distinct. The teen predicate answers false there (both
//! trivial baselines agree with that `false`), which the pinned teen
//! worked examples flip.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random numbers against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical example) and `value-everything` (every query answered with
//! the raw value).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    OrdinalSuffix,
    Ordinal,
    IsTeen,
    LastDigit,
    TensDigit,
}

const OP_ALL: [Op; 5] = [
    Op::OrdinalSuffix,
    Op::Ordinal,
    Op::IsTeen,
    Op::LastDigit,
    Op::TensDigit,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::OrdinalSuffix => "ordinal_suffix",
            Op::Ordinal => "ordinal",
            Op::IsTeen => "is_teen",
            Op::LastDigit => "last_digit",
            Op::TensDigit => "tens_digit",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::OrdinalSuffix => {
                "the two-letter suffix: st after a final digit of one, nd \
                 after two, rd after three, th otherwise — but a final pair \
                 of eleven, twelve, or thirteen always takes th"
            }
            Op::Ordinal => {
                "the number rendered in decimal with its ordinal suffix \
                 appended, such as twenty-one followed by st"
            }
            Op::IsTeen => {
                "whether the final two digits are eleven, twelve, or \
                 thirteen — the spelling exception that forces th"
            }
            Op::LastDigit => "the final decimal digit, as a number",
            Op::TensDigit => {
                "the tens digit — the second-to-last decimal digit — as a \
                 number; single-digit inputs have zero there"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::OrdinalSuffix | Op::Ordinal => "String",
            Op::IsTeen => "bool",
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

/// The ordinal suffix with the teen exception.
fn b_ordinal_suffix(n: u64) -> String {
    let teens = n % 100;
    let last = n % 10;
    if (11..=13).contains(&teens) {
        "th".to_string()
    } else if last == 1 {
        "st".to_string()
    } else if last == 2 {
        "nd".to_string()
    } else if last == 3 {
        "rd".to_string()
    } else {
        "th".to_string()
    }
}

/// The number rendered in decimal with its suffix appended.
fn b_ordinal(n: u64) -> String {
    let teens = n % 100;
    let last = n % 10;
    let suffix = if (11..=13).contains(&teens) {
        "th"
    } else if last == 1 {
        "st"
    } else if last == 2 {
        "nd"
    } else if last == 3 {
        "rd"
    } else {
        "th"
    };
    format!("{n}{suffix}")
}

/// Whether the final two digits are eleven through thirteen.
fn b_is_teen(n: u64) -> bool {
    (11..=13).contains(&(n % 100))
}

/// The final decimal digit.
fn b_last_digit(n: u64) -> i64 {
    (n % 10) as i64
}

/// The tens digit; single-digit inputs read zero.
fn b_tens_digit(n: u64) -> i64 {
    ((n / 10) % 10) as i64
}

/// The answer shape: scalars as `Num`, predicates as `Flag`, text as `Str`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
    Str(String),
}

impl Out {
    fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
            Out::Str(s) => format!("{s:?}"),
        }
    }
}

fn op_eval(op: Op, n: u64) -> Out {
    match op {
        Op::OrdinalSuffix => Out::Str(b_ordinal_suffix(n)),
        Op::Ordinal => Out::Str(b_ordinal(n)),
        Op::IsTeen => Out::Flag(b_is_teen(n)),
        Op::LastDigit => Out::Num(b_last_digit(n)),
        Op::TensDigit => Out::Num(b_tens_digit(n)),
    }
}

// ---- canonical number -------------------------------------------------------

/// The canonical number: sampled 0..=999 and retried until the anchor facts
/// hold.
///
/// Guaranteed for every seed: not a teen, final digit one/two/three (so the
/// suffix is st/nd/rd and any constant-`th` solution dies), and both digits
/// nonzero and distinct — which also forces a two-digit-or-more input, so a
/// cheat echoing the raw value is wrong on both digit answers. The teen
/// predicate answers false on the canonical example (both baselines agree
/// with that `false`), and the pinned teen worked examples flip it.
fn canonical(seed: u64) -> u64 {
    let mut rng = Rng::new(seed ^ 0x0BD1_4A11);
    for _ in 0..100_000 {
        let n = rng.below(1000);
        if anchors_hold(n) {
            return n;
        }
    }
    unreachable!("canonical number sampling failed to satisfy anchors");
}

fn anchors_hold(n: u64) -> bool {
    !b_is_teen(n)
        && matches!(b_last_digit(n), 1..=3)
        && b_last_digit(n) != 0
        && b_tens_digit(n) != 0
        && b_last_digit(n) != b_tens_digit(n)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0144);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical number first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // Zero: the th corner — "0th".
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // Single digits take st/nd/rd with no teen confusion.
    cases.push((1, spec.ops.map(|op| (op, op_eval(op, 1))).to_vec()));
    cases.push((2, spec.ops.map(|op| (op, op_eval(op, 2))).to_vec()));
    cases.push((3, spec.ops.map(|op| (op, op_eval(op, 3))).to_vec()));
    // A bare teen: final digit one yet the suffix is th.
    cases.push((11, spec.ops.map(|op| (op, op_eval(op, 11))).to_vec()));
    // An embedded teen: the exception survives further digits.
    cases.push((111, spec.ops.map(|op| (op, op_eval(op, 111))).to_vec()));
    for _ in 0..2 {
        let n = rng.below(1000);
        let outs = spec.ops.map(|op| (op, op_eval(op, n))).to_vec();
        cases.push((n, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the suffix types it as `u64`.
fn render_u64(n: u64) -> String {
    format!("{n}u64")
}

/// The shared suffix rule as emitted lines; `bound` prefixes the chain so it
/// can serve as a `let` binding or a bare tail expression.
fn suffix_chain_src(bound: bool) -> Vec<&'static str> {
    let mut lines: Vec<&'static str> = if bound {
        vec!["let suffix = ("]
    } else {
        vec![]
    };
    lines.extend([
        "if (11..=13).contains(&(n % 100)) {",
        "    \"th\"",
        "} else if n % 10 == 1 {",
        "    \"st\"",
        "} else if n % 10 == 2 {",
        "    \"nd\"",
        "} else if n % 10 == 3 {",
        "    \"rd\"",
        "} else {",
        "    \"th\"",
        "}",
    ]);
    lines
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(n: u64) -> {ret}");
    let body = match op {
        Op::OrdinalSuffix => {
            let mut lines = suffix_chain_src(true);
            lines.push(");");
            lines.push("suffix.to_string()");
            lines.join("\n    ")
        }
        Op::Ordinal => {
            let mut lines = suffix_chain_src(true);
            lines.push(");");
            lines.push("format!(\"{n}{suffix}\")");
            lines.join("\n    ")
        }
        // A property of the raw number alone.
        Op::IsTeen => "(11..=13).contains(&(n % 100))".to_string(),
        Op::LastDigit => "(n % 10) as i64".to_string(),
        Op::TensDigit => "((n / 10) % 10) as i64".to_string(),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(n: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(n: u64) -> {}", op.name(), op.ret())
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
        s.push_str(&format!("  n {}  ->  {}\n", render_u64(n), results));
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
         one number `n` of type `u64`, from zero through nine hundred \
         ninety-nine; ordinal suffixes follow English convention with the \
         eleven-through-thirteen exception.\n\
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
            render_u64(*n),
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0144;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = nx(&mut state) % 1000;\n\
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
                "String" => "String::new()",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = n;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the raw value no matter what was asked.
/// The canonical anchors keep both digit answers small and nonzero while the
/// number itself is at least ten, the suffix strings are never digits-only,
/// and the teen predicate answers false there — wrong on all five ops.
fn value_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    false\n}}\n"),
                "String" => format!("{sig} {{\n    n.to_string()\n}}\n"),
                _ => format!("{sig} {{\n    n as i64\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct OrdinalFamily;

impl Generator for OrdinalFamily {
    fn id(&self) -> &str {
        "ordinal"
    }
    fn category(&self) -> &str {
        "number-formatting"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("ordinal", seed);

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
            id: format!("ordinal/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure string formatting — no unsafe anywhere near it.
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
            ("value-everything".to_string(), value_everything(&spec)),
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
        let g = OrdinalFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Suffixes across the whole rule, teens included.
        assert_eq!(b_ordinal_suffix(0), "th");
        assert_eq!(b_ordinal_suffix(1), "st");
        assert_eq!(b_ordinal_suffix(2), "nd");
        assert_eq!(b_ordinal_suffix(3), "rd");
        assert_eq!(b_ordinal_suffix(4), "th");
        assert_eq!(b_ordinal_suffix(11), "th");
        assert_eq!(b_ordinal_suffix(12), "th");
        assert_eq!(b_ordinal_suffix(13), "th");
        assert_eq!(b_ordinal_suffix(21), "st");
        assert_eq!(b_ordinal_suffix(22), "nd");
        assert_eq!(b_ordinal_suffix(23), "rd");
        // Embedded teens keep the exception; lookalikes do not.
        assert_eq!(b_ordinal_suffix(111), "th");
        assert_eq!(b_ordinal_suffix(211), "th");
        assert_eq!(b_ordinal_suffix(613), "th");
        assert_eq!(b_ordinal_suffix(912), "th");
        assert_eq!(b_ordinal_suffix(101), "st");
        assert_eq!(b_ordinal_suffix(321), "st");
        assert_eq!(b_ordinal_suffix(422), "nd");
        // Full ordinals.
        assert_eq!(b_ordinal(0), "0th");
        assert_eq!(b_ordinal(1), "1st");
        assert_eq!(b_ordinal(11), "11th");
        assert_eq!(b_ordinal(21), "21st");
        assert_eq!(b_ordinal(92), "92nd");
        assert_eq!(b_ordinal(103), "103rd");
        assert_eq!(b_ordinal(214), "214th");
        // Teen predicate: bare and embedded teens, non-teen lookalikes.
        for n in [11u64, 12, 13, 111, 212, 313] {
            assert!(b_is_teen(n), "{n}");
        }
        for n in [10u64, 14, 19, 21, 110, 321, 422] {
            assert!(!b_is_teen(n), "{n}");
        }
        // Digits the rule reads.
        for d in 0..10u64 {
            assert_eq!(b_last_digit(d), d as i64);
        }
        assert_eq!(b_last_digit(381), 1);
        assert_eq!(b_last_digit(411), 1);
        for d in 0..10u64 {
            assert_eq!(b_tens_digit(d), 0);
        }
        assert_eq!(b_tens_digit(42), 4);
        assert_eq!(b_tens_digit(999), 9);
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
        // Both baselines must fail under EVERY pair with no skips on the
        // scalars and strings: the anchors force a non-teen number whose
        // final digit is one/two/three (suffix st/nd/rd — no constant th)
        // and whose two digits are nonzero and distinct, with the number
        // itself at least ten so echoing it is wrong on both digits. The
        // teen flag answers false there (both baselines agree); the pinned
        // teen examples flip it.
        for seed in 0..200u64 {
            let n = canonical(seed);
            let last = b_last_digit(n);
            let tens = b_tens_digit(n);
            // Anchor facts the sampler enforces.
            assert!(!b_is_teen(n), "seed {seed}");
            assert!(matches!(last, 1..=3), "seed {seed}");
            assert_ne!(last, 0, "const-zero survives at {n} seed {seed}");
            assert_ne!(tens, 0, "const-zero survives at {n} seed {seed}");
            assert_ne!(last, tens, "seed {seed}");
            assert!(n >= 10, "seed {seed}");
            // value-everything echoes the raw number.
            for v in [last, tens] {
                assert_ne!(v, n as i64, "value-everything survives at {n} seed {seed}");
            }
            assert_ne!(b_ordinal_suffix(n), n.to_string(), "seed {seed}");
            assert_ne!(b_ordinal(n), n.to_string(), "seed {seed}");
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
                // Match the `pub fn` line plus the paren so no bare-name
                // substring leaks (`ordinal` prefixes `ordinal_suffix`).
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
            // Solution-shaped leak tokens must stay out of the skeleton;
            // the worked examples legitimately show outputs, never rules.
            assert!(!sk.contains("% 100"));
            assert!(!sk.contains("% 10"));
            assert!(!sk.contains("/ 10"));
            assert!(!sk.contains(">= 11"));
            assert!(!sk.contains("<= 13"));
            assert!(!sk.contains("teens"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("% 100"));
            assert!(!p.contains("% 10"));
            assert!(!p.contains("/ 10"));
            assert!(!p.contains(">= 11"));
            assert!(!p.contains("<= 13"));
            assert!(!p.contains("teens"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here is unary: no call site may carry a comma.
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
        let g = OrdinalFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

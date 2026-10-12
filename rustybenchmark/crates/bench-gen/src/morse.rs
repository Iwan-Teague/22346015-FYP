//! The `morse` family (category `signal-codes`) — ITU numeric-code
//! rendering for one seeded decimal digit.
//!
//! Where `ordinal` decorates a number with a suffix and `roman` rewrites
//! it in numerals, this family exercises **symbol construction**: the
//! five-slot Morse code for a single digit, the dot and dash counts it
//! implies, the leading-symbol predicate, and the transmission length
//! that bills three units per dash. The domain is one digit `digit: u32`
//! from zero through nine. The seed prunes which two of five query ops
//! are required: `dot_count`, `dash_count`, `code`, `starts_with_dash`,
//! `signal_length`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! The canonical digit is sampled until its anchor facts hold: strictly
//! interior (at least one dot AND one dash, which rules out the all-dash
//! zero and the all-dot five), opening with a dot (so the predicate
//! answers false there — flipped by pinned high-digit examples), and
//! with the signal length distinct from both counts. That makes
//! `const-zero` wrong on all three scalars outright, and
//! `dot-everything` wrong on everything except its own dot tally.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random digits against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical example) and `dot-everything` (every query answered with
//! the dot tally — or the all-dot string).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    DotCount,
    DashCount,
    Code,
    StartsWithDash,
    SignalLength,
}

const OP_ALL: [Op; 5] = [
    Op::DotCount,
    Op::DashCount,
    Op::Code,
    Op::StartsWithDash,
    Op::SignalLength,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::DotCount => "dot_count",
            Op::DashCount => "dash_count",
            Op::Code => "code",
            Op::StartsWithDash => "starts_with_dash",
            Op::SignalLength => "signal_length",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::DotCount => {
                "how many dots the five-symbol code carries: the digit \
                 itself for one through five, mirrored down again for six \
                 through nine, and zero for the all-dash zero"
            }
            Op::DashCount => {
                "how many dashes fill the remaining slots — always five \
                 minus the dot count"
            }
            Op::Code => {
                "the five-symbol code itself: one through five open with \
                 that many dots and finish with dashes, six through nine \
                 reverse the pattern and open with dashes, and zero is \
                 five dashes in a row"
            }
            Op::StartsWithDash => {
                "whether the code's first symbol is a dash rather than a \
                 dot — true for zero and for six through nine"
            }
            Op::SignalLength => {
                "the transmission cost: one unit per dot plus three units \
                 per dash"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::Code => "String",
            Op::StartsWithDash => "bool",
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

/// Dots in the code: the digit itself below six, mirrored above, zero
/// for the all-dash zero.
fn b_dot_count(digit: u32) -> i64 {
    if digit == 0 {
        0
    } else if digit <= 5 {
        digit as i64
    } else {
        10 - digit as i64
    }
}

/// Dashes complete the five symbols.
fn b_dash_count(digit: u32) -> i64 {
    5 - b_dot_count(digit)
}

/// The five-symbol rendering; low digits lead with dots, high digits
/// (and zero) lead with dashes.
fn b_code(digit: u32) -> String {
    let dots = b_dot_count(digit);
    let dashes = b_dash_count(digit);
    let mut s = String::new();
    if b_starts_with_dash(digit) {
        for _ in 0..dashes {
            s.push('-');
        }
        for _ in 0..dots {
            s.push('.');
        }
    } else {
        for _ in 0..dots {
            s.push('.');
        }
        for _ in 0..dashes {
            s.push('-');
        }
    }
    s
}

/// A dash opener: the all-dash zero and every digit from six up.
fn b_starts_with_dash(digit: u32) -> bool {
    digit == 0 || digit >= 6
}

/// One unit per dot plus three per dash.
fn b_signal_length(digit: u32) -> i64 {
    b_dot_count(digit) + 3 * b_dash_count(digit)
}

/// The answer shape: scalars as `Num`, predicates as `Flag`, the code
/// as `Str`.
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

fn op_eval(op: Op, digit: u32) -> Out {
    match op {
        Op::DotCount => Out::Num(b_dot_count(digit)),
        Op::DashCount => Out::Num(b_dash_count(digit)),
        Op::Code => Out::Str(b_code(digit)),
        Op::StartsWithDash => Out::Flag(b_starts_with_dash(digit)),
        Op::SignalLength => Out::Num(b_signal_length(digit)),
    }
}

// ---- canonical digit --------------------------------------------------------

/// The canonical digit: sampled 0..=9 and retried until the anchor facts
/// hold.
///
/// Guaranteed for every seed: at least one dot AND one dash (interior
/// digits only — never the all-dash zero or the all-dot five), opening
/// with a dot so the predicate answers false there (both cheats agree,
/// and the pinned high-digit examples flip them), and with the signal
/// length away from both counts. That makes `const-zero` wrong on all
/// three scalars outright.
fn canonical(seed: u64) -> u32 {
    let mut rng = Rng::new(seed ^ 0xE5E5_D161);
    for _ in 0..100_000 {
        let d = rng.below(10) as u32;
        if anchors_hold(d) {
            return d;
        }
    }
    unreachable!("canonical digit sampling failed to satisfy anchors");
}

fn anchors_hold(digit: u32) -> bool {
    let dots = b_dot_count(digit);
    let dashes = b_dash_count(digit);
    let len = b_signal_length(digit);
    dots >= 1
        && dashes >= 1
        && !b_starts_with_dash(digit)
        && dots != dashes
        && len != dots
        && len != dashes
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u32, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0154);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical digit first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // Zero: the all-dash corner — no dots at all.
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // Five: the all-dot corner — the reversal midpoint.
    cases.push((5, spec.ops.map(|op| (op, op_eval(op, 5))).to_vec()));
    // Nine: the deep-reversal corner — one dot after four dashes.
    cases.push((9, spec.ops.map(|op| (op, op_eval(op, 9))).to_vec()));
    for _ in 0..3 {
        let d = rng.below(10) as u32;
        let outs = spec.ops.map(|op| (op, op_eval(op, d))).to_vec();
        cases.push((d, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the suffix types it as `u32`.
fn render_u32(d: u32) -> String {
    format!("{d}u32")
}

/// The shared mirror rule, emitted verbatim; every scalar body inlines
/// it because a seed's pair may not select `dot_count`.
const DOTS_RULE: &[&str] = &[
    "let dots = if digit == 0 {",
    "    0i64",
    "} else if digit <= 5 {",
    "    digit as i64",
    "} else {",
    "    10 - digit as i64",
    "};",
];

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(digit: u32) -> {ret}");
    let body = match op {
        Op::DotCount => {
            let mut lines: Vec<&str> = DOTS_RULE.to_vec();
            lines.push("dots");
            lines.join("\n    ")
        }
        Op::DashCount => {
            let mut lines: Vec<&str> = DOTS_RULE.to_vec();
            lines.push("5 - dots");
            lines.join("\n    ")
        }
        Op::Code => {
            let mut lines: Vec<&str> = DOTS_RULE.to_vec();
            lines.extend([
                "let dashes = 5 - dots;",
                "let mut s = String::new();",
                "if digit == 0 || digit >= 6 {",
                "    for _ in 0..dashes {",
                "        s.push('-');",
                "    }",
                "    for _ in 0..dots {",
                "        s.push('.');",
                "    }",
                "} else {",
                "    for _ in 0..dots {",
                "        s.push('.');",
                "    }",
                "    for _ in 0..dashes {",
                "        s.push('-');",
                "    }",
                "}",
                "s",
            ]);
            lines.join("\n    ")
        }
        // A property of the raw digit alone.
        Op::StartsWithDash => "digit == 0 || digit >= 6".to_string(),
        Op::SignalLength => {
            let mut lines: Vec<&str> = DOTS_RULE.to_vec();
            lines.push("dots + 3 * (5 - dots)");
            lines.join("\n    ")
        }
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(digit: u32) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(digit: u32) -> {}", op.name(), op.ret())
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
    for (digit, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  digit {}  ->  {}\n", render_u32(digit), results));
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
         one decimal digit `digit` of type `u32`, from zero through nine; \
         every digit maps to a five-symbol Morse code under the ITU \
         numeric convention.\n\
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
    for (i, (digit, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let digit = {};\n",
            render_u32(*digit),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "digit"),
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
            let call = call_src(*op, "digit");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0154;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let digit = (nx(&mut state) % 10) as u32;\n\
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
            format!("{sig} {{\n    let _ = digit;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the dot tally no matter what was asked.
/// The canonical anchors keep the dash count and signal length away from
/// the dot tally (dashes >= 1 makes the length strictly larger; the two
/// counts differ by construction), so this is exact only on `dot_count`
/// itself. The all-dot string never matches a code that must carry at
/// least one dash, and the predicate answers false where both cheats
/// agree — flipped by the pinned high-digit examples.
fn dot_everything(spec: &Spec) -> String {
    let dots_body = |tail: &str| {
        let mut lines: Vec<&str> = DOTS_RULE.to_vec();
        lines.push(tail);
        lines.join("\n    ")
    };
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    false\n}}\n"),
                "String" => {
                    format!("{sig} {{\n    let _ = digit;\n    \".....\".to_string()\n}}\n")
                }
                _ => format!("{sig} {{\n    {}\n}}\n", dots_body("dots")),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct MorseFamily;

impl Generator for MorseFamily {
    fn id(&self) -> &str {
        "morse"
    }
    fn category(&self) -> &str {
        "signal-codes"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("morse", seed);

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
            id: format!("morse/{seed:016x}"),
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
            ("dot-everything".to_string(), dot_everything(&spec)),
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

    /// The `dot-everything` cheat's answer for one op, simulated natively.
    fn dot_cheat(op: Op, digit: u32) -> Out {
        match op {
            Op::DotCount => Out::Num(b_dot_count(digit)),
            Op::DashCount | Op::SignalLength => Out::Num(b_dot_count(digit)),
            Op::StartsWithDash => Out::Flag(false),
            Op::Code => Out::Str(".....".to_string()),
        }
    }

    #[test]
    fn generation_is_deterministic() {
        let g = MorseFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Codes across every zone of the digit range.
        assert_eq!(b_code(0), "-----");
        assert_eq!(b_code(1), ".----");
        assert_eq!(b_code(3), "...--");
        assert_eq!(b_code(5), ".....");
        assert_eq!(b_code(6), "-....");
        assert_eq!(b_code(9), "----.");
        // Dot and dash counts mirror around five.
        assert_eq!(b_dot_count(0), 0);
        assert_eq!(b_dot_count(2), 2);
        assert_eq!(b_dot_count(5), 5);
        assert_eq!(b_dot_count(7), 3);
        assert_eq!(b_dash_count(1), 4);
        assert_eq!(b_dash_count(6), 1);
        assert_eq!(b_dash_count(9), 4);
        assert_eq!(b_dash_count(0), 5);
        // Dash openers: zero and the high half.
        assert!(b_starts_with_dash(0));
        assert!(b_starts_with_dash(6));
        assert!(b_starts_with_dash(9));
        assert!(!b_starts_with_dash(1));
        assert!(!b_starts_with_dash(5));
        // Transmission length bills three per dash.
        assert_eq!(b_signal_length(5), 5);
        assert_eq!(b_signal_length(1), 13);
        assert_eq!(b_signal_length(6), 7);
        assert_eq!(b_signal_length(0), 15);
        assert_eq!(b_signal_length(9), 13);
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
        // const-zero must fail outright on all three scalars; the
        // dot-everything cheat is exact only on its own dot tally. Both
        // cheats answer `false` on the predicate mid-canonical — that
        // agreement is flipped by the pinned high-digit examples (0, 9),
        // checked in worked_examples_agree_with_eval.
        for seed in 0..200u64 {
            let d = canonical(seed);
            let dots = b_dot_count(d);
            let dashes = b_dash_count(d);
            // Anchor facts the sampler enforces.
            assert!(dots >= 1, "seed {seed}");
            assert!(dashes >= 1, "seed {seed}");
            assert!(!b_starts_with_dash(d), "seed {seed}");
            assert_ne!(dots, dashes, "seed {seed}");
            let len = b_signal_length(d);
            for v in [dots, dashes, len] {
                assert_ne!(v, 0, "const-zero survives at digit {d} seed {seed}");
            }
            for op in OP_ALL {
                if matches!(op, Op::DotCount | Op::StartsWithDash) {
                    // Documented skips: the dot tally is the cheat's own
                    // answer, and both sides answer `false` on the
                    // predicate mid-canonical (flipped by pinned
                    // high-digit examples 0 and 9).
                    continue;
                }
                assert_ne!(
                    op_eval(op, d),
                    dot_cheat(op, d),
                    "dot-everything survives at {op:?} digit {d} seed {seed}"
                );
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (digit, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, digit), out, "seed {seed}");
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
                // Paren-suffixed so no bare-name prefix can false-match.
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
            // Solution-shaped leak tokens must stay out of the skeleton.
            assert!(!sk.contains("push("));
            assert!(!sk.contains(".repeat("));
            assert!(!sk.contains("for _ in"));
            assert!(!sk.contains("- digit as i64"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("push("));
            assert!(!p.contains(".repeat("));
            assert!(!p.contains("for _ in"));
            assert!(!p.contains("- digit as i64"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here is unary: no call site may carry a comma.
        for op in OP_ALL {
            let call = call_src(op, "digit");
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
        let g = MorseFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

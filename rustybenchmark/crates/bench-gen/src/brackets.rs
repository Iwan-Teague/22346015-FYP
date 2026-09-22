//! The `brackets` family (category `bracket-balance`) — probing a seeded
//! bracket sequence.
//!
//! Where `hex-color` parses a fixed-shape token and `caesar` shifts
//! letters, this family exercises **running-balance scans**: counting,
//! nesting depth, balance, and deficit over strings drawn from the
//! six-character alphabet `( ) [ ] { }`. Pairing is type-blind: any opener
//! raises the level and any closer lowers it. The seed prunes which two of
//! five query ops are required: `open_count`, `close_count`, `depth`,
//! `is_balanced`, `max_deficit`. C(5,2) = **10 distinct skills**, above the
//! diversity floor; op names are semantic.
//!
//! The canonical sequence is sampled until its anchor facts hold: nonempty,
//! unbalanced (a real deficit exists), nesting at least two deep, nonzero
//! counts on both sides, and all four numeric answers mutually distinct.
//! Those make `const-zero` wrong on every scalar there, and
//! `open-everything` wrong on the other three scalars; both cheats' `false`
//! balance flag agrees on the unbalanced canonical and is flipped by the
//! pinned balanced worked examples.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random sequences against the model.
//!
//! Trivial baselines: `const-zero` (zeroes and a false flag everywhere) and
//! `open-everything` (every scalar answered with the opening-bracket count).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    OpenCount,
    CloseCount,
    Depth,
    IsBalanced,
    MaxDeficit,
}

const OP_ALL: [Op; 5] = [
    Op::OpenCount,
    Op::CloseCount,
    Op::Depth,
    Op::IsBalanced,
    Op::MaxDeficit,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::OpenCount => "open_count",
            Op::CloseCount => "close_count",
            Op::Depth => "depth",
            Op::IsBalanced => "is_balanced",
            Op::MaxDeficit => "max_deficit",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::OpenCount => {
                "how many opening brackets — round, square, or curly — \
                 appear anywhere in the sequence"
            }
            Op::CloseCount => {
                "how many closing brackets — round, square, or curly — \
                 appear anywhere in the sequence"
            }
            Op::Depth => {
                "the maximum level reached while scanning left to right, \
                 where any opening bracket raises the level by one and any \
                 closing bracket lowers it by one; zero when no opening \
                 bracket appears"
            }
            Op::IsBalanced => {
                "whether the running level never drops below zero and ends \
                 at exactly zero after the whole scan"
            }
            Op::MaxDeficit => {
                "how far below zero the running level ever falls, reported \
                 as a positive magnitude; zero when the level never drops \
                 below zero"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::IsBalanced => "bool",
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

/// Count of openers: round, square, or curly.
fn b_open_count(text: &str) -> i64 {
    text.chars()
        .filter(|c| matches!(c, '(' | '[' | '{'))
        .count() as i64
}

/// Count of closers: round, square, or curly.
fn b_close_count(text: &str) -> i64 {
    text.chars()
        .filter(|c| matches!(c, ')' | ']' | '}'))
        .count() as i64
}

/// Maximum level reached during the left-to-right scan.
fn b_depth(text: &str) -> i64 {
    let mut level = 0i64;
    let mut best = 0i64;
    for c in text.chars() {
        if matches!(c, '(' | '[' | '{') {
            level += 1;
            if level > best {
                best = level;
            }
        } else {
            level -= 1;
        }
    }
    best
}

/// The running level never dips below zero and finishes at zero.
fn b_is_balanced(text: &str) -> bool {
    let mut level = 0i64;
    for c in text.chars() {
        if matches!(c, '(' | '[' | '{') {
            level += 1;
        } else {
            level -= 1;
            if level < 0 {
                return false;
            }
        }
    }
    level == 0
}

/// Deepest dip below zero, reported as a positive magnitude (0 if never).
fn b_max_deficit(text: &str) -> i64 {
    let mut level = 0i64;
    let mut worst = 0i64;
    for c in text.chars() {
        if matches!(c, '(' | '[' | '{') {
            level += 1;
        } else {
            level -= 1;
            if level < worst {
                worst = level;
            }
        }
    }
    -worst
}

/// The answer shape: numeric queries as `Num`, the balance flag as `Flag`.
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

fn op_eval(op: Op, text: &str) -> Out {
    match op {
        Op::OpenCount => Out::Num(b_open_count(text)),
        Op::CloseCount => Out::Num(b_close_count(text)),
        Op::Depth => Out::Num(b_depth(text)),
        Op::IsBalanced => Out::Flag(b_is_balanced(text)),
        Op::MaxDeficit => Out::Num(b_max_deficit(text)),
    }
}

// ---- canonical sequence -----------------------------------------------------

const CANONICAL_SEED: u64 = 0xB4AC_5E11;

const BRACKET_BYTES: &[u8; 6] = b"()[]{}";

/// Uniform random bracket sequence.
fn rand_text(rng: &mut Rng) -> String {
    let n = 1 + rng.below(9);
    let mut s = String::new();
    for _ in 0..n {
        s.push(BRACKET_BYTES[rng.below(6) as usize] as char);
    }
    s
}

/// The canonical sequence: sampled and retried until the anchor facts hold.
///
/// Guaranteed for every seed: nonempty, unbalanced with a real deficit,
/// nesting at least two deep, nonzero counts on both sides, and all four
/// numeric answers mutually distinct. That makes `const-zero` wrong on every
/// scalar there and `open-everything` wrong on the other three; both flags
/// read false mid-canonical (the sequence is unbalanced) and are flipped by
/// the pinned balanced examples.
fn canonical(seed: u64) -> String {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let t = rand_text(&mut rng);
        if anchors_hold(&t) {
            return t;
        }
    }
    unreachable!("canonical sequence sampling failed to satisfy anchors");
}

fn anchors_hold(text: &str) -> bool {
    let oc = b_open_count(text);
    let cc = b_close_count(text);
    let d = b_depth(text);
    let md = b_max_deficit(text);
    !text.is_empty()
        && oc > 0
        && cc > 0
        && d >= 2
        && !b_is_balanced(text)
        && md >= 1
        && oc != cc
        && oc != d
        && oc != md
        && cc != d
        && cc != md
        && d != md
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (String, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0152;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, c: &str| {
        cases.push((
            c.to_string(),
            spec.ops.map(|op| (op, op_eval(op, c))).to_vec(),
        ));
    };
    // Canonical sequence first.
    push(&mut cases, &canonical(seed));
    // Empty: every count zero, depth zero, balance vacuously true.
    push(&mut cases, "");
    // Minimal balanced pair flips the cheats' false flag.
    push(&mut cases, "()");
    // Surplus openers: unbalanced with depth three and no deficit.
    push(&mut cases, "(((");
    // Pure deficit: the level dips without ever rising first.
    push(&mut cases, ")(");
    for _ in 0..3 {
        let t = rand_text(&mut rng);
        push(&mut cases, &t);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site — a quoted string.
fn render_text(t: &str) -> String {
    format!("{t:?}")
}

/// The opener/closer membership test shared by the emitted bodies.
fn is_opener_src() -> &'static str {
    "matches!(c, '(' | '[' | '{')"
}

fn is_closer_src() -> &'static str {
    "matches!(c, ')' | ']' | '}')"
}

/// Emitted body for the two counting queries.
fn count_body(closer: bool) -> String {
    let pred = if closer {
        is_closer_src()
    } else {
        is_opener_src()
    };
    format!("    text.chars()\n        .filter(|&c| {pred})\n        .count() as i64\n")
}

/// Emitted body for depth and deficit — one scan tracking level plus extreme.
fn scan_body(deficit: bool) -> String {
    let mut s = String::new();
    s.push_str("    let mut level = 0i64;\n");
    if deficit {
        s.push_str("    let mut worst = 0i64;\n");
    } else {
        s.push_str("    let mut best = 0i64;\n");
    }
    s.push_str(&format!(
        "    for c in text.chars() {{\n        if {} {{\n            level += 1;\n",
        is_opener_src()
    ));
    if !deficit {
        s.push_str("            if level > best {\n                best = level;\n            }\n");
    }
    s.push_str("        } else {\n            level -= 1;\n");
    if deficit {
        s.push_str(
            "            if level < worst {\n                worst = level;\n            }\n",
        );
        s.push_str("        }\n    }\n    -worst\n");
    } else {
        s.push_str("        }\n    }\n    best\n");
    }
    s
}

fn balanced_body() -> String {
    let mut s = String::new();
    s.push_str("    let mut level = 0i64;\n");
    s.push_str(&format!(
        "    for c in text.chars() {{\n        if {} {{\n            level += 1;\n        }} else {{\n            level -= 1;\n            if level < 0 {{\n                return false;\n            }}\n        }}\n    }}\n    level == 0\n",
        is_opener_src()
    ));
    s
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    match op {
        Op::OpenCount => format!(
            "pub fn {name}(text: &str) -> {ret} {{\n{}\n}}\n",
            count_body(false)
        ),
        Op::CloseCount => format!(
            "pub fn {name}(text: &str) -> {ret} {{\n{}\n}}\n",
            count_body(true)
        ),
        Op::Depth => format!(
            "pub fn {name}(text: &str) -> {ret} {{\n{}\n}}\n",
            scan_body(false)
        ),
        Op::IsBalanced => format!(
            "pub fn {name}(text: &str) -> {ret} {{\n{}\n}}\n",
            balanced_body()
        ),
        Op::MaxDeficit => format!(
            "pub fn {name}(text: &str) -> {ret} {{\n{}\n}}\n",
            scan_body(true)
        ),
    }
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(text: &str) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(text: &str) -> {}", op.name(), op.ret())
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
    for (t, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  text {}  ->  {}\n", render_text(&t), results));
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
         one string `text` of type `&str`, drawn from the six bracket \
         characters: round, square, and curly openers with their matching \
         closers. Pairing is type-blind — any opener raises the running \
         level by one and any closer lowers it by one; the kinds are never \
         matched against each other. The balance predicate requires the \
         level to stay nonnegative throughout and finish at exactly zero.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - A single left-to-right scan over the characters is enough for \
         every query here.\n\
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
    for (i, (t, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let text = {}.to_string();\n",
            render_text(t),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "&text"),
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
            let call = call_src(*op, "&word");
            format!("        assert_eq!({call}, ref_{call});\n")
        })
        .collect::<Vec<_>>()
        .join("");
    let mut s = String::new();
    s.push_str(&format!(
        "use task::{{{}}};\n\n",
        spec.ops
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    s.push_str(&reference);
    s.push_str("fn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    s.push_str("const BRACKETS: [u8; 6] = *b\"()[]{}\";\n\n");
    s.push_str("#[test]\nfn differential_vs_reference() {\n    let mut state: u64 = 0xE7EE_ED00_0000_0152;\n    for _ in 0..3000 {\n");
    s.push_str("        let mut word = String::new();\n        let n = (nx(&mut state) % 8) + 1;\n        for _ in 0..n {\n            word.push(BRACKETS[(nx(&mut state) % 6) as usize] as char);\n        }\n");
    s.push_str(&asserts);
    s.push_str("    }\n}\n");
    s
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
            format!("{sig} {{\n    let _ = text;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every scalar with the opening count. The
/// canonical anchors keep the other three scalars distinct from it, so it is
/// wrong there; its `false` flag agrees on the unbalanced canonical and is
/// flipped by the pinned balanced examples.
fn open_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            if op.ret() == "bool" {
                format!("{sig} {{\n    false\n}}\n")
            } else {
                format!("{sig} {{\n    text.chars()\n        .filter(|&c| {})\n        .count() as i64\n}}\n", is_opener_src())
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct BracketsFamily;

impl Generator for BracketsFamily {
    fn id(&self) -> &str {
        "brackets"
    }
    fn category(&self) -> &str {
        "bracket-balance"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("brackets", seed);

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
            id: format!("brackets/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure scanning — no unsafe anywhere near it.
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
            ("open-everything".to_string(), open_everything(&spec)),
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
        let g = BracketsFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Counts, hand-pinned.
        assert_eq!(b_open_count("([{}])"), 3);
        assert_eq!(b_close_count("([{}])"), 3);
        assert_eq!(b_open_count(")]}"), 0);
        assert_eq!(b_close_count("(]"), 1);
        // Depth tracks highs only; a leading closer never sets one.
        assert_eq!(b_depth("([{}])"), 3);
        assert_eq!(b_depth("()()"), 1);
        assert_eq!(b_depth(")("), 0);
        // Balance needs a nonnegative prefix and a zero finish.
        assert!(b_is_balanced("([{}])"));
        assert!(b_is_balanced("()[]{}")); // type-blind pairs
        assert!(!b_is_balanced("((")); // ends high
        assert!(!b_is_balanced("](")); // dips negative
        assert!(b_is_balanced(""));
        // Deficit is the deepest dip as a positive magnitude.
        assert_eq!(b_max_deficit(")(".to_string().as_str()), 1);
        assert_eq!(b_max_deficit("))((("), 2);
        assert_eq!(b_max_deficit("((("), 0);
        assert_eq!(b_max_deficit(""), 0);
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
        // `const-zero` fails on every scalar at the canonical (all four
        // numeric answers are nonzero and distinct there). `open-everything`
        // fails on the other three scalars — its count answer agrees only on
        // `open_count` itself (documented skip). Both cheats' `false`
        // balance flag agrees mid-canonical (the sequence is unbalanced)
        // and is flipped by the balanced worked examples.
        for seed in 0..200u64 {
            let t = canonical(seed);
            let oc = b_open_count(&t);
            let cc = b_close_count(&t);
            let d = b_depth(&t);
            let md = b_max_deficit(&t);
            assert!(!t.is_empty(), "seed {seed}");
            assert!(!b_is_balanced(&t), "seed {seed}");
            assert!(d >= 2, "seed {seed}");
            for v in [oc, cc, d, md] {
                assert_ne!(v, 0, "const-zero survives at {t} seed {seed}");
            }
            assert_ne!(oc, cc, "open cheat survives at {t} seed {seed}");
            assert_ne!(oc, d, "seed {seed}");
            assert_ne!(oc, md, "seed {seed}");
            assert_ne!(cc, d, "seed {seed}");
            assert_ne!(cc, md, "seed {seed}");
            assert_ne!(d, md, "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (t, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &t), out, "seed {seed}");
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
            assert!(!sk.contains("matches!"));
            assert!(!sk.contains("'('"));
            assert!(!sk.contains("+= 1"));
            assert!(!sk.contains("-= 1"));
            assert!(!sk.contains(".filter("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("matches!"));
            assert!(!p.contains("'('"));
            assert!(!p.contains("+= 1"));
            assert!(!p.contains(".filter("));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here is unary: no call site may carry a comma.
        for op in OP_ALL {
            let call = call_src(op, "&text");
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
        let g = BracketsFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

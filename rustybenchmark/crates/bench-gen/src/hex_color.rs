//! The `hex-color` family (category `color-parsing`) — inspection of a
//! seeded colour literal.
//!
//! Where `caesar` shifts letters and `text-stats` counts words, this family
//! exercises **positional parsing of a fixed-shape token**: validating the
//! literal and decoding its three byte pairs plus a weighted blend. The
//! domain is one string `color: &str` of the shape `#RRGGBB` (any letter
//! case); every other shape is malformed, and malformed inputs yield `-1`
//! from numeric queries and `false` from the validity predicate. The seed
//! prunes which two of five query ops are required: `is_valid`,
//! `red_channel`, `green_channel`, `blue_channel`, `luma`. C(5,2) = **10
//! distinct skills**, above the diversity floor; op names are semantic.
//!
//! The canonical colour is sampled until its anchor facts hold: well-formed,
//! with all three channels nonzero, unsaturated (never 255), mutually
//! distinct, and with the blended luma distinct from every raw channel.
//! Those make `const-zero` wrong on every query there (the validity flag
//! reads true), and `white-everything` wrong on all four scalars; the
//! cheat's `true` flag agrees mid-canonical and is flipped by the pinned
//! malformed worked examples.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random colours against the model.
//!
//! Trivial baselines: `const-zero` (fails the validity flag outright on the
//! canonical example) and `white-everything` (every query answered with a
//! saturated channel value).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    IsValid,
    RedChannel,
    GreenChannel,
    BlueChannel,
    Luma,
}

const OP_ALL: [Op; 5] = [
    Op::IsValid,
    Op::RedChannel,
    Op::GreenChannel,
    Op::BlueChannel,
    Op::Luma,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::IsValid => "is_valid",
            Op::RedChannel => "red_channel",
            Op::GreenChannel => "green_channel",
            Op::BlueChannel => "blue_channel",
            Op::Luma => "luma",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::IsValid => {
                "whether the literal is well-formed: a hash sign followed \
                 by exactly six hexadecimal digits, upper or lower case"
            }
            Op::RedChannel => {
                "the red component decoded from the first byte pair after \
                 the hash, or minus one when the literal is malformed"
            }
            Op::GreenChannel => {
                "the green component decoded from the middle byte pair, or \
                 minus one when the literal is malformed"
            }
            Op::BlueChannel => {
                "the blue component decoded from the last byte pair, or \
                 minus one when the literal is malformed"
            }
            Op::Luma => {
                "perceived brightness blending the three channels with the \
                 standard broadcast weighting (about twenty-one percent \
                 red, seventy-two percent green, seven percent blue), \
                 truncated to an integer on the zero-to-two-five-five \
                 scale, or minus one when malformed"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::IsValid => "bool",
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

/// One nibble's value 0..=15, or −1 when the byte is not a hex digit.
fn b_nibble(c: u8) -> i64 {
    match c {
        b'0'..=b'9' => (c - b'0') as i64,
        b'a'..=b'f' => (c - b'a' + 10) as i64,
        b'A'..=b'F' => (c - b'A' + 10) as i64,
        _ => -1,
    }
}

/// The channel whose high nibble sits at byte offset `off` (1, 3, or 5);
/// `-1` when the literal is malformed.
fn b_channel(color: &str, off: usize) -> i64 {
    let bytes = color.as_bytes();
    if bytes.len() != 7 || bytes[0] != b'#' {
        return -1;
    }
    let hi = b_nibble(bytes[off]);
    let lo = b_nibble(bytes[off + 1]);
    if hi < 0 || lo < 0 {
        return -1;
    }
    hi * 16 + lo
}

/// Well-formed: hash plus exactly six hexadecimal digits.
fn b_is_valid(color: &str) -> bool {
    let bytes = color.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(|&c| b_nibble(c) >= 0)
}

/// Rec.709 luma on the 0..=255 scale; `-1` when malformed.
fn b_luma(color: &str) -> i64 {
    let r = b_channel(color, 1);
    let g = b_channel(color, 3);
    let b = b_channel(color, 5);
    if r < 0 {
        return -1;
    }
    (2126 * r + 7152 * g + 722 * b) / 10000
}

/// The answer shape: decoded values as `Num`, validity as `Flag`.
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

fn op_eval(op: Op, color: &str) -> Out {
    match op {
        Op::IsValid => Out::Flag(b_is_valid(color)),
        Op::RedChannel => Out::Num(b_channel(color, 1)),
        Op::GreenChannel => Out::Num(b_channel(color, 3)),
        Op::BlueChannel => Out::Num(b_channel(color, 5)),
        Op::Luma => Out::Num(b_luma(color)),
    }
}

// ---- canonical colour -------------------------------------------------------

const CANONICAL_SEED: u64 = 0xC010_BA11;

/// Uniform random well-formed colour literal.
fn rand_color(rng: &mut Rng) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::from("#");
    for _ in 0..6 {
        s.push(HEX[rng.below(16) as usize] as char);
    }
    s
}

/// The canonical colour: sampled and retried until the anchor facts hold.
///
/// Guaranteed for every seed: well-formed, with all three channels nonzero
/// and unsaturated, mutually distinct, and the blended luma distinct from
/// every raw channel. That makes `const-zero` wrong on every query there
/// (validity reads true), and `white-everything` wrong on all four scalars;
/// its `true` flag agrees there and is flipped by malformed examples.
fn canonical(seed: u64) -> String {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let c = rand_color(&mut rng);
        if anchors_hold(&c) {
            return c;
        }
    }
    unreachable!("canonical colour sampling failed to satisfy anchors");
}

fn anchors_hold(color: &str) -> bool {
    let r = b_channel(color, 1);
    let g = b_channel(color, 3);
    let b = b_channel(color, 5);
    let l = b_luma(color);
    b_is_valid(color)
        && r != 0
        && g != 0
        && b != 0
        && r != 255
        && g != 255
        && b != 255
        && r != g
        && r != b
        && g != b
        && l != r
        && l != g
        && l != b
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (String, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0150;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, c: &str| {
        cases.push((
            c.to_string(),
            spec.ops.map(|op| (op, op_eval(op, c))).to_vec(),
        ));
    };
    // Canonical colour first.
    push(&mut cases, &canonical(seed));
    // Malformed inputs pin the failure conventions on every op.
    push(&mut cases, "");
    // White: every channel saturated; the blend lands exactly on 255
    // because the weights sum to one.
    push(&mut cases, "#FFFFFF");
    // Black: zero conventions on a well-formed literal.
    push(&mut cases, "#000000");
    // Lowercase: decoding is case-insensitive; orange with a zero channel.
    push(&mut cases, "#ff8c00");
    for _ in 0..3 {
        let c = rand_color(&mut rng);
        push(&mut cases, &c);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site — a quoted string.
fn render_color(c: &str) -> String {
    format!("{c:?}")
}

/// The malformed-input guard every numeric body opens with.
fn guard_src() -> &'static str {
    "    let bytes = color.as_bytes();\n    if bytes.len() != 7 || bytes[0] != b'#' {\n        return -1;\n    }\n"
}

/// The hex-digit closure shared by the emitted decode bodies.
fn digit_closure_src() -> &'static str {
    "    let digit = |c: u8| -> i64 {\n        match c {\n            b'0'..=b'9' => (c - b'0') as i64,\n            b'a'..=b'f' => (c - b'a' + 10) as i64,\n            b'A'..=b'F' => (c - b'A' + 10) as i64,\n            _ => -1,\n        }\n    };\n"
}

fn channel_body(off: usize) -> String {
    let mut s = String::new();
    s.push_str(guard_src());
    s.push_str(digit_closure_src());
    s.push_str(&format!("    let hi = digit(bytes[{off}]);\n"));
    s.push_str(&format!("    let lo = digit(bytes[{}]);\n", off + 1));
    s.push_str("    if hi < 0 || lo < 0 {\n        return -1;\n    }\n");
    s.push_str("    hi * 16 + lo\n");
    s
}

fn luma_body() -> String {
    let mut s = String::new();
    s.push_str(guard_src());
    s.push_str(digit_closure_src());
    s.push_str("    let pair = |i: usize| -> i64 {\n        let hi = digit(bytes[i]);\n        let lo = digit(bytes[i + 1]);\n        if hi < 0 || lo < 0 {\n            -1\n        } else {\n            hi * 16 + lo\n        }\n    };\n");
    s.push_str("    let r = pair(1);\n");
    s.push_str("    let g = pair(3);\n");
    s.push_str("    let b = pair(5);\n");
    s.push_str("    if r < 0 {\n        return -1;\n    }\n");
    s.push_str("    (2126 * r + 7152 * g + 722 * b) / 10000\n");
    s
}

fn valid_body() -> &'static str {
    "    let bytes = color.as_bytes();\n    bytes.len() == 7\n        && bytes[0] == b'#'\n        && bytes[1..]\n            .iter()\n            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))\n"
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    match op {
        Op::IsValid => format!(
            "pub fn {name}(color: &str) -> {ret} {{\n{}\n}}\n",
            valid_body()
        ),
        Op::RedChannel => format!(
            "pub fn {name}(color: &str) -> {ret} {{\n{}\n}}\n",
            channel_body(1)
        ),
        Op::GreenChannel => format!(
            "pub fn {name}(color: &str) -> {ret} {{\n{}\n}}\n",
            channel_body(3)
        ),
        Op::BlueChannel => format!(
            "pub fn {name}(color: &str) -> {ret} {{\n{}\n}}\n",
            channel_body(5)
        ),
        Op::Luma => format!(
            "pub fn {name}(color: &str) -> {ret} {{\n{}\n}}\n",
            luma_body()
        ),
    }
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(color: &str) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(color: &str) -> {}", op.name(), op.ret())
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
    for (c, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  color {}  ->  {}\n", render_color(&c), results));
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
         one colour literal `color` of type `&str`: a hash sign followed by \
         exactly six hexadecimal digits, upper or lower case accepted. Any \
         other shape is malformed; malformed inputs yield minus one from \
         the numeric queries and false from the validity predicate. The \
         blend uses exact integer arithmetic and truncates on division.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - Work with exact integer arithmetic only; no floating point.\n\
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
    for (i, (c, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let color = {}.to_string();\n",
            render_color(c),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "&color"),
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
            let call = call_src(*op, "&color");
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
    s.push_str("const HEX: [u8; 16] = *b\"0123456789ABCDEF\";\n\n");
    s.push_str("#[test]\nfn differential_vs_reference() {\n    let mut state: u64 = 0xE7EE_ED00_0000_0150;\n    for _ in 0..3000 {\n");
    s.push_str("        let mut word = String::from(\"#\");\n        for _ in 0..6 {\n            word.push(HEX[(nx(&mut state) % 16) as usize] as char);\n        }\n        let color = word;\n");
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
            format!("{sig} {{\n    let _ = color;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer with a saturated channel no matter what was
/// asked. The canonical anchors keep every channel below saturation, so it
/// is wrong on all four scalars there; its `true` flag agrees on the
/// well-formed canonical and is flipped by the pinned malformed examples.
fn white_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            if op.ret() == "bool" {
                format!("{sig} {{\n    true\n}}\n")
            } else {
                format!("{sig} {{\n    255\n}}\n")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct HexColorFamily;

impl Generator for HexColorFamily {
    fn id(&self) -> &str {
        "hex-color"
    }
    fn category(&self) -> &str {
        "color-parsing"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("hex-color", seed);

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
            id: format!("hex-color/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure string parsing — no unsafe anywhere near it.
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
            ("white-everything".to_string(), white_everything(&spec)),
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
        let g = HexColorFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Validity: shape, length, and digit checks.
        assert!(b_is_valid("#1A2B3C"));
        assert!(b_is_valid("#ff0000")); // lowercase accepted
        assert!(!b_is_valid(""));
        assert!(!b_is_valid("#12345")); // too short
        assert!(!b_is_valid("1A2B3C")); // missing hash
        assert!(!b_is_valid("#12G456")); // bad digit mid-literal
                                         // Channels, hand-pinned per byte pair.
        assert_eq!(b_channel("#FF8000", 1), 255);
        assert_eq!(b_channel("#FF8000", 3), 128);
        assert_eq!(b_channel("#FF8000", 5), 0);
        assert_eq!(b_channel("#ff8c00", 3), 140); // case-insensitive
        assert_eq!(b_channel("#short", 1), -1); // malformed
                                                // Luma, hand-pinned against the weighting.
        assert_eq!(b_luma("#FFFFFF"), 255); // weights sum to exactly one
        assert_eq!(b_luma("#000000"), 0);
        assert_eq!(b_luma("#FF8000"), 145); // (542130 + 915456) / 10000
        assert_eq!(b_luma("#ff8c00"), 154); // (542130 + 1001280) / 10000
        assert_eq!(b_luma("#102030"), 29);
        assert_eq!(b_luma("nope"), -1);
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
        // `const-zero` fails on every query at the canonical (validity is
        // true there and every scalar is nonzero). `white-everything` fails
        // on all four scalars (channels are never saturated there) — its
        // `true` flag agrees mid-canonical and is flipped by the malformed
        // worked examples.
        for seed in 0..200u64 {
            let c = canonical(seed);
            let r = b_channel(&c, 1);
            let g = b_channel(&c, 3);
            let b = b_channel(&c, 5);
            assert!(b_is_valid(&c), "seed {seed}");
            for v in [r, g, b] {
                assert_ne!(v, 0, "const-zero survives at {c} seed {seed}");
                assert_ne!(v, 255, "white cheat survives at {c} seed {seed}");
            }
            assert_ne!(r, g, "seed {seed}");
            assert_ne!(r, b, "seed {seed}");
            assert_ne!(g, b, "seed {seed}");
            let l = b_luma(&c);
            assert_ne!(l, 0, "const-zero survives at {c} seed {seed}");
            assert_ne!(l, 255, "white cheat survives at {c} seed {seed}");
            assert_ne!(l, r, "seed {seed}");
            assert_ne!(l, g, "seed {seed}");
            assert_ne!(l, b, "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (c, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &c), out, "seed {seed}");
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
            assert!(!sk.contains("as_bytes"));
            assert!(!sk.contains("* 16"));
            assert!(!sk.contains("matches!"));
            assert!(!sk.contains("/ 10000"));
            assert!(!sk.contains("2126"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("as_bytes"));
            assert!(!p.contains("* 16"));
            assert!(!p.contains("matches!"));
            assert!(!p.contains("/ 10000"));
            assert!(!p.contains("2126"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here is unary: no call site may carry a comma.
        for op in OP_ALL {
            let call = call_src(op, "&color");
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
        let g = HexColorFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

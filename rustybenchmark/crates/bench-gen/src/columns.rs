//! The `columns` family (category `bijective-numeration`) — probing a seeded
//! spreadsheet column name.
//!
//! Spreadsheet engines name columns `A..Z`, then `AA..ZZ`, then `AAA..`:
//! bijective base-26 with no zero digit. Where `base-convert` counts digits
//! across representations, this family exercises the bijection itself: the
//! positional value fold, the digit count, validity, the trailing letter,
//! and the successor rule (`Z -> AA`, `AZ -> BA`, `ZZ -> AAA`). The seed
//! prunes which two of five query ops are required: `column_index`,
//! `name_width`, `is_valid`, `last_letter`, `next_name`. C(5,2) = **10
//! distinct skills**, above the diversity floor; op names are semantic.
//!
//! The canonical name is sampled until its anchor facts hold: a valid
//! uppercase run at least two letters wide, with a positional value that
//! differs from its width. Those make `const-zero` wrong on every answer
//! there, and `width-everything` wrong everywhere except its own query.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random names against the model.
//!
//! Trivial baselines: `const-zero` (zeroes, an empty string, and a false
//! flag everywhere) and `width-everything` (every scalar answered with the
//! letter count, every string answered with the empty string).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    ColumnIndex,
    NameWidth,
    IsValid,
    LastLetter,
    NextName,
}

const OP_ALL: [Op; 5] = [
    Op::ColumnIndex,
    Op::NameWidth,
    Op::IsValid,
    Op::LastLetter,
    Op::NextName,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::ColumnIndex => "column_index",
            Op::NameWidth => "name_width",
            Op::IsValid => "is_valid",
            Op::LastLetter => "last_letter",
            Op::NextName => "next_name",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::ColumnIndex => {
                "the numeric index of the column name under bijective base \
                 twenty-six, where each letter contributes its one-based \
                 alphabet rank — A is one, Z is twenty-six, AA is \
                 twenty-seven; a name that is empty scores zero"
            }
            Op::NameWidth => "how many letters the column name contains",
            Op::IsValid => {
                "whether the name is a non-empty run of uppercase letters \
                 from A through Z"
            }
            Op::LastLetter => {
                "the trailing letter of the name on its own; the empty \
                 string when the name is empty"
            }
            Op::NextName => {
                "the successor name in bijective base twenty-six — after Z \
                 comes AA, after AZ comes BA, after ZZ comes AAA; the empty \
                 name succeeds to A"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::LastLetter | Op::NextName => "String",
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

/// Positional value under bijective base-26; empty scores zero.
fn b_column_index(name: &str) -> i64 {
    let mut idx = 0i64;
    for c in name.bytes() {
        idx = idx * 26 + (c - b'A' + 1) as i64;
    }
    idx
}

/// Letter count of the name.
fn b_name_width(name: &str) -> i64 {
    name.chars().count() as i64
}

/// True for a non-empty run of uppercase `A..Z`.
fn b_is_valid(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|c| c.is_ascii_uppercase())
}

/// The trailing letter, or the empty string for an empty name.
fn b_last_letter(name: &str) -> String {
    match name.chars().last() {
        Some(c) => c.to_string(),
        None => String::new(),
    }
}

/// The bijective successor: `Z -> AA`, `AZ -> BA`, `ZZ -> AAA`.
fn b_next_name(name: &str) -> String {
    let mut bytes = name.as_bytes().to_vec();
    if bytes.is_empty() {
        return "A".to_string();
    }
    let mut pos = bytes.len() - 1;
    loop {
        if bytes[pos] == b'Z' {
            bytes[pos] = b'A';
            if pos == 0 {
                bytes.insert(0, b'A');
                break;
            }
            pos -= 1;
        } else {
            bytes[pos] += 1;
            break;
        }
    }
    String::from_utf8(bytes).unwrap_or_default()
}

/// The answer shape: numeric queries as `Num`, the validity flag as `Flag`,
/// the string answers as `Str`.
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

fn op_eval(op: Op, name: &str) -> Out {
    match op {
        Op::ColumnIndex => Out::Num(b_column_index(name)),
        Op::NameWidth => Out::Num(b_name_width(name)),
        Op::IsValid => Out::Flag(b_is_valid(name)),
        Op::LastLetter => Out::Str(b_last_letter(name)),
        Op::NextName => Out::Str(b_next_name(name)),
    }
}

// ---- canonical name ----------------------------------------------------------

const CANONICAL_SEED: u64 = 0xC01D_5EED;

/// Uniform random short column name (one to three uppercase letters).
fn rand_name(rng: &mut Rng) -> String {
    let n = 1 + rng.below(3);
    let mut s = String::new();
    for _ in 0..n {
        s.push((b'A' + rng.below(26) as u8) as char);
    }
    s
}

/// The canonical name: sampled and retried until the anchor facts hold.
///
/// Guaranteed for every seed: a valid uppercase run at least two letters
/// wide whose positional value differs from its width. That makes
/// `const-zero` wrong on every answer there and `width-everything` wrong on
/// every answer except `name_width` itself. Both cheats' empty strings are
/// wrong because a valid name always has a trailing letter and a real
/// successor, and their `false` flags die against the canonical's true one.
fn canonical(seed: u64) -> String {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let t = rand_name(&mut rng);
        if anchors_hold(&t) {
            return t;
        }
    }
    unreachable!("canonical name sampling failed to satisfy anchors");
}

fn anchors_hold(name: &str) -> bool {
    b_is_valid(name) && b_name_width(name) >= 2 && b_column_index(name) != b_name_width(name)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (String, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_015A;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, c: &str| {
        cases.push((
            c.to_string(),
            spec.ops.map(|op| (op, op_eval(op, c))).to_vec(),
        ));
    };
    // Canonical multi-letter name first.
    push(&mut cases, &canonical(seed));
    // Empty: zero index, zero width, invalid, empty strings.
    push(&mut cases, "");
    // The wrap edge: after Z comes AA.
    push(&mut cases, "Z");
    // Minimal single-letter corner.
    push(&mut cases, "A");
    for _ in 0..3 {
        let t = rand_name(&mut rng);
        push(&mut cases, &t);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site — a quoted string.
fn render_text(t: &str) -> String {
    format!("{t:?}")
}

/// Emitted body for the positional fold.
fn index_body() -> &'static str {
    "    let mut idx = 0i64;\n    for c in name.bytes() {\n        idx = idx * 26 + (c - b'A' + 1) as i64;\n    }\n    idx\n"
}

fn width_body() -> &'static str {
    "    name.chars().count() as i64\n"
}

fn valid_body() -> &'static str {
    "    !name.is_empty()\n        && name.bytes().all(|c| c.is_ascii_uppercase())\n"
}

fn last_letter_body() -> &'static str {
    "    match name.chars().last() {\n        Some(c) => c.to_string(),\n        None => String::new(),\n    }\n"
}

fn next_name_body() -> &'static str {
    "    let mut bytes = name.as_bytes().to_vec();\n    if bytes.is_empty() {\n        return \"A\".to_string();\n    }\n    let mut pos = bytes.len() - 1;\n    loop {\n        if bytes[pos] == b'Z' {\n            bytes[pos] = b'A';\n            if pos == 0 {\n                bytes.insert(0, b'A');\n                break;\n            }\n            pos -= 1;\n        } else {\n            bytes[pos] += 1;\n            break;\n        }\n    }\n    String::from_utf8(bytes).unwrap_or_default()\n"
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let body = match op {
        Op::ColumnIndex => index_body(),
        Op::NameWidth => width_body(),
        Op::IsValid => valid_body(),
        Op::LastLetter => last_letter_body(),
        Op::NextName => next_name_body(),
    };
    format!("pub fn {name}(name: &str) -> {ret} {{\n{body}}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(name: &str) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(name: &str) -> {}", op.name(), op.ret())
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
        s.push_str(&format!("  name {}  ->  {}\n", render_text(&t), results));
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
         one string `name` of type `&str`: a spreadsheet column name over \
         the uppercase letters A through Z. Column names follow bijective \
         base twenty-six — there is no zero digit, so after Z comes AA and \
         after ZZ comes AAA. The positional value of a name folds each \
         letter's one-based alphabet rank into place (A is one, Z is \
         twenty-six, AA is twenty-seven); a name that is empty scores zero \
         by convention here. The successor rule works like an odometer \
         whose digits run from A to Z: increment the trailing letter, and \
         on wrap carry leftward, growing the name when every digit was Z.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - Work with plain byte or character iteration; no external crates.\n\
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
            "#[test]\nfn ex{i}() {{\n    let name = {}.to_string();\n",
            render_text(t),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "&name"),
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
    s.push_str("#[test]\nfn differential_vs_reference() {\n    let mut state: u64 = 0xE7EE_ED00_0000_015A;\n    for _ in 0..3000 {\n");
    s.push_str("        let mut word = String::new();\n        let n = (nx(&mut state) % 3) + 1;\n        for _ in 0..n {\n            word.push((b'A' + (nx(&mut state) % 26) as u8) as char);\n        }\n");
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
                "String" => "String::new()",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = name;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every scalar with the letter count and every
/// string with the empty string. The canonical anchors keep the positional
/// value distinct from the width, so the scalar cheat is wrong there; its
/// empty strings are wrong on any valid name; its `false` flag dies against
/// the canonical's true one. Exact only for `name_width` itself.
fn width_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    false\n}}\n"),
                "String" => format!("{sig} {{\n    String::new()\n}}\n"),
                _ => format!(
                    "{sig} {{\n{name_chars}\n}}\n",
                    name_chars = width_body().trim_end()
                ),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct ColumnsFamily;

impl Generator for ColumnsFamily {
    fn id(&self) -> &str {
        "columns"
    }
    fn category(&self) -> &str {
        "bijective-numeration"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("columns", seed);

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
            id: format!("columns/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure string work — no unsafe anywhere near it.
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
            ("width-everything".to_string(), width_everything(&spec)),
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
        let g = ColumnsFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Positional fold, hand-pinned.
        assert_eq!(b_column_index("A"), 1);
        assert_eq!(b_column_index("Z"), 26);
        assert_eq!(b_column_index("AA"), 27);
        assert_eq!(b_column_index("ZZ"), 702);
        assert_eq!(b_column_index(""), 0);
        // Width.
        assert_eq!(b_name_width("XFD"), 3);
        assert_eq!(b_name_width(""), 0);
        // Validity: non-empty uppercase runs only.
        assert!(b_is_valid("AZ"));
        assert!(!b_is_valid(""));
        assert!(!b_is_valid("a"));
        assert!(!b_is_valid("AB1"));
        // Trailing letter.
        assert_eq!(b_last_letter("AZ"), "Z");
        assert_eq!(b_last_letter(""), "");
        // Successor carries like a bijective counter.
        assert_eq!(b_next_name("Z"), "AA");
        assert_eq!(b_next_name("AZ"), "BA");
        assert_eq!(b_next_name("ZZ"), "AAA");
        assert_eq!(b_next_name("XFD"), "XFE");
        assert_eq!(b_next_name(""), "A");
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
        // The canonical name is valid, at least two letters wide, and its
        // positional value differs from its width. That makes `const-zero`
        // wrong on every answer (nonzero scalars, nonempty strings, true
        // flag vs false) and `width-everything` wrong on every answer
        // except `name_width` itself — no skips anywhere.
        for seed in 0..200u64 {
            let t = canonical(seed);
            let idx = b_column_index(&t);
            let width = b_name_width(&t);
            assert!(b_is_valid(&t), "seed {seed}");
            assert!(width >= 2, "seed {seed}");
            assert_ne!(idx, width, "width cheat survives at {t} seed {seed}");
            for op in OP_ALL {
                match op_eval(op, &t) {
                    Out::Num(v) => {
                        assert_ne!(v, 0, "const-zero survives on {op:?} at {t} seed {seed}");
                        if matches!(op, Op::ColumnIndex) {
                            assert_ne!(v, width, "width cheat survives at {t} seed {seed}");
                        }
                    }
                    Out::Flag(b) => {
                        assert!(b, "flag cheats survive at {t} seed {seed}");
                    }
                    Out::Str(s) => {
                        assert!(
                            !s.is_empty(),
                            "empty-string cheats survive on {op:?} at {t} seed {seed}"
                        );
                        if matches!(op, Op::NextName) {
                            assert_ne!(s, t, "echo survives at {t} seed {seed}");
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
            assert!(!sk.contains("* 26"));
            assert!(!sk.contains("b'A'"));
            assert!(!sk.contains("is_ascii_uppercase"));
            assert!(!sk.contains("from_utf8"));
            assert!(!sk.contains("push("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("* 26"));
            assert!(!p.contains("b'A'"));
            assert!(!p.contains("is_ascii_uppercase"));
            assert!(!p.contains("from_utf8"));
            assert!(!p.contains("push("));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here is unary: no call site may carry a comma.
        for op in OP_ALL {
            let call = call_src(op, "&name");
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
        let g = ColumnsFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

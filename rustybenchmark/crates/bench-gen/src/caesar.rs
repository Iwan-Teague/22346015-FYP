//! `caesar` — classical-cipher transforms over seeded lowercase words.
//!
//! A task instance is one lowercase ASCII word plus a rotation amount in
//! `0..=25`; the seed picks two of five query operations over its cipher
//! forms. The model must implement both exactly as specified and match a
//! hidden reference on thousands of random inputs.
//!
//! Category: `classical-cipher`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    /// Every letter shifted forward by the instance's own rotation.
    Encode,
    /// The inverse walk — shifted backward by the same amount.
    Decode,
    /// The classic fixed half-turn of thirteen.
    Rot13,
    /// How many letters cross past `z` under the forward shift.
    Wraps,
    /// The mirror-alphabet substitution, independent of the rotation.
    Atbash,
}

const OP_ALL: [Op; 5] = [Op::Encode, Op::Decode, Op::Rot13, Op::Wraps, Op::Atbash];

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Encode => "encode",
            Op::Decode => "decode",
            Op::Rot13 => "rot13",
            Op::Wraps => "wraps",
            Op::Atbash => "atbash",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::Wraps => "i64",
            _ => "String",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Encode => "every letter shifted forward through the alphabet by the rotation amount, wrapping from z back around to a",
            Op::Decode => "the inverse walk — every letter shifted backward by the same amount, wrapping from a back up to z",
            Op::Rot13 => "every letter shifted by a fixed half-turn of thirteen positions, so applying it twice restores the original word",
            Op::Wraps => "how many letters cross past the end of the alphabet under the forward shift — those whose letter position plus the rotation reaches twenty-six or more",
            Op::Atbash => "the mirror-alphabet substitution mapping a to z, b to y, and so on — a reflection rather than a shift, so the rotation plays no part",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Spec {
    ops: [Op; 2],
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let i = rng.below(OP_ALL.len() as u64) as usize;
    let mut j = rng.below(OP_ALL.len() as u64) as usize;
    while j == i {
        j = rng.below(OP_ALL.len() as u64) as usize;
    }
    Spec {
        ops: [OP_ALL[i], OP_ALL[j]],
    }
}
// ---------------------------------------------------------------------------
// Native mirrors of the emitted query bodies.
// ---------------------------------------------------------------------------

fn shift_word(text: &str, amount: u32) -> String {
    text.chars()
        .map(|c| {
            let pos = c as u32 - 'a' as u32;
            let moved = (pos + amount) % 26;
            (b'a' + moved as u8) as char
        })
        .collect()
}

fn b_encode(text: &str, shift: u32) -> String {
    shift_word(text, shift)
}

fn b_decode(text: &str, shift: u32) -> String {
    shift_word(text, 26 - shift)
}

fn b_rot13(text: &str, _shift: u32) -> String {
    shift_word(text, 13)
}

fn b_wraps(text: &str, shift: u32) -> i64 {
    text.chars()
        .filter(|&c| c as u32 - 'a' as u32 + shift >= 26)
        .count() as i64
}

fn b_atbash(text: &str, _shift: u32) -> String {
    text.chars()
        .map(|c| (b'a' + (b'z' - c as u8)) as char)
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Str(String),
}

impl Out {
    fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Str(s) => format!("{s:?}"),
        }
    }
}

fn op_eval(op: Op, text: &str, shift: u32) -> Out {
    match op {
        Op::Encode => Out::Str(b_encode(text, shift)),
        Op::Decode => Out::Str(b_decode(text, shift)),
        Op::Rot13 => Out::Str(b_rot13(text, shift)),
        Op::Wraps => Out::Num(b_wraps(text, shift)),
        Op::Atbash => Out::Str(b_atbash(text, shift)),
    }
}

const CANONICAL_SEED: u64 = 0xCAE5_A11A;

/// The canonical input keeps every string answer away from the input itself
/// and away from each other (which rules out the degenerate rotations 0 and
/// 13), with a nonzero wrap count — so the zero cheat and the echo-the-input
/// cheat miss on every query, with no exceptions to document.
fn canonical(seed: u64) -> (String, u32) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let len = 2 + rng.below(9) as usize;
        let text: String = (0..len)
            .map(|_| (b'a' + rng.below(26) as u8) as char)
            .collect();
        let shift = rng.below(26) as u32;
        if anchors_hold(&text, shift) {
            return (text, shift);
        }
    }
    unreachable!("caesar canonical anchor search exhausted");
}

fn anchors_hold(text: &str, shift: u32) -> bool {
    if text.is_empty() {
        return false;
    }
    let enc = b_encode(text, shift);
    let dec = b_decode(text, shift);
    let atb = b_atbash(text, shift);
    let wr = b_wraps(text, shift);
    if wr < 1 || enc == text || dec == text || atb == text || enc == dec {
        return false;
    }
    true
}
// ---------------------------------------------------------------------------
// Worked examples, rendering, and emitted-source builders.
// ---------------------------------------------------------------------------

type ExampleCase = ((String, u32), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_014E;

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let can = canonical(seed);
    // Canonical first.
    let outs = OP_ALL
        .iter()
        .map(|&op| (op, op_eval(op, &can.0, can.1)))
        .collect();
    let mut cases: Vec<ExampleCase> = vec![(can.clone(), outs)];
    // The empty word: zero conventions for every query.
    let empty = (String::new(), 7u32);
    let outs = OP_ALL
        .iter()
        .map(|&op| (op, op_eval(op, &empty.0, empty.1)))
        .collect();
    cases.push((empty, outs));
    // Zero rotation: the identity on strings and no wraps at all.
    let zero = ("abc".to_string(), 0u32);
    let outs = OP_ALL
        .iter()
        .map(|&op| (op, op_eval(op, &zero.0, zero.1)))
        .collect();
    cases.push((zero, outs));
    // Heavy wrap corner: every letter crosses past z.
    let heavy = ("xyz".to_string(), 25u32);
    let outs = OP_ALL
        .iter()
        .map(|&op| (op, op_eval(op, &heavy.0, heavy.1)))
        .collect();
    cases.push((heavy, outs));
    for _ in 0..3 {
        let len = 1 + rng.below(9) as usize;
        let text: String = (0..len)
            .map(|_| (b'a' + rng.below(26) as u8) as char)
            .collect();
        let shift = rng.below(26) as u32;
        let outs = OP_ALL
            .iter()
            .map(|&op| (op, op_eval(op, &text, shift)))
            .collect();
        cases.push(((text, shift), outs));
    }
    cases
}

fn render_text(text: &str) -> String {
    format!("{text:?}")
}

fn render_u32(n: u32) -> String {
    format!("{n}u32")
}

fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}

fn shift_body_src(amount: &str) -> String {
    [
        "text.chars()",
        "    .map(|c| {",
        "        let moved = (c as u32 - 'a' as u32 + amount) % 26;",
        "        (b'a' + moved as u8) as char",
        "    })",
        "    .collect()",
    ]
    .join("\n    ")
    .replacen("amount", amount, 1)
}

fn op_fn_src(op: Op) -> String {
    let body: String = match op {
        Op::Encode => shift_body_src("shift"),
        Op::Decode => shift_body_src("(26 - shift)"),
        Op::Rot13 => shift_body_src("13"),
        Op::Wraps => [
            "text.chars()",
            "    .filter(|&c| c as u32 - 'a' as u32 + shift >= 26)",
            "    .count() as i64",
        ]
        .join("\n    "),
        Op::Atbash => [
            "let _ = shift;",
            "text.chars()",
            "    .map(|c| (b'a' + (b'z' - c as u8)) as char)",
            "    .collect()",
        ]
        .join("\n    "),
    };
    format!(
        "pub fn {}(text: &str, shift: u32) -> {} {{\n    {}\n}}\n",
        op.name(),
        op.ret(),
        body
    )
}

fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(text: &str, shift: u32) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(text: &str, shift: u32) -> {}",
        op.name(),
        op.ret()
    )
}

fn reference_src() -> String {
    OP_ALL
        .iter()
        .map(|&op| op_fn_src(op))
        .collect::<Vec<_>>()
        .join("\n")
}
// ---------------------------------------------------------------------------
// Emitted task surfaces: examples prose, skeleton, prompt, manifest.
// ---------------------------------------------------------------------------

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for ((text, shift), outs) in worked_examples(seed) {
        let results = outs
            .iter()
            .filter(|(op, _)| spec.ops.contains(op))
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  text {} shift {}  ->  {}\n",
            render_text(&text),
            render_u32(shift),
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
         given as `text`, one lowercase word of type `&str` using only the \
         letters a through z, and `shift`, a rotation amount of type `u32` \
         in the range zero through twenty-five; queries are classical \
         cipher transforms of the word.\n\
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
// ---------------------------------------------------------------------------
// Hidden tests and trivial baselines.
// ---------------------------------------------------------------------------

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let imports = spec
        .ops
        .iter()
        .map(|op| op.name())
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!("use task::{{{imports}}};\n\n");
    for (i, ((text, shift), outs)) in worked_examples(seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let text = {}.to_string();\n    let shift = {};\n",
            render_text(text),
            render_u32(*shift),
        ));
        for (op, out) in outs {
            if !spec.ops.contains(op) {
                continue;
            }
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "&text, shift"),
                out.lit(),
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the two selected ops, pasted into the test
/// file under `ref_*` names. Every body is self-contained, so the unrenamed
/// remainder stays callable.
fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src()
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
            let call = call_src(*op, "&text, shift");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_014E;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let mut text = String::new();\n\
         \x20       let len = (nx(&mut state) % 8) + 1;\n\
         \x20       for _ in 0..len {{\n\
         \x20           text.push((b'a' + (nx(&mut state) % 26) as u8) as char);\n\
         \x20       }}\n\
         \x20       let shift = (nx(&mut state) % 26) as u32;\n\
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

/// Degenerate: everything zero (and empty strings on the cipher queries).
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "String" => {
                    format!("{sig} {{\n    let _ = (text, shift);\n    String::new()\n}}\n")
                }
                _ => format!("{sig} {{\n    let _ = (text, shift);\n    0\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The echo cheat: answer with the input word itself no matter what was
/// asked. The canonical anchors force every string answer away from the
/// input and keep the wrap count nonzero, so this is exact nowhere on
/// canonical.
fn identity_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "String" => format!("{sig} {{\n    text.to_string()\n}}\n"),
                _ => format!("{sig} {{\n    let _ = shift;\n    0\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct CaesarFamily;

impl Generator for CaesarFamily {
    fn id(&self) -> &str {
        "caesar"
    }
    fn category(&self) -> &str {
        "classical-cipher"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("caesar", seed);

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
            id: format!("caesar/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure string/integer bookkeeping — no unsafe anywhere near it.
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // Default oracle weights (docs/04).
            weights: (0.70, 0.20, 0.10),
        }
    }

    fn reference_code(&self, _seed: u64) -> String {
        reference_src()
    }
    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(&sample(seed), seed)
    }
    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero(&spec)),
            (
                "identity-everything".to_string(),
                identity_everything(&spec),
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
        let g = CaesarFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        assert_eq!(b_encode("xyz", 1), "yza");
        assert_eq!(b_encode("hello", 13), "uryyb");
        assert_eq!(b_encode("b", 25), "a");
        assert_eq!(b_encode("abc", 0), "abc");
        // a->v and c->x both wrap backwards past the start.
        assert_eq!(b_decode("attack", 5), "voovxf");
        assert_eq!(b_rot13("nobody", 0), "abobql");
        assert_eq!(b_rot13("zoo", 4), "mbb");
        // Shift 25 wraps everything except 'a', which lands on z exactly.
        assert_eq!(b_wraps("cab", 25), 2);
        assert_eq!(b_wraps("azx", 7), 2);
        assert_eq!(b_wraps("zebra", 0), 0);
        assert_eq!(b_atbash("hello", 5), "svool");
        assert_eq!(b_atbash("azy", 0), "zab");
        // Empty-word conventions everywhere.
        assert_eq!(b_encode("", 3), "");
        assert_eq!(b_wraps("", 12), 0);
        assert_eq!(b_atbash("", 8), "");
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..300u64 {
            seen.insert(sample(seed));
        }
        assert!(seen.len() >= 9, "only {} distinct pairs", seen.len());
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        for seed in 0..200u64 {
            let (text, shift) = canonical(seed);
            assert!(anchors_hold(&text, shift), "seed {seed}: anchors violated");
            let enc = b_encode(&text, shift);
            let dec = b_decode(&text, shift);
            let rot = b_rot13(&text, shift);
            let atb = b_atbash(&text, shift);
            let wr = b_wraps(&text, shift);
            // const-zero: no string answer is empty and the count is nonzero.
            for s in [&enc, &dec, &rot, &atb] {
                assert!(!s.is_empty(), "seed {seed}");
            }
            assert_ne!(wr, 0, "seed {seed}");
            // identity-everything: no string answer equals the input word,
            // and the wrap count is not the cheat's zero. No skips needed —
            // the anchors force all four separations directly.
            assert_ne!(enc, text, "seed {seed}");
            assert_ne!(dec, text, "seed {seed}");
            assert_ne!(atb, text, "seed {seed}");
            assert_ne!(wr, 0, "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for ((text, shift), outs) in worked_examples(seed) {
                for (op, out) in outs {
                    assert_eq!(
                        &out,
                        &op_eval(op, &text, shift),
                        "seed {seed} op {}",
                        op.name()
                    );
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        let g = CaesarFamily;
        for seed in 0..50u64 {
            let reference = g.reference_code(seed);
            for op in sample(seed).ops {
                let marker = format!("pub fn {}(", op.name());
                assert_eq!(
                    reference.lines().filter(|l| l.starts_with(&marker)).count(),
                    1,
                    "seed {seed} op {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        let g = CaesarFamily;
        for seed in 0..50u64 {
            let sk = g.skeleton_code(seed);
            let task = g.generate(seed);
            for leak in ["% 26", "b'a'", "b'z'", ">= 26", "chars("] {
                assert!(!sk.contains(leak), "skeleton leaks {leak}");
                assert!(!task.prompt.contains(leak), "prompt leaks {leak}");
            }
            assert_eq!(sk.matches("todo!()").count(), 2);
            for op in sample(seed).ops {
                assert!(
                    task.prompt.contains(&op_sig_src(op)),
                    "prompt missing signature for {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for _seed in 0..50u64 {
            for op in OP_ALL {
                let call = call_src(op, "&text, shift");
                let sig = op_sig_src(op);
                let params = sig.split("->").next().unwrap();
                assert_eq!(
                    call.matches(',').count(),
                    params.matches(',').count(),
                    "op {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = CaesarFamily;
        let task = g.generate(7);
        assert!(task.prompt.contains(&task.canary));
    }
}

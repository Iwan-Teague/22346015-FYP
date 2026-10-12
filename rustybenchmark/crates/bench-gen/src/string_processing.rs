//! The `str-transform` family (category `string-processing`).
//!
//! A text-processing shape: the model implements `fn f(s: &str) -> String` as a
//! seed-selected three-stage pipeline over the characters of `s`:
//!
//! 1. **Filter** — which characters are kept: Alpha / Alnum / NonSpace / All.
//! 2. **Map** — how each kept character is transformed: Upper / Lower / SwapCase.
//! 3. **Order** — the result order: InOrder / Reversed.
//!
//! The structural surface is 4 × 3 × 2 = **24 distinct skills**, and the function
//! name is cosmetic — excluded from `spec_signature`. Everything is ASCII-only by
//! construction (the case maps are the `to_ascii_*` family, and the fuzzer draws
//! printable-ASCII bytes), so there are no UTF-8 char-boundary hazards and no
//! allocation surprises beyond the result `String`. Solution-first and
//! correct-by-construction (ADR-0003): the native `eval` and the emitted reference
//! are mirrored, and the differential fuzzes 3000 random ASCII strings.
//!
//! Every map is a genuine case transform (never identity), and the canonical
//! example `"Hello, World!"` contains both cases plus punctuation and a space, so
//! every one of the 24 combinations changes it and leaves it non-empty — which is
//! what makes both trivial baselines (`identity`, `empty`) fail on every seed.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Stage 1 — which characters are kept.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Filter {
    Alpha,
    Alnum,
    NonSpace,
    All,
}

/// Stage 2 — how each kept character's case is transformed.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Map {
    Upper,
    Lower,
    SwapCase,
}

struct Spec {
    filter: Filter,
    map: Map,
    reversed: bool,
    fn_name: &'static str,
}

const NAMES: &[&str] = &[
    "f",
    "process",
    "normalize",
    "clean",
    "transform_text",
    "sift_chars",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let filter = match rng.below(4) {
        0 => Filter::Alpha,
        1 => Filter::Alnum,
        2 => Filter::NonSpace,
        _ => Filter::All,
    };
    let map = match rng.below(3) {
        0 => Map::Upper,
        1 => Map::Lower,
        _ => Map::SwapCase,
    };
    let reversed = rng.below(2) == 1;
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        filter,
        map,
        reversed,
        fn_name,
    }
}

// ---- native reference (mirrors the emitted source exactly) ----------------

fn keep(filter: Filter, c: char) -> bool {
    match filter {
        Filter::Alpha => c.is_ascii_alphabetic(),
        Filter::Alnum => c.is_ascii_alphanumeric(),
        Filter::NonSpace => !c.is_whitespace(),
        Filter::All => true,
    }
}

fn map_char(map: Map, c: char) -> char {
    match map {
        Map::Upper => c.to_ascii_uppercase(),
        Map::Lower => c.to_ascii_lowercase(),
        Map::SwapCase => {
            if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c
            }
        }
    }
}

/// The answer: filter, case-map, then optionally reverse. Source of truth for the
/// emitted reference.
fn eval(spec: &Spec, s: &str) -> String {
    let filtered: String = s
        .chars()
        .filter(|&c| keep(spec.filter, c))
        .map(|c| map_char(spec.map, c))
        .collect();
    if spec.reversed {
        filtered.chars().rev().collect()
    } else {
        filtered
    }
}

// ---- emitted-source fragments (mirror the native functions above) ---------

fn filter_closure(filter: Filter) -> &'static str {
    match filter {
        Filter::Alpha => "|&c| c.is_ascii_alphabetic()",
        Filter::Alnum => "|&c| c.is_ascii_alphanumeric()",
        Filter::NonSpace => "|&c| !c.is_whitespace()",
        Filter::All => "|&_c| true",
    }
}

fn map_closure(map: Map) -> &'static str {
    match map {
        Map::Upper => "|c| c.to_ascii_uppercase()",
        Map::Lower => "|c| c.to_ascii_lowercase()",
        Map::SwapCase => {
            "|c| if c.is_ascii_uppercase() { c.to_ascii_lowercase() } \
             else if c.is_ascii_lowercase() { c.to_ascii_uppercase() } else { c }"
        }
    }
}

fn filter_prose(filter: Filter) -> &'static str {
    match filter {
        Filter::Alpha => "keep only the ASCII letters (drop everything else)",
        Filter::Alnum => "keep only the ASCII letters and digits",
        Filter::NonSpace => "keep every character that is not whitespace",
        Filter::All => "keep every character",
    }
}

fn map_prose(map: Map) -> &'static str {
    match map {
        Map::Upper => "convert each kept character to ASCII uppercase",
        Map::Lower => "convert each kept character to ASCII lowercase",
        Map::SwapCase => "swap the case of each kept ASCII letter (leave others unchanged)",
    }
}

fn reference_src(spec: &Spec) -> String {
    let ret = if spec.reversed {
        "filtered.chars().rev().collect()"
    } else {
        "filtered"
    };
    format!(
        "pub fn {name}(s: &str) -> String {{\n\
         \x20   let filtered: String = s.chars().filter({filter}).map({map}).collect();\n\
         \x20   {ret}\n\
         }}\n",
        name = spec.fn_name,
        filter = filter_closure(spec.filter),
        map = map_closure(spec.map),
        ret = ret,
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "//! Implement `{name}` below.\n\
         //!\n\
         {doc}\n\
         pub fn {name}(s: &str) -> String {{\n\
         \x20   todo!()\n\
         }}\n",
        name = spec.fn_name,
        doc = examples
            .lines()
            .map(|l| format!("//! {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// One worked example: (input, expected output).
type ExampleCase = (String, String);

/// Worked examples, computed natively so each is correct by construction. The
/// first case is the **canonical** one — the fixed input `"Hello, World!"`, which
/// has both letter cases, punctuation and a space, so every (filter, map, order)
/// combination changes it and leaves it non-empty. That is what makes both trivial
/// baselines (`identity`, `empty`) fail for every seed. The rest are seed-varied
/// random printable-ASCII strings (the family's biggest per-instance textual
/// lever, docs/02 Q30).
fn worked_examples(spec: &Spec, seed: u64) -> (String, Vec<ExampleCase>) {
    let mut rng = Rng::new(seed ^ 0x57ED_0000_0000_0023);
    let mut inputs: Vec<String> = vec!["Hello, World!".to_string()];
    for _ in 0..3 {
        let len = 3 + rng.below(8) as usize; // 3..=10
        let s: String = (0..len)
            .map(|_| (0x20u8 + rng.below(95) as u8) as char) // printable ASCII 0x20..=0x7e
            .collect();
        inputs.push(s);
    }

    let mut cases = Vec::new();
    let mut prose = String::new();
    for input in &inputs {
        let out = eval(spec, input);
        prose.push_str(&format!("  {input:?}  ->  {out:?}\n"));
        cases.push((input.clone(), out));
    }
    (prose, cases)
}

fn order_prose(reversed: bool) -> &'static str {
    if reversed {
        "Finally, reverse the order of the resulting characters."
    } else {
        "Keep the characters in their original order."
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "Implement the function `{name}` in `src/lib.rs`.\n\
         \n\
         Process the characters of `s` in three steps and return the result as a \
         `String`:\n\
         \n\
         1. **Filter** — {filter_prose}.\n\
         2. **Map** — {map_prose}.\n\
         3. **Order** — {order_prose}\n\
         \n\
         All inputs are ASCII. A character that is dropped by the filter does not \
         appear in the output.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - The input may be empty; the result is then the empty string.\n\
         \n\
         Signature:\n\
         ```rust\n\
         pub fn {name}(s: &str) -> String\n\
         ```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        filter_prose = filter_prose(spec.filter),
        map_prose = map_prose(spec.map),
        order_prose = order_prose(spec.reversed),
        examples = examples,
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
    let (_, cases) = worked_examples(spec, seed);
    let mut body = format!("use task::{};\n\n", spec.fn_name);
    for (i, (input, out)) in cases.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   assert_eq!({name}({input:?}), {out:?});\n\
             }}\n\n",
            name = spec.fn_name,
        ));
    }
    body.push_str(&format!(
        "#[test]\nfn empty_input() {{\n\
         \x20   assert_eq!({name}(\"\"), \"\");\n\
         }}\n",
        name = spec.fn_name,
    ));
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference =
        reference_src(spec).replacen(&format!("pub fn {}", spec.fn_name), "fn reference", 1);
    format!(
        "use task::{name};\n\
         \n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x57ED_ED00_0000_0042;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 12) as usize;\n\
         \x20       let s: String = (0..len).map(|_| (0x20u8 + (next() % 95) as u8) as char).collect();\n\
         \x20       assert_eq!({name}(&s), reference(&s), \"mismatch on {{s:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = reference,
    )
}

/// Degenerate: returns the input unchanged. Fails on the canonical example, which
/// every combination changes.
fn identity(spec: &Spec) -> String {
    format!(
        "pub fn {name}(s: &str) -> String {{ s.to_string() }}\n",
        name = spec.fn_name,
    )
}

/// Degenerate: always returns the empty string. Fails on the canonical example,
/// which every combination renders non-empty.
fn empty(spec: &Spec) -> String {
    format!(
        "pub fn {name}(s: &str) -> String {{ let _ = s; String::new() }}\n",
        name = spec.fn_name,
    )
}

pub struct StringProcessingFamily;

impl Generator for StringProcessingFamily {
    fn id(&self) -> &str {
        "str-transform"
    }
    fn category(&self) -> &str {
        "string-processing"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("str-transform", seed);

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
            id: format!("str-transform/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            // Building the result String legitimately allocates: no alloc constraint.
            alloc_test: String::new(),
            max_unsafe: Some(0),
            check_clippy: false,
            clippy_allow: Vec::new(),
            forbidden_paths: Vec::new(),
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
            ("identity".to_string(), identity(&spec)),
            ("empty".to_string(), empty(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is the (filter, map, order) trio. The function name is cosmetic
        // and there are no numeric constants — all excluded (Q31).
        let spec = sample(seed);
        let filter = match spec.filter {
            Filter::Alpha => "keep_alpha",
            Filter::Alnum => "keep_alnum",
            Filter::NonSpace => "keep_nonspace",
            Filter::All => "keep_all",
        };
        let map = match spec.map {
            Map::Upper => "upper",
            Map::Lower => "lower",
            Map::SwapCase => "swapcase",
        };
        let order = if spec.reversed { "reversed" } else { "inorder" };
        vec![
            format!("filter:{filter}"),
            format!("map:{map}"),
            format!("order:{order}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = StringProcessingFamily;
        assert_eq!(g.generate(19).prompt, g.generate(19).prompt);
        assert_eq!(g.generate(19).hidden, g.generate(19).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        // KeepAlpha + Upper + InOrder on "Hello, World!" -> "HELLOWORLD".
        let spec = Spec {
            filter: Filter::Alpha,
            map: Map::Upper,
            reversed: false,
            fn_name: "f",
        };
        assert_eq!(eval(&spec, "Hello, World!"), "HELLOWORLD");

        // KeepAll + SwapCase + Reversed on "aB c" -> map "Ab C" -> reversed "C bA".
        let spec = Spec {
            filter: Filter::All,
            map: Map::SwapCase,
            reversed: true,
            fn_name: "f",
        };
        assert_eq!(eval(&spec, "aB c"), "C bA");

        // KeepNonSpace + Lower + InOrder on "A B\tC" -> "abc".
        let spec = Spec {
            filter: Filter::NonSpace,
            map: Map::Lower,
            reversed: false,
            fn_name: "f",
        };
        assert_eq!(eval(&spec, "A B\tC"), "abc");
    }

    #[test]
    fn seeds_vary_the_pipeline() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}/{}", s.filter, s.map, s.reversed));
        }
        assert!(
            variants.len() >= 18,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_changes_under_every_combo() {
        // Both trivial baselines are caught on every seed only if the canonical
        // input is changed (identity) and left non-empty (empty) by every
        // (filter, map, order) combination.
        let canonical = "Hello, World!";
        for &filter in &[Filter::Alpha, Filter::Alnum, Filter::NonSpace, Filter::All] {
            for &map in &[Map::Upper, Map::Lower, Map::SwapCase] {
                for &reversed in &[false, true] {
                    let spec = Spec {
                        filter,
                        map,
                        reversed,
                        fn_name: "f",
                    };
                    let out = eval(&spec, canonical);
                    assert!(!out.is_empty(), "empty under {filter:?}/{map:?}/{reversed}");
                    assert_ne!(
                        out, canonical,
                        "unchanged under {filter:?}/{map:?}/{reversed}"
                    );
                }
            }
        }
    }

    #[test]
    fn reference_matches_native_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            let (_, cases) = worked_examples(&spec, seed);
            for (input, out) in cases {
                assert_eq!(eval(&spec, &input), out, "seed {seed}");
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = StringProcessingFamily;
        let t = g.generate(8);
        assert!(t.prompt.contains(&t.canary));
    }
}

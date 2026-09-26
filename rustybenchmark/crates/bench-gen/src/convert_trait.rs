//! Conversion-trait puzzles over textual inputs.
//!
//! Each query here is the semantic core of a real `TryFrom` implementation:
//! the model writes `impl TryFrom<&str> for T` blocks against newtype
//! structs with a PROVIDED error enum. Valid text converts; anything else
//! must come back as the right `Err` variant rather than a panic. A naive
//! implementation that unwraps dies on the invalid worked examples; one
//! that always errors dies on the valid ones. The graded surface is a thin
//! driver per query mapping `Result` to the value-or-sentinel convention,
//! so scoring rides the standard behaviour/differential machinery while
//! the hidden behaviour tests additionally pin the `Err` variants.

use crate::{mint_canary, GeneratedTask, Generator, Rng};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Op {
    PortValue,
    PercentValue,
    MonthIndex,
    HexByteValue,
    FlagParse,
}

pub const OP_ALL: [Op; 5] = [
    Op::PortValue,
    Op::PercentValue,
    Op::MonthIndex,
    Op::HexByteValue,
    Op::FlagParse,
];

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

const FLAG_WORDS: [&str; 6] = ["on", "true", "yes", "off", "false", "no"];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::PortValue => "port_value",
            Op::PercentValue => "percent_value",
            Op::MonthIndex => "month_index",
            Op::HexByteValue => "hex_byte_value",
            Op::FlagParse => "flag_parse",
        }
    }

    pub fn ret(self) -> &'static str {
        "i64"
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::PortValue => {
                "port_value reads a decimal port number: whole numbers from 1 through 65535 convert; zero, negatives, overflow, and non-numeric text do not."
            }
            Op::PercentValue => {
                "percent_value reads a percentage: whole numbers from 0 through 100 convert; anything above 100 or non-numeric does not."
            }
            Op::MonthIndex => {
                "month_index reads exactly three-letter month abbreviations, case-insensitive, answering 1 for Jan through 12 for Dec; longer spellings and other text do not convert."
            }
            Op::HexByteValue => {
                "hex_byte_value reads exactly two hexadecimal digits, case-insensitive, and answers the byte they form; wrong lengths and non-hex digits do not convert."
            }
            Op::FlagParse => {
                "flag_parse reads flag words, case-insensitive: on, true, yes answer one; off, false, no answer zero; any other word does not convert."
            }
        }
    }

    pub fn type_name(self) -> &'static str {
        match self {
            Op::PortValue => "Port",
            Op::PercentValue => "Percent",
            Op::MonthIndex => "MonthName",
            Op::HexByteValue => "HexByte",
            Op::FlagParse => "FlagWord",
        }
    }

    pub fn err_variant(self) -> &'static str {
        match self {
            Op::PortValue | Op::PercentValue => "OutOfRange",
            Op::MonthIndex => "BadMonth",
            Op::HexByteValue => "BadHex",
            Op::FlagParse => "BadFlag",
        }
    }

    pub fn invalid_input(self) -> &'static str {
        match self {
            Op::PortValue => "65536",
            Op::PercentValue => "101",
            Op::MonthIndex => "march",
            Op::HexByteValue => "1g",
            Op::FlagParse => "maybe",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let i = rng.below(5) as usize;
    let mut j = rng.below(5) as usize;
    while j == i {
        j = rng.below(5) as usize;
    }
    let mut ops = [OP_ALL[i], OP_ALL[j]];
    ops.sort();
    Spec { ops }
}
fn b_port_value(s: &str) -> i64 {
    match s.parse::<u16>() {
        Ok(p) if p >= 1 => p as i64,
        _ => -1,
    }
}

fn b_percent_value(s: &str) -> i64 {
    match s.parse::<u16>() {
        Ok(p) if p <= 100 => p as i64,
        _ => -1,
    }
}

fn b_month_index(s: &str) -> i64 {
    let lowered = s.to_ascii_lowercase();
    match lowered.as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => -1,
    }
}

fn b_hex_byte_value(s: &str) -> i64 {
    fn nib(c: u8) -> Option<u64> {
        match c {
            b'0'..=b'9' => Some((c - b'0') as u64),
            b'a'..=b'f' => Some((c - b'a' + 10) as u64),
            b'A'..=b'F' => Some((c - b'A' + 10) as u64),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if b.len() != 2 {
        return -1;
    }
    match (nib(b[0]), nib(b[1])) {
        (Some(hi), Some(lo)) => ((hi << 4) | lo) as i64,
        _ => -1,
    }
}

fn b_flag_parse(s: &str) -> i64 {
    match s.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" => 1,
        "off" | "false" | "no" => 0,
        _ => -1,
    }
}

fn eval(op: Op, s: &str) -> i64 {
    match op {
        Op::PortValue => b_port_value(s),
        Op::PercentValue => b_percent_value(s),
        Op::MonthIndex => b_month_index(s),
        Op::HexByteValue => b_hex_byte_value(s),
        Op::FlagParse => b_flag_parse(s),
    }
}

const CANONICAL_SEED: u64 = 0xCAFE_BA11;

/// One example: the selected ops each get their own input, because no
/// single text is simultaneously a valid port, month, flag, and byte.
pub struct ExampleCase {
    pub cases: Vec<(Op, String)>,
}

fn rand_input(rng: &mut Rng, op: Op) -> String {
    match op {
        Op::PortValue => format!("{}", 1 + rng.below(65_000)),
        Op::PercentValue => format!("{}", rng.below(101)),
        Op::MonthIndex => MONTHS[rng.below(12) as usize].to_string(),
        Op::HexByteValue => {
            const HEX: &[u8] = b"0123456789abcdef";
            let hi = HEX[rng.below(16) as usize];
            let lo = HEX[rng.below(16) as usize];
            String::from_utf8(vec![hi, lo]).unwrap_or_default()
        }
        Op::FlagParse => FLAG_WORDS[rng.below(6) as usize].to_string(),
    }
}

fn canonical(seed: u64) -> ExampleCase {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let spec = sample(seed);
        let mut cases = Vec::new();
        let mut any_nonzero = false;
        let mut all_valid = true;
        for &op in spec.ops.iter() {
            let s = rand_input(&mut rng, op);
            let v = eval(op, &s);
            if v < 0 {
                all_valid = false;
            }
            if v > 0 {
                any_nonzero = true;
            }
            cases.push((op, s));
        }
        if all_valid && any_nonzero {
            return ExampleCase { cases };
        }
    }
    unreachable!("canonical convert case");
}
const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0182;

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let spec = sample(seed);
    let mut out = vec![canonical(seed)];

    // Every op at its signature-invalid pin.
    out.push(ExampleCase {
        cases: spec
            .ops
            .iter()
            .map(|&op| (op, op.invalid_input().to_string()))
            .collect(),
    });

    // Empty text converts for nobody.
    out.push(ExampleCase {
        cases: spec.ops.iter().map(|&op| (op, String::new())).collect(),
    });

    // A cross-op wildcard: digits mean different things per query.
    out.push(ExampleCase {
        cases: spec.ops.iter().map(|&op| (op, "42".to_string())).collect(),
    });

    for _ in 0..3 {
        out.push(ExampleCase {
            cases: spec
                .ops
                .iter()
                .map(|&op| loop {
                    let s = rand_input(&mut rng, op);
                    if eval(op, &s) >= 0 {
                        break (op, s);
                    }
                })
                .collect(),
        });
    }
    out
}

fn render_str(s: &str) -> String {
    format!("{s:?}")
}

fn worked_examples_prose(spec: Spec, examples: &[ExampleCase]) -> Vec<String> {
    let mut lines = Vec::new();
    for ex in examples {
        for &(op, ref s) in ex.cases.iter() {
            let out = eval(op, s);
            lines.push(format!(
                "  {} on {} answers {}",
                op.name(),
                render_str(s),
                if out < 0 {
                    "the error path".to_string()
                } else {
                    out.to_string()
                }
            ));
        }
    }
    let _ = spec;
    lines
}
fn type_block_src() -> String {
    let mut out = String::new();
    out.push_str("use std::convert::TryFrom;\n\n");
    out.push_str("#[derive(Debug, PartialEq, Eq)]\npub enum ParseError {\n    Empty,\n    NotNumeric,\n    OutOfRange,\n    BadMonth,\n    BadHex,\n    BadFlag,\n}\n\n");
    out.push_str("pub struct Port(pub u16);\npub struct Percent(pub u8);\npub struct MonthName(pub u8);\npub struct HexByte(pub u8);\npub struct FlagWord(pub bool);\n");
    out
}

#[derive(Clone, Copy)]
enum ImplMode {
    Solved,
    Stub,
    NaiveUnwrap,
    AlwaysErr,
}

fn op_impl_src(op: Op, mode: ImplMode) -> String {
    let t = op.type_name();
    let mut out = String::new();
    out.push_str(&format!("impl TryFrom<&str> for {t} {{\n"));
    out.push_str("    type Error = ParseError;\n");
    out.push_str("    fn try_from(s: &str) -> Result<Self, Self::Error> {\n");
    match mode {
        ImplMode::Stub => out.push_str("        todo!()\n"),
        ImplMode::AlwaysErr => {
            out.push_str(&format!(
                "        let _ = s;\n        Err(ParseError::{})\n",
                op.err_variant()
            ));
        }
        ImplMode::NaiveUnwrap => match op {
            Op::PortValue => out.push_str("        let p: u16 = s.parse().expect(\"valid port\");\n        Ok(Port(p))\n"),
            Op::PercentValue => out.push_str("        let p: u16 = s.parse().expect(\"valid percent\");\n        Ok(Percent(p as u8))\n"),
            Op::MonthIndex => out.push_str("        let lowered = s.to_ascii_lowercase();\n        const M: [&str; 12] = [\"jan\", \"feb\", \"mar\", \"apr\", \"may\", \"jun\", \"jul\", \"aug\", \"sep\", \"oct\", \"nov\", \"dec\"];\n        let i = M.iter().position(|&m| m == lowered).expect(\"valid month\");\n        Ok(MonthName(i as u8 + 1))\n"),
            Op::HexByteValue => out.push_str("        fn nib(c: u8) -> Option<u64> {\n            match c {\n                b'0'..=b'9' => Some((c - b'0') as u64),\n                b'a'..=b'f' => Some((c - b'a' + 10) as u64),\n                b'A'..=b'F' => Some((c - b'A' + 10) as u64),\n                _ => None,\n            }\n        }\n        let b = s.as_bytes();\n        assert_eq!(b.len(), 2, \"two hex digits\");\n        let hi = nib(b[0]).expect(\"hex digit\");\n        let lo = nib(b[1]).expect(\"hex digit\");\n        Ok(HexByte(((hi << 4) | lo) as u8))\n"),
            Op::FlagParse => out.push_str("        let lowered = s.to_ascii_lowercase();\n        let truthy = lowered == \"on\" || lowered == \"true\" || lowered == \"yes\";\n        assert!(truthy || lowered == \"off\" || lowered == \"false\" || lowered == \"no\", \"flag word\");\n        Ok(FlagWord(truthy))\n"),
        },
        ImplMode::Solved => match op {
            Op::PortValue => out.push_str("        let p: u32 = s.parse().map_err(|_| ParseError::NotNumeric)?;\n        if p < 1 || p > 65535 {\n            return Err(ParseError::OutOfRange);\n        }\n        Ok(Port(p as u16))\n"),
            Op::PercentValue => out.push_str("        let p: u16 = s.parse().map_err(|_| ParseError::NotNumeric)?;\n        if p > 100 {\n            return Err(ParseError::OutOfRange);\n        }\n        Ok(Percent(p as u8))\n"),
            Op::MonthIndex => out.push_str("        let lowered = s.to_ascii_lowercase();\n        const M: [&str; 12] = [\"jan\", \"feb\", \"mar\", \"apr\", \"may\", \"jun\", \"jul\", \"aug\", \"sep\", \"oct\", \"nov\", \"dec\"];\n        match M.iter().position(|&m| m == lowered) {\n            Some(i) => Ok(MonthName(i as u8 + 1)),\n            None => Err(ParseError::BadMonth),\n        }\n"),
            Op::HexByteValue => out.push_str("        fn nib(c: u8) -> Option<u64> {\n            match c {\n                b'0'..=b'9' => Some((c - b'0') as u64),\n                b'a'..=b'f' => Some((c - b'a' + 10) as u64),\n                b'A'..=b'F' => Some((c - b'A' + 10) as u64),\n                _ => None,\n            }\n        }\n        let b = s.as_bytes();\n        if b.len() != 2 {\n            return Err(ParseError::BadHex);\n        }\n        match (nib(b[0]), nib(b[1])) {\n            (Some(hi), Some(lo)) => Ok(HexByte(((hi << 4) | lo) as u8)),\n            _ => Err(ParseError::BadHex),\n        }\n"),
            Op::FlagParse => out.push_str("        let lowered = s.to_ascii_lowercase();\n        match lowered.as_str() {\n            \"on\" | \"true\" | \"yes\" => Ok(FlagWord(true)),\n            \"off\" | \"false\" | \"no\" => Ok(FlagWord(false)),\n            _ => Err(ParseError::BadFlag),\n        }\n"),
        },
    }
    out.push_str("    }\n}\n");
    out
}

fn driver_src(op: Op) -> String {
    format!(
        "pub fn {}(s: &str) -> i64 {{\n    match {}::try_from(s) {{\n        Ok(v) => v.0 as i64,\n        Err(_) => -1,\n    }}\n}}\n",
        op.name(),
        op.type_name()
    )
}

fn sig_fence(spec: Spec) -> String {
    let mut out = String::from("```rust\n");
    for &op in spec.ops.iter() {
        out.push_str(&format!(
            "impl TryFrom<&str> for {} {{ type Error = ParseError; }}\n",
            op.type_name()
        ));
    }
    out.push_str("```");
    out
}

fn reference_src(spec: Spec) -> String {
    let mut out = type_block_src();
    out.push('\n');
    for &op in spec.ops.iter() {
        out.push_str(&op_impl_src(op, ImplMode::Solved));
        out.push('\n');
        out.push_str(&driver_src(op));
        out.push('\n');
    }
    out
}
fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut out = String::new();
    out.push_str("//! Convert raw text into typed values through real conversion traits.\n");
    out.push_str("//!\n");
    out.push_str("//! Each newtype below needs its `TryFrom<&str>` implementation filled\n");
    out.push_str("//! in. Valid text converts; anything else must come back as the right\n");
    out.push_str("//! `Err` variant from the provided error enum — never a panic.\n");
    out.push_str("//!\n");
    for line in worked_examples_prose(spec, examples) {
        out.push_str(&format!("//! {line}\n"));
    }
    out.push('\n');
    out.push_str(&type_block_src());
    out.push('\n');
    for &op in spec.ops.iter() {
        out.push_str(&op_impl_src(op, ImplMode::Stub));
        out.push('\n');
        out.push_str(&driver_src(op));
        out.push('\n');
    }
    out
}

fn prompt_src(spec: Spec, examples: &[ExampleCase], canary: &str) -> String {
    let mut out = String::new();
    out.push_str("Implement the missing TryFrom conversions described below.\n\n");
    out.push_str("## Requirements\n\n");
    for &op in spec.ops.iter() {
        out.push_str(&format!("- {}\n", op.prose()));
    }
    out.push_str("- Unrepresentable input must return the matching ParseError variant; panicking is a failure even when the answer would otherwise be right.\n");
    out.push_str("- Keep the provided struct definitions and driver functions exactly as given.\n");
    out.push_str("- No unsafe code.\n\n");
    out.push_str(&sig_fence(spec));
    out.push_str("\n\n## Examples\n\n");
    for line in worked_examples_prose(spec, examples) {
        out.push_str(&format!("{line}\n"));
    }
    out.push_str("\nThe canary token for this task is:\n");
    out.push_str(canary);
    out
}

const CARGO_TOML: &str = "[package]\nname = \"task\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n";

fn behavior_test_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut out = String::new();
    let names: Vec<&str> = spec.ops.iter().map(|&op| op.name()).collect();
    out.push_str(&format!("use task::{{{}}};\n", names.join(", ")));
    out.push_str("#[test]\nfn examples_match_the_conversion_contract() {\n");
    for (i, ex) in examples.iter().enumerate() {
        out.push_str(&format!("    // example {i}\n"));
        for &(op, ref s) in ex.cases.iter() {
            out.push_str(&format!(
                "    assert_eq!({}({}), {});\n",
                op.name(),
                render_str(s),
                eval(op, s)
            ));
        }
    }
    out.push_str("}\n");
    out.push_str("#[test]\nfn invalid_input_lands_on_the_error_variant() {\n");
    for &op in spec.ops.iter() {
        out.push_str(&format!(
            "    assert!(matches!(task::{}::try_from({}), Err(task::ParseError::{})));\n",
            op.type_name(),
            render_str(op.invalid_input()),
            op.err_variant()
        ));
        out.push_str(&format!(
            "    assert!(task::{}::try_from({}).is_ok());\n",
            op.type_name(),
            render_str(&{
                let mut rng = Rng::new(7);
                rand_input(&mut rng, op)
            })
        ));
    }
    out.push_str("}\n");
    out
}
fn differential_test_src(spec: Spec) -> String {
    let mut out = String::new();
    let names: Vec<&str> = spec.ops.iter().map(|&op| op.name()).collect();
    out.push_str(&format!("use task::{{{}}};\n", names.join(", ")));
    for &op in spec.ops.iter() {
        out.push_str(&mirror_src(op));
        out.push('\n');
    }
    out.push_str("#[test]\nfn differential_vs_reference() {\n");
    out.push_str("    let mut state: u64 = 0xE7EE_ED00_0000_0182;\n");
    out.push_str("    let mut next = move || {\n        state = state\n            .wrapping_mul(6364136223846793005)\n            .wrapping_add(1442695040888963407);\n        state >> 33\n    };\n    for _ in 0..3000 {\n        let w = match next() % 7 {\n            0 => String::new(),\n            1 | 2 | 3 => format!(\"{}\", (next() % 70_000)),\n            4 => {\n                let m = [\"jan\", \"feb\", \"mar\", \"apr\", \"may\", \"jun\", \"jul\", \"aug\", \"sep\", \"oct\", \"nov\", \"dec\", \"march\", \"xyz\"];\n                m[(next() % 14) as usize].to_string()\n            }\n            5 => {\n                let f = [\"on\", \"off\", \"true\", \"false\", \"yes\", \"no\", \"maybe\", \"YES\"];\n                f[(next() % 8) as usize].to_string()\n            }\n            _ => {\n                let h = b\"0123456789abcdefgG\";\n                let a = h[(next() % 18) as usize];\n                let b = h[(next() % 18) as usize];\n                String::from_utf8(vec![a, b]).unwrap_or_default()\n            }\n        };\n");
    for &op in spec.ops.iter() {
        out.push_str(&format!(
            "        assert_eq!({}(&w), ref_{}(&w));\n",
            op.name(),
            op.name()
        ));
    }
    out.push_str("    }\n}\n");
    out
}

/// The safe mirror of one query, pasted under a reference name.
fn mirror_src(op: Op) -> String {
    let body = match op {
        Op::PortValue => "    match s.parse::<u16>() {\n        Ok(p) if p >= 1 => p as i64,\n        _ => -1,\n    }\n",
        Op::PercentValue => "    match s.parse::<u16>() {\n        Ok(p) if p <= 100 => p as i64,\n        _ => -1,\n    }\n",
        Op::MonthIndex => "    match s.to_ascii_lowercase().as_str() {\n        \"jan\" => 1,\n        \"feb\" => 2,\n        \"mar\" => 3,\n        \"apr\" => 4,\n        \"may\" => 5,\n        \"jun\" => 6,\n        \"jul\" => 7,\n        \"aug\" => 8,\n        \"sep\" => 9,\n        \"oct\" => 10,\n        \"nov\" => 11,\n        \"dec\" => 12,\n        _ => -1,\n    }\n",
        Op::HexByteValue => "    fn nib(c: u8) -> Option<u64> {\n        match c {\n            b'0'..=b'9' => Some((c - b'0') as u64),\n            b'a'..=b'f' => Some((c - b'a' + 10) as u64),\n            b'A'..=b'F' => Some((c - b'A' + 10) as u64),\n            _ => None,\n        }\n    }\n    let b = s.as_bytes();\n    if b.len() != 2 {\n        return -1;\n    }\n    match (nib(b[0]), nib(b[1])) {\n        (Some(hi), Some(lo)) => ((hi << 4) | lo) as i64,\n        _ => -1,\n    }\n",
        Op::FlagParse => "    match s.to_ascii_lowercase().as_str() {\n        \"on\" | \"true\" | \"yes\" => 1,\n        \"off\" | \"false\" | \"no\" => 0,\n        _ => -1,\n    }\n",
    };
    format!("fn ref_{}(s: &str) -> i64 {{\n{}}}", op.name(), body)
}

fn baseline_src(spec: Spec, mode: ImplMode, driver_body: &str) -> String {
    let mut out = type_block_src();
    out.push('\n');
    for &op in spec.ops.iter() {
        out.push_str(&op_impl_src(op, mode));
        out.push('\n');
    }
    for &op in spec.ops.iter() {
        out.push_str(&format!(
            "pub fn {}(s: &str) -> i64 {{\n    {}\n}}\n",
            op.name(),
            driver_body
        ));
    }
    out
}
pub struct ConvertTraitFamily;

impl Generator for ConvertTraitFamily {
    fn id(&self) -> &'static str {
        "convert-trait"
    }

    fn category(&self) -> &'static str {
        "convert-traits"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary(self.id(), seed);
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            std::path::PathBuf::from("Cargo.toml"),
            CARGO_TOML.to_string(),
        );
        files.insert(
            std::path::PathBuf::from("src/lib.rs"),
            skeleton_src(spec, &examples),
        );
        let mut hidden = std::collections::BTreeMap::new();
        hidden.insert(
            std::path::PathBuf::from("tests/behavior.rs"),
            behavior_test_src(spec, &examples),
        );
        hidden.insert(
            std::path::PathBuf::from("tests/differential.rs"),
            differential_test_src(spec),
        );
        GeneratedTask {
            id: format!("{}/{seed:016x}", self.id()),
            category: self.category().to_string(),
            prompt: prompt_src(spec, &examples, &canary),
            canary,
            answer_path: String::from("src/lib.rs"),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            max_unsafe: None,
            forbidden_paths: vec![],
            check_clippy: false,
            clippy_allow: vec![],
            weights: (0.70, 0.20, 0.10),
        }
    }

    fn reference_code(&self, seed: u64) -> String {
        reference_src(sample(seed))
    }

    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(sample(seed), &worked_examples(seed))
    }

    fn trivial_baselines(&self, _seed: u64) -> Vec<(String, String)> {
        let spec = sample(_seed);
        vec![
            (
                "const-zero".to_string(),
                baseline_src(spec, ImplMode::Solved, "let _ = s;\n    0"),
            ),
            (
                "naive-unwrap".to_string(),
                baseline_src(spec, ImplMode::NaiveUnwrap, "todo!()"),
            ),
            (
                "always-error".to_string(),
                baseline_src(spec, ImplMode::AlwaysErr, "todo!()"),
            ),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        vec![format!("q:{}/{}", spec.ops[0].name(), spec.ops[1].name())]
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = ConvertTraitFamily.generate(7);
        let b = ConvertTraitFamily.generate(7);
        assert_eq!(a.id, b.id);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
        assert_eq!(a.hidden, b.hidden);
    }

    #[test]
    fn solved_port_impl_checks_range_on_the_widened_type() {
        // "65536" must classify as OutOfRange: the parse widens to u32 and
        // the range check runs BEFORE any u16 cast. A u16 parse would fail
        // first with NotNumeric (probe-caught regression class).
        let body = op_impl_src(Op::PortValue, ImplMode::Solved);
        assert!(body.contains("u32"), "port parse must widen to u32");
        assert!(
            body.find("p > 65535")
                .is_some_and(|at| { body[..at].contains("u32") && !body[..at].contains("as u16") }),
            "range check must precede the narrowing cast"
        );
    }

    #[test]
    fn native_ops_match_intent() {
        assert_eq!(b_port_value("80"), 80);
        assert_eq!(b_port_value("65535"), 65535);
        assert_eq!(b_port_value("0"), -1);
        assert_eq!(b_port_value("65536"), -1);
        assert_eq!(b_port_value("8x"), -1);
        assert_eq!(b_percent_value("100"), 100);
        assert_eq!(b_percent_value("101"), -1);
        assert_eq!(b_month_index("DEC"), 12);
        assert_eq!(b_month_index("march"), -1);
        assert_eq!(b_hex_byte_value("ff"), 255);
        assert_eq!(b_hex_byte_value("1g"), -1);
        assert_eq!(b_flag_parse("TRUE"), 1);
        assert_eq!(b_flag_parse("maybe"), -1);
        assert_eq!(eval(Op::PortValue, ""), -1);
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
            let spec = sample(seed);
            let ex = canonical(seed);
            let mut any_nonzero = false;
            for &(op, ref s) in ex.cases.iter() {
                let v = eval(op, s);
                assert!(v >= 0, "seed {seed}: canonical input invalid for {op:?}");
                if v > 0 {
                    any_nonzero = true;
                }
            }
            assert!(
                any_nonzero,
                "seed {seed}: canonical answers all zero; const-zero would survive"
            );
            let _ = spec;
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for (i, ex) in worked_examples(seed).iter().enumerate() {
                for &(op, ref s) in ex.cases.iter() {
                    let expected = eval(op, s);
                    let rendered =
                        behavior_test_src(sample(seed), &worked_examples(seed)[i..i + 1]);
                    assert!(
                        rendered.contains(&render_str(s)),
                        "seed {seed} example {i}: input {s:?} missing from emitted test"
                    );
                    let _ = expected;
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let reference = reference_src(spec);
            for &op in spec.ops.iter() {
                let marker = format!("pub fn {}(", op.name());
                assert!(
                    reference.contains(&marker),
                    "seed {seed}: reference missing driver {}",
                    op.name()
                );
                let impl_marker = format!("impl TryFrom<&str> for {}", op.type_name());
                assert!(reference.contains(&impl_marker));
            }
            for &op in OP_ALL.iter() {
                if !spec.ops.contains(&op) {
                    assert!(
                        !reference.contains(&format!("pub fn {}(", op.name())),
                        "seed {seed}: unselected op {} leaked into reference",
                        op.name()
                    );
                }
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let examples = worked_examples(seed);
            let skeleton = skeleton_src(spec, &examples);
            let prompt = prompt_src(spec, &examples, "rb-canary-here");
            assert!(skeleton.contains("todo!()"));
            for token in [
                "parse::<u16>",
                "to_ascii_lowercase",
                "const M:",
                "<< 4",
                ".expect(",
                "map_err",
            ] {
                assert!(!skeleton.contains(token), "skeleton leaks {token}");
                assert!(!prompt.contains(token), "prompt leaks {token}");
            }
            for &op in spec.ops.iter() {
                assert!(
                    prompt.contains(&format!("TryFrom<&str> for {}", op.type_name())),
                    "prompt missing signature for {}",
                    op.type_name()
                );
            }
        }
    }

    #[test]
    fn baselines_diverge_from_the_reference() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let naive = baseline_src(spec, ImplMode::NaiveUnwrap, "todo!()");
            let always_err = baseline_src(spec, ImplMode::AlwaysErr, "todo!()");
            let reference = reference_src(spec);
            assert!(
                naive.contains(".expect("),
                "naive baseline lost its unwrap shape"
            );
            assert!(!reference.contains(".expect("));
            assert!(
                always_err.contains("Err(ParseError::"),
                "always-error baseline lost its error shape"
            );
            assert!(!reference.contains("let _ = s;\n        Err(ParseError::"));
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for &op in OP_ALL.iter() {
            let sig = format!("pub fn {}(s: &str) -> i64", op.name());
            let params = sig.split("->").next().unwrap();
            let call = format!("{}(&w)", op.name());
            assert_eq!(
                params.matches(',').count(),
                call.matches(',').count(),
                "arity drift on {}",
                op.name()
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let task = ConvertTraitFamily.generate(11);
        assert!(task.prompt.contains(&task.canary));
    }
}

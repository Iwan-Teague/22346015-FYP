//! The `parse-traits` family (category `error-handling`) — implement **`FromStr`** and
//! **`TryFrom<i64>`** for a pinned newtype with a pinned error enum, getting the *validation order*
//! right.
//!
//! The other error-handling families fold, propagate, display and chain errors. This one is the
//! std conversion-trait pair every parsing type needs: `impl FromStr` (`type Err = ParseError`) and
//! `impl TryFrom<i64>` (`type Error = ParseError`), so that `"abc".parse::<Slug>()` and
//! `Slug::try_from(5)` / `5i64.try_into()` work. The pinned error is
//! `ParseError { Empty, BadChar(char), TooLong(usize), OutOfRange(i64) }`. What is graded is which
//! *variant and payload* comes out when an input is wrong in more than one way, which is a rule
//! stated in the prompt: **`CharsFirst`** checks characters before length; **`LengthFirst`** checks
//! length first, so `"BAD!!...(too long)"` is `TooLong`, not `BadChar`.
//!
//! Seed-selected on three axes:
//!
//! 1. **Type** — `Slug(String)` (lowercase letters, digits and `-`, at most `MAX_LEN` bytes),
//!    `Percent(u8)` (`"NN%"`, at most three digits, value at most 100) or `Code { letter, num }`
//!    (`"A1234"`: an uppercase letter and one to four digits).
//! 2. **Impl set** — `FromStr`, `TryFrom<i64>`, or both.
//! 3. **Order** — `CharsFirst` or `LengthFirst`.
//!
//! 3 x 3 x 2 = **18 distinct skills**; `MAX_LEN` is cosmetic and excluded from `spec_signature`
//! (Q31). Solution-first (ADR-0003): the native validators and the emitted impls are mirrored and
//! the differential compares 3000 random strings and integers against an inlined reference module
//! (results compared via their `Debug` text, since the two crates' types differ). `unwrap` and
//! `expect` are forbidden paths.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Ty {
    Slug,
    Percent,
    Code,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Impls {
    FromStr,
    TryFrom,
    Both,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Order {
    CharsFirst,
    LengthFirst,
}

struct Spec {
    ty: Ty,
    impls: Impls,
    order: Order,
    max_len: usize,
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let ty = match rng.below(3) {
        0 => Ty::Slug,
        1 => Ty::Percent,
        _ => Ty::Code,
    };
    let impls = match rng.below(3) {
        0 => Impls::FromStr,
        1 => Impls::TryFrom,
        _ => Impls::Both,
    };
    let order = if rng.below(2) == 0 {
        Order::CharsFirst
    } else {
        Order::LengthFirst
    };
    Spec {
        ty,
        impls,
        order,
        max_len: 6 + rng.below(8) as usize,
    }
}

fn has_from_str(s: &Spec) -> bool {
    matches!(s.impls, Impls::FromStr | Impls::Both)
}

fn has_try_from(s: &Spec) -> bool {
    matches!(s.impls, Impls::TryFrom | Impls::Both)
}

// ---- native reference ----------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum PE {
    Empty,
    BadChar(char),
    TooLong(usize),
    OutOfRange(i64),
}

/// A parsed value, rendered as a Rust literal (the type's name is fixed by the spec).
type Parsed = Result<String, PE>;

fn pe_lit(e: &PE) -> String {
    match e {
        PE::Empty => "ParseError::Empty".to_string(),
        PE::BadChar(c) => format!("ParseError::BadChar({c:?})"),
        PE::TooLong(n) => format!("ParseError::TooLong({n})"),
        PE::OutOfRange(v) => format!("ParseError::OutOfRange({v})"),
    }
}

fn slug_from_str(spec: &Spec, s: &str) -> Parsed {
    if s.is_empty() {
        return Err(PE::Empty);
    }
    let chars = || {
        s.chars()
            .find(|c| !matches!(c, 'a'..='z' | '0'..='9' | '-'))
            .map(PE::BadChar)
    };
    let len = || (s.len() > spec.max_len).then_some(PE::TooLong(s.len()));
    let e = match spec.order {
        Order::CharsFirst => chars().or_else(len),
        Order::LengthFirst => len().or_else(chars),
    };
    match e {
        Some(e) => Err(e),
        None => Ok(format!("Slug({s:?}.to_string())")),
    }
}

fn percent_from_str(spec: &Spec, s: &str) -> Parsed {
    if s.is_empty() {
        return Err(PE::Empty);
    }
    let Some(body) = s.strip_suffix('%') else {
        return Err(PE::BadChar(s.chars().last().unwrap_or('%')));
    };
    if body.is_empty() {
        return Err(PE::Empty);
    }
    let chars = || body.chars().find(|c| !c.is_ascii_digit()).map(PE::BadChar);
    let len = || (body.len() > 3).then_some(PE::TooLong(body.len()));
    let e = match spec.order {
        Order::CharsFirst => chars().or_else(len),
        Order::LengthFirst => len().or_else(chars),
    };
    if let Some(e) = e {
        return Err(e);
    }
    let v: i64 = body.parse().unwrap_or(0);
    if v > 100 {
        Err(PE::OutOfRange(v))
    } else {
        Ok(format!("Percent({v})"))
    }
}

fn code_from_str(spec: &Spec, s: &str) -> Parsed {
    if s.is_empty() {
        return Err(PE::Empty);
    }
    let c0 = s.chars().next().unwrap_or('A');
    let rest = &s[c0.len_utf8()..];
    let too_long = || (rest.len() > 4).then_some(PE::TooLong(rest.len()));
    let letter = || (!c0.is_ascii_uppercase()).then_some(PE::BadChar(c0));
    let tail = |_: ()| {
        if rest.is_empty() {
            Some(PE::Empty)
        } else {
            rest.chars().find(|c| !c.is_ascii_digit()).map(PE::BadChar)
        }
    };
    let e = match spec.order {
        // letter, then the digits (empty tail or a non-digit), then length
        Order::CharsFirst => letter().or_else(|| tail(())).or_else(too_long),
        // length first, then the same
        Order::LengthFirst => too_long().or_else(letter).or_else(|| tail(())),
    };
    if let Some(e) = e {
        return Err(e);
    }
    let num: u16 = rest.parse().unwrap_or(0);
    Ok(format!("Code {{ letter: {c0:?}, num: {num} }}"))
}

fn from_str(spec: &Spec, s: &str) -> Parsed {
    match spec.ty {
        Ty::Slug => slug_from_str(spec, s),
        Ty::Percent => percent_from_str(spec, s),
        Ty::Code => code_from_str(spec, s),
    }
}

fn try_from(spec: &Spec, n: i64) -> Parsed {
    match spec.ty {
        Ty::Slug => {
            if n < 0 {
                return Err(PE::OutOfRange(n));
            }
            let s = n.to_string();
            if s.len() > spec.max_len {
                return Err(PE::TooLong(s.len()));
            }
            Ok(format!("Slug({s:?}.to_string())"))
        }
        Ty::Percent => {
            if (0..=100).contains(&n) {
                Ok(format!("Percent({n})"))
            } else {
                Err(PE::OutOfRange(n))
            }
        }
        Ty::Code => {
            if (0..=9999).contains(&n) {
                Ok(format!("Code {{ letter: 'A', num: {n} }}"))
            } else {
                Err(PE::OutOfRange(n))
            }
        }
    }
}

// ---- emitted source ------------------------------------------------------------------------

fn ty_name(ty: Ty) -> &'static str {
    match ty {
        Ty::Slug => "Slug",
        Ty::Percent => "Percent",
        Ty::Code => "Code",
    }
}

fn prelude(spec: &Spec) -> String {
    let ty = match spec.ty {
        Ty::Slug => format!(
            "/// At most this many bytes.\npub const MAX_LEN: usize = {};\n\n#[derive(Debug, PartialEq)]\npub struct Slug(pub String);\n",
            spec.max_len
        ),
        Ty::Percent => "#[derive(Debug, PartialEq)]\npub struct Percent(pub u8);\n".to_string(),
        Ty::Code => "#[derive(Debug, PartialEq)]\npub struct Code {\n    pub letter: char,\n    pub num: u16,\n}\n".to_string(),
    };
    format!(
        "#[derive(Debug, PartialEq)]\npub enum ParseError {{\n    Empty,\n    BadChar(char),\n    TooLong(usize),\n    OutOfRange(i64),\n}}\n\n{ty}"
    )
}

fn from_str_src(spec: &Spec) -> String {
    let n = ty_name(spec.ty);
    let (chars, len, tail) = match spec.ty {
        Ty::Slug => (
            "        if let Some(c) = s.chars().find(|c| !matches!(c, 'a'..='z' | '0'..='9' | '-')) {\n            return Err(ParseError::BadChar(c));\n        }\n",
            "        if s.len() > MAX_LEN {\n            return Err(ParseError::TooLong(s.len()));\n        }\n",
            "        Ok(Slug(s.to_string()))\n",
        ),
        Ty::Percent => (
            "        if let Some(c) = body.chars().find(|c| !c.is_ascii_digit()) {\n            return Err(ParseError::BadChar(c));\n        }\n",
            "        if body.len() > 3 {\n            return Err(ParseError::TooLong(body.len()));\n        }\n",
            "        let v: i64 = body.parse().unwrap_or(0);\n        if v > 100 {\n            Err(ParseError::OutOfRange(v))\n        } else {\n            Ok(Percent(v as u8))\n        }\n",
        ),
        Ty::Code => (
            "        if !c0.is_ascii_uppercase() {\n            return Err(ParseError::BadChar(c0));\n        }\n        if rest.is_empty() {\n            return Err(ParseError::Empty);\n        }\n        if let Some(c) = rest.chars().find(|c| !c.is_ascii_digit()) {\n            return Err(ParseError::BadChar(c));\n        }\n",
            "        if rest.len() > 4 {\n            return Err(ParseError::TooLong(rest.len()));\n        }\n",
            "        let num: u16 = rest.parse().unwrap_or(0);\n        Ok(Code { letter: c0, num })\n",
        ),
    };
    let setup = match spec.ty {
        Ty::Slug => String::new(),
        Ty::Percent => "        let body = match s.strip_suffix('%') {\n            Some(b) => b,\n            None => return Err(ParseError::BadChar(s.chars().last().unwrap_or('%'))),\n        };\n        if body.is_empty() {\n            return Err(ParseError::Empty);\n        }\n".to_string(),
        Ty::Code => "        let c0 = s.chars().next().unwrap_or('A');\n        let rest = &s[c0.len_utf8()..];\n".to_string(),
    };
    // For `Code`, "chars" includes the letter/tail checks and LengthFirst puts length before them.
    let checks = match spec.order {
        Order::CharsFirst => format!("{chars}{len}"),
        Order::LengthFirst => format!("{len}{chars}"),
    };
    format!(
        "impl std::str::FromStr for {n} {{\n    type Err = ParseError;\n\n    fn from_str(s: &str) -> Result<{n}, ParseError> {{\n        if s.is_empty() {{\n            return Err(ParseError::Empty);\n        }}\n{setup}{checks}{tail}    }}\n}}\n"
    )
}

fn try_from_src(spec: &Spec) -> String {
    let n = ty_name(spec.ty);
    let body = match spec.ty {
        Ty::Slug => "        if n < 0 {\n            return Err(ParseError::OutOfRange(n));\n        }\n        let s = n.to_string();\n        if s.len() > MAX_LEN {\n            return Err(ParseError::TooLong(s.len()));\n        }\n        Ok(Slug(s))\n",
        Ty::Percent => "        if (0..=100).contains(&n) {\n            Ok(Percent(n as u8))\n        } else {\n            Err(ParseError::OutOfRange(n))\n        }\n",
        Ty::Code => "        if (0..=9999).contains(&n) {\n            Ok(Code { letter: 'A', num: n as u16 })\n        } else {\n            Err(ParseError::OutOfRange(n))\n        }\n",
    };
    format!(
        "impl TryFrom<i64> for {n} {{\n    type Error = ParseError;\n\n    fn try_from(n: i64) -> Result<{n}, ParseError> {{\n{body}    }}\n}}\n"
    )
}

fn reference_src(spec: &Spec) -> String {
    let mut s = prelude(spec);
    if has_from_str(spec) {
        s.push('\n');
        s.push_str(&from_str_src(spec));
    }
    if has_try_from(spec) {
        s.push('\n');
        s.push_str(&try_from_src(spec));
    }
    s
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .1
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Implement the conversion traits for `{}` below. The types are provided — keep them.\n//!\n{doc}\n{}\n// Your impls go here.\n",
        ty_name(spec.ty),
        prelude(spec)
    )
}

// ---- inputs and examples --------------------------------------------------------------------------

/// Hand-built strings that distinguish the validation orders (wrong in two ways at once), plus
/// boundaries; then seeded random strings over a small alphabet.
fn string_inputs(spec: &Spec, seed: u64) -> Vec<String> {
    let mut v: Vec<String> = match spec.ty {
        Ty::Slug => {
            let long_ok = "a".repeat(spec.max_len);
            let long = "a".repeat(spec.max_len + 3);
            vec![
                "".into(),
                "abc-12".into(),
                long_ok,
                format!("{long}!"), // too long AND a bad char: the order decides
                format!("A{}", "a".repeat(spec.max_len)), // bad first char AND too long by one
                "Abc".into(),
                "a b".into(),
                "x!y!".into(),
            ]
        }
        Ty::Percent => vec![
            "".into(),
            "7%".into(),
            "100%".into(),
            "101%".into(),
            "%".into(),
            "50".into(),
            "5x%".into(),
            "12345%".into(),
            "12x45%".into(), // too long AND a bad char
            "x1234%".into(), // bad char first, too long
        ],
        Ty::Code => vec![
            "".into(),
            "A".into(),
            "A1".into(),
            "Z9999".into(),
            "a123".into(),
            "A12345".into(),
            "A12x45".into(), // too long AND a bad char
            "a12345".into(), // bad letter AND too long
            "Axy".into(),
        ],
    };
    let mut rng = Rng::new(seed ^ 0x9A25_0000_0000_0D07);
    let alphabet: Vec<char> = match spec.ty {
        Ty::Slug => "ab1-A!".chars().collect(),
        Ty::Percent => "12%x".chars().collect(),
        Ty::Code => "AZ19a".chars().collect(),
    };
    for _ in 0..6 {
        let n = rng.below(10) as usize;
        v.push(
            (0..n)
                .map(|_| alphabet[rng.below(alphabet.len() as u64) as usize])
                .collect(),
        );
    }
    v
}

fn int_inputs(spec: &Spec) -> Vec<i64> {
    let mut v = vec![0, 7, 100, 101, -1, 9999, 10000, 123_456_789_012];
    v.push(10_i64.pow(spec.max_len as u32)); // exactly max_len+1 digits
    v.push(10_i64.pow(spec.max_len as u32) - 1); // exactly max_len digits
    v
}

fn result_lit(spec: &Spec, r: &Parsed) -> String {
    let _ = spec;
    match r {
        Ok(v) => format!("Ok({v})"),
        Err(e) => format!("Err({})", pe_lit(e)),
    }
}

fn worked_examples(spec: &Spec, seed: u64) -> (Vec<String>, String) {
    let strs = string_inputs(spec, seed);
    let mut prose = String::new();
    let n = ty_name(spec.ty);
    if has_from_str(spec) {
        for s in strs.iter().take(10) {
            prose.push_str(&format!(
                "  {s:?}.parse::<{n}>()  ->  {}\n",
                result_lit(spec, &from_str(spec, s))
            ));
        }
    }
    if has_try_from(spec) {
        for k in int_inputs(spec).iter().take(6) {
            prose.push_str(&format!(
                "  {n}::try_from({k}i64)  ->  {}\n",
                result_lit(spec, &try_from(spec, *k))
            ));
        }
    }
    (strs, prose)
}

fn order_prose(spec: &Spec) -> String {
    let what = match spec.ty {
        Ty::Slug => "characters (anything outside `a-z`, `0-9`, `-`)",
        Ty::Percent => "the digits before the `%` (anything that is not an ASCII digit)",
        Ty::Code => "the characters (the first must be `A-Z`, the rest ASCII digits)",
    };
    match spec.order {
        Order::CharsFirst => format!("Check the {what} **before** the length: an input that is both badly formed and too long is `BadChar`."),
        Order::LengthFirst => format!("Check the **length before** the {what}: an input that is both too long and badly formed is `TooLong`."),
    }
}

fn ty_prose(spec: &Spec) -> String {
    match spec.ty {
        Ty::Slug => format!("`Slug(String)`: lowercase ASCII letters, digits and `-`, at most `MAX_LEN` ({}) **bytes**. Empty input is `Empty`; the first offending character is `BadChar(c)`; a too-long input is `TooLong(<byte length>)`. `Slug::try_from(n: i64)`: negative is `OutOfRange(n)`, otherwise the slug of `n`'s decimal digits, `TooLong(<digit count>)` if that exceeds `MAX_LEN`.", spec.max_len),
        Ty::Percent => "`Percent(u8)`: text of the form `<digits>%`. Empty input is `Empty`; text that does not end in `%` is `BadChar(<its last character>)`; `\"%\"` alone is `Empty`. At most three digits (`TooLong(<digit count>)` otherwise); the first non-digit is `BadChar(c)`; a value above 100 is `OutOfRange(value)`. `Percent::try_from(n: i64)`: 0..=100, else `OutOfRange(n)`.".to_string(),
        Ty::Code => "`Code { letter, num }`: one uppercase ASCII letter then one to four ASCII digits (`\"A1234\"`). Empty input is `Empty`; a letter that is not `A-Z` is `BadChar(<that character>)`; a letter with nothing after it is `Empty`; the first non-digit after the letter is `BadChar(c)`; more than four digits is `TooLong(<digit count>)`. `Code::try_from(n: i64)`: 0..=9999 gives `Code { letter: 'A', num: n }`, else `OutOfRange(n)`.".to_string(),
    }
}

fn impls_prose(spec: &Spec) -> &'static str {
    match spec.impls {
        Impls::FromStr => "`impl std::str::FromStr` (`type Err = ParseError`), so `s.parse::<T>()` works",
        Impls::TryFrom => "`impl TryFrom<i64>` (`type Error = ParseError`), so `T::try_from(n)` and `n.try_into()` work",
        Impls::Both => "both `impl std::str::FromStr` (`type Err = ParseError`) and `impl TryFrom<i64>` (`type Error = ParseError`)",
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (_, examples) = worked_examples(spec, seed);
    let order = if has_from_str(spec) {
        format!("{}\n\n", order_prose(spec))
    } else {
        String::new()
    };
    format!(
        "In `src/lib.rs`, implement {impls} for `{n}`. `ParseError` and `{n}` are provided — keep them unchanged.\n\
         \n\
         {ty}\n\
         \n\
         {order}\
         Constraints:\n\
         - Return exactly the variants and payloads above. Do not use `unsafe`, `unwrap` or `expect`.\n\
         \n\
         Provided in `src/lib.rs`:\n\
         ```rust\n\
         {prelude}```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        impls = impls_prose(spec),
        n = ty_name(spec.ty),
        ty = ty_prose(spec),
        prelude = prelude(spec),
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
    let n = ty_name(spec.ty);
    let mut body = format!("use task::{{ParseError, {n}}};\n\n");
    if has_from_str(spec) {
        for (i, s) in string_inputs(spec, seed).iter().enumerate() {
            body.push_str(&format!(
                "#[test]\nfn parse{i}() {{\n    assert_eq!({s:?}.parse::<{n}>(), {});\n}}\n\n",
                result_lit(spec, &from_str(spec, s))
            ));
        }
    }
    if has_try_from(spec) {
        for (i, k) in int_inputs(spec).iter().enumerate() {
            body.push_str(&format!(
                "#[test]\nfn try_from{i}() {{\n    assert_eq!({n}::try_from({k}i64), {want});\n    let via_into: Result<{n}, ParseError> = ({k}i64).try_into();\n    assert_eq!(via_into, {want});\n}}\n\n",
                want = result_lit(spec, &try_from(spec, *k))
            ));
        }
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    let n = ty_name(spec.ty);
    let alphabet = match spec.ty {
        Ty::Slug => "ab1-A! z",
        Ty::Percent => "1239%x ",
        Ty::Code => "AZ19a ",
    };
    let mut checks = String::new();
    if has_from_str(spec) {
        checks.push_str(&format!(
            "        assert_eq!(format!(\"{{:?}}\", s.parse::<task::{n}>()), format!(\"{{:?}}\", s.parse::<reference::{n}>()), \"{{s:?}}\");\n"
        ));
    }
    if has_try_from(spec) {
        checks.push_str(&format!(
            "        assert_eq!(format!(\"{{:?}}\", task::{n}::try_from(k)), format!(\"{{:?}}\", reference::{n}::try_from(k)), \"{{k}}\");\n"
        ));
    }
    format!(
        "mod reference {{\n{indented}}}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let alphabet: Vec<char> = {alphabet:?}.chars().collect();\n\
         \x20   let mut state: u64 = 0x9A25_ED00_0000_0054;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 20) as usize;\n\
         \x20       let s: String = (0..len).map(|_| alphabet[(next() as usize) % alphabet.len()]).collect();\n\
         \x20       let k = (next() % 20001) as i64 - 5000;\n\
         \x20       let _ = (&s, k);\n\
         {checks}\
         \x20   }}\n\
         }}\n"
    )
}

/// Degenerate: always fails with `Empty` / `OutOfRange`.
fn always_err(spec: &Spec) -> String {
    let n = ty_name(spec.ty);
    let mut s = prelude(spec);
    if has_from_str(spec) {
        s.push_str(&format!("\nimpl std::str::FromStr for {n} {{\n    type Err = ParseError;\n\n    fn from_str(s: &str) -> Result<{n}, ParseError> {{\n        let _ = s;\n        Err(ParseError::Empty)\n    }}\n}}\n"));
    }
    if has_try_from(spec) {
        s.push_str(&format!("\nimpl TryFrom<i64> for {n} {{\n    type Error = ParseError;\n\n    fn try_from(n: i64) -> Result<{n}, ParseError> {{\n        Err(ParseError::OutOfRange(n))\n    }}\n}}\n"));
    }
    s
}

/// Degenerate: lenient: accepts everything it can wrap.
fn lenient(spec: &Spec) -> String {
    let n = ty_name(spec.ty);
    let (from_body, try_body) = match spec.ty {
        Ty::Slug => ("Ok(Slug(s.to_string()))", "Ok(Slug(n.to_string()))"),
        Ty::Percent => (
            "Ok(Percent(s.trim_end_matches('%').parse().unwrap_or(0)))",
            "Ok(Percent(n as u8))",
        ),
        Ty::Code => (
            "Ok(Code { letter: s.chars().next().unwrap_or('A'), num: 0 })",
            "Ok(Code { letter: 'A', num: n as u16 })",
        ),
    };
    let mut s = prelude(spec);
    if has_from_str(spec) {
        s.push_str(&format!("\nimpl std::str::FromStr for {n} {{\n    type Err = ParseError;\n\n    fn from_str(s: &str) -> Result<{n}, ParseError> {{\n        {from_body}\n    }}\n}}\n"));
    }
    if has_try_from(spec) {
        s.push_str(&format!("\nimpl TryFrom<i64> for {n} {{\n    type Error = ParseError;\n\n    fn try_from(n: i64) -> Result<{n}, ParseError> {{\n        {try_body}\n    }}\n}}\n"));
    }
    s
}

pub struct ParseTraitsFamily;

impl Generator for ParseTraitsFamily {
    fn id(&self) -> &str {
        "parse-traits"
    }
    fn category(&self) -> &str {
        "error-handling"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("parse-traits", seed);

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
            id: format!("parse-traits/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            max_unsafe: Some(0),
            forbidden_paths: vec!["unwrap".to_string(), "expect".to_string()],
            check_clippy: false,
            clippy_allow: Vec::new(),
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
            ("always-err".to_string(), always_err(&spec)),
            ("lenient".to_string(), lenient(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let ty = match spec.ty {
            Ty::Slug => "slug",
            Ty::Percent => "percent",
            Ty::Code => "code",
        };
        let impls = match spec.impls {
            Impls::FromStr => "from_str",
            Impls::TryFrom => "try_from",
            Impls::Both => "both",
        };
        // The validation order only matters when `FromStr` is implemented.
        let order = if has_from_str(&spec) {
            match spec.order {
                Order::CharsFirst => "chars_first",
                Order::LengthFirst => "length_first",
            }
        } else {
            "n/a"
        };
        vec![
            format!("ty:{ty}"),
            format!("impls:{impls}"),
            format!("order:{order}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(ty: Ty, impls: Impls, order: Order) -> Spec {
        Spec {
            ty,
            impls,
            order,
            max_len: 8,
        }
    }

    #[test]
    fn generation_is_deterministic() {
        let g = ParseTraitsFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn validators_match_intent() {
        let s = spec(Ty::Slug, Impls::Both, Order::CharsFirst);
        assert_eq!(
            slug_from_str(&s, "abc-1"),
            Ok("Slug(\"abc-1\".to_string())".to_string())
        );
        assert_eq!(slug_from_str(&s, ""), Err(PE::Empty));
        assert_eq!(slug_from_str(&s, "aXb"), Err(PE::BadChar('X')));
        assert_eq!(slug_from_str(&s, "aaaaaaaaa"), Err(PE::TooLong(9)));
        // Both wrong: the order decides.
        assert_eq!(slug_from_str(&s, "aaaaaaaaaX"), Err(PE::BadChar('X')));
        let l = spec(Ty::Slug, Impls::Both, Order::LengthFirst);
        assert_eq!(slug_from_str(&l, "aaaaaaaaaX"), Err(PE::TooLong(10)));
        let p = spec(Ty::Percent, Impls::Both, Order::CharsFirst);
        assert_eq!(percent_from_str(&p, "50%"), Ok("Percent(50)".to_string()));
        assert_eq!(percent_from_str(&p, "101%"), Err(PE::OutOfRange(101)));
        assert_eq!(percent_from_str(&p, "50"), Err(PE::BadChar('0')));
        assert_eq!(percent_from_str(&p, "%"), Err(PE::Empty));
        assert_eq!(percent_from_str(&p, "12x45%"), Err(PE::BadChar('x')));
        let pl = spec(Ty::Percent, Impls::Both, Order::LengthFirst);
        assert_eq!(percent_from_str(&pl, "12x45%"), Err(PE::TooLong(5)));
        let c = spec(Ty::Code, Impls::Both, Order::CharsFirst);
        assert_eq!(
            code_from_str(&c, "A12"),
            Ok("Code { letter: 'A', num: 12 }".to_string())
        );
        assert_eq!(code_from_str(&c, "A"), Err(PE::Empty));
        assert_eq!(code_from_str(&c, "a12345"), Err(PE::BadChar('a')));
        let cl = spec(Ty::Code, Impls::Both, Order::LengthFirst);
        assert_eq!(code_from_str(&cl, "a12345"), Err(PE::TooLong(5)));
        assert_eq!(try_from(&c, 10_000), Err(PE::OutOfRange(10_000)));
    }

    #[test]
    fn the_inputs_distinguish_the_two_orders_for_every_type() {
        // The order axis is only graded if some input is wrong in both ways at once.
        for ty in [Ty::Slug, Ty::Percent, Ty::Code] {
            let a = spec(ty, Impls::FromStr, Order::CharsFirst);
            let b = spec(ty, Impls::FromStr, Order::LengthFirst);
            let ins = string_inputs(&a, 3);
            assert!(
                ins.iter().any(|s| from_str(&a, s) != from_str(&b, s)),
                "{ty:?}: no input separates the validation orders"
            );
        }
    }

    #[test]
    fn the_baselines_are_wrong_on_the_inputs() {
        for ty in [Ty::Slug, Ty::Percent, Ty::Code] {
            let s = spec(ty, Impls::Both, Order::CharsFirst);
            let ins = string_inputs(&s, 3);
            // always-err is wrong whenever some input parses; lenient is wrong whenever some
            // input is rejected.
            assert!(ins.iter().any(|x| from_str(&s, x).is_ok()), "{ty:?}");
            assert!(ins.iter().any(|x| from_str(&s, x).is_err()), "{ty:?}");
            assert!(int_inputs(&s).iter().any(|&k| try_from(&s, k).is_ok()));
            assert!(int_inputs(&s).iter().any(|&k| try_from(&s, k).is_err()));
        }
    }

    #[test]
    fn order_is_not_part_of_the_signature_without_from_str() {
        let mut sigs = std::collections::HashSet::new();
        for seed in 0..600u64 {
            sigs.insert(ParseTraitsFamily.spec_signature(seed).join("|"));
        }
        // 3 types x (FromStr x 2 orders + Both x 2 orders + TryFrom x 1) = 15.
        assert_eq!(sigs.len(), 15);
    }

    #[test]
    fn unwrap_expect_forbidden_and_canary_present() {
        let t = ParseTraitsFamily.generate(3);
        assert!(t.forbidden_paths.contains(&"unwrap".to_string()));
        assert!(t.prompt.contains(&t.canary));
    }
}

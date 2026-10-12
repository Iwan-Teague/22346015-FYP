//! The `idiom-shape` family (category `idiom-refactor`) — the seventh idiom-refactor family, on
//! three **API-shape** lints that `cargo clippy --fix` cannot apply and whose idiomatic fix
//! *changes the public API*: **`clippy::result_unit_err`**, **`clippy::large_enum_variant`**
//! and **`clippy::too_many_arguments`**.
//!
//! Earlier idiom families rewrite a loop (`idiom-loop`, `-counter`, `-copy`), the body of an API
//! (`idiom-api`, `-traits`) or a signature's borrow form (`idiom-ptr`). These three lints are
//! different: the fix is a *new type or layout*, so a prompt has to **pin the API change** for
//! the hidden tests to call it. The prompt names every new type, field and message exactly.
//! (Measured against the installed clippy 1.97, all three survive `cargo clippy --fix`.)
//!
//! * **Unit error** — `pub fn parse_level(s: &str) -> Result<u8, ()>` must return a real error
//!   type `LevelError` that implements `Display` and `std::error::Error`. Style A: a tuple struct
//!   carrying the input; style B: an enum with `Empty`, `NotNumber(input)` and `OutOfRange(value)`.
//! * **Large variant** — `enum Packet { Ping, Text(String), Data([u8; 512]) }` (style A) or
//!   `Frame(Frame)` with a 416-byte `Frame` struct (style B) must hold the big payload in a `Box`.
//! * **Too many arguments** — `fn score(w, h, d, t, a, b, c, e: i64)` takes eight scalars. Style A
//!   bundles them into one `Params` struct; style B into two (`Dims` and `Coef`).
//!
//! Seed-selected on **which defects are present** (the 7 non-empty subsets) and **each present
//! defect's style** (2 each): 3x2 + 3x4 + 1x8 = **26 distinct skills**. Coefficients, bounds and
//! the weight formula's constant are cosmetic and excluded from `spec_signature` (Q31). The hidden
//! tests use the *new* API (so an unchanged answer does not build), `allow` is a forbidden path,
//! and behaviour is the same function in a new shape. Constraint-dominant per docs/04.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Style {
    A,
    B,
}

struct Spec {
    /// Style of each present defect: unit error, large variant, too many args.
    err: Option<Style>,
    big: Option<Style>,
    args: Option<Style>,
    lo: i64,
    hi: i64,
    /// `weight` of a `Data` packet sums this many leading bytes.
    take: usize,
    /// Coefficients of `score`.
    k: [i64; 4],
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let mask = 1 + rng.below(7) as u8;
    let style = |rng: &mut Rng| {
        if rng.below(2) == 0 {
            Style::A
        } else {
            Style::B
        }
    };
    let err = (mask & 1 != 0).then(|| style(&mut rng));
    let big = (mask & 2 != 0).then(|| style(&mut rng));
    let args = (mask & 4 != 0).then(|| style(&mut rng));
    let lo = rng.below(5) as i64;
    let hi = lo + 5 + rng.below(40) as i64;
    Spec {
        err,
        big,
        args,
        lo,
        hi,
        take: 3 + rng.below(10) as usize,
        k: [
            2 + rng.below(4) as i64,
            2 + rng.below(4) as i64,
            2 + rng.below(4) as i64,
            2 + rng.below(4) as i64,
        ],
    }
}

// ---- native reference ------------------------------------------------------------------

/// `parse_level`: Ok(level) or the style-B failure (the style-A error carries the input only).
#[derive(Clone, Debug, PartialEq)]
enum LevelFail {
    Empty,
    NotNumber(String),
    OutOfRange(i64),
}

fn parse_level(spec: &Spec, s: &str) -> Result<u8, LevelFail> {
    let t = s.trim();
    if t.is_empty() {
        return Err(LevelFail::Empty);
    }
    let v: i64 = t.parse().map_err(|_| LevelFail::NotNumber(s.to_string()))?;
    if (spec.lo..=spec.hi).contains(&v) {
        Ok(v as u8)
    } else {
        Err(LevelFail::OutOfRange(v))
    }
}

fn score(spec: &Spec, p: [i64; 8]) -> i64 {
    let [w, h, d, t, a, b, c, e] = p;
    w * h * spec.k[0] + d * t * spec.k[1] - a * b * spec.k[2] + c * spec.k[3] - e
}

// ---- emitted source ----------------------------------------------------------------------

const PARAM_NAMES: [&str; 8] = ["w", "h", "d", "t", "a", "b", "c", "e"];

fn score_expr(spec: &Spec, access: &dyn Fn(&str) -> String) -> String {
    let v = |n: &str| access(n);
    format!(
        "{} * {} * {k0} + {} * {} * {k1} - {} * {} * {k2} + {} * {k3} - {}",
        v("w"),
        v("h"),
        v("d"),
        v("t"),
        v("a"),
        v("b"),
        v("c"),
        v("e"),
        k0 = spec.k[0],
        k1 = spec.k[1],
        k2 = spec.k[2],
        k3 = spec.k[3],
    )
}

fn parse_level_given(spec: &Spec) -> String {
    format!(
        "pub fn parse_level(s: &str) -> Result<u8, ()> {{\n\
         \x20   let t = s.trim();\n\
         \x20   if t.is_empty() {{\n\
         \x20       return Err(());\n\
         \x20   }}\n\
         \x20   let v: i64 = t.parse().map_err(|_| ())?;\n\
         \x20   if ({lo}..={hi}).contains(&v) {{\n\
         \x20       Ok(v as u8)\n\
         \x20   }} else {{\n\
         \x20       Err(())\n\
         \x20   }}\n\
         }}\n",
        lo = spec.lo,
        hi = spec.hi
    )
}

fn parse_level_ref(spec: &Spec, style: Style) -> String {
    let (ty, empty, notnum, range) = match style {
        Style::A => (
            "#[derive(Debug, PartialEq)]\npub struct LevelError(pub String);\n\nimpl std::fmt::Display for LevelError {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        write!(f, \"invalid level: {}\", self.0)\n    }\n}\n\nimpl std::error::Error for LevelError {}\n\n",
            "LevelError(s.to_string())",
            "LevelError(s.to_string())",
            "LevelError(s.to_string())",
        ),
        Style::B => (
            "#[derive(Debug, PartialEq)]\npub enum LevelError {\n    Empty,\n    NotNumber(String),\n    OutOfRange(i64),\n}\n\nimpl std::fmt::Display for LevelError {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        match self {\n            LevelError::Empty => write!(f, \"empty\"),\n            LevelError::NotNumber(s) => write!(f, \"not a number: {s}\"),\n            LevelError::OutOfRange(v) => write!(f, \"{v} is out of range\"),\n        }\n    }\n}\n\nimpl std::error::Error for LevelError {}\n\n",
            "LevelError::Empty",
            "LevelError::NotNumber(s.to_string())",
            "LevelError::OutOfRange(v)",
        ),
    };
    format!(
        "{ty}pub fn parse_level(s: &str) -> Result<u8, LevelError> {{\n\
         \x20   let t = s.trim();\n\
         \x20   if t.is_empty() {{\n\
         \x20       return Err({empty});\n\
         \x20   }}\n\
         \x20   let v: i64 = t.parse().map_err(|_| {notnum})?;\n\
         \x20   if ({lo}..={hi}).contains(&v) {{\n\
         \x20       Ok(v as u8)\n\
         \x20   }} else {{\n\
         \x20       Err({range})\n\
         \x20   }}\n\
         }}\n",
        lo = spec.lo,
        hi = spec.hi
    )
}

fn packet_given(spec: &Spec, style: Style) -> String {
    packet_src(spec, style, false)
}

fn packet_src(spec: &Spec, style: Style, boxed: bool) -> String {
    let (decl, variant, weight_arm) = match style {
        Style::A => (
            String::new(),
            if boxed {
                "Data(Box<[u8; 512]>)"
            } else {
                "Data([u8; 512])"
            },
            format!(
                "Packet::Data(b) => b.iter().take({}).map(|&x| x as usize).sum(),",
                spec.take
            ),
        ),
        Style::B => (
            "pub struct Frame {\n    pub header: [u8; 16],\n    pub body: [u8; 400],\n}\n\n".to_string(),
            if boxed { "Frame(Box<Frame>)" } else { "Frame(Frame)" },
            "Packet::Frame(f) => f.header.iter().map(|&x| x as usize).sum::<usize>() + f.body.len(),"
                .to_string(),
        ),
    };
    format!(
        "{decl}pub enum Packet {{\n    Ping,\n    Text(String),\n    {variant},\n}}\n\n\
         pub fn weight(p: &Packet) -> usize {{\n    match p {{\n        Packet::Ping => 1,\n        Packet::Text(s) => s.len(),\n        {weight_arm}\n    }}\n}}\n"
    )
}

fn score_given(spec: &Spec) -> String {
    let params = PARAM_NAMES
        .iter()
        .map(|n| format!("{n}: i64"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "pub fn score({params}) -> i64 {{\n    {}\n}}\n",
        score_expr(spec, &|n| n.to_string())
    )
}

fn score_ref(spec: &Spec, style: Style) -> String {
    match style {
        Style::A => {
            let fields: String = PARAM_NAMES
                .iter()
                .map(|n| format!("    pub {n}: i64,\n"))
                .collect();
            format!(
                "pub struct Params {{\n{fields}}}\n\npub fn score(p: Params) -> i64 {{\n    {}\n}}\n",
                score_expr(spec, &|n| format!("p.{n}"))
            )
        }
        Style::B => {
            let dims: String = ["w", "h", "d", "t"]
                .iter()
                .map(|n| format!("    pub {n}: i64,\n"))
                .collect();
            let coef: String = ["a", "b", "c", "e"]
                .iter()
                .map(|n| format!("    pub {n}: i64,\n"))
                .collect();
            let access = |n: &str| {
                if ["w", "h", "d", "t"].contains(&n) {
                    format!("dims.{n}")
                } else {
                    format!("coef.{n}")
                }
            };
            format!(
                "pub struct Dims {{\n{dims}}}\n\npub struct Coef {{\n{coef}}}\n\npub fn score(dims: Dims, coef: Coef) -> i64 {{\n    {}\n}}\n",
                score_expr(spec, &access)
            )
        }
    }
}

fn given_src(spec: &Spec) -> String {
    let mut parts = Vec::new();
    if spec.err.is_some() {
        parts.push(parse_level_given(spec));
    }
    if let Some(s) = spec.big {
        parts.push(packet_given(spec, s));
    }
    if spec.args.is_some() {
        parts.push(score_given(spec));
    }
    parts.join("\n")
}

fn reference_src(spec: &Spec) -> String {
    let mut parts = Vec::new();
    if let Some(s) = spec.err {
        parts.push(parse_level_ref(spec, s));
    }
    if let Some(s) = spec.big {
        parts.push(packet_src(spec, s, true));
    }
    if let Some(s) = spec.args {
        parts.push(score_ref(spec, s));
    }
    parts.join("\n")
}

fn skeleton_src(spec: &Spec) -> String {
    format!(
        "//! Make this API idiomatic and clippy-clean; the prompt pins the new types.\n\n{}",
        given_src(spec)
    )
}

// ---- prompt ---------------------------------------------------------------------------------

fn err_prose(spec: &Spec, style: Style) -> String {
    let (lo, hi) = (spec.lo, spec.hi);
    match style {
        Style::A => format!(
            "- `parse_level` returns `Result<u8, ()>` (clippy: `result_unit_err`). Make it return `Result<u8, LevelError>` with \
             `pub struct LevelError(pub String);` holding the **original, untrimmed input**. `LevelError` derives `Debug` and \
             `PartialEq`, implements `std::fmt::Display` as `invalid level: <input>`, and implements `std::error::Error`. \
             Behaviour is unchanged: the trimmed text must parse as an integer in {lo}..={hi}."
        ),
        Style::B => format!(
            "- `parse_level` returns `Result<u8, ()>` (clippy: `result_unit_err`). Make it return `Result<u8, LevelError>` with \
             `pub enum LevelError {{ Empty, NotNumber(String), OutOfRange(i64) }}` (derive `Debug` and `PartialEq`): \
             `Empty` when the trimmed text is empty, `NotNumber(<original, untrimmed input>)` when it is not an integer, \
             `OutOfRange(<value>)` when it is outside {lo}..={hi}. `Display`: `empty`, `not a number: <input>`, \
             `<value> is out of range`. It implements `std::error::Error`."
        ),
    }
}

fn big_prose(style: Style) -> &'static str {
    match style {
        Style::A => "- `Packet::Data` holds a 512-byte array inline, making every `Packet` that big (clippy: `large_enum_variant`). Change it to `Data(Box<[u8; 512]>)`; `weight` keeps its behaviour.",
        Style::B => "- `Packet::Frame` holds a 416-byte `Frame` inline (clippy: `large_enum_variant`). Change it to `Frame(Box<Frame>)`; the `Frame` struct and `weight`'s behaviour are unchanged.",
    }
}

fn args_prose(style: Style) -> &'static str {
    match style {
        Style::A => "- `score` takes eight `i64` arguments (clippy: `too_many_arguments`). Replace them with one struct: `pub struct Params { pub w: i64, pub h: i64, pub d: i64, pub t: i64, pub a: i64, pub b: i64, pub c: i64, pub e: i64 }` and `pub fn score(p: Params) -> i64`. The result is unchanged.",
        Style::B => "- `score` takes eight `i64` arguments (clippy: `too_many_arguments`). Group them into two structs: `pub struct Dims { pub w: i64, pub h: i64, pub d: i64, pub t: i64 }` and `pub struct Coef { pub a: i64, pub b: i64, pub c: i64, pub e: i64 }`, with `pub fn score(dims: Dims, coef: Coef) -> i64`. The result is unchanged.",
    }
}

fn examples(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    let mut rng = Rng::new(seed ^ 0x1D5A_0000_0000_0A01);
    if spec.err.is_some() {
        for text in ["  7 ", "", "x9", "1000"] {
            let shown = match (spec.err, parse_level(spec, text)) {
                (_, Ok(v)) => format!("Ok({v})"),
                (Some(Style::A), Err(_)) => format!("Err(LevelError({text:?}.to_string()))"),
                (_, Err(LevelFail::Empty)) => "Err(LevelError::Empty)".to_string(),
                (_, Err(LevelFail::NotNumber(i))) => {
                    format!("Err(LevelError::NotNumber({i:?}.to_string()))")
                }
                (_, Err(LevelFail::OutOfRange(v))) => format!("Err(LevelError::OutOfRange({v}))"),
            };
            s.push_str(&format!("  parse_level({text:?})  ->  {shown}\n"));
        }
    }
    if spec.big.is_some() {
        s.push_str("  weight(&Packet::Ping)  ->  1\n  weight(&Packet::Text(\"hello\".to_string()))  ->  5\n");
    }
    if spec.args.is_some() {
        for _ in 0..2 {
            let p: [i64; 8] = std::array::from_fn(|_| rng.below(9) as i64 - 3);
            s.push_str(&format!(
                "  score({p:?} as the eight arguments in order)  ->  {}\n",
                score(spec, p)
            ));
        }
    }
    s
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let mut items = String::new();
    if let Some(st) = spec.err {
        items.push_str(&err_prose(spec, st));
        items.push('\n');
    }
    if let Some(st) = spec.big {
        items.push_str(big_prose(st));
        items.push('\n');
    }
    if let Some(st) = spec.args {
        items.push_str(args_prose(st));
        items.push('\n');
    }
    format!(
        "The functions in `src/lib.rs` work but trip clippy lints whose idiomatic fix changes the public API. \
         Fix every lint below **exactly as specified** (the checks call the new API) while preserving behaviour:\n\
         {items}\n\
         Here is the current code:\n\
         \n\
         ```rust\n\
         {current}\n\
         ```\n\
         \n\
         Examples of the behaviour that must hold:\n\
         {examples}\n\
         Constraints:\n\
         - The rewrite must produce **no** `clippy` warnings and must not hide them with `#[allow(..)]`.\n\
         - Use exactly the names and field names above. Do not use `unsafe`.\n\
         \n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        current = given_src(spec).trim_end(),
        examples = examples(spec, seed),
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

// ---- tests -------------------------------------------------------------------------------------

fn imports(spec: &Spec, krate: &str) -> String {
    let mut names: Vec<&str> = Vec::new();
    if let Some(s) = spec.err {
        names.extend(["parse_level", "LevelError"]);
        let _ = s;
    }
    if let Some(s) = spec.big {
        names.extend(["weight", "Packet"]);
        if s == Style::B {
            names.push("Frame");
        }
    }
    if let Some(s) = spec.args {
        names.push("score");
        names.extend(if s == Style::A {
            vec!["Params"]
        } else {
            vec!["Dims", "Coef"]
        });
    }
    format!("use {krate}::{{{}}};\n", names.join(", "))
}

fn level_expected(spec: &Spec, text: &str) -> String {
    match (spec.err, parse_level(spec, text)) {
        (_, Ok(v)) => format!("Ok({v})"),
        (Some(Style::A), Err(_)) => format!("Err(LevelError({text:?}.to_string()))"),
        (_, Err(LevelFail::Empty)) => "Err(LevelError::Empty)".to_string(),
        (_, Err(LevelFail::NotNumber(i))) => {
            format!("Err(LevelError::NotNumber({i:?}.to_string()))")
        }
        (_, Err(LevelFail::OutOfRange(v))) => format!("Err(LevelError::OutOfRange({v}))"),
    }
}

fn level_message(spec: &Spec, text: &str) -> Option<String> {
    match (spec.err?, parse_level(spec, text)) {
        (_, Ok(_)) => None,
        (Style::A, Err(_)) => Some(format!("invalid level: {text}")),
        (Style::B, Err(LevelFail::Empty)) => Some("empty".to_string()),
        (Style::B, Err(LevelFail::NotNumber(i))) => Some(format!("not a number: {i}")),
        (Style::B, Err(LevelFail::OutOfRange(v))) => Some(format!("{v} is out of range")),
    }
}

const LEVEL_CASES: [&str; 8] = ["7", "  7 ", "", "   ", "x9", "-3", "1000", "0"];

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let mut body = format!("{}\n", imports(spec, "task"));
    let mut rng = Rng::new(seed ^ 0x1D5B_0000_0000_0A02);
    if spec.err.is_some() {
        let mut cases: Vec<String> = LEVEL_CASES.iter().map(|s| s.to_string()).collect();
        cases.push(format!("{}", spec.lo));
        cases.push(format!("{}", spec.hi + 1));
        for (i, t) in cases.iter().enumerate() {
            body.push_str(&format!(
                "#[test]\nfn level{i}() {{\n    assert_eq!(parse_level({t:?}), {});\n",
                level_expected(spec, t)
            ));
            if let Some(m) = level_message(spec, t) {
                body.push_str(&format!(
                    "    assert_eq!(parse_level({t:?}).unwrap_err().to_string(), {m:?});\n    let boxed: Result<u8, Box<dyn std::error::Error>> = parse_level({t:?}).map_err(|e| e.into());\n    assert!(boxed.is_err());\n"
                ));
            }
            body.push_str("}\n\n");
        }
    }
    if let Some(style) = spec.big {
        let (data, dw) = match style {
            Style::A => (
                "Packet::Data(Box::new([5u8; 512]))".to_string(),
                (5 * spec.take.min(512)).to_string(),
            ),
            Style::B => (
                "Packet::Frame(Box::new(Frame { header: [2; 16], body: [9; 400] }))".to_string(),
                (2 * 16 + 400).to_string(),
            ),
        };
        body.push_str(&format!(
            "#[test]\nfn packets() {{\n    assert_eq!(weight(&Packet::Ping), 1);\n    assert_eq!(weight(&Packet::Text(\"hello\".to_string())), 5);\n    assert_eq!(weight(&{data}), {dw});\n    // The point of the Box: the enum is no bigger than its payload pointer plus a tag.\n    assert!(std::mem::size_of::<Packet>() <= 64, \"Packet is {{}} bytes\", std::mem::size_of::<Packet>());\n}}\n\n"
        ));
    }
    if let Some(style) = spec.args {
        for i in 0..4 {
            let p: [i64; 8] = std::array::from_fn(|_| rng.below(15) as i64 - 5);
            let call = match style {
                Style::A => format!(
                    "score(Params {{ {} }})",
                    PARAM_NAMES
                        .iter()
                        .zip(p)
                        .map(|(n, v)| format!("{n}: {v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                Style::B => format!(
                    "score(Dims {{ w: {}, h: {}, d: {}, t: {} }}, Coef {{ a: {}, b: {}, c: {}, e: {} }})",
                    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]
                ),
            };
            body.push_str(&format!(
                "#[test]\nfn score{i}() {{\n    assert_eq!({call}, {});\n}}\n\n",
                score(spec, p)
            ));
        }
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    let mut body = format!(
        "mod reference {{\n{indented}}}\n\n#[test]\nfn differential_vs_reference() {{\n    let mut state: u64 = 0x1D5C_ED00_0000_0051;\n    let mut next = || {{\n        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        state >> 33\n    }};\n    let texts = [\"\", \" \", \"7\", \" 12 \", \"x\", \"-1\", \"99\", \"3.5\", \"0\", \"+4\"];\n    for _ in 0..3000 {{\n"
    );
    if spec.err.is_some() {
        body.push_str(
            "        let s = texts[(next() % 10) as usize];\n        assert_eq!(format!(\"{:?}\", task::parse_level(s)), format!(\"{:?}\", reference::parse_level(s)), \"{s:?}\");\n        assert_eq!(task::parse_level(s).map_err(|e| e.to_string()), reference::parse_level(s).map_err(|e| e.to_string()));\n",
        );
    }
    if let Some(style) = spec.big {
        let (t, r) = match style {
            Style::A => (
                "task::Packet::Data(Box::new(arr))",
                "reference::Packet::Data(Box::new(arr))",
            ),
            Style::B => (
                "task::Packet::Frame(Box::new(task::Frame { header: [arr[0]; 16], body: arr[..400].try_into().unwrap() }))",
                "reference::Packet::Frame(Box::new(reference::Frame { header: [arr[0]; 16], body: arr[..400].try_into().unwrap() }))",
            ),
        };
        body.push_str(&format!(
            "        let mut arr = [0u8; 512];\n        for b in arr.iter_mut() {{\n            *b = (next() % 256) as u8;\n        }}\n        assert_eq!(task::weight(&{t}), reference::weight(&{r}));\n        let txt = \"abcdefgh\".repeat((next() % 4) as usize);\n        assert_eq!(task::weight(&task::Packet::Text(txt.clone())), reference::weight(&reference::Packet::Text(txt)));\n"
        ));
    }
    if let Some(style) = spec.args {
        body.push_str(
            "        let p: Vec<i64> = (0..8).map(|_| (next() % 41) as i64 - 20).collect();\n",
        );
        let (t, r) = match style {
            Style::A => {
                let f = |k: &str| {
                    PARAM_NAMES
                        .iter()
                        .enumerate()
                        .map(|(i, n)| format!("{n}: p[{i}]"))
                        .collect::<Vec<_>>()
                        .join(", ")
                        .replace("@", k)
                };
                (
                    format!("task::score(task::Params {{ {} }})", f("")),
                    format!("reference::score(reference::Params {{ {} }})", f("")),
                )
            }
            Style::B => (
                "task::score(task::Dims { w: p[0], h: p[1], d: p[2], t: p[3] }, task::Coef { a: p[4], b: p[5], c: p[6], e: p[7] })".to_string(),
                "reference::score(reference::Dims { w: p[0], h: p[1], d: p[2], t: p[3] }, reference::Coef { a: p[4], b: p[5], c: p[6], e: p[7] })".to_string(),
            ),
        };
        body.push_str(&format!("        assert_eq!({t}, {r}, \"{{p:?}}\");\n"));
    }
    body.push_str("    }\n}\n");
    body
}

fn unchanged(spec: &Spec) -> String {
    given_src(spec)
}

fn allow_attrs(spec: &Spec) -> String {
    format!(
        "#![allow(clippy::result_unit_err, clippy::large_enum_variant, clippy::too_many_arguments)]\n{}",
        given_src(spec)
    )
}

pub struct IdiomShapeFamily;

impl Generator for IdiomShapeFamily {
    fn id(&self) -> &str {
        "idiom-shape"
    }
    fn category(&self) -> &str {
        "idiom-refactor"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("idiom-shape", seed);

        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(PathBuf::from("src/lib.rs"), skeleton_src(&spec));

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
            id: format!("idiom-shape/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            max_unsafe: None,
            forbidden_paths: vec!["allow".to_string()],
            check_clippy: true,
            clippy_allow: Vec::new(),
            // docs/04 idiom-refactor weights: the task *is* the constraint (clippy).
            weights: (0.30, 0.60, 0.10),
        }
    }

    fn reference_code(&self, seed: u64) -> String {
        reference_src(&sample(seed))
    }
    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(&sample(seed))
    }
    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("unchanged".to_string(), unchanged(&spec)),
            ("allow-attrs".to_string(), allow_attrs(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let tag = |s: Option<Style>| match s {
            None => "none",
            Some(Style::A) => "a",
            Some(Style::B) => "b",
        };
        vec![
            format!("err:{}", tag(spec.err)),
            format!("big:{}", tag(spec.big)),
            format!("args:{}", tag(spec.args)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = IdiomShapeFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn all_26_skills_appear_and_every_spec_has_a_defect() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..800u64 {
            let s = sample(seed);
            assert!(s.err.is_some() || s.big.is_some() || s.args.is_some());
            seen.insert(IdiomShapeFamily.spec_signature(seed).join("|"));
        }
        assert_eq!(seen.len(), 26);
    }

    #[test]
    fn given_has_each_defect_and_the_reference_none() {
        for seed in 0..120u64 {
            let s = sample(seed);
            let (g, r) = (given_src(&s), reference_src(&s));
            assert_eq!(g.contains("Result<u8, ()>"), s.err.is_some(), "seed {seed}");
            assert!(!r.contains("Result<u8, ()>"));
            assert_eq!(
                g.contains("Data([u8; 512])") || g.contains("Frame(Frame)"),
                s.big.is_some()
            );
            assert!(!r.contains("Data([u8; 512])") && !r.contains("Frame(Frame)"));
            assert_eq!(g.contains("pub fn score(w: i64"), s.args.is_some());
            assert!(!r.contains("pub fn score(w: i64"));
        }
    }

    #[test]
    fn native_behaviour_matches_intent() {
        let s = Spec {
            err: Some(Style::B),
            big: None,
            args: None,
            lo: 2,
            hi: 9,
            take: 4,
            k: [1, 2, 3, 4],
        };
        assert_eq!(parse_level(&s, " 5 "), Ok(5));
        assert_eq!(parse_level(&s, "  "), Err(LevelFail::Empty));
        assert_eq!(parse_level(&s, "x"), Err(LevelFail::NotNumber("x".into())));
        assert_eq!(parse_level(&s, "10"), Err(LevelFail::OutOfRange(10)));
        assert_eq!(parse_level(&s, "1"), Err(LevelFail::OutOfRange(1)));
        assert_eq!(
            score(&s, [1, 2, 3, 4, 5, 6, 7, 8]),
            2 + 12 * 2 - 30 * 3 + 7 * 4 - 8
        );
    }

    #[test]
    fn the_tests_use_the_new_api_so_unchanged_code_cannot_build() {
        for seed in 0..60u64 {
            let s = sample(seed);
            let t = IdiomShapeFamily.generate(seed);
            let b = &t.hidden[&PathBuf::from("tests/behavior.rs")];
            if s.err.is_some() {
                assert!(
                    b.contains("LevelError") && b.contains("to_string()"),
                    "seed {seed}"
                );
            }
            if let Some(st) = s.big {
                assert!(b.contains("Box::new"), "seed {seed}");
                assert!(
                    b.contains("size_of::<Packet>()"),
                    "seed {seed}: no size check for {st:?}"
                );
            }
            if let Some(st) = s.args {
                assert!(
                    b.contains(if st == Style::A { "Params {" } else { "Dims {" }),
                    "seed {seed}"
                );
            }
        }
    }

    #[test]
    fn allow_is_forbidden_and_canary_present() {
        let t = IdiomShapeFamily.generate(3);
        assert_eq!(t.forbidden_paths, vec!["allow".to_string()]);
        assert!(t.prompt.contains(&t.canary));
    }
}

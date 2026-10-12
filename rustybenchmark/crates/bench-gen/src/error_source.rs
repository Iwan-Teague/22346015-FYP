//! The `error-source` family (category `error-handling`) — implement `Display` and
//! `std::error::Error::source` for a pinned error enum.
//!
//! The three existing `error-handling` families are about *producing* errors: validation
//! over a pinned enum (`error-handling`), checked arithmetic (`checked-eval`) and `?` across
//! error types (`err-chain`). This one is about **being** a good error: a `Display` impl that
//! renders each variant in a prescribed style, and an `Error::source` that exposes the wrapped
//! cause so a caller can walk the chain. The enum is pinned in the skeleton (docs/04:
//! error-handling pins the public error type); the model writes the two `impl`s.
//!
//! The wrapper variant holds its cause in one of three ways, and each has its own `source`
//! spelling — which is where models slip:
//!
//! * **Concrete** — `Io(IoFail)`: `Some(e)` coerces `&IoFail` to `&(dyn Error + 'static)`.
//! * **Boxed** — `Io(Box<dyn Error>)`: needs `Some(e.as_ref())`; `Some(e)` is a type error.
//! * **Chained** — `Context(String, Box<AppError>)`: the cause is the enum itself, so walking
//!   `source()` recurses down an arbitrarily deep chain.
//!
//! Seed-selected on two axes:
//!
//! 1. **Style** — how each variant renders: Plain / Bracket (`[E1] ..`) / Colon (`missing: ..`)
//!    / Upper (`MISSING ..`, which also needs `to_uppercase`).
//! 2. **Payload** — Concrete / Boxed / Chained, as above.
//!
//! 4 x 3 = **12 distinct skills**. Strings in the examples are cosmetic. A wrapper's `Display`
//! must *not* include its cause's text (that is what `source()` is for), so the chain
//! `["outer", "inner", ..]` is exactly the sequence of `Display`s down `source()`.
//! Solution-first (ADR-0003): the native `display`/`chain` and the emitted impls are mirrored
//! from one template table, and the differential builds the same random error tree against the
//! model and an inlined reference module and compares the whole chain.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — how each variant renders.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Style {
    Plain,
    Bracket,
    Colon,
    Upper,
}

/// Axis 2 — how the wrapper variant holds its cause.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Payload {
    Concrete,
    Boxed,
    Chained,
}

struct Spec {
    style: Style,
    payload: Payload,
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let style = match rng.below(4) {
        0 => Style::Plain,
        1 => Style::Bracket,
        2 => Style::Colon,
        _ => Style::Upper,
    };
    let payload = match rng.below(3) {
        0 => Payload::Concrete,
        1 => Payload::Boxed,
        _ => Payload::Chained,
    };
    Spec { style, payload }
}

// ---- the native error value -----------------------------------------------------

/// The native mirror of `AppError`. `Io` is used by Concrete/Boxed, `Ctx` by Chained.
#[derive(Clone, Debug, PartialEq)]
enum E {
    Missing(String),
    Invalid(String, String),
    Io(String),
    Ctx(String, Box<E>),
}

/// Which variant a template is for.
#[derive(Clone, Copy)]
enum Which {
    Missing,
    Invalid,
    Io,
    Ctx,
}

/// One row of the template table: the `write!` format string and its argument expressions.
/// An argument ending in `.to_uppercase()` is upper-cased by the native renderer too.
fn template(style: Style, which: Which) -> (&'static str, &'static [&'static str]) {
    match (style, which) {
        (Style::Plain, Which::Missing) => ("missing key {}", &["k"]),
        (Style::Plain, Which::Invalid) => ("invalid {}: {}", &["key", "reason"]),
        (Style::Plain, Which::Io) => ("i/o failure", &[]),
        (Style::Plain, Which::Ctx) => ("{}", &["msg"]),
        (Style::Bracket, Which::Missing) => ("[E1] missing key {}", &["k"]),
        (Style::Bracket, Which::Invalid) => ("[E2] invalid {}: {}", &["key", "reason"]),
        (Style::Bracket, Which::Io) => ("[E3] i/o failure", &[]),
        (Style::Bracket, Which::Ctx) => ("[E3] {}", &["msg"]),
        (Style::Colon, Which::Missing) => ("missing: {}", &["k"]),
        (Style::Colon, Which::Invalid) => ("invalid: {} ({})", &["key", "reason"]),
        (Style::Colon, Which::Io) => ("io: wrapped", &[]),
        (Style::Colon, Which::Ctx) => ("ctx: {}", &["msg"]),
        (Style::Upper, Which::Missing) => ("MISSING {}", &["k.to_uppercase()"]),
        (Style::Upper, Which::Invalid) => ("INVALID {}={}", &["key", "reason"]),
        (Style::Upper, Which::Io) => ("IO", &[]),
        (Style::Upper, Which::Ctx) => ("CTX {}", &["msg"]),
    }
}

/// Render a template natively: substitute `{}` left to right with the bound values.
fn render(style: Style, which: Which, binds: &[(&str, &str)]) -> String {
    let (fmt, args) = template(style, which);
    let mut out = String::new();
    let mut parts = fmt.split("{}");
    out.push_str(parts.next().unwrap_or(""));
    for (arg, tail) in args.iter().zip(parts) {
        let (name, upper) = match arg.strip_suffix(".to_uppercase()") {
            Some(n) => (n, true),
            None => (*arg, false),
        };
        let v = binds
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
            .unwrap_or("");
        if upper {
            out.push_str(&v.to_uppercase());
        } else {
            out.push_str(v);
        }
        out.push_str(tail);
    }
    out
}

/// The wrapper's own message — never its cause's.
fn display(spec: &Spec, e: &E) -> String {
    match e {
        E::Missing(k) => render(spec.style, Which::Missing, &[("k", k)]),
        E::Invalid(key, reason) => render(
            spec.style,
            Which::Invalid,
            &[("key", key), ("reason", reason)],
        ),
        E::Io(_) => render(spec.style, Which::Io, &[]),
        E::Ctx(msg, _) => render(spec.style, Which::Ctx, &[("msg", msg)]),
    }
}

/// `IoFail`'s fixed message (pinned in the skeleton, so not part of the model's answer).
fn io_fail_msg(path: &str) -> String {
    format!("cannot read {path}")
}

/// The sequence of messages down `source()`.
fn chain(spec: &Spec, e: &E) -> Vec<String> {
    let mut v = vec![display(spec, e)];
    match e {
        E::Io(path) => v.push(io_fail_msg(path)),
        E::Ctx(_, inner) => v.extend(chain(spec, inner)),
        _ => {}
    }
    v
}

// ---- emitted-source fragments ---------------------------------------------------

/// The pinned prelude (kept verbatim by the model).
fn prelude_src(spec: &Spec) -> String {
    let io_fail = "#[derive(Debug)]\n\
         pub struct IoFail {\n\
         \x20   pub path: String,\n\
         }\n\
         \n\
         impl std::fmt::Display for IoFail {\n\
         \x20   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n\
         \x20       write!(f, \"cannot read {}\", self.path)\n\
         \x20   }\n\
         }\n\
         \n\
         impl std::error::Error for IoFail {}\n\
         \n";
    let wrapper = match spec.payload {
        Payload::Concrete => "\x20   Io(IoFail),\n",
        Payload::Boxed => "\x20   Io(Box<dyn std::error::Error>),\n",
        Payload::Chained => "\x20   Context(String, Box<AppError>),\n",
    };
    format!(
        "{io_fail}#[derive(Debug)]\n\
         pub enum AppError {{\n\
         \x20   Missing(String),\n\
         \x20   Invalid {{ key: String, reason: String }},\n\
         {wrapper}}}\n"
    )
}

fn impls_src(spec: &Spec) -> String {
    let arm = |pat: &str, which: Which| -> String {
        let (fmt, args) = template(spec.style, which);
        let args = if args.is_empty() {
            String::new()
        } else {
            format!(", {}", args.join(", "))
        };
        format!("            {pat} => write!(f, {fmt:?}{args}),\n")
    };
    let wrapper_arm = match spec.payload {
        Payload::Concrete | Payload::Boxed => arm("AppError::Io(_)", Which::Io),
        Payload::Chained => arm("AppError::Context(msg, _)", Which::Ctx),
    };
    let source_arm = match spec.payload {
        Payload::Concrete => "            AppError::Io(e) => Some(e),\n",
        Payload::Boxed => "            AppError::Io(e) => Some(e.as_ref()),\n",
        Payload::Chained => "            AppError::Context(_, inner) => Some(inner.as_ref()),\n",
    };
    format!(
        "impl std::fmt::Display for AppError {{\n\
         \x20   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{\n\
         \x20       match self {{\n\
         {missing}{invalid}{wrapper_arm}\
         \x20       }}\n\
         \x20   }}\n\
         }}\n\
         \n\
         impl std::error::Error for AppError {{\n\
         \x20   fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {{\n\
         \x20       match self {{\n\
         {source_arm}\
         \x20           _ => None,\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n",
        missing = arm("AppError::Missing(k)", Which::Missing),
        invalid = arm("AppError::Invalid { key, reason }", Which::Invalid),
    )
}

fn reference_src(spec: &Spec) -> String {
    format!("{}\n{}", prelude_src(spec), impls_src(spec))
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples_prose(spec, seed)
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Implement `Display` and `std::error::Error` for `AppError` below. The types are\n\
         //! provided — keep them.\n\
         //!\n\
         {doc}\n\
         {prelude}\n\
         // Your impls go here.\n",
        prelude = prelude_src(spec),
    )
}

/// Rust source building an `E` as an `AppError` (`prefix` is e.g. `""` or `"task::"`).
fn lit(spec: &Spec, prefix: &str, e: &E) -> String {
    let s = |x: &str| format!("{x:?}.to_string()");
    match e {
        E::Missing(k) => format!("{prefix}AppError::Missing({})", s(k)),
        E::Invalid(k, r) => format!(
            "{prefix}AppError::Invalid {{ key: {}, reason: {} }}",
            s(k),
            s(r)
        ),
        E::Io(path) => match spec.payload {
            Payload::Boxed => format!(
                "{prefix}AppError::Io(Box::new({prefix}IoFail {{ path: {} }}))",
                s(path)
            ),
            _ => format!(
                "{prefix}AppError::Io({prefix}IoFail {{ path: {} }})",
                s(path)
            ),
        },
        E::Ctx(msg, inner) => format!(
            "{prefix}AppError::Context({}, Box::new({}))",
            s(msg),
            lit(spec, prefix, inner)
        ),
    }
}

// ---- worked examples --------------------------------------------------------------

/// A fresh lowercase word of 3..=7 letters. Example strings are generated, not drawn from a
/// palette, so instances differ in their text (view distance) while the structure -- the
/// skill -- is set by the spec alone.
fn word(rng: &mut Rng) -> String {
    let len = 3 + rng.below(5) as usize;
    (0..len)
        .map(|_| (b'a' + rng.below(26) as u8) as char)
        .collect()
}

fn phrase(rng: &mut Rng) -> String {
    format!("{} {}", word(rng), word(rng))
}

fn path(rng: &mut Rng) -> String {
    format!(
        "{}/{}.{}",
        word(rng),
        word(rng),
        ["txt", "cfg", "bin", "log"][rng.below(4) as usize]
    )
}

/// A random error tree valid for the spec's payload (depth-bounded for `Chained`).
fn random_error(spec: &Spec, rng: &mut Rng, depth: u32) -> E {
    let wrapper_ok = depth > 0;
    let roll = rng.below(if wrapper_ok { 4 } else { 2 });
    match roll {
        0 => E::Missing(word(rng)),
        1 => E::Invalid(word(rng), phrase(rng)),
        _ => match spec.payload {
            Payload::Concrete | Payload::Boxed => E::Io(path(rng)),
            Payload::Chained => E::Ctx(phrase(rng), Box::new(random_error(spec, rng, depth - 1))),
        },
    }
}

/// The wrapper value (a chain of at least two messages) that both trivial baselines must miss.
fn canonical_wrapper(spec: &Spec) -> E {
    match spec.payload {
        Payload::Concrete | Payload::Boxed => E::Io("etc/app.conf".to_string()),
        Payload::Chained => E::Ctx(
            "loading config".to_string(),
            Box::new(E::Ctx(
                "reading file".to_string(),
                Box::new(E::Missing("path".to_string())),
            )),
        ),
    }
}

fn worked_examples(spec: &Spec, seed: u64) -> Vec<E> {
    let mut rng = Rng::new(seed ^ 0xE550_0000_0000_0A11);
    let mut v = vec![
        E::Missing(word(&mut rng)),
        E::Invalid(word(&mut rng), phrase(&mut rng)),
        canonical_wrapper(spec),
    ];
    for _ in 0..3 {
        v.push(random_error(spec, &mut rng, 2));
    }
    v
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for e in worked_examples(spec, seed) {
        s.push_str(&format!(
            "  {}  ->  {:?}\n",
            lit(spec, "", &e),
            chain(spec, &e)
        ));
    }
    s
}

fn style_prose(style: Style, payload: Payload) -> String {
    let wrapper = match payload {
        Payload::Concrete | Payload::Boxed => ("Io", ""),
        Payload::Chained => ("Context", " (its message is the `String`)"),
    };
    let row = |which: Which, name: &str, note: &str| {
        let (fmt, args) = template(style, which);
        let args = if args.is_empty() {
            String::new()
        } else {
            format!("   [arguments: {}]", args.join(", "))
        };
        format!("  - `{name}`{note}: `{fmt}`{args}\n")
    };
    format!(
        "{}{}{}{}",
        row(Which::Missing, "Missing(k)", ""),
        row(Which::Invalid, "Invalid { key, reason }", ""),
        match payload {
            Payload::Concrete | Payload::Boxed => row(Which::Io, wrapper.0, wrapper.1),
            Payload::Chained => row(Which::Ctx, "Context(msg, _)", wrapper.1),
        },
        ""
    )
}

fn source_prose(payload: Payload) -> &'static str {
    match payload {
        Payload::Concrete => {
            "`Io` wraps an `IoFail`: its `source()` is that `IoFail`. `Missing` and `Invalid` have no source."
        }
        Payload::Boxed => {
            "`Io` wraps a `Box<dyn std::error::Error>`: its `source()` is the boxed error. `Missing` and `Invalid` have no source."
        }
        Payload::Chained => {
            "`Context` wraps another `AppError`: its `source()` is that inner error (which may itself be a `Context`, to any depth). `Missing` and `Invalid` have no source."
        }
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    format!(
        "Implement `std::fmt::Display` and `std::error::Error` for the `AppError` enum in \
         `src/lib.rs`. The enum (and the `IoFail` type) are already provided — keep them \
         unchanged and add the two `impl` blocks.\n\
         \n\
         `Display` must render each variant with exactly these `write!` formats (shown with \
         their arguments, in order):\n\
         {style}\n\
         A wrapper's `Display` shows **only its own message**, never its cause's text; the \
         cause is reached through `source()`.\n\
         \n\
         `Error::source` must return the wrapped cause: {source}\n\
         \n\
         The message of an `IoFail` is fixed by the provided code (`cannot read <path>`).\n\
         \n\
         Constraints:\n\
         - Do not change the provided types.\n\
         - Do not use `unsafe`.\n\
         \n\
         Provided in `src/lib.rs`:\n\
         ```rust\n\
         {prelude}```\n\
         \n\
         Examples (each line is the value, then the messages found by following `source()` \
         from it, outermost first):\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        style = style_prose(spec.style, spec.payload),
        source = source_prose(spec.payload),
        prelude = prelude_src(spec),
        examples = worked_examples_prose(spec, seed),
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

const CHAIN_FN: &str = "fn chain(e: &dyn std::error::Error) -> Vec<String> {\n\
    \x20   let mut v = vec![e.to_string()];\n\
    \x20   let mut cur = e.source();\n\
    \x20   while let Some(s) = cur {\n\
    \x20       v.push(s.to_string());\n\
    \x20       cur = s.source();\n\
    \x20   }\n\
    \x20   v\n\
    }\n";

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let mut body = format!("use task::{{AppError, IoFail}};\n\n{CHAIN_FN}\n");
    for (i, e) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let e = {value};\n\
             \x20   assert_eq!(e.to_string(), {shown:?});\n\
             \x20   assert_eq!(chain(&e), {expected:?});\n\
             }}\n\n",
            value = lit(spec, "", e),
            shown = display(spec, e),
            expected = chain(spec, e),
        ));
    }
    // A boxed `dyn Error` must work too: the enum is used through `Box<dyn Error>`.
    body.push_str(&format!(
        "#[test]\nfn usable_as_a_boxed_dyn_error() {{\n\
         \x20   let e: Box<dyn std::error::Error> = Box::new({value});\n\
         \x20   assert_eq!(chain(e.as_ref()), {expected:?});\n\
         }}\n",
        value = lit(spec, "", &canonical_wrapper(spec)),
        expected = chain(spec, &canonical_wrapper(spec)),
    ));
    body
}

/// Emit the random-tree builder and chain walker the differential uses against both crates.
fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    let ctx_variant = spec.payload == Payload::Chained;
    // A local tree type shared by both builders.
    let tree = "#[derive(Clone, Debug)]\n\
         enum Tree {\n\
         \x20   Missing(String),\n\
         \x20   Invalid(String, String),\n\
         \x20   Io(String),\n\
         \x20   Ctx(String, Box<Tree>),\n\
         }\n";
    let build = |krate: &str| -> String {
        let io = match spec.payload {
            Payload::Boxed => {
                format!("{krate}::AppError::Io(Box::new({krate}::IoFail {{ path: p.clone() }}))")
            }
            Payload::Concrete => {
                format!("{krate}::AppError::Io({krate}::IoFail {{ path: p.clone() }})")
            }
            // Never produced for Chained; keeps the match exhaustive.
            Payload::Chained => format!("{krate}::AppError::Missing(p.clone())"),
        };
        let ctx = if ctx_variant {
            format!(
                "Tree::Ctx(m, inner) => {krate}::AppError::Context(m.clone(), Box::new(build_{krate}(inner))),"
            )
        } else {
            format!("Tree::Ctx(_, inner) => build_{krate}(inner),")
        };
        format!(
            "fn build_{krate}(t: &Tree) -> {krate}::AppError {{\n\
             \x20   match t {{\n\
             \x20       Tree::Missing(k) => {krate}::AppError::Missing(k.clone()),\n\
             \x20       Tree::Invalid(k, r) => {krate}::AppError::Invalid {{ key: k.clone(), reason: r.clone() }},\n\
             \x20       Tree::Io(p) => {io},\n\
             \x20       {ctx}\n\
             \x20   }}\n\
             }}\n"
        )
    };
    format!(
        "mod reference {{\n{indented}}}\n\n\
         {tree}\n\
         {build_task}\n\
         {build_ref}\n\
         {CHAIN_FN}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xE550_ED00_0000_0045;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   let words = [\"a\", \"bb\", \"port\", \"x y\", \"\", \"Ünï\", \"q-1\"];\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let mut t = match next() % 3 {{\n\
         \x20           0 => Tree::Missing(words[(next() % 7) as usize].to_string()),\n\
         \x20           1 => Tree::Invalid(words[(next() % 7) as usize].to_string(), words[(next() % 7) as usize].to_string()),\n\
         \x20           _ => Tree::Io(words[(next() % 7) as usize].to_string()),\n\
         \x20       }};\n\
         \x20       if {ctx_variant} {{\n\
         \x20           for _ in 0..(next() % 4) {{\n\
         \x20               t = Tree::Ctx(words[(next() % 7) as usize].to_string(), Box::new(t));\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       let got = build_task(&t);\n\
         \x20       let want = build_reference(&t);\n\
         \x20       assert_eq!(chain(&got), chain(&want), \"{{t:?}}\");\n\
         \x20   }}\n\
         }}\n",
        build_task = build("task"),
        build_ref = build("reference"),
    )
}

/// Degenerate: `Display` writes nothing and there is no `source`.
fn empty_display(spec: &Spec) -> String {
    format!(
        "{}\n\
         impl std::fmt::Display for AppError {{\n\
         \x20   fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{\n\
         \x20       Ok(())\n\
         \x20   }}\n\
         }}\n\
         \n\
         impl std::error::Error for AppError {{}}\n",
        prelude_src(spec)
    )
}

/// Degenerate: correct `Display`, but no `source` — the chain never descends.
fn no_source(spec: &Spec) -> String {
    let full = impls_src(spec);
    // Keep only the Display impl; replace the Error impl with an empty one.
    let display_end = full
        .find("impl std::error::Error for AppError")
        .unwrap_or(full.len());
    format!(
        "{}\n{}impl std::error::Error for AppError {{}}\n",
        prelude_src(spec),
        &full[..display_end]
    )
}

pub struct ErrorSourceFamily;

impl Generator for ErrorSourceFamily {
    fn id(&self) -> &str {
        "error-source"
    }
    fn category(&self) -> &str {
        "error-handling"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("error-source", seed);

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
            id: format!("error-source/{seed:016x}"),
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
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // error-handling: L2 behaviour + L3 with the error type pinned (docs/04) —
            // the category default weights.
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
            ("empty-display".to_string(), empty_display(&spec)),
            ("no-source".to_string(), no_source(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let style = match spec.style {
            Style::Plain => "plain",
            Style::Bracket => "bracket",
            Style::Colon => "colon",
            Style::Upper => "upper",
        };
        let payload = match spec.payload {
            Payload::Concrete => "concrete",
            Payload::Boxed => "boxed",
            Payload::Chained => "chained",
        };
        vec![format!("style:{style}"), format!("payload:{payload}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STYLES: [Style; 4] = [Style::Plain, Style::Bracket, Style::Colon, Style::Upper];
    const PAYLOADS: [Payload; 3] = [Payload::Concrete, Payload::Boxed, Payload::Chained];

    fn spec(style: Style, payload: Payload) -> Spec {
        Spec { style, payload }
    }

    #[test]
    fn generation_is_deterministic() {
        let g = ErrorSourceFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn render_matches_the_templates() {
        let s = spec(Style::Plain, Payload::Concrete);
        assert_eq!(display(&s, &E::Missing("port".into())), "missing key port");
        assert_eq!(
            display(&s, &E::Invalid("mode".into(), "bad".into())),
            "invalid mode: bad"
        );
        let s = spec(Style::Bracket, Payload::Chained);
        assert_eq!(
            display(
                &s,
                &E::Ctx("loading".into(), Box::new(E::Missing("k".into())))
            ),
            "[E3] loading"
        );
        let s = spec(Style::Colon, Payload::Boxed);
        assert_eq!(
            display(&s, &E::Invalid("a".into(), "b".into())),
            "invalid: a (b)"
        );
        assert_eq!(display(&s, &E::Io("p".into())), "io: wrapped");
        // Upper upper-cases only the argument marked `.to_uppercase()`.
        let s = spec(Style::Upper, Payload::Concrete);
        assert_eq!(display(&s, &E::Missing("port".into())), "MISSING PORT");
        assert_eq!(
            display(&s, &E::Invalid("mode".into(), "bad".into())),
            "INVALID mode=bad"
        );
    }

    #[test]
    fn chain_walks_down_the_causes() {
        let s = spec(Style::Plain, Payload::Chained);
        let e = E::Ctx(
            "outer".into(),
            Box::new(E::Ctx("inner".into(), Box::new(E::Missing("k".into())))),
        );
        assert_eq!(chain(&s, &e), vec!["outer", "inner", "missing key k"]);
        let s = spec(Style::Plain, Payload::Concrete);
        assert_eq!(
            chain(&s, &E::Io("a.txt".into())),
            vec!["i/o failure", "cannot read a.txt"]
        );
        assert_eq!(chain(&s, &E::Missing("k".into())), vec!["missing key k"]);
    }

    #[test]
    fn canonical_wrapper_defeats_both_baselines_under_every_combination() {
        // empty-display fails if every message is non-empty; no-source fails if the wrapper's
        // chain has more than one entry. Both under every (style, payload).
        for &style in &STYLES {
            for &payload in &PAYLOADS {
                let s = spec(style, payload);
                let w = canonical_wrapper(&s);
                let c = chain(&s, &w);
                assert!(
                    c.len() >= 2,
                    "{style:?}/{payload:?}: chain too short: {c:?}"
                );
                assert!(
                    c.iter().all(|m| !m.is_empty()),
                    "{style:?}/{payload:?}: {c:?}"
                );
                for e in worked_examples(&s, 3) {
                    assert!(!display(&s, &e).is_empty(), "{style:?}/{payload:?}");
                }
            }
        }
    }

    #[test]
    fn random_errors_only_use_variants_the_payload_has() {
        let mut rng = Rng::new(5);
        for &payload in &PAYLOADS {
            let s = spec(Style::Plain, payload);
            for _ in 0..200 {
                let e = random_error(&s, &mut rng, 2);
                fn has(e: &E, f: &dyn Fn(&E) -> bool) -> bool {
                    f(e) || matches!(e, E::Ctx(_, i) if has(i, f))
                }
                match payload {
                    Payload::Chained => assert!(!has(&e, &|x| matches!(x, E::Io(_)))),
                    _ => assert!(!has(&e, &|x| matches!(x, E::Ctx(..)))),
                }
            }
        }
    }

    #[test]
    fn prelude_pins_the_payload_shape() {
        assert!(prelude_src(&spec(Style::Plain, Payload::Concrete)).contains("Io(IoFail)"));
        assert!(prelude_src(&spec(Style::Plain, Payload::Boxed))
            .contains("Io(Box<dyn std::error::Error>)"));
        assert!(prelude_src(&spec(Style::Plain, Payload::Chained))
            .contains("Context(String, Box<AppError>)"));
    }

    #[test]
    fn reference_source_spells_the_right_source_coercion() {
        assert!(impls_src(&spec(Style::Plain, Payload::Concrete)).contains("Some(e)"));
        assert!(impls_src(&spec(Style::Plain, Payload::Boxed)).contains("Some(e.as_ref())"));
        assert!(impls_src(&spec(Style::Plain, Payload::Chained)).contains("Some(inner.as_ref())"));
    }

    #[test]
    fn seeds_vary_both_axes() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..200u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.style, s.payload));
        }
        assert_eq!(variants.len(), 12);
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let t = ErrorSourceFamily.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

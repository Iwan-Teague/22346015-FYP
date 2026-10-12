//! The `lifetime-split` family (category `borrow-lifetimes`) — a third borrow shape: the model
//! must write the **lifetime annotations**, and get *which argument the result borrows from*
//! right.
//!
//! `window-op` and `dual-region` test aliasing (`&mut` through a window, `split_at_mut`). This
//! family tests the other half of docs/04's `borrow-lifetimes` row: **lifetime elision and
//! explicit lifetimes**. The function takes two string slices and returns a slice (or
//! `Option` of one) cut out of exactly one of them:
//!
//! ```text
//! pub fn f(text: &str, sep: &str) -> &str      // does NOT compile: E0106
//! ```
//!
//! With two reference parameters the compiler cannot elide the output lifetime, so the skeleton
//! itself fails to build until the model names a lifetime — and the *obvious* fix (`'a` on both
//! arguments, the textbook `longest` shape) is **wrong here**: the hidden behaviour test drops
//! the separator `String` while the result is still in use, which only compiles when the result
//! is tied to the source argument alone (`E0597` otherwise). The test target then fails to
//! build and behaviour scores 0.0, the same "signature wrong => unsatisfiable driver" mechanism
//! `trait-impl` uses.
//!
//! Seed-selected on three axes:
//!
//! 1. **Op** — how the slice is cut from the source: BeforeFirst / AfterFirst / BeforeLast /
//!    AfterLast occurrence of the separator, or StripPrefix / StripSuffix of it.
//! 2. **Ret** — `&str` (a miss falls back to a documented default) or `Option<&str>` (a miss
//!    is `None`).
//! 3. **Source position** — whether the borrowed-from argument is first or second, so
//!    "the first parameter" is not a memorisable answer.
//!
//! 6 x 2 x 2 = **24 distinct skills**. Constraint-dominant like the other borrow-lifetimes
//! families (docs/04): a hidden allocation probe catches the `Box::leak` escape hatch (which
//! compiles, passes behaviour, and returns `&'static str`), and `leak` is also a forbidden path.
//! Solution-first (ADR-0003): the native `eval` and the emitted reference are mirrored and the
//! differential fuzzes 3000 random (source, separator) pairs.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — how the slice is cut from the source.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Op {
    BeforeFirst,
    AfterFirst,
    BeforeLast,
    AfterLast,
    StripPrefix,
    StripSuffix,
}

/// Axis 2 — what a miss looks like.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Ret {
    Plain,
    Optional,
}

/// Axis 3 — which parameter the result borrows from.
#[derive(Clone, Copy, Debug, PartialEq)]
enum SourcePos {
    First,
    Second,
}

struct Spec {
    op: Op,
    ret: Ret,
    pos: SourcePos,
    fn_name: &'static str,
    /// (source param name, separator param name)
    params: (&'static str, &'static str),
    sep: &'static str,
}

const NAMES: &[&str] = &["f", "carve", "cut_at", "extract", "slice_out", "pick_part"];
const PARAMS: &[(&str, &str)] = &[
    ("text", "sep"),
    ("s", "pat"),
    ("input", "delim"),
    ("haystack", "needle"),
    ("line", "key"),
];
/// Separators are non-empty and contain no letters, so they cannot overlap the letter words
/// the examples are built from.
const SEPS: &[&str] = &[",", ";", "::", "->", "=", "/", " | ", "--"];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let op = match rng.below(6) {
        0 => Op::BeforeFirst,
        1 => Op::AfterFirst,
        2 => Op::BeforeLast,
        3 => Op::AfterLast,
        4 => Op::StripPrefix,
        _ => Op::StripSuffix,
    };
    let ret = if rng.below(2) == 0 {
        Ret::Plain
    } else {
        Ret::Optional
    };
    let pos = if rng.below(2) == 0 {
        SourcePos::First
    } else {
        SourcePos::Second
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    let params = PARAMS[rng.below(PARAMS.len() as u64) as usize];
    let sep = SEPS[rng.below(SEPS.len() as u64) as usize];
    Spec {
        op,
        ret,
        pos,
        fn_name,
        params,
        sep,
    }
}

// ---- native reference (mirrors the emitted source exactly) ----------------

/// The slice the op cuts out, or `None` when the separator is absent (or, for the strip ops,
/// not at the relevant end). The source of truth for the emitted reference.
fn cut<'a>(op: Op, text: &'a str, sep: &str) -> Option<&'a str> {
    match op {
        Op::BeforeFirst => text.find(sep).map(|i| &text[..i]),
        Op::AfterFirst => text.find(sep).map(|i| &text[i + sep.len()..]),
        Op::BeforeLast => text.rfind(sep).map(|i| &text[..i]),
        Op::AfterLast => text.rfind(sep).map(|i| &text[i + sep.len()..]),
        Op::StripPrefix => text.strip_prefix(sep),
        Op::StripSuffix => text.strip_suffix(sep),
    }
}

/// What the `Plain` return type yields on a miss.
fn fallback(op: Op, text: &str) -> &str {
    match op {
        Op::AfterFirst | Op::AfterLast => &text[text.len()..],
        _ => text,
    }
}

/// The full answer for a spec: `Plain` specs always return `Some`.
fn eval<'a>(spec: &Spec, text: &'a str, sep: &str) -> Option<&'a str> {
    let hit = cut(spec.op, text, sep);
    match spec.ret {
        Ret::Plain => Some(hit.unwrap_or_else(|| fallback(spec.op, text))),
        Ret::Optional => hit,
    }
}

// ---- emitted-source fragments (mirror the native functions above) ---------

fn cut_expr(op: Op, t: &str, s: &str) -> String {
    match op {
        Op::BeforeFirst => format!("{t}.find({s}).map(|i| &{t}[..i])"),
        Op::AfterFirst => format!("{t}.find({s}).map(|i| &{t}[i + {s}.len()..])"),
        Op::BeforeLast => format!("{t}.rfind({s}).map(|i| &{t}[..i])"),
        Op::AfterLast => format!("{t}.rfind({s}).map(|i| &{t}[i + {s}.len()..])"),
        Op::StripPrefix => format!("{t}.strip_prefix({s})"),
        Op::StripSuffix => format!("{t}.strip_suffix({s})"),
    }
}

fn fallback_expr(op: Op, t: &str) -> String {
    match op {
        Op::AfterFirst | Op::AfterLast => format!("&{t}[{t}.len()..]"),
        _ => t.to_string(),
    }
}

fn ret_ty(ret: Ret) -> &'static str {
    match ret {
        Ret::Plain => "&'a str",
        Ret::Optional => "Option<&'a str>",
    }
}

/// The parameter list with a lifetime on the source only (the correct signature).
fn params_with_lifetime(spec: &Spec) -> String {
    let (t, s) = spec.params;
    match spec.pos {
        SourcePos::First => format!("{t}: &'a str, {s}: &str"),
        SourcePos::Second => format!("{s}: &str, {t}: &'a str"),
    }
}

/// The same parameter list with the lifetimes elided (what the skeleton shows).
fn params_elided(spec: &Spec) -> String {
    let (t, s) = spec.params;
    match spec.pos {
        SourcePos::First => format!("{t}: &str, {s}: &str"),
        SourcePos::Second => format!("{s}: &str, {t}: &str"),
    }
}

fn ret_elided(ret: Ret) -> &'static str {
    match ret {
        Ret::Plain => "&str",
        Ret::Optional => "Option<&str>",
    }
}

/// Call arguments in the spec's parameter order, from a source expr and a separator expr.
fn call_args(spec: &Spec, text: &str, sep: &str) -> String {
    match spec.pos {
        SourcePos::First => format!("{text}, {sep}"),
        SourcePos::Second => format!("{sep}, {text}"),
    }
}

fn reference_src(spec: &Spec) -> String {
    let (t, s) = spec.params;
    let body = match spec.ret {
        Ret::Plain => format!(
            "{}.unwrap_or({})",
            cut_expr(spec.op, t, s),
            fallback_expr(spec.op, t)
        ),
        Ret::Optional => cut_expr(spec.op, t, s),
    };
    format!(
        "pub fn {name}<'a>({params}) -> {ret} {{\n    {body}\n}}\n",
        name = spec.fn_name,
        params = params_with_lifetime(spec),
        ret = ret_ty(spec.ret),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "//! Implement `{name}` below. The signature is deliberately left without lifetime\n\
         //! annotations: it does not compile until you add them.\n\
         //!\n\
         {doc}\n\
         pub fn {name}({params}) -> {ret} {{\n\
         \x20   todo!()\n\
         }}\n",
        name = spec.fn_name,
        params = params_elided(spec),
        ret = ret_elided(spec.ret),
        doc = examples
            .lines()
            .map(|l| format!("//! {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// The canonical (source, separator) pair. It is **constructed per op** so every op changes
/// it and leaves a non-empty, shorter result — the property both trivial baselines (`empty`
/// / `none`, and `echo-source`) need in order to fail on every seed.
fn canonical(spec: &Spec) -> String {
    let k = spec.sep;
    match spec.op {
        Op::StripPrefix => format!("{k}ab{k}cd"),
        Op::StripSuffix => format!("ab{k}cd{k}"),
        _ => format!("ab{k}cd{k}ef"),
    }
}

/// One worked example: (source, expected).
type ExampleCase = (String, Option<String>);

/// Worked examples, computed natively. The first is the canonical case; two are
/// seed-varied (separator-rich, sometimes starting or ending with the separator so the strip
/// ops have hits); the last has no separator at all so the miss behaviour is pinned.
fn worked_examples(spec: &Spec, seed: u64) -> (String, Vec<ExampleCase>) {
    let mut rng = Rng::new(seed ^ 0x11FE_714E_5911_7001);
    let mut sources = vec![canonical(spec)];
    for _ in 0..2 {
        let n = 2 + rng.below(3) as usize; // 2..=4 words
        let mut s = String::new();
        if rng.below(3) == 0 {
            s.push_str(spec.sep);
        }
        for i in 0..n {
            if i > 0 {
                s.push_str(spec.sep);
            }
            s.push_str(&word(&mut rng));
        }
        if rng.below(3) == 0 {
            s.push_str(spec.sep);
        }
        sources.push(s);
    }
    sources.push(word(&mut rng)); // no separator: the miss case

    let mut prose = String::new();
    let mut cases = Vec::new();
    for src in sources {
        let out = eval(spec, &src, spec.sep).map(str::to_string);
        let shown = match (&out, spec.ret) {
            (Some(o), Ret::Plain) => format!("{o:?}"),
            (Some(o), Ret::Optional) => format!("Some({o:?})"),
            (None, _) => "None".to_string(),
        };
        prose.push_str(&format!(
            "  {name}({args})  ->  {shown}\n",
            name = spec.fn_name,
            args = call_args(spec, &format!("{src:?}"), &format!("{:?}", spec.sep)),
        ));
        cases.push((src, out));
    }
    (prose, cases)
}

fn word(rng: &mut Rng) -> String {
    let len = 1 + rng.below(3) as usize;
    (0..len)
        .map(|_| (b'a' + rng.below(10) as u8) as char)
        .collect()
}

fn miss_prose(spec: &Spec) -> &'static str {
    match (spec.ret, spec.op) {
        (Ret::Optional, _) => "If there is no such occurrence, return `None`.",
        (Ret::Plain, Op::AfterFirst | Op::AfterLast) => {
            "If there is no such occurrence, return the empty string."
        }
        (Ret::Plain, _) => "If there is no such occurrence, return the whole source unchanged.",
    }
}

fn op_prose(op: Op, t: &str, s: &str) -> String {
    match op {
        Op::BeforeFirst => format!(
            "Return the part of `{t}` **before the first occurrence** of `{s}` (the leftmost match)."
        ),
        Op::AfterFirst => format!(
            "Return the part of `{t}` **after the first occurrence** of `{s}` (the leftmost match)."
        ),
        Op::BeforeLast => format!(
            "Return the part of `{t}` **before the last occurrence** of `{s}` (the match that starts furthest right)."
        ),
        Op::AfterLast => format!(
            "Return the part of `{t}` **after the last occurrence** of `{s}` (the match that starts furthest right)."
        ),
        Op::StripPrefix => format!(
            "Return `{t}` with `{s}` removed from its **start**, once, if it starts with `{s}`."
        ),
        Op::StripSuffix => format!(
            "Return `{t}` with `{s}` removed from its **end**, once, if it ends with `{s}`."
        ),
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (examples, _) = worked_examples(spec, seed);
    let (t, s) = spec.params;
    format!(
        "Implement the function `{name}` in `src/lib.rs`.\n\
         \n\
         {op_prose} {miss}\n\
         \n\
         `{s}` is never empty. The result is a *slice of `{t}`*: it must not copy, and it must \
         borrow from `{t}` **only** — a caller may drop `{s}` while still using the result.\n\
         \n\
         The signature below has its lifetimes elided and does not compile as written \
         (rustc cannot pick an output lifetime with two reference parameters). Add the \
         lifetime annotations it needs.\n\
         \n\
         Constraints:\n\
         - Return a slice of the input; do not allocate.\n\
         - Do not use `unsafe`, and do not leak memory to obtain a longer lifetime.\n\
         \n\
         Signature (add lifetimes):\n\
         ```rust\n\
         pub fn {name}({params}) -> {ret}\n\
         ```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        op_prose = op_prose(spec.op, t, s),
        miss = miss_prose(spec),
        params = params_elided(spec),
        ret = ret_elided(spec.ret),
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

/// The expected value as Rust source, for the spec's return type.
fn expected_lit(spec: &Spec, out: &Option<String>) -> String {
    match (spec.ret, out) {
        (Ret::Plain, Some(o)) => format!("{o:?}"),
        (Ret::Plain, None) => unreachable!("Plain specs always produce a value"),
        (Ret::Optional, Some(o)) => format!("Some({o:?})"),
        (Ret::Optional, None) => "None::<&str>".to_string(),
    }
}

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let (_, cases) = worked_examples(spec, seed);
    let mut body = format!("use task::{};\n\n", spec.fn_name);
    for (i, (src, out)) in cases.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   assert_eq!({name}({args}), {expected});\n\
             }}\n\n",
            name = spec.fn_name,
            args = call_args(spec, &format!("{src:?}"), &format!("{:?}", spec.sep)),
            expected = expected_lit(spec, out),
        ));
    }
    body.push_str(&scoped_test_src(spec));
    body
}

/// The lifetime check: the separator dies before the result is used. This only compiles when
/// the result is tied to the source argument alone. It is included in **every** hidden test
/// target (behaviour, differential, alloc), so a wrong lifetime zeroes all of them rather
/// than only the one that happens to hold it — otherwise the family's central skill would
/// cost the answer only a fraction of its score.
fn scoped_block_src(spec: &Spec) -> String {
    let src = canonical(spec);
    let out = eval(spec, &src, spec.sep).map(str::to_string);
    format!(
        "\x20   // scoped-separator check\n\
         \x20   {{\n\
         \x20       let source = String::from({src:?});\n\
         \x20       let result;\n\
         \x20       {{\n\
         \x20           let separator = String::from({sep:?});\n\
         \x20           result = {name}({args});\n\
         \x20       }}\n\
         \x20       assert_eq!(result, {expected});\n\
         \x20   }}\n",
        name = spec.fn_name,
        sep = spec.sep,
        args = call_args(spec, "&source", "&separator"),
        expected = expected_lit(spec, &out),
    )
}

/// The block as a standalone test (behaviour and differential targets). The alloc target
/// cannot use a separate test: tests run on parallel threads and this one allocates, which
/// would be counted against the measured one, so there the block runs first inside it.
fn scoped_test_src(spec: &Spec) -> String {
    format!(
        "#[test]\nfn separator_may_be_dropped_before_the_result_is_used() {{\n{}}}\n",
        scoped_block_src(spec)
    )
}

fn differential_test_src(spec: &Spec) -> String {
    let reference =
        reference_src(spec).replacen(&format!("pub fn {}", spec.fn_name), "fn reference", 1);
    let alphabet: String = {
        let mut a: Vec<char> = "ab".chars().collect();
        for c in spec.sep.chars() {
            if !a.contains(&c) {
                a.push(c);
            }
        }
        a.into_iter().collect()
    };
    format!(
        "use task::{name};\n\
         \n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let alphabet: Vec<char> = {alphabet:?}.chars().collect();\n\
         \x20   let mut state: u64 = 0x11FE_5911_7D1F_F001;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as usize\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = next() % 14;\n\
         \x20       let text: String = (0..len).map(|_| alphabet[next() % alphabet.len()]).collect();\n\
         \x20       let klen = 1 + next() % 2;\n\
         \x20       let sep: String = (0..klen).map(|_| alphabet[next() % alphabet.len()]).collect();\n\
         \x20       let got = {name}({got_args});\n\
         \x20       let want = reference({want_args});\n\
         \x20       assert_eq!(got, want, \"text={{text:?}} sep={{sep:?}}\");\n\
         \x20   }}\n\
         }}\n         \n\
         {scoped}",
        name = spec.fn_name,
        reference = reference,
        alphabet = alphabet,
        got_args = call_args(spec, "&text", "&sep"),
        want_args = call_args(spec, "&text", "&sep"),
        scoped = scoped_test_src(spec),
    )
}

fn alloc_test_src(spec: &Spec) -> String {
    let src = canonical(spec);
    format!(
        "use task::{name};\n\
         use std::alloc::{{GlobalAlloc, Layout, System}};\n\
         use std::sync::atomic::{{AtomicUsize, Ordering}};\n\
         \n\
         static ALLOCS: AtomicUsize = AtomicUsize::new(0);\n\
         struct Counting;\n\
         unsafe impl GlobalAlloc for Counting {{\n\
         \x20   unsafe fn alloc(&self, l: Layout) -> *mut u8 {{ ALLOCS.fetch_add(1, Ordering::SeqCst); System.alloc(l) }}\n\
         \x20   unsafe fn dealloc(&self, p: *mut u8, l: Layout) {{ System.dealloc(p, l) }}\n\
         }}\n\
         #[global_allocator]\n\
         static GLOBAL: Counting = Counting;\n\
         \n\
         #[test]\n\
         fn slicing_does_not_allocate() {{\n\
         {scoped_block}\
         \x20   let source = String::from({src:?});\n\
         \x20   let separator = String::from({sep:?});\n\
         \x20   let before = ALLOCS.load(Ordering::SeqCst);\n\
         \x20   for _ in 0..100 {{\n\
         \x20       std::hint::black_box({name}({args}));\n\
         \x20   }}\n\
         \x20   let after = ALLOCS.load(Ordering::SeqCst);\n\
         \x20   assert_eq!(after - before, 0, \"allocated {{}} time(s)\", after - before);\n\
         }}\n",
        name = spec.fn_name,
        sep = spec.sep,
        args = call_args(spec, "&source", "&separator"),
        scoped_block = scoped_block_src(spec),
    )
}

/// Degenerate: correct lifetimes and shape, but returns nothing useful (`""` / `None`). The
/// canonical result is non-empty `Some(..)` under every spec.
fn const_empty(spec: &Spec) -> String {
    let (t, _) = spec.params;
    let value = match spec.ret {
        Ret::Plain => "\"\"",
        Ret::Optional => "None",
    };
    format!(
        "pub fn {name}<'a>({params}) -> {ret} {{ let _ = {t}; {value} }}\n",
        name = spec.fn_name,
        params = params_with_lifetime(spec),
        ret = ret_ty(spec.ret),
    )
}

/// Degenerate: returns the whole source regardless. The canonical case is changed by every op.
fn echo_source(spec: &Spec) -> String {
    let (t, _) = spec.params;
    let value = match spec.ret {
        Ret::Plain => t.to_string(),
        Ret::Optional => format!("Some({t})"),
    };
    format!(
        "pub fn {name}<'a>({params}) -> {ret} {{ {value} }}\n",
        name = spec.fn_name,
        params = params_with_lifetime(spec),
        ret = ret_ty(spec.ret),
    )
}

pub struct LifetimeSplitFamily;

impl Generator for LifetimeSplitFamily {
    fn id(&self) -> &str {
        "lifetime-split"
    }
    fn category(&self) -> &str {
        "borrow-lifetimes"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("lifetime-split", seed);

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
        hidden.insert(
            PathBuf::from("tests/alloc.rs"),
            crate::thread_local_counter(alloc_test_src(&spec)),
        );

        GeneratedTask {
            id: format!("lifetime-split/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: "alloc".to_string(),
            max_unsafe: Some(0),
            // `leak` closes the `Box::leak` / `String::leak` route to a `'static` result.
            forbidden_paths: vec!["leak".to_string()],
            check_clippy: false,
            clippy_allow: Vec::new(),
            // borrow-lifetimes is constraint-dominant (docs/04).
            weights: (0.35, 0.55, 0.10),
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
        let label = match spec.ret {
            Ret::Plain => "const-empty",
            Ret::Optional => "const-none",
        };
        vec![
            (label.to_string(), const_empty(&spec)),
            ("echo-source".to_string(), echo_source(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is (op, ret, source position). Function/parameter names and the
        // separator are cosmetic and excluded (Q31).
        let spec = sample(seed);
        let op = match spec.op {
            Op::BeforeFirst => "before_first",
            Op::AfterFirst => "after_first",
            Op::BeforeLast => "before_last",
            Op::AfterLast => "after_last",
            Op::StripPrefix => "strip_prefix",
            Op::StripSuffix => "strip_suffix",
        };
        let ret = match spec.ret {
            Ret::Plain => "plain",
            Ret::Optional => "optional",
        };
        let pos = match spec.pos {
            SourcePos::First => "first",
            SourcePos::Second => "second",
        };
        vec![
            format!("op:{op}"),
            format!("ret:{ret}"),
            format!("src:{pos}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_OPS: [Op; 6] = [
        Op::BeforeFirst,
        Op::AfterFirst,
        Op::BeforeLast,
        Op::AfterLast,
        Op::StripPrefix,
        Op::StripSuffix,
    ];

    fn spec(op: Op, ret: Ret, sep: &'static str) -> Spec {
        Spec {
            op,
            ret,
            pos: SourcePos::First,
            fn_name: "f",
            params: ("text", "sep"),
            sep,
        }
    }

    #[test]
    fn generation_is_deterministic() {
        let g = LifetimeSplitFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        let ev = |op, ret, t, k| eval(&spec(op, ret, ","), t, k);
        assert_eq!(ev(Op::BeforeFirst, Ret::Plain, "a,b,c", ","), Some("a"));
        assert_eq!(ev(Op::AfterFirst, Ret::Plain, "a,b,c", ","), Some("b,c"));
        assert_eq!(ev(Op::BeforeLast, Ret::Plain, "a,b,c", ","), Some("a,b"));
        assert_eq!(ev(Op::AfterLast, Ret::Plain, "a,b,c", ","), Some("c"));
        assert_eq!(ev(Op::StripPrefix, Ret::Plain, ",a", ","), Some("a"));
        assert_eq!(ev(Op::StripSuffix, Ret::Plain, "a,", ","), Some("a"));
        // Strip removes once, not repeatedly.
        assert_eq!(ev(Op::StripPrefix, Ret::Plain, ",,a", ","), Some(",a"));
    }

    #[test]
    fn miss_behaviour_per_ret() {
        let ev = |op, ret| eval(&spec(op, ret, ","), "abc", ",");
        // Plain: before/strip fall back to the whole source, after falls back to "".
        assert_eq!(ev(Op::BeforeFirst, Ret::Plain), Some("abc"));
        assert_eq!(ev(Op::BeforeLast, Ret::Plain), Some("abc"));
        assert_eq!(ev(Op::StripPrefix, Ret::Plain), Some("abc"));
        assert_eq!(ev(Op::StripSuffix, Ret::Plain), Some("abc"));
        assert_eq!(ev(Op::AfterFirst, Ret::Plain), Some(""));
        assert_eq!(ev(Op::AfterLast, Ret::Plain), Some(""));
        // Optional: always None on a miss.
        for op in ALL_OPS {
            assert_eq!(ev(op, Ret::Optional), None, "{op:?}");
        }
    }

    #[test]
    fn first_and_last_differ_with_multiple_occurrences() {
        let e = |op| cut(op, "a::b::c", "::");
        assert_eq!(e(Op::BeforeFirst), Some("a"));
        assert_eq!(e(Op::BeforeLast), Some("a::b"));
        assert_eq!(e(Op::AfterFirst), Some("b::c"));
        assert_eq!(e(Op::AfterLast), Some("c"));
    }

    #[test]
    fn canonical_defeats_both_baselines_under_every_combination() {
        // const-empty / const-none and echo-source fail on every seed only if the canonical
        // result is a present, non-empty value different from the whole source — under every
        // (op, ret, separator).
        for &op in &ALL_OPS {
            for &ret in &[Ret::Plain, Ret::Optional] {
                for &sep in SEPS {
                    let s = spec(op, ret, sep);
                    let src = canonical(&s);
                    let out = eval(&s, &src, sep)
                        .unwrap_or_else(|| panic!("canonical missed under {op:?}/{ret:?}/{sep:?}"));
                    assert!(!out.is_empty(), "empty under {op:?}/{ret:?}/{sep:?}");
                    assert_ne!(out, src, "echo passes under {op:?}/{ret:?}/{sep:?}");
                }
            }
        }
    }

    #[test]
    fn examples_include_a_miss_case_and_hits() {
        // The last example has no separator; for Optional specs it must be a None, pinning
        // the miss behaviour.
        let s = spec(Op::BeforeFirst, Ret::Optional, ",");
        let (_, cases) = worked_examples(&s, 5);
        assert_eq!(cases.len(), 4);
        assert!(cases[0].1.is_some());
        assert_eq!(cases.last().unwrap().1, None);
    }

    #[test]
    fn plain_specs_never_produce_a_missing_example() {
        for seed in 0..200u64 {
            let s = sample(seed);
            if s.ret == Ret::Plain {
                let (_, cases) = worked_examples(&s, seed);
                assert!(cases.iter().all(|c| c.1.is_some()), "seed {seed}");
            }
        }
    }

    #[test]
    fn seeds_vary_all_three_axes() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..400u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}/{:?}", s.op, s.ret, s.pos));
        }
        assert_eq!(variants.len(), 24, "expected all 6x2x2 specs to appear");
    }

    #[test]
    fn skeleton_has_elided_lifetimes_and_reference_has_a_lifetime() {
        let g = LifetimeSplitFamily;
        for seed in 0..40u64 {
            let sk = g.skeleton_code(seed);
            assert!(
                !sk.contains("'a"),
                "seed {seed}: skeleton leaks the lifetime"
            );
            assert!(sk.contains("todo!()"));
            let r = g.reference_code(seed);
            assert!(r.contains("<'a>"), "seed {seed}: reference lacks lifetime");
            // The separator parameter must NOT carry 'a — that is the whole point.
            let s = sample(seed);
            assert!(
                !r.contains(&format!("{}: &'a str", s.params.1)),
                "seed {seed}: separator tied to the result lifetime"
            );
        }
    }

    #[test]
    fn the_scoped_separator_test_is_in_every_target_and_uses_both_orders() {
        let g = LifetimeSplitFamily;
        let mut saw = [false, false];
        for seed in 0..60u64 {
            let t = g.generate(seed);
            for file in [
                "tests/behavior.rs",
                "tests/differential.rs",
                "tests/alloc.rs",
            ] {
                let src = &t.hidden[&PathBuf::from(file)];
                assert!(
                    src.contains("// scoped-separator check"),
                    "seed {seed}: {file} lacks the scoped-separator test"
                );
            }
            match sample(seed).pos {
                SourcePos::First => saw[0] = true,
                SourcePos::Second => saw[1] = true,
            }
        }
        assert!(saw[0] && saw[1]);
    }

    #[test]
    fn leak_is_forbidden() {
        assert_eq!(
            LifetimeSplitFamily.generate(3).forbidden_paths,
            vec!["leak".to_string()]
        );
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let t = LifetimeSplitFamily.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

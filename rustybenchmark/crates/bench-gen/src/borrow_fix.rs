//! The `borrow-fix` family (category `borrow-checking`) — borrowing
//! puzzles over a pair of words.
//!
//! Where the trivia families exercise arithmetic, this one exercises
//! **real borrow reasoning**: several answers must be slices of the
//! INPUTS themselves (`&str` tied to the arguments' lifetimes), so a
//! solution that copies its way out does not type-check, and a solution
//! that allocates anywhere on the hot path fails the allocation probe.
//!
//! The domain is an ordered pair of lowercase words. The seed prunes
//! which two of five query ops are required: `longer_name`,
//! `middle_of_longer`, `shared_prefix_len`, `common_letter_count`,
//! `first_diff`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic. All five take the pair.
//!
//! The canonical pair is CONSTRUCTED: a short shared head of one to
//! three letters, then tails that diverge immediately and differ in
//! length — so `first_diff` lands inside the pair (nonzero), both
//! scalars stay separable, and the longer word is unambiguous. The
//! hidden allocation probe (`tests/alloc.rs`) counts every heap
//! allocation through a counting global allocator: warm up once, reset,
//! run the queries again, and assert nothing was allocated. The
//! `clone-everything` baseline is behaviorally exact but starts every
//! body with a gratuitous `format!` sink — it compiles, passes every
//! behavior assertion, and fails the probe on every seed.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random word pairs against the model.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    LongerName,
    MiddleOfLonger,
    SharedPrefixLen,
    CommonLetterCount,
    FirstDiff,
}

const OP_ALL: [Op; 5] = [
    Op::LongerName,
    Op::MiddleOfLonger,
    Op::SharedPrefixLen,
    Op::CommonLetterCount,
    Op::FirstDiff,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::LongerName => "longer_name",
            Op::MiddleOfLonger => "middle_of_longer",
            Op::SharedPrefixLen => "shared_prefix_len",
            Op::CommonLetterCount => "common_letter_count",
            Op::FirstDiff => "first_diff",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::LongerName => {
                "the longer of the two words itself — borrowed straight \
                 from an argument, never copied"
            }
            Op::MiddleOfLonger => {
                "the single byte at half the length of the longer word — \
                 again a slice of the input itself"
            }
            Op::SharedPrefixLen => {
                "how many leading bytes the two words share before they \
                 first differ"
            }
            Op::CommonLetterCount => {
                "how many distinct letters appear in both words at once — \
                 each shared letter counts once no matter how often it \
                 repeats"
            }
            Op::FirstDiff => {
                "the byte index where the two words first diverge — \
                 negative one when one word is a prefix of the other or \
                 they match exactly"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::LongerName | Op::MiddleOfLonger => "&str",
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

/// The longer word, borrowed from an argument; ties resolve to `a`.
fn b_longer_name<'a>(a: &'a str, b: &'a str) -> &'a str {
    if b.len() > a.len() {
        b
    } else {
        a
    }
}

/// One byte of the longer word at half its length.
fn b_middle_of_longer<'a>(a: &'a str, b: &'a str) -> &'a str {
    let longer = b_longer_name(a, b);
    if longer.is_empty() {
        return "";
    }
    let mid = longer.len() / 2;
    &longer[mid..mid + 1]
}

/// Leading bytes shared before the first divergence.
fn b_shared_prefix_len(a: &str, b: &str) -> i64 {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count() as i64
}

/// Distinct letters present in both words; repeats count once.
fn b_common_letter_count(a: &str, b: &str) -> i64 {
    let mut count = 0i64;
    let bytes = a.as_bytes();
    for (i, x) in bytes.iter().enumerate() {
        if bytes[..i].contains(x) {
            continue;
        }
        if b.bytes().any(|y| y == *x) {
            count += 1;
        }
    }
    count
}

/// First differing byte index; -1 on a prefix or exact match.
fn b_first_diff(a: &str, b: &str) -> i64 {
    for (i, (x, y)) in a.bytes().zip(b.bytes()).enumerate() {
        if x != y {
            return i as i64;
        }
    }
    -1
}

/// The answer shape: scalars as `Num`, borrowed slices as quoted `Str`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Str(String),
}

impl Out {
    fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            // Slices are compared against quoted literals.
            Out::Str(s) => format!("{s:?}"),
        }
    }
}

fn op_eval(op: Op, a: &str, b: &str) -> Out {
    match op {
        Op::LongerName => Out::Str(b_longer_name(a, b).to_string()),
        Op::MiddleOfLonger => Out::Str(b_middle_of_longer(a, b).to_string()),
        Op::SharedPrefixLen => Out::Num(b_shared_prefix_len(a, b)),
        Op::CommonLetterCount => Out::Num(b_common_letter_count(a, b)),
        Op::FirstDiff => Out::Num(b_first_diff(a, b)),
    }
}

// ---- canonical pair -------------------------------------------------------

const CANONICAL_SEED: u64 = 0xB0A1_FA11;

/// The canonical pair is CONSTRUCTED, not blind-sampled: a short shared
/// head of one to three letters, then tails that diverge immediately
/// (different first letter after the head) and differ in length. Every
/// seed therefore gets `first_diff` inside the pair, a nonzero shared
/// prefix, at least two common distinct letters, and one unambiguous
/// longer word.
fn canonical(seed: u64) -> (String, String) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let mut shared = String::new();
        for _ in 0..1 + rng.below(3) {
            shared.push((b'a' + rng.below(26) as u8) as char);
        }
        let first_a = (b'a' + rng.below(26) as u8) as char;
        let mut first_b = (b'a' + rng.below(26) as u8) as char;
        while first_b == first_a {
            first_b = (b'a' + rng.below(26) as u8) as char;
        }
        let mut wa = String::new();
        let mut wb = String::new();
        wa.push_str(&shared);
        wb.push_str(&shared);
        wa.push(first_a);
        wb.push(first_b);
        for _ in 0..rng.below(5) {
            wa.push((b'a' + rng.below(26) as u8) as char);
        }
        for _ in 0..rng.below(5) {
            wb.push((b'a' + rng.below(26) as u8) as char);
        }
        if anchors_hold(&wa, &wb) {
            return (wa, wb);
        }
    }
    unreachable!("canonical pair sampling failed to satisfy anchors");
}

fn anchors_hold(a: &str, b: &str) -> bool {
    !a.is_empty()
        && !b.is_empty()
        && a != b
        && a.len() != b.len()
        && b_shared_prefix_len(a, b) >= 1
        && b_first_diff(a, b) >= 1
        && b_common_letter_count(a, b) >= 2
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((String, String), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0174;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical constructed pair first.
    let can = canonical(seed);
    cases.push((
        can.clone(),
        spec.ops
            .map(|op| (op, op_eval(op, &can.0, &can.1)))
            .to_vec(),
    ));
    // All-empty conventions.
    cases.push((
        (String::new(), String::new()),
        spec.ops.map(|op| (op, op_eval(op, "", ""))).to_vec(),
    ));
    // Equal words: first_diff answers -1.
    cases.push((
        ("abc".into(), "abc".into()),
        spec.ops.map(|op| (op, op_eval(op, "abc", "abc"))).to_vec(),
    ));
    // Prefix case: no divergence inside the zip.
    cases.push((
        ("ab".into(), "abcdef".into()),
        spec.ops
            .map(|op| (op, op_eval(op, "ab", "abcdef")))
            .to_vec(),
    ));
    // Disjoint words share nothing.
    cases.push((
        ("xyz".into(), "abc".into()),
        spec.ops.map(|op| (op, op_eval(op, "xyz", "abc"))).to_vec(),
    ));
    for _ in 0..3 {
        let mut wa = String::new();
        let mut wb = String::new();
        for _ in 0..1 + rng.below(6) {
            wa.push((b'a' + rng.below(26) as u8) as char);
        }
        for _ in 0..1 + rng.below(6) {
            wb.push((b'a' + rng.below(26) as u8) as char);
        }
        let outs = spec.ops.map(|op| (op, op_eval(op, &wa, &wb))).to_vec();
        cases.push(((wa, wb), outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; quoted words type the tuple.
fn render_pair(a: &str, b: &str) -> String {
    format!("({a:?}, {b:?})")
}

fn op_fn_src(op: Op) -> String {
    match op {
        Op::LongerName => format!(
            "pub fn longer_name<'a>(a: &'a str, b: &'a str) -> &'a str {{\n    {}\n}}\n",
            ["if b.len() > a.len() {", "    b", "} else {", "    a", "}"].join("\n    ")
        ),
        Op::MiddleOfLonger => format!(
            "pub fn middle_of_longer<'a>(a: &'a str, b: &'a str) -> &'a str {{\n    {}\n}}\n",
            [
                "let longer = if b.len() > a.len() { b } else { a };",
                "if longer.is_empty() {",
                "    return \"\";",
                "}",
                "let mid = longer.len() / 2;",
                "&longer[mid..mid + 1]",
            ]
            .join("\n    ")
        ),
        Op::SharedPrefixLen => format!(
            "pub fn shared_prefix_len(a: &str, b: &str) -> {} {{\n    {}\n}}\n",
            op.ret(),
            ["a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count() as i64"].join("\n    ")
        ),
        Op::CommonLetterCount => format!(
            "pub fn common_letter_count(a: &str, b: &str) -> {} {{\n    {}\n}}\n",
            op.ret(),
            [
                "let mut count = 0i64;",
                "let bytes = a.as_bytes();",
                "for (i, x) in bytes.iter().enumerate() {",
                "    if bytes[..i].contains(x) {",
                "        continue;",
                "    }",
                "    if b.bytes().any(|y| y == *x) {",
                "        count += 1;",
                "    }",
                "}",
                "count",
            ]
            .join("\n    ")
        ),
        Op::FirstDiff => format!(
            "pub fn first_diff(a: &str, b: &str) -> {} {{\n    {}\n}}\n",
            op.ret(),
            [
                "for (i, (x, y)) in a.bytes().zip(b.bytes()).enumerate() {",
                "    if x != y {",
                "        return i as i64;",
                "    }",
                "}",
                "-1",
            ]
            .join("\n    ")
        ),
    }
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    // Borrowed answers MUST annotate the lifetime: two `&str` inputs
    // cannot elide an output tied to one of them.
    match op {
        Op::LongerName => "pub fn longer_name<'a>(a: &'a str, b: &'a str) -> &'a str".to_string(),
        Op::MiddleOfLonger => {
            "pub fn middle_of_longer<'a>(a: &'a str, b: &'a str) -> &'a str".to_string()
        }
        _ => format!("pub fn {}(a: &str, b: &str) -> {}", op.name(), op.ret()),
    }
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op in an emitted assertion — all five
/// take the pair.
fn call_src(op: Op) -> String {
    format!("{}(a, b)", op.name())
}
fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for ((a, b), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  pair {}  ->  {}\n",
            render_pair(&a, &b),
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
        "//! Implement the two query functions below. The answers must\n\
         //! borrow from the arguments — never copy.\n\
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
         an ordered pair `(a, b)` of lowercase words.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - Word-shaped answers are borrows of the arguments themselves; \
         the graders also run an allocation probe that fails if a query \
         touches the heap, so the queries must not allocate anywhere.\n\
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
    for (i, ((a, b), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (a, b) = {};\n",
            render_pair(a, b),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op),
                out.lit(),
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the two selected ops, pasted into the
/// test file under `ref_*` names.
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
    // The fuzz loop binds `wa`/`wb` as owned `String`s; every call
    // borrows them (`&wa`) so neither side moves them out.
    let asserts = spec
        .ops
        .iter()
        .map(|op| {
            let name = op.name();
            format!("        assert_eq!({name}(&wa, &wb), ref_{name}(&wa, &wb));\n")
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0174;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let na = (nx(&mut state) % 6) + 1;\n\
         \x20       let nb = (nx(&mut state) % 6) + 1;\n\
         \x20       let mut wa = String::new();\n\
         \x20       let mut wb = String::new();\n\
         \x20       for _ in 0..na {{ wa.push((b'a' + (nx(&mut state) % 26) as u8) as char); }}\n\
         \x20       for _ in 0..nb {{ wb.push((b'a' + (nx(&mut state) % 26) as u8) as char); }}\n\
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
/// Degenerate: zero answers everywhere.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let tail = match op.ret() {
                "&str" => "\"\"",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = (a, b);\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Behaviorally exact — and allocating on every call. Each body starts
/// with a gratuitous `format!` sink: the baseline compiles, passes every
/// behavior assertion, and fails the allocation probe outright.
fn clone_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let sink = "let _sink = format!(\"{a}{b}\");";
            let rest: &[&str] = match op {
                Op::LongerName => &["if b.len() > a.len() {", "    b", "} else {", "    a", "}"],
                Op::MiddleOfLonger => &[
                    "let longer = if b.len() > a.len() { b } else { a };",
                    "if longer.is_empty() {",
                    "    return \"\";",
                    "}",
                    "let mid = longer.len() / 2;",
                    "&longer[mid..mid + 1]",
                ],
                Op::SharedPrefixLen => {
                    &["a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count() as i64"]
                }
                Op::CommonLetterCount => &[
                    "let mut count = 0i64;",
                    "let bytes = a.as_bytes();",
                    "for (i, x) in bytes.iter().enumerate() {",
                    "    if bytes[..i].contains(x) {",
                    "        continue;",
                    "    }",
                    "    if b.bytes().any(|y| y == *x) {",
                    "        count += 1;",
                    "    }",
                    "}",
                    "count",
                ],
                Op::FirstDiff => &[
                    "for (i, (x, y)) in a.bytes().zip(b.bytes()).enumerate() {",
                    "    if x != y {",
                    "        return i as i64;",
                    "    }",
                    "}",
                    "-1",
                ],
            };
            let mut lines: Vec<&str> = Vec::with_capacity(rest.len() + 1);
            lines.push(sink);
            lines.extend_from_slice(rest);
            format!("{sig} {{\n    {}\n}}\n", lines.join("\n    "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}
/// The hidden allocation probe: a counting global allocator wraps every
/// heap touch. Warm up once (lazy runtime setup may allocate), reset the
/// counter, run the queries again, and assert nothing was allocated.
fn alloc_test_src(spec: &Spec) -> String {
    let imports = spec
        .ops
        .iter()
        .map(|op| op.name())
        .collect::<Vec<_>>()
        .join(", ");
    let mut s = String::new();
    s.push_str("//! No-allocation gate: the query functions must borrow their\n");
    s.push_str("//! way to each answer without touching the heap.\n");
    s.push_str("use std::alloc::{GlobalAlloc, Layout, System};\n");
    s.push_str("use std::sync::atomic::{AtomicUsize, Ordering};\n");
    s.push_str(&format!("use task::{{{imports}}};\n\n"));
    s.push_str("static COUNT: AtomicUsize = AtomicUsize::new(0);\n\n");
    s.push_str("struct Counting;\n\n");
    s.push_str("unsafe impl GlobalAlloc for Counting {\n");
    s.push_str("    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {\n");
    s.push_str("        COUNT.fetch_add(1, Ordering::SeqCst);\n");
    s.push_str("        unsafe { System.alloc(layout) }\n");
    s.push_str("    }\n\n");
    s.push_str("    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {\n");
    s.push_str("        unsafe { System.dealloc(ptr, layout) }\n");
    s.push_str("    }\n}\n\n");
    s.push_str("#[global_allocator]\nstatic ALLOCATOR: Counting = Counting;\n\n");
    s.push_str("fn exercise(a: &str, b: &str) {\n");
    for op in spec.ops {
        s.push_str(&format!("    std::hint::black_box({}(a, b));\n", op.name()));
    }
    s.push_str("}\n\n");
    s.push_str("#[test]\nfn hot_path_allocates_nothing() {\n");
    s.push_str("    // The warm-up pass absorbs one-time lazy initialization.\n");
    s.push_str("    exercise(\"gravel\", \"grave\");\n");
    s.push_str("    COUNT.store(0, Ordering::SeqCst);\n");
    // A second, distinct pair runs under the counter too, so a memoizer
    // that paid its allocation during warm-up cannot reuse one cached
    // answer across both.
    s.push_str("    exercise(\"amber\", \"amble\");\n");
    s.push_str("    exercise(\"gravel\", \"grave\");\n");
    s.push_str("    assert_eq!(\n");
    s.push_str("        COUNT.load(Ordering::SeqCst),\n");
    s.push_str("        0,\n");
    s.push_str("        \"alloc: hot path allocated\"\n");
    s.push_str("    );\n}\n");
    s
}
pub struct BorrowFixFamily;

impl Generator for BorrowFixFamily {
    fn id(&self) -> &str {
        "borrow-fix"
    }
    fn category(&self) -> &str {
        "borrow-checking"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("borrow-fix", seed);

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
        // The allocation probe is the point of this family: it rides the
        // standard oracle's L3 constraint slot.
        hidden.insert(
            PathBuf::from("tests/alloc.rs"),
            crate::thread_local_counter(alloc_test_src(&spec)),
        );

        GeneratedTask {
            id: format!("borrow-fix/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            // Run tests/alloc.rs as the L3 allocation constraint.
            alloc_test: "alloc".to_string(),
            max_unsafe: None,
            forbidden_paths: Vec::new(),
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
            ("clone-everything".to_string(), clone_everything(&spec)),
            ("const-zero".to_string(), const_zero(&spec)),
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
        let g = BorrowFixFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Longer word, borrowed either way; ties take the first.
        assert_eq!(b_longer_name("cat", "horse"), "horse");
        assert_eq!(b_longer_name("horse", "cat"), "horse");
        assert_eq!(b_longer_name("owl", "bat"), "owl");
        // Middle byte of the winner.
        assert_eq!(b_middle_of_longer("cat", "horse"), "r");
        assert_eq!(b_middle_of_longer("x", "abcd"), "c");
        assert_eq!(b_middle_of_longer("", ""), "");
        // Shared heads.
        assert_eq!(b_shared_prefix_len("caravan", "cart"), 3);
        assert_eq!(b_shared_prefix_len("cart", "caravan"), 3);
        assert_eq!(b_shared_prefix_len("dog", "cat"), 0);
        assert_eq!(b_shared_prefix_len("ab", "abcdef"), 2);
        // Distinct letters present in both; repeats collapse.
        assert_eq!(b_common_letter_count("apple", "pleat"), 4);
        assert_eq!(b_common_letter_count("aabb", "ab"), 2);
        assert_eq!(b_common_letter_count("dog", "cat"), 0);
        // First divergence; -1 on prefix or equality.
        assert_eq!(b_first_diff("dog", "cat"), 0);
        assert_eq!(b_first_diff("caravan", "cart"), 3);
        assert_eq!(b_first_diff("ab", "abcdef"), -1);
        assert_eq!(b_first_diff("abc", "abc"), -1);
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
        // The constructed canonical pair has NO degenerate answers and
        // NO flag ops, so there are no skips anywhere: both scalars are
        // nonzero, the first divergence sits inside the pair, at least
        // two distinct letters are shared, and the words differ in
        // length so `longer_name` is unambiguous.
        for seed in 0..200u64 {
            let (a, b) = canonical(seed);
            let prefix = b_shared_prefix_len(&a, &b);
            let common = b_common_letter_count(&a, &b);
            let diff = b_first_diff(&a, &b);
            let longer = b_longer_name(&a, &b);
            let middle = b_middle_of_longer(&a, &b);
            assert!(!a.is_empty() && !b.is_empty(), "seed {seed}");
            assert_ne!(a.len(), b.len(), "seed {seed}: lengths must differ");
            assert_ne!(a, b, "seed {seed}");
            assert!(prefix >= 1, "const-zero survives at seed {seed}");
            assert!(diff >= 1, "seed {seed}: divergence must be interior");
            assert!(common >= 2, "seed {seed}: too few shared letters");
            assert!(!longer.is_empty(), "seed {seed}");
            assert!(!middle.is_empty(), "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((a, b), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &a, &b), out, "seed {seed}");
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
                // Match the whole signature line: borrowed answers carry
                // lifetimes between the name and the paren.
                let fn_line = op_sig_src(op);
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
            // Allocation-shaped leak tokens must stay out of the
            // skeleton; the worked examples legitimately show outputs,
            // never rules — so tokens carry implementation shapes.
            assert!(!sk.contains("to_string("));
            assert!(!sk.contains("format!("));
            assert!(!sk.contains("vec!["));
            assert!(!sk.contains(".collect("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("to_string("));
            assert!(!p.contains("format!("));
            assert!(!p.contains("vec!["));
            assert!(!p.contains(".collect("));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op takes the pair: exactly one comma on both sides.
        for op in OP_ALL {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call = call_src(op);
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn reference_avoids_allocation_shapes() {
        // The load-bearing structural pin: the emitted reference never
        // names an allocating operation, while the clone-everything
        // baseline does on every body — that is exactly what the hidden
        // allocation probe punishes.
        for seed in [0u64, 1, 2, 7, 42] {
            let spec = sample(seed);
            let src = reference_src(&spec);
            for token in ["to_string(", "format!(", "vec![", ".collect("] {
                assert!(
                    !src.contains(token),
                    "seed {seed}: reference allocates via {token}"
                );
            }
            let cheat = clone_everything(&spec);
            for token in ["to_string(", "format!(", "vec![", ".collect("] {
                if token == "format!(" {
                    assert!(cheat.contains(token), "cheat must allocate");
                } else {
                    assert!(!cheat.contains(token));
                }
            }
        }
    }

    #[test]
    fn alloc_probe_is_wired_into_the_task() {
        let g = BorrowFixFamily;
        let t = g.generate(15);
        // The probe rides the standard oracle's L3 slot...
        assert_eq!(t.alloc_test, "alloc");
        // ...as a real hidden file with the counting allocator and every
        // selected op exercised.
        let probe = t
            .hidden
            .get(&PathBuf::from("tests/alloc.rs"))
            .expect("alloc probe must ship as a hidden test");
        assert!(probe.contains("#[global_allocator]"));
        assert!(probe.contains("hot_path_allocates_nothing"));
        let spec = sample(15);
        for op in spec.ops {
            assert!(probe.contains(op.name()), "probe must call {}", op.name());
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = BorrowFixFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }

    #[test]
    fn alloc_probe_counts_two_distinct_inputs_after_the_reset() {
        for seed in 0..20u64 {
            let t = BorrowFixFamily.generate(seed);
            let probe = &t.hidden[std::path::Path::new("tests/alloc.rs")];
            let reset = probe
                .find("COUNT.store(0")
                .expect("probe must zero the counter after warm-up");
            // The counted round touches a second, differently-shaped pair:
            // a memoizer that cached `gravel`/`grave` during warm-up still
            // has to allocate when it first sees `amber`/`amble`.
            let amber = probe[reset..]
                .find("exercise(\"amber\", \"amble\")")
                .expect("second input must be exercised post-reset")
                + reset;
            let gravel = probe[reset..]
                .find("exercise(\"gravel\", \"grave\")")
                .expect("original input must also be counted post-reset")
                + reset;
            assert!(reset < amber && reset < gravel, "seed {seed}");
            assert_ne!(amber, gravel);
        }
    }
}

//! The `lifetime-view` family (category `borrow-lifetimes`) — a fourth borrow shape: a
//! **struct that holds a borrow**, and methods whose results must outlive the `&self` they were
//! called through.
//!
//! `lifetime-split` makes the model write lifetimes on a free function whose elided form does
//! not compile. This is its quieter sibling: the elided form of a *method* **compiles**.
//!
//! ```text
//! impl<'a> View<'a> {
//!     pub fn head(&self, n: usize) -> View<'_>   // compiles — and is wrong
//! }
//! ```
//!
//! `'_` here is the lifetime of the `&self` borrow, not of the data the view wraps, so the
//! returned view cannot be used after the parent view is dropped. The hidden tests drop the
//! parent first (`E0597` for the elided answer), which is the lifetime-elision mistake that
//! actually occurs in practice: the code builds, the tests do not. The correct return type is
//! `View<'a>`.
//!
//! The type, `new` and `as_slice` (which returns `&'a [i64]`) are pinned; the model implements
//! three of five slicing methods (`head`, `tail`, `init`, `last_n`, `inner`), chosen by seed.
//!
//! Seed-selected on two axes:
//!
//! 1. **Methods** — which 3 of the 5: C(5,3) = 10 sets.
//! 2. **Miss** — what an out-of-range `n` does: `Plain` clamps (never panics, returns the
//!    documented empty/whole view) or `Optional` returns `None`.
//!
//! 10 x 2 = **20 distinct skills**; the type name is cosmetic and excluded from
//! `spec_signature` (Q31). Constraint-dominant like the other borrow-lifetimes families
//! (docs/04): a hidden allocation probe and the forbidden `leak` path close the `Box::leak`
//! escape. The lifetime check is in **every** hidden target so a wrong signature zeroes all of
//! them (see the `lifetime-split` entry in BUILD-LOG for why).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    Head,
    Tail,
    Init,
    LastN,
    Inner,
}

const ALL_OPS: [Op; 5] = [Op::Head, Op::Tail, Op::Init, Op::LastN, Op::Inner];

#[derive(Clone, Copy, Debug, PartialEq)]
enum Miss {
    Plain,
    Optional,
}

struct Spec {
    ops: Vec<Op>,
    miss: Miss,
    name: &'static str,
}

const NAMES: &[&str] = &["View", "Window", "Span", "Region", "Cursor"];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    // A uniformly chosen 3-subset by partial Fisher-Yates.
    let mut idx = [0usize, 1, 2, 3, 4];
    for i in 0..3 {
        let j = i + rng.below((5 - i) as u64) as usize;
        idx.swap(i, j);
    }
    let mut ops: Vec<Op> = idx[..3].iter().map(|&i| ALL_OPS[i]).collect();
    ops.sort();
    let miss = if rng.below(2) == 0 {
        Miss::Plain
    } else {
        Miss::Optional
    };
    let name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec { ops, miss, name }
}

fn method_name(op: Op) -> &'static str {
    match op {
        Op::Head => "head",
        Op::Tail => "tail",
        Op::Init => "init",
        Op::LastN => "last_n",
        Op::Inner => "inner",
    }
}

// ---- native reference ---------------------------------------------------------

/// The slice the op selects, or `None` for an out-of-range `n` under `Optional`.
fn apply(op: Op, miss: Miss, data: &[i64], n: usize) -> Option<&[i64]> {
    let len = data.len();
    match miss {
        Miss::Plain => Some(match op {
            Op::Head => &data[..n.min(len)],
            Op::Tail => &data[n.min(len)..],
            Op::Init => &data[..len - n.min(len)],
            Op::LastN => &data[len - n.min(len)..],
            Op::Inner => {
                if n.saturating_mul(2) >= len {
                    &data[..0]
                } else {
                    &data[n..len - n]
                }
            }
        }),
        Miss::Optional => match op {
            Op::Head if n <= len => Some(&data[..n]),
            Op::Tail if n <= len => Some(&data[n..]),
            Op::Init if n <= len => Some(&data[..len - n]),
            Op::LastN if n <= len => Some(&data[len - n..]),
            Op::Inner if n.saturating_mul(2) <= len => Some(&data[n..len - n]),
            _ => None,
        },
    }
}

// ---- emitted source -----------------------------------------------------------

/// What a method body does.
#[derive(Clone, Copy, PartialEq)]
enum Body {
    Todo,
    Correct,
    /// Returns the whole view regardless of `n`.
    Echo,
    /// Returns an empty view (or `None`).
    Empty,
}

fn correct_body(spec: &Spec, op: Op) -> String {
    let n = spec.name;
    match spec.miss {
        Miss::Plain => match op {
            Op::Head => format!("let k = n.min(self.data.len());\n        {n} {{ data: &self.data[..k] }}"),
            Op::Tail => format!("let k = n.min(self.data.len());\n        {n} {{ data: &self.data[k..] }}"),
            Op::Init => format!(
                "let k = self.data.len() - n.min(self.data.len());\n        {n} {{ data: &self.data[..k] }}"
            ),
            Op::LastN => format!(
                "let k = self.data.len() - n.min(self.data.len());\n        {n} {{ data: &self.data[k..] }}"
            ),
            Op::Inner => format!(
                "let len = self.data.len();\n        if n.saturating_mul(2) >= len {{\n            {n} {{ data: &self.data[..0] }}\n        }} else {{\n            {n} {{ data: &self.data[n..len - n] }}\n        }}"
            ),
        },
        Miss::Optional => {
            let (cond, slice) = match op {
                Op::Head => ("n > len", "..n"),
                Op::Tail => ("n > len", "n.."),
                Op::Init => ("n > len", "..len - n"),
                Op::LastN => ("n > len", "len - n.."),
                Op::Inner => ("n.saturating_mul(2) > len", "n..len - n"),
            };
            format!(
                "let len = self.data.len();\n        if {cond} {{\n            None\n        }} else {{\n            Some({n} {{ data: &self.data[{slice}] }})\n        }}"
            )
        }
    }
}

fn method_src(spec: &Spec, op: Op, lifetime: &str, body: Body) -> String {
    let n = spec.name;
    let ret = match spec.miss {
        Miss::Plain => format!("{n}<{lifetime}>"),
        Miss::Optional => format!("Option<{n}<{lifetime}>>"),
    };
    let inner = match body {
        Body::Todo => "todo!()".to_string(),
        Body::Correct => correct_body(spec, op),
        Body::Echo => match spec.miss {
            Miss::Plain => "let _ = n;\n        *self".to_string(),
            Miss::Optional => "let _ = n;\n        Some(*self)".to_string(),
        },
        Body::Empty => match spec.miss {
            Miss::Plain => format!("let _ = n;\n        {n} {{ data: &[] }}"),
            Miss::Optional => "let _ = n;\n        None".to_string(),
        },
    };
    format!(
        "    pub fn {}(&self, n: usize) -> {ret} {{\n        {inner}\n    }}\n",
        method_name(op)
    )
}

/// The whole file: pinned items, then the three methods (with the given lifetime spelling and
/// bodies).
fn file_src(spec: &Spec, lifetime: &str, body: Body) -> String {
    let n = spec.name;
    let methods: String = spec
        .ops
        .iter()
        .map(|&op| format!("\n{}", method_src(spec, op, lifetime, body)))
        .collect();
    format!(
        "#[derive(Debug, Clone, Copy)]\n\
         pub struct {n}<'a> {{\n\
         \x20   data: &'a [i64],\n\
         }}\n\
         \n\
         impl<'a> {n}<'a> {{\n\
         \x20   pub fn new(data: &'a [i64]) -> {n}<'a> {{\n\
         \x20       {n} {{ data }}\n\
         \x20   }}\n\
         \n\
         \x20   /// The wrapped slice, with the full lifetime of the data (not of `&self`).\n\
         \x20   pub fn as_slice(&self) -> &'a [i64] {{\n\
         \x20       self.data\n\
         \x20   }}\n\
         {methods}}}\n"
    )
}

fn reference_src(spec: &Spec) -> String {
    file_src(spec, "'a", Body::Correct)
}

/// What the model is shown and handed: elided `'_` returns with `todo!()` bodies. It compiles.
fn given_src(spec: &Spec) -> String {
    file_src(spec, "'_", Body::Todo)
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .1
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Implement the three `{name}` methods below. The type, `new` and `as_slice` are\n\
         //! provided — keep them.\n\
         //!\n\
         {doc}\n\
         {given}",
        name = spec.name,
        given = given_src(spec),
    )
}

// ---- worked examples ----------------------------------------------------------

/// One case: the data and an `n` to try on every method.
struct Case {
    data: Vec<i64>,
    n: usize,
}

/// The canonical case: eight distinct non-zero values and `n = 2`, so every method's result is a
/// non-empty proper sub-view under both miss policies — what both baselines need to fail.
fn canonical() -> Case {
    Case {
        data: vec![1, 2, 3, 4, 5, 6, 7, 8],
        n: 2,
    }
}

fn worked_examples(spec: &Spec, seed: u64) -> (Vec<Case>, String) {
    let mut rng = Rng::new(seed ^ 0x71E3_0000_0000_0B1D);
    let mut cases = vec![canonical()];
    for _ in 0..2 {
        let len = 3 + rng.below(7) as usize;
        let data = (0..len).map(|_| 1 + rng.below(90) as i64).collect();
        // Sometimes out of range, so the miss policy is pinned by an example.
        let n = rng.below(len as u64 + 3) as usize;
        cases.push(Case { data, n });
    }
    let mut prose = String::new();
    for c in &cases {
        for &op in &spec.ops {
            let out = apply(op, spec.miss, &c.data, c.n);
            let shown = match (spec.miss, out) {
                (Miss::Plain, Some(s)) => format!("{s:?}"),
                (Miss::Optional, Some(s)) => format!("Some({s:?})"),
                (_, None) => "None".to_string(),
            };
            prose.push_str(&format!(
                "  {}::new(&{:?}).{}({})  ->  {}\n",
                spec.name,
                c.data,
                method_name(op),
                c.n,
                shown
            ));
        }
    }
    (cases, prose)
}

fn miss_prose(spec: &Spec) -> &'static str {
    match spec.miss {
        Miss::Plain => {
            "Never panic: clamp `n` to what is available (so `head(n)` with `n >= len` is the whole view, `tail(n)` with `n >= len` is empty, and `inner(n)` is empty once `2n >= len`)."
        }
        Miss::Optional => {
            "Return `None` when `n` is out of range: `n > len` for `head`/`tail`/`init`/`last_n`, and `2n > len` for `inner`. Otherwise return `Some(view)` (possibly empty)."
        }
    }
}

fn op_prose(op: Op) -> &'static str {
    match op {
        Op::Head => "`head(n)` — the first `n` elements",
        Op::Tail => "`tail(n)` — everything after the first `n` elements",
        Op::Init => "`init(n)` — everything except the last `n` elements",
        Op::LastN => "`last_n(n)` — the last `n` elements",
        Op::Inner => "`inner(n)` — the middle, with `n` elements removed from each end",
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let ops: String = spec
        .ops
        .iter()
        .map(|&o| format!("  - {}\n", op_prose(o)))
        .collect();
    let (_, examples) = worked_examples(spec, seed);
    format!(
        "Implement the three methods of `{name}` in `src/lib.rs`. `{name}<'a>` is a view over a \
         borrowed slice; the type, `new` and `as_slice` are provided, and each method's body is \
         `todo!()`.\n\
         \n\
         Each method returns a **sub-view** of the same data:\n\
         {ops}\
         \n\
         {miss}\n\
         \n\
         The result is a view onto the *original data*, not onto the `{name}` value the method \
         was called on: a caller must be able to keep using the returned view after the parent \
         `{name}` has been dropped (the data it wraps is still alive). Make the signatures say so.\n\
         \n\
         Constraints:\n\
         - Do not allocate or copy the data, and do not leak memory to extend a lifetime.\n\
         - Do not use `unsafe`. Do not change the provided items.\n\
         \n\
         Provided in `src/lib.rs`:\n\
         ```rust\n\
         {given}```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.name,
        miss = miss_prose(spec),
        given = given_src(spec),
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

/// `Vec<i64>` / `Option<Vec<i64>>` expression for one call on `view`.
fn call_to_vec(spec: &Spec, view: &str, op: Op, n: &str) -> String {
    let call = format!("{view}.{}({n})", method_name(op));
    match spec.miss {
        Miss::Plain => format!("{call}.as_slice().to_vec()"),
        Miss::Optional => format!("{call}.map(|s| s.as_slice().to_vec())"),
    }
}

fn expected_lit(spec: &Spec, out: Option<&[i64]>) -> String {
    match (spec.miss, out) {
        (Miss::Plain, Some(s)) => format!("vec!{s:?}"),
        (Miss::Optional, Some(s)) => format!("Some(vec!{s:?})"),
        (_, None) => "None::<Vec<i64>>".to_string(),
    }
}

/// The lifetime check: the parent view dies before the child is used. It only compiles when the
/// method returns `View<'a>` rather than `View<'_>` (tied to `&self`). Present in every hidden
/// target; as a block so the alloc target can run it inside its measured test.
fn scoped_block_src(spec: &Spec) -> String {
    let c = canonical();
    let op = spec.ops[0];
    let want = apply(op, spec.miss, &c.data, c.n);
    // The child itself (a view) must outlive `parent`, so keep the view, convert afterwards.
    let child = format!("parent.{}({})", method_name(op), c.n);
    let finish = match spec.miss {
        Miss::Plain => "child.as_slice().to_vec()".to_string(),
        Miss::Optional => "child.map(|s| s.as_slice().to_vec())".to_string(),
    };
    format!(
        "    // scoped-parent check\n\
         \x20   {{\n\
         \x20       let data = vec!{data:?};\n\
         \x20       let child;\n\
         \x20       {{\n\
         \x20           let parent = {name}::new(&data);\n\
         \x20           child = {child};\n\
         \x20       }}\n\
         \x20       assert_eq!({finish}, {want});\n\
         \x20   }}\n",
        data = c.data,
        name = spec.name,
        want = expected_lit(spec, want),
    )
}

fn scoped_test_src(spec: &Spec) -> String {
    format!(
        "#[test]\nfn parent_may_be_dropped_before_the_child_is_used() {{\n{}}}\n",
        scoped_block_src(spec)
    )
}

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let (cases, _) = worked_examples(spec, seed);
    let mut body = format!("use task::{};\n\n", spec.name);
    for (i, c) in cases.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let data = vec!{:?};\n    let v = {}::new(&data);\n",
            c.data, spec.name
        ));
        for &op in &spec.ops {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_to_vec(spec, "v", op, &c.n.to_string()),
                expected_lit(spec, apply(op, spec.miss, &c.data, c.n))
            ));
        }
        body.push_str("}\n\n");
    }
    body.push_str(&scoped_test_src(spec));
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    let mut checks = String::new();
    for &op in &spec.ops {
        checks.push_str(&format!(
            "        assert_eq!({}, {}, \"{} data={{data:?}} n={{n}}\");\n",
            call_to_vec(spec, "tv", op, "n"),
            call_to_vec(spec, "rv", op, "n"),
            method_name(op)
        ));
    }
    format!(
        "use task::{name};\n\n\
         mod reference {{\n{indented}}}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x71E3_ED00_0000_0046;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 13) as usize;\n\
         \x20       let data: Vec<i64> = (0..len).map(|_| (next() % 199) as i64 - 99).collect();\n\
         \x20       let n = (next() % 16) as usize;\n\
         \x20       let tv = {name}::new(&data);\n\
         \x20       let rv = reference::{name}::new(&data);\n\
         {checks}\
         \x20   }}\n\
         }}\n\
         \n\
         {scoped}",
        name = spec.name,
        scoped = scoped_test_src(spec),
    )
}

fn alloc_test_src(spec: &Spec) -> String {
    let c = canonical();
    let mut calls = String::new();
    for &op in &spec.ops {
        calls.push_str(&format!(
            "        std::hint::black_box(v.{}({}));\n",
            method_name(op),
            c.n
        ));
    }
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
         {scoped}\
         \x20   let data = vec!{data:?};\n\
         \x20   let v = {name}::new(&data);\n\
         \x20   let before = ALLOCS.load(Ordering::SeqCst);\n\
         \x20   for _ in 0..100 {{\n\
         {calls}\
         \x20   }}\n\
         \x20   let after = ALLOCS.load(Ordering::SeqCst);\n\
         \x20   assert_eq!(after - before, 0, \"allocated {{}} time(s)\", after - before);\n\
         }}\n",
        name = spec.name,
        scoped = scoped_block_src(spec),
        data = c.data,
    )
}

/// Degenerate: every method returns the whole view (correct lifetimes).
fn echo(spec: &Spec) -> String {
    file_src(spec, "'a", Body::Echo)
}

/// Degenerate: every method returns an empty view / `None` (correct lifetimes).
fn empty(spec: &Spec) -> String {
    file_src(spec, "'a", Body::Empty)
}

pub struct LifetimeViewFamily;

impl Generator for LifetimeViewFamily {
    fn id(&self) -> &str {
        "lifetime-view"
    }
    fn category(&self) -> &str {
        "borrow-lifetimes"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("lifetime-view", seed);

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
            id: format!("lifetime-view/{seed:016x}"),
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
        vec![
            ("echo-whole".to_string(), echo(&spec)),
            ("empty".to_string(), empty(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let ops: Vec<&str> = spec.ops.iter().map(|&o| method_name(o)).collect();
        let miss = match spec.miss {
            Miss::Plain => "plain",
            Miss::Optional => "optional",
        };
        vec![format!("ops:{}", ops.join("+")), format!("miss:{miss}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(ops: &[Op], miss: Miss) -> Spec {
        Spec {
            ops: ops.to_vec(),
            miss,
            name: "View",
        }
    }

    #[test]
    fn generation_is_deterministic() {
        let g = LifetimeViewFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn apply_matches_intent() {
        let d = [1, 2, 3, 4, 5, 6, 7, 8];
        let p = |op, n| apply(op, Miss::Plain, &d, n).unwrap().to_vec();
        assert_eq!(p(Op::Head, 2), vec![1, 2]);
        assert_eq!(p(Op::Tail, 2), vec![3, 4, 5, 6, 7, 8]);
        assert_eq!(p(Op::Init, 2), vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(p(Op::LastN, 2), vec![7, 8]);
        assert_eq!(p(Op::Inner, 2), vec![3, 4, 5, 6]);
        // Plain clamps.
        assert_eq!(p(Op::Head, 99), d.to_vec());
        assert_eq!(p(Op::Tail, 99), Vec::<i64>::new());
        assert_eq!(p(Op::Inner, 4), Vec::<i64>::new());
        // Optional misses.
        let o = |op, n| apply(op, Miss::Optional, &d, n).map(|s| s.to_vec());
        assert_eq!(o(Op::Head, 9), None);
        assert_eq!(o(Op::Head, 8), Some(d.to_vec()));
        assert_eq!(o(Op::Inner, 4), Some(vec![]));
        assert_eq!(o(Op::Inner, 5), None);
    }

    #[test]
    fn canonical_defeats_both_baselines_under_every_op_and_policy() {
        // echo-whole fails if the result differs from the whole data; empty fails if the
        // result is present and non-empty.
        let c = canonical();
        for &op in &ALL_OPS {
            for &miss in &[Miss::Plain, Miss::Optional] {
                let out = apply(op, miss, &c.data, c.n)
                    .unwrap_or_else(|| panic!("{op:?}/{miss:?}: canonical missed"));
                assert!(!out.is_empty(), "{op:?}/{miss:?}: empty");
                assert_ne!(out, &c.data[..], "{op:?}/{miss:?}: whole");
            }
        }
    }

    #[test]
    fn the_given_code_uses_elided_lifetimes_and_the_reference_does_not() {
        let s = spec(&[Op::Head, Op::Tail, Op::Inner], Miss::Plain);
        let given = given_src(&s);
        assert!(given.contains("-> View<'_>") && given.contains("todo!()"));
        let r = reference_src(&s);
        assert!(r.contains("-> View<'a>") && !r.contains("'_"));
        let so = spec(&[Op::Head, Op::Tail, Op::Inner], Miss::Optional);
        assert!(given_src(&so).contains("Option<View<'_>>"));
        assert!(reference_src(&so).contains("Option<View<'a>>"));
    }

    #[test]
    fn scoped_check_is_in_every_target() {
        let g = LifetimeViewFamily;
        for seed in 0..30u64 {
            let t = g.generate(seed);
            for file in [
                "tests/behavior.rs",
                "tests/differential.rs",
                "tests/alloc.rs",
            ] {
                assert!(
                    t.hidden[&PathBuf::from(file)].contains("scoped-parent check")
                        || t.hidden[&PathBuf::from(file)]
                            .contains("parent_may_be_dropped_before_the_child_is_used"),
                    "seed {seed}: {file} lacks the scoped-parent check"
                );
            }
        }
    }

    #[test]
    fn seeds_vary_methods_and_policy() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..600u64 {
            let s = sample(seed);
            assert_eq!(s.ops.len(), 3);
            variants.insert(format!("{:?}/{:?}", s.ops, s.miss));
        }
        assert_eq!(variants.len(), 20);
    }

    #[test]
    fn leak_is_forbidden_and_canary_present() {
        let t = LifetimeViewFamily.generate(3);
        assert_eq!(t.forbidden_paths, vec!["leak".to_string()]);
        assert!(t.prompt.contains(&t.canary));
    }
}

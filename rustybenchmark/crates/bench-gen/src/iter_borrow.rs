//! The `iter-borrow` family (category `borrow-lifetimes`) — return a **lazy iterator that
//! borrows `self`**, and say so in the return type.
//!
//! A fifth borrow shape. A pinned `Series` owns a `Vec<i64>`; the model implements three
//! methods that each return an iterator over it. The skeleton's return types are the natural
//! ones and compile with stub (empty-iterator) bodies, but a body that borrows `self` does **not** type-check
//! against them:
//!
//! ```text
//! pub fn positives(&self) -> impl Iterator<Item = i64>      // E0700: hidden type captures `'_`
//! pub fn positives(&self) -> Box<dyn Iterator<Item = i64>>  // lifetime may not live long enough
//! ```
//!
//! Both need `+ '_`. That is a very common stumbling block (and `impl Trait` capture rules differ by
//! edition), and the cheap way out — `collect()` into a `Vec` and return `vec.into_iter()`, which
//! owns its data and needs no lifetime — is exactly what a hidden allocation probe catches: the
//! methods are called on 256 elements and only `next()` is taken, so a lazy iterator allocates
//! nothing (`impl`) or at most the one `Box` (`Boxed`), and an eager one allocates a `Vec`.
//!
//! Seed-selected on two axes:
//!
//! 1. **Methods** — which 3 of 6 iterator-returning methods: `positives`, `doubled`,
//!    `every_other`, `pair_sums` (`windows`), `running_max` (`scan`), `big_refs` (yields
//!    `&i64`, which already names the borrow — a decoy for the pattern).
//! 2. **Return kind** — `impl Iterator<..> + '_` or `Box<dyn Iterator<..> + '_>`.
//!
//! C(6,3) x 2 = **40 distinct skills**; the type name is cosmetic and excluded from
//! `spec_signature` (Q31). Constraint-dominant (docs/04); `leak` is forbidden. Solution-first
//! (ADR-0003): the native `values` and the emitted bodies are mirrored, and the differential
//! compares every method's full output on 3000 random series against an inlined reference.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    Positives,
    Doubled,
    EveryOther,
    PairSums,
    RunningMax,
    BigRefs,
}

const ALL_OPS: [Op; 6] = [
    Op::Positives,
    Op::Doubled,
    Op::EveryOther,
    Op::PairSums,
    Op::RunningMax,
    Op::BigRefs,
];

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Impl,
    Boxed,
}

struct Spec {
    ops: Vec<Op>,
    kind: Kind,
    name: &'static str,
}

const NAMES: &[&str] = &["Series", "Track", "Reel", "Tape", "Ledger"];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let mut idx = [0usize, 1, 2, 3, 4, 5];
    for i in 0..3 {
        let j = i + rng.below((6 - i) as u64) as usize;
        idx.swap(i, j);
    }
    let mut ops: Vec<Op> = idx[..3].iter().map(|&i| ALL_OPS[i]).collect();
    ops.sort();
    let kind = if rng.below(2) == 0 {
        Kind::Impl
    } else {
        Kind::Boxed
    };
    let name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec { ops, kind, name }
}

fn method_name(op: Op) -> &'static str {
    match op {
        Op::Positives => "positives",
        Op::Doubled => "doubled",
        Op::EveryOther => "every_other",
        Op::PairSums => "pair_sums",
        Op::RunningMax => "running_max",
        Op::BigRefs => "big_refs",
    }
}

/// The iterator's item type as written in the signature.
fn item_ty(op: Op) -> &'static str {
    match op {
        Op::BigRefs => "&i64",
        _ => "i64",
    }
}

// ---- native reference ---------------------------------------------------------------

fn values(op: Op, data: &[i64]) -> Vec<i64> {
    match op {
        Op::Positives => data.iter().copied().filter(|&x| x > 0).collect(),
        Op::Doubled => data.iter().map(|&x| x * 2).collect(),
        Op::EveryOther => data.iter().copied().step_by(2).collect(),
        Op::PairSums => data.windows(2).map(|w| w[0] + w[1]).collect(),
        Op::RunningMax => data
            .iter()
            .scan(i64::MIN, |m, &x| {
                *m = (*m).max(x);
                Some(*m)
            })
            .collect(),
        Op::BigRefs => data.iter().copied().filter(|&x| x >= 10).collect(),
    }
}

// ---- emitted source -----------------------------------------------------------------

fn chain_src(op: Op) -> &'static str {
    match op {
        Op::Positives => "self.data.iter().copied().filter(|&x| x > 0)",
        Op::Doubled => "self.data.iter().map(|&x| x * 2)",
        Op::EveryOther => "self.data.iter().copied().step_by(2)",
        Op::PairSums => "self.data.windows(2).map(|w| w[0] + w[1])",
        Op::RunningMax => {
            "self.data.iter().scan(i64::MIN, |m, &x| {\n            *m = (*m).max(x);\n            Some(*m)\n        })"
        }
        Op::BigRefs => "self.data.iter().filter(|&&x| x >= 10)",
    }
}

/// How a method body is written.
#[derive(Clone, Copy, PartialEq)]
enum Body {
    Correct,
    /// Collect into a `Vec` first and return its owning iterator: correct, eager, allocates.
    Eager,
    /// An empty iterator.
    Empty,
}

fn sig_ret(spec: &Spec, op: Op, captured: bool) -> String {
    let item = item_ty(op);
    // `Box<dyn Iterator<Item = &i64>>` is ill-formed on its own (the trait object defaults to
    // `'static` while the item borrows), so for that one method the borrow is already written in
    // the given signature -- it is the decoy: the other two methods are the ones that need `+ '_`.
    let decoy = op == Op::BigRefs && spec.kind == Kind::Boxed;
    let tail = if captured || decoy { " + '_" } else { "" };
    match spec.kind {
        Kind::Impl => format!("impl Iterator<Item = {item}>{tail}"),
        Kind::Boxed => format!("Box<dyn Iterator<Item = {item}>{tail}>"),
    }
}

fn method_src(spec: &Spec, op: Op, captured: bool, body: Body) -> String {
    let wrap = |expr: &str| match spec.kind {
        Kind::Impl => expr.to_string(),
        Kind::Boxed => format!("Box::new({expr})"),
    };
    let inner = match body {
        Body::Correct => wrap(chain_src(op)),
        Body::Eager => match op {
            // `&i64` items cannot outlive a local Vec, so there is no eager form: the baseline
            // degenerates to an empty iterator for this method.
            Op::BigRefs => wrap("std::iter::empty()"),
            _ => wrap(&format!(
                "{{\n            let v: Vec<i64> = {}.collect();\n            v.into_iter()\n        }}",
                chain_src(op)
            )),
        },
        Body::Empty => wrap("std::iter::empty()"),
    };
    format!(
        "    pub fn {}(&self) -> {} {{\n        {inner}\n    }}\n",
        method_name(op),
        sig_ret(spec, op, captured)
    )
}

fn file_src(spec: &Spec, captured: bool, body: Body) -> String {
    let n = spec.name;
    let methods: String = spec
        .ops
        .iter()
        .map(|&op| format!("\n{}", method_src(spec, op, captured, body)))
        .collect();
    format!(
        "pub struct {n} {{\n\
         \x20   data: Vec<i64>,\n\
         }}\n\
         \n\
         impl {n} {{\n\
         \x20   pub fn new(data: Vec<i64>) -> {n} {{\n\
         \x20       {n} {{ data }}\n\
         \x20   }}\n\
         {methods}}}\n"
    )
}

fn reference_src(spec: &Spec) -> String {
    file_src(spec, true, Body::Correct)
}

/// What the model is handed: the natural, capture-less signatures with stub bodies that return an
/// empty iterator. (`todo!()` does not type-check as an `impl Iterator` body -- the diverging
/// expression falls back to `()` -- so the stub is an explicit empty iterator.)
fn given_src(spec: &Spec) -> String {
    file_src(spec, false, Body::Empty)
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .1
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Implement the three `{name}` methods below. The type and `new` are provided — keep them.\n\
         //!\n\
         {doc}\n\
         {given}",
        name = spec.name,
        given = given_src(spec),
    )
}

// ---- worked examples ------------------------------------------------------------------

/// The canonical data: mixed signs, values on both sides of 10, length 8 — every method yields a
/// non-empty proper result (what both baselines need to fail).
fn canonical() -> Vec<i64> {
    vec![5, -3, 12, 0, 8, -1, 15, 9]
}

fn worked_examples(spec: &Spec, seed: u64) -> (Vec<Vec<i64>>, String) {
    let mut rng = Rng::new(seed ^ 0x17E8_0000_0000_0B20);
    let mut datas = vec![canonical()];
    for _ in 0..2 {
        let len = 3 + rng.below(6) as usize;
        datas.push((0..len).map(|_| rng.below(41) as i64 - 15).collect());
    }
    let mut prose = String::new();
    for d in &datas {
        for &op in &spec.ops {
            prose.push_str(&format!(
                "  {}::new(vec!{:?}).{}()  ->  {:?}\n",
                spec.name,
                d,
                method_name(op),
                values(op, d)
            ));
        }
    }
    (datas, prose)
}

fn op_prose(op: Op) -> &'static str {
    match op {
        Op::Positives => "`positives()` — the elements greater than 0, in order",
        Op::Doubled => "`doubled()` — every element times 2, in order",
        Op::EveryOther => "`every_other()` — elements at index 0, 2, 4, …",
        Op::PairSums => "`pair_sums()` — the sum of each adjacent pair (`windows(2)`); empty for fewer than 2 elements",
        Op::RunningMax => "`running_max()` — for each position, the largest element seen so far",
        Op::BigRefs => "`big_refs()` — references to the elements that are `>= 10`, in order",
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let ops: String = spec
        .ops
        .iter()
        .map(|&o| format!("  - {}\n", op_prose(o)))
        .collect();
    let (_, examples) = worked_examples(spec, seed);
    let kind = match spec.kind {
        Kind::Impl => "an `impl Iterator`",
        Kind::Boxed => "a `Box<dyn Iterator>`",
    };
    format!(
        "Implement the three methods of `{name}` in `src/lib.rs`. `{name}` owns a `Vec<i64>`; \
         `new` is provided and each method's body is a stub that returns an empty iterator.\n\
         \n\
         Each method returns {kind} over the series' own data, **lazily**:\n\
         {ops}\
         \n\
         The iterator borrows the `{name}` it was called on, so the return type has to say so — \
         the signatures as given are not yet right for a body that borrows `self`; fix them.\n\
         \n\
         Constraints:\n\
         - Be lazy: do not collect into a `Vec` (or clone the data) to avoid the borrow. The checks \
         take only the first element of each iterator over a long series and count allocations.\n\
         - Do not use `unsafe` or leak memory. Do not change `new`.\n\
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

/// `Vec<i64>` expression collecting one method's output (derefs `&i64` items).
fn collect_expr(op: Op, recv: &str) -> String {
    match op {
        Op::BigRefs => format!(
            "{recv}.{}().copied().collect::<Vec<i64>>()",
            method_name(op)
        ),
        _ => format!("{recv}.{}().collect::<Vec<i64>>()", method_name(op)),
    }
}

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let (datas, _) = worked_examples(spec, seed);
    let mut body = format!("use task::{};\n\n", spec.name);
    for (i, d) in datas.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let s = {}::new(vec!{d:?});\n",
            spec.name
        ));
        for &op in &spec.ops {
            body.push_str(&format!(
                "    assert_eq!({}, {:?});\n",
                collect_expr(op, "s"),
                values(op, d)
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    let mut checks = String::new();
    for &op in &spec.ops {
        checks.push_str(&format!(
            "        assert_eq!({}, {}, \"{} {{data:?}}\");\n",
            collect_expr(op, "t"),
            collect_expr(op, "r"),
            method_name(op)
        ));
    }
    format!(
        "use task::{name};\n\n\
         mod reference {{\n{indented}}}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x17E8_ED00_0000_004A;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 13) as usize;\n\
         \x20       let data: Vec<i64> = (0..len).map(|_| (next() % 61) as i64 - 20).collect();\n\
         \x20       let t = {name}::new(data.clone());\n\
         \x20       let r = reference::{name}::new(data.clone());\n\
         {checks}\
         \x20   }}\n\
         }}\n",
        name = spec.name,
    )
}

fn alloc_test_src(spec: &Spec) -> String {
    let mut calls = String::new();
    for &op in &spec.ops {
        calls.push_str(&format!(
            "        std::hint::black_box(s.{}().next());\n",
            method_name(op)
        ));
    }
    // Lazy `impl`: zero allocations. Lazy `Box<dyn>`: at most the one Box per call.
    let limit = match spec.kind {
        Kind::Impl => "0".to_string(),
        Kind::Boxed => format!("{} * 50", spec.ops.len()),
    };
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
         fn iterators_are_lazy() {{\n\
         \x20   let s = {name}::new((0..256).map(|x| x % 17 - 5).collect());\n\
         \x20   let before = ALLOCS.load(Ordering::SeqCst);\n\
         \x20   for _ in 0..50 {{\n\
         {calls}\
         \x20   }}\n\
         \x20   let used = ALLOCS.load(Ordering::SeqCst) - before;\n\
         \x20   assert!(used <= {limit}, \"allocated {{used}} time(s) taking the first element of each iterator\");\n\
         }}\n",
        name = spec.name,
    )
}

/// Degenerate: correct output, but collected eagerly into an owned `Vec` (allocates).
fn eager(spec: &Spec) -> String {
    file_src(spec, true, Body::Eager)
}

/// Degenerate: every iterator is empty.
fn empty(spec: &Spec) -> String {
    file_src(spec, true, Body::Empty)
}

pub struct IterBorrowFamily;

impl Generator for IterBorrowFamily {
    fn id(&self) -> &str {
        "iter-borrow"
    }
    fn category(&self) -> &str {
        "borrow-lifetimes"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("iter-borrow", seed);

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
            id: format!("iter-borrow/{seed:016x}"),
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
            ("eager-collect".to_string(), eager(&spec)),
            ("empty".to_string(), empty(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let ops: Vec<&str> = spec.ops.iter().map(|&o| method_name(o)).collect();
        let kind = match spec.kind {
            Kind::Impl => "impl",
            Kind::Boxed => "boxed",
        };
        vec![format!("ops:{}", ops.join("+")), format!("kind:{kind}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = IterBorrowFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn values_match_intent() {
        let d = [5, -3, 12, 0, 8, -1, 15, 9];
        assert_eq!(values(Op::Positives, &d), vec![5, 12, 8, 15, 9]);
        assert_eq!(values(Op::Doubled, &d), vec![10, -6, 24, 0, 16, -2, 30, 18]);
        assert_eq!(values(Op::EveryOther, &d), vec![5, 12, 8, 15]);
        assert_eq!(values(Op::PairSums, &d), vec![2, 9, 12, 8, 7, 14, 24]);
        assert_eq!(
            values(Op::RunningMax, &d),
            vec![5, 5, 12, 12, 12, 12, 15, 15]
        );
        assert_eq!(values(Op::BigRefs, &d), vec![12, 15]);
        assert!(values(Op::PairSums, &[1]).is_empty());
    }

    #[test]
    fn canonical_defeats_the_empty_baseline_under_every_op() {
        // `empty` fails on every seed iff every method yields something on the canonical data.
        for &op in &ALL_OPS {
            assert!(!values(op, &canonical()).is_empty(), "{op:?}");
        }
    }

    #[test]
    fn the_given_signatures_omit_the_capture_and_the_reference_has_it() {
        for seed in 0..60u64 {
            let s = sample(seed);
            let given = given_src(&s);
            for &op in &s.ops {
                // Only the `Box<dyn Iterator<Item = &i64>>` decoy carries `+ '_` already.
                let decoy = op == Op::BigRefs && s.kind == Kind::Boxed;
                let line = given
                    .lines()
                    .find(|l| l.contains(&format!("pub fn {}(", method_name(op))))
                    .unwrap();
                assert_eq!(line.contains("'_"), decoy, "seed {seed}: {line}");
            }
            assert!(
                given.contains("std::iter::empty()"),
                "seed {seed}: stub body missing"
            );
            let r = reference_src(&s);
            assert!(r.contains("+ '_"), "seed {seed}");
            match s.kind {
                Kind::Impl => assert!(r.contains("impl Iterator") && !r.contains("Box<dyn")),
                Kind::Boxed => assert!(r.contains("Box<dyn Iterator") && r.contains("Box::new(")),
            }
        }
    }

    #[test]
    fn alloc_limit_depends_on_kind() {
        for seed in 0..40u64 {
            let s = sample(seed);
            let a = alloc_test_src(&s);
            match s.kind {
                Kind::Impl => assert!(a.contains("assert!(used <= 0,")),
                Kind::Boxed => assert!(a.contains("* 50")),
            }
        }
    }

    #[test]
    fn seeds_vary_methods_and_kind() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..1500u64 {
            let s = sample(seed);
            assert_eq!(s.ops.len(), 3);
            variants.insert(format!("{:?}/{:?}", s.ops, s.kind));
        }
        assert_eq!(variants.len(), 40);
    }

    #[test]
    fn leak_is_forbidden_and_canary_present() {
        let t = IterBorrowFamily.generate(3);
        assert_eq!(t.forbidden_paths, vec!["leak".to_string()]);
        assert!(t.prompt.contains(&t.canary));
    }
}

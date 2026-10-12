//! The `generic-bounds` family (category `trait-bounds`) — writing your
//! own generic functions over standard-library bounds.
//!
//! Where `trait-impl` pins a trait for the model to implement and
//! `generic-select` bounds a driver, this family asks for GENERIC
//! functions whose correctness is checked on TWO unrelated element
//! types: the hidden behaviour tests instantiate every query on both a
//! list of `i64` and a list of `&str`. A solution hard-coded to integers
//! fails COMPILATION on the words instantiation and scores zero — no
//! oracle changes needed, the ordinary behaviour target carries the
//! catch.
//!
//! The seed prunes which two of five query ops are required:
//! `count_distinct`, `all_same`, `has_adjacent_dup`, `last_index_of`,
//! `second_smallest_index`. Four are bounded by `PartialEq`; the
//! second-smallest query needs `Ord`. C(5,2) = **10 distinct skills**,
//! above the diversity floor; op names are semantic.
//!
//! The canonical lists are sampled until their anchor facts hold: the
//! numeric list carries three-plus distinct values, a side-by-side
//! duplicate pair, a repeated middle entry whose last occurrence is not
//! the leading index, and a second-smallest position clear of zero — so
//! constant cheats miss everywhere. The parallel word list is kept
//! non-degenerate too.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same generic bodies; the
//! differential fuzzes 3000 integer lists against the model while the
//! dual-instantiation behaviour tests pin cross-type generality.
//!
//! Trivial baselines: `const-zero` (fails every scalar outright on the
//! canonical lists) and `hardcoded-i64-everything` (behaviourally
//! correct for numbers but typed `[i64]` throughout, so the words
//! instantiation does not compile — dead on EVERY pair).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    CountDistinct,
    AllSame,
    HasAdjacentDup,
    LastIndexOf,
    SecondSmallestIndex,
}

const OP_ALL: [Op; 5] = [
    Op::CountDistinct,
    Op::AllSame,
    Op::HasAdjacentDup,
    Op::LastIndexOf,
    Op::SecondSmallestIndex,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::CountDistinct => "count_distinct",
            Op::AllSame => "all_same",
            Op::HasAdjacentDup => "has_adjacent_dup",
            Op::LastIndexOf => "last_index_of",
            Op::SecondSmallestIndex => "second_smallest_index",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::CountDistinct => {
                "how many different values appear — first occurrences \
                 counted once"
            }
            Op::AllSame => {
                "whether every entry matches the first; an empty list does \
                 not qualify"
            }
            Op::HasAdjacentDup => "whether two equal entries sit side by side somewhere",
            Op::LastIndexOf => {
                "the position of the final occurrence of the middle entry \
                 (the one at half the length), or minus one when absent"
            }
            Op::SecondSmallestIndex => {
                "the position of the second-smallest entry under the \
                 natural ordering, or minus one when fewer than two \
                 entries; ties among the minimum still count"
            }
        }
    }

    /// The standard-library bound this op's emitted signature declares.
    fn bound(self) -> &'static str {
        match self {
            Op::SecondSmallestIndex => "Ord",
            _ => "PartialEq",
        }
    }

    /// Extra parameters beyond `items`.
    fn extra_arg(self) -> &'static str {
        match self {
            Op::LastIndexOf => ", target: &T",
            _ => "",
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::AllSame | Op::HasAdjacentDup => "bool",
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

/// First-occurrence dedup scan — no collections, no allocation.
fn b_count_distinct<T: PartialEq>(xs: &[T]) -> i64 {
    let mut seen = 0i64;
    for (i, x) in xs.iter().enumerate() {
        if !xs[..i].contains(x) {
            seen += 1;
        }
    }
    seen
}

/// Empty lists do not qualify.
fn b_all_same<T: PartialEq>(xs: &[T]) -> bool {
    match xs.first() {
        Some(first) => xs.iter().all(|x| x == first),
        None => false,
    }
}

/// Side-by-side equality anywhere.
fn b_has_adjacent_dup<T: PartialEq>(xs: &[T]) -> bool {
    xs.windows(2).any(|pair| pair[0] == pair[1])
}

/// Final occurrence of `target`, minus one when absent.
fn b_last_index_of<T: PartialEq>(xs: &[T], target: &T) -> i64 {
    for (i, x) in xs.iter().enumerate().rev() {
        if x == target {
            return i as i64;
        }
    }
    -1
}

/// Runner-up under the natural ordering; duplicates of the minimum are
/// legitimate candidates; fewer than two entries answers minus one.
fn b_second_smallest_index<T: Ord>(xs: &[T]) -> i64 {
    if xs.len() < 2 {
        return -1;
    }
    let mut best = 0usize;
    for i in 1..xs.len() {
        if xs[i] < xs[best] {
            best = i;
        }
    }
    let mut runner: Option<usize> = None;
    for i in 0..xs.len() {
        if i == best {
            continue;
        }
        runner = match runner {
            None => Some(i),
            Some(r) => {
                if xs[i] < xs[r] {
                    Some(i)
                } else {
                    Some(r)
                }
            }
        };
    }
    runner.map(|r| r as i64).unwrap_or(-1)
}

/// The answer shape: scalars as `Num`, predicates as `Flag`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(v) => v.to_string(),
        }
    }
}

fn eval_num(op: Op, xs: &[i64]) -> Out {
    match op {
        Op::CountDistinct => Out::Num(b_count_distinct(xs)),
        Op::AllSame => Out::Flag(b_all_same(xs)),
        Op::HasAdjacentDup => Out::Flag(b_has_adjacent_dup(xs)),
        Op::LastIndexOf => {
            if xs.is_empty() {
                Out::Num(-1)
            } else {
                Out::Num(b_last_index_of(xs, &xs[xs.len() / 2]))
            }
        }
        Op::SecondSmallestIndex => Out::Num(b_second_smallest_index(xs)),
    }
}

fn eval_word(op: Op, xs: &[&str]) -> Out {
    match op {
        Op::CountDistinct => Out::Num(b_count_distinct(xs)),
        Op::AllSame => Out::Flag(b_all_same(xs)),
        Op::HasAdjacentDup => Out::Flag(b_has_adjacent_dup(xs)),
        Op::LastIndexOf => {
            if xs.is_empty() {
                Out::Num(-1)
            } else {
                Out::Num(b_last_index_of(xs, &xs[xs.len() / 2]))
            }
        }
        Op::SecondSmallestIndex => Out::Num(b_second_smallest_index(xs)),
    }
}

// ---- canonical lists ------------------------------------------------------

const CANONICAL_SEED: u64 = 0x9EA7_BA11;

const WORDS_POOL: [&str; 8] = ["ash", "birch", "cedar", "elm", "fir", "oak", "pine", "yew"];

/// The canonical pair of lists: sampled until the anchor facts hold.
///
/// The numeric list carries three-plus distinct values, a side-by-side
/// duplicate, a repeated middle entry whose final position clears the
/// leading index, and a second-smallest position clear of zero. The
/// word list stays non-degenerate (two-plus distinct values, never all
/// one word).
fn canonical(seed: u64) -> (Vec<i64>, Vec<&'static str>) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = 3 + rng.below(4);
        let nums: Vec<i64> = (0..n).map(|_| rng.below(7) as i64).collect();
        let wn = 2 + rng.below(4);
        let words: Vec<&'static str> = (0..wn)
            .map(|_| WORDS_POOL[rng.below(WORDS_POOL.len() as u64) as usize])
            .collect();
        if nums_anchors_hold(&nums) && words_anchors_hold(&words) {
            return (nums, words);
        }
    }
    unreachable!("canonical lists failed to satisfy anchors");
}

fn nums_anchors_hold(xs: &[i64]) -> bool {
    let mid = &xs[xs.len() / 2];
    b_count_distinct(xs) >= 3
        && !b_all_same(xs)
        && b_has_adjacent_dup(xs)
        && b_last_index_of(xs, mid) >= 1
        && b_second_smallest_index(xs) >= 1
}

fn words_anchors_hold(xs: &[&str]) -> bool {
    b_count_distinct(xs) >= 2 && !b_all_same(xs)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (Vec<i64>, Vec<&'static str>, Vec<(Op, Out, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0176;

fn case(spec: &Spec, nums: Vec<i64>, words: Vec<&'static str>) -> ExampleCase {
    let outs = spec
        .ops
        .map(|op| (op, eval_num(op, &nums), eval_word(op, &words)))
        .to_vec();
    (nums, words, outs)
}

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical pair first.
    let (can_n, can_w) = canonical(seed);
    cases.push(case(spec, can_n, can_w));
    // Empty lists pin the zero conventions on every op.
    cases.push(case(spec, Vec::new(), Vec::new()));
    // One shared value everywhere: all_same TRUE flips constant-false cheats.
    cases.push(case(spec, vec![7, 7, 7], vec!["oak", "oak", "oak"]));
    // Separated duplicates never sit side by side: adjacent-dup FALSE.
    cases.push(case(spec, vec![2, 9, 2], vec!["fir", "oak", "fir"]));
    // A strictly rising run: the runner-up sits at index one.
    cases.push(case(spec, vec![4, 8, 15], vec!["ash", "elm", "yew"]));
    for _ in 0..3 {
        let n = 1 + rng.below(6);
        let nums: Vec<i64> = (0..n).map(|_| rng.below(9) as i64).collect();
        let wn = 1 + rng.below(5);
        let words: Vec<&'static str> = (0..wn)
            .map(|_| WORDS_POOL[rng.below(WORDS_POOL.len() as u64) as usize])
            .collect();
        cases.push(case(spec, nums, words));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a numeric list; the first element types the slice.
fn render_nums(xs: &[i64]) -> String {
    if xs.is_empty() {
        return "&[]".to_string();
    }
    let mut parts = Vec::new();
    for (i, x) in xs.iter().enumerate() {
        if i == 0 {
            parts.push(format!("{x}i64"));
        } else {
            parts.push(x.to_string());
        }
    }
    format!("&[{}]", parts.join(", "))
}

/// Emitted literal for a word list.
fn render_words(xs: &[&str]) -> String {
    let items = xs
        .iter()
        .map(|w| format!("{w:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{items}]")
}

fn op_fn_src(op: Op) -> String {
    match op {
        Op::CountDistinct => format!(
            "pub fn {}<T: {}>(items: &[T]) -> {} {{\n    {}\n}}\n",
            op.name(),
            op.bound(),
            op.ret(),
            [
                "let mut seen = 0i64;",
                "for (i, x) in items.iter().enumerate() {",
                "    if !items[..i].contains(x) {",
                "        seen += 1;",
                "    }",
                "}",
                "seen",
            ]
            .join("\n    ")
        ),
        Op::AllSame => format!(
            "pub fn {}<T: {}>(items: &[T]) -> {} {{\n    {}\n}}\n",
            op.name(),
            op.bound(),
            op.ret(),
            [
                "match items.first() {",
                "    Some(first) => items.iter().all(|x| x == first),",
                "    None => false,",
                "}",
            ]
            .join("\n    ")
        ),
        Op::HasAdjacentDup => format!(
            "pub fn {}<T: {}>(items: &[T]) -> {} {{\n    {}\n}}\n",
            op.name(),
            op.bound(),
            op.ret(),
            ["items.windows(2).any(|pair| pair[0] == pair[1])"].join("\n    ")
        ),
        Op::LastIndexOf => format!(
            "pub fn {}<T: {}>(items: &[T], target: &T) -> {} {{\n    {}\n}}\n",
            op.name(),
            op.bound(),
            op.ret(),
            [
                "for (i, x) in items.iter().enumerate().rev() {",
                "    if x == target {",
                "        return i as i64;",
                "    }",
                "}",
                "-1",
            ]
            .join("\n    ")
        ),
        Op::SecondSmallestIndex => format!(
            "pub fn {}<T: {}>(items: &[T]) -> {} {{\n    {}\n}}\n",
            op.name(),
            op.bound(),
            op.ret(),
            [
                "if items.len() < 2 {",
                "    return -1;",
                "}",
                "let mut best = 0usize;",
                "for i in 1..items.len() {",
                "    if items[i] < items[best] {",
                "        best = i;",
                "    }",
                "}",
                "let mut runner: Option<usize> = None;",
                "for i in 0..items.len() {",
                "    if i == best {",
                "        continue;",
                "    }",
                "    runner = match runner {",
                "        None => Some(i),",
                "        Some(r) => {",
                "            if items[i] < items[r] {",
                "                Some(i)",
                "            } else {",
                "                Some(r)",
                "            }",
                "        }",
                "    };",
                "}",
                "runner.map(|r| r as i64).unwrap_or(-1)",
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
    format!(
        "pub fn {}<T: {}>(items: &[T]{}) -> {}",
        op.name(),
        op.bound(),
        op.extra_arg(),
        op.ret()
    )
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op against a bound list. The last-index
/// query targets the middle entry of that same list.
fn call_src(op: Op, var: &str) -> String {
    match op {
        Op::LastIndexOf => {
            format!("last_index_of({v}, &{v}[{v}.len() / 2])", v = var)
        }
        _ => format!("{}({})", op.name(), var),
    }
}
fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (nums, words, outs) in worked_examples(spec, seed) {
        let num_results = outs
            .iter()
            .map(|(op, on, _)| format!("{} = {}", op.name(), on.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        let word_results = outs
            .iter()
            .map(|(op, _, ow)| format!("{} = {}", op.name(), ow.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  nums {}  ->  {}\n  words {}  ->  {}\n",
            render_nums(&nums),
            num_results,
            render_words(&words),
            word_results
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
        "//! Implement the two query functions below. They must work for\n\
         //! ANY element type satisfying the bounds shown — the tests run\n\
         //! them on both numbers and words.\n\
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
        "Implement the two query functions in `src/lib.rs`. The input is a \
         slice of elements of some element type; your functions must be \
         generic over that type with exactly the bounds shown, and they \
         must work equally for integers and for word strings.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - Keep the exact signatures shown, including the bounds.\n\
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
    for (i, (nums, words, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let nums: &[i64] = {};\n    let words: &[&str] = {};\n",
            render_nums(nums),
            render_words(words),
        ));
        for (op, on, ow) in outs {
            // The middle-entry target does not exist for empty lists;
            // those conventions stay pinned by the other ops.
            if matches!(op, Op::LastIndexOf) && nums.is_empty() {
                continue;
            }
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "nums"),
                on.lit(),
            ));
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "words"),
                ow.lit(),
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the two selected ops, pasted into the test
/// file under `ref_*` names. Fuzzing runs on integers only; cross-type
/// generality is pinned by the dual-instantiation behaviour tests.
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
    let mut asserts = String::new();
    for op in spec.ops.iter() {
        if matches!(op, Op::LastIndexOf) {
            asserts.push_str(
                "        assert_eq!(last_index_of(&vals, &vals[vals.len() / 2]), ref_last_index_of(&vals, &vals[vals.len() / 2]));\n",
            );
        } else {
            let call = format!("{}(&vals)", op.name());
            asserts.push_str(&format!("        assert_eq!({call}, ref_{call});\n"));
        }
    }
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0176;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = (nx(&mut state) % 6) + 1;\n\
         \x20       let mut vals = Vec::new();\n\
         \x20       for _ in 0..n {{\n\
         \x20           vals.push((nx(&mut state) % 9) as i64);\n\
         \x20       }}\n\
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
                "bool" => "false",
                _ => "0",
            };
            let silence = match op {
                Op::LastIndexOf => "let _ = (items, target);",
                _ => "let _ = items;",
            };
            format!("{sig} {{\n    {silence}\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: behaviourally correct but hard-coded to `i64`.
/// The words instantiation of the behaviour tests does not COMPILE, so
/// this baseline scores zero on every pair — the same relationship the
/// allocation probe has with clone-happy answers in `borrow-fix`.
fn hardcoded_i64_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let name = op.name();
            let ret = op.ret();
            match op {
                Op::CountDistinct => format!(
                    "pub fn {name}(items: &[i64]) -> {ret} {{\n    {}\n}}\n",
                    [
                        "let mut seen = 0i64;",
                        "for (i, x) in items.iter().enumerate() {",
                        "    if !items[..i].contains(x) {",
                        "        seen += 1;",
                        "    }",
                        "}",
                        "seen",
                    ]
                    .join("\n    ")
                ),
                Op::AllSame => format!(
                    "pub fn {name}(items: &[i64]) -> {ret} {{\n    {}\n}}\n",
                    ["items.iter().all(|x| *x == items[0])"].join("\n    ")
                ),
                Op::HasAdjacentDup => format!(
                    "pub fn {name}(items: &[i64]) -> {ret} {{\n    {}\n}}\n",
                    ["items.windows(2).any(|pair| pair[0] == pair[1])"].join("\n    ")
                ),
                Op::LastIndexOf => format!(
                    "pub fn {name}(items: &[i64], target: &i64) -> {ret} {{\n    {}\n}}\n",
                    [
                        "for (i, x) in items.iter().enumerate().rev() {",
                        "    if x == target {",
                        "        return i as i64;",
                        "    }",
                        "}",
                        "-1",
                    ]
                    .join("\n    ")
                ),
                Op::SecondSmallestIndex => format!(
                    "pub fn {name}(items: &[i64]) -> {ret} {{\n    {}\n}}\n",
                    [
                        "if items.len() < 2 {",
                        "    return -1;",
                        "}",
                        "let mut best = 0usize;",
                        "for i in 1..items.len() {",
                        "    if items[i] < items[best] {",
                        "        best = i;",
                        "    }",
                        "}",
                        "let mut runner: Option<usize> = None;",
                        "for i in 0..items.len() {",
                        "    if i == best {",
                        "        continue;",
                        "    }",
                        "    runner = match runner {",
                        "        None => Some(i),",
                        "        Some(r) => {",
                        "            if items[i] < items[r] {",
                        "                Some(i)",
                        "            } else {",
                        "                Some(r)",
                        "            }",
                        "        }",
                        "    };",
                        "}",
                        "runner.map(|r| r as i64).unwrap_or(-1)",
                    ]
                    .join("\n    ")
                ),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct GenericBoundsFamily;

impl Generator for GenericBoundsFamily {
    fn id(&self) -> &str {
        "generic-bounds"
    }
    fn category(&self) -> &str {
        "trait-bounds"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("generic-bounds", seed);

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
            id: format!("generic-bounds/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure comparisons and index arithmetic — no unsafe anywhere.
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // Default oracle weights (docs/04).
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
            ("const-zero".to_string(), const_zero(&spec)),
            (
                "hardcoded-i64-everything".to_string(),
                hardcoded_i64_everything(&spec),
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
        let g = GenericBoundsFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Distinct counting collapses repeats wherever they sit.
        assert_eq!(b_count_distinct(&[3, 1, 3, 7, 7, 2]), 4);
        assert_eq!(b_count_distinct(&[9, 4, 9, 4, 9]), 2);
        assert_eq!(b_count_distinct::<i64>(&[]), 0);
        // All-same needs content.
        assert!(b_all_same(&[5, 5, 5]));
        assert!(!b_all_same(&[3, 3, 5, 3]));
        assert!(!b_all_same::<i64>(&[]));
        // Adjacent duplicates only count side by side.
        assert!(b_has_adjacent_dup(&[1, 2, 2, 3]));
        assert!(!b_has_adjacent_dup(&[2, 9, 2]));
        // Last occurrence wins; absent targets answer minus one.
        assert_eq!(b_last_index_of(&[6, 6, 6, 6], &6), 3);
        assert_eq!(b_last_index_of(&[4, 8, 15], &16), -1);
        // Runner-up: duplicate minima are legitimate candidates.
        assert_eq!(b_second_smallest_index(&[2, 2, 5]), 1);
        assert_eq!(b_second_smallest_index(&[9, 9]), 1);
        assert_eq!(b_second_smallest_index(&[5, 3]), 0);
        assert_eq!(b_second_smallest_index::<i64>(&[]), -1);
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
        // The canonical numeric list carries three-plus distinct values,
        // a side-by-side duplicate pair, a repeated middle entry whose
        // final position clears the leading index, and a runner-up
        // position clear of zero — so const-zero misses every scalar and
        // its all-same flag loses outright. Only the adjacent-duplicate
        // flag could coincide... no: the anchor forces it TRUE, killing
        // constant-false cheats directly. The word list stays
        // non-degenerate too.
        for seed in 0..200u64 {
            let (nums, words) = canonical(seed);
            let mid = &nums[nums.len() / 2];
            let cd = b_count_distinct(&nums);
            let li = b_last_index_of(&nums, mid);
            let ss = b_second_smallest_index(&nums);
            // Anchor facts the sampler enforces.
            assert!(cd >= 3, "seed {seed}: three-plus distinct values");
            assert!(!b_all_same(&nums), "seed {seed}: not uniform");
            assert!(b_has_adjacent_dup(&nums), "seed {seed}: adjacent pair");
            assert!(li >= 1, "seed {seed}: last hit clears index zero");
            assert!(ss >= 1, "seed {seed}: runner-up clears index zero");
            // const-zero survives nowhere on the scalars.
            assert_ne!(cd, 0, "const-zero survives at seed {seed}");
            assert_ne!(li, 0, "seed {seed}");
            assert_ne!(ss, 0, "seed {seed}");
            // The parallel word list stays non-degenerate.
            let wcd = b_count_distinct(&words);
            assert!(wcd >= 2, "seed {seed}: words keep two-plus values");
            assert!(!b_all_same(&words), "seed {seed}: words not uniform");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (nums, words, outs) in worked_examples(&spec, seed) {
                for (op, on, ow) in outs {
                    assert_eq!(eval_num(op, &nums), on, "seed {seed}");
                    assert_eq!(eval_word(op, &words), ow, "seed {seed}");
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
                // Generic signatures interpose `<` before any paren, so
                // match on `pub fn name<`.
                let fn_line = format!("pub fn {}<", op.name());
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
            // Solution-shaped leak tokens must stay out of the skeleton;
            // the worked examples legitimately show outputs, never
            // rules — so tokens carry implementation shapes. The bounds
            // themselves appear in the signature fence by design.
            assert!(!sk.contains(".contains("));
            assert!(!sk.contains(".windows("));
            assert!(!sk.contains("enumerate()"));
            assert!(!sk.contains("unwrap_or("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(".contains("));
            assert!(!p.contains(".windows("));
            assert!(!p.contains("enumerate()"));
            assert!(!p.contains("unwrap_or("));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Only the last-index query carries an extra target argument:
        // exactly one comma on both sides there, zero elsewhere.
        for op in OP_ALL {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call = call_src(op, "items");
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn hardcode_baseline_fails_the_words_instantiation() {
        // The catch mechanism, pinned structurally: the baseline is
        // typed `[i64]` throughout with no generics, so instantiating
        // it on words does not compile — while the reference keeps the
        // generic signatures intact.
        let src = hardcoded_i64_everything(&sample(0));
        assert!(src.contains("&[i64]"));
        assert!(!src.contains("<T:"));
        let rsrc = reference_src(&sample(0));
        assert!(rsrc.contains("<T:"));
        assert!(!rsrc.contains("&[i64]"));
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = GenericBoundsFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

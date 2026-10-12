//! `roman` — numeral-form queries over seeded integers in the classical
//! roman range (`1..=3999`).
//!
//! A task instance is one integer; the seed picks two of five query
//! operations over its classical roman numeral form. The model must
//! implement both exactly as specified and match a hidden reference on
//! thousands of random inputs.
//!
//! Category: `roman-numerals`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    /// The classical roman numeral form itself.
    ToRoman,
    /// How many symbols the roman form uses.
    NumSymbols,
    /// How many subtractive pairs appear in the form.
    SubtractivePairs,
    /// Face value of the largest symbol in the form.
    LargestSymbolValue,
    /// Face value of the smallest symbol in the form.
    SmallestSymbolValue,
}

const OP_ALL: [Op; 5] = [
    Op::ToRoman,
    Op::NumSymbols,
    Op::SubtractivePairs,
    Op::LargestSymbolValue,
    Op::SmallestSymbolValue,
];

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::ToRoman => "to_roman",
            Op::NumSymbols => "num_symbols",
            Op::SubtractivePairs => "subtractive_pairs",
            Op::LargestSymbolValue => "largest_symbol_value",
            Op::SmallestSymbolValue => "smallest_symbol_value",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::ToRoman => "String",
            _ => "i64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::ToRoman => "the classical roman numeral of the input, built greedily from thousands down to ones using the subtractive pairs only (four and nine styles) — valid for inputs one through 3999",
            Op::NumSymbols => "how many roman symbols the classical form uses in total",
            Op::SubtractivePairs => "how many distinct subtractive pairs (the four-style and nine-style combinations in each digit column) appear in the classical form",
            Op::LargestSymbolValue => "the face value of the highest-valued roman symbol appearing anywhere in the classical form",
            Op::SmallestSymbolValue => "the face value of the lowest-valued roman symbol appearing anywhere in the classical form",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Spec {
    ops: [Op; 2],
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let i = rng.below(OP_ALL.len() as u64) as usize;
    let mut j = rng.below(OP_ALL.len() as u64) as usize;
    while j == i {
        j = rng.below(OP_ALL.len() as u64) as usize;
    }
    Spec {
        ops: [OP_ALL[i], OP_ALL[j]],
    }
}
// ---------------------------------------------------------------------------
// Native mirrors of the emitted query bodies.
// ---------------------------------------------------------------------------

fn b_to_roman(n: u64) -> String {
    const THOUSANDS: [&str; 4] = ["", "M", "MM", "MMM"];
    const HUNDREDS: [&str; 10] = ["", "C", "CC", "CCC", "CD", "D", "DC", "DCC", "DCCC", "CM"];
    const TENS: [&str; 10] = ["", "X", "XX", "XXX", "XL", "L", "LX", "LXX", "LXXX", "XC"];
    const ONES: [&str; 10] = ["", "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX"];
    let n = n as usize;
    format!(
        "{}{}{}{}",
        THOUSANDS[n / 1000],
        HUNDREDS[(n % 1000) / 100],
        TENS[(n % 100) / 10],
        ONES[n % 10]
    )
}

fn b_num_symbols(n: u64) -> i64 {
    b_to_roman(n).chars().count() as i64
}

const SUBTRACTIVE_PAIRS: [&str; 6] = ["CM", "CD", "XC", "XL", "IX", "IV"];

fn b_subtractive_pairs(n: u64) -> i64 {
    let form = b_to_roman(n);
    let mut count = 0i64;
    for pair in SUBTRACTIVE_PAIRS {
        if form.contains(pair) {
            count += 1;
        }
    }
    count
}

const SYMBOL_VALUES_DESC: [(char, i64); 7] = [
    ('M', 1000),
    ('D', 500),
    ('C', 100),
    ('L', 50),
    ('X', 10),
    ('V', 5),
    ('I', 1),
];

fn b_largest_symbol_value(n: u64) -> i64 {
    let form = b_to_roman(n);
    for (sym, value) in SYMBOL_VALUES_DESC {
        if form.contains(sym) {
            return value;
        }
    }
    0
}

fn b_smallest_symbol_value(n: u64) -> i64 {
    let form = b_to_roman(n);
    let mut smallest = i64::MAX;
    for (sym, value) in SYMBOL_VALUES_DESC {
        if form.contains(sym) && value < smallest {
            smallest = value;
        }
    }
    if smallest == i64::MAX {
        0
    } else {
        smallest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Str(String),
}

impl Out {
    fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Str(s) => format!("{s:?}"),
        }
    }
}

fn op_eval(op: Op, n: u64) -> Out {
    match op {
        Op::ToRoman => Out::Str(b_to_roman(n)),
        Op::NumSymbols => Out::Num(b_num_symbols(n)),
        Op::SubtractivePairs => Out::Num(b_subtractive_pairs(n)),
        Op::LargestSymbolValue => Out::Num(b_largest_symbol_value(n)),
        Op::SmallestSymbolValue => Out::Num(b_smallest_symbol_value(n)),
    }
}

const CANONICAL_SEED: u64 = 0x4E0C_11A5;

/// The canonical input carries at least one subtractive pair and four
/// scalar answers that are pairwise distinct AND all different from the
/// input itself — so both the zero cheat and the echo-the-input cheat miss
/// on every query, with no exceptions to document.
fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let cand = rng.below(3999) + 1;
        if anchors_hold(cand) {
            return cand;
        }
    }
    unreachable!("roman canonical anchor search exhausted");
}

fn anchors_hold(n: u64) -> bool {
    if !(1..=3999).contains(&n) {
        return false;
    }
    let ns = b_num_symbols(n);
    let sp = b_subtractive_pairs(n);
    let ls = b_largest_symbol_value(n);
    let ss = b_smallest_symbol_value(n);
    if sp < 1 {
        return false;
    }
    let scalars = [ns, sp, ls, ss];
    for i in 0..scalars.len() {
        // No answer may equal the input itself (defeats echo cheats).
        if scalars[i] == n as i64 {
            return false;
        }
        for j in (i + 1)..scalars.len() {
            if scalars[i] == scalars[j] {
                return false;
            }
        }
    }
    true
}
// ---------------------------------------------------------------------------
// Worked examples, rendering, and emitted-source builders.
// ---------------------------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0x0000_1244;

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let can = canonical(seed);
    // Canonical first.
    let mut cases: Vec<ExampleCase> = vec![(
        can,
        OP_ALL.iter().map(|&op| (op, op_eval(op, can))).collect(),
    )];
    // The minimal input: single symbol, no subtractive pairs.
    cases.push((1, OP_ALL.iter().map(|&op| (op, op_eval(op, 1))).collect()));
    // The maximal input: widest form with three subtractive pairs.
    cases.push((
        3999,
        OP_ALL.iter().map(|&op| (op, op_eval(op, 3999))).collect(),
    ));
    // A classic: MCMXCIV.
    cases.push((
        1994,
        OP_ALL.iter().map(|&op| (op, op_eval(op, 1994))).collect(),
    ));
    for _ in 0..3 {
        let v = rng.below(3999) + 1;
        let outs = OP_ALL.iter().map(|&op| (op, op_eval(op, v))).collect();
        cases.push((v, outs));
    }
    cases
}

fn render_u64(n: u64) -> String {
    format!("{n}u64")
}

fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}

const ROMAN_TABLES_SRC: &str = r#"    const THOUSANDS: [&str; 4] = ["", "M", "MM", "MMM"];
    const HUNDREDS: [&str; 10] = [
        "", "C", "CC", "CCC", "CD", "D", "DC", "DCC", "DCCC", "CM",
    ];
    const TENS: [&str; 10] = [
        "", "X", "XX", "XXX", "XL", "L", "LX", "LXX", "LXXX", "XC",
    ];
    const ONES: [&str; 10] = [
        "", "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX",
    ];
"#;

fn to_roman_body_src() -> String {
    format!(
        "{}    let n = n as usize;\n    format!(\n        \"{{}}{{}}{{}}{{}}\",\n        THOUSANDS[n / 1000],\n        HUNDREDS[(n % 1000) / 100],\n        TENS[(n % 100) / 10],\n        ONES[n % 10]\n    )",
        ROMAN_TABLES_SRC
    )
}

fn form_src() -> &'static str {
    "let form = to_roman(n);"
}

fn pairs_table_src() -> &'static str {
    "const PAIRS: [&str; 6] = [\"CM\", \"CD\", \"XC\", \"XL\", \"IX\", \"IV\"];"
}

fn values_table_src() -> &'static str {
    "const VALUES: [(char, i64); 7] = [\n        ('M', 1000),\n        ('D', 500),\n        ('C', 100),\n        ('L', 50),\n        ('X', 10),\n        ('V', 5),\n        ('I', 1),\n    ];"
}

fn op_fn_src(op: Op) -> String {
    let body: String = match op {
        Op::ToRoman => to_roman_body_src(),
        Op::NumSymbols => ["to_roman(n).chars().count() as i64"].join("\n    "),
        Op::SubtractivePairs => [
            form_src(),
            pairs_table_src(),
            "let mut count = 0i64;",
            "for pair in PAIRS {",
            "    if form.contains(pair) {",
            "        count += 1;",
            "    }",
            "}",
            "count",
        ]
        .join("\n    "),
        Op::LargestSymbolValue => [
            form_src(),
            values_table_src(),
            "for (sym, value) in VALUES {",
            "    if form.contains(sym) {",
            "        return value;",
            "    }",
            "}",
            "0",
        ]
        .join("\n    "),
        Op::SmallestSymbolValue => [
            form_src(),
            values_table_src(),
            "let mut smallest = i64::MAX;",
            "for (sym, value) in VALUES {",
            "    if form.contains(sym) && value < smallest {",
            "        smallest = value;",
            "    }",
            "}",
            "if smallest == i64::MAX { 0 } else { smallest }",
        ]
        .join("\n    "),
    };
    format!(
        "pub fn {}(n: u64) -> {} {{\n    {}\n}}\n",
        op.name(),
        op.ret(),
        body
    )
}

fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(n: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(n: u64) -> {}", op.name(), op.ret())
}

fn reference_src() -> String {
    OP_ALL
        .iter()
        .map(|&op| op_fn_src(op))
        .collect::<Vec<_>>()
        .join("\n")
}
// ---------------------------------------------------------------------------
// Emitted task surfaces: examples prose, skeleton, prompt, manifest.
// ---------------------------------------------------------------------------

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (n, outs) in worked_examples(seed) {
        let results = outs
            .iter()
            .filter(|(op, _)| spec.ops.contains(op))
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  n {}  ->  {}\n", render_u64(n), results));
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
        "//! Implement the two query functions below.\n\
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
         given as `n`, one integer of type `u64` in the range one through \
         3999; queries are properties of its classical roman numeral form.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
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
// ---------------------------------------------------------------------------
// Hidden tests and trivial baselines.
// ---------------------------------------------------------------------------

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let imports = spec
        .ops
        .iter()
        .map(|op| op.name())
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!("use task::{{{imports}}};\n\n");
    for (i, (n, outs)) in worked_examples(seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let n = {};\n",
            render_u64(*n),
        ));
        for (op, out) in outs {
            if !spec.ops.contains(op) {
                continue;
            }
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "n"),
                out.lit(),
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the two selected ops, pasted into the test
/// file under `ref_*` names. The unrenamed remainder stays callable because
/// the scalar bodies build on `to_roman`.
fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src()
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
    let asserts = spec
        .ops
        .iter()
        .map(|op| {
            let call = call_src(*op, "n");
            format!("        assert_eq!({call}, ref_{call});\n")
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0126;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = (nx(&mut state) % 3999) + 1;\n\
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

/// Degenerate: everything zero (and an empty string on the form query).
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "String" => format!("{sig} {{\n    let _ = n;\n    String::new()\n}}\n"),
                _ => format!("{sig} {{\n    let _ = n;\n    0\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The echo cheat: answer with the input itself no matter what was asked.
/// The canonical anchors force every scalar answer away from the input and
/// keep the form a letter string, so this is exact nowhere on canonical.
fn value_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "String" => format!("{sig} {{\n    n.to_string()\n}}\n"),
                _ => format!("{sig} {{\n    n as i64\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct RomanFamily;

impl Generator for RomanFamily {
    fn id(&self) -> &str {
        "roman"
    }
    fn category(&self) -> &str {
        "roman-numerals"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("roman", seed);

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
            id: format!("roman/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure string/integer bookkeeping — no unsafe anywhere near it.
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // Default oracle weights (docs/04).
            weights: (0.70, 0.20, 0.10),
        }
    }

    fn reference_code(&self, _seed: u64) -> String {
        reference_src()
    }
    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(&sample(seed), seed)
    }
    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero(&spec)),
            ("value-everything".to_string(), value_everything(&spec)),
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
        let g = RomanFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        assert_eq!(b_to_roman(1994), "MCMXCIV");
        assert_eq!(b_num_symbols(1994), 7);
        assert_eq!(b_subtractive_pairs(1994), 3);
        assert_eq!(b_largest_symbol_value(1994), 1000);
        assert_eq!(b_smallest_symbol_value(1994), 1);
        // No subtractive pairs anywhere.
        assert_eq!(b_subtractive_pairs(3888), 0);
        assert_eq!(b_num_symbols(3888), 15);
        // Nine-style pair carries X and I.
        assert_eq!(b_largest_symbol_value(9), 10);
        assert_eq!(b_smallest_symbol_value(9), 1);
        // Forty has no ones column at all.
        assert_eq!(b_to_roman(40), "XL");
        assert_eq!(b_smallest_symbol_value(40), 10);
        assert_eq!(b_num_symbols(1), 1);
        assert_eq!(b_num_symbols(3999), 9);
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
            let n = canonical(seed);
            assert!(anchors_hold(n), "seed {seed}: canonical anchors violated");
            let form = b_to_roman(n);
            let answers = [
                b_num_symbols(n),
                b_subtractive_pairs(n),
                b_largest_symbol_value(n),
                b_smallest_symbol_value(n),
            ];
            // const-zero: every scalar nonzero, the form nonempty.
            for v in answers {
                assert_ne!(v, 0, "seed {seed}");
            }
            assert!(!form.is_empty(), "seed {seed}");
            // value-everything: no scalar equals the input, and the form
            // never looks like a decimal echo.
            for v in answers {
                assert_ne!(v, n as i64, "seed {seed}");
            }
            assert_ne!(form, n.to_string(), "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for (n, outs) in worked_examples(seed) {
                for (op, out) in outs {
                    assert_eq!(&out, &op_eval(op, n), "seed {seed} op {}", op.name());
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        let g = RomanFamily;
        for seed in 0..50u64 {
            let reference = g.reference_code(seed);
            for op in sample(seed).ops {
                let marker = format!("pub fn {}(", op.name());
                assert_eq!(
                    reference.lines().filter(|l| l.starts_with(&marker)).count(),
                    1,
                    "seed {seed} op {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        let g = RomanFamily;
        for seed in 0..50u64 {
            let sk = g.skeleton_code(seed);
            let task = g.generate(seed);
            for leak in ["contains(", "\"CM\",", ".chars()", "PAIRS"] {
                assert!(!sk.contains(leak), "skeleton leaks {leak}");
                assert!(!task.prompt.contains(leak), "prompt leaks {leak}");
            }
            assert_eq!(sk.matches("todo!()").count(), 2);
            for op in sample(seed).ops {
                assert!(
                    task.prompt.contains(&op_sig_src(op)),
                    "prompt missing signature for {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for _seed in 0..50u64 {
            for op in OP_ALL {
                let call = call_src(op, "n");
                let sig = op_sig_src(op);
                assert_eq!(
                    call.matches(',').count(),
                    sig.matches(',').count(),
                    "op {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = RomanFamily;
        let task = g.generate(7);
        assert!(task.prompt.contains(&task.canary));
    }
}

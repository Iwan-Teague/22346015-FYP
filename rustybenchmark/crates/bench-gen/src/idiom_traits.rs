//! The `idiom-traits` family (category `idiom-refactor`) — the sixth idiom-refactor family, on two
//! more lints `cargo clippy --fix` cannot apply: **`clippy::inherent_to_string`** and
//! **`clippy::non_canonical_partial_ord_impl`**.
//!
//! The model is given a small type that implements a std trait *the wrong way* and must make it
//! idiomatic, clippy-clean, with behaviour as the prompt states it:
//!
//! * **ToString** — `impl Temp { pub fn to_string(&self) -> String }`: an inherent method that
//!   should be `impl fmt::Display`. The hidden tests format with `{}` and pass the type to a
//!   `T: Display` function, so an inherent method alone does not build.
//! * **Ord** — a custom `Ord::cmp` with a `PartialOrd::partial_cmp` that does *not* forward to it
//!   (it compares one field only). That is a latent bug as well as a lint: `a < b` disagrees with
//!   `a.cmp(&b)`. The idiomatic fix is `Some(self.cmp(other))`; the prompt states that `cmp` is the
//!   truth and the tests check `<`, `>`, `partial_cmp`, `max` and `sort` all agree with it.
//!
//! **Q14, measured.** In a scratch crate against the installed clippy (1.97), `cargo clippy --fix`
//! left both lints unchanged. (It *did* rewrite `impl Into<B> for A` into `impl From<A> for B`, so
//! `from_over_into` is not used here; `too_many_arguments`, `large_enum_variant` and
//! `result_unit_err` also survive `--fix` but change the API in ways a prompt cannot pin, so they
//! are left for a later family.)
//!
//! Seed-selected on: **which defects are present** (ToString only, Ord only, or both), the
//! **display format** (3) and the **ordering** (4: lexicographic, major-descending, minor-first,
//! by sum). 3 + 4 + 3x4 = **19 distinct skills**. `allow` is a forbidden path.
//! Constraint-dominant per docs/04 (behaviour 0.30 / constraint 0.60 / quality 0.10).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fmt {
    Celsius,
    Bracket,
    Deg,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Order {
    Lex,
    MajorDesc,
    MinorFirst,
    BySum,
}

struct Spec {
    fmt: Option<Fmt>,
    order: Option<Order>,
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    // 19 equally likely skills: 3 (fmt only) + 4 (order only) + 12 (both).
    let n = rng.below(19);
    let f = |i: u64| match i % 3 {
        0 => Fmt::Celsius,
        1 => Fmt::Bracket,
        _ => Fmt::Deg,
    };
    let o = |i: u64| match i % 4 {
        0 => Order::Lex,
        1 => Order::MajorDesc,
        2 => Order::MinorFirst,
        _ => Order::BySum,
    };
    match n {
        0..=2 => Spec {
            fmt: Some(f(n)),
            order: None,
        },
        3..=6 => Spec {
            fmt: None,
            order: Some(o(n - 3)),
        },
        _ => Spec {
            fmt: Some(f((n - 7) / 4)),
            order: Some(o((n - 7) % 4)),
        },
    }
}

// ---- native reference ---------------------------------------------------------------

fn render(fmt: Fmt, n: i64) -> String {
    match fmt {
        Fmt::Celsius => format!("{n}C"),
        Fmt::Bracket => format!("[{n}]"),
        Fmt::Deg => format!("{n} deg"),
    }
}

fn cmp(order: Order, a: (i64, i64), b: (i64, i64)) -> Ordering {
    let (am, an) = a;
    let (bm, bn) = b;
    match order {
        Order::Lex => am.cmp(&bm).then(an.cmp(&bn)),
        Order::MajorDesc => bm.cmp(&am).then(an.cmp(&bn)),
        Order::MinorFirst => an.cmp(&bn).then(am.cmp(&bm)),
        Order::BySum => (am + an).cmp(&(bm + bn)).then(am.cmp(&bm)),
    }
}

// ---- emitted source -------------------------------------------------------------------

fn fmt_args(fmt: Fmt) -> &'static str {
    match fmt {
        Fmt::Celsius => "\"{}C\"",
        Fmt::Bracket => "\"[{}]\"",
        Fmt::Deg => "\"{} deg\"",
    }
}

fn cmp_body(order: Order) -> &'static str {
    match order {
        Order::Lex => "self.major.cmp(&other.major).then(self.minor.cmp(&other.minor))",
        Order::MajorDesc => "other.major.cmp(&self.major).then(self.minor.cmp(&other.minor))",
        Order::MinorFirst => "self.minor.cmp(&other.minor).then(self.major.cmp(&other.major))",
        Order::BySum => {
            "(self.major + self.minor)\n            .cmp(&(other.major + other.minor))\n            .then(self.major.cmp(&other.major))"
        }
    }
}

fn uses(spec: &Spec, idiomatic: bool) -> String {
    let mut s = String::new();
    if spec.order.is_some() {
        s.push_str("use std::cmp::Ordering;\n");
    }
    if spec.fmt.is_some() && idiomatic {
        s.push_str("use std::fmt;\n");
    }
    if !s.is_empty() {
        s.push('\n');
    }
    s
}

fn temp_src(fmt: Fmt, idiomatic: bool) -> String {
    if idiomatic {
        format!(
            "pub struct Temp(pub i64);\n\
             \n\
             impl fmt::Display for Temp {{\n\
             \x20   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {{\n\
             \x20       write!(f, {}, self.0)\n\
             \x20   }}\n\
             }}\n",
            fmt_args(fmt)
        )
    } else {
        format!(
            "pub struct Temp(pub i64);\n\
             \n\
             impl Temp {{\n\
             \x20   pub fn to_string(&self) -> String {{\n\
             \x20       format!({}, self.0)\n\
             \x20   }}\n\
             }}\n",
            fmt_args(fmt)
        )
    }
}

fn rank_src(order: Order, idiomatic: bool) -> String {
    let partial = if idiomatic {
        "Some(self.cmp(other))"
    } else {
        // Compares one field only: disagrees with `cmp` whenever the majors tie or the order is
        // not major-ascending.
        "self.major.partial_cmp(&other.major)"
    };
    format!(
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub struct Rank {{\n\
         \x20   pub major: i64,\n\
         \x20   pub minor: i64,\n\
         }}\n\
         \n\
         impl Ord for Rank {{\n\
         \x20   fn cmp(&self, other: &Self) -> Ordering {{\n\
         \x20       {}\n\
         \x20   }}\n\
         }}\n\
         \n\
         impl PartialOrd for Rank {{\n\
         \x20   fn partial_cmp(&self, other: &Self) -> Option<Ordering> {{\n\
         \x20       {partial}\n\
         \x20   }}\n\
         }}\n",
        cmp_body(order)
    )
}

fn src(spec: &Spec, idiomatic: bool) -> String {
    let mut parts = Vec::new();
    if let Some(f) = spec.fmt {
        parts.push(temp_src(f, idiomatic));
    }
    if let Some(o) = spec.order {
        parts.push(rank_src(o, idiomatic));
    }
    format!("{}{}", uses(spec, idiomatic), parts.join("\n"))
}

fn given_src(spec: &Spec) -> String {
    src(spec, false)
}

fn reference_src(spec: &Spec) -> String {
    src(spec, true)
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Make the trait implementations idiomatic and clippy-clean.\n\
         //!\n\
         {doc}\n\
         {}",
        given_src(spec)
    )
}

// ---- worked examples ----------------------------------------------------------------------

fn pairs(seed: u64) -> Vec<((i64, i64), (i64, i64))> {
    let mut rng = Rng::new(seed ^ 0x1D70_0000_0000_0A55);
    // Canonical: same major (exposes the one-field comparison), and one with differing majors
    // whose order depends on the ordering variant.
    let mut v = vec![((2, 5), (2, 3)), ((1, 9), (3, 0))];
    for _ in 0..8 {
        let mut p = || (rng.below(81) as i64 - 40, rng.below(81) as i64 - 40);
        v.push((p(), p()));
    }
    v
}

fn temps(seed: u64) -> Vec<i64> {
    let mut rng = Rng::new(seed ^ 0x1D71_0000_0000_0A56);
    {
        let mut v = vec![21, -4];
        v.extend((0..6).map(|_| rng.below(400) as i64 - 150));
        v
    }
}

fn ord_word(o: Ordering) -> &'static str {
    match o {
        Ordering::Less => "Less",
        Ordering::Equal => "Equal",
        Ordering::Greater => "Greater",
    }
}

fn worked_examples(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    if let Some(f) = spec.fmt {
        for n in temps(seed).iter().take(6) {
            s.push_str(&format!(
                "  format!(\"{{}}\", Temp({n}))  ->  {:?}\n",
                render(f, *n)
            ));
        }
    }
    if let Some(o) = spec.order {
        for (a, b) in pairs(seed).iter().take(6) {
            s.push_str(&format!(
                "  Rank {{ major: {}, minor: {} }}.cmp(&Rank {{ major: {}, minor: {} }})  ->  {}\n",
                a.0,
                a.1,
                b.0,
                b.1,
                ord_word(cmp(o, *a, *b))
            ));
        }
    }
    s
}

fn order_prose(o: Order) -> &'static str {
    match o {
        Order::Lex => "by `major`, then by `minor`, both ascending",
        Order::MajorDesc => "by `major` **descending**, then by `minor` ascending",
        Order::MinorFirst => "by `minor` ascending, then by `major` ascending",
        Order::BySum => "by `major + minor` ascending, then by `major` ascending",
    }
}

fn defects_prose(spec: &Spec) -> String {
    let mut v = Vec::new();
    if spec.fmt.is_some() {
        v.push(
            "`Temp` has an inherent `to_string` method that should be a `Display` impl (clippy: `inherent_to_string`)"
                .to_string(),
        );
    }
    if let Some(o) = spec.order {
        v.push(format!(
            "`Rank`'s `PartialOrd::partial_cmp` does not agree with its `Ord::cmp` (clippy: `non_canonical_partial_ord_impl`). `cmp` is the truth: it orders {}, and `<`, `>`, `partial_cmp`, `max`, `min` and `sort` must all agree with it",
            order_prose(o)
        ));
    }
    v.join("; and ")
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let fmt_note = spec.fmt.map_or(String::new(), |f| {
        format!(
            " `Temp`'s text form is exactly `{}` for `Temp(21)`.",
            render(f, 21)
        )
    });
    format!(
        "The types in `src/lib.rs` work, but implement standard traits the non-idiomatic way: {defects}.{fmt_note} \
         Make them idiomatic and `clippy`-clean.\n\
         \n\
         Here is the current code:\n\
         \n\
         ```rust\n\
         {current}\n\
         ```\n\
         \n\
         Examples of the behaviour that must hold:\n\
         {examples}\n\
         Constraints:\n\
         - The rewrite must produce **no** `clippy` warnings and must not hide them with `#[allow(..)]`: \
         the checks format with `{{}}`, pass `Temp` to a `T: Display` function and compare `Rank`s \
         with the operators, so a lint that is silenced instead of fixed will not build or will \
         disagree.\n\
         - Keep the type and field names and the derives. Do not use `unsafe`.\n\
         \n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        defects = defects_prose(spec),
        current = given_src(spec).trim_end(),
        examples = worked_examples(spec, seed),
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

fn imports(spec: &Spec) -> String {
    let mut names = Vec::new();
    if spec.fmt.is_some() {
        names.push("Temp");
    }
    if spec.order.is_some() {
        names.push("Rank");
    }
    let ord = if spec.order.is_some() {
        "use std::cmp::Ordering;\n"
    } else {
        ""
    };
    format!("{ord}use task::{{{}}};\n", names.join(", "))
}

fn rank_lit(r: (i64, i64)) -> String {
    format!("Rank {{ major: {}, minor: {} }}", r.0, r.1)
}

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let mut body = format!("{}\n", imports(spec));
    if spec.fmt.is_some() {
        body.push_str(
            "fn show<T: std::fmt::Display>(t: &T) -> String {\n    format!(\"{t}\")\n}\n\n",
        );
    }
    if let Some(f) = spec.fmt {
        for (i, n) in temps(seed).iter().enumerate() {
            body.push_str(&format!(
                "#[test]\nfn temp{i}() {{\n    let t = Temp({n});\n    assert_eq!(format!(\"{{}}\", t), {want:?});\n    assert_eq!(show(&t), {want:?});\n    assert_eq!(t.to_string(), {want:?});\n}}\n\n",
                want = render(f, *n)
            ));
        }
    }
    if let Some(o) = spec.order {
        for (i, (a, b)) in pairs(seed).iter().enumerate() {
            let want = cmp(o, *a, *b);
            let (la, lb) = (rank_lit(*a), rank_lit(*b));
            body.push_str(&format!(
                "#[test]\nfn rank{i}() {{\n    let (a, b) = ({la}, {lb});\n    assert_eq!(a.cmp(&b), Ordering::{want:?});\n    assert_eq!(a.partial_cmp(&b), Some(Ordering::{want:?}));\n    assert_eq!(a < b, {lt});\n    assert_eq!(a > b, {gt});\n    assert_eq!(a <= b, {le});\n    assert_eq!(std::cmp::max(a, b), {mx});\n}}\n\n",
                lt = want == Ordering::Less,
                gt = want == Ordering::Greater,
                le = want != Ordering::Greater,
                mx = if want == Ordering::Less { lb.clone() } else { la.clone() },
            ));
        }
        // `sort` (Ord) and `sort_by(partial_cmp)` must give the same order.
        let mut v: Vec<(i64, i64)> = pairs(seed).iter().flat_map(|(a, b)| [*a, *b]).collect();
        let lits = v
            .iter()
            .map(|r| rank_lit(*r))
            .collect::<Vec<_>>()
            .join(", ");
        v.sort_by(|a, b| cmp(o, *a, *b));
        let sorted = v
            .iter()
            .map(|r| rank_lit(*r))
            .collect::<Vec<_>>()
            .join(", ");
        body.push_str(&format!(
            "#[test]\nfn sorting_agrees_with_cmp() {{\n    let mut by_ord = vec![{lits}];\n    let mut by_partial = by_ord.clone();\n    by_ord.sort();\n    by_partial.sort_by(|a, b| a.partial_cmp(b).unwrap());\n    assert_eq!(by_ord, vec![{sorted}]);\n    assert_eq!(by_partial, by_ord);\n}}\n"
        ));
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    let mut checks = String::new();
    if spec.fmt.is_some() {
        checks.push_str(
            "        let n = (next() % 201) as i64 - 100;\n        assert_eq!(format!(\"{}\", task::Temp(n)), format!(\"{}\", reference::Temp(n)));\n",
        );
    }
    if spec.order.is_some() {
        checks.push_str(
            "        let (a, b) = ((next() % 9) as i64 - 4, (next() % 9) as i64 - 4);\n        let (c, d) = ((next() % 9) as i64 - 4, (next() % 9) as i64 - 4);\n        let (ta, tb) = (task::Rank { major: a, minor: b }, task::Rank { major: c, minor: d });\n        let (ra, rb) = (reference::Rank { major: a, minor: b }, reference::Rank { major: c, minor: d });\n        assert_eq!(ta.cmp(&tb), ra.cmp(&rb), \"cmp {a},{b} {c},{d}\");\n        assert_eq!(ta.partial_cmp(&tb), ra.partial_cmp(&rb), \"partial_cmp {a},{b} {c},{d}\");\n        assert_eq!(ta < tb, ra < rb);\n        assert_eq!(ta >= tb, ra >= rb);\n",
        );
    }
    format!(
        "mod reference {{\n{indented}}}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x1D70_ED00_0000_004D;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         {checks}\
         \x20   }}\n\
         }}\n"
    )
}

fn unchanged(spec: &Spec) -> String {
    given_src(spec)
}

fn allow_attrs(spec: &Spec) -> String {
    format!(
        "#![allow(clippy::inherent_to_string, clippy::non_canonical_partial_ord_impl)]\n{}",
        given_src(spec)
    )
}

pub struct IdiomTraitsFamily;

impl Generator for IdiomTraitsFamily {
    fn id(&self) -> &str {
        "idiom-traits"
    }
    fn category(&self) -> &str {
        "idiom-refactor"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("idiom-traits", seed);

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
            id: format!("idiom-traits/{seed:016x}"),
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
        skeleton_src(&sample(seed), seed)
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
        let fmt = match spec.fmt {
            None => "none",
            Some(Fmt::Celsius) => "celsius",
            Some(Fmt::Bracket) => "bracket",
            Some(Fmt::Deg) => "deg",
        };
        let order = match spec.order {
            None => "none",
            Some(Order::Lex) => "lex",
            Some(Order::MajorDesc) => "major_desc",
            Some(Order::MinorFirst) => "minor_first",
            Some(Order::BySum) => "by_sum",
        };
        vec![format!("fmt:{fmt}"), format!("order:{order}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = IdiomTraitsFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn every_spec_has_a_defect_and_all_19_appear() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..600u64 {
            let s = sample(seed);
            assert!(s.fmt.is_some() || s.order.is_some(), "seed {seed}");
            seen.insert(IdiomTraitsFamily.spec_signature(seed).join("|"));
        }
        assert_eq!(seen.len(), 19);
    }

    #[test]
    fn native_orderings_match_intent() {
        let (a, b) = ((2, 5), (2, 3));
        assert_eq!(cmp(Order::Lex, a, b), Ordering::Greater);
        assert_eq!(cmp(Order::MajorDesc, (1, 9), (3, 0)), Ordering::Greater);
        assert_eq!(cmp(Order::MinorFirst, (1, 9), (3, 0)), Ordering::Greater);
        assert_eq!(cmp(Order::BySum, (1, 9), (3, 3)), Ordering::Greater);
        assert_eq!(
            cmp(Order::BySum, (4, 1), (1, 4)),
            Ordering::Greater,
            "tie on sum: major decides"
        );
    }

    #[test]
    fn the_given_partial_cmp_really_disagrees_with_cmp_on_the_canonical_pairs() {
        // The given code's partial_cmp compares `major` only. For every ordering the canonical
        // pairs must expose that, or the Ord defect would not be test-visible.
        for o in [
            Order::Lex,
            Order::MajorDesc,
            Order::MinorFirst,
            Order::BySum,
        ] {
            let exposed = [((2, 5), (2, 3)), ((1, 9), (3, 0))]
                .iter()
                .any(|&(a, b)| a.0.partial_cmp(&b.0) != Some(cmp(o, a, b)));
            assert!(
                exposed,
                "{o:?}: major-only partial_cmp passes both canonical pairs"
            );
        }
    }

    #[test]
    fn given_and_reference_differ_exactly_where_the_defects_are() {
        for seed in 0..100u64 {
            let s = sample(seed);
            let (g, r) = (given_src(&s), reference_src(&s));
            assert_eq!(
                g.contains("pub fn to_string"),
                s.fmt.is_some(),
                "seed {seed}"
            );
            assert!(!r.contains("pub fn to_string"), "seed {seed}");
            assert_eq!(r.contains("impl fmt::Display"), s.fmt.is_some());
            assert_eq!(g.contains("self.major.partial_cmp"), s.order.is_some());
            assert_eq!(r.contains("Some(self.cmp(other))"), s.order.is_some());
        }
    }

    #[test]
    fn the_hidden_tests_use_display_and_the_operators() {
        for seed in 0..60u64 {
            let s = sample(seed);
            let t = IdiomTraitsFamily.generate(seed);
            let b = &t.hidden[&PathBuf::from("tests/behavior.rs")];
            if s.fmt.is_some() {
                assert!(b.contains("T: std::fmt::Display") && b.contains("format!(\"{}\", t)"));
            }
            if s.order.is_some() {
                assert!(b.contains("a < b") && b.contains("partial_cmp") && b.contains("sort_by"));
            }
        }
    }

    #[test]
    fn allow_is_forbidden_and_canary_present() {
        let t = IdiomTraitsFamily.generate(3);
        assert_eq!(t.forbidden_paths, vec!["allow".to_string()]);
        assert!(t.prompt.contains(&t.canary));
    }
}

//! The `unit-generic` family (category `traits-generics`) — **associated consts** and a
//! generic function that reads them through its type parameters.
//!
//! The other `traits-generics` families implement a trait with an associated *type*
//! (`trait-impl`), write a generic function over a trait's *methods* (`generic-select`), implement
//! std operator traits (`ops-overload`) or write a blanket impl (`blanket-impl`). This one is the
//! const-flavoured corner: a pinned `trait Unit { const FACTOR: i64; const SUFFIX: &'static str; }`
//! and three pinned unit structs. The model writes the three `impl Unit` blocks from a table in the
//! prompt, then **one generic function** that uses `A::FACTOR` / `B::SUFFIX` with no value of the
//! type in sight (`convert::<Km, M>(3)`), or — in the by-value style — takes marker values
//! (`convert(Km, M, 3)`).
//!
//! Seed-selected on two axes:
//!
//! 1. **Function** — `convert` (`v * A / B`), `label` (`"{v}{A::SUFFIX}"`), `larger` (the suffix of
//!    the bigger unit; ties go to the first), `total` (`a*A + b*B` in base units), `leftover`
//!    (`(v*A) % B`), `fits` (does `v` of `A` make a whole number of `B`).
//! 2. **Style** — type-level (`f::<A, B>(..)`, no value of the unit type) or by-value
//!    (`f(A, B, ..)`).
//!
//! 6 x 2 = **12 distinct skills**; the unit names, suffixes, factors and function name are cosmetic
//! and excluded from `spec_signature` (Q31). Getting a const or a bound wrong makes the hidden
//! tests fail to build (0.0), the `trait-impl` mechanism. Solution-first (ADR-0003): the native
//! functions and the emitted ones are mirrored, and the differential compares every ordered pair
//! of the three units (including a unit with itself) against an inlined reference module.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Func {
    Convert,
    Label,
    Larger,
    Total,
    Leftover,
    Fits,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Style {
    TypeLevel,
    ByValue,
}

/// One row of the unit table.
#[derive(Clone, Copy)]
struct Unit {
    name: &'static str,
    factor: i64,
    suffix: &'static str,
}

struct Spec {
    func: Func,
    style: Style,
    units: [Unit; 3],
}

const NAME_SETS: &[([&str; 3], [&str; 3])] = &[
    (["Tiny", "Mid", "Big"], ["mm", "cm", "m"]),
    (["Bit", "Byte", "Block"], ["b", "kb", "mb"]),
    (["Tick", "Beat", "Bar"], ["t", "bt", "br"]),
    (["Pinch", "Spoon", "Cup"], ["pn", "sp", "cp"]),
];
const FACTORS: &[i64] = &[1, 2, 3, 4, 5, 6, 8, 10, 12, 16, 24, 60, 100];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let func = match rng.below(6) {
        0 => Func::Convert,
        1 => Func::Label,
        2 => Func::Larger,
        3 => Func::Total,
        4 => Func::Leftover,
        _ => Func::Fits,
    };
    let style = if rng.below(2) == 0 {
        Style::TypeLevel
    } else {
        Style::ByValue
    };
    let (names, suffixes) = NAME_SETS[rng.below(NAME_SETS.len() as u64) as usize];
    // Three distinct factors, ascending.
    let mut idx: Vec<usize> = Vec::new();
    while idx.len() < 3 {
        let i = rng.below(FACTORS.len() as u64) as usize;
        if !idx.contains(&i) {
            idx.push(i);
        }
    }
    let mut fs: Vec<i64> = idx.iter().map(|&i| FACTORS[i]).collect();
    fs.sort();
    let units = [0, 1, 2].map(|k| Unit {
        name: names[k],
        factor: fs[k],
        suffix: suffixes[k],
    });
    Spec { func, style, units }
}

fn fn_name(func: Func) -> &'static str {
    match func {
        Func::Convert => "convert",
        Func::Label => "label",
        Func::Larger => "larger",
        Func::Total => "total",
        Func::Leftover => "leftover",
        Func::Fits => "fits",
    }
}

// ---- native reference -------------------------------------------------------------

/// The result of one call, rendered as a Rust literal.
fn native(func: Func, a: Unit, b: Unit, x: i64, y: i64) -> String {
    match func {
        Func::Convert => (x * a.factor / b.factor).to_string(),
        Func::Label => format!("{:?}", format!("{x}{}", a.suffix)),
        Func::Larger => format!(
            "{:?}",
            if b.factor > a.factor {
                b.suffix
            } else {
                a.suffix
            }
        ),
        Func::Total => (x * a.factor + y * b.factor).to_string(),
        Func::Leftover => ((x * a.factor) % b.factor).to_string(),
        Func::Fits => ((x * a.factor) % b.factor == 0).to_string(),
    }
}

// ---- emitted source ---------------------------------------------------------------

fn trait_and_types(spec: &Spec) -> String {
    let mut s = String::from(
        "pub trait Unit {\n    const FACTOR: i64;\n    const SUFFIX: &'static str;\n}\n\n",
    );
    for u in &spec.units {
        s.push_str(&format!("pub struct {};\n", u.name));
    }
    s
}

fn impls_src(spec: &Spec, factor_override: Option<i64>, blank_suffix: bool) -> String {
    spec.units
        .iter()
        .map(|u| {
            format!(
                "impl Unit for {} {{\n    const FACTOR: i64 = {};\n    const SUFFIX: &'static str = {:?};\n}}\n",
                u.name,
                factor_override.unwrap_or(u.factor),
                if blank_suffix { "" } else { u.suffix },
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parameters of the generic function (after the type parameters).
fn params(spec: &Spec) -> String {
    let by_value = spec.style == Style::ByValue;
    match spec.func {
        Func::Convert | Func::Leftover | Func::Fits => {
            if by_value {
                "_from: A, _to: B, v: i64".to_string()
            } else {
                "v: i64".to_string()
            }
        }
        Func::Label => {
            if by_value {
                "_unit: A, v: i64".to_string()
            } else {
                "v: i64".to_string()
            }
        }
        Func::Larger => {
            if by_value {
                "_a: A, _b: B".to_string()
            } else {
                String::new()
            }
        }
        Func::Total => {
            if by_value {
                "_a: A, _b: B, x: i64, y: i64".to_string()
            } else {
                "x: i64, y: i64".to_string()
            }
        }
    }
}

fn generics(func: Func) -> &'static str {
    match func {
        Func::Label => "<A: Unit>",
        _ => "<A: Unit, B: Unit>",
    }
}

fn ret_ty(func: Func) -> &'static str {
    match func {
        Func::Label => "String",
        Func::Larger => "&'static str",
        Func::Fits => "bool",
        _ => "i64",
    }
}

fn body(func: Func) -> &'static str {
    match func {
        Func::Convert => "v * A::FACTOR / B::FACTOR",
        Func::Label => "format!(\"{}{}\", v, A::SUFFIX)",
        Func::Larger => {
            "if B::FACTOR > A::FACTOR {\n        B::SUFFIX\n    } else {\n        A::SUFFIX\n    }"
        }
        Func::Total => "x * A::FACTOR + y * B::FACTOR",
        Func::Leftover => "(v * A::FACTOR) % B::FACTOR",
        Func::Fits => "(v * A::FACTOR) % B::FACTOR == 0",
    }
}

fn fn_src(spec: &Spec, with_body: Option<&str>) -> String {
    let inner = with_body.unwrap_or(body(spec.func));
    format!(
        "pub fn {name}{g}({p}) -> {r} {{\n    {inner}\n}}\n",
        name = fn_name(spec.func),
        g = generics(spec.func),
        p = params(spec),
        r = ret_ty(spec.func),
    )
}

fn reference_src(spec: &Spec) -> String {
    format!(
        "{}\n{}\n{}",
        trait_and_types(spec),
        impls_src(spec, None, false),
        fn_src(spec, None)
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .1
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Implement `Unit` for the three units and the generic `{name}` below. The trait and\n\
         //! the unit types are provided — keep them.\n\
         //!\n\
         {doc}\n\
         {types}\n\
         {sig}",
        name = fn_name(spec.func),
        types = trait_and_types(spec),
        sig = fn_src(spec, Some("todo!()")),
    )
}

// ---- worked examples --------------------------------------------------------------

/// A call: which two units (indices) and the numeric arguments.
#[derive(Clone, Copy)]
struct Call {
    a: usize,
    b: usize,
    x: i64,
    y: i64,
}

/// Source of one call. Type-level: `convert::<A, B>(v)`; by-value: `convert(A, B, v)`.
fn call_src(spec: &Spec, c: Call) -> String {
    let (a, b) = (spec.units[c.a].name, spec.units[c.b].name);
    let name = fn_name(spec.func);
    let (tys, vals): (String, String) = match spec.func {
        Func::Label => (format!("<{a}>"), a.to_string()),
        _ => (format!("<{a}, {b}>"), format!("{a}, {b}")),
    };
    let nums = match spec.func {
        Func::Convert | Func::Leftover | Func::Fits => format!("{}", c.x),
        Func::Label => format!("{}", c.x),
        Func::Larger => String::new(),
        Func::Total => format!("{}, {}", c.x, c.y),
    };
    match spec.style {
        Style::TypeLevel => format!("{name}::{tys}({nums})"),
        Style::ByValue => {
            if nums.is_empty() {
                format!("{name}({vals})")
            } else {
                format!("{name}({vals}, {nums})")
            }
        }
    }
}

fn result_of(spec: &Spec, c: Call) -> String {
    native(spec.func, spec.units[c.a], spec.units[c.b], c.x, c.y)
}

/// The canonical calls: every ordered pair of distinct units (6) plus a unit with itself, with
/// arguments that make every pair's result differ from the all-ones and identity baselines.
fn canonical_calls() -> Vec<Call> {
    let mut v = Vec::new();
    for a in 0..3 {
        for b in 0..3 {
            v.push(Call {
                a,
                b,
                x: 7 + a as i64 * 2,
                y: 5 + b as i64,
            });
        }
    }
    v
}

fn worked_examples(spec: &Spec, seed: u64) -> (Vec<Call>, String) {
    let mut rng = Rng::new(seed ^ 0x0E17_0000_0000_0A17);
    let mut calls = Vec::new();
    // A readable sample for the prompt: a few of the canonical pairs...
    let canon = canonical_calls();
    for &i in &[1usize, 3, 5, 8] {
        calls.push(canon[i]);
    }
    // ...and two random ones.
    for _ in 0..2 {
        calls.push(Call {
            a: rng.below(3) as usize,
            b: rng.below(3) as usize,
            x: 1 + rng.below(40) as i64,
            y: 1 + rng.below(40) as i64,
        });
    }
    let prose: String = calls
        .iter()
        .map(|&c| format!("  {}  ->  {}\n", call_src(spec, c), result_of(spec, c)))
        .collect();
    (calls, prose)
}

fn func_prose(func: Func) -> &'static str {
    match func {
        Func::Convert => "`convert` turns `v` of unit `A` into whole units of `B`: `v * A::FACTOR / B::FACTOR` (integer division)",
        Func::Label => "`label` renders `v` with its unit's suffix: `v` followed immediately by `A::SUFFIX`, e.g. `7` with suffix `\"xy\"` gives `\"7xy\"`",
        Func::Larger => "`larger` returns the suffix of whichever unit has the greater `FACTOR`; if the factors are equal (the same unit twice) it returns `A`'s suffix",
        Func::Total => "`total` is the combined size of `x` of `A` and `y` of `B` in base units: `x * A::FACTOR + y * B::FACTOR`",
        Func::Leftover => "`leftover` is what remains when `v` of `A` is split into whole `B`: `(v * A::FACTOR) % B::FACTOR`",
        Func::Fits => "`fits` is true when `v` of `A` is a whole number of `B`: `(v * A::FACTOR) % B::FACTOR == 0`",
    }
}

fn style_prose(spec: &Spec) -> String {
    match spec.style {
        Style::TypeLevel => "The function takes **no value of the unit types**: callers name the units with a turbofish, e.g. `{ex}`.".replace(
            "{ex}",
            &call_src(spec, canonical_calls()[1]),
        ),
        Style::ByValue => "The function takes the unit values as marker arguments (the unit structs are unit-like, so `Mid` is a value), e.g. `{ex}`.".replace(
            "{ex}",
            &call_src(spec, canonical_calls()[1]),
        ),
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let table: String = spec
        .units
        .iter()
        .map(|u| {
            format!(
                "  - `{}`: `FACTOR = {}`, `SUFFIX = {:?}`\n",
                u.name, u.factor, u.suffix
            )
        })
        .collect();
    let (_, examples) = worked_examples(spec, seed);
    format!(
        "In `src/lib.rs`, implement the `Unit` trait for the three provided unit types, then write \
         the generic function `{name}`.\n\
         \n\
         The units (`Unit` has two associated consts, `FACTOR` and `SUFFIX`):\n\
         {table}\
         \n\
         {func}. {style}\n\
         \n\
         Constraints:\n\
         - Keep the trait and the unit types unchanged; bound the function's type parameters by `Unit`.\n\
         - Do not use `unsafe`.\n\
         \n\
         Provided in `src/lib.rs`:\n\
         ```rust\n\
         {types}```\n\
         \n\
         Signature to implement:\n\
         ```rust\n\
         {sig}```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = fn_name(spec.func),
        func = func_prose(spec.func),
        style = style_prose(spec),
        types = trait_and_types(spec),
        sig = fn_src(spec, Some("/* ... */")),
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

fn uses(spec: &Spec) -> String {
    let names: Vec<&str> = spec.units.iter().map(|u| u.name).collect();
    format!(
        "use task::{{{}, {}}};\n",
        fn_name(spec.func),
        names.join(", ")
    )
}

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let (calls, _) = worked_examples(spec, seed);
    let mut body = format!("{}\n", uses(spec));
    // The sampled calls first, then every canonical pair.
    let mut all = calls;
    all.extend(canonical_calls());
    for (i, c) in all.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn call{i}() {{\n    assert_eq!({}, {});\n}}\n\n",
            call_src(spec, *c),
            result_of(spec, *c)
        ));
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    let mut checks = String::new();
    for a in 0..3 {
        for b in 0..3 {
            let c = Call { a, b, x: 0, y: 0 };
            // Replace the literal args with the loop variables.
            let text = |krate: &str| -> String {
                let (an, bn) = (spec.units[c.a].name, spec.units[c.b].name);
                let name = fn_name(spec.func);
                let (tys, vals) = match spec.func {
                    Func::Label => (format!("<{krate}::{an}>"), format!("{krate}::{an}")),
                    _ => (
                        format!("<{krate}::{an}, {krate}::{bn}>"),
                        format!("{krate}::{an}, {krate}::{bn}"),
                    ),
                };
                let nums = match spec.func {
                    Func::Larger => String::new(),
                    Func::Total => "x, y".to_string(),
                    _ => "x".to_string(),
                };
                match spec.style {
                    Style::TypeLevel => format!("{krate}::{name}::{tys}({nums})"),
                    Style::ByValue => {
                        if nums.is_empty() {
                            format!("{krate}::{name}({vals})")
                        } else {
                            format!("{krate}::{name}({vals}, {nums})")
                        }
                    }
                }
            };
            checks.push_str(&format!(
                "        assert_eq!({}, {}, \"{a}->{b} x={{x}} y={{y}}\");\n",
                text("task"),
                text("reference"),
            ));
        }
    }
    format!(
        "mod reference {{\n{indented}}}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x0E17_ED00_0000_004B;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let x = (next() % 200) as i64;\n\
         \x20       let y = (next() % 50) as i64;\n\
         \x20       let _ = y;\n\
         {checks}\
         \x20   }}\n\
         }}\n"
    )
}

/// Degenerate: every unit has `FACTOR = 1` and an empty suffix (compiles; every factor-dependent
/// answer is wrong).
fn all_ones(spec: &Spec) -> String {
    format!(
        "{}\n{}\n{}",
        trait_and_types(spec),
        impls_src(spec, Some(1), true),
        fn_src(spec, None)
    )
}

/// Degenerate: correct impls, but the function ignores the units.
fn ignore_types(spec: &Spec) -> String {
    let silent = match spec.func {
        Func::Convert | Func::Leftover | Func::Total => "0",
        Func::Label => "String::new()",
        Func::Larger => "\"\"",
        Func::Fits => "true",
    };
    // Mark the parameters used so the baseline is warning-light; unused names are fine anyway.
    format!(
        "{}\n{}\n{}",
        trait_and_types(spec),
        impls_src(spec, None, false),
        fn_src(spec, Some(silent))
    )
}

pub struct UnitGenericFamily;

impl Generator for UnitGenericFamily {
    fn id(&self) -> &str {
        "unit-generic"
    }
    fn category(&self) -> &str {
        "traits-generics"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("unit-generic", seed);

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
            id: format!("unit-generic/{seed:016x}"),
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
            // traits-generics: docs/04 default weights (L1 + signature match emphasis).
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
            ("all-ones".to_string(), all_ones(&spec)),
            ("ignore-types".to_string(), ignore_types(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let style = match spec.style {
            Style::TypeLevel => "type_level",
            Style::ByValue => "by_value",
        };
        vec![
            format!("func:{}", fn_name(spec.func)),
            format!("style:{style}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FUNCS: [Func; 6] = [
        Func::Convert,
        Func::Label,
        Func::Larger,
        Func::Total,
        Func::Leftover,
        Func::Fits,
    ];

    fn spec_with(func: Func, style: Style, factors: [i64; 3]) -> Spec {
        let names = ["Tiny", "Mid", "Big"];
        let suffixes = ["mm", "cm", "m"];
        Spec {
            func,
            style,
            units: [0, 1, 2].map(|k| Unit {
                name: names[k],
                factor: factors[k],
                suffix: suffixes[k],
            }),
        }
    }

    #[test]
    fn generation_is_deterministic() {
        let g = UnitGenericFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn native_matches_intent() {
        let s = spec_with(Func::Convert, Style::TypeLevel, [1, 10, 1000]);
        let [mm, cm, m] = s.units;
        assert_eq!(native(Func::Convert, m, cm, 3, 0), "300");
        assert_eq!(native(Func::Convert, mm, cm, 25, 0), "2");
        assert_eq!(native(Func::Label, cm, m, 7, 0), "\"7cm\"");
        assert_eq!(native(Func::Larger, mm, m, 0, 0), "\"m\"");
        assert_eq!(native(Func::Larger, m, mm, 0, 0), "\"m\"");
        assert_eq!(
            native(Func::Larger, cm, cm, 0, 0),
            "\"cm\"",
            "tie goes to the first"
        );
        assert_eq!(native(Func::Total, m, cm, 2, 5), "2050");
        assert_eq!(native(Func::Leftover, mm, cm, 25, 0), "5");
        assert_eq!(native(Func::Fits, mm, cm, 25, 0), "false");
        assert_eq!(native(Func::Fits, mm, cm, 30, 0), "true");
    }

    #[test]
    fn call_syntax_follows_the_style() {
        let ty = spec_with(Func::Convert, Style::TypeLevel, [1, 10, 1000]);
        let c = Call {
            a: 2,
            b: 0,
            x: 3,
            y: 0,
        };
        assert_eq!(call_src(&ty, c), "convert::<Big, Tiny>(3)");
        let bv = spec_with(Func::Convert, Style::ByValue, [1, 10, 1000]);
        assert_eq!(call_src(&bv, c), "convert(Big, Tiny, 3)");
        let lab = spec_with(Func::Label, Style::ByValue, [1, 10, 1000]);
        assert_eq!(call_src(&lab, c), "label(Big, 3)");
        let lg = spec_with(Func::Larger, Style::TypeLevel, [1, 10, 1000]);
        assert_eq!(call_src(&lg, c), "larger::<Big, Tiny>()");
        let tot = spec_with(Func::Total, Style::ByValue, [1, 10, 1000]);
        assert_eq!(
            call_src(
                &tot,
                Call {
                    a: 1,
                    b: 2,
                    x: 4,
                    y: 6
                }
            ),
            "total(Mid, Big, 4, 6)"
        );
    }

    #[test]
    fn canonical_defeats_both_baselines_under_every_function_and_factor_table() {
        // all-ones fails if some canonical call's answer depends on the factors/suffixes;
        // ignore-types fails if some canonical answer differs from the constant it returns.
        let tables: [[i64; 3]; 4] = [[1, 10, 1000], [2, 3, 5], [6, 60, 100], [4, 16, 24]];
        for &func in &FUNCS {
            for f in tables {
                let s = spec_with(func, Style::TypeLevel, f);
                let ones = spec_with(func, Style::TypeLevel, [1, 1, 1]);
                let canon = canonical_calls();
                let differs_from_ones = canon.iter().any(|&c| {
                    let real = result_of(&s, c);
                    // The baseline also blanks suffixes.
                    let base = native(
                        func,
                        Unit {
                            suffix: "",
                            ..ones.units[c.a]
                        },
                        Unit {
                            suffix: "",
                            ..ones.units[c.b]
                        },
                        c.x,
                        c.y,
                    );
                    real != base
                });
                assert!(
                    differs_from_ones,
                    "{func:?}/{f:?}: all-ones passes every canonical call"
                );
                let silent = match func {
                    Func::Convert | Func::Leftover | Func::Total => "0",
                    Func::Label => "\"\"",
                    Func::Larger => "\"\"",
                    Func::Fits => "true",
                };
                assert!(
                    canon.iter().any(|&c| result_of(&s, c) != silent),
                    "{func:?}/{f:?}: ignore-types passes every canonical call"
                );
            }
        }
    }

    #[test]
    fn factors_are_distinct_and_ascending() {
        for seed in 0..300u64 {
            let s = sample(seed);
            assert!(
                s.units[0].factor < s.units[1].factor && s.units[1].factor < s.units[2].factor,
                "seed {seed}"
            );
        }
    }

    #[test]
    fn the_skeleton_lacks_the_impls_and_the_reference_has_them() {
        for seed in 0..40u64 {
            let s = sample(seed);
            let sk = skeleton_src(&s, seed);
            assert!(!sk.contains("impl Unit for"), "seed {seed}");
            assert!(sk.contains("todo!()"));
            let r = reference_src(&s);
            assert_eq!(r.matches("impl Unit for").count(), 3, "seed {seed}");
        }
    }

    #[test]
    fn seeds_vary_both_axes() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.func, s.style));
        }
        assert_eq!(variants.len(), 12);
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let t = UnitGenericFamily.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

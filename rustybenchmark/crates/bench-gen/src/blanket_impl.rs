//! The `blanket-impl` family (category `traits-generics`) — write a blanket `impl<T: Shape>
//! Describe for T`, including the `?Sized` bound when trait objects must work.
//!
//! `trait-impl` implements a trait for *one* provided type; `generic-select` writes a generic
//! function over a trait; `ops-overload` implements std traits. This family tests **coherence-
//! level generics**: a *blanket* impl that gives every `T: Shape` a second trait, `Describe`,
//! from `Shape`'s two required methods. Two traps are in the hidden tests:
//!
//! * **Per-type impls are not enough.** The pinned code already has two shapes (`Sq`, `Rect`).
//!   A model that writes `impl Describe for Sq` and `impl Describe for Rect` compiles, and
//!   passes the examples, but the hidden tests define a *third* shape and call `describe()` on
//!   it, so the test target fails to build. Only a blanket impl satisfies it.
//! * **`?Sized`.** In the `Unsized` variant the tests call `describe()` through a
//!   `Box<dyn Shape>` and a `&dyn Shape`. `impl<T: Shape> Describe for T` has an implicit
//!   `T: Sized` bound, so `dyn Shape` does not get the impl; `impl<T: Shape + ?Sized>` does.
//!
//! Seed-selected on two axes:
//!
//! 1. **Style** — how `describe` renders from `area()` and `sides()`: five formats, one
//!    branching on parity, one dividing, one repeating a character.
//! 2. **Reach** — `Sized` (concrete types only) or `Unsized` (trait objects must work too).
//!
//! 5 x 2 = **10 distinct skills**; trait and type names are cosmetic and excluded from
//! `spec_signature` (Q31). Solution-first (ADR-0003): the native `describe` and the emitted
//! impl share the format table; the differential implements both crates' `Shape` for one
//! test-local type and compares the two `describe`s on 3000 random (area, sides) pairs.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Style {
    SidesArea,
    Verbose,
    Parity,
    PerSide,
    Stars,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Reach {
    Sized,
    Unsized,
}

struct Spec {
    style: Style,
    reach: Reach,
    /// (shape trait, describe trait, square type, rectangle type) -- cosmetic.
    names: (&'static str, &'static str, &'static str, &'static str),
}

const NAMES: &[(&str, &str, &str, &str)] = &[
    ("Shape", "Describe", "Sq", "Rect"),
    ("Figure", "Label", "Square", "Box2"),
    ("Polygon", "Summary", "Quad", "Slab"),
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let style = match rng.below(5) {
        0 => Style::SidesArea,
        1 => Style::Verbose,
        2 => Style::Parity,
        3 => Style::PerSide,
        _ => Style::Stars,
    };
    let reach = if rng.below(2) == 0 {
        Reach::Sized
    } else {
        Reach::Unsized
    };
    let names = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        style,
        reach,
        names,
    }
}

// ---- native reference -----------------------------------------------------------

fn describe(style: Style, area: i64, sides: i64) -> String {
    match style {
        Style::SidesArea => format!("{sides}:{area}"),
        Style::Verbose => format!("area {area} over {sides} sides"),
        Style::Parity => {
            if area % 2 == 0 {
                format!("even-{area}")
            } else {
                format!("odd-{area}")
            }
        }
        Style::PerSide => format!("{area} => {} per side", area / sides),
        Style::Stars => format!("{}{area}", "*".repeat(sides as usize)),
    }
}

/// The body of `describe`, as source, over `a` (area) and `s` (sides) bindings.
fn body_src(style: Style) -> &'static str {
    match style {
        Style::SidesArea => "format!(\"{}:{}\", s, a)",
        Style::Verbose => "format!(\"area {} over {} sides\", a, s)",
        Style::Parity => {
            "if a % 2 == 0 {\n            format!(\"even-{}\", a)\n        } else {\n            format!(\"odd-{}\", a)\n        }"
        }
        Style::PerSide => "format!(\"{} => {} per side\", a, a / s)",
        Style::Stars => "format!(\"{}{}\", \"*\".repeat(s as usize), a)",
    }
}

// ---- emitted source ----------------------------------------------------------------

fn prelude_src(spec: &Spec) -> String {
    let (shape, desc, sq, rect) = spec.names;
    format!(
        "pub trait {shape} {{\n\
         \x20   fn area(&self) -> i64;\n\
         \x20   fn sides(&self) -> i64;\n\
         }}\n\
         \n\
         pub trait {desc} {{\n\
         \x20   fn describe(&self) -> String;\n\
         }}\n\
         \n\
         pub struct {sq}(pub i64);\n\
         pub struct {rect}(pub i64, pub i64);\n\
         \n\
         impl {shape} for {sq} {{\n\
         \x20   fn area(&self) -> i64 {{\n\
         \x20       self.0 * self.0\n\
         \x20   }}\n\
         \x20   fn sides(&self) -> i64 {{\n\
         \x20       4\n\
         \x20   }}\n\
         }}\n\
         \n\
         impl {shape} for {rect} {{\n\
         \x20   fn area(&self) -> i64 {{\n\
         \x20       self.0 * self.1\n\
         \x20   }}\n\
         \x20   fn sides(&self) -> i64 {{\n\
         \x20       4\n\
         \x20   }}\n\
         }}\n"
    )
}

fn blanket_impl_src(spec: &Spec, sized_bound: &str, body: &str) -> String {
    let (shape, desc, _, _) = spec.names;
    format!(
        "impl<T: {shape}{sized_bound}> {desc} for T {{\n\
         \x20   fn describe(&self) -> String {{\n\
         \x20       let a = self.area();\n\
         \x20       let s = self.sides();\n\
         \x20       {body}\n\
         \x20   }}\n\
         }}\n"
    )
}

fn reference_src(spec: &Spec) -> String {
    let bound = match spec.reach {
        Reach::Sized => "",
        Reach::Unsized => " + ?Sized",
    };
    format!(
        "{}\n{}",
        prelude_src(spec),
        blanket_impl_src(spec, bound, body_src(spec.style))
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
        "//! Implement `{desc}` below. The traits and the two shapes are provided — keep them.\n\
         //!\n\
         {doc}\n\
         {prelude}\n\
         // Your impl goes here.\n",
        desc = spec.names.1,
        prelude = prelude_src(spec),
    )
}

// ---- worked examples -----------------------------------------------------------------

/// A value in the tests: one of the two pinned shapes, or a test-local `Poly`.
#[derive(Clone, Debug)]
enum Val {
    Sq(i64),
    Rect(i64, i64),
    Poly { area: i64, sides: i64 },
}

fn val_area_sides(v: &Val) -> (i64, i64) {
    match v {
        Val::Sq(k) => (k * k, 4),
        Val::Rect(w, h) => (w * h, 4),
        Val::Poly { area, sides } => (*area, *sides),
    }
}

fn worked_examples(spec: &Spec, seed: u64) -> (Vec<Val>, String) {
    let mut rng = Rng::new(seed ^ 0xB1A4_0000_0000_0C07);
    let vals = vec![
        Val::Sq(3),
        Val::Rect(2, 5),
        Val::Poly {
            area: 9 + rng.below(40) as i64,
            sides: 3 + rng.below(4) as i64,
        },
        Val::Sq(2 + rng.below(9) as i64),
        Val::Rect(1 + rng.below(9) as i64, 1 + rng.below(9) as i64),
    ];
    let (_, _, sq, rect) = spec.names;
    let mut prose = String::new();
    for v in &vals {
        let (a, s) = val_area_sides(v);
        let shown = match v {
            Val::Sq(k) => format!("{sq}({k})"),
            Val::Rect(w, h) => format!("{rect}({w}, {h})"),
            Val::Poly { area, sides } => {
                format!("<a shape with area() = {area}, sides() = {sides}>")
            }
        };
        prose.push_str(&format!(
            "  {shown}.describe()  ->  {:?}\n",
            describe(spec.style, a, s)
        ));
    }
    (vals, prose)
}

fn style_prose(style: Style) -> &'static str {
    match style {
        Style::SidesArea => "`\"<sides>:<area>\"`, e.g. `\"4:9\"`",
        Style::Verbose => "`\"area <area> over <sides> sides\"`",
        Style::Parity => "`\"even-<area>\"` when the area is even, otherwise `\"odd-<area>\"`",
        Style::PerSide => {
            "`\"<area> => <q> per side\"` where `<q>` is `area / sides` (integer division)"
        }
        Style::Stars => {
            "the character `*` repeated `sides` times, followed by the area, e.g. `\"****9\"`"
        }
    }
}

fn reach_prose(spec: &Spec) -> String {
    let shape = spec.names.0;
    match spec.reach {
        Reach::Sized => format!("It must work for every type that implements `{shape}`, including types you cannot see (other crates and tests define their own shapes)."),
        Reach::Unsized => format!("It must work for every type that implements `{shape}`, including types you cannot see, **and for trait objects**: `describe()` must be callable on a `Box<dyn {shape}>` and on a `&dyn {shape}`."),
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (shape, desc, _, _) = spec.names;
    let (_, examples) = worked_examples(spec, seed);
    format!(
        "Give every `{shape}` a `{desc}` implementation in `src/lib.rs`. The two traits and the \
         shapes `{sq}` and `{rect}` are provided; keep them unchanged and add one `impl`.\n\
         \n\
         `describe()` returns {style}, where the area is `self.area()` and the number of sides is \
         `self.sides()`.\n\
         \n\
         {reach}\n\
         \n\
         Constraints:\n\
         - Do not change the provided traits or types.\n\
         - Do not use `unsafe`.\n\
         \n\
         Provided in `src/lib.rs`:\n\
         ```rust\n\
         {prelude}```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        sq = spec.names.2,
        rect = spec.names.3,
        style = style_prose(spec.style),
        reach = reach_prose(spec),
        prelude = prelude_src(spec),
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

/// A test-local shape the model has never seen, implementing the given crate's `Shape`.
fn poly_decl(spec: &Spec, krate: &str) -> String {
    let shape = spec.names.0;
    format!(
        "struct Poly {{ area: i64, sides: i64 }}\n\
         impl {krate}::{shape} for Poly {{\n\
         \x20   fn area(&self) -> i64 {{ self.area }}\n\
         \x20   fn sides(&self) -> i64 {{ self.sides }}\n\
         }}\n"
    )
}

fn val_expr(spec: &Spec, v: &Val) -> String {
    let (_, _, sq, rect) = spec.names;
    match v {
        Val::Sq(k) => format!("{sq}({k})"),
        Val::Rect(w, h) => format!("{rect}({w}, {h})"),
        Val::Poly { area, sides } => format!("Poly {{ area: {area}, sides: {sides} }}"),
    }
}

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let (shape, desc, sq, rect) = spec.names;
    let (vals, _) = worked_examples(spec, seed);
    let mut body = format!(
        "use task::{{{shape}, {desc}, {sq}, {rect}}};\n\n{}\n\
         fn show<T: {desc}>(t: &T) -> String {{\n    t.describe()\n}}\n\n",
        poly_decl(spec, "task")
    );
    for (i, v) in vals.iter().enumerate() {
        let (a, s) = val_area_sides(v);
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let v = {};\n    assert_eq!(v.describe(), {:?});\n    assert_eq!(show(&v), {:?});\n}}\n\n",
            val_expr(spec, v),
            describe(spec.style, a, s),
            describe(spec.style, a, s),
        ));
    }
    if spec.reach == Reach::Unsized {
        let (a, s) = val_area_sides(&vals[0]);
        let want = describe(spec.style, a, s);
        body.push_str(&format!(
            "#[test]\nfn works_through_trait_objects() {{\n\
             \x20   let boxed: Box<dyn {shape}> = Box::new({});\n\
             \x20   assert_eq!(boxed.describe(), {want:?});\n\
             \x20   let by_ref: &dyn {shape} = &{};\n\
             \x20   assert_eq!(by_ref.describe(), {want:?});\n\
             }}\n",
            val_expr(spec, &vals[0]),
            val_expr(spec, &vals[0]),
        ));
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let (shape, desc, _, _) = spec.names;
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    // For Unsized, also compare through `&dyn` to exercise the `?Sized` blanket.
    let dyn_check = if spec.reach == Reach::Unsized {
        format!(
            "        let td: &dyn task::{shape} = &p;\n\
             \x20       let rd: &dyn reference::{shape} = &p;\n\
             \x20       assert_eq!(task::{desc}::describe(td), reference::{desc}::describe(rd), \"dyn area={{area}} sides={{sides}}\");\n"
        )
    } else {
        String::new()
    };
    format!(
        "mod reference {{\n{indented}}}\n\n\
         {poly_task}\n\
         {poly_ref}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xB1A4_ED00_0000_0047;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let area = (next() % 200) as i64;\n\
         \x20       let sides = 1 + (next() % 8) as i64;\n\
         \x20       let p = Poly {{ area, sides }};\n\
         \x20       assert_eq!(task::{desc}::describe(&p), reference::{desc}::describe(&p), \"area={{area}} sides={{sides}}\");\n\
         {dyn_check}\
         \x20   }}\n\
         }}\n",
        poly_task = poly_decl(spec, "task"),
        // The second impl block reuses `Poly`: only the trait path differs.
        poly_ref = poly_decl(spec, "reference")
            .lines()
            .skip(1)
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Degenerate: per-type impls for the two pinned shapes only (compiles; the hidden tests'
/// third shape does not satisfy it).
fn per_type(spec: &Spec) -> String {
    let (_, desc, sq, rect) = spec.names;
    let imp = |ty: &str| {
        format!(
            "impl {desc} for {ty} {{\n\
             \x20   fn describe(&self) -> String {{\n\
             \x20       let a = self.area();\n\
             \x20       let s = self.sides();\n\
             \x20       {}\n\
             \x20   }}\n\
             }}\n",
            body_src(spec.style)
        )
    };
    format!("{}\n{}\n{}", prelude_src(spec), imp(sq), imp(rect))
}

/// Degenerate: a correct-shaped blanket impl that describes nothing.
fn const_empty(spec: &Spec) -> String {
    format!(
        "{}\n{}",
        prelude_src(spec),
        blanket_impl_src(spec, " + ?Sized", "let _ = (a, s);\n        String::new()")
    )
}

pub struct BlanketImplFamily;

impl Generator for BlanketImplFamily {
    fn id(&self) -> &str {
        "blanket-impl"
    }
    fn category(&self) -> &str {
        "traits-generics"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("blanket-impl", seed);

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
            id: format!("blanket-impl/{seed:016x}"),
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
            ("per-type".to_string(), per_type(&spec)),
            ("const-empty".to_string(), const_empty(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let style = match spec.style {
            Style::SidesArea => "sides_area",
            Style::Verbose => "verbose",
            Style::Parity => "parity",
            Style::PerSide => "per_side",
            Style::Stars => "stars",
        };
        let reach = match spec.reach {
            Reach::Sized => "sized",
            Reach::Unsized => "unsized",
        };
        vec![format!("style:{style}"), format!("reach:{reach}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STYLES: [Style; 5] = [
        Style::SidesArea,
        Style::Verbose,
        Style::Parity,
        Style::PerSide,
        Style::Stars,
    ];

    #[test]
    fn generation_is_deterministic() {
        let g = BlanketImplFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn describe_matches_intent() {
        assert_eq!(describe(Style::SidesArea, 9, 4), "4:9");
        assert_eq!(describe(Style::Verbose, 10, 4), "area 10 over 4 sides");
        assert_eq!(describe(Style::Parity, 10, 4), "even-10");
        assert_eq!(describe(Style::Parity, 9, 4), "odd-9");
        assert_eq!(describe(Style::PerSide, 10, 4), "10 => 2 per side");
        assert_eq!(describe(Style::Stars, 9, 3), "***9");
    }

    #[test]
    fn the_third_shape_is_a_real_third_shape() {
        // The per-type baseline only fails if the hidden tests use a type outside {Sq, Rect}:
        // every spec's behaviour examples must include a `Poly`.
        for seed in 0..40u64 {
            let t = BlanketImplFamily.generate(seed);
            let b = &t.hidden[&PathBuf::from("tests/behavior.rs")];
            assert!(
                b.contains("Poly {"),
                "seed {seed}: no third shape in behavior"
            );
            let d = &t.hidden[&PathBuf::from("tests/differential.rs")];
            assert!(
                d.contains("struct Poly"),
                "seed {seed}: no third shape in differential"
            );
        }
    }

    #[test]
    fn canonical_defeats_const_empty_under_every_style() {
        // const-empty fails on every seed iff describe() is never empty for the canonical
        // shapes (Sq(3): area 9, sides 4; Rect(2, 5): area 10).
        for &st in &STYLES {
            for (a, s) in [(9, 4), (10, 4)] {
                assert!(!describe(st, a, s).is_empty(), "{st:?} {a} {s}");
            }
        }
    }

    #[test]
    fn unsized_specs_get_the_dyn_checks_and_the_bound() {
        for seed in 0..60u64 {
            let s = sample(seed);
            let t = BlanketImplFamily.generate(seed);
            let b = &t.hidden[&PathBuf::from("tests/behavior.rs")];
            let r = reference_src(&s);
            match s.reach {
                Reach::Unsized => {
                    assert!(b.contains("works_through_trait_objects"));
                    assert!(r.contains("+ ?Sized"));
                }
                Reach::Sized => {
                    assert!(!b.contains("dyn "));
                    assert!(!r.contains("?Sized"));
                }
            }
        }
    }

    #[test]
    fn division_style_never_divides_by_zero_in_generated_cases() {
        for seed in 0..100u64 {
            let s = sample(seed);
            for v in worked_examples(&s, seed).0 {
                assert!(val_area_sides(&v).1 >= 1, "seed {seed}: zero sides");
            }
        }
    }

    #[test]
    fn seeds_vary_both_axes() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..200u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.style, s.reach));
        }
        assert_eq!(variants.len(), 10);
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let t = BlanketImplFamily.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

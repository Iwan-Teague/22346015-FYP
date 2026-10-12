//! The `idiom-ptr` family (category `idiom-refactor`) — the fifth idiom-refactor family, on
//! **`clippy::ptr_arg`**: parameters written `&Vec<T>`, `&String`, `&PathBuf` or `&mut Vec<T>`
//! that should be the borrowed forms `&[T]`, `&str`, `&Path`, `&mut [T]`.
//!
//! Where `idiom-loop` / `idiom-counter` / `idiom-copy` rewrite loops and `idiom-api` rewrites an
//! API, this one rewrites **signatures**. **Q14, measured:** in a scratch crate against the
//! installed clippy (1.97) `cargo clippy --fix` left every `ptr_arg` form (`&Vec`, `&String`,
//! `&PathBuf`, `&mut Vec`) unchanged, and did *not* flag a `&mut Vec<T>` whose body calls `push`,
//! which is the decoy this family carries.
//!
//! The model is given a handful of working functions with the owned-container parameters and must
//! change the signatures while preserving behaviour. Three things stop it from cheating:
//!
//! * The hidden tests (behaviour **and** differential) call the functions with **slices, array references and string literals**
//!   (`sum_all(&[1, 2, 3])`, `count_vowels("hello")`, `has_ext(Path::new("a.txt"), "txt")`), which
//!   do not coerce to `&Vec`/`&String`/`&PathBuf`, so an answer that leaves a signature alone does
//!   not build.
//! * `#[allow(clippy::ptr_arg)]` is a forbidden path (the AST check sees attribute paths).
//! * The decoy `grow(&mut Vec<i64>)` *needs* the `Vec` (it pushes), so over-eagerly "fixing" it
//!   to `&mut [i64]` does not compile.
//!
//! Seed-selected on one axis plus cosmetics: **which 3 of 6 flagged functions** are present
//! (C(6,3) = **20 distinct skills**). Each function also has a seeded variant (`sum_all` vs
//! `max_or_zero`, ...) and the shift constant of `add_to_all`; these change the examples and the
//! function name but not the skill, so they are excluded from `spec_signature` (Q31).
//! Constraint-dominant per docs/04 (behaviour 0.30 / constraint 0.60 / quality 0.10).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// The six flagged function *shapes* (the skill axis).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Shape {
    VecRead,
    StrRead,
    VecMut,
    StrReturn,
    PathRead,
    VecPair,
}

const ALL: [Shape; 6] = [
    Shape::VecRead,
    Shape::StrRead,
    Shape::VecMut,
    Shape::StrReturn,
    Shape::PathRead,
    Shape::VecPair,
];

/// One chosen function: its shape plus the cosmetic variant bit and constant.
#[derive(Clone, Copy)]
struct Func {
    shape: Shape,
    variant: bool,
}

struct Spec {
    funcs: Vec<Func>,
    /// The shift for `add_to_all` (1..=9).
    k: i64,
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let mut idx = [0usize, 1, 2, 3, 4, 5];
    for i in 0..3 {
        let j = i + rng.below((6 - i) as u64) as usize;
        idx.swap(i, j);
    }
    let mut shapes: Vec<Shape> = idx[..3].iter().map(|&i| ALL[i]).collect();
    shapes.sort();
    let funcs = shapes
        .into_iter()
        .map(|shape| Func {
            shape,
            variant: rng.below(2) == 1,
        })
        .collect();
    Spec {
        funcs,
        k: 1 + rng.below(9) as i64,
    }
}

fn name(f: Func) -> &'static str {
    match (f.shape, f.variant) {
        (Shape::VecRead, false) => "sum_all",
        (Shape::VecRead, true) => "max_or_zero",
        (Shape::StrRead, false) => "count_vowels",
        (Shape::StrRead, true) => "count_upper",
        (Shape::VecMut, false) => "add_to_all",
        (Shape::VecMut, true) => "negate_all",
        (Shape::StrReturn, false) => "first_word",
        (Shape::StrReturn, true) => "last_word",
        (Shape::PathRead, false) => "has_ext",
        (Shape::PathRead, true) => "stem_of",
        (Shape::VecPair, false) => "dot",
        (Shape::VecPair, true) => "matches",
    }
}

// ---- source: given (owned-container params) and reference (borrowed forms) ---------------

/// `owned`: the un-idiomatic signature (what the model is given).
fn func_src(f: Func, k: i64, owned: bool) -> String {
    let n = name(f);
    let (vec_ref, str_ref, path_ref, vec_mut) = if owned {
        ("&Vec<i64>", "&String", "&PathBuf", "&mut Vec<i64>")
    } else {
        ("&[i64]", "&str", "&Path", "&mut [i64]")
    };
    match (f.shape, f.variant) {
        (Shape::VecRead, false) => {
            format!("pub fn {n}(xs: {vec_ref}) -> i64 {{\n    xs.iter().sum()\n}}\n")
        }
        (Shape::VecRead, true) => format!(
            "pub fn {n}(xs: {vec_ref}) -> i64 {{\n    xs.iter().copied().max().unwrap_or(0)\n}}\n"
        ),
        (Shape::StrRead, false) => format!(
            "pub fn {n}(s: {str_ref}) -> usize {{\n    s.chars().filter(|c| \"aeiou\".contains(*c)).count()\n}}\n"
        ),
        (Shape::StrRead, true) => format!(
            "pub fn {n}(s: {str_ref}) -> usize {{\n    s.chars().filter(|c| c.is_uppercase()).count()\n}}\n"
        ),
        (Shape::VecMut, false) => format!(
            "pub fn {n}(xs: {vec_mut}) {{\n    for x in xs.iter_mut() {{\n        *x += {k};\n    }}\n}}\n"
        ),
        (Shape::VecMut, true) => format!(
            "pub fn {n}(xs: {vec_mut}) {{\n    for x in xs.iter_mut() {{\n        *x = -*x;\n    }}\n}}\n"
        ),
        (Shape::StrReturn, false) => format!(
            "pub fn {n}(s: {str_ref}) -> &str {{\n    s.split(' ').next().unwrap_or(\"\")\n}}\n"
        ),
        (Shape::StrReturn, true) => format!(
            "pub fn {n}(s: {str_ref}) -> &str {{\n    s.split(' ').next_back().unwrap_or(\"\")\n}}\n"
        ),
        (Shape::PathRead, false) => format!(
            "pub fn {n}(p: {path_ref}, ext: &str) -> bool {{\n    p.extension().is_some_and(|e| e == ext)\n}}\n"
        ),
        (Shape::PathRead, true) => format!(
            "pub fn {n}(p: {path_ref}) -> Option<&str> {{\n    p.file_stem().and_then(|s| s.to_str())\n}}\n"
        ),
        (Shape::VecPair, false) => format!(
            "pub fn {n}(a: {vec_ref}, b: {vec_ref}) -> i64 {{\n    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()\n}}\n"
        ),
        (Shape::VecPair, true) => format!(
            "pub fn {n}(a: {vec_ref}, b: {vec_ref}) -> usize {{\n    a.iter().zip(b.iter()).filter(|(x, y)| x == y).count()\n}}\n"
        ),
    }
}

/// The decoy: it pushes, so it genuinely needs `&mut Vec`. Already clippy-clean; the model must
/// leave it alone.
const DECOY: &str =
    "/// Appends the current length. Needs the `Vec` itself, so `&mut Vec<i64>` is right here.\n\
    pub fn grow(xs: &mut Vec<i64>) {\n\
    \x20   let n = xs.len() as i64;\n\
    \x20   xs.push(n);\n\
    }\n";

fn uses_path(spec: &Spec) -> bool {
    spec.funcs.iter().any(|f| f.shape == Shape::PathRead)
}

fn prelude(spec: &Spec, owned: bool) -> String {
    if !uses_path(spec) {
        return String::new();
    }
    if owned {
        "use std::path::PathBuf;\n\n".to_string()
    } else {
        "use std::path::Path;\n\n".to_string()
    }
}

fn body(spec: &Spec, owned: bool) -> String {
    let mut s = prelude(spec, owned);
    for f in &spec.funcs {
        s.push_str(&func_src(*f, spec.k, owned));
        s.push('\n');
    }
    s.push_str(DECOY);
    s
}

fn given_src(spec: &Spec) -> String {
    body(spec, true)
}

fn reference_src(spec: &Spec) -> String {
    body(spec, false)
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .1
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Make the parameter types idiomatic and clippy-clean, preserving behaviour.\n\
         //!\n\
         {doc}\n\
         {}",
        given_src(spec)
    )
}

// ---- native reference and examples ----------------------------------------------------------

/// One test input.
#[derive(Clone, Debug)]
enum Input {
    Vecs(Vec<i64>, Vec<i64>),
    Text(String),
    Path(String, String),
}

fn text_lit(s: &str) -> String {
    format!("{s:?}")
}

fn vec_lit(v: &[i64]) -> String {
    format!("{v:?}")
}

/// Rust call expression and the expected value literal for `f` on `input`, in the form the
/// hidden tests use: array references, slices of a `Vec`, `&str` literals, `Path::new`.
fn call_and_expected(f: Func, k: i64, input: &Input) -> Option<(String, String)> {
    let n = name(f);
    match (f.shape, f.variant, input) {
        (Shape::VecRead, false, Input::Vecs(a, _)) => Some((
            format!("{n}(&{})", vec_lit(a)),
            a.iter().sum::<i64>().to_string(),
        )),
        (Shape::VecRead, true, Input::Vecs(a, _)) => Some((
            format!("{n}(&{})", vec_lit(a)),
            a.iter().copied().max().unwrap_or(0).to_string(),
        )),
        (Shape::StrRead, false, Input::Text(s)) => Some((
            format!("{n}({})", text_lit(s)),
            s.chars()
                .filter(|c| "aeiou".contains(*c))
                .count()
                .to_string(),
        )),
        (Shape::StrRead, true, Input::Text(s)) => Some((
            format!("{n}({})", text_lit(s)),
            s.chars().filter(|c| c.is_uppercase()).count().to_string(),
        )),
        (Shape::VecMut, v, Input::Vecs(a, _)) => {
            let want: Vec<i64> = a.iter().map(|x| if v { -x } else { x + k }).collect();
            Some((
                format!("{{ let mut a = {}; {n}(&mut a); a.to_vec() }}", vec_lit(a)),
                format!("vec!{}", vec_lit(&want)),
            ))
        }
        (Shape::StrReturn, false, Input::Text(s)) => Some((
            format!("{n}({})", text_lit(s)),
            text_lit(s.split(' ').next().unwrap_or("")),
        )),
        (Shape::StrReturn, true, Input::Text(s)) => Some((
            format!("{n}({})", text_lit(s)),
            text_lit(s.split(' ').next_back().unwrap_or("")),
        )),
        (Shape::PathRead, false, Input::Path(p, ext)) => Some((
            format!("{n}(Path::new({}), {})", text_lit(p), text_lit(ext)),
            std::path::Path::new(p)
                .extension()
                .is_some_and(|e| e == ext.as_str())
                .to_string(),
        )),
        (Shape::PathRead, true, Input::Path(p, _)) => Some((
            format!("{n}(Path::new({}))", text_lit(p)),
            match std::path::Path::new(p).file_stem().and_then(|s| s.to_str()) {
                Some(s) => format!("Some({})", text_lit(s)),
                None => "None".to_string(),
            },
        )),
        (Shape::VecPair, false, Input::Vecs(a, b)) => Some((
            format!("{n}(&{}, &{})", vec_lit(a), vec_lit(b)),
            a.iter().zip(b).map(|(x, y)| x * y).sum::<i64>().to_string(),
        )),
        (Shape::VecPair, true, Input::Vecs(a, b)) => Some((
            format!("{n}(&{}, &{})", vec_lit(a), vec_lit(b)),
            a.iter().zip(b).filter(|(x, y)| x == y).count().to_string(),
        )),
        _ => None,
    }
}

fn input_kind(f: Func) -> u8 {
    match f.shape {
        Shape::VecRead | Shape::VecMut | Shape::VecPair => 0,
        Shape::StrRead | Shape::StrReturn => 1,
        Shape::PathRead => 2,
    }
}

const WORDS: &[&str] = &[
    "Alpha", "beta", "GAMMA", "delta", "Echo", "foxtrot", "audio",
];
const STEMS: &[&str] = &["report", "notes", "data", "image", "log"];
const EXTS: &[&str] = &["txt", "rs", "md", "png"];

fn random_input(kind: u8, rng: &mut Rng) -> Input {
    match kind {
        0 => {
            let la = 2 + rng.below(5) as usize;
            let a: Vec<i64> = (0..la).map(|_| rng.below(21) as i64 - 10).collect();
            let b: Vec<i64> = (0..la + rng.below(2) as usize)
                .map(|_| rng.below(21) as i64 - 10)
                .collect();
            Input::Vecs(a, b)
        }
        1 => {
            let n = 2 + rng.below(3) as usize;
            let words: Vec<&str> = (0..n)
                .map(|_| WORDS[rng.below(WORDS.len() as u64) as usize])
                .collect();
            Input::Text(words.join(" "))
        }
        _ => {
            let stem = STEMS[rng.below(STEMS.len() as u64) as usize];
            let ext = EXTS[rng.below(EXTS.len() as u64) as usize];
            let dir = ["src", "docs", "out/v2"][rng.below(3) as usize];
            // The probed extension is sometimes the right one, sometimes not.
            let probe = if rng.below(2) == 0 {
                ext
            } else {
                EXTS[rng.below(EXTS.len() as u64) as usize]
            };
            Input::Path(format!("{dir}/{stem}.{ext}"), probe.to_string())
        }
    }
}

fn canonical_input(kind: u8) -> Input {
    match kind {
        0 => Input::Vecs(vec![3, -1, 4, 1, -5], vec![2, -1, 4, 0, -5]),
        1 => Input::Text("Hello wOrld Again".to_string()),
        _ => Input::Path("dir/report.final.txt".to_string(), "txt".to_string()),
    }
}

/// (function, expression, expected) triples: the canonical input plus two random ones per function.
fn cases(spec: &Spec, seed: u64) -> Vec<(Func, String, String)> {
    let mut rng = Rng::new(seed ^ 0x9747_0000_0000_0A12);
    let mut out = Vec::new();
    for &f in &spec.funcs {
        let kind = input_kind(f);
        let inputs = [
            canonical_input(kind),
            random_input(kind, &mut rng),
            random_input(kind, &mut rng),
            random_input(kind, &mut rng),
            random_input(kind, &mut rng),
            random_input(kind, &mut rng),
        ];
        for inp in &inputs {
            if let Some((call, want)) = call_and_expected(f, spec.k, inp) {
                out.push((f, call, want));
            }
        }
    }
    out
}

fn worked_examples(spec: &Spec, seed: u64) -> ((), String) {
    let mut prose = String::new();
    for (_, call, want) in cases(spec, seed).iter() {
        prose.push_str(&format!("  {call}  ->  {want}\n"));
    }
    ((), prose)
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (_, examples) = worked_examples(spec, seed);
    format!(
        "The functions in `src/lib.rs` work, but their parameters are written as owned containers \
         behind a reference (`&Vec<_>`, `&String`, `&PathBuf`, `&mut Vec<_>`) where the borrowed \
         forms (`&[_]`, `&str`, `&Path`, `&mut [_]`) would do (clippy: `ptr_arg`). Make the \
         signatures idiomatic and `clippy`-clean while preserving behaviour: callers must be able to \
         pass slices, array references and string literals, not only `Vec`s and `String`s.\n\
         \n\
         Here is the current code:\n\
         \n\
         ```rust\n\
         {current}\n\
         ```\n\
         \n\
         Examples of the behaviour that must be kept (note the argument forms):\n\
         {examples}\n\
         Constraints:\n\
         - The rewrite must produce **no** `clippy` warnings, and must not hide them with \
         `#[allow(..)]`: the checks pass slices, arrays and literals, so a signature left as it is \
         will not build.\n\
         - Change only what clippy flags. A function that really needs the `Vec` itself (it pushes) \
         must keep its `&mut Vec` parameter.\n\
         - Keep every function's name and behaviour. Do not use `unsafe`.\n\
         \n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        current = given_src(spec).trim_end(),
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
    let mut names: Vec<&str> = spec.funcs.iter().map(|f| name(*f)).collect();
    names.push("grow");
    let mut s = format!("use task::{{{}}};\n", names.join(", "));
    if uses_path(spec) {
        s.push_str("use std::path::Path;\n");
    }
    s
}

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let mut body = format!("{}\n", imports(spec));
    for (i, (_, call, want)) in cases(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    assert_eq!({call}, {want});\n}}\n\n"
        ));
    }
    // Slices of a longer Vec: the point of `&[T]`.
    for f in &spec.funcs {
        if f.shape == Shape::VecRead {
            body.push_str(&format!(
                "#[test]\nfn {}_takes_a_subslice() {{\n    let v = vec![9, 1, 2, 3];\n    assert_eq!({}(&v[1..]), {});\n}}\n\n",
                name(*f),
                name(*f),
                if f.variant { "3" } else { "6" }
            ));
        }
    }
    body.push_str(
        "#[test]\nfn the_decoy_still_takes_a_vec() {\n    let mut v = vec![5, 6];\n    grow(&mut v);\n    assert_eq!(v, vec![5, 6, 2]);\n}\n",
    );
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    let mut checks = String::new();
    for f in &spec.funcs {
        let n = name(*f);
        let line = match (f.shape, f.variant) {
            (Shape::VecRead, _) => format!("assert_eq!(task::{n}(&a[..]), reference::{n}(&a[..]), \"{n} {{a:?}}\");"),
            (Shape::StrRead, _) | (Shape::StrReturn, _) => {
                format!("assert_eq!(task::{n}(s.as_str()), reference::{n}(s.as_str()), \"{n} {{s:?}}\");")
            }
            (Shape::VecMut, _) => format!(
                "{{ let (mut x, mut y) = (a.clone(), a.clone()); task::{n}(&mut x[..]); reference::{n}(&mut y[..]); assert_eq!(x, y, \"{n} {{a:?}}\"); }}"
            ),
            (Shape::PathRead, false) => format!(
                "assert_eq!(task::{n}(std::path::Path::new(&s), \"txt\"), reference::{n}(std::path::Path::new(&s), \"txt\"), \"{n} {{s:?}}\");"
            ),
            (Shape::PathRead, true) => format!(
                "assert_eq!(task::{n}(std::path::Path::new(&s)), reference::{n}(std::path::Path::new(&s)), \"{n} {{s:?}}\");"
            ),
            (Shape::VecPair, _) => {
                format!("assert_eq!(task::{n}(&a[..], &b[..]), reference::{n}(&a[..], &b[..]), \"{n} {{a:?}} {{b:?}}\");")
            }
        };
        checks.push_str(&format!("        {line}\n"));
    }
    format!(
        "mod reference {{\n{indented}}}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x9747_ED00_0000_004C;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   let alphabet: Vec<char> = \"abAB. /\".chars().collect();\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let la = (next() % 7) as usize;\n\
         \x20       let a: Vec<i64> = (0..la).map(|_| (next() % 41) as i64 - 20).collect();\n\
         \x20       let b: Vec<i64> = (0..(next() % 7) as usize).map(|_| (next() % 41) as i64 - 20).collect();\n\
         \x20       let s: String = (0..(next() % 10) as usize).map(|_| alphabet[(next() % 7) as usize]).collect();\n\
         \x20       let _ = (&b, &s);\n\
         {checks}\
         \x20   }}\n\
         }}\n",
    )
}

/// The "lazy copy-paste" baseline: the given code unchanged.
fn unchanged(spec: &Spec) -> String {
    given_src(spec)
}

/// The cheat the prompt and the hidden tests close.
fn allow_attrs(spec: &Spec) -> String {
    format!("#![allow(clippy::ptr_arg)]\n{}", given_src(spec))
}

pub struct IdiomPtrFamily;

impl Generator for IdiomPtrFamily {
    fn id(&self) -> &str {
        "idiom-ptr"
    }
    fn category(&self) -> &str {
        "idiom-refactor"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("idiom-ptr", seed);

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
            id: format!("idiom-ptr/{seed:016x}"),
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
            // `#[allow(..)]` is the cheat the prompt forbids; the AST path check sees attribute
            // paths, so it is a measured violation rather than only a failed build.
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
        // The skill is *which* signature shapes are present. The variant bit and the shift
        // constant change the examples and the function name only.
        let spec = sample(seed);
        let shapes: Vec<&str> = spec
            .funcs
            .iter()
            .map(|f| match f.shape {
                Shape::VecRead => "vec_read",
                Shape::StrRead => "str_read",
                Shape::VecMut => "vec_mut",
                Shape::StrReturn => "str_return",
                Shape::PathRead => "path_read",
                Shape::VecPair => "vec_pair",
            })
            .collect();
        vec![format!("shapes:{}", shapes.join("+"))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = IdiomPtrFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn given_uses_owned_params_and_reference_uses_borrowed() {
        for seed in 0..80u64 {
            let s = sample(seed);
            let given = given_src(&s);
            let r = reference_src(&s);
            assert!(
                given.contains("&Vec<i64>")
                    || given.contains("&String")
                    || given.contains("&PathBuf")
                    || given.contains("&mut Vec<i64>"),
                "seed {seed}"
            );
            for bad in ["&Vec<i64>", "&String", "&PathBuf"] {
                assert!(!r.contains(bad), "seed {seed}: reference still has {bad}");
            }
            // The decoy keeps its `&mut Vec` in both.
            assert!(given.contains("pub fn grow(xs: &mut Vec<i64>)"));
            assert!(r.contains("pub fn grow(xs: &mut Vec<i64>)"));
            // `&mut Vec<i64>` appears in the reference only for the decoy.
            assert_eq!(r.matches("(xs: &mut Vec<i64>)").count(), 1, "seed {seed}");
        }
    }

    #[test]
    fn expected_values_are_computed_natively() {
        let f = Func {
            shape: Shape::VecRead,
            variant: false,
        };
        let (call, want) = call_and_expected(f, 1, &Input::Vecs(vec![3, -1, 4], vec![])).unwrap();
        assert_eq!(call, "sum_all(&[3, -1, 4])");
        assert_eq!(want, "6");
        let g = Func {
            shape: Shape::VecMut,
            variant: false,
        };
        let (call, want) = call_and_expected(g, 5, &Input::Vecs(vec![1, 2], vec![])).unwrap();
        assert!(call.contains("add_to_all(&mut a)"));
        assert_eq!(want, "vec![6, 7]");
        let p = Func {
            shape: Shape::PathRead,
            variant: true,
        };
        let (_, want) =
            call_and_expected(p, 1, &Input::Path("a/b.tar.gz".into(), String::new())).unwrap();
        assert_eq!(want, "Some(\"b.tar\")");
    }

    #[test]
    fn the_tests_pass_slices_and_literals_not_owned_containers() {
        // The unchanged baseline fails to build only if every test call uses a form that does
        // not coerce to the owned parameter type.
        for seed in 0..60u64 {
            let t = IdiomPtrFamily.generate(seed);
            let b = &t.hidden[&PathBuf::from("tests/behavior.rs")];
            assert!(!b.contains("&vec!") && !b.contains("String::from") && !b.contains("PathBuf"));
            let s = sample(seed);
            for f in &s.funcs {
                match f.shape {
                    Shape::StrRead | Shape::StrReturn => assert!(
                        b.contains(&format!("{}(\"", name(*f))),
                        "seed {seed}: no &str literal call for {}",
                        name(*f)
                    ),
                    Shape::PathRead => assert!(b.contains("Path::new(")),
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn allow_is_forbidden_and_the_cheat_baseline_carries_it() {
        let t = IdiomPtrFamily.generate(3);
        assert_eq!(t.forbidden_paths, vec!["allow".to_string()]);
        assert!(allow_attrs(&sample(3)).starts_with("#![allow(clippy::ptr_arg)]"));
    }

    #[test]
    fn seeds_vary_the_function_set_only_in_the_signature() {
        let mut sets = std::collections::HashSet::new();
        for seed in 0..800u64 {
            let s = sample(seed);
            assert_eq!(s.funcs.len(), 3);
            sets.insert(IdiomPtrFamily.spec_signature(seed).join("|"));
        }
        assert_eq!(sets.len(), 20);
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let t = IdiomPtrFamily.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

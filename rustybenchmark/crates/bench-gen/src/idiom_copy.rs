//! The `idiom-copy` family (category `idiom-refactor`) — the third idiom-refactor family, a
//! third clippy lint: **`clippy::manual_memcpy`**.
//!
//! Same *de-idiomatisation* move as `idiom-loop` and `idiom-counter`: the model is given a
//! working function that copies a run of elements between slices with an explicit index loop
//! (`for i in 0..n { dst[i] = src[i]; }`) and must rewrite it as the slice operation it is
//! (`copy_from_slice` / `clone_from_slice`), preserving behaviour exactly. The given code is
//! behaviourally correct and *only clippy distinguishes it*.
//!
//! **Q14 (the `clippy --fix` trap), measured.** In a scratch crate against the installed clippy
//! (1.97), eleven common manual-idiom lints were applied with `cargo clippy --fix`: `manual_find`,
//! `manual_map`, `manual_unwrap_or`, `question_mark`, `manual_swap`, `manual_div_ceil`,
//! `manual_abs_diff`, `implicit_saturating_sub`, `manual_is_multiple_of`, `filter_next` and
//! `while_let_on_iterator`-style pop loops were all rewritten mechanically and would be rejected as
//! families. **`manual_memcpy` alone survived** `--fix` unchanged, in every loop shape used here
//! (offsets on either side, a counted range, a windowed range, `i64` / `String` / `u8`). That is
//! why this lint, and not the dozen friendlier ones, carries a family.
//!
//! Seed-selected on three axes:
//!
//! 1. **Shape** — which side is offset: `Same` (`dst[i] = src[i]`), `ShiftDst`
//!    (`dst[i + K] = src[i]`), `ShiftSrc` (`dst[i] = src[i + K]`).
//! 2. **Extent** — how the loop range is given: `SrcLen` (the whole of `src`, less the shift),
//!    `Count` (`0..n`), `Window` (`start..start + n`).
//! 3. **Elem** — `i64` and `u8` (`copy_from_slice`) or `String` (`clone_from_slice`).
//!
//! 3 x 3 x 3 = **27 distinct skills**; the shift `K`, parameter names and function name are
//! cosmetic and excluded from `spec_signature` (Q31). The idiomatic answer is a single slice
//! copy; an iterator `zip` rewrite is also clippy-clean and accepted. Constraint-dominant per
//! docs/04 (behaviour 0.30 / constraint 0.60 / quality 0.10).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — which side of the copy is offset.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Shape {
    Same,
    ShiftDst,
    ShiftSrc,
}

/// Axis 2 — how the loop range is expressed.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Extent {
    SrcLen,
    Count,
    Window,
}

/// Axis 3 — the element type.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Elem {
    Int,
    Byte,
    Text,
}

struct Spec {
    shape: Shape,
    extent: Extent,
    elem: Elem,
    /// The shift distance (1..=4) — cosmetic.
    k: usize,
    fn_name: &'static str,
    /// (dst, src) parameter names — cosmetic.
    names: (&'static str, &'static str),
}

const FN_NAMES: &[&str] = &[
    "copy_run",
    "blit",
    "transfer",
    "splice_in",
    "move_block",
    "fill_from",
];
const PARAM_NAMES: &[(&str, &str)] = &[("dst", "src"), ("out", "input"), ("target", "source")];

/// Text palette: index 0 is the destination's initial filler; 1..=7 are source words.
const WORDS: &[&str] = &["-", "ant", "bee", "cat", "dog", "elk", "fox", "gnu"];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let shape = match rng.below(3) {
        0 => Shape::Same,
        1 => Shape::ShiftDst,
        _ => Shape::ShiftSrc,
    };
    let extent = match rng.below(3) {
        0 => Extent::SrcLen,
        1 => Extent::Count,
        _ => Extent::Window,
    };
    let elem = match rng.below(3) {
        0 => Elem::Int,
        1 => Elem::Byte,
        _ => Elem::Text,
    };
    let k = 1 + rng.below(4) as usize;
    let fn_name = FN_NAMES[rng.below(FN_NAMES.len() as u64) as usize];
    let names = PARAM_NAMES[rng.below(PARAM_NAMES.len() as u64) as usize];
    Spec {
        shape,
        extent,
        elem,
        k,
        fn_name,
        names,
    }
}

// ---- native reference ------------------------------------------------------

/// A test case: the source data, the destination length, and the loop parameters.
#[derive(Clone, Debug)]
struct Case {
    /// Source values (palette indices for `Text`).
    src: Vec<i64>,
    dst_len: usize,
    n: usize,
    start: usize,
}

fn shifts(spec: &Spec) -> (usize, usize) {
    match spec.shape {
        Shape::Same => (0, 0),
        Shape::ShiftDst => (spec.k, 0),
        Shape::ShiftSrc => (0, spec.k),
    }
}

/// The number of elements copied and the base index of the loop.
fn extent_of(spec: &Spec, c: &Case) -> (usize, usize) {
    let (_, sk) = shifts(spec);
    match spec.extent {
        Extent::SrcLen => (c.src.len() - sk, 0),
        Extent::Count => (c.n, 0),
        Extent::Window => (c.n, c.start),
    }
}

/// The answer: the destination after the copy. Uses the idiomatic slice copy, so the
/// generator itself stays clippy-clean; the hidden differential uses an explicit loop, an
/// independent rendering of the same semantics.
fn eval(spec: &Spec, c: &Case) -> Vec<i64> {
    let mut dst = vec![0i64; c.dst_len];
    let (cnt, base) = extent_of(spec, c);
    let (dk, sk) = shifts(spec);
    dst[base + dk..base + dk + cnt].copy_from_slice(&c.src[base + sk..base + sk + cnt]);
    dst
}

// ---- emitted-source fragments ----------------------------------------------

fn elem_ty(elem: Elem) -> &'static str {
    match elem {
        Elem::Int => "i64",
        Elem::Byte => "u8",
        Elem::Text => "String",
    }
}

fn elem_lit(elem: Elem, v: i64) -> String {
    match elem {
        Elem::Int | Elem::Byte => v.to_string(),
        Elem::Text => format!("{:?}.to_string()", WORDS[v as usize]),
    }
}

fn vec_lit(elem: Elem, vs: &[i64]) -> String {
    let items: Vec<String> = vs.iter().map(|&v| elem_lit(elem, v)).collect();
    format!("vec![{}]", items.join(", "))
}

fn params_decl(spec: &Spec) -> String {
    let (d, s) = spec.names;
    let t = elem_ty(spec.elem);
    let tail = match spec.extent {
        Extent::SrcLen => "",
        Extent::Count => ", n: usize",
        Extent::Window => ", start: usize, n: usize",
    };
    format!("{d}: &mut [{t}], {s}: &[{t}]{tail}")
}

fn call_args(spec: &Spec, c: &Case) -> String {
    match spec.extent {
        Extent::SrcLen => String::new(),
        Extent::Count => format!(", {}", c.n),
        Extent::Window => format!(", {}, {}", c.start, c.n),
    }
}

/// `+ K` or nothing.
fn plus(k: usize, active: bool) -> String {
    if active {
        format!(" + {k}")
    } else {
        String::new()
    }
}

/// The non-idiomatic loop. Trips `clippy::manual_memcpy`, which survives `--fix` (Q14).
fn deidiom_src(spec: &Spec) -> String {
    let (d, s) = spec.names;
    let (dk, sk) = shifts(spec);
    let range = match (spec.extent, spec.shape) {
        (Extent::SrcLen, Shape::ShiftSrc) => format!("0..{s}.len() - {}", spec.k),
        (Extent::SrcLen, _) => format!("0..{s}.len()"),
        (Extent::Count, _) => "0..n".to_string(),
        (Extent::Window, _) => "start..start + n".to_string(),
    };
    let rhs = if spec.elem == Elem::Text {
        format!("{s}[i{}].clone()", plus(spec.k, sk > 0))
    } else {
        format!("{s}[i{}]", plus(spec.k, sk > 0))
    };
    format!(
        "pub fn {name}({params}) {{\n\
         \x20   for i in {range} {{\n\
         \x20       {d}[i{dpl}] = {rhs};\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        params = params_decl(spec),
        dpl = plus(spec.k, dk > 0),
    )
}

/// The idiomatic rewrite: one slice copy.
fn reference_src(spec: &Spec) -> String {
    let (d, s) = spec.names;
    let (dk, sk) = shifts(spec);
    let method = if spec.elem == Elem::Text {
        "clone_from_slice"
    } else {
        "copy_from_slice"
    };
    // `base`: the loop's first index; `cnt`: how many elements.
    let (pre, base, cnt) = match spec.extent {
        Extent::SrcLen if sk > 0 => (
            format!("    let n = {s}.len() - {};\n", spec.k),
            String::new(),
            "n".to_string(),
        ),
        Extent::SrcLen => (String::new(), String::new(), format!("{s}.len()")),
        Extent::Count => (String::new(), String::new(), "n".to_string()),
        Extent::Window => (String::new(), "start".to_string(), "n".to_string()),
    };
    // An index expression `base + shift` rendered without redundant zeros.
    let lo = |shift: usize| -> String {
        match (base.is_empty(), shift) {
            (true, 0) => String::new(),
            (true, k) => k.to_string(),
            (false, 0) => base.clone(),
            (false, k) => format!("{base} + {k}"),
        }
    };
    let hi = |shift: usize| -> String {
        let l = lo(shift);
        if l.is_empty() {
            cnt.clone()
        } else {
            format!("{l} + {cnt}")
        }
    };
    // A whole-`src` copy is `copy_from_slice(src)`: `&src[..src.len()]` would trip
    // `clippy::redundant_slicing`.
    let src_arg = if spec.extent == Extent::SrcLen && sk == 0 {
        s.to_string()
    } else {
        format!("&{s}[{}..{}]", lo(sk), hi(sk))
    };
    format!(
        "pub fn {name}({params}) {{\n\
         {pre}\
         \x20   {d}[{dlo}..{dhi}].{method}({src_arg});\n\
         }}\n",
        name = spec.fn_name,
        params = params_decl(spec),
        dlo = lo(dk),
        dhi = hi(dk),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples_prose(spec, seed)
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Rewrite `{name}` below in idiomatic, clippy-clean Rust, preserving its\n\
         //! exact behaviour.\n\
         //!\n\
         {doc}\n\
         {deidiom}",
        name = spec.fn_name,
        deidiom = deidiom_src(spec),
    )
}

// ---- worked examples ---------------------------------------------------------

fn draw_src(spec: &Spec, rng: &mut Rng, len: usize) -> Vec<i64> {
    (0..len)
        .map(|_| match spec.elem {
            Elem::Int => 1 + rng.below(99) as i64,
            Elem::Byte => 1 + rng.below(250) as i64,
            Elem::Text => 1 + rng.below(7) as i64,
        })
        .collect()
}

/// A valid case: every index the loop touches is in range of both slices.
fn make_case(spec: &Spec, rng: &mut Rng) -> Case {
    let (dk, sk) = shifts(spec);
    let n = 1 + rng.below(5) as usize;
    let start = rng.below(4) as usize;
    let extra = rng.below(3) as usize;
    let src_len = match spec.extent {
        Extent::SrcLen => sk + 1 + rng.below(6) as usize,
        Extent::Count => n + sk + extra,
        Extent::Window => start + n + sk + extra,
    };
    let (cnt, base) = match spec.extent {
        Extent::SrcLen => (src_len - sk, 0),
        Extent::Count => (n, 0),
        Extent::Window => (n, start),
    };
    let dst_len = base + cnt + dk + rng.below(3) as usize;
    Case {
        src: draw_src(spec, rng, src_len),
        dst_len,
        n,
        start,
    }
}

/// The canonical case: ten non-filler source values (long enough for the largest shift plus the window), copying at least three, so any
/// copy visibly changes a destination of fillers — the property the `noop` baseline needs.
fn canonical(spec: &Spec) -> Case {
    let (dk, _) = shifts(spec);
    let src: Vec<i64> = match spec.elem {
        Elem::Int => vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        Elem::Byte => vec![101, 102, 103, 104, 105, 106, 107, 108, 109, 110],
        Elem::Text => vec![1, 2, 3, 4, 5, 6, 7, 1, 2, 3],
    };
    Case {
        src,
        dst_len: 10 + dk + 1,
        n: 3,
        start: 1,
    }
}

fn worked_examples(spec: &Spec, seed: u64) -> Vec<Case> {
    let mut rng = Rng::new(seed ^ 0x1D2C_0000_0000_0071);
    let mut cases = vec![canonical(spec)];
    for _ in 0..2 {
        cases.push(make_case(spec, &mut rng));
    }
    cases
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for c in worked_examples(spec, seed) {
        let out = eval(spec, &c);
        let init = vec![0i64; c.dst_len];
        s.push_str(&format!(
            "  {name}({d}: {before}, {src}: {sv}{tail})  ->  {d} == {after}\n",
            name = spec.fn_name,
            d = spec.names.0,
            src = spec.names.1,
            before = vec_lit_plain(spec.elem, &init),
            sv = vec_lit_plain(spec.elem, &c.src),
            tail = match spec.extent {
                Extent::SrcLen => String::new(),
                Extent::Count => format!(", n: {}", c.n),
                Extent::Window => format!(", start: {}, n: {}", c.start, c.n),
            },
            after = vec_lit_plain(spec.elem, &out),
        ));
    }
    s
}

/// Compact display form (no `.to_string()` noise): `[1, 2]` or `["ant", "-"]`.
fn vec_lit_plain(elem: Elem, vs: &[i64]) -> String {
    let items: Vec<String> = vs
        .iter()
        .map(|&v| match elem {
            Elem::Int | Elem::Byte => v.to_string(),
            Elem::Text => format!("{:?}", WORDS[v as usize]),
        })
        .collect();
    format!("[{}]", items.join(", "))
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (d, s) = spec.names;
    format!(
        "The function `{name}` in `src/lib.rs` works but copies a run of elements from `{s}` into \
         `{d}` with a hand-written index loop. Rewrite it in **idiomatic Rust** — the slice \
         operation this loop is — so that it is `clippy`-clean, while preserving its exact \
         behaviour and its signature.\n\
         \n\
         Here is the current implementation:\n\
         \n\
         ```rust\n\
         {current}\n\
         ```\n\
         \n\
         The caller guarantees every index the loop touches is in range. It behaves like this \
         (`{d}` starts filled with its filler value, `0` or `\"-\"`):\n\
         {examples}\n\
         Constraints:\n\
         - Keep the signature `pub fn {name}({params})` exactly.\n\
         - The rewrite must produce **no** `clippy` warnings.\n\
         - Do not use `unsafe`.\n\
         \n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        current = deidiom_src(spec).trim_end(),
        params = params_decl(spec),
        examples = worked_examples_prose(spec, seed),
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

fn filler_lit(elem: Elem) -> String {
    elem_lit(elem, 0)
}

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let mut body = format!("use task::{};\n\n", spec.fn_name);
    for (i, c) in worked_examples(spec, seed).iter().enumerate() {
        let out = eval(spec, c);
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let mut {d}: Vec<{t}> = vec![{filler}; {len}];\n\
             \x20   let {s}: Vec<{t}> = {src};\n\
             \x20   {name}(&mut {d}, &{s}{args});\n\
             \x20   assert_eq!({d}, {expected});\n\
             }}\n\n",
            d = spec.names.0,
            s = spec.names.1,
            t = elem_ty(spec.elem),
            filler = filler_lit(spec.elem),
            len = c.dst_len,
            src = vec_lit(spec.elem, &c.src),
            name = spec.fn_name,
            args = call_args(spec, c),
            expected = vec_lit(spec.elem, &out),
        ));
    }
    body
}

/// The differential's reference is an explicit element-by-element loop (in a test file, so
/// never clippy'd): an independent rendering of `eval`'s slice copy.
fn differential_test_src(spec: &Spec) -> String {
    let t = elem_ty(spec.elem);
    let (dk, sk) = shifts(spec);
    let (cnt_expr, base_expr) = match spec.extent {
        Extent::SrcLen => (format!("src.len() - {sk}"), "0".to_string()),
        Extent::Count => ("n".to_string(), "0".to_string()),
        Extent::Window => ("n".to_string(), "start".to_string()),
    };
    let (sig_tail, call_tail) = match spec.extent {
        Extent::SrcLen => (String::new(), String::new()),
        Extent::Count => (", n: usize".to_string(), ", n".to_string()),
        Extent::Window => (
            ", start: usize, n: usize".to_string(),
            ", start, n".to_string(),
        ),
    };
    let elem_expr = match spec.elem {
        Elem::Int => "(next() % 199) as i64 - 99".to_string(),
        Elem::Byte => "(next() % 251) as u8".to_string(),
        Elem::Text => "WORDS[(next() % 7) as usize].to_string()".to_string(),
    };
    let filler = filler_lit(spec.elem);
    format!(
        "use task::{name};\n\
         \n\
         const WORDS: [&str; 7] = [\"ant\", \"bee\", \"cat\", \"dog\", \"elk\", \"fox\", \"gnu\"];\n\
         \n\
         fn reference(dst: &mut [{t}], src: &[{t}]{sig_tail}) {{\n\
         \x20   let base = {base_expr};\n\
         \x20   let cnt = {cnt_expr};\n\
         \x20   for j in 0..cnt {{\n\
         \x20       dst[base + j + {dk}] = src[base + j + {sk}].clone();\n\
         \x20   }}\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x1D2C_ED00_0000_0044;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = (next() % 6) as usize;\n\
         \x20       let start = (next() % 5) as usize;\n\
         \x20       let _ = (n, start);\n\
         \x20       let src_len = {src_len_expr};\n\
         \x20       let src: Vec<{t}> = (0..src_len).map(|_| {elem_expr}).collect();\n\
         \x20       let dst_len = {dst_len_expr};\n\
         \x20       let mut got: Vec<{t}> = vec![{filler}; dst_len];\n\
         \x20       let mut want = got.clone();\n\
         \x20       {name}(&mut got, &src{call_tail});\n\
         \x20       reference(&mut want, &src{call_tail});\n\
         \x20       assert_eq!(got, want, \"src={{src:?}} n={{n}} start={{start}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        src_len_expr = match spec.extent {
            Extent::SrcLen => format!("{sk} + (next() % 7) as usize"),
            Extent::Count => format!("n + {sk} + (next() % 3) as usize"),
            Extent::Window => format!("start + n + {sk} + (next() % 3) as usize"),
        },
        dst_len_expr = match spec.extent {
            Extent::SrcLen => format!("src_len - {sk} + {dk} + (next() % 3) as usize"),
            Extent::Count => format!("n + {dk} + (next() % 3) as usize"),
            Extent::Window => format!("start + n + {dk} + (next() % 3) as usize"),
        },
    )
}

/// The "lazy copy-paste" baseline: the unchanged loop. Behaviourally correct, so it fails only
/// on clippy.
fn unchanged(spec: &Spec) -> String {
    deidiom_src(spec)
}

/// A behaviourally-wrong baseline: accepts the arguments and copies nothing.
fn noop(spec: &Spec) -> String {
    let (d, s) = spec.names;
    let tail = match spec.extent {
        Extent::SrcLen => "",
        Extent::Count => ", n",
        Extent::Window => ", start, n",
    };
    format!(
        "pub fn {name}({params}) {{ let _ = ({d}, {s}{tail}); }}\n",
        name = spec.fn_name,
        params = params_decl(spec),
    )
}

pub struct IdiomCopyFamily;

impl Generator for IdiomCopyFamily {
    fn id(&self) -> &str {
        "idiom-copy"
    }
    fn category(&self) -> &str {
        "idiom-refactor"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("idiom-copy", seed);

        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("Cargo.toml"), cargo_toml());
        // The model's starting file is the non-idiomatic function (it rewrites it).
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
            id: format!("idiom-copy/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // `unsafe` is irrelevant here; opting the check out keeps the L3 constraint
            // layer purely clippy (the idiomaticity signal).
            max_unsafe: None,
            forbidden_paths: Vec::new(),
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
            // Load-bearing baseline: returning the code unchanged is behaviourally correct
            // but not idiomatic — caught by clippy, not behaviour.
            ("unchanged".to_string(), unchanged(&spec)),
            ("noop".to_string(), noop(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let shape = match spec.shape {
            Shape::Same => "same",
            Shape::ShiftDst => "shift_dst",
            Shape::ShiftSrc => "shift_src",
        };
        let extent = match spec.extent {
            Extent::SrcLen => "src_len",
            Extent::Count => "count",
            Extent::Window => "window",
        };
        let elem = match spec.elem {
            Elem::Int => "int",
            Elem::Byte => "byte",
            Elem::Text => "text",
        };
        vec![
            format!("shape:{shape}"),
            format!("extent:{extent}"),
            format!("elem:{elem}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(shape: Shape, extent: Extent, elem: Elem, k: usize) -> Spec {
        Spec {
            shape,
            extent,
            elem,
            k,
            fn_name: "f",
            names: ("dst", "src"),
        }
    }

    const SHAPES: [Shape; 3] = [Shape::Same, Shape::ShiftDst, Shape::ShiftSrc];
    const EXTENTS: [Extent; 3] = [Extent::SrcLen, Extent::Count, Extent::Window];
    const ELEMS: [Elem; 3] = [Elem::Int, Elem::Byte, Elem::Text];

    #[test]
    fn generation_is_deterministic() {
        let g = IdiomCopyFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    /// An independent, explicit-loop rendering of the semantics, to cross-check `eval`.
    fn loop_eval(spec: &Spec, c: &Case) -> Vec<i64> {
        let (dk, sk) = shifts(spec);
        let (cnt, base) = extent_of(spec, c);
        let mut dst = vec![0i64; c.dst_len];
        for j in 0..cnt {
            dst[base + j + dk] = c.src[base + j + sk];
        }
        dst
    }

    #[test]
    fn eval_matches_the_explicit_loop_everywhere() {
        let mut rng = Rng::new(7);
        for &shape in &SHAPES {
            for &extent in &EXTENTS {
                for &elem in &ELEMS {
                    for k in 1..=4 {
                        let s = spec(shape, extent, elem, k);
                        for _ in 0..50 {
                            let c = make_case(&s, &mut rng);
                            assert_eq!(eval(&s, &c), loop_eval(&s, &c), "{shape:?}/{extent:?}/{k}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn eval_matches_intent() {
        let c = Case {
            src: vec![1, 2, 3, 4],
            dst_len: 6,
            n: 2,
            start: 1,
        };
        // Same + Window: positions 1..3 copied in place.
        let s = spec(Shape::Same, Extent::Window, Elem::Int, 2);
        assert_eq!(eval(&s, &c), vec![0, 2, 3, 0, 0, 0]);
        // ShiftDst + Count: dst[i + 2] = src[i] for i in 0..2.
        let s = spec(Shape::ShiftDst, Extent::Count, Elem::Int, 2);
        assert_eq!(eval(&s, &c), vec![0, 0, 1, 2, 0, 0]);
        // ShiftSrc + SrcLen: dst[i] = src[i + 2] for i in 0..2.
        let s = spec(Shape::ShiftSrc, Extent::SrcLen, Elem::Int, 2);
        assert_eq!(eval(&s, &c), vec![3, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn every_generated_case_is_in_range() {
        // `eval` panics on an out-of-range index, so exercising it over many seeds proves the
        // generated cases (and the canonical) respect the documented precondition.
        for seed in 0..400u64 {
            let s = sample(seed);
            for c in worked_examples(&s, seed) {
                let _ = eval(&s, &c);
            }
        }
    }

    #[test]
    fn canonical_changes_a_filler_destination_under_every_combination() {
        // The `noop` baseline fails on every seed only if the canonical copy writes at least
        // one non-filler value.
        for &shape in &SHAPES {
            for &extent in &EXTENTS {
                for &elem in &ELEMS {
                    for k in 1..=4 {
                        let s = spec(shape, extent, elem, k);
                        let c = canonical(&s);
                        let out = eval(&s, &c);
                        assert!(
                            out.iter().any(|&v| v != 0),
                            "{shape:?}/{extent:?}/{elem:?}/{k}: canonical copy left the filler untouched"
                        );
                        assert!(c.src.iter().all(|&v| v != 0), "source contains the filler");
                    }
                }
            }
        }
    }

    #[test]
    fn emitted_sources_have_the_expected_shape() {
        for seed in 0..60u64 {
            let s = sample(seed);
            let skel = deidiom_src(&s);
            assert!(
                skel.contains("for i in"),
                "seed {seed}: no loop in the given code"
            );
            let r = reference_src(&s);
            assert!(!r.contains("for "), "seed {seed}: reference still loops");
            let want = if s.elem == Elem::Text {
                "clone_from_slice"
            } else {
                "copy_from_slice"
            };
            assert!(r.contains(want), "seed {seed}: {r}");
            if s.elem == Elem::Text {
                assert!(
                    skel.contains(".clone()"),
                    "seed {seed}: text loop must clone"
                );
            }
        }
    }

    #[test]
    fn seeds_vary_all_three_axes() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..600u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}/{:?}", s.shape, s.extent, s.elem));
        }
        assert_eq!(variants.len(), 27);
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let t = IdiomCopyFamily.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

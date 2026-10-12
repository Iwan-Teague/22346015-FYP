//! The `ops-overload` family (category `traits-generics`) — implement the standard operator
//! and iterator-fold traits for a pinned value type.
//!
//! `trait-impl` implements a *user* trait with an associated type; `generic-select` writes a
//! generic function over one. This family covers the other large part of everyday trait work:
//! the **`std::ops` / `std::iter` traits** — `Add`, `Mul`, `Neg`, `AddAssign`, `MulAssign`,
//! `Sum`, `Product` — including the reference forms (`&a + &b`) whose `impl` is easy to forget.
//! The value type and its constructor are pinned in the skeleton; the model writes the trait
//! impls. The hidden drivers use the operators directly (`a + b`, `&a * &b`, `x += y`,
//! `iter.sum::<T>()`), so a missing or mistyped impl makes the test target fail to build and
//! the answer scores 0.0 — the same "signature wrong => unsatisfiable driver" mechanism as
//! `trait-impl`, here on std traits.
//!
//! Seed-selected on two axes:
//!
//! 1. **Algebra** — what the operators *mean*: component-wise `Pair`, complex `Cplx`
//!    (`*` is complex multiplication), residues `Mod` (arithmetic mod a seed-chosen prime), or
//!    saturating `Sat` (results clamp into a fixed range).
//! 2. **Op set** — which traits must exist: `Core` (Add, Mul, Neg), `ByRef` (Add and Mul for
//!    both `T` and `&T`), `Assign` (Add, Mul, AddAssign, MulAssign), `Fold` (Add, Mul, Sum,
//!    Product).
//!
//! 4 x 4 = **16 distinct skills**; the modulus and the type name are cosmetic and excluded from
//! `spec_signature` (Q31). Solution-first (ADR-0003): the native algebra below and the emitted
//! impls are mirrored, and the differential fuzzes 3000 random operand sets against an inlined
//! copy of the reference (as a nested module, so both `T`s coexist). Operands are bounded so no
//! legal expression overflows `i64`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — what `+`, `*` and unary `-` mean for the value type.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Alg {
    Pair,
    Cplx,
    Mod,
    Sat,
}

/// Axis 2 — which operator traits the model must implement.
#[derive(Clone, Copy, Debug, PartialEq)]
enum OpSet {
    Core,
    ByRef,
    Assign,
    Fold,
}

struct Spec {
    alg: Alg,
    ops: OpSet,
    /// The value type's name — cosmetic.
    name: &'static str,
    /// Modulus for `Alg::Mod` (a prime); unused otherwise — cosmetic, excluded from the signature.
    m: i64,
}

const NAMES: &[&str] = &["Elem", "Quant", "Datum", "Atom", "Quark", "Wval"];
const MODULI: &[i64] = &[7, 11, 13];
/// The saturation bound for `Alg::Sat`.
const LIMIT: i64 = 100;

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let alg = match rng.below(4) {
        0 => Alg::Pair,
        1 => Alg::Cplx,
        2 => Alg::Mod,
        _ => Alg::Sat,
    };
    let ops = match rng.below(4) {
        0 => OpSet::Core,
        1 => OpSet::ByRef,
        2 => OpSet::Assign,
        _ => OpSet::Fold,
    };
    let name = NAMES[rng.below(NAMES.len() as u64) as usize];
    let m = MODULI[rng.below(MODULI.len() as u64) as usize];
    Spec { alg, ops, name, m }
}

// ---- native algebra (mirrors the emitted impl bodies exactly) -------------

/// A value as a normalised pair. `Mod`/`Sat` use only `.0`.
type V = (i64, i64);

/// Bring raw components into the algebra's canonical form (what the pinned `new` does).
fn norm(spec: &Spec, v: V) -> V {
    match spec.alg {
        Alg::Pair | Alg::Cplx => v,
        Alg::Mod => (v.0.rem_euclid(spec.m), 0),
        Alg::Sat => (v.0.clamp(-LIMIT, LIMIT), 0),
    }
}

fn add(spec: &Spec, l: V, r: V) -> V {
    norm(spec, (l.0 + r.0, l.1 + r.1))
}

fn mul(spec: &Spec, l: V, r: V) -> V {
    match spec.alg {
        Alg::Pair => (l.0 * r.0, l.1 * r.1),
        Alg::Cplx => (l.0 * r.0 - l.1 * r.1, l.0 * r.1 + l.1 * r.0),
        Alg::Mod | Alg::Sat => norm(spec, (l.0 * r.0, 0)),
    }
}

fn neg(spec: &Spec, s: V) -> V {
    norm(spec, (-s.0, -s.1))
}

fn zero(_spec: &Spec) -> V {
    (0, 0)
}

fn one(spec: &Spec) -> V {
    match spec.alg {
        Alg::Pair => (1, 1),
        Alg::Cplx => (1, 0),
        Alg::Mod | Alg::Sat => (1, 0),
    }
}

// ---- emitted-source fragments ---------------------------------------------

/// Rust expression for a value in this algebra, built from component expressions.
fn mk(spec: &Spec, path: &str, x: &str, y: &str) -> String {
    match spec.alg {
        Alg::Pair | Alg::Cplx => format!("{path}{} {{ a: {x}, b: {y} }}", spec.name),
        Alg::Mod | Alg::Sat => {
            let _ = y;
            format!("{path}{}::new({x})", spec.name)
        }
    }
}

fn lit(spec: &Spec, v: V) -> String {
    mk(spec, "", &v.0.to_string(), &v.1.to_string())
}

/// The `(i64, i64)` key the differential compares.
fn key_fn(spec: &Spec) -> &'static str {
    match spec.alg {
        Alg::Pair | Alg::Cplx => "(x.a, x.b)",
        Alg::Mod | Alg::Sat => "(x.val(), 0)",
    }
}

fn comp_field(spec: &Spec, e: &str, i: usize) -> String {
    match (spec.alg, i) {
        (Alg::Pair | Alg::Cplx, 0) => format!("{e}.a"),
        (Alg::Pair | Alg::Cplx, _) => format!("{e}.b"),
        (Alg::Mod | Alg::Sat, _) => format!("{e}.v"),
    }
}

fn add_e(spec: &Spec, l: &str, r: &str) -> String {
    let n = spec.name;
    match spec.alg {
        Alg::Pair | Alg::Cplx => format!(
            "{n} {{ a: {} + {}, b: {} + {} }}",
            comp_field(spec, l, 0),
            comp_field(spec, r, 0),
            comp_field(spec, l, 1),
            comp_field(spec, r, 1)
        ),
        Alg::Mod | Alg::Sat => format!("{n}::new({l}.v + {r}.v)"),
    }
}

fn mul_e(spec: &Spec, l: &str, r: &str) -> String {
    let n = spec.name;
    match spec.alg {
        Alg::Pair => format!("{n} {{ a: {l}.a * {r}.a, b: {l}.b * {r}.b }}"),
        Alg::Cplx => {
            format!("{n} {{ a: {l}.a * {r}.a - {l}.b * {r}.b, b: {l}.a * {r}.b + {l}.b * {r}.a }}")
        }
        Alg::Mod | Alg::Sat => format!("{n}::new({l}.v * {r}.v)"),
    }
}

fn neg_e(spec: &Spec, s: &str) -> String {
    let n = spec.name;
    match spec.alg {
        Alg::Pair | Alg::Cplx => format!("{n} {{ a: -{s}.a, b: -{s}.b }}"),
        Alg::Mod | Alg::Sat => format!("{n}::new(-{s}.v)"),
    }
}

fn zero_e(spec: &Spec) -> String {
    lit(spec, zero(spec))
}

fn one_e(spec: &Spec) -> String {
    lit(spec, one(spec))
}

/// The pinned prelude: the type, its derives, and (for `Mod`/`Sat`) the normalising `new` and
/// the `val` getter the hidden tests construct and read values through.
fn prelude_src(spec: &Spec) -> String {
    let n = spec.name;
    match spec.alg {
        Alg::Pair | Alg::Cplx => format!(
            "#[derive(Debug, Clone, Copy, PartialEq)]\n\
             pub struct {n} {{\n\
             \x20   pub a: i64,\n\
             \x20   pub b: i64,\n\
             }}\n"
        ),
        Alg::Mod => format!(
            "pub const MODULUS: i64 = {m};\n\
             \n\
             #[derive(Debug, Clone, Copy, PartialEq)]\n\
             pub struct {n} {{\n\
             \x20   v: i64,\n\
             }}\n\
             \n\
             impl {n} {{\n\
             \x20   /// Reduce any integer into `0..MODULUS`.\n\
             \x20   pub fn new(v: i64) -> {n} {{\n\
             \x20       {n} {{ v: v.rem_euclid(MODULUS) }}\n\
             \x20   }}\n\
             \x20   pub fn val(&self) -> i64 {{\n\
             \x20       self.v\n\
             \x20   }}\n\
             }}\n",
            m = spec.m
        ),
        Alg::Sat => format!(
            "pub const LIMIT: i64 = {LIMIT};\n\
             \n\
             #[derive(Debug, Clone, Copy, PartialEq)]\n\
             pub struct {n} {{\n\
             \x20   v: i64,\n\
             }}\n\
             \n\
             impl {n} {{\n\
             \x20   /// Clamp any integer into `-LIMIT..=LIMIT`.\n\
             \x20   pub fn new(v: i64) -> {n} {{\n\
             \x20       {n} {{ v: v.clamp(-LIMIT, LIMIT) }}\n\
             \x20   }}\n\
             \x20   pub fn val(&self) -> i64 {{\n\
             \x20       self.v\n\
             \x20   }}\n\
             }}\n"
        ),
    }
}

/// What an impl body does: the correct algebra, or one of the two degenerate answers.
#[derive(Clone, Copy, PartialEq)]
enum Body {
    Correct,
    /// Returns the left operand / leaves the receiver unchanged.
    EchoLhs,
    /// Returns the zero value.
    Zero,
}

fn bin_body(
    spec: &Spec,
    body: Body,
    l: &str,
    r: &str,
    f: fn(&Spec, &str, &str) -> String,
) -> String {
    match body {
        Body::Correct => f(spec, l, r),
        Body::EchoLhs => format!("{{ let _ = {r}; {l} }}"),
        Body::Zero => format!("{{ let _ = ({l}, {r}); {} }}", zero_e(spec)),
    }
    // `Correct` is a bare expression, the others are braced blocks; both are valid fn bodies
    // once wrapped by the caller's `{ ... }`.
}

/// The trait impls for the spec's op set.
fn impls_src(spec: &Spec, body: Body) -> String {
    let n = spec.name;
    let mut s = String::new();
    let mut bin = |tr: &str, method: &str, f: fn(&Spec, &str, &str) -> String, by_ref: bool| {
        let (l, r) = if by_ref {
            ("(*self)", "(*rhs)")
        } else {
            ("self", "rhs")
        };
        let expr = bin_body(spec, body, l, r, f);
        if by_ref {
            s.push_str(&format!(
                "impl<'a> std::ops::{tr}<&'a {n}> for &'a {n} {{\n\
                 \x20   type Output = {n};\n\
                 \x20   fn {method}(self, rhs: &'a {n}) -> {n} {{\n\
                 \x20       {expr}\n\
                 \x20   }}\n\
                 }}\n\n"
            ));
        } else {
            s.push_str(&format!(
                "impl std::ops::{tr} for {n} {{\n\
                 \x20   type Output = {n};\n\
                 \x20   fn {method}(self, rhs: {n}) -> {n} {{\n\
                 \x20       {expr}\n\
                 \x20   }}\n\
                 }}\n\n"
            ));
        }
    };
    match spec.ops {
        OpSet::Core | OpSet::Fold | OpSet::Assign => {
            bin("Add", "add", add_e, false);
            bin("Mul", "mul", mul_e, false);
        }
        OpSet::ByRef => {
            bin("Add", "add", add_e, false);
            bin("Mul", "mul", mul_e, false);
            bin("Add", "add", add_e, true);
            bin("Mul", "mul", mul_e, true);
        }
    }
    match spec.ops {
        OpSet::Core => {
            let e = match body {
                Body::Correct => neg_e(spec, "self"),
                Body::EchoLhs => "self".to_string(),
                Body::Zero => zero_e(spec),
            };
            s.push_str(&format!(
                "impl std::ops::Neg for {n} {{\n\
                 \x20   type Output = {n};\n\
                 \x20   fn neg(self) -> {n} {{\n\
                 \x20       {e}\n\
                 \x20   }}\n\
                 }}\n"
            ));
        }
        OpSet::ByRef => {}
        OpSet::Assign => {
            for (tr, method, f) in [
                (
                    "AddAssign",
                    "add_assign",
                    add_e as fn(&Spec, &str, &str) -> String,
                ),
                ("MulAssign", "mul_assign", mul_e),
            ] {
                let stmt = match body {
                    Body::Correct => format!("*self = {};", f(spec, "(*self)", "rhs")),
                    Body::EchoLhs => "let _ = rhs;".to_string(),
                    Body::Zero => format!("let _ = rhs; *self = {};", zero_e(spec)),
                };
                s.push_str(&format!(
                    "impl std::ops::{tr} for {n} {{\n\
                     \x20   fn {method}(&mut self, rhs: {n}) {{\n\
                     \x20       {stmt}\n\
                     \x20   }}\n\
                     }}\n\n"
                ));
            }
        }
        OpSet::Fold => {
            for (tr, method, ident, f) in [
                (
                    "Sum",
                    "sum",
                    zero_e(spec),
                    add_e as fn(&Spec, &str, &str) -> String,
                ),
                ("Product", "product", one_e(spec), mul_e),
            ] {
                let e = match body {
                    Body::Correct => {
                        format!("iter.fold({ident}, |acc, x| {})", f(spec, "acc", "x"))
                    }
                    Body::EchoLhs => format!("iter.next().unwrap_or({ident})"),
                    Body::Zero => format!("{{ let _ = iter.count(); {} }}", zero_e(spec)),
                };
                let mut_kw = if body == Body::EchoLhs { "mut " } else { "" };
                s.push_str(&format!(
                    "impl std::iter::{tr} for {n} {{\n\
                     \x20   fn {method}<I: Iterator<Item = {n}>>({mut_kw}iter: I) -> {n} {{\n\
                     \x20       {e}\n\
                     \x20   }}\n\
                     }}\n\n"
                ));
            }
        }
    }
    s
}

fn reference_src(spec: &Spec) -> String {
    format!(
        "{}\n{}",
        prelude_src(spec),
        impls_src(spec, Body::Correct).trim_end()
    ) + "\n"
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "//! Implement the operator traits for `{name}` below. The type is provided — keep it.\n\
         //!\n\
         {doc}\n\
         {prelude}\n\
         // Your trait impls go here.\n",
        name = spec.name,
        prelude = prelude_src(spec),
        doc = examples
            .lines()
            .map(|l| format!("//! {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

// ---- worked examples --------------------------------------------------------

/// One operand triple and the (expression, expected) checks the op set exercises on it.
struct Case {
    abc: [V; 3],
    /// (test-code expression over `a`, `b`, `c` bindings, display text, expected value)
    checks: Vec<(String, String, V)>,
}

/// The canonical triple per algebra. It is constructed so every op's result differs from both
/// the left operand and the zero value under every modulus — the property both trivial
/// baselines need in order to fail on every seed (checked by a unit test).
fn canonical(spec: &Spec) -> [V; 3] {
    match spec.alg {
        Alg::Pair => [(3, 4), (5, 6), (2, 1)],
        Alg::Cplx => [(3, 4), (5, 6), (2, 1)],
        Alg::Mod => [(3, 0), (5, 0), (4, 0)],
        Alg::Sat => [(30, 0), (40, 0), (50, 0)],
    }
}

fn random_triple(spec: &Spec, rng: &mut Rng) -> [V; 3] {
    let mut draw = || -> V {
        match spec.alg {
            Alg::Pair | Alg::Cplx => (rng.below(19) as i64 - 9, rng.below(19) as i64 - 9),
            Alg::Mod => (rng.below(spec.m as u64) as i64, 0),
            Alg::Sat => (rng.below(161) as i64 - 80, 0),
        }
    };
    [draw(), draw(), draw()]
}

fn checks_for(spec: &Spec, [a, b, c]: [V; 3]) -> Vec<(String, String, V)> {
    let mut v: Vec<(String, String, V)> = Vec::new();
    let mut push =
        |expr: &str, text: &str, val: V| v.push((expr.to_string(), text.to_string(), val));
    match spec.ops {
        OpSet::Core => {
            push("a + b", "a + b", add(spec, a, b));
            push("a * b", "a * b", mul(spec, a, b));
            push("-a", "-a", neg(spec, a));
        }
        OpSet::ByRef => {
            push("a + b", "a + b", add(spec, a, b));
            push("&a + &b", "&a + &b", add(spec, a, b));
            push("&a * &b", "&a * &b", mul(spec, a, b));
            push("&c * &c", "&c * &c", mul(spec, c, c));
        }
        OpSet::Assign => {
            push(
                "{ let mut x = a; x += b; x }",
                "{ let mut x = a; x += b; x }",
                add(spec, a, b),
            );
            push(
                "{ let mut x = a; x *= b; x }",
                "{ let mut x = a; x *= b; x }",
                mul(spec, a, b),
            );
            push("a + b", "a + b", add(spec, a, b));
            push("a * b", "a * b", mul(spec, a, b));
        }
        OpSet::Fold => {
            let s = add(spec, add(spec, a, b), c);
            let p = mul(spec, mul(spec, a, b), c);
            push(
                "vec![a, b, c].into_iter().sum::<T>()",
                "[a, b, c].into_iter().sum::<T>()",
                s,
            );
            push(
                "vec![a, b, c].into_iter().product::<T>()",
                "[a, b, c].into_iter().product::<T>()",
                p,
            );
            push(
                "Vec::<T>::new().into_iter().sum::<T>()",
                "(empty).sum::<T>()",
                zero(spec),
            );
            push(
                "Vec::<T>::new().into_iter().product::<T>()",
                "(empty).product::<T>()",
                one(spec),
            );
        }
    }
    v
}

fn worked_examples(spec: &Spec, seed: u64) -> (String, Vec<Case>) {
    let mut rng = Rng::new(seed ^ 0x0905_0AE2_90E1_0C0D);
    let triples = vec![
        canonical(spec),
        random_triple(spec, &mut rng),
        random_triple(spec, &mut rng),
    ];
    let mut prose = String::new();
    let mut cases = Vec::new();
    for abc in triples {
        let checks = checks_for(spec, abc);
        prose.push_str(&format!(
            "  with a = {}, b = {}, c = {}:\n",
            lit(spec, abc[0]),
            lit(spec, abc[1]),
            lit(spec, abc[2])
        ));
        for (_, text, val) in &checks {
            prose.push_str(&format!(
                "    {} == {}\n",
                text.replace('T', spec.name),
                lit(spec, *val)
            ));
        }
        cases.push(Case { abc, checks });
    }
    (prose, cases)
}

fn ops_prose(spec: &Spec) -> &'static str {
    match spec.ops {
        OpSet::Core => "`std::ops::Add`, `std::ops::Mul` and `std::ops::Neg`, all by value",
        OpSet::ByRef => {
            "`std::ops::Add` and `std::ops::Mul`, both for `{T}` by value **and** for references, \
             so `a + b`, `&a + &b` and `&a * &b` all work (every form yields an owned `{T}`)"
        }
        OpSet::Assign => {
            "`std::ops::Add`, `std::ops::Mul`, `std::ops::AddAssign` and `std::ops::MulAssign`"
        }
        OpSet::Fold => {
            "`std::ops::Add`, `std::ops::Mul`, `std::iter::Sum` and `std::iter::Product`, so \
             `values.into_iter().sum::<{T}>()` and `.product::<{T}>()` work over an iterator of \
             owned `{T}`; the empty sum is the zero value and the empty product is the one value"
        }
    }
}

fn alg_prose(spec: &Spec) -> String {
    let n = spec.name;
    match spec.alg {
        Alg::Pair => format!(
            "`{n} {{ a, b }}` is a pair. `+` and `*` act **component-wise** \
             (`(a, b) * (c, d) = (a*c, b*d)`); `-x` negates each component. Zero is `(0, 0)`, \
             one is `(1, 1)`."
        ),
        Alg::Cplx => format!(
            "`{n} {{ a, b }}` is the complex number `a + b*i`. `+` is component-wise; `*` is \
             complex multiplication, `(a + bi)(c + di) = (ac - bd) + (ad + bc)i`; `-x` negates \
             each component. Zero is `(0, 0)`, one is `(1, 0)`."
        ),
        Alg::Mod => format!(
            "`{n}` is a residue modulo `MODULUS` ({m}), always kept in `0..MODULUS` — build values \
             with `{n}::new` (which reduces) and read them with `.val()`. `+` and `*` are modular; \
             `-x` is the additive inverse. Zero is `{n}::new(0)`, one is `{n}::new(1)`.",
            m = spec.m
        ),
        Alg::Sat => format!(
            "`{n}` is an integer saturated into `-LIMIT..=LIMIT` (`LIMIT` = {LIMIT}) — build values \
             with `{n}::new` (which clamps) and read them with `.val()`. `+` and `*` compute the \
             exact result and then clamp it; `-x` negates. Zero is `{n}::new(0)`, one is \
             `{n}::new(1)`."
        ),
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "Implement operator traits for the `{name}` type in `src/lib.rs`. The type (and, where \
         shown, its constructor) is already provided — keep it unchanged and add the `impl` \
         blocks.\n\
         \n\
         {alg}\n\
         \n\
         Implement {ops}.\n\
         \n\
         Constraints:\n\
         - Do not change the provided type, constants or methods.\n\
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
        name = spec.name,
        alg = alg_prose(spec),
        ops = ops_prose(spec).replace("{T}", spec.name),
        prelude = prelude_src(spec),
        examples = examples,
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
    let (_, cases) = worked_examples(spec, seed);
    let mut body = format!("use task::{};\n\n", spec.name);
    for (i, case) in cases.iter().enumerate() {
        body.push_str(&format!("#[test]\nfn ex{i}() {{\n"));
        for (var, v) in ["a", "b", "c"].iter().zip(case.abc.iter()) {
            body.push_str(&format!("    let {var} = {};\n", lit(spec, *v)));
        }
        for (expr, _, val) in &case.checks {
            let expr = expr.replace("::<T>", &format!("::<{}>", spec.name));
            body.push_str(&format!("    assert_eq!({expr}, {});\n", lit(spec, *val)));
        }
        body.push_str("}\n\n");
    }
    body
}

/// Replace the value-construction and key placeholders in a differential template.
fn fill(spec: &Spec, tpl: &str) -> String {
    let scale = if spec.alg == Alg::Sat { " * 12" } else { "" };
    tpl.replace("@N@", spec.name)
        .replace("@KEY@", key_fn(spec))
        .replace("@SCALE@", scale)
        .replace("@MK_T@", &mk(spec, "task::", "x", "y"))
        .replace("@MK_R@", &mk(spec, "reference::", "x", "y"))
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let head = format!(
        "mod reference {{\n{}}}\n\n\
         fn key_t(x: &task::@N@) -> (i64, i64) {{ @KEY@ }}\n\
         fn key_r(x: &reference::@N@) -> (i64, i64) {{ @KEY@ }}\n\
         fn mk_t(x: i64, y: i64) -> task::@N@ {{ @MK_T@ }}\n\
         fn mk_r(x: i64, y: i64) -> reference::@N@ {{ @MK_R@ }}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x0905_0DFF_E2E1_0001;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (((state >> 33) % 19) as i64 - 9) @SCALE@\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let (x1, y1, x2, y2, x3, y3) = (next(), next(), next(), next(), next(), next());\n\
         \x20       let (a, b, c) = (mk_t(x1, y1), mk_t(x2, y2), mk_t(x3, y3));\n\
         \x20       let (ra, rb, rc) = (mk_r(x1, y1), mk_r(x2, y2), mk_r(x3, y3));\n\
         \x20       let _ = (c, rc);\n",
        reference.lines().map(|l| format!("    {l}\n")).collect::<String>(),
    );
    let check = |t: &str, r: &str| {
        format!("        assert_eq!(key_t(&({t})), key_r(&({r})), \"{{x1}},{{y1}} {{x2}},{{y2}} {{x3}},{{y3}}\");\n")
    };
    let mut body = String::new();
    match spec.ops {
        OpSet::Core => {
            body.push_str(&check("a + b", "ra + rb"));
            body.push_str(&check("a * b", "ra * rb"));
            body.push_str(&check("-a", "-ra"));
        }
        OpSet::ByRef => {
            body.push_str(&check("a + b", "ra + rb"));
            body.push_str(&check("&a + &b", "&ra + &rb"));
            body.push_str(&check("&a * &b", "&ra * &rb"));
        }
        OpSet::Assign => {
            body.push_str(&check(
                "{ let mut t = a; t += b; t }",
                "{ let mut t = ra; t += rb; t }",
            ));
            body.push_str(&check(
                "{ let mut t = a; t *= b; t }",
                "{ let mut t = ra; t *= rb; t }",
            ));
            body.push_str(&check("a + b", "ra + rb"));
            body.push_str(&check("a * b", "ra * rb"));
        }
        OpSet::Fold => {
            body.push_str(
                "        let n = (x1.rem_euclid(5)) as usize;\n\
                 \x20       let tv: Vec<task::@N@> = [a, b, c, a, b].into_iter().take(n).collect();\n\
                 \x20       let rv: Vec<reference::@N@> = [ra, rb, rc, ra, rb].into_iter().take(n).collect();\n"
            );
            body.push_str(&check(
                "tv.clone().into_iter().sum::<task::@N@>()",
                "rv.clone().into_iter().sum::<reference::@N@>()",
            ));
            body.push_str(&check(
                "tv.into_iter().product::<task::@N@>()",
                "rv.into_iter().product::<reference::@N@>()",
            ));
            body.push_str(&check("a + b", "ra + rb"));
            body.push_str(&check("a * b", "ra * rb"));
        }
    }
    let tail = "    }\n}\n";
    // `@KEY@` carries a literal `x`, so substitute after assembling.
    fill(spec, &format!("{head}{body}{tail}"))
}

/// Degenerate: operators that return the left operand (assigns do nothing, folds return the
/// first element).
fn echo_lhs(spec: &Spec) -> String {
    format!(
        "{}\n{}",
        prelude_src(spec),
        impls_src(spec, Body::EchoLhs).trim_end()
    ) + "\n"
}

/// Degenerate: every operator returns the zero value.
fn all_zero(spec: &Spec) -> String {
    format!(
        "{}\n{}",
        prelude_src(spec),
        impls_src(spec, Body::Zero).trim_end()
    ) + "\n"
}

pub struct OpsOverloadFamily;

impl Generator for OpsOverloadFamily {
    fn id(&self) -> &str {
        "ops-overload"
    }
    fn category(&self) -> &str {
        "traits-generics"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("ops-overload", seed);

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
            id: format!("ops-overload/{seed:016x}"),
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
            // traits-generics uses docs/04 default weights (L1 + signature match emphasis).
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
            ("echo-lhs".to_string(), echo_lhs(&spec)),
            ("all-zero".to_string(), all_zero(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is (algebra, op set). The type name and the modulus are cosmetic (Q31).
        let spec = sample(seed);
        let alg = match spec.alg {
            Alg::Pair => "pair",
            Alg::Cplx => "cplx",
            Alg::Mod => "mod",
            Alg::Sat => "sat",
        };
        let ops = match spec.ops {
            OpSet::Core => "core",
            OpSet::ByRef => "byref",
            OpSet::Assign => "assign",
            OpSet::Fold => "fold",
        };
        vec![format!("alg:{alg}"), format!("ops:{ops}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(alg: Alg, ops: OpSet, m: i64) -> Spec {
        Spec {
            alg,
            ops,
            name: "T",
            m,
        }
    }

    const ALGS: [Alg; 4] = [Alg::Pair, Alg::Cplx, Alg::Mod, Alg::Sat];
    const OPSETS: [OpSet; 4] = [OpSet::Core, OpSet::ByRef, OpSet::Assign, OpSet::Fold];

    #[test]
    fn generation_is_deterministic() {
        let g = OpsOverloadFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn algebra_matches_intent() {
        let p = spec(Alg::Pair, OpSet::Core, 7);
        assert_eq!(add(&p, (3, 4), (5, 6)), (8, 10));
        assert_eq!(mul(&p, (3, 4), (5, 6)), (15, 24));
        assert_eq!(neg(&p, (3, 4)), (-3, -4));
        let c = spec(Alg::Cplx, OpSet::Core, 7);
        // (3 + 4i)(5 + 6i) = 15 - 24 + (18 + 20)i
        assert_eq!(mul(&c, (3, 4), (5, 6)), (-9, 38));
        assert_eq!(mul(&c, (0, 1), (0, 1)), (-1, 0), "i * i = -1");
        let m = spec(Alg::Mod, OpSet::Core, 7);
        assert_eq!(add(&m, (3, 0), (5, 0)), (1, 0));
        assert_eq!(mul(&m, (3, 0), (5, 0)), (1, 0));
        assert_eq!(neg(&m, (3, 0)), (4, 0));
        assert_eq!(neg(&m, (0, 0)), (0, 0), "-0 stays 0 mod M");
        let s = spec(Alg::Sat, OpSet::Core, 7);
        assert_eq!(add(&s, (70, 0), (70, 0)), (100, 0));
        assert_eq!(mul(&s, (-30, 0), (40, 0)), (-100, 0));
        assert_eq!(neg(&s, (100, 0)), (-100, 0));
    }

    #[test]
    fn identities_are_identities() {
        for &alg in &ALGS {
            let s = spec(alg, OpSet::Core, 11);
            for v in [(3, 4), (0, 0), (-5, 2)] {
                let v = norm(&s, v);
                assert_eq!(add(&s, v, zero(&s)), v, "{alg:?} x + 0");
                assert_eq!(mul(&s, v, one(&s)), v, "{alg:?} x * 1");
            }
        }
    }

    #[test]
    fn canonical_defeats_both_baselines_under_every_combination() {
        // echo-lhs returns the left operand (first element for folds); all-zero returns the zero
        // value. Both fail on every seed only if every checked result avoids both.
        for &alg in &ALGS {
            for &ops in &OPSETS {
                for &m in MODULI {
                    let s = spec(alg, ops, m);
                    let [a, b, c] = canonical(&s);
                    // (label, result, the left operand echo-lhs would return)
                    let results: Vec<(&str, V, V)> = match ops {
                        OpSet::Core => vec![
                            ("a+b", add(&s, a, b), a),
                            ("a*b", mul(&s, a, b), a),
                            ("-a", neg(&s, a), a),
                        ],
                        OpSet::ByRef => vec![
                            ("a+b", add(&s, a, b), a),
                            ("a*b", mul(&s, a, b), a),
                            ("c*c", mul(&s, c, c), c),
                        ],
                        OpSet::Assign => {
                            vec![("a+=b", add(&s, a, b), a), ("a*=b", mul(&s, a, b), a)]
                        }
                        OpSet::Fold => vec![
                            ("sum", add(&s, add(&s, a, b), c), a),
                            ("prod", mul(&s, mul(&s, a, b), c), a),
                        ],
                    };
                    for (label, r, lhs) in results {
                        let r = norm(&s, r);
                        assert_ne!(r, norm(&s, lhs), "{alg:?}/{ops:?}/{m} {label} == lhs");
                        assert_ne!(r, zero(&s), "{alg:?}/{ops:?}/{m} {label} == zero");
                    }
                }
            }
        }
    }

    #[test]
    fn seeds_vary_both_axes() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..200u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.alg, s.ops));
        }
        assert_eq!(variants.len(), 16);
    }

    #[test]
    fn skeleton_has_the_type_but_no_impls_and_reference_has_them() {
        let g = OpsOverloadFamily;
        for seed in 0..40u64 {
            let sk = g.skeleton_code(seed);
            let s = sample(seed);
            assert!(sk.contains(&format!("pub struct {}", s.name)));
            assert!(!sk.contains("impl std::ops") && !sk.contains("impl std::iter"));
            let r = g.reference_code(seed);
            assert!(r.contains("impl std::ops::Add for") || r.contains("impl std::ops::Add<"));
        }
    }

    #[test]
    fn by_ref_set_emits_reference_impls_and_others_do_not() {
        for &ops in &OPSETS {
            let src = impls_src(&spec(Alg::Pair, ops, 7), Body::Correct);
            assert_eq!(src.contains("for &'a T"), ops == OpSet::ByRef, "{ops:?}");
        }
    }

    #[test]
    fn examples_use_the_provided_constructor_for_residue_algebras() {
        let t = OpsOverloadFamily.generate(2);
        // Whatever the seed picks, literals in the tests must be buildable from the prelude.
        let s = sample(2);
        let b = &t.hidden[&PathBuf::from("tests/behavior.rs")];
        match s.alg {
            Alg::Mod | Alg::Sat => assert!(b.contains("::new(")),
            _ => assert!(b.contains(" { a: ")),
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let t = OpsOverloadFamily.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

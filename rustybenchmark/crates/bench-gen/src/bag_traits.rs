//! The `bag-traits` family (category `traits-generics`) — implement the std **collection traits**
//! for a generic container, including the `type IntoIter = ...` associated type.
//!
//! A pinned `Bag<T>` owns a `Vec<T>` and offers `new`, `push`, `len`, `items`. The model implements
//! three of five collection traits, chosen by seed:
//!
//! * `IntoIterator for Bag<T>` (by value), `IntoIterator for &'a Bag<T>` and
//!   `IntoIterator for &'a mut Bag<T>` — three impls with three different `Item` types and three
//!   different iterator types, two of them carrying a lifetime;
//! * `FromIterator<T> for Bag<T>` (`collect::<Bag<_>>()`);
//! * `Extend<T> for Bag<T>`.
//!
//! The iteration order is the second axis, and it is what makes the `IntoIter` associated type
//! worth testing: **forward** (`std::vec::IntoIter<T>`, `std::slice::Iter<'a, T>`,
//! `std::slice::IterMut<'a, T>`), **reverse** (the same wrapped in `std::iter::Rev<..>`) or **every
//! other element** (wrapped in `std::iter::StepBy<..>`). On stable Rust `type IntoIter = impl
//! Iterator` is not available, so the adapter type must be spelled out. The `&mut` form makes the
//! order observable in the data: `for x in &mut bag { *x += 1 }` under `StepBy` touches only every
//! other element.
//!
//! 10 form sets x 3 orders = **30 distinct skills**. Solution-first (ADR-0003): the native order
//! function and the emitted adapters are mirrored, and the differential compares each present form
//! against an inlined reference module on 3000 random vectors. Default traits-generics weights.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Form {
    Owned,
    ByRef,
    ByMut,
    FromIter,
    Extend,
}

const ALL_FORMS: [Form; 5] = [
    Form::Owned,
    Form::ByRef,
    Form::ByMut,
    Form::FromIter,
    Form::Extend,
];

#[derive(Clone, Copy, Debug, PartialEq)]
enum Order {
    Forward,
    Reverse,
    StepBy,
}

impl Order {
    fn next(self) -> Order {
        match self {
            Order::Forward => Order::Reverse,
            Order::Reverse => Order::StepBy,
            Order::StepBy => Order::Forward,
        }
    }
}

struct Spec {
    forms: Vec<Form>,
    order: Order,
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let mut idx = [0usize, 1, 2, 3, 4];
    for i in 0..3 {
        let j = i + rng.below((5 - i) as u64) as usize;
        idx.swap(i, j);
    }
    let mut forms: Vec<Form> = idx[..3].iter().map(|&i| ALL_FORMS[i]).collect();
    forms.sort();
    let order = match rng.below(3) {
        0 => Order::Forward,
        1 => Order::Reverse,
        _ => Order::StepBy,
    };
    Spec { forms, order }
}

// ---- native model -------------------------------------------------------------------------

/// The *indices* an iteration visits, in visiting order, over `n` items.
fn visit(order: Order, n: usize) -> Vec<usize> {
    match order {
        Order::Forward => (0..n).collect(),
        Order::Reverse => (0..n).rev().collect(),
        Order::StepBy => (0..n).step_by(2).collect(),
    }
}

// ---- emitted source ----------------------------------------------------------------------------

const PRELUDE: &str = "pub struct Bag<T> {\n\
    \x20   items: Vec<T>,\n\
    }\n\
    \n\
    impl<T> Bag<T> {\n\
    \x20   pub fn new() -> Bag<T> {\n\
    \x20       Bag { items: Vec::new() }\n\
    \x20   }\n\
    \n\
    \x20   pub fn push(&mut self, v: T) {\n\
    \x20       self.items.push(v);\n\
    \x20   }\n\
    \n\
    \x20   pub fn len(&self) -> usize {\n\
    \x20       self.items.len()\n\
    \x20   }\n\
    \n\
    \x20   pub fn is_empty(&self) -> bool {\n\
    \x20       self.items.is_empty()\n\
    \x20   }\n\
    \n\
    \x20   pub fn items(&self) -> &[T] {\n\
    \x20       &self.items\n\
    \x20   }\n\
    }\n\
    \n\
    impl<T> Default for Bag<T> {\n\
    \x20   fn default() -> Self {\n\
    \x20       Bag::new()\n\
    \x20   }\n\
    }\n";

/// Wrap an iterator type in the order's adapter.
fn wrap_ty(order: Order, inner: &str) -> String {
    match order {
        Order::Forward => inner.to_string(),
        Order::Reverse => format!("std::iter::Rev<{inner}>"),
        Order::StepBy => format!("std::iter::StepBy<{inner}>"),
    }
}

fn wrap_expr(order: Order, inner: &str) -> String {
    match order {
        Order::Forward => inner.to_string(),
        Order::Reverse => format!("{inner}.rev()"),
        Order::StepBy => format!("{inner}.step_by(2)"),
    }
}

/// How an impl's body is written.
#[derive(Clone, Copy, PartialEq)]
enum Body {
    Correct,
    Empty,
}

fn form_src(form: Form, order: Order, body: Body) -> String {
    let empty = body == Body::Empty;
    match form {
        Form::Owned => {
            let (ty, expr) = if empty {
                (
                    "std::iter::Empty<T>".to_string(),
                    "{ let _ = self; std::iter::empty() }".to_string(),
                )
            } else {
                (
                    wrap_ty(order, "std::vec::IntoIter<T>"),
                    wrap_expr(order, "self.items.into_iter()"),
                )
            };
            format!("impl<T> IntoIterator for Bag<T> {{\n    type Item = T;\n    type IntoIter = {ty};\n\n    fn into_iter(self) -> Self::IntoIter {{\n        {expr}\n    }}\n}}\n")
        }
        Form::ByRef => {
            let (ty, expr) = if empty {
                (
                    "std::iter::Empty<&'a T>".to_string(),
                    "{ let _ = self; std::iter::empty() }".to_string(),
                )
            } else {
                (
                    wrap_ty(order, "std::slice::Iter<'a, T>"),
                    wrap_expr(order, "self.items.iter()"),
                )
            };
            format!("impl<'a, T> IntoIterator for &'a Bag<T> {{\n    type Item = &'a T;\n    type IntoIter = {ty};\n\n    fn into_iter(self) -> Self::IntoIter {{\n        {expr}\n    }}\n}}\n")
        }
        Form::ByMut => {
            let (ty, expr) = if empty {
                (
                    "std::iter::Empty<&'a mut T>".to_string(),
                    "{ let _ = self; std::iter::empty() }".to_string(),
                )
            } else {
                (
                    wrap_ty(order, "std::slice::IterMut<'a, T>"),
                    wrap_expr(order, "self.items.iter_mut()"),
                )
            };
            format!("impl<'a, T> IntoIterator for &'a mut Bag<T> {{\n    type Item = &'a mut T;\n    type IntoIter = {ty};\n\n    fn into_iter(self) -> Self::IntoIter {{\n        {expr}\n    }}\n}}\n")
        }
        Form::FromIter => {
            let inner = if empty {
                "let _ = iter;\n        Bag::new()"
            } else {
                "let mut bag = Bag::new();\n        for x in iter {\n            bag.push(x);\n        }\n        bag"
            };
            format!("impl<T> FromIterator<T> for Bag<T> {{\n    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {{\n        {inner}\n    }}\n}}\n")
        }
        Form::Extend => {
            let inner = if empty {
                "let _ = iter;"
            } else {
                "for x in iter {\n            self.push(x);\n        }"
            };
            format!("impl<T> Extend<T> for Bag<T> {{\n    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {{\n        {inner}\n    }}\n}}\n")
        }
    }
}

fn file_src(spec: &Spec, order: Order, body: Body) -> String {
    let impls: Vec<String> = spec
        .forms
        .iter()
        .map(|&f| form_src(f, order, body))
        .collect();
    format!("{PRELUDE}\n{}", impls.join("\n"))
}

fn reference_src(spec: &Spec) -> String {
    file_src(spec, spec.order, Body::Correct)
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .1
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Implement the three collection traits for `Bag<T>` below. The type is provided — keep it.\n//!\n{doc}\n{PRELUDE}\n// Your impls go here.\n"
    )
}

// ---- examples ----------------------------------------------------------------------------------

fn canonical() -> Vec<i64> {
    vec![10, 20, 30, 40, 50]
}

fn worked_examples(spec: &Spec, seed: u64) -> (Vec<Vec<i64>>, String) {
    let mut rng = Rng::new(seed ^ 0xBA6F_0000_0000_0C11);
    let mut cases = vec![canonical()];
    for _ in 0..4 {
        let n = 3 + rng.below(6) as usize;
        cases.push((0..n).map(|_| rng.below(90) as i64 + 1).collect());
    }
    let mut prose = String::new();
    for c in &cases {
        for &f in &spec.forms {
            let line = match f {
                Form::Owned => format!(
                    "bag of {c:?} -> `bag.into_iter().collect::<Vec<_>>()` == {:?}",
                    visit(spec.order, c.len())
                        .iter()
                        .map(|&i| c[i])
                        .collect::<Vec<_>>()
                ),
                Form::ByRef => format!(
                    "bag of {c:?} -> `(&bag).into_iter().copied().collect::<Vec<_>>()` == {:?}",
                    visit(spec.order, c.len())
                        .iter()
                        .map(|&i| c[i])
                        .collect::<Vec<_>>()
                ),
                Form::ByMut => {
                    let mut after = c.clone();
                    for (rank, i) in visit(spec.order, c.len()).into_iter().enumerate() {
                        after[i] += rank as i64 + 1;
                    }
                    format!("bag of {c:?} -> `let mut k = 0; for x in &mut bag {{ k += 1; *x += k; }}` leaves `bag.items()` == {after:?}")
                }
                Form::FromIter => {
                    format!("`{c:?}.into_iter().collect::<Bag<i64>>().items()` == {c:?}")
                }
                Form::Extend => {
                    format!("an empty bag after `bag.extend({c:?})` has `items()` == {c:?}")
                }
            };
            prose.push_str(&format!("  {line}\n"));
        }
    }
    (cases, prose)
}

fn order_prose(order: Order) -> &'static str {
    match order {
        Order::Forward => "in **insertion order**",
        Order::Reverse => "in **reverse insertion order** (last pushed first)",
        Order::StepBy => "over **every other element** starting with the first (indices 0, 2, 4, …), in insertion order",
    }
}

fn form_prose(f: Form) -> &'static str {
    match f {
        Form::Owned => "`impl IntoIterator for Bag<T>` — consuming iteration, `Item = T`",
        Form::ByRef => "`impl<'a, T> IntoIterator for &'a Bag<T>` — `Item = &'a T`",
        Form::ByMut => "`impl<'a, T> IntoIterator for &'a mut Bag<T>` — `Item = &'a mut T`",
        Form::FromIter => "`impl<T> FromIterator<T> for Bag<T>` — `collect::<Bag<_>>()` pushes the items in iteration order",
        Form::Extend => "`impl<T> Extend<T> for Bag<T>` — pushes each item in iteration order",
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let forms: String = spec
        .forms
        .iter()
        .map(|&f| format!("  - {}\n", form_prose(f)))
        .collect();
    let (_, examples) = worked_examples(spec, seed);
    format!(
        "Implement these standard-library collection traits for `Bag<T>` in `src/lib.rs`. `Bag<T>` (with `new`, `push`, \
         `len`, `is_empty`, `items`) is provided — keep it unchanged.\n\
         \n\
         {forms}\
         \n\
         Every `IntoIterator` form you implement iterates {order}. On stable Rust you must spell the `type IntoIter = ...` \
         associated type out (for example `std::slice::Iter<'a, T>` wrapped in the adapter that gives that order); \
         `FromIterator` and `Extend` are unaffected by the order.\n\
         \n\
         Constraints:\n\
         - Do not change `Bag`. Do not use `unsafe`.\n\
         \n\
         Provided in `src/lib.rs`:\n\
         ```rust\n\
         {PRELUDE}```\n\
         \n\
         Examples (`i64` items):\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        order = order_prose(spec.order),
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

fn bag_expr(c: &[i64]) -> String {
    format!("{{ let mut b = Bag::new(); for &x in &{c:?} {{ b.push(x); }} b }}")
}

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let (cases, _) = worked_examples(spec, seed);
    let mut body = String::from("use task::Bag;\n\n");
    for (i, c) in cases.iter().enumerate() {
        let order_items: Vec<i64> = visit(spec.order, c.len()).iter().map(|&k| c[k]).collect();
        body.push_str(&format!("#[test]\nfn case{i}() {{\n"));
        for &f in &spec.forms {
            match f {
                Form::Owned => body.push_str(&format!(
                    "    let bag = {};\n    let v: Vec<i64> = bag.into_iter().collect();\n    assert_eq!(v, {order_items:?});\n    let bag = {};\n    let mut sum = 0;\n    for x in bag {{\n        sum += x;\n    }}\n    assert_eq!(sum, {});\n",
                    bag_expr(c), bag_expr(c), order_items.iter().sum::<i64>()
                )),
                Form::ByRef => body.push_str(&format!(
                    "    let bag = {};\n    let v: Vec<&i64> = (&bag).into_iter().collect();\n    assert_eq!(v, {order_items:?}.iter().collect::<Vec<_>>());\n    let mut sum = 0;\n    for x in &bag {{\n        sum += *x;\n    }}\n    assert_eq!(sum, {});\n    assert_eq!(bag.len(), {});\n",
                    bag_expr(c), order_items.iter().sum::<i64>(), c.len()
                )),
                Form::ByMut => {
                    let mut after = c.clone();
                    for (rank, k) in visit(spec.order, c.len()).into_iter().enumerate() {
                        after[k] += rank as i64 + 1;
                    }
                    body.push_str(&format!(
                        "    let mut bag = {};\n    let mut k = 0;\n    for x in &mut bag {{\n        k += 1;\n        *x += k;\n    }}\n    assert_eq!(bag.items(), &{after:?}[..]);\n",
                        bag_expr(c)
                    ));
                }
                Form::FromIter => body.push_str(&format!(
                    "    let b: Bag<i64> = {c:?}.into_iter().collect();\n    assert_eq!(b.items(), &{c:?}[..]);\n    let s: Bag<String> = [\"x\", \"y\"].iter().map(|s| s.to_string()).collect();\n    assert_eq!(s.items(), &[\"x\".to_string(), \"y\".to_string()][..]);\n"
                )),
                Form::Extend => body.push_str(&format!(
                    "    let mut b: Bag<i64> = Bag::new();\n    b.extend({c:?});\n    assert_eq!(b.items(), &{c:?}[..]);\n    b.extend(vec![0, 0]);\n    assert_eq!(b.len(), {});\n",
                    c.len() + 2
                )),
            }
        }
        body.push_str("}\n\n");
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    let mut checks = String::new();
    for &f in &spec.forms {
        let line = match f {
            Form::Owned => "assert_eq!(mk_t(&v).into_iter().collect::<Vec<i64>>(), mk_r(&v).into_iter().collect::<Vec<i64>>());",
            Form::ByRef => "assert_eq!((&mk_t(&v)).into_iter().copied().collect::<Vec<i64>>(), (&mk_r(&v)).into_iter().copied().collect::<Vec<i64>>());",
            Form::ByMut => "{ let (mut a, mut b) = (mk_t(&v), mk_r(&v)); let (mut ka, mut kb) = (0, 0); for x in &mut a { ka += 1; *x += ka; } for x in &mut b { kb += 1; *x += kb; } assert_eq!(a.items(), b.items()); }",
            Form::FromIter => "assert_eq!(v.iter().copied().collect::<task::Bag<i64>>().items(), v.iter().copied().collect::<reference::Bag<i64>>().items());",
            Form::Extend => "{ let (mut a, mut b) = (task::Bag::new(), reference::Bag::new()); a.extend(v.clone()); b.extend(v.clone()); assert_eq!(a.items(), b.items()); }",
        };
        checks.push_str(&format!("        {line}\n"));
    }
    format!(
        "mod reference {{\n{indented}}}\n\n\
         fn mk_t(v: &[i64]) -> task::Bag<i64> {{\n    let mut b = task::Bag::new();\n    for &x in v {{\n        b.push(x);\n    }}\n    b\n}}\n\n\
         fn mk_r(v: &[i64]) -> reference::Bag<i64> {{\n    let mut b = reference::Bag::new();\n    for &x in v {{\n        b.push(x);\n    }}\n    b\n}}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xBA6F_ED00_0000_0053;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = (next() % 9) as usize;\n\
         \x20       let v: Vec<i64> = (0..n).map(|_| (next() % 100) as i64).collect();\n\
         {checks}\
         \x20   }}\n\
         }}\n"
    )
}

/// Degenerate: every iteration is empty and `FromIterator` / `Extend` do nothing.
fn empty(spec: &Spec) -> String {
    file_src(spec, spec.order, Body::Empty)
}

/// Degenerate: correct impls for the *wrong* order (the next one cyclically).
fn wrong_order(spec: &Spec) -> String {
    file_src(spec, spec.order.next(), Body::Correct)
}

pub struct BagTraitsFamily;

impl Generator for BagTraitsFamily {
    fn id(&self) -> &str {
        "bag-traits"
    }
    fn category(&self) -> &str {
        "traits-generics"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("bag-traits", seed);

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
            id: format!("bag-traits/{seed:016x}"),
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
            ("empty".to_string(), empty(&spec)),
            ("wrong-order".to_string(), wrong_order(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let forms: Vec<&str> = spec
            .forms
            .iter()
            .map(|f| match f {
                Form::Owned => "owned",
                Form::ByRef => "ref",
                Form::ByMut => "mut",
                Form::FromIter => "from_iter",
                Form::Extend => "extend",
            })
            .collect();
        let order = match spec.order {
            Order::Forward => "forward",
            Order::Reverse => "reverse",
            Order::StepBy => "step_by",
        };
        vec![
            format!("forms:{}", forms.join("+")),
            format!("order:{order}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = BagTraitsFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn visit_orders_match_intent() {
        assert_eq!(visit(Order::Forward, 5), vec![0, 1, 2, 3, 4]);
        assert_eq!(visit(Order::Reverse, 5), vec![4, 3, 2, 1, 0]);
        assert_eq!(visit(Order::StepBy, 5), vec![0, 2, 4]);
        assert_eq!(visit(Order::StepBy, 0), Vec::<usize>::new());
    }

    #[test]
    fn the_wrong_order_baseline_differs_on_the_canonical_items() {
        // wrong-order fails on every seed iff each order gives a different canonical sequence.
        let c = canonical();
        let seqs: Vec<Vec<i64>> = [Order::Forward, Order::Reverse, Order::StepBy]
            .iter()
            .map(|&o| visit(o, c.len()).iter().map(|&i| c[i]).collect())
            .collect();
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    assert_ne!(seqs[i], seqs[j]);
                }
            }
        }
        // And the order axis is observable by the forms: Owned/ByRef/ByMut see it; FromIter/Extend
        // do not, so a spec with only those two forms plus one iterator form is still sensitive.
        for seed in 0..200u64 {
            let s = sample(seed);
            assert!(
                s.forms
                    .iter()
                    .any(|f| matches!(f, Form::Owned | Form::ByRef | Form::ByMut)),
                "seed {seed}: no iterator form, wrong-order cannot be caught"
            );
        }
    }

    /// What the canonical behaviour tests can see of a form under an order.
    fn observation(f: Form, order: Order) -> Vec<i64> {
        let c = canonical();
        match f {
            Form::Owned | Form::ByRef => visit(order, c.len()).iter().map(|&i| c[i]).collect(),
            Form::ByMut => {
                let mut after = c.clone();
                for (rank, i) in visit(order, c.len()).into_iter().enumerate() {
                    after[i] += rank as i64 + 1;
                }
                after
            }
            Form::FromIter | Form::Extend => c,
        }
    }

    #[test]
    fn wrong_order_is_observable_under_every_form_set() {
        for seed in 0..400u64 {
            let s = sample(seed);
            let seen = |o: Order| -> Vec<Vec<i64>> {
                s.forms.iter().map(|&f| observation(f, o)).collect()
            };
            assert_ne!(
                seen(s.order),
                seen(s.order.next()),
                "seed {seed}: {:?} {:?}",
                s.forms,
                s.order
            );
        }
    }

    #[test]
    fn the_adapter_types_follow_the_order() {
        let r = form_src(Form::ByRef, Order::Reverse, Body::Correct);
        assert!(r.contains("std::iter::Rev<std::slice::Iter<'a, T>>") && r.contains(".rev()"));
        let s = form_src(Form::ByMut, Order::StepBy, Body::Correct);
        assert!(
            s.contains("std::iter::StepBy<std::slice::IterMut<'a, T>>")
                && s.contains(".step_by(2)")
        );
        let f = form_src(Form::Owned, Order::Forward, Body::Correct);
        assert!(f.contains("type IntoIter = std::vec::IntoIter<T>;"));
    }

    #[test]
    fn seeds_vary_both_axes() {
        let mut s = std::collections::HashSet::new();
        for seed in 0..800u64 {
            s.insert(BagTraitsFamily.spec_signature(seed).join("|"));
        }
        assert_eq!(s.len(), 30);
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let t = BagTraitsFamily.generate(10);
        assert!(t.prompt.contains(&t.canary));
    }
}

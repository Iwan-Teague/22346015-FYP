//! The `expr-tree` family (category `pattern-matching`) — the second
//! pattern-matching family.
//!
//! Where `stack-machine` matches flatly over a `Vec<Op>` program driving a stack,
//! this family matches **recursively over a boxed expression tree** — structural
//! recursion through `Box<Expr>` children, the other half of Rust pattern
//! matching (nested destructuring plus ownership of the boxed spine). The model
//! implements `pub fn {name}(e: &Expr) -> i64` evaluating a small arithmetic AST,
//! whose **variant set is pruned by seed**: two of four binary operators and two
//! of three unary operators are selected, so the very enum the model must match
//! over differs per seed (the enum is provided and pinned, like `error-handling`'s
//! error type — semantics live in the variant names, plumbing is the task).
//!
//! C(4,2) × C(3,2) = **18 distinct skills**, the authoritative diversity measure
//! (Q31); the function name is cosmetic and there are no numeric constants — both
//! excluded from `spec_signature`. Solution-first and correct-by-construction
//! (ADR-0003): native `eval` (which knows *all eight* variants) and the emitted
//! reference are renderings of the same fold; the differential fuzzes 3000 random
//! trees against the model.
//!
//! Overflow-safe by construction: leaves are bounded (-9..=9, never zero in
//! fuzzed trees), unary operators are Neg/Abs/Double only (no Square, so values
//! cannot compound exponentially), and fuzzed trees have ≤7 nodes — worst case
//! magnitude stays in the tens of thousands, far from `i64` limits even in debug.
//!
//! Trivial baselines: `const-zero` and a `first-val` cheat (return the leaf if
//! the root happens to be one, 0 otherwise). Both fail on every seed because the
//! canonical example is a compound tree whose value is provably non-zero under
//! all 18 operator combinations (pinned).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Binary-operator menu — two of these four are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Max,
}

/// Unary-operator menu — two of these three are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq)]
enum UnOp {
    Neg,
    Abs,
    Double,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Spec {
    bins: [BinOp; 2],
    uns: [UnOp; 2],
    fn_name: &'static str,
}

const BIN_ALL: [BinOp; 4] = [BinOp::Add, BinOp::Sub, BinOp::Mul, BinOp::Max];
const UN_ALL: [UnOp; 3] = [UnOp::Neg, UnOp::Abs, UnOp::Double];

const NAMES: &[&str] = &[
    "eval",
    "value",
    "evaluate",
    "expr_value",
    "eval_tree",
    "interpret",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    // Deterministic 2-of-4 and 2-of-3 selections without replacement.
    let i1 = rng.below(4);
    let mut i2 = rng.below(4);
    while i2 == i1 {
        i2 = rng.below(4);
    }
    let bins = [BIN_ALL[i1 as usize], BIN_ALL[i2 as usize]];
    let j1 = rng.below(3);
    let mut j2 = rng.below(3);
    while j2 == j1 {
        j2 = rng.below(3);
    }
    let uns = [UN_ALL[j1 as usize], UN_ALL[j2 as usize]];
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec { bins, uns, fn_name }
}

// ---- native mirror tree (knows ALL variants; spec only prunes emission) ----

/// The native counterpart of the emitted `Expr`. Every variant that can ever be
/// emitted has a home here, so one compiled `eval` serves every spec.
#[derive(Clone, Debug, PartialEq)]
enum Tree {
    Val(i64),
    Neg(Box<Tree>),
    Abs(Box<Tree>),
    Double(Box<Tree>),
    Add(Box<Tree>, Box<Tree>),
    Sub(Box<Tree>, Box<Tree>),
    Mul(Box<Tree>, Box<Tree>),
    Max(Box<Tree>, Box<Tree>),
}

fn un_apply(op: UnOp, x: i64) -> i64 {
    match op {
        UnOp::Neg => -x,
        UnOp::Abs => x.abs(),
        UnOp::Double => x * 2,
    }
}

fn bin_apply(op: BinOp, a: i64, b: i64) -> i64 {
    match op {
        BinOp::Add => a + b,
        BinOp::Sub => a - b,
        BinOp::Mul => a * b,
        BinOp::Max => a.max(b),
    }
}

/// The answer: fold the tree. Source of truth for the emitted reference.
/// Operator semantics live in `bin_apply`/`un_apply` alone — this fold only
/// walks, so the native mirror and every emitted reference agree by
/// construction rather than by duplicated match arms.
fn eval_tree(t: &Tree) -> i64 {
    match t {
        Tree::Val(v) => *v,
        Tree::Neg(x) => un_apply(UnOp::Neg, eval_tree(x)),
        Tree::Abs(x) => un_apply(UnOp::Abs, eval_tree(x)),
        Tree::Double(x) => un_apply(UnOp::Double, eval_tree(x)),
        Tree::Add(a, b) => bin_apply(BinOp::Add, eval_tree(a), eval_tree(b)),
        Tree::Sub(a, b) => bin_apply(BinOp::Sub, eval_tree(a), eval_tree(b)),
        Tree::Mul(a, b) => bin_apply(BinOp::Mul, eval_tree(a), eval_tree(b)),
        Tree::Max(a, b) => bin_apply(BinOp::Max, eval_tree(a), eval_tree(b)),
    }
}

// ---- shared emitted-source fragments --------------------------------------

/// Variant name as it appears in the emitted enum and patterns.
fn un_variant(op: UnOp) -> &'static str {
    match op {
        UnOp::Neg => "Neg",
        UnOp::Abs => "Abs",
        UnOp::Double => "Double",
    }
}

fn bin_variant(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "Add",
        BinOp::Sub => "Sub",
        BinOp::Mul => "Mul",
        BinOp::Max => "Max",
    }
}

/// The unary arm body over the recursive call `{name}(x)`.
fn un_arm_expr(op: UnOp, name: &str) -> String {
    match op {
        UnOp::Neg => format!("-{name}(x)"),
        UnOp::Abs => format!("{name}(x).abs()"),
        UnOp::Double => format!("{name}(x) * 2"),
    }
}

/// The binary arm body over the two recursive calls.
fn bin_arm_expr(op: BinOp, name: &str) -> String {
    match op {
        BinOp::Add => format!("{name}(a) + {name}(b)"),
        BinOp::Sub => format!("{name}(a) - {name}(b)"),
        BinOp::Mul => format!("{name}(a) * {name}(b)"),
        BinOp::Max => format!("{name}(a).max({name}(b))"),
    }
}

fn un_prose(op: UnOp) -> &'static str {
    match op {
        UnOp::Neg => "the negation of its child",
        UnOp::Abs => "the absolute value of its child",
        UnOp::Double => "twice its child's value",
    }
}

fn bin_prose(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "the sum of its children",
        BinOp::Sub => "the first child minus the second",
        BinOp::Mul => "the product of its children",
        BinOp::Max => "the larger of its children",
    }
}

/// The seed-pruned enum, emitted verbatim into the skeleton, reference,
/// behavior test, differential and both baselines.
fn enum_src(spec: &Spec) -> String {
    let mut lines = String::from(
        "#[derive(Debug, Clone, PartialEq)]\n\
         pub enum Expr {\n\
         \x20   Val(i64),\n",
    );
    for u in spec.uns {
        lines.push_str(&format!("    {}(Box<Expr>),\n", un_variant(u)));
    }
    for b in spec.bins {
        lines.push_str(&format!("    {}(Box<Expr>, Box<Expr>),\n", bin_variant(b)));
    }
    lines.push_str("}\n");
    lines
}

// ---- the idiomatic reference (the answer) ---------------------------------

fn reference_src(spec: &Spec) -> String {
    let name = spec.fn_name;
    let mut arms = String::new();
    arms.push_str("        Expr::Val(v) => *v,\n");
    for u in spec.uns {
        arms.push_str(&format!(
            "        Expr::{}(x) => {},\n",
            un_variant(u),
            un_arm_expr(u, name)
        ));
    }
    for b in spec.bins {
        arms.push_str(&format!(
            "        Expr::{}(a, b) => {},\n",
            bin_variant(b),
            bin_arm_expr(b, name)
        ));
    }
    format!(
        "{enum_src}\n\
         pub fn {name}(e: &Expr) -> i64 {{\n\
         \x20   match e {{\n\
         {arms}\
         \x20   }}\n\
         }}\n",
        enum_src = enum_src(spec),
        name = name,
        arms = arms,
    )
}

// ---- worked examples ------------------------------------------------------

/// A leaf with a non-zero magnitude, signed by `rng`.
fn rand_leaf(rng: &mut Rng) -> Tree {
    let mag = 1 + rng.below(9) as i64; // 1..=9
    let v = if rng.below(2) == 0 { mag } else { -mag };
    Tree::Val(v)
}

/// Build one canonical tree exercising BOTH selected binops, BOTH selected
/// unops, and `Val`: `B1( U1( B2( U2(Val(1)), Val(3) ) ), Val(7) )`.
///
/// The inner value `X` ranges over ±1..±6, ±8, ±10, ±12 across every operator
/// combination — never 0 and never ±7 — so the whole tree is non-zero whether
/// `B1` is Add (needs X=-7), Sub (X=7), Mul (X=0) or Max (never zero).
fn canonical_tree(spec: &Spec) -> Tree {
    let (b1, b2) = (spec.bins[0], spec.bins[1]);
    let (u1, u2) = (spec.uns[0], spec.uns[1]);
    let wrap_un = |op: UnOp, t: Tree| match op {
        UnOp::Neg => Tree::Neg(Box::new(t)),
        UnOp::Abs => Tree::Abs(Box::new(t)),
        UnOp::Double => Tree::Double(Box::new(t)),
    };
    let wrap_bin = |op: BinOp, a: Tree, b: Tree| match op {
        BinOp::Add => Tree::Add(Box::new(a), Box::new(b)),
        BinOp::Sub => Tree::Sub(Box::new(a), Box::new(b)),
        BinOp::Mul => Tree::Mul(Box::new(a), Box::new(b)),
        BinOp::Max => Tree::Max(Box::new(a), Box::new(b)),
    };
    let inner = wrap_bin(b2, wrap_un(u2, Tree::Val(1)), Tree::Val(3));
    wrap_bin(b1, wrap_un(u1, inner), Tree::Val(7))
}

/// Random tree from the allowed variants. Depth-limited; unary chains are capped
/// at length 2 so values stay tiny.
fn rand_tree(spec: &Spec, rng: &mut Rng, depth: u32, un_chain: u32) -> Tree {
    if depth == 0 {
        return rand_leaf(rng);
    }
    // Weights: leaf-ish 4, unop 2 (unless chain too deep), binop 3.
    let roll = rng.below(9);
    if roll < 4 {
        rand_leaf(rng)
    } else if roll < 6 && un_chain < 2 {
        let op = spec.uns[rng.below(2) as usize];
        let child = rand_tree(spec, rng, depth - 1, un_chain + 1);
        match op {
            UnOp::Neg => Tree::Neg(Box::new(child)),
            UnOp::Abs => Tree::Abs(Box::new(child)),
            UnOp::Double => Tree::Double(Box::new(child)),
        }
    } else if roll < 6 {
        rand_leaf(rng)
    } else {
        let op = spec.bins[rng.below(2) as usize];
        let a = rand_tree(spec, rng, depth - 1, 0);
        let b = rand_tree(spec, rng, depth - 1, 0);
        match op {
            BinOp::Add => Tree::Add(Box::new(a), Box::new(b)),
            BinOp::Sub => Tree::Sub(Box::new(a), Box::new(b)),
            BinOp::Mul => Tree::Mul(Box::new(a), Box::new(b)),
            BinOp::Max => Tree::Max(Box::new(a), Box::new(b)),
        }
    }
}

type ExampleCase = (Tree, i64);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0031);
    let mut out: Vec<ExampleCase> = vec![{
        let t = canonical_tree(spec);
        let out = eval_tree(&t);
        (t, out)
    }];
    for _ in 0..3 {
        let depth = 1 + rng.below(3) as u32; // 1..=3
        let t = rand_tree(spec, &mut rng, depth, 0);
        let res = eval_tree(&t);
        out.push((t, res));
    }
    out
}

/// Render a native `Tree` as emitted-source syntax for the pruned enum.
fn render_tree(t: &Tree) -> String {
    match t {
        Tree::Val(v) => format!("Expr::Val({v})"),
        Tree::Neg(x) => format!("Expr::Neg(Box::new({}))", render_tree(x)),
        Tree::Abs(x) => format!("Expr::Abs(Box::new({}))", render_tree(x)),
        Tree::Double(x) => format!("Expr::Double(Box::new({}))", render_tree(x)),
        Tree::Add(a, b) => format!(
            "Expr::Add(Box::new({}), Box::new({}))",
            render_tree(a),
            render_tree(b)
        ),
        Tree::Sub(a, b) => format!(
            "Expr::Sub(Box::new({}), Box::new({}))",
            render_tree(a),
            render_tree(b)
        ),
        Tree::Mul(a, b) => format!(
            "Expr::Mul(Box::new({}), Box::new({}))",
            render_tree(a),
            render_tree(b)
        ),
        Tree::Max(a, b) => format!(
            "Expr::Max(Box::new({}), Box::new({}))",
            render_tree(a),
            render_tree(b)
        ),
    }
}

/// One-line indented prose form for prompt readability:
/// `Add(Val(3), Neg(Sub(Double(Val(1)), Val(4))))`.
fn prose_tree(t: &Tree) -> String {
    match t {
        Tree::Val(v) => format!("Val({v})"),
        Tree::Neg(x) => format!("Neg({})", prose_tree(x)),
        Tree::Abs(x) => format!("Abs({})", prose_tree(x)),
        Tree::Double(x) => format!("Double({})", prose_tree(x)),
        Tree::Add(a, b) => format!("Add({}, {})", prose_tree(a), prose_tree(b)),
        Tree::Sub(a, b) => format!("Sub({}, {})", prose_tree(a), prose_tree(b)),
        Tree::Mul(a, b) => format!("Mul({}, {})", prose_tree(a), prose_tree(b)),
        Tree::Max(a, b) => format!("Max({}, {})", prose_tree(a), prose_tree(b)),
    }
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (t, out) in worked_examples(spec, seed) {
        s.push_str(&format!("  {}  ->  {out}\n", prose_tree(&t)));
    }
    s
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples_prose(spec, seed)
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Implement `{name}` below.\n\
         //!\n\
         //! Examples (`{name}(&tree)` -> result):\n\
         {doc}\n\
         {enum_src}\n\
         pub fn {name}(e: &Expr) -> i64 {{\n\
         \x20   todo!()\n\
         }}\n",
        name = spec.fn_name,
        doc = doc,
        enum_src = enum_src(spec),
    )
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let mut ops = String::new();
    ops.push_str("- `Val(v)`: the leaf value `v`.\n");
    for u in spec.uns {
        ops.push_str(&format!("- `{}`: {}.\n", un_variant(u), un_prose(u)));
    }
    for b in spec.bins {
        ops.push_str(&format!("- `{}`: {}.\n", bin_variant(b), bin_prose(b)));
    }
    format!(
        "Implement the function `{name}` in `src/lib.rs`. The `Expr` enum below is \
         already provided; keep it exactly as written.\n\
         \n\
         `Expr` is a small arithmetic expression tree. `{name}` returns the integer \
         the tree evaluates to. Each variant means:\n\
         {ops}\n\
         Any correct implementation is fine — recursion through the boxed children \
         is natural but not required.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         \n\
         Signature:\n\
         ```rust\n\
         pub fn {name}(e: &Expr) -> i64\n\
         ```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        ops = ops,
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

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let mut body = format!("use task::{{Expr, {}}};\n\n", spec.fn_name);
    for (i, (t, out)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let tree = {tree};\n\
             \x20   assert_eq!({name}(&tree), {out});\n\
             }}\n\n",
            tree = render_tree(t),
            name = spec.fn_name,
        ));
    }
    body
}

/// The differential's reference — the same pruned enum plus the recursive fold,
/// pasted into the test file under `reference`.
fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec)
        .replacen(enum_src(spec).as_str(), "", 1)
        .replacen(&format!("pub fn {}", spec.fn_name), "fn reference", 1);
    // Emitted random-tree builder mirroring `rand_tree`: LCG state passed as
    // &mut u64; leaves non-zero in -9..=9; depth ≤ 3; unary chain ≤ 2. Numeric
    // match arms only — never variant names, which would be irrefutable bindings.
    // `@LEAF@` is replaced after formatting (it must not be a format placeholder).
    let leaf_expr = "{\n\
         \x20           let mag = (nx(state) % 9 + 1) as i64;\n\
         \x20           if nx(state) % 2 == 0 { Expr::Val(mag) } else { Expr::Val(-mag) }\n\
         \x20       }";
    let un_sel = format!(
        "    }} else if roll < 6 && chain < 2 {{\n\
         \x20       match nx(state) % 2 {{\n\
         {un_arms}\n\
         \x20       }}\n\
         \x20   }} else if roll < 6 {{\n\
         \x20       @LEAF@\n",
        un_arms = spec
            .uns
            .iter()
            .enumerate()
            .map(|(i, u)| {
                let arm = if i == 0 { "0" } else { "_" };
                format!(
                    "\x20           {arm} => Expr::{}(Box::new(gen(depth - 1, chain + 1, state))),",
                    un_variant(*u)
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let bin_sel = format!(
        "    }} else {{\n\
         \x20       match nx(state) % 2 {{\n\
         {bin_arms}\n\
         \x20       }}\n",
        bin_arms = spec
            .bins
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let arm = if i == 0 { "0" } else { "_" };
                format!(
                    "\x20           {arm} => Expr::{}(Box::new(gen(depth - 1, 0, state)), Box::new(gen(depth - 1, 0, state))),",
                    bin_variant(*b)
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    );
    format!(
        "use task::{{Expr, {name}}};\n\
         \n\
         {reference}\n\
         fn nx(state: &mut u64) -> u64 {{\n\
         \x20   *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20   *state >> 33\n\
         }}\n\
         \n\
         fn leaf(state: &mut u64) -> Expr {{\n\
         \x20   let mag = (nx(state) % 9 + 1) as i64;\n\
         \x20   if nx(state) % 2 == 0 {{ Expr::Val(mag) }} else {{ Expr::Val(-mag) }}\n\
         }}\n\
         \n\
         fn gen(depth: u32, chain: u32, state: &mut u64) -> Expr {{\n\
         \x20   let roll = nx(state) % 9;\n\
         \x20   if depth == 0 || roll < 4 {{\n\
         \x20       leaf(state)\n\
         {un_sel}\
         {bin_sel}\
         \x20   }}\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0044;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let depth = 1 + (nx(&mut state) % 3) as u32;\n\
         \x20       let tree = gen(depth, 0, &mut state);\n\
         \x20       assert_eq!({name}(&tree), reference(&tree));\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = reference,
        un_sel = un_sel.replace("@LEAF@", leaf_expr),
        bin_sel = bin_sel,
    )
}

/// Degenerate: always returns 0. Caught because the canonical tree's value is
/// non-zero under every operator combination (pinned).
fn const_zero(spec: &Spec) -> String {
    format!(
        "{enum_src}\n\
         pub fn {name}(e: &Expr) -> i64 {{ let _ = e; 0 }}\n",
        enum_src = enum_src(spec),
        name = spec.fn_name,
    )
}

/// The structural cheat: return a bare leaf's value, 0 for anything compound.
/// Behaviourally right on trivial inputs only — the canonical example is compound.
fn first_val(spec: &Spec) -> String {
    format!(
        "{enum_src}\n\
         pub fn {name}(e: &Expr) -> i64 {{\n\
         \x20   if let Expr::Val(v) = e {{ *v }} else {{ 0 }}\n\
         }}\n",
        enum_src = enum_src(spec),
        name = spec.fn_name,
    )
}

pub struct ExprTreeFamily;

impl Generator for ExprTreeFamily {
    fn id(&self) -> &str {
        "expr-tree"
    }
    fn category(&self) -> &str {
        "pattern-matching"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("expr-tree", seed);

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
            id: format!("expr-tree/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // No unsafe anywhere near an AST fold.
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // Default oracle weights (docs/04): pattern-matching is not one of
            // the re-weighted categories.
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
            ("first-val".to_string(), first_val(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let mut bins = spec.bins.map(bin_variant);
        let mut uns = spec.uns.map(un_variant);
        bins.sort_unstable();
        uns.sort_unstable();
        vec![
            format!("bin:{}/{}", bins[0], bins[1]),
            format!("un:{}/{}", uns[0], uns[1]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = ExprTreeFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        use Tree::{Abs, Add, Double, Max, Mul, Neg, Sub, Val};
        assert_eq!(eval_tree(&Add(Box::new(Val(3)), Box::new(Val(4)))), 7);
        assert_eq!(eval_tree(&Sub(Box::new(Val(3)), Box::new(Val(4)))), -1);
        assert_eq!(eval_tree(&Mul(Box::new(Val(3)), Box::new(Val(4)))), 12);
        assert_eq!(eval_tree(&Max(Box::new(Val(3)), Box::new(Val(4)))), 4);
        assert_eq!(eval_tree(&Neg(Box::new(Val(5)))), -5);
        assert_eq!(eval_tree(&Abs(Box::new(Val(-5)))), 5);
        assert_eq!(eval_tree(&Double(Box::new(Val(-5)))), -10);
        // Nested: Neg(Double(Abs(Sub(Mul(2,3), Max(4,1))))) = -(2*|6-4|) = -4.
        let t = Neg(Box::new(Double(Box::new(Abs(Box::new(Sub(
            Box::new(Mul(Box::new(Val(2)), Box::new(Val(3)))),
            Box::new(Max(Box::new(Val(4)), Box::new(Val(1)))),
        )))))));
        assert_eq!(eval_tree(&t), -4);
    }

    #[test]
    fn seeds_vary_operator_subsets() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.bins, s.uns));
        }
        assert!(
            variants.len() >= 12,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_result_is_nonzero_and_not_first_val() {
        // Both baselines are caught on every seed only if the canonical tree is
        // compound AND evaluates to something other than 0 under all 18 combos.
        for b1 in BIN_ALL {
            for b2 in BIN_ALL {
                if b1 == b2 {
                    continue;
                }
                for &u1 in &UN_ALL {
                    for &u2 in &UN_ALL {
                        if u1 == u2 {
                            continue;
                        }
                        let spec = Spec {
                            bins: [b1, b2],
                            uns: [u1, u2],
                            fn_name: "f",
                        };
                        let t = canonical_tree(&spec);
                        let v = eval_tree(&t);
                        assert_ne!(v, 0, "canonical is zero under {spec:?}");
                        assert!(!matches!(t, Tree::Val(_)), "canonical must be compound");
                        // first-val returns 0 for compound roots, so v != 0 covers it.
                    }
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (input, out) in worked_examples(&spec, seed) {
                assert_eq!(eval_tree(&input), out, "seed {seed}");
            }
        }
    }

    #[test]
    fn emitted_reference_compiles_against_pruned_enum() {
        // Structural check: the emitted reference mentions exactly the selected
        // variants and none of the pruned ones. The clippy-clean / compiles proof
        // happens end-to-end in validate-family.
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let src = reference_src(&spec);
            assert!(src.contains("Expr::Val(v) => *v"));
            for u in spec.uns {
                assert!(src.contains(un_variant(u)));
            }
            for b in spec.bins {
                assert!(src.contains(bin_variant(b)));
            }
            for u in UN_ALL {
                if !spec.uns.contains(&u) {
                    assert!(!src.contains(un_variant(u)));
                }
            }
            for b in BIN_ALL {
                if !spec.bins.contains(&b) {
                    assert!(!src.contains(bin_variant(b)));
                }
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = ExprTreeFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

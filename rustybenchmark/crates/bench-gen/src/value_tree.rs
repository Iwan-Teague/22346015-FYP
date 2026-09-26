//! The `value-tree` family (category `recursion`) — the founding member of a
//! new category.
//!
//! Where `expr-tree` folds a *homogeneous* arithmetic AST through a boxed spine,
//! this family recurses over an **owned heterogeneous value tree**: `Val` mixes
//! `Null`, `Bool`, `Int`, `Text` and `List(Vec<Val>)`, so the model must both
//! destructure every variant *and* decide which variants each query counts —
//! structural recursion plus per-variant relevance, not arithmetic.
//!
//! The **variant set is fixed** (all five variants are always provided and
//! pinned); what the seed prunes is the **query pair**: two of five counting
//! functions — `depth`, `leaves`, `sum` (ints only), `text_len` (chars in
//! strings), `nulls`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; function names are semantic here (the op IS the spec), so unlike
//! `expr-tree` there is no cosmetic name roll.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native queries
//! and the emitted reference render the same fold; the differential fuzzes
//! 3000 random trees against the model.
//!
//! Overflow-free by construction: counts are bounded by tree size (≤ ~dozens)
//! and `sum` only adds non-zero leaves in ±9 with ≤7 nodes — nowhere near
//! `i64` limits even in debug builds.
//!
//! Trivial baselines: `const-zero` (both fns return 0) and `no-recursion`
//! (treats any `List` as a leaf). Both fail on every seed because the canonical
//! example's root is a compound list whose answers are pinned non-degenerate:
//! depth 3 ≠ 1, 5 leaves ≠ 1, sum = x+y ≠ 0, text_len 2 ≠ 0, nulls 1 ≠ 0.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Depth,
    Leaves,
    Sum,
    TextLen,
    Nulls,
}

const OP_ALL: [Op; 5] = [Op::Depth, Op::Leaves, Op::Sum, Op::TextLen, Op::Nulls];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Depth => "depth",
            Op::Leaves => "leaves",
            Op::Sum => "sum",
            Op::TextLen => "text_len",
            Op::Nulls => "nulls",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::Sum => "i64",
            _ => "usize",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Depth => {
                "the number of levels: every leaf counts as depth 1, \
                          a list counts as 1 plus the deepest child (an empty \
                          list has depth 1)"
            }
            Op::Leaves => {
                "how many non-list values the tree contains, \
                          counting nested ones"
            }
            Op::Sum => {
                "the total of all integers anywhere in the tree \
                       (non-integers contribute nothing)"
            }
            Op::TextLen => {
                "the total character count of all text values \
                           anywhere in the tree"
            }
            Op::Nulls => "how many nulls the tree contains, counting nested ones",
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

/// The value tree itself — provided verbatim to the model, so the native
/// mirror and every emitted artifact share it exactly.
#[derive(Clone, Debug, PartialEq)]
enum Val {
    Null,
    Bool(bool),
    Int(i64),
    Text(String),
    List(Vec<Val>),
}

fn val_depth(v: &Val) -> usize {
    match v {
        Val::List(xs) => 1 + xs.iter().map(val_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn val_leaves(v: &Val) -> usize {
    match v {
        Val::List(xs) => xs.iter().map(val_leaves).sum(),
        _ => 1,
    }
}

fn val_sum(v: &Val) -> i64 {
    match v {
        Val::Int(x) => *x,
        Val::List(xs) => xs.iter().map(val_sum).sum(),
        _ => 0,
    }
}

fn val_text_len(v: &Val) -> usize {
    match v {
        Val::Text(s) => s.chars().count(),
        Val::List(xs) => xs.iter().map(val_text_len).sum(),
        _ => 0,
    }
}

fn val_nulls(v: &Val) -> usize {
    match v {
        Val::Null => 1,
        Val::List(xs) => xs.iter().map(val_nulls).sum(),
        _ => 0,
    }
}

fn eval(op: Op, v: &Val) -> i64 {
    match op {
        Op::Depth => val_depth(v) as i64,
        Op::Leaves => val_leaves(v) as i64,
        Op::Sum => val_sum(v),
        Op::TextLen => val_text_len(v) as i64,
        Op::Nulls => val_nulls(v) as i64,
    }
}

// ---- emitted-source fragments ---------------------------------------------

/// The enum, emitted verbatim into skeleton, reference, behavior test,
/// differential and both baselines.
fn enum_src() -> String {
    "#[derive(Debug, Clone, PartialEq)]\n\
     pub enum Val {\n\
     \x20   Null,\n\
     \x20   Bool(bool),\n\
     \x20   Int(i64),\n\
     \x20   Text(String),\n\
     \x20   List(Vec<Val>),\n\
     }\n"
    .to_string()
}

/// The recursive `List` arm body for one op.
fn list_arm_src(op: Op, name: &str) -> String {
    match op {
        Op::Depth => format!("1 + v.iter().map({name}).max().unwrap_or(0)"),
        _ => format!("v.iter().map({name}).sum()"),
    }
}

/// The extra non-list arm for ops that count a specific variant.
fn extra_arm_src(op: Op) -> Option<String> {
    match op {
        Op::Depth | Op::Leaves => None,
        Op::Sum => Some("        Val::Int(x) => *x,\n".to_string()),
        Op::TextLen => Some("        Val::Text(s) => s.chars().count(),\n".to_string()),
        Op::Nulls => Some("        Val::Null => 1,\n".to_string()),
    }
}

fn default_arm_src(op: Op) -> &'static str {
    match op {
        Op::Depth | Op::Leaves => "1",
        Op::Sum | Op::TextLen | Op::Nulls => "0",
    }
}

/// One complete query function over the shared enum.
fn query_fn_src(op: Op) -> String {
    let name = op.name();
    let extras = extra_arm_src(op).unwrap_or_default();
    format!(
        "pub fn {name}(v: &Val) -> {ret} {{\n\
         \x20   match v {{\n\
         \x20       Val::List(v) => {list},\n\
         {extras}\
         \x20       _ => {default},\n\
         \x20   }}\n\
         }}\n",
        name = name,
        ret = op.ret(),
        list = list_arm_src(op, name),
        extras = extras,
        default = default_arm_src(op),
    )
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn query_stub_src(op: Op) -> String {
    format!(
        "pub fn {name}(v: &Val) -> {ret} {{\n\
         \x20   todo!()\n\
         }}\n",
        name = op.name(),
        ret = op.ret(),
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn query_sig_src(op: Op) -> String {
    format!("pub fn {}(v: &Val) -> {}", op.name(), op.ret())
}

fn reference_src(spec: &Spec) -> String {
    let mut s = enum_src();
    for op in spec.ops {
        s.push_str(&query_fn_src(op));
    }
    s
}

// ---- worked examples ------------------------------------------------------

/// The canonical example: a compound root touching every variant except that
/// `Bool` appears once at top level. Seeded ints stay non-zero and their sum
/// stays non-zero, so every possible query pair separates both baselines.
fn canonical_val(seed: u64) -> Val {
    let mut rng = Rng::new(seed ^ 0xCA17_0A17_0000_0032);
    loop {
        let mx = 1 + rng.below(9);
        let x = sign(&mut rng, mx);
        let my = 1 + rng.below(9);
        let y = sign(&mut rng, my);
        if x + y != 0 {
            return Val::List(vec![
                Val::Bool(true),
                Val::Int(x),
                Val::Text("ab".to_string()),
                Val::List(vec![Val::Null, Val::Int(y)]),
            ]);
        }
    }
}

fn sign(rng: &mut Rng, mag: u64) -> i64 {
    if rng.below(2) == 0 {
        mag as i64
    } else {
        -(mag as i64)
    }
}

/// Random value from the allowed variants. Depth-limited; scalars weighted 7
/// of 10 so most fuzzed trees stay small while nesting still occurs.
fn rand_val(rng: &mut Rng, depth: u32) -> Val {
    if depth == 0 || rng.below(10) < 7 {
        match rng.below(4) {
            0 => Val::Null,
            1 => Val::Bool(rng.below(2) == 0),
            2 => {
                let mag = 1 + rng.below(9);
                Val::Int(sign(rng, mag))
            }
            _ => Val::Text(
                (0..rng.below(4))
                    .map(|_| (b'a' + rng.below(3) as u8) as char)
                    .collect(),
            ),
        }
    } else {
        Val::List(
            (0..rng.below(3))
                .map(|_| rand_val(rng, depth - 1))
                .collect(),
        )
    }
}

type ExampleCase = (Val, Vec<(Op, i64)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0033);
    let mut out: Vec<ExampleCase> = vec![{
        let v = canonical_val(seed);
        let outs = spec.ops.map(|op| (op, eval(op, &v))).to_vec();
        (v, outs)
    }];
    for _ in 0..3 {
        let d = 1 + rng.below(3) as u32;
        let v = rand_val(&mut rng, d);
        let outs = spec.ops.map(|op| (op, eval(op, &v))).to_vec();
        out.push((v, outs));
    }
    out
}

/// Render a native `Val` as emitted-source syntax.
fn render_val(v: &Val) -> String {
    match v {
        Val::Null => "Val::Null".to_string(),
        Val::Bool(b) => format!("Val::Bool({b})"),
        Val::Int(x) => format!("Val::Int({x})"),
        Val::Text(s) => format!("Val::Text({s:?}.to_string())"),
        Val::List(xs) => format!(
            "Val::List(vec![{}])",
            xs.iter().map(render_val).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// One-line indented prose form for prompt readability:
/// `List([Bool(true), Int(3), Text("ab"), List([Null, Int(-4)])])`.
fn prose_val(v: &Val) -> String {
    match v {
        Val::Null => "Null".to_string(),
        Val::Bool(b) => format!("Bool({b})"),
        Val::Int(x) => format!("Int({x})"),
        Val::Text(s) => format!("Text({s:?})"),
        Val::List(xs) => format!(
            "List([{}])",
            xs.iter().map(prose_val).collect::<Vec<_>>().join(", ")
        ),
    }
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (v, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  {}  ->  {}\n", prose_val(&v), results));
    }
    s
}

fn variant_docs() -> String {
    "- `Null`: an empty marker value.\n\
     - `Bool(b)`: a boolean.\n\
     - `Int(x)`: a signed integer.\n\
     - `Text(s)`: a string of characters.\n\
     - `List(values)`: zero or more nested values.\n"
        .to_string()
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples_prose(spec, seed)
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    let fns = spec.ops.map(query_stub_src).concat();
    format!(
        "//! Implement the two query functions below.\n\
         //!\n\
         //! Examples:\n\
         {doc}\n\
         {enum_src}\n\
         {fns}",
        doc = doc,
        enum_src = enum_src(),
        fns = fns,
    )
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let mut reqs = String::new();
    for op in spec.ops {
        reqs.push_str(&format!("- `{}`: {}.\n", op.name(), op.prose()));
    }
    format!(
        "Implement the two query functions in `src/lib.rs`. The `Val` enum below \
         is already provided; keep it exactly as written.\n\
         \n\
         `Val` is a heterogeneous tree of owned values. Each variant means:\n\
         {variants}\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine — recursion into `List` children is \
         natural but not required.\n\
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
        variants = variant_docs(),
        reqs = reqs,
        signatures = spec
            .ops
            .iter()
            .map(|op| format!("{}\n", query_sig_src(*op)))
            .collect::<Vec<_>>()
            .join(""),
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
    let imports = spec
        .ops
        .iter()
        .map(|op| op.name())
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!("use task::{{Val, {}}};\n\n", imports);
    for (i, (v, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let tree = {tree};\n",
            tree = render_val(v),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({name}(&tree), {out});\n",
                name = op.name(),
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the shared enum plus the two query fns,
/// pasted into the test file under `ref_*` names.
fn differential_test_src(spec: &Spec) -> String {
    let mut reference = reference_src(spec).replacen(enum_src().as_str(), "", 1);
    for op in spec.ops {
        reference = reference.replacen(
            &format!("pub fn {}", op.name()),
            &format!("fn ref_{}", op.name()),
            1,
        );
    }
    // Emitted random-tree builder mirroring `rand_val`: LCG state passed as
    // &mut u64; ints non-zero in -9..=9; depth ≤ 3. Numeric match arms only —
    // never variant names, which would be irrefutable bindings.
    let scalar_sel = "\
     \x20       match nx(state) % 4 {\n\
     \x20           0 => Val::Null,\n\
     \x20           1 => Val::Bool(nx(state) % 2 == 0),\n\
     \x20           2 => {\n\
     \x20               let mag = (nx(state) % 9 + 1) as i64;\n\
     \x20               if nx(state) % 2 == 0 { Val::Int(mag) } else { Val::Int(-mag) }\n\
     \x20           }\n\
     \x20           _ => {\n\
     \x20               let len = (nx(state) % 4) as usize;\n\
     \x20               let mut s = String::new();\n\
     \x20               for _ in 0..len {\n\
     \x20                   s.push((b'a' + (nx(state) % 3) as u8) as char);\n\
     \x20               }\n\
     \x20               Val::Text(s)\n\
     \x20           }\n\
     \x20       }\n";
    format!(
        "use task::{{Val, {imports}}};\n\
         \n\
         {reference}\
         fn nx(state: &mut u64) -> u64 {{\n\
         \x20   *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20   *state >> 33\n\
         }}\n\
         \n\
         fn gen(depth: u32, state: &mut u64) -> Val {{\n\
         \x20   let roll = nx(state) % 10;\n\
         \x20   if depth == 0 || roll < 7 {{\n\
         {scalar_sel}\
         \x20   }} else {{\n\
         \x20       let n = (nx(state) % 3) as usize;\n\
         \x20       let mut xs = Vec::new();\n\
         \x20       for _ in 0..n {{\n\
         \x20           xs.push(gen(depth - 1, state));\n\
         \x20       }}\n\
         \x20       Val::List(xs)\n\
         \x20   }}\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0045;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let d = 1 + (nx(&mut state) % 3) as u32;\n\
         \x20       let tree = gen(d, &mut state);\n\
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
        scalar_sel = scalar_sel,
        asserts = spec
            .ops
            .iter()
            .map(|op| {
                format!(
                    "\x20       assert_eq!({name}(&tree), ref_{name}(&tree));\n",
                    name = op.name(),
                )
            })
            .collect::<Vec<_>>()
            .join(""),
    )
}

/// Degenerate: both fns return 0. Caught on every seed because the canonical
/// example pins non-zero answers for all five ops (depth 3, leaves 5, sum
/// x+y≠0, text_len 2, nulls 1).
fn const_zero(spec: &Spec) -> String {
    let fns = spec
        .ops
        .iter()
        .map(|op| {
            format!(
                "pub fn {name}(v: &Val) -> {ret} {{ let _ = v; 0 }}\n",
                name = op.name(),
                ret = op.ret(),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("{enum_src}\n{fns}", enum_src = enum_src())
}

/// The structural cheat: treat any `List` like a leaf. Right on scalars only —
/// the canonical root is compound, where every op diverges from its flat answer
/// (depth 1 vs 3, leaves 1 vs 5, sum 0 vs x+y, text_len 0 vs 2, nulls 0 vs 1).
fn no_recursion(spec: &Spec) -> String {
    let fns = spec
        .ops
        .iter()
        .map(|op| {
            let default = default_arm_src(*op);
            let extra = match op {
                Op::Sum => "        Val::Int(x) => *x,\n",
                Op::TextLen => "        Val::Text(s) => s.chars().count(),\n",
                Op::Nulls => "        Val::Null => 1,\n",
                _ => "",
            };
            format!(
                "pub fn {name}(v: &Val) -> {ret} {{\n\
                 \x20   match v {{\n\
                 {extra}\
                 \x20       _ => {default},\n\
                 \x20   }}\n\
                 }}\n",
                name = op.name(),
                ret = op.ret(),
                extra = extra,
                default = default,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("{enum_src}\n{fns}", enum_src = enum_src())
}

pub struct ValueTreeFamily;

impl Generator for ValueTreeFamily {
    fn id(&self) -> &str {
        "value-tree"
    }
    fn category(&self) -> &str {
        "recursion"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("value-tree", seed);

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
            id: format!("value-tree/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // No unsafe anywhere near a pure tree walk.
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // Default oracle weights (docs/04); the new category starts
            // unweighted until the corpus grows around it.
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
            ("no-recursion".to_string(), no_recursion(&spec)),
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
        let g = ValueTreeFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_queries_match_intent() {
        use Val::{Bool, Int, List, Null, Text};
        let leafy = List(vec![Bool(true), Int(3), Text("ab".into())]);
        assert_eq!(val_depth(&leafy), 2);
        assert_eq!(val_leaves(&leafy), 3);
        assert_eq!(val_sum(&leafy), 3);
        assert_eq!(val_text_len(&leafy), 2);
        assert_eq!(val_nulls(&leafy), 0);

        let deep = List(vec![
            Null,
            List(vec![Int(-4), List(vec![Text("z".into())])]),
        ]);
        assert_eq!(val_depth(&deep), 4);
        assert_eq!(val_leaves(&deep), 3);
        assert_eq!(val_sum(&deep), -4);
        assert_eq!(val_text_len(&deep), 1);
        assert_eq!(val_nulls(&deep), 1);

        // Empty list: a leaf-like node for depth (depth 1, no children).
        assert_eq!(val_depth(&List(vec![])), 1);
        assert_eq!(val_leaves(&List(vec![])), 0);
        assert_eq!(val_sum(&List(vec![])), 0);
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
        // Both baselines must fail under EVERY query pair, so each individual
        // op must separate them on the canonical example alone.
        for seed in 0..200u64 {
            let v = canonical_val(seed);
            assert_eq!(val_depth(&v), 3);
            assert_eq!(val_leaves(&v), 5);
            assert_ne!(val_sum(&v), 0);
            assert_eq!(val_text_len(&v), 2);
            assert_eq!(val_nulls(&v), 1);
            assert!(matches!(v, Val::List(_)), "canonical must be compound");
        }
    }

    #[test]
    fn worked_examples_agree_with_queries() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (input, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(eval(op, &input), out, "seed {seed}");
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
                // Match on the emitted `pub fn` line: bare names substring-
                // collide (e.g. iterator `.sum()` inside every counting arm).
                let fn_line = format!("pub fn {}", op.name());
                if spec.ops.contains(&op) {
                    assert!(src.contains(&fn_line));
                } else {
                    assert!(!src.contains(&fn_line), "{:?} leaked", op);
                }
            }
            assert!(src.contains("pub enum Val"));
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let sk = skeleton_src(&spec, seed);
            assert!(sk.contains("todo!()"), "skeleton must be stubbed");
            assert!(!sk.contains("unwrap_or"), "skeleton leaks the fold");
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("match v"));
            for op in spec.ops {
                assert!(p.contains(&query_sig_src(op)));
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = ValueTreeFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

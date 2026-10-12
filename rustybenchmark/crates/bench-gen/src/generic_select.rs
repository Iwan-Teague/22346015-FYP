//! The `generic-select` family (category `traits-generics`).
//!
//! A *second* `traits-generics` family that exercises the sibling skill to
//! `trait-impl`: instead of *implementing* a trait, the model **writes a generic
//! function bounded by one** — `fn f<T: Ranked>(items: &[T]) -> Option<i64>`. The
//! trait `Ranked { fn rank(&self) -> i64; }` is pinned in the skeleton; the model
//! writes the generic consumer. It is also selection-shaped rather than a fold, so
//! it reads differently from the reduce/pipeline families.
//!
//! Seed-selected on two axes:
//!
//! 1. **Select** — which item's rank is chosen: Max / Min / First / Last.
//! 2. **Project** — how the chosen rank `r` is transformed: Identity / Abs /
//!    Double / Square.
//!
//! The structural surface is 4 × 4 = **16 distinct skills**. `None` iff the slice
//! is empty. Solution-first and correct-by-construction (ADR-0003): native `eval`
//! and the emitted reference are mirrored, and the differential fuzzes 3000 random
//! slices (built as `Vec<R>` for a hidden `R: Ranked`). Ranks are bounded
//! (∈ -30..=30) so `Square` cannot overflow `i64` (30² = 900).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — which item's rank is chosen.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Select {
    Max,
    Min,
    First,
    Last,
}

/// Axis 2 — how the chosen rank is projected to the answer.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Project {
    Identity,
    Abs,
    Double,
    Square,
}

struct Spec {
    select: Select,
    project: Project,
    fn_name: &'static str,
}

const NAMES: &[&str] = &["f", "pick", "select_rank", "choose", "extract", "resolve"];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let select = match rng.below(4) {
        0 => Select::Max,
        1 => Select::Min,
        2 => Select::First,
        _ => Select::Last,
    };
    let project = match rng.below(4) {
        0 => Project::Identity,
        1 => Project::Abs,
        2 => Project::Double,
        _ => Project::Square,
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        select,
        project,
        fn_name,
    }
}

// ---- native reference (mirrors the emitted source exactly) ----------------

fn project(p: Project, r: i64) -> i64 {
    match p {
        Project::Identity => r,
        Project::Abs => r.abs(),
        Project::Double => r * 2,
        Project::Square => r * r,
    }
}

/// The answer: choose a rank from the slice per `select`, then project it. `None`
/// on an empty slice. Source of truth for the emitted reference. (`Max`/`Min`
/// return the extreme *value*, so ties do not affect the answer.)
fn eval(spec: &Spec, ranks: &[i64]) -> Option<i64> {
    if ranks.is_empty() {
        return None;
    }
    let chosen = match spec.select {
        Select::Max => *ranks.iter().max().unwrap(),
        Select::Min => *ranks.iter().min().unwrap(),
        Select::First => ranks[0],
        Select::Last => ranks[ranks.len() - 1],
    };
    Some(project(spec.project, chosen))
}

// ---- emitted-source fragments (mirror the native functions above) ---------

fn select_expr(select: Select) -> &'static str {
    match select {
        Select::Max => "items.iter().map(|it| it.rank()).max().unwrap()",
        Select::Min => "items.iter().map(|it| it.rank()).min().unwrap()",
        Select::First => "items[0].rank()",
        Select::Last => "items[items.len() - 1].rank()",
    }
}

/// The same selection over a plain `&[i64]` of ranks — the differential's free
/// reference works on the ranks directly rather than through `T: Ranked`.
fn ranks_select_expr(select: Select) -> &'static str {
    match select {
        Select::Max => "ranks.iter().copied().max().unwrap()",
        Select::Min => "ranks.iter().copied().min().unwrap()",
        Select::First => "ranks[0]",
        Select::Last => "ranks[ranks.len() - 1]",
    }
}

fn project_expr(p: Project) -> &'static str {
    match p {
        Project::Identity => "chosen",
        Project::Abs => "chosen.abs()",
        Project::Double => "chosen * 2",
        Project::Square => "chosen * chosen",
    }
}

fn select_prose(select: Select) -> &'static str {
    match select {
        Select::Max => "the largest `rank()` among the items",
        Select::Min => "the smallest `rank()` among the items",
        Select::First => "the `rank()` of the first item",
        Select::Last => "the `rank()` of the last item",
    }
}

fn project_prose(p: Project) -> &'static str {
    match p {
        Project::Identity => "return it unchanged",
        Project::Abs => "return its absolute value",
        Project::Double => "return it multiplied by 2",
        Project::Square => "return its square",
    }
}

const TRAIT_SRC: &str = "pub trait Ranked {\n\
     \x20   /// The item's rank.\n\
     \x20   fn rank(&self) -> i64;\n\
     }\n";

fn reference_src(spec: &Spec) -> String {
    format!(
        "{trait_src}\n\
         pub fn {name}<T: Ranked>(items: &[T]) -> Option<i64> {{\n\
         \x20   if items.is_empty() {{\n\
         \x20       return None;\n\
         \x20   }}\n\
         \x20   let chosen = {select};\n\
         \x20   Some({project})\n\
         }}\n",
        trait_src = TRAIT_SRC,
        name = spec.fn_name,
        select = select_expr(spec.select),
        project = project_expr(spec.project),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "//! Implement the generic function `{name}` below. The `Ranked` trait is\n\
         //! provided — keep it.\n\
         //!\n\
         {doc}\n\
         {trait_src}\n\
         pub fn {name}<T: Ranked>(items: &[T]) -> Option<i64> {{\n\
         \x20   todo!()\n\
         }}\n",
        name = spec.fn_name,
        trait_src = TRAIT_SRC,
        doc = examples
            .lines()
            .map(|l| format!("//! {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// One worked example: (ranks, expected answer).
type ExampleCase = (Vec<i64>, Option<i64>);

/// Worked examples, computed natively so each is correct by construction. Shown as
/// the items' *ranks* (the model works over any `T: Ranked`). The first case is the
/// **canonical** one — the fixed ranks `[3, 7, 2, 5]`, all positive and distinct so
/// every (select, project) combination yields `Some(v)` with `v` neither `None` nor
/// `0` — which makes both trivial baselines (`const-none`, `const-zero`) fail on
/// every seed. The rest are seed-varied random ranks (including negatives, so `Abs`
/// is exercised).
fn worked_examples(spec: &Spec, seed: u64) -> (String, Vec<ExampleCase>) {
    let mut rng = Rng::new(seed ^ 0x9A17_0000_0000_0029);
    let mut inputs: Vec<Vec<i64>> = vec![vec![3, 7, 2, 5]];
    for _ in 0..3 {
        let len = 2 + rng.below(6) as usize; // 2..=7
        let input: Vec<i64> = (0..len).map(|_| rng.below(61) as i64 - 30).collect(); // -30..=30
        inputs.push(input);
    }

    let mut cases = Vec::new();
    let mut prose = String::new();
    for input in &inputs {
        let out = eval(spec, input);
        let rendered = match out {
            Some(v) => format!("Some({v})"),
            None => "None".to_string(),
        };
        prose.push_str(&format!("  ranks {input:?}  ->  {rendered}\n"));
        cases.push((input.clone(), out));
    }
    (prose, cases)
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "Implement the generic function `{name}` in `src/lib.rs`. The `Ranked` \
         trait is already provided; keep it and write `{name}` generic over any \
         `T: Ranked`.\n\
         \n\
         Choose {select_prose}, then {project_prose}. If `items` is empty, return \
         `None`.\n\
         \n\
         Constraints:\n\
         - Keep the signature `pub fn {name}<T: Ranked>(items: &[T]) -> Option<i64>` \
         exactly, including the trait bound.\n\
         - Do not use `unsafe`.\n\
         \n\
         Provided interface (in `src/lib.rs`):\n\
         ```rust\n\
         pub trait Ranked {{\n\
         \x20   fn rank(&self) -> i64;\n\
         }}\n\
         pub fn {name}<T: Ranked>(items: &[T]) -> Option<i64>;\n\
         ```\n\
         \n\
         Examples (given each item's `rank()`):\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        select_prose = select_prose(spec.select),
        project_prose = project_prose(spec.project),
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

/// A hidden concrete `Ranked` type shared by the behaviour and differential tests.
const HIDDEN_TYPE: &str = "struct R(i64);\n\
     impl Ranked for R {\n\
     \x20   fn rank(&self) -> i64 {\n\
     \x20       self.0\n\
     \x20   }\n\
     }\n";

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let (_, cases) = worked_examples(spec, seed);
    let mut body = format!("use task::{{Ranked, {}}};\n\n{HIDDEN_TYPE}\n", spec.fn_name);
    for (i, (ranks, out)) in cases.iter().enumerate() {
        let expect = match out {
            Some(v) => format!("Some({v})"),
            None => "None".to_string(),
        };
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let items: Vec<R> = vec!{ranks:?}.into_iter().map(R).collect();\n\
             \x20   assert_eq!({name}(&items), {expect});\n\
             }}\n\n",
            name = spec.fn_name,
        ));
    }
    body.push_str(&format!(
        "#[test]\nfn empty_is_none() {{\n\
         \x20   let items: Vec<R> = Vec::new();\n\
         \x20   assert_eq!({name}(&items), None);\n\
         }}\n",
        name = spec.fn_name,
    ));
    body
}

fn differential_test_src(spec: &Spec) -> String {
    // A free reference over the ranks, mirroring `eval`.
    let reference = format!(
        "fn reference(ranks: &[i64]) -> Option<i64> {{\n\
         \x20   if ranks.is_empty() {{\n\
         \x20       return None;\n\
         \x20   }}\n\
         \x20   let chosen = {chosen};\n\
         \x20   Some({project})\n\
         }}\n",
        chosen = ranks_select_expr(spec.select),
        project = project_expr(spec.project),
    );
    format!(
        "use task::{{Ranked, {name}}};\n\
         \n\
         {HIDDEN_TYPE}\n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x9A17_ED00_0000_0042;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 12) as usize;\n\
         \x20       let ranks: Vec<i64> = (0..len).map(|_| (next() % 61) as i64 - 30).collect();\n\
         \x20       let items: Vec<R> = ranks.iter().copied().map(R).collect();\n\
         \x20       assert_eq!({name}(&items), reference(&ranks), \"mismatch: {{ranks:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = reference,
    )
}

/// Degenerate: always `None`. Fails the canonical example, which is non-empty.
fn const_none(spec: &Spec) -> String {
    format!(
        "{trait_src}\n\
         pub fn {name}<T: Ranked>(items: &[T]) -> Option<i64> {{ let _ = items; None }}\n",
        trait_src = TRAIT_SRC,
        name = spec.fn_name,
    )
}

/// Degenerate: always `Some(0)`. Fails the canonical example, whose answer is never
/// `Some(0)`. Both baselines are constants because any *shaped* degenerate (first
/// rank, etc.) coincides with a real spec on the canonical input.
fn const_zero(spec: &Spec) -> String {
    format!(
        "{trait_src}\n\
         pub fn {name}<T: Ranked>(items: &[T]) -> Option<i64> {{ let _ = items; Some(0) }}\n",
        trait_src = TRAIT_SRC,
        name = spec.fn_name,
    )
}

pub struct GenericSelectFamily;

impl Generator for GenericSelectFamily {
    fn id(&self) -> &str {
        "generic-select"
    }
    fn category(&self) -> &str {
        "traits-generics"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("generic-select", seed);

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
            id: format!("generic-select/{seed:016x}"),
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
            check_clippy: false,
            clippy_allow: Vec::new(),
            forbidden_paths: Vec::new(),
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
            ("const-none".to_string(), const_none(&spec)),
            ("const-zero".to_string(), const_zero(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is the (select, project) pair. The function name is cosmetic;
        // there are no numeric constants — all excluded (Q31).
        let spec = sample(seed);
        let select = match spec.select {
            Select::Max => "max",
            Select::Min => "min",
            Select::First => "first",
            Select::Last => "last",
        };
        let project = match spec.project {
            Project::Identity => "identity",
            Project::Abs => "abs",
            Project::Double => "double",
            Project::Square => "square",
        };
        vec![format!("select:{select}"), format!("project:{project}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = GenericSelectFamily;
        assert_eq!(g.generate(27).prompt, g.generate(27).prompt);
        assert_eq!(g.generate(27).hidden, g.generate(27).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        let mk = |select, project| Spec {
            select,
            project,
            fn_name: "f",
        };
        // Max rank of [3,7,2,5] = 7, squared = 49.
        assert_eq!(
            eval(&mk(Select::Max, Project::Square), &[3, 7, 2, 5]),
            Some(49)
        );
        // Min rank = 2, doubled = 4.
        assert_eq!(
            eval(&mk(Select::Min, Project::Double), &[3, 7, 2, 5]),
            Some(4)
        );
        // First rank = 3, identity.
        assert_eq!(
            eval(&mk(Select::First, Project::Identity), &[3, 7, 2, 5]),
            Some(3)
        );
        // Last rank = 5, abs.
        assert_eq!(
            eval(&mk(Select::Last, Project::Abs), &[3, 7, 2, 5]),
            Some(5)
        );
        // Abs of a negative extreme.
        assert_eq!(eval(&mk(Select::Min, Project::Abs), &[-8, 2, -3]), Some(8));
        // Empty is None.
        assert_eq!(eval(&mk(Select::Max, Project::Identity), &[]), None);
    }

    #[test]
    fn seeds_vary_select_and_project() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.select, s.project));
        }
        assert!(
            variants.len() >= 14,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_is_some_and_never_zero() {
        // Both constant baselines are caught on every seed only if the canonical
        // ranks yield Some(v) with v != 0 under every (select, project) combo.
        let canonical = [3i64, 7, 2, 5];
        for &select in &[Select::Max, Select::Min, Select::First, Select::Last] {
            for &project in &[
                Project::Identity,
                Project::Abs,
                Project::Double,
                Project::Square,
            ] {
                let spec = Spec {
                    select,
                    project,
                    fn_name: "f",
                };
                let ans = eval(&spec, &canonical);
                assert!(
                    matches!(ans, Some(v) if v != 0),
                    "canonical answer {ans:?} is None or 0 under {select:?}/{project:?}"
                );
            }
        }
    }

    #[test]
    fn reference_matches_native_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            let (_, cases) = worked_examples(&spec, seed);
            for (ranks, out) in cases {
                assert_eq!(eval(&spec, &ranks), out, "seed {seed}");
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = GenericSelectFamily;
        let t = g.generate(13);
        assert!(t.prompt.contains(&t.canary));
    }
}

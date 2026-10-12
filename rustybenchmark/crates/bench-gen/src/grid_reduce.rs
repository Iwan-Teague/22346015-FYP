//! The `grid-reduce` family (category `data-structures`).
//!
//! A fifth family in a new category, exercising nested-slice / 2D indexing — a
//! different Rust skill from the first four. The model implements
//! `reduce(grid: &[Vec<i64>]) -> Vec<i64>` over a **rectangular** grid: a
//! seed-selected axis (per-row or per-column) and a seed-selected reduction
//! (Sum / Max / Min / Product / CountPositive / Range). Solution-first and
//! correct-by-construction (ADR-0003): native `eval` and the emitted reference are
//! mirrored, so the differential fuzz keeps them honest.
//!
//! Structural surface: 2 axes × 6 reductions = 12 distinct skills. The function
//! name is cosmetic and there are no free numeric constants, so `spec_signature`
//! is exactly `(axis, reduction)`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Axis {
    Rows,
    Cols,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Reduction {
    Sum,
    Max,
    Min,
    Product,
    CountPositive,
    Range,
}

struct Spec {
    axis: Axis,
    reduction: Reduction,
    fn_name: &'static str,
}

const NAMES: &[&str] = &[
    "reduce",
    "fold_grid",
    "collapse",
    "summarise",
    "aggregate_grid",
    "reduce_axis",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let axis = if rng.below(2) == 0 {
        Axis::Rows
    } else {
        Axis::Cols
    };
    let reduction = match rng.below(6) {
        0 => Reduction::Sum,
        1 => Reduction::Max,
        2 => Reduction::Min,
        3 => Reduction::Product,
        4 => Reduction::CountPositive,
        _ => Reduction::Range,
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        axis,
        reduction,
        fn_name,
    }
}

/// Native reduction of one slice (a row, or a gathered column). Mirrors [`red_expr`]
/// exactly, including the empty-slice conventions (Sum/Max/Min/CountPositive/Range → 0,
/// Product → 1).
fn reduce_slice(r: Reduction, xs: &[i64]) -> i64 {
    match r {
        Reduction::Sum => xs.iter().sum(),
        Reduction::Max => xs.iter().copied().max().unwrap_or(0),
        Reduction::Min => xs.iter().copied().min().unwrap_or(0),
        Reduction::Product => xs.iter().product(),
        Reduction::CountPositive => xs.iter().filter(|&&x| x > 0).count() as i64,
        Reduction::Range => {
            if xs.is_empty() {
                0
            } else {
                xs.iter().max().unwrap() - xs.iter().min().unwrap()
            }
        }
    }
}

/// Native reference. Rectangular grids only (all rows the same length).
fn eval(spec: &Spec, grid: &[Vec<i64>]) -> Vec<i64> {
    match spec.axis {
        Axis::Rows => grid
            .iter()
            .map(|row| reduce_slice(spec.reduction, row))
            .collect(),
        Axis::Cols => {
            if grid.is_empty() {
                return Vec::new();
            }
            let ncols = grid[0].len();
            (0..ncols)
                .map(|j| {
                    let col: Vec<i64> = grid.iter().map(|row| row[j]).collect();
                    reduce_slice(spec.reduction, &col)
                })
                .collect()
        }
    }
}

// ---- emitted-source fragments (mirror the native fns above) ---------------

/// The reduction as emitted source, an expression over a binding `xs: &[i64]`.
fn red_expr(r: Reduction) -> &'static str {
    match r {
        Reduction::Sum => "xs.iter().sum::<i64>()",
        Reduction::Max => "xs.iter().copied().max().unwrap_or(0)",
        Reduction::Min => "xs.iter().copied().min().unwrap_or(0)",
        Reduction::Product => "xs.iter().product::<i64>()",
        Reduction::CountPositive => "xs.iter().filter(|&&x| x > 0).count() as i64",
        Reduction::Range => {
            "if xs.is_empty() { 0 } else { xs.iter().max().unwrap() - xs.iter().min().unwrap() }"
        }
    }
}

fn axis_prose(a: Axis) -> &'static str {
    match a {
        Axis::Rows => "one output value per row, in row order",
        Axis::Cols => "one output value per column, in column order",
    }
}

fn reduction_prose(r: Reduction) -> &'static str {
    match r {
        Reduction::Sum => "the sum of its elements",
        Reduction::Max => "the maximum element (0 if the line is empty)",
        Reduction::Min => "the minimum element (0 if the line is empty)",
        Reduction::Product => "the product of its elements (1 if the line is empty)",
        Reduction::CountPositive => "the count of strictly-positive elements",
        Reduction::Range => "its range, max minus min (0 if the line is empty)",
    }
}

fn reference_src(spec: &Spec) -> String {
    let red = red_expr(spec.reduction);
    let body = match spec.axis {
        Axis::Rows => format!(
            "\x20   grid.iter()\n\
             \x20       .map(|row| {{ let xs: &[i64] = row; {red} }})\n\
             \x20       .collect()"
        ),
        Axis::Cols => format!(
            "\x20   if grid.is_empty() {{\n\
             \x20       return Vec::new();\n\
             \x20   }}\n\
             \x20   let ncols = grid[0].len();\n\
             \x20   (0..ncols)\n\
             \x20       .map(|j| {{\n\
             \x20           let col: Vec<i64> = grid.iter().map(|row| row[j]).collect();\n\
             \x20           let xs: &[i64] = &col;\n\
             \x20           {red}\n\
             \x20       }})\n\
             \x20       .collect()"
        ),
    };
    format!(
        "pub fn {name}(grid: &[Vec<i64>]) -> Vec<i64> {{\n{body}\n}}\n",
        name = spec.fn_name,
    )
}

fn render_grid(g: &[Vec<i64>]) -> String {
    if g.is_empty() {
        return "Vec::<Vec<i64>>::new()".to_string();
    }
    let rows: Vec<String> = g.iter().map(|r| format!("vec!{r:?}")).collect();
    format!("vec![{}]", rows.join(", "))
}

fn prose_grid(g: &[Vec<i64>]) -> String {
    format!("{g:?}")
}

/// Seed-varied worked examples: `(grid, expected)`, computed natively. Always includes
/// a canonical multi-row rectangular grid — changed by every (axis, reduction) and never
/// equal to the flattened grid — so both trivial baselines fail on every seed; plus a
/// couple of random rectangular grids and the empty grid.
fn worked_examples(spec: &Spec, seed: u64) -> Vec<(Vec<Vec<i64>>, Vec<i64>)> {
    let mut rng = Rng::new(seed ^ 0x6817_D2A0_0000_0001);
    let mut grids: Vec<Vec<Vec<i64>>> = Vec::new();

    // Canonical 2×3 grid of distinct values (base varies by seed). Multi-row and
    // multi-column, so per-row and per-column outputs are both non-trivial and never
    // equal the row-major flatten.
    {
        let b = 1 + (seed % 5) as i64;
        grids.push(vec![vec![b, b + 1, b + 2], vec![b + 3, b + 4, b + 5]]);
    }
    // Random rectangular grids.
    for _ in 0..2 {
        let nrows = 1 + rng.below(3) as usize; // 1..=3
        let ncols = 1 + rng.below(3) as usize; // 1..=3
        let grid: Vec<Vec<i64>> = (0..nrows)
            .map(|_| (0..ncols).map(|_| rng.below(19) as i64 - 9).collect())
            .collect();
        grids.push(grid);
    }
    // The empty grid.
    grids.push(Vec::new());

    grids
        .into_iter()
        .map(|g| {
            let out = eval(spec, &g);
            (g, out)
        })
        .collect()
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (g, out) in worked_examples(spec, seed) {
        s.push_str(&format!("  {}  ->  {out:?}\n", prose_grid(&g)));
    }
    s
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let examples = worked_examples_prose(spec, seed);
    format!(
        "//! Implement `{name}` below.\n\
         //!\n\
         {doc}\n\
         pub fn {name}(grid: &[Vec<i64>]) -> Vec<i64> {{\n\
         \x20   todo!()\n\
         }}\n",
        name = spec.fn_name,
        doc = examples
            .lines()
            .map(|l| format!("//! {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let examples = worked_examples_prose(spec, seed);
    format!(
        "Implement the function `{name}` in `src/lib.rs`.\n\
         \n\
         `grid` is a rectangular grid of `i64` (every row has the same length). Produce \
         {axis}, where each output value is {reduction}. An empty grid returns an empty \
         `Vec`.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         \n\
         Signature:\n\
         ```rust\n\
         pub fn {name}(grid: &[Vec<i64>]) -> Vec<i64>\n\
         ```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        axis = axis_prose(spec.axis),
        reduction = reduction_prose(spec.reduction),
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
    let mut body = format!("use task::{};\n\n", spec.fn_name);
    for (i, (grid, out)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let grid: Vec<Vec<i64>> = {grid};\n\
             \x20   assert_eq!({name}(&grid), vec!{out:?});\n\
             }}\n\n",
            grid = render_grid(grid),
            name = spec.fn_name,
        ));
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference =
        reference_src(spec).replacen(&format!("pub fn {}", spec.fn_name), "fn reference", 1);
    format!(
        "use task::{name};\n\
         \n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x1F2E_3D4C_5B6A_7988;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let nrows = (next() % 5) as usize;\n\
         \x20       let ncols = (next() % 5) as usize;\n\
         \x20       let grid: Vec<Vec<i64>> = (0..nrows)\n\
         \x20           .map(|_| (0..ncols).map(|_| (next() % 19) as i64 - 9).collect())\n\
         \x20           .collect();\n\
         \x20       assert_eq!({name}(&grid), reference(&grid), \"mismatch: {{grid:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = reference,
    )
}

/// Degenerate: always empty. Fails on any non-empty grid.
fn const_empty(spec: &Spec) -> String {
    format!(
        "pub fn {name}(grid: &[Vec<i64>]) -> Vec<i64> {{ let _ = grid; Vec::new() }}\n",
        name = spec.fn_name,
    )
}

/// Degenerate: flattens the grid row-major, ignoring the axis and reduction. Fails
/// whenever the real output differs from the flattening (which the canonical case
/// guarantees).
fn flatten(spec: &Spec) -> String {
    format!(
        "pub fn {name}(grid: &[Vec<i64>]) -> Vec<i64> {{\n\
         \x20   grid.iter().flatten().copied().collect()\n\
         }}\n",
        name = spec.fn_name,
    )
}

pub struct GridReduceFamily;

impl Generator for GridReduceFamily {
    fn id(&self) -> &str {
        "grid-reduce"
    }
    fn category(&self) -> &str {
        "data-structures"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("grid-reduce", seed);

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
            id: format!("grid-reduce/{seed:016x}"),
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
            ("const-empty".to_string(), const_empty(&spec)),
            ("flatten".to_string(), flatten(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        vec![
            format!("axis:{:?}", spec.axis),
            format!("reduction:{:?}", spec.reduction),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = GridReduceFamily;
        assert_eq!(g.generate(5).prompt, g.generate(5).prompt);
        assert_eq!(g.generate(5).hidden, g.generate(5).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        let rows_sum = Spec {
            axis: Axis::Rows,
            reduction: Reduction::Sum,
            fn_name: "reduce",
        };
        assert_eq!(
            eval(&rows_sum, &[vec![1, 2, 3], vec![4, 5, 6]]),
            vec![6, 15]
        );
        let cols_sum = Spec {
            axis: Axis::Cols,
            reduction: Reduction::Sum,
            fn_name: "reduce",
        };
        assert_eq!(
            eval(&cols_sum, &[vec![1, 2, 3], vec![4, 5, 6]]),
            vec![5, 7, 9]
        );
        // Empty grid → empty.
        assert_eq!(eval(&rows_sum, &[]), Vec::<i64>::new());
    }

    #[test]
    fn reductions_are_correct() {
        let g = [vec![-2, 3, 0], vec![4, -1, 5]];
        let mk = |r| Spec {
            axis: Axis::Rows,
            reduction: r,
            fn_name: "reduce",
        };
        assert_eq!(eval(&mk(Reduction::Max), &g), vec![3, 5]);
        assert_eq!(eval(&mk(Reduction::Min), &g), vec![-2, -1]);
        assert_eq!(eval(&mk(Reduction::Product), &g), vec![0, -20]);
        assert_eq!(eval(&mk(Reduction::CountPositive), &g), vec![1, 2]);
        assert_eq!(eval(&mk(Reduction::Range), &g), vec![5, 6]); // 3-(-2), 5-(-1)
    }

    #[test]
    fn seeds_vary_axis_and_reduction() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..120u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.axis, s.reduction));
        }
        assert!(
            variants.len() >= 10,
            "expected variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = GridReduceFamily;
        let t = g.generate(2);
        assert!(t.prompt.contains(&t.canary));
    }
}

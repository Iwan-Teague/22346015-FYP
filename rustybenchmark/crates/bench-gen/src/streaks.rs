//! The `streaks` family (category `streak-analysis`) — directional
//! run-tracking over win/loss sequences.
//!
//! Where `rle` tracks value runs and `minmax` reads order statistics,
//! this family exercises **directional streak semantics**: the win run
//! currently alive at the end of the schedule, the best run anywhere in
//! it, the plain win count, the perfect-season sweep, and the
//! lost-the-opener-won-the-closer finish. The domain is a sequence of
//! outcomes, each `u64` zero or one (one is a win). The seed prunes
//! which two of five query ops are required: `current_win_streak`,
//! `best_win_streak`, `num_wins`, `is_perfect_season`, `strong_finish`.
//! C(5,2) = **10 distinct skills**, above the diversity floor; op names
//! are semantic.
//!
//! The canonical season is sampled until its anchor facts hold: it
//! opens on a loss and closes on a win, so `strong_finish` answers TRUE
//! there (constant-false cheats die outright on every op), the schedule
//! carries a two-win run somewhere, and the three scalars stay pairwise
//! distinct. An opening loss also forces a non-perfect season — that
//! predicate answers FALSE on the canonical shape and constant-true
//! cheats die there too (the pinned sweep example flips cheats that
//! answer false everywhere).
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random seasons against the model.
//!
//! Trivial baselines: `const-zero` (fails every scalar outright on the
//! canonical season) and `all-wins-everything` (every query answered as
//! if the whole schedule were won — exact nowhere once a single loss
//! sits anywhere in the record).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    CurrentWinStreak,
    BestWinStreak,
    NumWins,
    IsPerfectSeason,
    StrongFinish,
}

const OP_ALL: [Op; 5] = [
    Op::CurrentWinStreak,
    Op::BestWinStreak,
    Op::NumWins,
    Op::IsPerfectSeason,
    Op::StrongFinish,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::CurrentWinStreak => "current_win_streak",
            Op::BestWinStreak => "best_win_streak",
            Op::NumWins => "num_wins",
            Op::IsPerfectSeason => "is_perfect_season",
            Op::StrongFinish => "strong_finish",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::CurrentWinStreak => {
                "how many consecutive wins the team carries into today — \
                 the run alive at the far end of the record"
            }
            Op::BestWinStreak => "the longest winning run anywhere in the record",
            Op::NumWins => "how many games were won in total",
            Op::IsPerfectSeason => {
                "whether every single game was won — an empty record is \
                 no season at all"
            }
            Op::StrongFinish => "whether the team dropped its opener but won its closer",
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::IsPerfectSeason | Op::StrongFinish => "bool",
            _ => "i64",
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

/// Wins carried into today: the trailing run from the far end.
fn b_current_win_streak(results: &[u64]) -> i64 {
    let mut run = 0i64;
    for &r in results.iter().rev() {
        if r == 1 {
            run += 1;
        } else {
            break;
        }
    }
    run
}

/// The longest winning run anywhere in the record.
fn b_best_win_streak(results: &[u64]) -> i64 {
    let mut best = 0i64;
    let mut cur = 0i64;
    for &r in results {
        if r == 1 {
            cur += 1;
            if cur > best {
                best = cur;
            }
        } else {
            cur = 0;
        }
    }
    best
}

/// Total games won.
fn b_num_wins(results: &[u64]) -> i64 {
    results.iter().filter(|&&r| r == 1).count() as i64
}

/// A clean sweep: every game won; an empty record is no season.
fn b_is_perfect_season(results: &[u64]) -> bool {
    !results.is_empty() && results.iter().all(|&r| r == 1)
}

/// Dropped the opener, won the closer.
fn b_strong_finish(results: &[u64]) -> bool {
    match (results.first(), results.last()) {
        (Some(&f), Some(&l)) => f == 0 && l == 1,
        _ => false,
    }
}

/// The answer shape: scalars as `Num`, predicates as `Flag`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(v) => v.to_string(),
        }
    }
}

fn op_eval(op: Op, results: &[u64]) -> Out {
    match op {
        Op::CurrentWinStreak => Out::Num(b_current_win_streak(results)),
        Op::BestWinStreak => Out::Num(b_best_win_streak(results)),
        Op::NumWins => Out::Num(b_num_wins(results)),
        Op::IsPerfectSeason => Out::Flag(b_is_perfect_season(results)),
        Op::StrongFinish => Out::Flag(b_strong_finish(results)),
    }
}

// ---- canonical season -------------------------------------------------------

const CANONICAL_SEED: u64 = 0x57EA_4A11;

/// The canonical season: sampled from the full table and retried until
/// the anchor facts hold.
///
/// Guaranteed for every seed: it opens on a loss and closes on a win —
/// `strong_finish` answers TRUE there (constant-false cheats die
/// outright) while the opening loss keeps the sweep predicate FALSE
/// (constant-true cheats die too and the pinned perfect example flips
/// cheats that answer false everywhere). A two-win run sits somewhere,
/// so all three scalars are at least one and pairwise distinct.
fn canonical(seed: u64) -> Vec<u64> {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = 4 + rng.below(5);
        let v: Vec<u64> = (0..n).map(|_| rng.below(2)).collect();
        if anchors_hold(&v) {
            return v;
        }
    }
    unreachable!("canonical season sampling failed to satisfy anchors");
}

fn anchors_hold(v: &[u64]) -> bool {
    // Opening loss + closing win keep the scalars alive and the sweep
    // out; a two-win run keeps best clear of the trailing run alone.
    b_strong_finish(v)
        && b_best_win_streak(v) >= 2
        && b_current_win_streak(v) != b_best_win_streak(v)
        && b_current_win_streak(v) != b_num_wins(v)
        && b_best_win_streak(v) != b_num_wins(v)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (Vec<u64>, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_016E;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical strong-finish season first.
    let can = canonical(seed);
    cases.push((
        can.clone(),
        spec.ops.map(|op| (op, op_eval(op, &can))).to_vec(),
    ));
    // Empty record: zero conventions everywhere.
    cases.push((
        Vec::new(),
        spec.ops.map(|op| (op, op_eval(op, &[]))).to_vec(),
    ));
    // A perfect sweep — flips constant-false cheats.
    cases.push((
        vec![1u64, 1, 1, 1],
        spec.ops
            .map(|op| (op, op_eval(op, &[1u64, 1, 1, 1])))
            .to_vec(),
    ));
    // All losses — flips constant-true cheats on the sweep.
    cases.push((
        vec![0u64, 0, 0],
        spec.ops.map(|op| (op, op_eval(op, &[0u64, 0, 0]))).to_vec(),
    ));
    // The shortest possible strong finish.
    cases.push((
        vec![0u64, 1],
        spec.ops.map(|op| (op, op_eval(op, &[0u64, 1]))).to_vec(),
    ));
    for _ in 0..3 {
        let n = 1 + rng.below(6);
        let v: Vec<u64> = (0..n).map(|_| rng.below(2)).collect();
        let outs = spec.ops.map(|op| (op, op_eval(op, &v))).to_vec();
        cases.push((v, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first element types the slice.
fn render_results(v: &[u64]) -> String {
    if v.is_empty() {
        "&[]".to_string()
    } else {
        let items = v
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!("&[{items}u64]")
    }
}

fn op_fn_src(op: Op) -> String {
    match op {
        Op::CurrentWinStreak => format!(
            "pub fn current_win_streak(results: &[u64]) -> {} {{\n    {}\n}}\n",
            op.ret(),
            [
                "let mut run = 0;",
                "for &r in results.iter().rev() {",
                "    if r == 1 {",
                "        run += 1;",
                "    } else {",
                "        break;",
                "    }",
                "}",
                "run",
            ]
            .join("\n    ")
        ),
        Op::BestWinStreak => format!(
            "pub fn best_win_streak(results: &[u64]) -> {} {{\n    {}\n}}\n",
            op.ret(),
            [
                "let mut best = 0;",
                "let mut cur = 0;",
                "for &r in results {",
                "    if r == 1 {",
                "        cur += 1;",
                "        if cur > best {",
                "            best = cur;",
                "        }",
                "    } else {",
                "        cur = 0;",
                "    }",
                "}",
                "best",
            ]
            .join("\n    ")
        ),
        Op::NumWins => format!(
            "pub fn num_wins(results: &[u64]) -> {} {{\n    {}\n}}\n",
            op.ret(),
            ["results.iter().filter(|&&r| r == 1).count() as i64"].join("\n    ")
        ),
        Op::IsPerfectSeason => format!(
            "pub fn is_perfect_season(results: &[u64]) -> {} {{\n    {}\n}}\n",
            op.ret(),
            ["!results.is_empty() && results.iter().all(|&r| r == 1)"].join("\n    ")
        ),
        Op::StrongFinish => format!(
            "pub fn strong_finish(results: &[u64]) -> {} {{\n    {}\n}}\n",
            op.ret(),
            [
                "match (results.first(), results.last()) {",
                "    (Some(&f), Some(&l)) => f == 0 && l == 1,",
                "    _ => false,",
                "}",
            ]
            .join("\n    ")
        ),
    }
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(results: &[u64]) -> {}", op.name(), op.ret())
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op in an emitted assertion.
fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}
fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (v, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  season {}  ->  {}\n",
            render_results(&v),
            results
        ));
    }
    s
}
fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples_prose(spec, seed)
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    let fns = spec.ops.map(op_stub_src).concat();
    format!(
        "//! Implement the two query functions below.\n\
         //!\n\
         //! Examples:\n\
         {doc}\n\
         {fns}",
        doc = doc,
        fns = fns,
    )
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let mut reqs = String::new();
    for op in spec.ops {
        reqs.push_str(&format!("- `{}`: {}.\n", op.name(), op.prose()));
    }
    format!(
        "Implement the two query functions in `src/lib.rs`. The input is \
         a season of results, each `u64` zero or one — one marks a win. \
         The record is ordered from the opener to the closer.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - Work with exact integer arithmetic only; no floating point.\n\
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
        reqs = reqs,
        signatures = spec
            .ops
            .iter()
            .map(|op| format!("{}\n", op_sig_src(*op)))
            .collect::<Vec<_>>()
            .join(""),
        examples = worked_examples_prose(spec, seed),
        canary = canary,
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
    let mut body = format!("use task::{{{imports}}};\n\n");
    for (i, (v, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let results = {};\n",
            render_results(v),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "results"),
                out.lit(),
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the two selected ops, pasted into the test
/// file under `ref_*` names.
fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec)
        .replacen(
            &format!("pub fn {}", spec.ops[0].name()),
            &format!("fn ref_{}", spec.ops[0].name()),
            1,
        )
        .replacen(
            &format!("pub fn {}", spec.ops[1].name()),
            &format!("fn ref_{}", spec.ops[1].name()),
            1,
        );
    let asserts = spec
        .ops
        .iter()
        .map(|op| {
            let call = call_src(*op, "&vals");
            format!("        assert_eq!({call}, ref_{call});\n")
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "use task::{{{imports}}};\n\
         \n\
         {reference}\
         fn nx(state: &mut u64) -> u64 {{\n\
         \x20   *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20   *state >> 33\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_016E;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = (nx(&mut state) % 7) as usize;\n\
         \x20       let mut vals: Vec<u64> = Vec::new();\n\
         \x20       for _ in 0..n {{\n\
         \x20           vals.push((nx(&mut state) % 2) as u64);\n\
         \x20       }}\n\
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
        asserts = asserts,
    )
}
/// Degenerate: zero answers everywhere.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let tail = match op.ret() {
                "bool" => "false",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = results;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query as if every game were won.
/// On the canonical season this misses everywhere — a loss sits up
/// front, so all three scalars fall short of the schedule length, the
/// sweep predicate loses to its constant true, and the strong-finish
/// predicate loses to its constant false. No skips anywhere.
fn allwins_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => match op {
                    Op::IsPerfectSeason => format!("{sig} {{\n    true\n}}\n"),
                    _ => format!("{sig} {{\n    false\n}}\n"),
                },
                _ => format!("{sig} {{\n    results.len() as i64\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct StreaksFamily;

impl Generator for StreaksFamily {
    fn id(&self) -> &str {
        "streaks"
    }
    fn category(&self) -> &str {
        "streak-analysis"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("streaks", seed);

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
            id: format!("streaks/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer queries — no unsafe anywhere.
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // Default oracle weights (docs/04).
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
            ("all-wins-everything".to_string(), allwins_everything(&spec)),
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
        let g = StreaksFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Trailing run: a late loss kills it, a perfect season trails it all.
        assert_eq!(b_current_win_streak(&[1, 1, 1, 0]), 0);
        assert_eq!(b_current_win_streak(&[1, 0, 1, 1]), 2);
        assert_eq!(b_current_win_streak(&[0, 0]), 0);
        assert_eq!(b_current_win_streak(&[1, 1, 1]), 3);
        // Peak run anywhere.
        assert_eq!(b_best_win_streak(&[0, 1, 1, 0, 1]), 2);
        assert_eq!(b_best_win_streak(&[1, 1, 1, 1]), 4);
        assert_eq!(b_best_win_streak(&[0, 0, 0]), 0);
        // Plain count.
        assert_eq!(b_num_wins(&[1, 0, 1, 1]), 3);
        assert_eq!(b_num_wins(&[]), 0);
        // Sweep needs every game; empty is no season.
        assert!(b_is_perfect_season(&[1, 1, 1]));
        assert!(!b_is_perfect_season(&[]));
        assert!(!b_is_perfect_season(&[1, 0, 1]));
        // Strong finish: loss up front, win at the close.
        assert!(b_strong_finish(&[0, 1]));
        assert!(b_strong_finish(&[0, 1, 1, 0, 1]));
        assert!(!b_strong_finish(&[1, 0, 1]));
        assert!(!b_strong_finish(&[0, 1, 0]));
        assert!(!b_strong_finish(&[]));
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
        // The canonical season opens on a loss and closes on a win:
        // const-zero dies on all three scalars outright (each is at
        // least one) and its strong-finish FALSE loses to the canonical
        // TRUE; only the sweep predicate agrees (FALSE) with const-zero
        // — flipped by the pinned sweep example. The all-wins cheat
        // misses everywhere on canonical: an up-front loss keeps every
        // scalar short of the schedule length, and both of its flag
        // answers lose outright. No skips for it at all.
        for seed in 0..200u64 {
            let can = canonical(seed);
            let cur = b_current_win_streak(&can);
            let best = b_best_win_streak(&can);
            let wins = b_num_wins(&can);
            // Anchor facts the sampler enforces.
            assert!(b_strong_finish(&can), "seed {seed}: must finish strong");
            assert!(best >= 2, "seed {seed}: two-win run required");
            assert_ne!(cur, best, "seed {seed}");
            assert_ne!(cur, wins, "seed {seed}");
            assert_ne!(best, wins, "seed {seed}");
            assert!(!can.is_empty(), "seed {seed}");
            // const-zero survives nowhere on the scalars.
            assert_ne!(cur, 0, "const-zero survives at seed {seed}");
            assert_ne!(best, 0, "seed {seed}");
            assert_ne!(wins, 0, "seed {seed}");
            // all-wins survives nowhere: scalars fall short of len,
            // sweep TRUE loses to the opening loss.
            let len = can.len() as i64;
            assert_ne!(cur, len, "all-wins survives current at seed {seed}");
            assert_ne!(best, len, "all-wins survives best at seed {seed}");
            assert_ne!(wins, len, "all-wins survives wins at seed {seed}");
            assert!(
                !b_is_perfect_season(&can),
                "all-wins survives sweep at seed {seed}"
            );
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (v, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &v), out, "seed {seed}");
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
                // Match the `pub fn` line plus the paren so no bare-name
                // substring leaks.
                let fn_line = format!("pub fn {}(", op.name());
                if spec.ops.contains(&op) {
                    assert!(src.contains(&fn_line));
                } else {
                    assert!(!src.contains(&fn_line), "{op:?} leaked");
                }
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let sk = skeleton_src(&spec, seed);
            assert!(sk.contains("todo!()"), "skeleton must be stubbed");
            // Solution-shaped leak tokens must stay out of the skeleton;
            // the worked examples legitimately show outputs, never
            // rules — so tokens carry implementation shapes.
            assert!(!sk.contains(".rev("));
            assert!(!sk.contains(".max("));
            assert!(!sk.contains(".filter("));
            assert!(!sk.contains("break"));
            assert!(!sk.contains("first()"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(".rev("));
            assert!(!p.contains(".max("));
            assert!(!p.contains(".filter("));
            assert!(!p.contains("break"));
            assert!(!p.contains("first()"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here takes the slice alone: no commas on either side.
        for op in OP_ALL {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call = call_src(op, "results");
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = StreaksFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

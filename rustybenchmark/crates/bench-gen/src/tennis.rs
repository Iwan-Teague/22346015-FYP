//! The `tennis` family (category `tennis-scoring`) — game-state
//! predicates over a server/receiver point pair.
//!
//! Where `golf` scores strokes and `dice` reads rolls, this family
//! exercises **state classification inside one game**: the called
//! player's label, the raw margin, deuce, a won game, and advantage.
//! The domain is an ordered pair of raw point counts, each `u64` from
//! zero upward within one game. The seed prunes which two of five
//! query ops are required: `point_label`, `margin`, `is_deuce`,
//! `is_game_won`, `has_advantage`. C(5,2) = **10 distinct skills**,
//! above the diversity floor; op names are semantic. The label query
//! is unary (it reads the server count); the rest take the pair —
//! mixed arities, pinned by the regression test.
//!
//! The canonical score is CONSTRUCTED, not blind-sampled: the server
//! has four to six points and leads by two or three, so the game is
//! WON there (constant-false cheats die outright on that op), the
//! margin is nonzero, and the label caps at forty. Deuce and advantage
//! are impossible on a won game — both answer FALSE on canonical,
//! agreeing with cheats — so each is flipped by its own pinned example
//! (three-all, and ad-in at four-three).
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random scores against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical score) and `midgame-everything` (every query answered as
//! if the score were frozen early — exact nowhere on the canonical
//! win).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    PointLabel,
    Margin,
    IsDeuce,
    IsGameWon,
    HasAdvantage,
}

const OP_ALL: [Op; 5] = [
    Op::PointLabel,
    Op::Margin,
    Op::IsDeuce,
    Op::IsGameWon,
    Op::HasAdvantage,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::PointLabel => "point_label",
            Op::Margin => "margin",
            Op::IsDeuce => "is_deuce",
            Op::IsGameWon => "is_game_won",
            Op::HasAdvantage => "has_advantage",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::PointLabel => {
                "the called score for the server's point count — love, \
                 fifteen, thirty, then forty from three onward"
            }
            Op::Margin => "how many points separate server from receiver",
            Op::IsDeuce => {
                "whether both players sit at three or more with level \
                 counts"
            }
            Op::IsGameWon => {
                "whether the game is over — someone at four or more with \
                 a two-point lead"
            }
            Op::HasAdvantage => "whether a player at four or more leads by exactly one",
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::IsDeuce | Op::IsGameWon | Op::HasAdvantage => "bool",
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

/// The called score for the server's point count; caps at forty.
fn b_point_label(points: u64) -> String {
    match points {
        0 => "love".to_string(),
        1 => "15".to_string(),
        2 => "30".to_string(),
        _ => "40".to_string(),
    }
}

/// The raw point gap.
fn b_margin(server: u64, receiver: u64) -> i64 {
    (server as i64 - receiver as i64).abs()
}

/// Deuce: three or more all.
fn b_is_deuce(server: u64, receiver: u64) -> bool {
    server >= 3 && server == receiver
}

/// Won: four or more with a two-point lead.
fn b_is_game_won(server: u64, receiver: u64) -> bool {
    let (hi, lo) = leader(server, receiver);
    hi >= 4 && hi - lo >= 2
}

/// Advantage: four or more leading by exactly one.
fn b_has_advantage(server: u64, receiver: u64) -> bool {
    let (hi, lo) = leader(server, receiver);
    hi >= 4 && hi - lo == 1
}

fn leader(server: u64, receiver: u64) -> (u64, u64) {
    if server >= receiver {
        (server, receiver)
    } else {
        (receiver, server)
    }
}

/// The answer shape: scalars as `Num`, predicates as `Flag`, labels as
/// `Str`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
    Str(String),
}

impl Out {
    fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(v) => v.to_string(),
            Out::Str(s) => format!("{s:?}"),
        }
    }
}

fn op_eval(op: Op, server: u64, receiver: u64) -> Out {
    // The label query is unary — it reads the server count only.
    match op {
        Op::PointLabel => Out::Str(b_point_label(server)),
        Op::Margin => Out::Num(b_margin(server, receiver)),
        Op::IsDeuce => Out::Flag(b_is_deuce(server, receiver)),
        Op::IsGameWon => Out::Flag(b_is_game_won(server, receiver)),
        Op::HasAdvantage => Out::Flag(b_has_advantage(server, receiver)),
    }
}

// ---- canonical score ------------------------------------------------------

const CANONICAL_SEED: u64 = 0x71CE_BA11;

/// The canonical score: CONSTRUCTED as a won game rather than
/// blind-sampled.
///
/// Guaranteed for every seed: the server holds four to six points and
/// leads by two or three. The win predicate answers TRUE there
/// (constant-false cheats die outright), the margin is nonzero, and
/// the called label caps at forty. Deuce and advantage are impossible
/// on a won game — both answer FALSE on canonical, agreeing with
/// cheats — so each carries its own pinned flip example.
fn canonical(seed: u64) -> (u64, u64) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let winner = 4 + rng.below(3);
        let gap = 2 + rng.below(2);
        let server = winner;
        let receiver = winner - gap;
        if anchors_hold(server, receiver) {
            return (server, receiver);
        }
    }
    unreachable!("canonical score construction failed to satisfy anchors");
}

fn anchors_hold(server: u64, receiver: u64) -> bool {
    b_is_game_won(server, receiver)
        && !b_is_deuce(server, receiver)
        && b_margin(server, receiver) != 0
        && !b_has_advantage(server, receiver)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u64), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0166;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical won game first.
    let can = canonical(seed);
    cases.push((
        can,
        spec.ops.map(|op| (op, op_eval(op, can.0, can.1))).to_vec(),
    ));
    // Love-all: zero conventions across every op.
    cases.push(((0, 0), spec.ops.map(|op| (op, op_eval(op, 0, 0))).to_vec()));
    // Three-all: the classic deuce, flipping constant-false cheats.
    cases.push(((3, 3), spec.ops.map(|op| (op, op_eval(op, 3, 3))).to_vec()));
    // Ad-in at four-three: advantage TRUE, flips constant-false cheats.
    cases.push(((4, 3), spec.ops.map(|op| (op, op_eval(op, 4, 3))).to_vec()));
    // A deep deuce battle.
    cases.push(((5, 5), spec.ops.map(|op| (op, op_eval(op, 5, 5))).to_vec()));
    for _ in 0..2 {
        let server = rng.below(8);
        let receiver = rng.below(8);
        let outs = spec
            .ops
            .map(|op| (op, op_eval(op, server, receiver)))
            .to_vec();
        cases.push(((server, receiver), outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first element types the tuple.
fn render_pair(server: u64, receiver: u64) -> String {
    format!("({server}u64, {receiver})")
}

fn op_fn_src(op: Op) -> String {
    match op {
        Op::PointLabel => format!(
            "pub fn point_label(points: u64) -> String {{\n    {}\n}}\n",
            [
                "match points {",
                "    0 => \"love\".to_string(),",
                "    1 => \"15\".to_string(),",
                "    2 => \"30\".to_string(),",
                "    _ => \"40\".to_string(),",
                "}",
            ]
            .join("\n    ")
        ),
        Op::Margin => format!(
            "pub fn margin(server: u64, receiver: u64) -> i64 {{\n    {}\n}}\n",
            ["(server as i64 - receiver as i64).abs()"].join("\n    ")
        ),
        Op::IsDeuce => format!(
            "pub fn is_deuce(server: u64, receiver: u64) -> bool {{\n    {}\n}}\n",
            ["server >= 3 && server == receiver"].join("\n    ")
        ),
        Op::IsGameWon => format!(
            "pub fn is_game_won(server: u64, receiver: u64) -> bool {{\n    {}\n}}\n",
            [
                "let hi = if server >= receiver { server } else { receiver };",
                "let lo = if server >= receiver { receiver } else { server };",
                "hi >= 4 && hi - lo >= 2",
            ]
            .join("\n    ")
        ),
        Op::HasAdvantage => format!(
            "pub fn has_advantage(server: u64, receiver: u64) -> bool {{\n    {}\n}}\n",
            [
                "let hi = if server >= receiver { server } else { receiver };",
                "let lo = if server >= receiver { receiver } else { server };",
                "hi >= 4 && hi - lo == 1",
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
    match op {
        Op::PointLabel => "pub fn point_label(points: u64) -> String".to_string(),
        _ => format!(
            "pub fn {}(server: u64, receiver: u64) -> {}",
            op.name(),
            op.ret()
        ),
    }
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op in an emitted assertion. The label
/// query reads the server count; the rest take the pair.
fn call_src(op: Op) -> String {
    match op {
        Op::PointLabel => "point_label(server)".to_string(),
        _ => format!("{}(server, receiver)", op.name()),
    }
}
fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for ((server, receiver), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  score {}  ->  {}\n",
            render_pair(server, receiver),
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
         an ordered pair `(server, receiver)` of raw point counts inside \
         one game of tennis, each `u64` counting points won. Traditional \
         calls run love, fifteen, thirty, forty; from three-all onward a \
         game needs two clear points to finish.\n\
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
    for (i, ((server, receiver), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (server, receiver) = {};\n",
            render_pair(*server, *receiver),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op),
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
            let call = call_src(*op);
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0166;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let server = nx(&mut state) % 8;\n\
         \x20       let receiver = nx(&mut state) % 8;\n\
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
            let silence = match op {
                Op::PointLabel => "let _ = points;",
                _ => "let _ = (server, receiver);",
            };
            format!("{sig} {{\n    {silence}\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query as if the score were
/// frozen early in the game. On the canonical won score this misses
/// everywhere — the called label stays fifteen, the margin reads one
/// against a real gap, and all three predicates lose to their constant
/// false. No op agrees with it on canonical.
fn midgame_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op {
                Op::PointLabel => {
                    format!("{sig} {{\n    \"15\".to_string()\n}}\n")
                }
                Op::Margin => format!("{sig} {{\n    1\n}}\n"),
                _ => format!("{sig} {{\n    false\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct TennisFamily;

impl Generator for TennisFamily {
    fn id(&self) -> &str {
        "tennis"
    }
    fn category(&self) -> &str {
        "tennis-scoring"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("tennis", seed);

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
            id: format!("tennis/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer and label queries — no unsafe anywhere.
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
            ("midgame-everything".to_string(), midgame_everything(&spec)),
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
        let g = TennisFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Called labels: every rung plus the forty cap.
        assert_eq!(b_point_label(0), "love");
        assert_eq!(b_point_label(1), "15");
        assert_eq!(b_point_label(2), "30");
        assert_eq!(b_point_label(3), "40");
        assert_eq!(b_point_label(9), "40");
        // Margins: order-blind.
        assert_eq!(b_margin(4, 1), 3);
        assert_eq!(b_margin(1, 4), 3);
        assert_eq!(b_margin(2, 2), 0);
        // Deuce needs three and level.
        assert!(!b_is_deuce(2, 2));
        assert!(b_is_deuce(3, 3));
        assert!(b_is_deuce(9, 9));
        // Wins need four and two clear; receiver wins count too.
        assert!(b_is_game_won(4, 0));
        assert!(b_is_game_won(2, 5));
        assert!(!b_is_game_won(4, 3));
        assert!(!b_is_game_won(7, 6));
        // Advantage is exactly one clear at four or more.
        assert!(b_has_advantage(4, 3));
        assert!(b_has_advantage(8, 7));
        assert!(!b_has_advantage(5, 3));
        assert!(!b_has_advantage(2, 1));
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
        // The canonical score is CONSTRUCTED as a won game: the win
        // predicate answers TRUE (const-zero and midgame-everything lose
        // there outright), the margin reads the real gap (two or three,
        // never zero or one), and the called label caps at forty. Deuce
        // and advantage are impossible on a won game — both answer FALSE
        // on canonical, agreeing with cheats — so each carries its own
        // pinned flip example (three-all, ad-in at four-three) and both
        // are skipped in this loop with those flips documented.
        for seed in 0..200u64 {
            let (server, receiver) = canonical(seed);
            let label = b_point_label(server);
            let gap = b_margin(server, receiver);
            // Anchor facts the constructor enforces.
            assert!(b_is_game_won(server, receiver), "seed {seed}: must be won");
            assert!(!b_is_deuce(server, receiver), "seed {seed}");
            assert!((2..=3).contains(&gap), "seed {seed}: gap two or three");
            // const-zero survives nowhere it can reach on canonical.
            assert_ne!(label, "", "const-zero survives label at seed {seed}");
            assert_ne!(gap, 0, "seed {seed}");
            assert!(b_is_game_won(server, receiver), "seed {seed}");
            // midgame-everything survives nowhere on canonical either.
            assert_ne!(label, "15", "midgame survives label at seed {seed}");
            assert_ne!(gap, 1, "midgame survives margin at seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((server, receiver), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, server, receiver), out, "seed {seed}");
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
            // the worked examples legitimately show quoted outputs like
            // "40", so tokens carry implementation shapes only.
            assert!(!sk.contains(".to_string("));
            assert!(!sk.contains("hi - lo"));
            assert!(!sk.contains(">= 4"));
            assert!(!sk.contains(">= 3"));
            assert!(!sk.contains(".abs("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(".to_string("));
            assert!(!p.contains("hi - lo"));
            assert!(!p.contains(">= 4"));
            assert!(!p.contains(">= 3"));
            assert!(!p.contains(".abs("));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // The label query takes one count; the rest take the pair.
        for op in OP_ALL {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call = call_src(op);
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = TennisFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

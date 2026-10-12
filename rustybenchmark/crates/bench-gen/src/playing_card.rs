//! The `playing-card` family (category `card-games`) — lookup semantics
//! over one playing card.
//!
//! Where `pitch` reads MIDI pairs and `perms` decomposes octal modes,
//! this family exercises **card-table conventions**: the rank's poker
//! name, the face-card predicate, the blackjack score, the suit's name
//! in its fixed order, and the red-suit predicate. The domain is an
//! ordered pair: a rank `u64` from one through thirteen (ace is one,
//! jack eleven, queen twelve, king thirteen) and a suit `u64` from zero
//! through three in the fixed order clubs, diamonds, hearts, spades.
//! The seed prunes which two of five query ops are required:
//! `rank_name`, `is_face_card`, `blackjack_value`, `suit_name`,
//! `is_red`. C(5,2) = **10 distinct skills**, above the diversity floor;
//! op names are semantic.
//!
//! The canonical card is sampled until its anchor facts hold: it is a
//! RED FACE CARD — so both predicates answer TRUE there and every
//! trivial baseline fails on every op outright (the pinned black-ace
//! example flips constant-true cheats).
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random cards against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical card) and `rank-everything` (every query answered with the
//! raw rank — wrong on all five for a face card, whose name is spelled,
//! whose score is ten, and whose predicates answer true).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    RankName,
    IsFaceCard,
    BlackjackValue,
    SuitName,
    IsRed,
}

const OP_ALL: [Op; 5] = [
    Op::RankName,
    Op::IsFaceCard,
    Op::BlackjackValue,
    Op::SuitName,
    Op::IsRed,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::RankName => "rank_name",
            Op::IsFaceCard => "is_face_card",
            Op::BlackjackValue => "blackjack_value",
            Op::SuitName => "suit_name",
            Op::IsRed => "is_red",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::RankName => {
                "the card's rank rendered as table text: the ace, the \
                 number itself for two through ten, then jack, queen, \
                 king"
            }
            Op::IsFaceCard => "whether the rank is a face card — jack, queen, or king",
            Op::BlackjackValue => {
                "the blackjack score of the rank: the ace counts \
                 eleven, face cards count ten, and number cards count \
                 themselves"
            }
            Op::SuitName => {
                "the suit's name, in the fixed order clubs, diamonds, \
                 hearts, spades"
            }
            Op::IsRed => {
                "whether the suit is one of the two red ones — hearts \
                 or diamonds"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::RankName | Op::SuitName => "String",
            Op::IsFaceCard | Op::IsRed => "bool",
            Op::BlackjackValue => "i64",
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

/// Poker-text rank name: A, 2..10, J, Q, K.
fn b_rank_name(rank: u64) -> String {
    match rank {
        1 => "A".to_string(),
        11 => "J".to_string(),
        12 => "Q".to_string(),
        13 => "K".to_string(),
        n => n.to_string(),
    }
}

/// Face cards are jack, queen, king.
fn b_is_face_card(rank: u64) -> bool {
    rank >= 11
}

/// Blackjack score: ace eleven, faces ten, pips themselves.
fn b_blackjack_value(rank: u64) -> i64 {
    match rank {
        1 => 11,
        11..=13 => 10,
        n => n as i64,
    }
}

/// Suit name in the fixed order; out-of-range renders a dash.
fn b_suit_name(suit: u64) -> String {
    match suit {
        0 => "clubs".to_string(),
        1 => "diamonds".to_string(),
        2 => "hearts".to_string(),
        3 => "spades".to_string(),
        _ => "-".to_string(),
    }
}

/// Hearts and diamonds are red.
fn b_is_red(suit: u64) -> bool {
    suit == 1 || suit == 2
}

/// The answer shape: scalars as `Num`, predicates as `Flag`, text as `Str`.
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
            Out::Flag(b) => b.to_string(),
            Out::Str(s) => format!("{s:?}"),
        }
    }
}

fn op_eval(op: Op, rank: u64, suit: u64) -> Out {
    match op {
        Op::RankName => Out::Str(b_rank_name(rank)),
        Op::IsFaceCard => Out::Flag(b_is_face_card(rank)),
        Op::BlackjackValue => Out::Num(b_blackjack_value(rank)),
        Op::SuitName => Out::Str(b_suit_name(suit)),
        Op::IsRed => Out::Flag(b_is_red(suit)),
    }
}

// ---- canonical card -------------------------------------------------------

/// The canonical card: sampled from the full deck and retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: a RED FACE CARD — jack, queen, or king of
/// hearts or diamonds. Both predicates answer TRUE there, so
/// constant-false cheats die outright (the pinned black-ace example
/// flips constant-true ones); the blackjack score is ten, distinct from
/// every face rank; and the two names come from disjoint vocabularies,
/// so echoing one query's answer for another is wrong everywhere.
fn canonical(seed: u64) -> (u64, u64) {
    let mut rng = Rng::new(seed ^ 0xFA9E_C411);
    for _ in 0..100_000 {
        let rank = 1 + rng.below(13);
        let suit = rng.below(4);
        if anchors_hold(rank, suit) {
            return (rank, suit);
        }
    }
    unreachable!("canonical card sampling failed to satisfy anchors");
}

fn anchors_hold(rank: u64, suit: u64) -> bool {
    // A red face card: both predicates true, score ten (never equal to
    // a face rank), names from disjoint vocabularies.
    b_is_face_card(rank)
        && b_is_red(suit)
        && b_blackjack_value(rank) != rank as i64
        && b_rank_name(rank) != b_suit_name(suit)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u64), Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_015C);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical red face card first.
    let can = canonical(seed);
    cases.push((
        can,
        spec.ops.map(|op| (op, op_eval(op, can.0, can.1))).to_vec(),
    ));
    // Black ace of clubs: both predicates FALSE — flips constant-true cheats.
    cases.push(((1, 0), spec.ops.map(|op| (op, op_eval(op, 1, 0))).to_vec()));
    // A low pip in spades.
    cases.push(((2, 3), spec.ops.map(|op| (op, op_eval(op, 2, 3))).to_vec()));
    for _ in 0..3 {
        let rank = 1 + rng.below(13);
        let suit = rng.below(4);
        let outs = spec.ops.map(|op| (op, op_eval(op, rank, suit))).to_vec();
        cases.push(((rank, suit), outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first element types the tuple.
fn render_pair(rank: u64, suit: u64) -> String {
    format!("({rank}u64, {suit})")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(rank: u64, suit: u64) -> {ret}");
    let body = match op {
        Op::RankName => [
            "let _ = suit;",
            "match rank {",
            "    1 => \"A\".to_string(),",
            "    11 => \"J\".to_string(),",
            "    12 => \"Q\".to_string(),",
            "    13 => \"K\".to_string(),",
            "    n => n.to_string(),",
            "}",
        ]
        .join("\n    "),
        Op::IsFaceCard => ["let _ = suit;", "rank >= 11"].join("\n    "),
        Op::BlackjackValue => [
            "let _ = suit;",
            "match rank {",
            "    1 => 11,",
            "    11..=13 => 10,",
            "    n => n as i64,",
            "}",
        ]
        .join("\n    "),
        Op::SuitName => [
            "let _ = rank;",
            "match suit {",
            "    0 => \"clubs\".to_string(),",
            "    1 => \"diamonds\".to_string(),",
            "    2 => \"hearts\".to_string(),",
            "    3 => \"spades\".to_string(),",
            "    _ => \"-\".to_string(),",
            "}",
        ]
        .join("\n    "),
        Op::IsRed => ["let _ = rank;", "suit == 1 || suit == 2"].join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(rank: u64, suit: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(rank: u64, suit: u64) -> {}", op.name(), op.ret())
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
    for ((rank, suit), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  card {}  ->  {}\n",
            render_pair(rank, suit),
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
         an ordered pair `(rank, suit)`: a rank `u64` from one through \
         thirteen (the ace is one, jack eleven, queen twelve, king \
         thirteen; number cards are their own value) and a suit `u64` \
         from zero through three in the fixed order clubs, diamonds, \
         hearts, spades.\n\
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
    for (i, ((rank, suit), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (rank, suit) = {};\n",
            render_pair(*rank, *suit),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "rank, suit"),
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
            let call = call_src(*op, "rank, suit");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_015C;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let rank = (nx(&mut state) % 13) + 1;\n\
         \x20       let suit = nx(&mut state) % 4;\n\
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
                "String" => "String::new()",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = (rank, suit);\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the raw rank. On the
/// canonical red face card this misses everywhere — the spelled name is
/// not a digit string, the score is ten rather than the face rank, and
/// both predicates answer true where this answers false.
fn rank_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    false\n}}\n"),
                "String" => format!("{sig} {{\n    rank.to_string()\n}}\n"),
                _ => format!("{sig} {{\n    rank as i64\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct PlayingCardFamily;

impl Generator for PlayingCardFamily {
    fn id(&self) -> &str {
        "playing-card"
    }
    fn category(&self) -> &str {
        "card-games"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("playing-card", seed);

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
            id: format!("playing-card/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure lookup and integer queries — no unsafe anywhere.
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
            ("rank-everything".to_string(), rank_everything(&spec)),
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
        let g = PlayingCardFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Rank names: ace, pips, faces.
        assert_eq!(b_rank_name(1), "A");
        for n in 2..=10u64 {
            assert_eq!(b_rank_name(n), n.to_string());
        }
        assert_eq!(b_rank_name(11), "J");
        assert_eq!(b_rank_name(12), "Q");
        assert_eq!(b_rank_name(13), "K");
        // Face boundary: jack and above, ten is not a face.
        assert!(!b_is_face_card(1));
        for n in 2..=10u64 {
            assert!(!b_is_face_card(n));
        }
        assert!(b_is_face_card(11));
        assert!(b_is_face_card(12));
        assert!(b_is_face_card(13));
        // Blackjack: ace eleven, faces ten, pips themselves.
        assert_eq!(b_blackjack_value(1), 11);
        for n in 2..=10u64 {
            assert_eq!(b_blackjack_value(n), n as i64);
        }
        assert_eq!(b_blackjack_value(11), 10);
        assert_eq!(b_blackjack_value(12), 10);
        assert_eq!(b_blackjack_value(13), 10);
        // Suit names walk the fixed order; suit independent of rank.
        assert_eq!(b_suit_name(0), "clubs");
        assert_eq!(b_suit_name(1), "diamonds");
        assert_eq!(b_suit_name(2), "hearts");
        assert_eq!(b_suit_name(3), "spades");
        // Red suits are hearts and diamonds only.
        assert!(!b_is_red(0));
        assert!(b_is_red(1));
        assert!(b_is_red(2));
        assert!(!b_is_red(3));
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
        // The canonical card is a RED FACE CARD, so NO skips anywhere:
        // const-zero dies on all five ops outright (score ten, spelled
        // names, both predicates true); rank-everything misses too —
        // its digit-string name is not the spelled name, its score is
        // the face rank rather than ten, and its false flags lose to
        // the canonical TRUEs. The pinned black-ace example flips
        // constant-true cheats.
        for seed in 0..200u64 {
            let (rank, suit) = canonical(seed);
            let bjv = b_blackjack_value(rank);
            // Anchor facts the sampler enforces.
            assert!(b_is_face_card(rank), "seed {seed}: must be a face card");
            assert!(b_is_red(suit), "seed {seed}: must be a red suit");
            assert_ne!(
                bjv, rank as i64,
                "seed {seed}: score must differ from the face rank"
            );
            assert_ne!(
                b_rank_name(rank),
                b_suit_name(suit),
                "seed {seed}: name vocabularies must stay disjoint"
            );
            // const-zero survives nowhere.
            assert_ne!(bjv, 0, "const-zero survives at seed {seed}");
            assert!(!b_rank_name(rank).is_empty(), "seed {seed}");
            assert!(!b_suit_name(suit).is_empty(), "seed {seed}");
            assert!(b_is_face_card(rank), "seed {seed}");
            assert!(b_is_red(suit), "seed {seed}");
            // rank-everything survives nowhere on this card.
            let rn = b_rank_name(rank);
            let sn = b_suit_name(suit);
            assert_ne!(
                bjv, rank as i64,
                "rank-everything survives blackjack_value at seed {seed}"
            );
            assert_ne!(
                rn,
                rank.to_string(),
                "rank-everything survives rank_name at seed {seed}"
            );
            assert_ne!(
                sn,
                rank.to_string(),
                "rank-everything survives suit_name at seed {seed}"
            );
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((rank, suit), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, rank, suit), out, "seed {seed}");
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
            // the worked examples legitimately show outputs like "J",
            // never rules — so tokens carry implementation shapes.
            assert!(!sk.contains(">= 11"));
            assert!(!sk.contains("== 1 ||"));
            assert!(!sk.contains("11..=13"));
            assert!(!sk.contains(".to_string("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(">= 11"));
            assert!(!p.contains("== 1 ||"));
            assert!(!p.contains("11..=13"));
            assert!(!p.contains(".to_string("));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here takes the pair: exactly one comma on both sides.
        for op in OP_ALL {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call = call_src(op, "rank, suit");
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = PlayingCardFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

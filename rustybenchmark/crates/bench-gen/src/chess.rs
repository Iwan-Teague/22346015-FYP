//! The `chess` family (category `chess-values`) — material-table
//! arithmetic over a matchup pair.
//!
//! Where `tennis` reads a game score and `playing-card` reads one card,
//! this family exercises **table lookups plus a cross-side compare**:
//! the material value of my piece, its name, the minor-piece and royal
//! predicates, and whether trading my piece for theirs wins material.
//! The domain is an ordered pair of piece codes, each `u64` from one
//! through six (one pawn, two knight, three bishop, four rook, five
//! queen, six king). The seed prunes which two of five query ops are
//! required: `piece_value`, `piece_name`, `is_minor`, `is_royal`,
//! `trades_favorably`. C(5,2) = **10 distinct skills**, above the
//! diversity floor; op names are semantic. The two lookup queries are
//! unary (they read my side); the other three take the pair — mixed
//! arities, pinned by the regression test.
//!
//! The canonical matchup is constructed, not blind-sampled: my side is
//! a rook or the queen and theirs is a pawn or a knight, so the trade
//! predicate answers TRUE there (constant-false cheats die outright),
//! neither unary flag fires (both agree with cheats' constant false and
//! are flipped by the pinned knight and king examples), and every
//! scalar answer stays clear of zero and of the pawn-mine cheat.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random matchups against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical matchup) and `pawn-mine-everything` (every query answered
//! as if my side were a pawn — exact nowhere on the canonical matchup,
//! whose rook-or-queen disagrees on both lookups and loses the trade).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    PieceValue,
    PieceName,
    IsMinor,
    IsRoyal,
    TradesFavorably,
}

const OP_ALL: [Op; 5] = [
    Op::PieceValue,
    Op::PieceName,
    Op::IsMinor,
    Op::IsRoyal,
    Op::TradesFavorably,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::PieceValue => "piece_value",
            Op::PieceName => "piece_name",
            Op::IsMinor => "is_minor",
            Op::IsRoyal => "is_royal",
            Op::TradesFavorably => "trades_favorably",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::PieceValue => {
                "my piece's material worth — one point for a pawn, three \
                 for each minor piece, five for a rook, nine for the \
                 queen, and nothing at all for a king"
            }
            Op::PieceName => "my piece's name",
            Op::IsMinor => "whether my piece is one of the two minor pieces",
            Op::IsRoyal => "whether my piece is the king",
            Op::TradesFavorably => "whether giving up my piece for theirs wins material",
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::PieceName => "String",
            Op::IsMinor | Op::IsRoyal | Op::TradesFavorably => "bool",
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

/// The material table: pawn one, minors three, rook five, queen nine,
/// king beyond price (zero for trading math).
fn b_value(code: u64) -> i64 {
    match code {
        1 => 1,
        2 | 3 => 3,
        4 => 5,
        5 => 9,
        _ => 0,
    }
}

/// My piece's material worth.
fn b_piece_value(mine: u64, theirs: u64) -> i64 {
    let _ = theirs;
    b_value(mine)
}

/// My piece's name.
fn b_piece_name(mine: u64, theirs: u64) -> String {
    let _ = theirs;
    match mine {
        1 => "pawn".to_string(),
        2 => "knight".to_string(),
        3 => "bishop".to_string(),
        4 => "rook".to_string(),
        5 => "queen".to_string(),
        _ => "king".to_string(),
    }
}

/// Minor pieces are exactly knight and bishop.
fn b_is_minor(mine: u64, theirs: u64) -> bool {
    let _ = theirs;
    mine == 2 || mine == 3
}

/// Only the king is royal.
fn b_is_royal(mine: u64, theirs: u64) -> bool {
    let _ = theirs;
    mine == 6
}

/// Whether my material strictly exceeds theirs; a royal trade never
/// counts because the king's value is zero.
fn b_trades_favorably(mine: u64, theirs: u64) -> bool {
    b_value(mine) > b_value(theirs)
}

/// The answer shape: scalars as `Num`, predicates as `Flag`, names as
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

fn op_eval(op: Op, mine: u64, theirs: u64) -> Out {
    // Unary lookup queries read MY side only.
    match op {
        Op::PieceValue => Out::Num(b_piece_value(mine, theirs)),
        Op::PieceName => Out::Str(b_piece_name(mine, theirs)),
        Op::IsMinor => Out::Flag(b_is_minor(mine, theirs)),
        Op::IsRoyal => Out::Flag(b_is_royal(mine, theirs)),
        Op::TradesFavorably => Out::Flag(b_trades_favorably(mine, theirs)),
    }
}

// ---- canonical matchup ----------------------------------------------------

const CANONICAL_SEED: u64 = 0x8C4E_55A1;

/// The canonical matchup: constructed so the anchors hold by arithmetic,
/// not blind sampling.
///
/// Guaranteed for every seed: my side is a rook or the queen and theirs
/// is a pawn or a knight — the trade predicate answers TRUE there
/// (constant-false cheats die outright), neither unary flag fires (both
/// agree with cheats' constant false and are flipped by pinned examples),
/// and every scalar stays clear of zero and of the pawn-mine cheat.
fn canonical(seed: u64) -> (u64, u64) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let mine = [4u64, 5][rng.below(2) as usize];
        let theirs = 1 + rng.below(2);
        if anchors_hold(mine, theirs) {
            return (mine, theirs);
        }
    }
    unreachable!("canonical matchup sampling failed to satisfy anchors");
}

fn anchors_hold(mine: u64, theirs: u64) -> bool {
    // STRICT: my side must actually win the material exchange.
    b_trades_favorably(mine, theirs) && !b_is_minor(mine, theirs) && !b_is_royal(mine, theirs)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u64), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0168;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical winning matchup first.
    let can = canonical(seed);
    cases.push((
        can,
        spec.ops.map(|op| (op, op_eval(op, can.0, can.1))).to_vec(),
    ));
    // Knight versus pawn: flips the minor flag's constant false.
    cases.push(((2, 1), spec.ops.map(|op| (op, op_eval(op, 2, 1))).to_vec()));
    // King versus pawn: flips the royal flag; the trade loses material
    // under the zero convention.
    cases.push(((6, 1), spec.ops.map(|op| (op, op_eval(op, 6, 1))).to_vec()));
    // Pawn versus pawn: pure conventions.
    cases.push(((1, 1), spec.ops.map(|op| (op, op_eval(op, 1, 1))).to_vec()));
    // Bishop versus rook: minor again true, trade goes the other way.
    cases.push(((3, 4), spec.ops.map(|op| (op, op_eval(op, 3, 4))).to_vec()));
    for _ in 0..3 {
        let mine = 1 + rng.below(6);
        let theirs = 1 + rng.below(6);
        let outs = spec.ops.map(|op| (op, op_eval(op, mine, theirs))).to_vec();
        cases.push(((mine, theirs), outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first element types the tuple.
fn render_pair(mine: u64, theirs: u64) -> String {
    format!("({mine}u64, {theirs})")
}

fn op_fn_src(op: Op) -> String {
    match op {
        Op::PieceValue => format!(
            "pub fn piece_value(piece: u64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            [
                "match piece {",
                "    1 => 1,",
                "    2 | 3 => 3,",
                "    4 => 5,",
                "    5 => 9,",
                "    _ => 0,",
                "}",
            ]
            .join("\n    ")
        ),
        Op::PieceName => format!(
            "pub fn piece_name(piece: u64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            [
                "match piece {",
                "    1 => \"pawn\".to_string(),",
                "    2 => \"knight\".to_string(),",
                "    3 => \"bishop\".to_string(),",
                "    4 => \"rook\".to_string(),",
                "    5 => \"queen\".to_string(),",
                "    _ => \"king\".to_string(),",
                "}",
            ]
            .join("\n    ")
        ),
        Op::IsMinor => format!(
            "pub fn is_minor(mine: u64, theirs: u64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            ["let _ = theirs;", "mine == 2 || mine == 3"].join("\n    ")
        ),
        Op::IsRoyal => format!(
            "pub fn is_royal(mine: u64, theirs: u64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            ["let _ = theirs;", "mine == 6"].join("\n    ")
        ),
        Op::TradesFavorably => format!(
            "pub fn trades_favorably(mine: u64, theirs: u64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            [
                "let my_value = match mine {",
                "    1 => 1,",
                "    2 | 3 => 3,",
                "    4 => 5,",
                "    5 => 9,",
                "    _ => 0,",
                "};",
                "let their_value = match theirs {",
                "    1 => 1,",
                "    2 | 3 => 3,",
                "    4 => 5,",
                "    5 => 9,",
                "    _ => 0,",
                "};",
                "my_value > their_value",
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
        Op::PieceValue => format!("pub fn piece_value(piece: u64) -> {}", op.ret()),
        Op::PieceName => format!("pub fn piece_name(piece: u64) -> {}", op.ret()),
        _ => format!(
            "pub fn {}(mine: u64, theirs: u64) -> {}",
            op.name(),
            op.ret()
        ),
    }
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op in an emitted assertion. The lookup
/// queries read my side only; the rest take the pair.
fn call_src(op: Op) -> String {
    match op {
        Op::PieceValue | Op::PieceName => format!("{}(mine)", op.name()),
        _ => format!("{}(mine, theirs)", op.name()),
    }
}
fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for ((mine, theirs), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  matchup {}  ->  {}\n",
            render_pair(mine, theirs),
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
         an ordered pair `(mine, theirs)`: two piece codes, each `u64` \
         from one through six — one pawn, two knight, three bishop, four \
         rook, five queen, six king.\n\
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
    for (i, ((mine, theirs), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (mine, theirs) = {};\n",
            render_pair(*mine, *theirs),
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0168;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let mine = (nx(&mut state) % 6) + 1;\n\
         \x20       let theirs = (nx(&mut state) % 6) + 1;\n\
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
            let silence = match op {
                Op::PieceValue | Op::PieceName => "let _ = piece;",
                _ => "let _ = (mine, theirs);",
            };
            format!("{sig} {{\n    {silence}\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every lookup as if my side were a pawn.
/// On the canonical matchup this misses everywhere — the rook-or-queen
/// disagrees on both lookups and loses the trade — while both flags
/// agree (false) and are flipped by the pinned knight and king examples.
fn pawn_mine_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op {
                Op::PieceValue => {
                    format!("{sig} {{\n    let _ = piece;\n    1\n}}\n",)
                }
                Op::PieceName => {
                    format!("{sig} {{\n    \"pawn\".to_string()\n}}\n")
                }
                Op::IsMinor | Op::IsRoyal => format!("{sig} {{\n    false\n}}\n"),
                Op::TradesFavorably => format!(
                    "{sig} {{\n    {}\n}}\n",
                    [
                        "let their_value = match theirs {",
                        "    1 => 1,",
                        "    2 | 3 => 3,",
                        "    4 => 5,",
                        "    5 => 9,",
                        "    _ => 0,",
                        "};",
                        "1 > their_value",
                    ]
                    .join("\n    ")
                ),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct ChessFamily;

impl Generator for ChessFamily {
    fn id(&self) -> &str {
        "chess"
    }
    fn category(&self) -> &str {
        "chess-values"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("chess", seed);

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
            id: format!("chess/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure table lookups and integer compares — no unsafe anywhere.
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
            (
                "pawn-mine-everything".to_string(),
                pawn_mine_everything(&spec),
            ),
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
        let g = ChessFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // The material table, including the priceless king.
        assert_eq!(b_piece_value(1, 1), 1);
        assert_eq!(b_piece_value(2, 1), 3);
        assert_eq!(b_piece_value(3, 1), 3);
        assert_eq!(b_piece_value(4, 1), 5);
        assert_eq!(b_piece_value(5, 1), 9);
        assert_eq!(b_piece_value(6, 1), 0);
        // Names read my side only.
        assert_eq!(b_piece_name(5, 2), "queen");
        assert_eq!(b_piece_name(6, 2), "king");
        // Minor pieces are exactly knight and bishop.
        assert!(b_is_minor(2, 1));
        assert!(b_is_minor(3, 4));
        for code in [1u64, 4, 5, 6] {
            assert!(!b_is_minor(code, 1));
        }
        // Only the king is royal.
        assert!(b_is_royal(6, 5));
        for code in 1..=5u64 {
            assert!(!b_is_royal(code, 1));
        }
        // Trades: queen-for-pawn wins both orders; equals never;
        // a royal trade loses under the zero convention.
        assert!(b_trades_favorably(5, 1));
        assert!(!b_trades_favorably(1, 5));
        assert!(!b_trades_favorably(4, 4));
        assert!(!b_trades_favorably(2, 3));
        assert!(b_trades_favorably(4, 2));
        assert!(!b_trades_favorably(6, 1));
        assert!(b_trades_favorably(1, 6));
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
        // The canonical matchup is rook-or-queen versus pawn-or-knight:
        // const-zero dies on every op outright (nonzero value, nonempty
        // name, trade TRUE); pawn-mine-everything misses both lookups
        // and the trade. Both flags agree (false) with every cheat on
        // canonical — the pinned knight and king examples flip them.
        for seed in 0..200u64 {
            let (mine, theirs) = canonical(seed);
            let val = b_piece_value(mine, theirs);
            let name = b_piece_name(mine, theirs);
            // Anchor facts the sampler enforces.
            assert!(
                b_trades_favorably(mine, theirs),
                "seed {seed}: must win the trade"
            );
            assert!(!b_is_minor(mine, theirs), "seed {seed}");
            assert!(!b_is_royal(mine, theirs), "seed {seed}");
            // const-zero survives nowhere on the scalars.
            assert_ne!(val, 0, "const-zero survives at seed {seed}");
            assert!(!name.is_empty(), "seed {seed}");
            // pawn-mine-everything survives nowhere on the scalars.
            assert_ne!(val, 1, "pawn cheat survives value at seed {seed}");
            assert_ne!(name, "pawn", "pawn cheat survives name at seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((mine, theirs), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, mine, theirs), out, "seed {seed}");
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
            // the worked examples legitimately show quoted names, never
            // rules — so tokens carry implementation shapes only.
            assert!(!sk.contains("=> 1"));
            assert!(!sk.contains("2 | 3"));
            assert!(!sk.contains(".to_string("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("=> 1"));
            assert!(!p.contains("2 | 3"));
            assert!(!p.contains(".to_string("));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Lookup queries take one code; the rest take the pair.
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
        let g = ChessFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

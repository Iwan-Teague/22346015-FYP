//! Pattern-matching puzzles over one wire of tagged messages.
//!
//! Every query here is answered by matching on an enum with payloads, and
//! the match must be exhaustive: Rust rejects any arm set that forgets a
//! variant. The skill is binding the right payloads in each arm — and
//! moving the two weighted kinds in OPPOSITE directions for the balance.
//! A cheat that collapses every arm to a constant compiles but answers
//! wrong on every non-degenerate wire.

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// The three message kinds on one wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Msg {
    /// A request carrying a weight.
    Ask(u64),
    /// A reply carrying a weight.
    Tell(u64),
    /// Keep-alive with no payload.
    Ping,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    TotalPayload,
    MaxPayload,
    FirstPingIndex,
    CountKind,
    WeightedBalance,
}

pub const OP_ALL: [Op; 5] = [
    Op::TotalPayload,
    Op::MaxPayload,
    Op::FirstPingIndex,
    Op::CountKind,
    Op::WeightedBalance,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::TotalPayload => "total_payload",
            Op::MaxPayload => "max_payload",
            Op::FirstPingIndex => "first_ping_index",
            Op::CountKind => "count_kind",
            Op::WeightedBalance => "weighted_balance",
        }
    }

    pub fn ret(self) -> &'static str {
        match self {
            Op::CountKind => "i64",
            _ => "i64",
        }
    }

    pub fn extra_arg(self) -> &'static str {
        match self {
            Op::CountKind => ", kind: u64",
            _ => "",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::TotalPayload => {
                "total payload weight across requests and replies (keep-alives weigh nothing)"
            }
            Op::MaxPayload => {
                "heaviest payload on the wire, or -1 when nothing carries one"
            }
            Op::FirstPingIndex => {
                "position of the first keep-alive, or -1 when there is none"
            }
            Op::CountKind => {
                "how many messages belong to kind 1 (requests), 2 (replies) or 3 (keep-alives); other codes answer -1"
            }
            Op::WeightedBalance => {
                "requests minus replies as a signed balance - the two weighted arms move in OPPOSITE directions"
            }
        }
    }
}

type Out = i64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let a = rng.below(5);
    let mut b = rng.below(5);
    while b == a {
        b = rng.below(5);
    }
    let pick = |i: u64| OP_ALL[i as usize];
    let mut ops = [pick(a), pick(b)];
    ops.sort();
    Spec { ops }
}
pub fn b_total_payload(wire: &[Msg]) -> i64 {
    let mut total = 0i64;
    for m in wire {
        match *m {
            Msg::Ask(w) => total += w as i64,
            Msg::Tell(w) => total += w as i64,
            Msg::Ping => {}
        }
    }
    total
}

pub fn b_max_payload(wire: &[Msg]) -> i64 {
    let mut best = -1i64;
    for m in wire {
        match *m {
            Msg::Ask(w) => best = best.max(w as i64),
            Msg::Tell(w) => best = best.max(w as i64),
            Msg::Ping => {}
        }
    }
    best
}

pub fn b_first_ping_index(wire: &[Msg]) -> i64 {
    for (i, m) in wire.iter().enumerate() {
        match *m {
            Msg::Ping => return i as i64,
            Msg::Ask(_) | Msg::Tell(_) => {}
        }
    }
    -1
}

pub fn b_count_kind(wire: &[Msg], kind: u64) -> i64 {
    let mut hits = 0i64;
    for m in wire {
        match (*m, kind) {
            (Msg::Ask(_), 1) | (Msg::Tell(_), 2) | (Msg::Ping, 3) => hits += 1,
            _ => {}
        }
    }
    if (1..=3).contains(&kind) {
        hits
    } else {
        -1
    }
}

pub fn b_weighted_balance(wire: &[Msg]) -> i64 {
    let mut balance = 0i64;
    for m in wire {
        match *m {
            Msg::Ask(w) => balance += w as i64,
            Msg::Tell(w) => balance -= w as i64,
            Msg::Ping => {}
        }
    }
    balance
}

pub fn op_eval(op: Op, wire: &[Msg], kind: u64) -> Out {
    match op {
        Op::TotalPayload => b_total_payload(wire),
        Op::MaxPayload => b_max_payload(wire),
        Op::FirstPingIndex => b_first_ping_index(wire),
        Op::CountKind => b_count_kind(wire, kind),
        Op::WeightedBalance => b_weighted_balance(wire),
    }
}

const CANONICAL_SEED: u64 = 0xEA9C_FA11;

/// A canonical wire carries both weighted kinds plus a keep-alive that is
/// NOT at the front, all six answers are pairwise distinct, and the two
/// weighted sums disagree so the opposite-direction balance is forced.
fn canonical(seed: u64) -> Vec<Msg> {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = 3 + rng.below(4);
        let mut wire = Vec::new();
        for _ in 0..n {
            match rng.below(6) {
                0 | 1 => wire.push(Msg::Ask(2 + rng.below(8))),
                2 | 3 => wire.push(Msg::Tell(2 + rng.below(8))),
                _ => wire.push(Msg::Ping),
            }
        }
        if anchors_hold(&wire) {
            return wire;
        }
    }
    unreachable!("canonical wire unreachable");
}

fn anchors_hold(wire: &[Msg]) -> bool {
    let total = b_total_payload(wire);
    let max = b_max_payload(wire);
    let fpi = b_first_ping_index(wire);
    let ck1 = b_count_kind(wire, 1);
    let ck2 = b_count_kind(wire, 2);
    let bal = b_weighted_balance(wire);
    if total < 4 || max < 2 || fpi < 1 || ck1 < 1 || ck2 < 1 || bal == 0 || bal == total {
        return false;
    }
    let answers = [total, max, fpi, ck1, ck2, bal];
    for i in 0..answers.len() {
        for j in (i + 1)..answers.len() {
            if answers[i] == answers[j] {
                return false;
            }
        }
    }
    true
}
pub struct ExampleCase {
    pub wire: Vec<Msg>,
    pub kind: u64,
    pub answers: Vec<(Op, Out)>,
}

const EXAMPLES_SEED: u64 = 0x0000_018A;

fn case(wire: Vec<Msg>, kind: u64) -> ExampleCase {
    let mut answers = Vec::new();
    for op in OP_ALL {
        answers.push((op, op_eval(op, &wire, kind)));
    }
    ExampleCase {
        wire,
        kind,
        answers,
    }
}

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut out = vec![case(canonical(seed), 2)];
    out.push(case(Vec::new(), 1));
    out.push(case(vec![Msg::Ping, Msg::Ping], 3));
    out.push(case(vec![Msg::Ask(5)], 1));
    for _ in 0..3 {
        let n = rng.below(6);
        let mut wire = Vec::new();
        for _ in 0..n {
            match rng.below(6) {
                0 | 1 => wire.push(Msg::Ask(2 + rng.below(8))),
                2 | 3 => wire.push(Msg::Tell(2 + rng.below(8))),
                _ => wire.push(Msg::Ping),
            }
        }
        let kind = rng.below(4) + 1;
        out.push(case(wire, kind));
    }
    out
}

fn render_msg(m: Msg) -> String {
    match m {
        Msg::Ask(w) => format!("Msg::Ask({})", w),
        Msg::Tell(w) => format!("Msg::Tell({})", w),
        Msg::Ping => "Msg::Ping".to_string(),
    }
}

fn render_wire(wire: &[Msg]) -> String {
    if wire.is_empty() {
        return "Vec::new()".to_string();
    }
    let items: Vec<String> = wire.iter().map(|m| render_msg(*m)).collect();
    format!("vec![{}]", items.join(", "))
}

pub fn call_src(op: Op, var: &str) -> String {
    match op {
        Op::CountKind => format!("{}({}, kind)", op.name(), var),
        _ => format!("{}({})", op.name(), var),
    }
}
pub fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(wire: &[Msg]{}) -> {}",
        op.name(),
        op.extra_arg(),
        op.ret()
    )
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n        todo!()\n    }}", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: String = match op {
        Op::TotalPayload => [
            "let mut total = 0i64;",
            "for m in wire {",
            "    match *m {",
            "        Msg::Ask(w) => total += w as i64,",
            "        Msg::Tell(w) => total += w as i64,",
            "        Msg::Ping => {}",
            "    }",
            "}",
            "total",
        ]
        .join("\n    "),
        Op::MaxPayload => [
            "let mut best = -1i64;",
            "for m in wire {",
            "    match *m {",
            "        Msg::Ask(w) => best = best.max(w as i64),",
            "        Msg::Tell(w) => best = best.max(w as i64),",
            "        Msg::Ping => {}",
            "    }",
            "}",
            "best",
        ]
        .join("\n    "),
        Op::FirstPingIndex => [
            "for (i, m) in wire.iter().enumerate() {",
            "    match *m {",
            "        Msg::Ping => return i as i64,",
            "        Msg::Ask(_) | Msg::Tell(_) => {}",
            "    }",
            "}",
            "-1",
        ]
        .join("\n    "),
        Op::CountKind => [
            "let mut hits = 0i64;",
            "for m in wire {",
            "    match (*m, kind) {",
            "        (Msg::Ask(_), 1) | (Msg::Tell(_), 2) | (Msg::Ping, 3) => hits += 1,",
            "        _ => {}",
            "    }",
            "}",
            "if (1..=3).contains(&kind) {",
            "    hits",
            "} else {",
            "    -1",
            "}",
        ]
        .join("\n    "),
        Op::WeightedBalance => [
            "let mut balance = 0i64;",
            "for m in wire {",
            "    match *m {",
            "        Msg::Ask(w) => balance += w as i64,",
            "        Msg::Tell(w) => balance -= w as i64,",
            "        Msg::Ping => {}",
            "    }",
            "}",
            "balance",
        ]
        .join("\n    "),
    };
    format!("{} {{\n    {}\n}}", op_sig_src(op), body)
}

pub const ENUM_SRC: &str = "/// The three message kinds on one wire.\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub enum Msg {\n    /// A request carrying a weight.\n    Ask(u64),\n    /// A reply carrying a weight.\n    Tell(u64),\n    /// Keep-alive with no payload.\n    Ping,\n}\n";

pub fn reference_src(spec: &Spec) -> String {
    let mut src = String::from(ENUM_SRC);
    for op in spec.ops {
        src.push_str(&op_fn_src(op));
        src.push('\n');
    }
    src
}

pub fn worked_examples_prose(spec: &Spec, seed: u64) -> Vec<String> {
    let mut lines = Vec::new();
    for (i, ex) in worked_examples(seed).iter().enumerate() {
        let mut parts = Vec::new();
        for (op, out) in &ex.answers {
            if spec.ops.contains(op) {
                parts.push(format!("{} = {}", op.name(), out));
            }
        }
        if parts.is_empty() {
            continue;
        }
        lines.push(format!(
            "ex{} wire {:?} kind {} -> {}",
            i,
            ex.wire,
            ex.kind,
            parts.join(", ")
        ));
    }
    lines
}

pub fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let mut sk = String::from("//! Pattern-matching puzzles over one wire of tagged messages.\n//!\n//! The `Msg` enum is PROVIDED. Each query below must be answered with an\n//! exhaustive match that binds the payloads the arm needs - keep-alives\n//! carry none, and the two weighted kinds move in opposite directions\n//! for the balance query. Rust rejects any arm set that forgets a variant.\n//!\n//! Worked examples:\n");
    for line in worked_examples_prose(spec, seed) {
        sk.push_str("//! ");
        sk.push_str(&line);
        sk.push('\n');
    }
    sk.push('\n');
    sk.push_str(ENUM_SRC);
    sk.push('\n');
    for op in spec.ops {
        sk.push_str(&op_stub_src(op));
        sk.push('\n');
    }
    sk
}
pub fn prompt_intro() -> String {
    String::from(
        "Implement the stubbed query functions over one wire of tagged messages.\n\
         \n\
         Requirements:\n",
    )
}

pub fn cargo_toml() -> String {
    String::from(
        "[package]\nname = \"task\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n",
    )
}

pub fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let names: Vec<String> = spec.ops.iter().map(|op| op.name().to_string()).collect();
    let mut src = format!("use task::Msg;\nuse task::{{{}}};\n\n", names.join(", "));
    for (i, ex) in worked_examples(seed).iter().enumerate() {
        for (op, out) in &ex.answers {
            if !spec.ops.contains(op) {
                continue;
            }
            src.push_str("#[test]\n");
            src.push_str(&format!("fn ex{}_{}() {{\n", i, op.name()));
            src.push_str(&format!("    let wire = {};\n", render_wire(&ex.wire)));
            if *op == Op::CountKind {
                src.push_str(&format!("    let kind = {}u64;\n", ex.kind));
            }
            src.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "&wire"),
                out
            ));
            src.push_str("}\n\n");
        }
    }
    src
}

pub fn differential_test_src(spec: &Spec) -> String {
    let names: Vec<String> = spec.ops.iter().map(|op| op.name().to_string()).collect();
    let mut src = format!("use task::{{{}}};\n\n", names.join(", "));
    // The paste KEEPS the enum definition: the ref-side fns need a local
    // Msg because the use-line imports only the drivers.
    let mut pasted = reference_src(spec);
    for op in spec.ops {
        let needle = format!("pub fn {}(", op.name());
        let replacement = format!("fn ref_{}(", op.name());
        assert_eq!(pasted.matches(&needle).count(), 1, "rename target missing");
        pasted = pasted.replacen(&needle, &replacement, 1);
    }
    src.push_str(&pasted);
    src.push('\n');
    src.push_str(
        "\nfn nx(state: &mut u64) -> u64 {\n    *state = state\n        .wrapping_mul(6364136223846793005)\n        .wrapping_add(1442695040888963407)\n        >> 33;\n    *state\n}\n\n#[test]\nfn differential_vs_reference() {\n",
    );
    src.push_str("    let mut state: u64 = 0xE7EE_ED00_0000_018A;\n");
    src.push_str("    for _ in 0..3000 {\n");
    src.push_str("        let n = (nx(&mut state) % 6) as usize;\n");
    src.push_str("        let mut wire = Vec::new();\n");
    src.push_str("        let mut mirror = Vec::new();\n");
    src.push_str("        for _ in 0..n {\n");
    src.push_str("            match nx(&mut state) % 3 {\n");
    src.push_str("                0 => {\n");
    src.push_str("                    let w = (nx(&mut state) % 9) + 2;\n");
    src.push_str("                    wire.push(task::Msg::Ask(w));\n");
    src.push_str("                    mirror.push(Msg::Ask(w));\n");
    src.push_str("                }\n");
    src.push_str("                1 => {\n");
    src.push_str("                    let w = (nx(&mut state) % 9) + 2;\n");
    src.push_str("                    wire.push(task::Msg::Tell(w));\n");
    src.push_str("                    mirror.push(Msg::Tell(w));\n");
    src.push_str("                }\n");
    src.push_str("                _ => {\n");
    src.push_str("                    wire.push(task::Msg::Ping);\n");
    src.push_str("                    mirror.push(Msg::Ping);\n");
    src.push_str("                }\n");
    src.push_str("            }\n");
    src.push_str("        }\n");
    src.push_str("        let kind = (nx(&mut state) % 4) + 1;\n");
    for op in spec.ops {
        let call = match op {
            Op::CountKind => format!("{name}(&wire, kind)", name = op.name()),
            _ => format!("{name}(&wire)", name = op.name()),
        };
        let ref_call = match op {
            Op::CountKind => format!("ref_{name}(&mirror, kind)", name = op.name()),
            _ => format!("ref_{name}(&mirror)", name = op.name()),
        };
        src.push_str(&format!("        assert_eq!({}, {});\n", call, ref_call));
    }
    src.push_str("    }\n}\n");
    src
}
pub fn prompt_src(spec: &Spec, seed: u64) -> String {
    let mut p = prompt_intro();
    for op in spec.ops {
        p.push_str(&format!("- {}.\n", op.prose()));
    }
    p.push_str("\nConstraints:\n");
    p.push_str("- Every match must be exhaustive; Rust will reject a forgotten variant.\n");
    p.push_str("- Keep the provided signatures and the Msg enum unchanged.\n");
    p.push_str("- No unsafe code.\n\n");
    p.push_str("Signatures:\n```\n");
    for op in spec.ops {
        p.push_str(&op_sig_src(op));
        p.push('\n');
    }
    p.push_str("```\n\nWorked examples:\n");
    for line in worked_examples_prose(spec, seed) {
        p.push_str(&line);
        p.push('\n');
    }
    let canary = mint_canary("enum-match", seed);
    p.push_str(&format!(
        "\nYour answer must still contain the canary string \"{canary}\" in its doc comment.\n"
    ));
    p
}

pub const CONST_ZERO_SRC: &str = "pub fn total_payload(wire: &[Msg]) -> i64 {\n    let _ = wire;\n    0\n}\npub fn max_payload(wire: &[Msg]) -> i64 {\n    let _ = wire;\n    0\n}\npub fn first_ping_index(wire: &[Msg]) -> i64 {\n    let _ = wire;\n    0\n}\npub fn count_kind(wire: &[Msg], kind: u64) -> i64 {\n    let _ = (wire, kind);\n    0\n}\npub fn weighted_balance(wire: &[Msg]) -> i64 {\n    let _ = wire;\n    0\n}\n";

/// Every query answered with the running Ask+Tell total - the classic
/// "one number for everything" cheat. The empty-wire example alone kills
/// it on every pair (max_payload and first_ping_index must answer -1).
pub const SUM_EVERYTHING_SRC: &str = "pub fn total_payload(wire: &[Msg]) -> i64 {\n    let mut total = 0i64;\n    for m in wire {\n        match *m {\n            Msg::Ask(w) => total += w as i64,\n            Msg::Tell(w) => total += w as i64,\n            Msg::Ping => {}\n        }\n    }\n    total\n}\npub fn max_payload(wire: &[Msg]) -> i64 {\n    let mut total = 0i64;\n    for m in wire {\n        match *m {\n            Msg::Ask(w) => total += w as i64,\n            Msg::Tell(w) => total += w as i64,\n            Msg::Ping => {}\n        }\n    }\n    total\n}\npub fn first_ping_index(wire: &[Msg]) -> i64 {\n    let mut total = 0i64;\n    for m in wire {\n        match *m {\n            Msg::Ask(w) => total += w as i64,\n            Msg::Tell(w) => total += w as i64,\n            Msg::Ping => {}\n        }\n    }\n    total\n}\npub fn count_kind(wire: &[Msg], kind: u64) -> i64 {\n    let _ = kind;\n    let mut total = 0i64;\n    for m in wire {\n        match *m {\n            Msg::Ask(w) => total += w as i64,\n            Msg::Tell(w) => total += w as i64,\n            Msg::Ping => {}\n        }\n    }\n    total\n}\npub fn weighted_balance(wire: &[Msg]) -> i64 {\n    let mut total = 0i64;\n    for m in wire {\n        match *m {\n            Msg::Ask(w) => total += w as i64,\n            Msg::Tell(w) => total += w as i64,\n            Msg::Ping => {}\n        }\n    }\n    total\n}\n";
pub struct EnumMatchFamily;

impl Generator for EnumMatchFamily {
    fn id(&self) -> &'static str {
        "enum-match"
    }

    fn category(&self) -> &'static str {
        "pattern-matching"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let skeleton = skeleton_src(&spec, seed);
        let prompt = prompt_src(&spec, seed);
        GeneratedTask {
            id: format!("enum-match/{seed:016x}"),
            category: self.category().to_string(),
            prompt,
            canary: mint_canary("enum-match", seed),
            answer_path: String::from("src/lib.rs"),
            files: [
                (std::path::PathBuf::from("Cargo.toml"), cargo_toml()),
                (std::path::PathBuf::from("src/lib.rs"), skeleton),
            ]
            .into_iter()
            .collect(),
            hidden: [
                (
                    std::path::PathBuf::from("tests/behavior.rs"),
                    behavior_test_src(&spec, seed),
                ),
                (
                    std::path::PathBuf::from("tests/differential.rs"),
                    differential_test_src(&spec),
                ),
            ]
            .into_iter()
            .collect(),
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            max_unsafe: None,
            forbidden_paths: vec![],
            check_clippy: false,
            clippy_allow: vec![],
            weights: (0.70, 0.20, 0.10),
        }
    }

    fn reference_code(&self, seed: u64) -> String {
        reference_src(&sample(seed))
    }

    fn skeleton_code(&self, seed: u64) -> String {
        let spec = sample(seed);
        skeleton_src(&spec, seed)
    }

    fn trivial_baselines(&self, _seed: u64) -> Vec<(String, String)> {
        vec![
            ("const-zero".to_string(), CONST_ZERO_SRC.to_string()),
            (
                "sum-everything".to_string(),
                ENUM_SRC.to_string() + SUM_EVERYTHING_SRC,
            ),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let mut sigs: Vec<String> = spec
            .ops
            .iter()
            .map(|op| format!("q:{}", op.name()))
            .collect();
        sigs.sort();
        sigs
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = EnumMatchFamily.generate(7);
        let b = EnumMatchFamily.generate(7);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
        assert_eq!(a.hidden, b.hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        let wire = [Msg::Ask(3), Msg::Ping, Msg::Tell(10)];
        assert_eq!(b_total_payload(&wire), 13);
        assert_eq!(b_max_payload(&wire), 10);
        assert_eq!(b_first_ping_index(&wire), 1);
        assert_eq!(b_weighted_balance(&wire), -7);
        let tally = [Msg::Ask(1), Msg::Ping, Msg::Tell(3)];
        assert_eq!(b_count_kind(&tally, 1), 1);
        assert_eq!(b_count_kind(&tally, 2), 1);
        assert_eq!(b_count_kind(&tally, 3), 1);
        assert_eq!(b_count_kind(&tally, 9), -1);
        assert_eq!(b_max_payload(&[]), -1);
        assert_eq!(b_max_payload(&[Msg::Ping]), -1);
        assert_eq!(b_first_ping_index(&[Msg::Ask(2)]), -1);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..300u64 {
            seen.insert(sample(seed));
        }
        assert!(seen.len() >= 9, "only {} distinct pairs", seen.len());
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        for seed in 0..200u64 {
            let wire = canonical(seed);
            let total = b_total_payload(&wire);
            let max = b_max_payload(&wire);
            let fpi = b_first_ping_index(&wire);
            let ck1 = b_count_kind(&wire, 1);
            let ck2 = b_count_kind(&wire, 2);
            let bal = b_weighted_balance(&wire);
            // anchors: nonzero, ping present but not first, both kinds used
            assert!(total >= 4, "seed {seed}");
            assert!(max >= 2, "seed {seed}");
            assert!(fpi >= 1, "seed {seed}");
            assert!(ck1 >= 1 && ck2 >= 1, "seed {seed}");
            assert_ne!(bal, 0, "seed {seed}");
            assert_ne!(bal, total, "seed {seed}");
            // const-zero cheat dies on the three weighted scalars
            for v in [total, max] {
                assert_ne!(v, 0, "const-zero survives on seed {seed}");
                assert_ne!(v, -1, "sentinel collision on seed {seed}");
            }
            // weighted_balance is signed by design: -1 is a real answer,
            // so only zero and echo are excluded for it.
            let _ = bal;
            // sum-everything cheat answers `total` everywhere; every op's
            // truth is pinned pairwise-distinct from it by anchors_hold
            assert_ne!(max, total, "sum-everything survives max on seed {seed}");
            assert_ne!(fpi, total, "sum-everything survives fpi on seed {seed}");
            assert_ne!(ck1, total, "sum-everything survives ck1 on seed {seed}");
            assert_ne!(ck2, total, "sum-everything survives ck2 on seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for ex in worked_examples(seed) {
                for (op, out) in ex.answers {
                    assert_eq!(
                        op_eval(op, &ex.wire, ex.kind),
                        out,
                        "seed {seed} op {}",
                        op.name()
                    );
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let src = reference_src(&spec);
            for op in OP_ALL {
                let marker = format!("pub fn {}(", op.name());
                if spec.ops.contains(&op) {
                    assert!(src.contains(&marker), "missing {}", op.name());
                } else {
                    assert!(!src.contains(&marker), "extra {}", op.name());
                }
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let sk = skeleton_src(&spec, seed);
            let p = prompt_src(&spec, seed);
            assert!(sk.contains("todo!()"));
            assert!(!p.contains("todo!()"));
            for token in ["+= w", "-= w", ".max("] {
                assert!(!sk.contains(token), "leak {token} in skeleton");
                assert!(!p.contains(token), "leak {token} in prompt");
            }
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)), "sig missing {}", op.name());
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for op in OP_ALL {
            let sig = op_sig_src(op).split("->").next().unwrap().to_string();
            let call = match op {
                Op::CountKind => format!("{}(&wire, kind)", op.name()),
                _ => format!("{}(&wire)", op.name()),
            };
            assert_eq!(
                sig.matches(',').count(),
                call.matches(',').count(),
                "arity drift on {}",
                op.name()
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in 0..20u64 {
            let t = EnumMatchFamily.generate(seed);
            assert!(t.prompt.contains(&t.canary));
        }
    }
}

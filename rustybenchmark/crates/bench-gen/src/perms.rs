//! The `perms` family (category `unix-permissions`) — octal mode
//! decomposition and the classic nine-symbol rendering.
//!
//! Where `bitset` asks after population counts and `base-convert` counts
//! digits across bases, this family exercises **positional extraction**
//! over a fixed three-digit octal shape: the owner, group, and other
//! digits of one Unix permission mode, the `rwxrwxrwx` rendering built
//! from their bits, and the any-class execute predicate. The domain is
//! one mode `mode: u64` from `0` through `0o777`. The seed prunes which
//! two of five query ops are required: `owner_digits`, `group_digits`,
//! `other_digits`, `to_symbols`, `anyone_execute`. C(5,2) = **10
//! distinct skills**, above the diversity floor; op names are semantic.
//!
//! The canonical mode is sampled until its anchor facts hold: all three
//! digits nonzero and mutually distinct, with at least one execute bit
//! anywhere. That makes `const-zero` wrong on every answer outright,
//! and `owner-everything` wrong on everything except its own digit.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random modes against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical example) and `owner-everything` (every query answered with
//! the owner digit — or the all-dash string).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    OwnerDigits,
    GroupDigits,
    OtherDigits,
    ToSymbols,
    AnyoneExecute,
}

const OP_ALL: [Op; 5] = [
    Op::OwnerDigits,
    Op::GroupDigits,
    Op::OtherDigits,
    Op::ToSymbols,
    Op::AnyoneExecute,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::OwnerDigits => "owner_digits",
            Op::GroupDigits => "group_digits",
            Op::OtherDigits => "other_digits",
            Op::ToSymbols => "to_symbols",
            Op::AnyoneExecute => "anyone_execute",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::OwnerDigits => {
                "the owner class's octal digit of the mode — the \
                 hundreds place, six bit positions up"
            }
            Op::GroupDigits => {
                "the group class's octal digit — the middle digit, \
                 three bit positions up"
            }
            Op::OtherDigits => {
                "the other class's octal digit — the lowest digit, the \
                 bottom three bits"
            }
            Op::ToSymbols => {
                "the classic nine-symbol rendering, three positions per \
                 class in owner/group/other order, each position showing \
                 its letter or a dash"
            }
            Op::AnyoneExecute => {
                "whether at least one of the three classes carries an \
                 execute permission"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::ToSymbols => "String",
            Op::AnyoneExecute => "bool",
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

/// The owner (hundreds) octal digit.
fn b_owner_digits(mode: u64) -> i64 {
    (mode / 64) as i64
}

/// The group (tens) octal digit.
fn b_group_digits(mode: u64) -> i64 {
    ((mode / 8) % 8) as i64
}

/// The other (ones) octal digit.
fn b_other_digits(mode: u64) -> i64 {
    (mode % 8) as i64
}

/// The nine-symbol rendering, three positions per class.
fn b_to_symbols(mode: u64) -> String {
    let mut s = String::new();
    for shift in [6u32, 3, 0] {
        let digit = ((mode >> shift) & 7) as u8;
        s.push(if digit & 4 != 0 { 'r' } else { '-' });
        s.push(if digit & 2 != 0 { 'w' } else { '-' });
        s.push(if digit & 1 != 0 { 'x' } else { '-' });
    }
    s
}

/// True when any of the three classes carries the execute bit.
fn b_anyone_execute(mode: u64) -> bool {
    ((mode >> 6) & 1) == 1 || ((mode >> 3) & 1) == 1 || (mode & 1) == 1
}

/// The answer shape: scalars as `Num`, predicates as `Flag`, the
/// rendering as `Str`.
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

fn op_eval(op: Op, mode: u64) -> Out {
    match op {
        Op::OwnerDigits => Out::Num(b_owner_digits(mode)),
        Op::GroupDigits => Out::Num(b_group_digits(mode)),
        Op::OtherDigits => Out::Num(b_other_digits(mode)),
        Op::ToSymbols => Out::Str(b_to_symbols(mode)),
        Op::AnyoneExecute => Out::Flag(b_anyone_execute(mode)),
    }
}

// ---- canonical mode ---------------------------------------------------------

/// The canonical mode: sampled `0..512` and retried until the anchor
/// facts hold.
///
/// Guaranteed for every seed: all three digits nonzero and mutually
/// distinct (so each digit query has its own answer), with at least one
/// execute bit anywhere (so both cheats' `false` predicates die
/// mid-canonical). That makes `const-zero` wrong on every answer
/// outright.
fn canonical(seed: u64) -> u64 {
    let mut rng = Rng::new(seed ^ 0xA55E_C115);
    for _ in 0..100_000 {
        let m = rng.below(512);
        if anchors_hold(m) {
            return m;
        }
    }
    unreachable!("canonical mode sampling failed to satisfy anchors");
}

fn anchors_hold(mode: u64) -> bool {
    let o = b_owner_digits(mode);
    let g = b_group_digits(mode);
    let t = b_other_digits(mode);
    o >= 1 && g >= 1 && t >= 1 && o != g && o != t && g != t && b_anyone_execute(mode)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0156);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical mode first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // Zero: the empty mode — all dashes, no execute anywhere.
    cases.push((0o000, spec.ops.map(|op| (op, op_eval(op, 0o000))).to_vec()));
    // Full grant: every letter in every class.
    cases.push((0o777, spec.ops.map(|op| (op, op_eval(op, 0o777))).to_vec()));
    // The classic private file: owner read/write only.
    cases.push((0o600, spec.ops.map(|op| (op, op_eval(op, 0o600))).to_vec()));
    for _ in 0..3 {
        let m = rng.below(512);
        let outs = spec.ops.map(|op| (op, op_eval(op, m))).to_vec();
        cases.push((m, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the suffix types it as `u64`.
fn render_u64(m: u64) -> String {
    format!("{m}u64")
}

/// The nine-symbol rendering, emitted verbatim; self-contained because a
/// seed's pair may not select `to_symbols`.
const SYMBOLS_BODY: &[&str] = &[
    "let mut s = String::new();",
    "for shift in [6u32, 3, 0] {",
    "    let digit = ((mode >> shift) & 7) as u8;",
    "    s.push(if digit & 4 != 0 { 'r' } else { '-' });",
    "    s.push(if digit & 2 != 0 { 'w' } else { '-' });",
    "    s.push(if digit & 1 != 0 { 'x' } else { '-' });",
    "}",
    "s",
];

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(mode: u64) -> {ret}");
    let body = match op {
        Op::OwnerDigits => "(mode / 64) as i64".to_string(),
        Op::GroupDigits => "((mode / 8) % 8) as i64".to_string(),
        Op::OtherDigits => "(mode % 8) as i64".to_string(),
        Op::ToSymbols => SYMBOLS_BODY.join("\n    "),
        Op::AnyoneExecute => {
            "((mode >> 6) & 1) == 1 || ((mode >> 3) & 1) == 1 || (mode & 1) == 1".to_string()
        }
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(mode: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(mode: u64) -> {}", op.name(), op.ret())
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
    for (mode, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  mode {}  ->  {}\n", render_u64(mode), results));
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
         one Unix permission mode `mode` of type `u64`, from zero through \
         0o777; its three octal digits describe the owner, group, and \
         other access classes, and each digit's bits are read, write, \
         execute from most to least significant.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
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
    for (i, (mode, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let mode = {};\n",
            render_u64(*mode),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "mode"),
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
            let call = call_src(*op, "mode");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0156;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let mode = nx(&mut state) % 512;\n\
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
            format!("{sig} {{\n    let _ = mode;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the owner digit no matter what was asked.
/// The canonical anchors keep the group and other digits distinct from it
/// (all three mutually distinct), so this is exact only on `owner_digits`
/// itself. The all-dash string never matches a rendering that must carry
/// letters (every digit nonzero), and the predicate answers false where
/// both cheats agree — but canonical requires an execute bit, so the
/// cheat dies mid-canonical directly.
fn owner_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    false\n}}\n"),
                "String" => {
                    format!("{sig} {{\n    let _ = mode;\n    \"---------\".to_string()\n}}\n")
                }
                _ => format!("{sig} {{\n    (mode / 64) as i64\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct PermsFamily;

impl Generator for PermsFamily {
    fn id(&self) -> &str {
        "perms"
    }
    fn category(&self) -> &str {
        "unix-permissions"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("perms", seed);

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
            id: format!("perms/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer bookkeeping — no unsafe anywhere near it.
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
            ("owner-everything".to_string(), owner_everything(&spec)),
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

    /// The `owner-everything` cheat's answer for one op, simulated natively.
    fn owner_cheat(op: Op, mode: u64) -> Out {
        match op {
            Op::OwnerDigits => Out::Num(b_owner_digits(mode)),
            Op::GroupDigits | Op::OtherDigits => Out::Num(b_owner_digits(mode)),
            Op::ToSymbols => Out::Str("---------".to_string()),
            Op::AnyoneExecute => Out::Flag(false),
        }
    }

    #[test]
    fn generation_is_deterministic() {
        let g = PermsFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Digit extraction across all three classes.
        assert_eq!(b_owner_digits(0o754), 7);
        assert_eq!(b_owner_digits(0o644), 6);
        assert_eq!(b_owner_digits(0), 0);
        assert_eq!(b_owner_digits(0o700 + 63), 7);
        assert_eq!(b_group_digits(0o754), 5);
        assert_eq!(b_group_digits(0o007), 0);
        assert_eq!(b_group_digits(0o070), 7);
        assert_eq!(b_other_digits(0o754), 4);
        assert_eq!(b_other_digits(0o007), 7);
        assert_eq!(b_other_digits(0o640), 0);
        // The classic renderings.
        assert_eq!(b_to_symbols(0o754), "rwxr-xr--");
        assert_eq!(b_to_symbols(0o000), "---------");
        assert_eq!(b_to_symbols(0o777), "rwxrwxrwx");
        assert_eq!(b_to_symbols(0o600), "rw-------");
        assert_eq!(b_to_symbols(0o001), "--------x");
        // Any-class execute detection.
        assert!(b_anyone_execute(0o754));
        assert!(!b_anyone_execute(0o644));
        assert!(b_anyone_execute(0o001));
        assert!(b_anyone_execute(0o010));
        assert!(b_anyone_execute(0o100));
        assert!(!b_anyone_execute(0o000));
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
        // const-zero must fail outright on every answer; the
        // owner-everything cheat is exact only on its own digit. Both
        // cheats answer `false` on the predicate — but canonical
        // requires an execute bit, so they die mid-canonical directly.
        for seed in 0..200u64 {
            let m = canonical(seed);
            let o = b_owner_digits(m);
            let g = b_group_digits(m);
            let t = b_other_digits(m);
            // Anchor facts the sampler enforces.
            assert!(o >= 1 && g >= 1 && t >= 1, "seed {seed}");
            assert_ne!(o, g, "seed {seed}");
            assert_ne!(o, t, "seed {seed}");
            assert_ne!(g, t, "seed {seed}");
            assert!(b_anyone_execute(m), "seed {seed}");
            for v in [o, g, t] {
                assert_ne!(v, 0, "const-zero survives at mode {m:o} seed {seed}");
            }
            for op in OP_ALL {
                if matches!(op, Op::OwnerDigits) {
                    // Documented skip: the owner digit is the cheat's
                    // own answer.
                    continue;
                }
                assert_ne!(
                    op_eval(op, m),
                    owner_cheat(op, m),
                    "owner-everything survives at {op:?} mode {m:o} seed {seed}"
                );
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (mode, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, mode), out, "seed {seed}");
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
                // Paren-suffixed so no bare-name prefix can false-match.
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
            // Solution-shaped leak tokens must stay out of the skeleton.
            assert!(!sk.contains("/ 64"));
            assert!(!sk.contains("/ 8"));
            assert!(!sk.contains("% 8"));
            assert!(!sk.contains("& 1"));
            assert!(!sk.contains("push("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("/ 64"));
            assert!(!p.contains("/ 8"));
            assert!(!p.contains("% 8"));
            assert!(!p.contains("& 1"));
            assert!(!p.contains("push("));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here is unary: no call site may carry a comma.
        for op in OP_ALL {
            let call = call_src(op, "mode");
            assert_eq!(
                call.matches(',').count(),
                op_sig_src(op).matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{}`",
                op_sig_src(op)
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = PermsFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

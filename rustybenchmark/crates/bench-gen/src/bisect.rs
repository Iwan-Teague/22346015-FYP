//! The `bisect` family (category `sorted-queries`) — rank and position
//! statistics of one probe value inside one sorted sequence.
//!
//! Where `minmax` measures order statistics of the values themselves and
//! `sorted` measures properties of an ordering, this family locates a
//! probe within it: the lower/upper bound positions and how many
//! elements fall strictly below, at most, or exactly at the probe. The
//! domain is one ascending-sorted `&[i64]` paired with a single probe
//! value; every op is a pure function of the pair. The seed prunes which
//! two of five query ops are required: `lower_bound`, `upper_bound`,
//! `count_less`, `count_leq`, `count_equal`. C(5,2) = **10 distinct
//! skills**, above the diversity floor; op names are semantic.
//!
//! On sorted input two natural identities hold — `lower_bound` equals
//! `count_less`, and `upper_bound` equals `count_leq` — so the five ops
//! collapse to three answer groups. The canonical input is sampled until
//! every group is nonzero, the run at the probe holds at least two
//! duplicates, elements exist on both sides of the probe, and the
//! greater-count lands outside all three groups. That makes `const-zero`
//! fail everywhere and the `greater-everything` cheat (every query
//! answered with the number of elements above the probe) exact nowhere.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random sorted sequences against the model.
//!
//! Trivial baselines: `const-zero` (fails outright on the canonical
//! pair) and `greater-everything` (every query answered with the count
//! of elements strictly above the probe).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    LowerBound,
    UpperBound,
    CountLess,
    CountLeq,
    CountEqual,
}

const OP_ALL: [Op; 5] = [
    Op::LowerBound,
    Op::UpperBound,
    Op::CountLess,
    Op::CountLeq,
    Op::CountEqual,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::LowerBound => "lower_bound",
            Op::UpperBound => "upper_bound",
            Op::CountLess => "count_less",
            Op::CountLeq => "count_leq",
            Op::CountEqual => "count_equal",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::LowerBound => {
                "the index of the first element greater than or equal \
                 to the probe (equivalently, how many elements are \
                 smaller)"
            }
            Op::UpperBound => {
                "the index of the first element strictly greater than \
                 the probe (how many elements are at most the probe)"
            }
            Op::CountLess => "how many elements are strictly smaller than the probe",
            Op::CountLeq => "how many elements are at most the probe",
            Op::CountEqual => {
                "how many elements are exactly equal to the probe \
                 (the size of its run)"
            }
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

fn b_lower_bound(xs: &[i64], probe: i64) -> i64 {
    xs.iter().filter(|&&x| x < probe).count() as i64
}

fn b_upper_bound(xs: &[i64], probe: i64) -> i64 {
    xs.iter().filter(|&&x| x <= probe).count() as i64
}

fn b_count_less(xs: &[i64], probe: i64) -> i64 {
    xs.iter().filter(|&&x| x < probe).count() as i64
}

fn b_count_leq(xs: &[i64], probe: i64) -> i64 {
    xs.iter().filter(|&&x| x <= probe).count() as i64
}

fn b_count_equal(xs: &[i64], probe: i64) -> i64 {
    xs.iter().filter(|&&x| x == probe).count() as i64
}

/// One op's answer. All five ops return scalars here, so `Out` is a
/// plain alias — no flag variant needed.
type Out = i64;

fn op_eval(op: Op, xs: &[i64], probe: i64) -> Out {
    match op {
        Op::LowerBound => b_lower_bound(xs, probe),
        Op::UpperBound => b_upper_bound(xs, probe),
        Op::CountLess => b_count_less(xs, probe),
        Op::CountLeq => b_count_leq(xs, probe),
        Op::CountEqual => b_count_equal(xs, probe),
    }
}

// ---- canonical input --------------------------------------------------------

/// Sample a short ascending-sorted sequence plus a probe. Values and
/// the probe live in a small signed window so duplicates are frequent.
fn rand_pair(rng: &mut Rng, max_len: u64) -> (Vec<i64>, i64) {
    let n = 1 + rng.below(max_len);
    let mut vals: Vec<i64> = Vec::new();
    for _ in 0..n {
        vals.push(rng.below(41) as i64 - 20);
    }
    vals.sort_unstable();
    let probe = rng.below(41) as i64 - 20;
    (vals, probe)
}

const CANONICAL_SEED: u64 = 0xB15E_5EED;

/// The canonical pair: sampled until every answer group is nonzero, the
/// run at the probe holds at least two elements, elements exist on both
/// sides of the probe, and the greater-count sits outside all three
/// groups — `const-zero` fails everywhere and `greater-everything` is
/// exact nowhere.
fn canonical(seed: u64) -> (Vec<i64>, i64) {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let (xs, probe) = rand_pair(&mut rng, 8);
        if anchors_hold(&xs, probe) {
            return (xs, probe);
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(xs: &[i64], probe: i64) -> bool {
    let len = xs.len() as i64;
    let less = b_count_less(xs, probe);
    let leq = b_count_leq(xs, probe);
    let equal = b_count_equal(xs, probe);
    let greater = len - leq;
    !xs.is_empty()
        && equal >= 2
        && less >= 1
        && greater >= 1
        && greater != less
        && greater != equal
        && greater != leq
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (Vec<i64>, i64, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0134;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, xs: Vec<i64>, probe: i64| {
        cases.push((
            xs.clone(),
            probe,
            spec.ops.map(|op| (op, op_eval(op, &xs, probe))).to_vec(),
        ));
    };
    // Canonical pair first.
    let (can_xs, can_probe) = canonical(seed);
    push(&mut cases, can_xs, can_probe);
    // Empty slice: zero conventions everywhere.
    push(&mut cases, Vec::new(), 3);
    // Whole sequence equals the probe.
    push(&mut cases, vec![7, 7, 7, 7], 7);
    // Singleton hit.
    push(&mut cases, vec![-5], -5);
    for _ in 0..3 {
        let (xs, probe) = rand_pair(&mut rng, 5);
        push(&mut cases, xs, probe);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for the sequence: a `&[i64]` slice with the first
/// element suffix-typed so empty and singleton forms infer correctly.
fn render_slice(xs: &[i64]) -> String {
    if xs.is_empty() {
        return "&[]".to_string();
    }
    let mut parts: Vec<String> = xs.iter().map(|v| v.to_string()).collect();
    parts[0] = format!("{}i64", parts[0]);
    format!("&[{}]", parts.join(", "))
}

/// Emitted literal for the probe: a bare integer (the call-site
/// signature types it as `i64`).
fn render_probe(probe: i64) -> String {
    probe.to_string()
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = "(xs: &[i64], probe: i64) -> i64";
    let body = match op {
        Op::LowerBound | Op::CountLess => {
            "xs.iter().filter(|&&x| x < probe).count() as i64".to_string()
        }
        Op::UpperBound | Op::CountLeq => {
            "xs.iter().filter(|&&x| x <= probe).count() as i64".to_string()
        }
        Op::CountEqual => "xs.iter().filter(|&&x| x == probe).count() as i64".to_string(),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(xs: &[i64], probe: i64) -> i64 {{\n    todo!()\n}}\n",
        op.name()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(xs: &[i64], probe: i64) -> i64", op.name())
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
    for (xs, probe, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  xs {}  probe {}  ->  {}\n",
            render_slice(&xs),
            render_probe(probe),
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
         one ascending-sorted borrowed slice of integers plus a single \
         probe value; queries are rank and position statistics of the \
         probe within that ordering. Handle the empty slice and probes \
         outside the sequence gracefully.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - The input slice arrives already sorted ascending; you need not re-sort it.\n\
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
    for (i, (xs, probe, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let xs = {};\n    let probe = {};\n",
            render_slice(xs),
            render_probe(*probe),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "xs, probe"),
                out
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
            let call = call_src(*op, "&vals, probe");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0134;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let mut vals: Vec<i64> = Vec::new();\n\
         \x20       let n = (nx(&mut state) % 6 + 2) as usize;\n\
         \x20       for _ in 0..n {{\n\
         \x20           vals.push((nx(&mut state) % 41) as i64 - 20);\n\
         \x20       }}\n\
         \x20       vals.sort();\n\
         \x20       let probe = (nx(&mut state) % 61) as i64 - 30;\n\
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
/// Degenerate: everything zero.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    let _ = (xs, probe);\n    0\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the number of elements
/// strictly above the probe. The canonical anchors keep all three
/// answer groups away from that count, so this is exact nowhere.
fn greater_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    xs.iter().filter(|&&x| x > probe).count() as i64\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct BisectFamily;

impl Generator for BisectFamily {
    fn id(&self) -> &str {
        "bisect"
    }
    fn category(&self) -> &str {
        "sorted-queries"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("bisect", seed);

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
            id: format!("bisect/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure sorted-slice bookkeeping — no unsafe anywhere near it.
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
            ("greater-everything".to_string(), greater_everything(&spec)),
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
        let g = BisectFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Lower bound: first position at or above the probe.
        assert_eq!(b_lower_bound(&[1, 3, 3, 5, 7], 4), 3);
        assert_eq!(b_lower_bound(&[1, 3, 3, 5, 7], 3), 1);
        assert_eq!(b_lower_bound(&[1, 3, 3, 5, 7], 8), 5);
        assert_eq!(b_lower_bound(&[], 5), 0);
        // Upper bound: skips the whole equal run.
        assert_eq!(b_upper_bound(&[1, 3, 3, 5, 7], 3), 3);
        assert_eq!(b_upper_bound(&[2, 2, 2], 2), 3);
        assert_eq!(b_upper_bound(&[2, 4, 6], 2), 1);
        assert_eq!(b_upper_bound(&[], -4), 0);
        // Strictly-smaller count.
        assert_eq!(b_count_less(&[-9, -3, 0, 3], 0), 2);
        assert_eq!(b_count_less(&[2, 2, 2], 2), 0);
        // At-most count.
        assert_eq!(b_count_leq(&[1, 3, 3, 5, 7], 4), 3);
        assert_eq!(b_count_leq(&[1, 3, 5], 9), 3);
        // Equal-run size: zero when the probe is absent.
        assert_eq!(b_count_equal(&[1, 3, 3, 5, 7], 3), 2);
        assert_eq!(b_count_equal(&[1, 3, 3, 5, 7], 4), 0);
        // Partition invariant on a longer run.
        let sorted = [-8i64, -8, -3, -1, 0, 0, 0, 4, 9, 12];
        for probe in [-9, -8, -4, -1, 0, 1, 4, 13] {
            let less = b_count_less(&sorted, probe);
            let equal = b_count_equal(&sorted, probe);
            let greater = sorted.len() as i64 - b_count_leq(&sorted, probe);
            assert_eq!(less + equal + greater, sorted.len() as i64);
        }
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
        // Both baselines must fail under EVERY pair. On the canonical
        // pair all three answer groups are nonzero and distinct from
        // the greater-count, so `const-zero` separates everywhere and
        // `greater-everything` is exact nowhere — no skips.
        for seed in 0..200u64 {
            let (xs, probe) = canonical(seed);
            let less = b_count_less(&xs, probe);
            let leq = b_count_leq(&xs, probe);
            let equal = b_count_equal(&xs, probe);
            let greater = xs.len() as i64 - leq;
            assert!(
                equal >= 2 && less >= 1 && greater >= 1,
                "anchors broken seed {seed}"
            );
            for op in OP_ALL {
                let truth = op_eval(op, &xs, probe);
                assert_ne!(truth, 0, "const-zero survives {op:?} seed {seed}");
                assert_ne!(truth, greater, "greater-cheat survives {op:?} seed {seed}");
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (xs, probe, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &xs, probe), out, "seed {seed}");
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
                // Match the `pub fn` line so no bare-name substring leaks.
                let fn_line = format!("pub fn {}", op.name());
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
            assert!(!sk.contains("partition_point"));
            assert!(!sk.contains("binary_search"));
            assert!(!sk.contains(".iter()"));
            assert!(!sk.contains(".filter("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("partition_point"));
            assert!(!p.contains("binary_search"));
            assert!(!p.contains(".iter()"));
            assert!(!p.contains(".filter("));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every call site passes exactly two arguments — one comma —
        // matching the parameter list of its signature.
        for op in OP_ALL {
            let call = call_src(op, "&vals, probe");
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = BisectFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}

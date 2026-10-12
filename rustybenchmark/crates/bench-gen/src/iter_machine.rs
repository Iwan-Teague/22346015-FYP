//! Custom iterator state machines over one length.
//!
//! The model is handed a dedicated struct whose `Iterator` implementation
//! has an empty `next()` plus a complete driver that collects exactly `n`
//! items. The skill is writing the state machine itself: what to yield on
//! each poll, how the cursor advances afterwards, and why an unbounded
//! machine terminates under `take(n)`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    Fibs,
    Squares,
    Evens,
    Triangulars,
    Alts,
}

pub const OP_ALL: [Op; 5] = [Op::Fibs, Op::Squares, Op::Evens, Op::Triangulars, Op::Alts];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::Fibs => "fibs",
            Op::Squares => "squares",
            Op::Evens => "evens",
            Op::Triangulars => "triangulars",
            Op::Alts => "alts",
        }
    }

    pub fn ret(self) -> &'static str {
        match self {
            Op::Alts => "i64",
            _ => "u64",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::Fibs => "the Fibonacci walk opened at zero, one pair advanced per item",
            Op::Squares => "the perfect squares counted up from zero",
            Op::Evens => "the even numbers counted up from zero, zero included",
            Op::Triangulars => "the running sums of a count from zero",
            Op::Alts => "the naturals with every odd position negated",
        }
    }

    /// The machine struct name emitted alongside this op.
    pub fn machine(self) -> &'static str {
        match self {
            Op::Fibs => "FibsMachine",
            Op::Squares => "SquaresMachine",
            Op::Evens => "EvensMachine",
            Op::Triangulars => "TriangularsMachine",
            Op::Alts => "AltsMachine",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let a = rng.below(5) as usize;
    let mut b = rng.below(5) as usize;
    while b == a {
        b = rng.below(5) as usize;
    }
    Spec {
        ops: [OP_ALL[a], OP_ALL[b]],
    }
}

/// Fresh per-family constants (drift-guarded unique repo-wide).
pub const CANONICAL_SEED: u64 = 0x17E5_FA11;
fn b_fibs(n: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        out.push(a);
        let nxt = a.wrapping_add(b);
        a = b;
        b = nxt;
    }
    out
}

fn b_squares(n: usize) -> Vec<u64> {
    (0..n as u64).map(|i| i * i).collect()
}

fn b_evens(n: usize) -> Vec<u64> {
    (0..n as u64).map(|i| i * 2).collect()
}

fn b_triangulars(n: usize) -> Vec<u64> {
    (0..n as u64).map(|i| i * (i + 1) / 2).collect()
}

fn b_alts(n: usize) -> Vec<i64> {
    (0..n as u64)
        .map(|i| if i % 2 == 0 { i as i64 } else { -(i as i64) })
        .collect()
}

/// A rendered expected answer: typed vec literal or the empty constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VecOut {
    U64(Vec<u64>),
    I64(Vec<i64>),
}

impl VecOut {
    pub fn lit(&self) -> String {
        match self {
            VecOut::U64(v) => {
                if v.is_empty() {
                    "Vec::<u64>::new()".to_string()
                } else {
                    format!("vec![{}u64, {}]", v[0], {
                        v[1..]
                            .iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                }
            }
            VecOut::I64(v) => {
                if v.is_empty() {
                    "Vec::<i64>::new()".to_string()
                } else {
                    format!("vec![{}i64, {}]", v[0], {
                        v[1..]
                            .iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                }
            }
        }
    }
}

pub fn op_eval(op: Op, n: usize) -> VecOut {
    match op {
        Op::Fibs => VecOut::U64(b_fibs(n)),
        Op::Squares => VecOut::U64(b_squares(n)),
        Op::Evens => VecOut::U64(b_evens(n)),
        Op::Triangulars => VecOut::U64(b_triangulars(n)),
        Op::Alts => VecOut::I64(b_alts(n)),
    }
}

fn anchors_hold(n: u64) -> bool {
    (4..=15).contains(&n)
}

pub fn canonical(seed: u64) -> usize {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = 3 + rng.below(9);
        if anchors_hold(n) {
            return n as usize;
        }
    }
    unreachable!("canonical anchor unreachable");
}
pub const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0180;

pub struct ExampleCase {
    pub n: usize,
    pub answers: Vec<(Op, VecOut)>,
}

fn case(n: usize) -> ExampleCase {
    let mut answers = Vec::new();
    for &op in OP_ALL.iter() {
        answers.push((op, op_eval(op, n)));
    }
    ExampleCase { n, answers }
}

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut out = vec![case(canonical(seed))];
    out.push(case(0));
    out.push(case(1));
    out.push(case(2));
    for _ in 0..8 {
        out.push(case(rng.below(10) as usize));
    }
    out
}

/// The single scalar input renders as a bare literal.
pub fn render_input(n: usize) -> String {
    n.to_string()
}

/// The solved machine machinery for one op: struct + Iterator impl + driver.
/// Built by concatenation — the bodies are brace-heavy and format! escaping
/// of nested struct literals is error-prone.
pub fn iter_src(op: Op, solved: bool) -> String {
    let next_body: &str = if solved { solved_next(op) } else { "todo!()" };
    let (machine, item, driver) = match op {
        Op::Fibs => ("FibsMachine", "u64", "fibs"),
        Op::Squares => ("SquaresMachine", "u64", "squares"),
        Op::Evens => ("EvensMachine", "u64", "evens"),
        Op::Triangulars => ("TriangularsMachine", "u64", "triangulars"),
        Op::Alts => ("AltsMachine", "i64", "alts"),
    };
    let mut s = String::new();
    s.push_str(&format!("pub struct {} {}\n", machine, state_shape(op)));
    s.push_str(&format!("impl std::iter::Iterator for {} {{\n", machine));
    s.push_str(&format!("    type Item = {};\n", item));
    s.push_str(&format!("    fn next(&mut self) -> Option<{}> {{\n", item));
    s.push_str(next_body);
    s.push('\n');
    s.push_str("    }\n}\n");
    s.push_str(&format!(
        "pub fn {}(n: usize) -> Vec<{}> {{\n",
        driver, item
    ));
    s.push_str(&format!(
        "    {}{}.take(n).collect()\n",
        machine,
        state_init(op)
    ));
    s.push_str("}\n");
    s
}

fn solved_next(op: Op) -> &'static str {
    match op {
        Op::Fibs => {
            "        let out = self.a;\n        let nxt = self.a.wrapping_add(self.b);\n        self.a = self.b;\n        self.b = nxt;\n        Some(out)"
        }
        Op::Squares => "        let out = self.i * self.i;\n        self.i += 1;\n        Some(out)",
        Op::Evens => "        let out = self.i * 2;\n        self.i += 1;\n        Some(out)",
        Op::Triangulars => "        let out = self.i * (self.i + 1) / 2;\n        self.i += 1;\n        Some(out)",
        Op::Alts => {
            "        let out = if self.i % 2 == 0 {\n            self.i as i64\n        } else {\n            -(self.i as i64)\n        };\n        self.i += 1;\n        Some(out)"
        }
    }
}

fn state_shape(op: Op) -> &'static str {
    match op {
        Op::Fibs => "{ a: u64, b: u64 }",
        _ => "{ i: u64 }",
    }
}

fn state_init(op: Op) -> &'static str {
    match op {
        Op::Fibs => "{ a: 0, b: 1 }",
        _ => "{ i: 0 }",
    }
}

pub fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(n: usize) -> Vec<{}>", op.name(), op.ret())
}

pub fn reference_src(spec: Spec) -> String {
    let mut parts: Vec<String> = Vec::new();
    for &op in spec.ops.iter() {
        parts.push(iter_src(op, true));
    }
    parts.join("\n")
}
pub fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}

pub fn worked_examples_prose(spec: Spec, seed: u64) -> String {
    let mut lines = Vec::new();
    for ex in worked_examples(seed).iter() {
        let mut parts = Vec::new();
        for &(op, ref out) in ex.answers.iter() {
            if spec.ops.contains(&op) {
                parts.push(format!("{} = {}", op.name(), out.lit()));
            }
        }
        if !parts.is_empty() {
            lines.push(format!("//!   n {}  ->  {}", ex.n, parts.join(", ")));
        } else {
            lines.push(format!("//!   n {}  ->  (pair-dependent)", ex.n));
        }
    }
    lines.join("\n")
}

pub fn cargo_toml() -> String {
    "[package]\nname = \"task\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n"
        .to_string()
}

pub fn skeleton_src(spec: Spec, seed: u64) -> String {
    let mut head = format!(
        "//! Fill in the `next()` of each iterator state machine below.\n//!\n//! Each machine is unbounded; its driver collects exactly `n` items via\n//! `take(n)`, so termination is already handled — the skill is what each\n//! poll yields and how the cursor advances afterwards.\n//!\n//! Worked examples:\n{}\n",
        worked_examples_prose(spec, seed)
    );
    for op in spec.ops.iter() {
        let stub = iter_src(*op, false);
        head.push_str(&stub);
        head.push('\n');
    }
    head
}

pub fn prompt(spec: Spec, seed: u64) -> String {
    let canary = mint_canary("iter-machine", seed);
    let mut reqs = Vec::new();
    for &op in spec.ops.iter() {
        reqs.push(format!("- `{}` must produce {}.", op.name(), op.prose()));
    }
    let sigs: Vec<String> = spec.ops.iter().map(|&op| op_sig_src(op)).collect();
    format!(
        "Implement custom iterator state machines.\n\nEach machine below is a dedicated struct implementing std::iter::Iterator whose next() is empty. The driver functions are complete: they construct the machine and collect exactly n items with take. Fill ONLY the missing next() bodies so every driver returns its sequence exactly.\n\nRequirements:\n{}\nConstraints:\n- No unsafe code.\n- Keep every signature and struct name exactly as given; only fill in the todo!() bodies.\n- The machines are unbounded on purpose; yield forever rather than adding your own stopping logic.\n\nSignatures:\n```rust\n{}\n```\n\nWorked examples:\n```\n{}\n```\n\nThe task's hidden canary is: {}\n",
        reqs.join("\n"),
        sigs.join("\n"),
        worked_examples_prose(spec, seed),
        canary
    )
}
pub fn behavior_test_src(spec: Spec, seed: u64) -> String {
    let names: Vec<&str> = spec.ops.iter().map(|&o| o.name()).collect();
    let mut s = format!("use task::{{{}}};\n", names.join(", "));
    for (i, ex) in worked_examples(seed).iter().enumerate() {
        let mut asserts = Vec::new();
        for &(op, ref out) in ex.answers.iter() {
            if spec.ops.contains(&op) {
                asserts.push(format!(
                    "assert_eq!({}, {});",
                    call_src(op, &render_input(ex.n)),
                    out.lit()
                ));
            }
        }
        s.push_str(&format!(
            "\n#[test]\nfn ex{}() {{\n    {}\n}}\n",
            i,
            asserts.join("\n    ")
        ));
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let names: Vec<&str> = spec.ops.iter().map(|&o| o.name()).collect();
    let mut s = format!("use task::{{{}}};\n\n", names.join(", "));
    let mut refs = reference_src(spec);
    for &op in spec.ops.iter() {
        let pat = format!("pub fn {}(", op.name());
        let rep = format!("fn ref_{}(", op.name());
        assert_eq!(refs.matches(&pat).count(), 1, "{}", pat);
        refs = refs.replacen(&pat, &rep, 1);
    }
    s.push_str(&refs);
    s.push_str(
        "\nfn nx(state: &mut u64) -> u64 {\n    *state = state\n        .wrapping_mul(6364136223846793005)\n        .wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n#[test]\nfn differential_vs_reference() {\n    let mut state: u64 = 0xE7EE_ED00_0000_0180;\n    for _ in 0..3000 {\n        let n = (nx(&mut state) % 13) as usize;\n",
    );
    for &op in spec.ops.iter() {
        let c = call_src(op, "n");
        s.push_str(&format!(
            "        assert_eq!({}, ref_{}(n));\n",
            c,
            op.name()
        ));
    }
    s.push_str("    }\n}\n");
    s
}

pub fn const_zero() -> String {
    let mut parts = Vec::new();
    for op in OP_ALL.iter() {
        parts.push(format!(
            "pub fn {}(n: usize) -> Vec<{}> {{\n    let _ = n;\n    vec![]\n}}\n",
            op.name(),
            op.ret()
        ));
    }
    parts.join("\n")
}

/// Machines whose cursor starts one step late — the first value never
/// appears. Wrong for every non-empty input.
pub fn off_by_one() -> String {
    let mut parts = Vec::new();
    for op in OP_ALL.iter() {
        let src = iter_src(*op, true)
            .replace("{ a: 0, b: 1 }", "{ a: 1, b: 1 }")
            .replace("{ i: 0 }", "{ i: 1 }");
        parts.push(src);
    }
    parts.join("\n")
}
pub struct IterMachineFamily;

impl Generator for IterMachineFamily {
    fn id(&self) -> &'static str {
        "iter-machine"
    }

    fn category(&self) -> &'static str {
        "custom-iterators"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let mut files = std::collections::BTreeMap::new();
        files.insert(std::path::PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(
            std::path::PathBuf::from("src/lib.rs"),
            skeleton_src(spec, seed),
        );
        let mut hidden = std::collections::BTreeMap::new();
        hidden.insert(
            std::path::PathBuf::from("tests/behavior.rs"),
            behavior_test_src(spec, seed),
        );
        hidden.insert(
            std::path::PathBuf::from("tests/differential.rs"),
            differential_test_src(spec),
        );
        GeneratedTask {
            id: format!("iter-machine/{:016x}", seed),
            category: self.category().to_string(),
            prompt: prompt(spec, seed),
            canary: mint_canary(self.id(), seed),
            answer_path: String::from("src/lib.rs"),
            files,
            hidden,
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
        reference_src(sample(seed))
    }

    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(sample(seed), seed)
    }

    fn trivial_baselines(&self, _seed: u64) -> Vec<(String, String)> {
        vec![
            ("const-zero".to_string(), const_zero()),
            ("off-by-one".to_string(), off_by_one()),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let mut names: Vec<String> = sample(seed)
            .ops
            .iter()
            .map(|&op| format!("q:{}", op.name()))
            .collect();
        names.sort();
        names
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = IterMachineFamily.generate(11);
        let b = IterMachineFamily.generate(11);
        assert_eq!(a.id, b.id);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
        assert_eq!(a.hidden, b.hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        assert_eq!(b_fibs(6), vec![0, 1, 1, 2, 3, 5]);
        assert_eq!(b_fibs(0), Vec::<u64>::new());
        assert_eq!(b_squares(4), vec![0, 1, 4, 9]);
        assert_eq!(b_evens(3), vec![0, 2, 4]);
        assert_eq!(b_triangulars(5), vec![0, 1, 3, 6, 10]);
        assert_eq!(b_alts(5), vec![0, -1, 2, -3, 4]);
        assert_eq!(b_alts(0), Vec::<i64>::new());
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut specs = std::collections::HashSet::new();
        for seed in 0..300u64 {
            specs.insert(sample(seed));
        }
        assert!(specs.len() >= 9);
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        for seed in 0..200u64 {
            let n = canonical(seed);
            assert!((4..=15).contains(&n));
            for &op in OP_ALL.iter() {
                match op_eval(op, n) {
                    VecOut::U64(v) => {
                        assert_eq!(v.len(), n);
                        // every machine opens at zero; the off-by-one
                        // baseline starts its cursor at one and misses it
                        assert_eq!(v[0], 0);
                    }
                    VecOut::I64(ref v) => {
                        assert_eq!(v.len(), n);
                        assert_eq!(v[0], 0);
                    }
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for ex in worked_examples(seed).iter() {
                for &(op, ref out) in ex.answers.iter() {
                    let got = op_eval(op, ex.n);
                    assert_eq!(&got, out);
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in 0..50u64 {
            let spec = sample(seed);
            let reference = reference_src(spec);
            for &op in OP_ALL.iter() {
                let needle = format!("pub fn {}(", op.name());
                let count = reference.matches(&needle).count();
                if spec.ops.contains(&op) {
                    assert_eq!(count, 1, "seed {seed} missing {}", op.name());
                } else {
                    assert_eq!(count, 0, "seed {seed} leaked {}", op.name());
                }
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            let skel = skeleton_src(spec, seed);
            let p = prompt(spec, seed);
            assert!(skel.contains("todo!()"));
            assert!(!skel.contains("wrapping_add"));
            assert!(!p.contains("wrapping_add"));
            for token in ["* self.i", "(self.i + 1)", "% 2 == 0"] {
                assert!(!skel.contains(token), "{token} leaked into skeleton");
                assert!(!p.contains(token), "{token} leaked into prompt");
            }
            for &op in spec.ops.iter() {
                assert!(skel.contains(&op_sig_src(op)));
                assert!(p.contains(&op_sig_src(op)));
                assert!(skel.contains(&format!("impl std::iter::Iterator for {}", op.machine())));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for seed in 0..40u64 {
            let spec = sample(seed);
            for &op in spec.ops.iter() {
                let sig = op_sig_src(op);
                let params = sig.split("->").next().unwrap();
                let sig_commas = params.matches(',').count();
                let call = call_src(op, "n");
                assert_eq!(call.matches(',').count(), sig_commas);
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in 0..20u64 {
            let spec = sample(seed);
            let p = prompt(spec, seed);
            assert!(p.contains(&mint_canary("iter-machine", seed)));
        }
    }
}

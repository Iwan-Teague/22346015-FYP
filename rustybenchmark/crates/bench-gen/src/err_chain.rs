//! The `err-chain` family (category `error-handling`).
//!
//! A *third* `error-handling` family, testing the sub-skill neither predecessor
//! does: **`?` propagation across distinct error types**. The model implements
//! `fn f(input: &str) -> Result<i64, PipelineError>` over a whitespace-separated
//! token stream, where the pinned `parse_token` helper fails with its own
//! `ParseFail` type — so the `?` operator only compiles once the model provides
//! `impl From<ParseFail> for PipelineError`. Where `error-handling` (#1) is
//! validate-over-`&[&str]` and `checked-eval` (#2) is checked arithmetic, this is
//! the From-conversion chain: parse failure → `Bad(token)`, rule violation →
//! `Bound(value)`, empty input → `Empty` — the *first* failure wins.
//!
//! Seed-selected on three axes:
//!
//! 1. **Fold** — the reduction over the parsed values: Sum / Product / AbsSum.
//! 2. **Rule** — the per-value precondition checked after parsing: Positive /
//!    AtMost(b) / InRange(lo, hi) / Even (failure `→ Bound(v)`).
//! 3. **Policy** — what a parse failure does: Propagate (`Bad`, via `?`+`From`)
//!    or Skip (the token is dropped; only the `Bound`/`Empty` paths remain).
//!
//! The structural surface is 3 × 4 × 2 = **24 distinct skills**; the rule bounds
//! are constant parameters of the same skill (Q31), excluded from
//! `spec_signature` along with the function name. The `PipelineError` enum, the
//! `ParseFail` payload and `parse_token` are pinned in the skeleton (docs/04:
//! error-handling pins the public error type; the differential grades *which*
//! variant is returned, not how it is spelled). Solution-first and
//! correct-by-construction (ADR-0003): native `eval` and the emitted reference
//! are mirrored, and the differential fuzzes 3000 random inputs over values
//! bounded so no fold can overflow. The differential's inlined copy converts
//! parse failures with an explicit `PipelineError::Bad(e.0)` rather than `?`, so
//! it compiles against *any* behaviourally correct answer — even one that used
//! `map_err` instead of the requested `From` impl — and stays a pure behaviour
//! comparison.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — the fold over the parsed values.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Fold {
    Sum,
    Product,
    AbsSum,
}

/// Axis 2 — the per-value precondition, checked after parsing.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Rule {
    Positive,
    AtMost(i64),
    InRange(i64, i64),
    Even,
}

/// Axis 3 — what an unparseable token does.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Policy {
    Propagate,
    Skip,
}

struct Spec {
    fold: Fold,
    rule: Rule,
    policy: Policy,
    fn_name: &'static str,
}

const NAMES: &[&str] = &[
    "run",
    "process",
    "evaluate",
    "pipeline",
    "compute",
    "reduce_line",
];

/// Tokens that never parse as `i64` (used by the differential and random examples).
const GARBAGE: &[&str] = &["x", "1.5", "n/a", "-"];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let fold = match rng.below(3) {
        0 => Fold::Sum,
        1 => Fold::Product,
        _ => Fold::AbsSum,
    };
    let rule = match rng.below(4) {
        0 => Rule::Positive,
        1 => Rule::AtMost([5, 10, 20][rng.below(3) as usize]),
        2 => {
            let (lo, hi) = [(0, 10), (-5, 5), (1, 8)][rng.below(3) as usize];
            Rule::InRange(lo, hi)
        }
        _ => Rule::Even,
    };
    let policy = match rng.below(2) {
        0 => Policy::Propagate,
        _ => Policy::Skip,
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        fold,
        rule,
        policy,
        fn_name,
    }
}

// ---- native reference (mirrors the emitted source exactly) ----------------

fn init_val(fold: Fold) -> i64 {
    match fold {
        Fold::Product => 1,
        _ => 0,
    }
}

fn init_expr(fold: Fold) -> &'static str {
    match fold {
        Fold::Product => "1",
        _ => "0",
    }
}

fn step_val(fold: Fold, acc: i64, v: i64) -> i64 {
    match fold {
        Fold::Sum => acc + v,
        Fold::Product => acc * v,
        Fold::AbsSum => acc + v.abs(),
    }
}

fn step_expr(fold: Fold) -> &'static str {
    match fold {
        Fold::Sum => "acc + v",
        Fold::Product => "acc * v",
        Fold::AbsSum => "acc + v.abs()",
    }
}

fn rule_ok(rule: Rule, v: i64) -> bool {
    match rule {
        Rule::Positive => v > 0,
        Rule::AtMost(b) => v <= b,
        Rule::InRange(lo, hi) => v >= lo && v <= hi,
        Rule::Even => v % 2 == 0,
    }
}

fn rule_cond(rule: Rule) -> String {
    match rule {
        Rule::Positive => "v > 0".to_string(),
        Rule::AtMost(b) => format!("v <= {b}"),
        Rule::InRange(lo, hi) => format!("v >= {lo} && v <= {hi}"),
        Rule::Even => "v % 2 == 0".to_string(),
    }
}

/// The answer over a token stream. Errors are tag strings that mirror the pinned
/// `PipelineError` variants, matching how the emitted enum derives `PartialEq`:
/// `"Empty"`, `"Bound(v)"`, `"Bad(token)"`.
fn eval(spec: &Spec, input: &str) -> Result<i64, String> {
    let toks: Vec<&str> = input.split_whitespace().collect();
    if toks.is_empty() {
        return Err("Empty".to_string());
    }
    let mut acc = init_val(spec.fold);
    for tok in toks {
        let v = match tok.parse::<i64>() {
            Ok(v) => v,
            Err(_) => match spec.policy {
                Policy::Skip => continue,
                Policy::Propagate => return Err(format!("Bad({tok})")),
            },
        };
        if !rule_ok(spec.rule, v) {
            return Err(format!("Bound({v})"));
        }
        acc = step_val(spec.fold, acc, v);
    }
    Ok(acc)
}

// ---- emitted-source fragments (mirror the native functions above) ---------

const PINNED_SRC: &str = "#[derive(Debug, PartialEq)]\n\
      pub enum PipelineError {\n\
      \x20   Bad(String),\n\
      \x20   Bound(i64),\n\
      \x20   Empty,\n\
      }\n\
      \n\
      pub struct ParseFail(pub String);\n\
      \n\
      pub fn parse_token(s: &str) -> Result<i64, ParseFail> {\n\
      \x20   s.parse::<i64>().map_err(|_| ParseFail(s.to_string()))\n\
      }\n";

fn from_impl_src() -> String {
    "impl From<ParseFail> for PipelineError {\n\
     \x20   fn from(e: ParseFail) -> Self {\n\
     \x20       PipelineError::Bad(e.0)\n\
     \x20   }\n\
     }\n"
    .to_string()
}

fn reference_src(spec: &Spec) -> String {
    let parse_line = match spec.policy {
        Policy::Propagate => "let v = parse_token(tok)?;",
        Policy::Skip => {
            "let v = match parse_token(tok) {\n\
             \x20           Ok(v) => v,\n\
             \x20           Err(_) => continue,\n\
             \x20       };"
        }
    };
    format!(
        "{pinned}\n\
         {from_impl}\n\
         pub fn {name}(input: &str) -> Result<i64, PipelineError> {{\n\
         \x20   let toks: Vec<&str> = input.split_whitespace().collect();\n\
         \x20   if toks.is_empty() {{\n\
         \x20       return Err(PipelineError::Empty);\n\
         \x20   }}\n\
         \x20   let mut acc: i64 = {init};\n\
         \x20   for tok in toks {{\n\
         \x20       {parse_line}\n\
         \x20       if !({rule}) {{\n\
         \x20           return Err(PipelineError::Bound(v));\n\
         \x20       }}\n\
         \x20       acc = {step};\n\
         \x20   }}\n\
         \x20   Ok(acc)\n\
         }}\n",
        pinned = PINNED_SRC,
        from_impl = from_impl_src(),
        name = spec.fn_name,
        init = init_expr(spec.fold),
        parse_line = parse_line,
        rule = rule_cond(spec.rule),
        step = step_expr(spec.fold),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let examples = worked_examples_prose(spec, seed);
    format!(
        "//! Implement `{name}` below. The `PipelineError` enum, the `ParseFail`\n\
         //! payload type and the `parse_token` helper are provided; keep them.\n\
         //!\n\
         {doc}\n\
         {pinned}\n\
         pub fn {name}(input: &str) -> Result<i64, PipelineError> {{\n\
         \x20   todo!()\n\
         }}\n",
        name = spec.fn_name,
        pinned = PINNED_SRC,
        doc = examples
            .lines()
            .map(|l| format!("//! {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Derives the non-canonical worked examples; unique across families (lib.rs guard).
const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01F0;

/// Worked examples: `(input, expected)`, expected computed natively so each is
/// correct by construction. The set always includes the **canonical** all-valid
/// case `"2 4 2"` (valid under every rule the sampler can pick, so its answer is
/// `Ok(v)` with `v ∉ {0, Empty, Bound}` — which catches both const baselines), a
/// **parse-failure** case (the example that distinguishes the policy axis:
/// `Err(Bad)` under Propagate, a clean `Ok` under Skip), a constructed
/// **rule-violation** case (`Err(Bound)` under both policies), the **empty** case
/// (`Err(Empty)` — which catches the no-empty baseline), and two seed-varied
/// random cases. Seed-varying is the biggest per-instance textual lever (Q30).
fn worked_examples(spec: &Spec, seed: u64) -> Vec<(String, Result<i64, String>)> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut out: Vec<(String, Result<i64, String>)> = Vec::new();

    // Canonical all-valid case (see doc comment).
    out.push(("2 4 2".to_string(), eval(spec, "2 4 2")));

    // Parse-failure case: a clean lead, a garbage token, a clean tail. Under
    // Propagate this is Err(Bad("x")); under Skip the token is dropped and the
    // rest folds normally.
    out.push(("2 x 4".to_string(), eval(spec, "2 x 4")));

    // Constructed rule-violation case: parses fine, violates the rule.
    let viol = violating_value(spec.rule);
    let rv = format!("2 {viol} 4");
    out.push((rv.clone(), eval(spec, &rv)));

    // Empty case (no tokens).
    out.push((String::new(), eval(spec, "")));

    // Two seed-varied random cases: small integers with the occasional garbage
    // token, so both failure paths stay exercised without overflowing the fold.
    for _ in 0..2 {
        let len = 2 + rng.below(4) as usize; // 2..=5
        let mut toks: Vec<String> = Vec::new();
        for _ in 0..len {
            if rng.below(4) == 0 {
                toks.push(GARBAGE[rng.below(GARBAGE.len() as u64) as usize].to_string());
            } else {
                toks.push((rng.below(19) as i64 - 9).to_string()); // -9..=9
            }
        }
        let input = toks.join(" ");
        out.push((input.clone(), eval(spec, &input)));
    }
    out
}

/// A value guaranteed to violate `rule` while still parsing — the middle token of
/// the rule-violation example.
fn violating_value(rule: Rule) -> i64 {
    match rule {
        Rule::Positive => 0,
        Rule::AtMost(b) => b + 1,
        Rule::InRange(_, hi) => hi + 1,
        // 3 is odd, and every other rule the sampler can pick passes it too, so
        // this example only ever fails via the Even rule.
        Rule::Even => 3,
    }
}

/// Render an eval result the way the pinned enum spells it (used in prompts,
/// skeleton docs and emitted tests).
fn render_expected(res: &Result<i64, String>) -> String {
    match res {
        Ok(v) => format!("Ok({v})"),
        Err(e) => {
            if e == "Empty" {
                "Err(PipelineError::Empty)".to_string()
            } else if let Some(inner) = e.strip_prefix("Bad(").and_then(|r| r.strip_suffix(')')) {
                format!("Err(PipelineError::Bad({inner:?}.to_string()))")
            } else if let Some(inner) = e.strip_prefix("Bound(").and_then(|r| r.strip_suffix(')')) {
                format!("Err(PipelineError::Bound({inner}))")
            } else {
                unreachable!("unexpected error tag: {e}")
            }
        }
    }
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (input, res) in worked_examples(spec, seed) {
        s.push_str(&format!("  {input:?}  ->  {}\n", render_expected(&res)));
    }
    s
}

fn fold_prose(fold: Fold) -> &'static str {
    match fold {
        Fold::Sum => "their sum",
        Fold::Product => "their product",
        Fold::AbsSum => "the sum of their absolute values",
    }
}

fn rule_prose(rule: Rule) -> String {
    match rule {
        Rule::Positive => "be strictly positive (`> 0`)".to_string(),
        Rule::AtMost(b) => format!("be at most `{b}`"),
        Rule::InRange(lo, hi) => format!("be in the range `{lo}..={hi}` inclusive"),
        Rule::Even => "be even".to_string(),
    }
}

fn policy_prose(policy: Policy) -> String {
    match policy {
        Policy::Propagate => "If a token does not parse, return \
             `Err(PipelineError::Bad(token))` with the offending token. Wire the \
             conversion up by implementing `impl From<ParseFail> for PipelineError` \
             and propagating with the `?` operator."
            .to_string(),
        Policy::Skip => "Tokens that do not parse are skipped silently (the fold \
             continues with the remaining tokens)."
            .to_string(),
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let examples = worked_examples_prose(spec, seed);
    let from_note = match spec.policy {
        Policy::Propagate => {
            "\n\
         Constraints:\n\
         - Provide `impl From<ParseFail> for PipelineError` and use `?` for the \
         conversion; do not `unwrap` or `expect` on parse results.\n"
        }
        Policy::Skip => {
            "\n\
         Constraints:\n\
         - Never panic: no `unwrap` or `expect` on parse results.\n"
        }
    };
    format!(
        "Implement the function `{name}` in `src/lib.rs`. The `PipelineError` enum, \
         the `ParseFail` payload type and the `parse_token` helper are already \
         provided; keep them exactly as they are.\n\
         \n\
         `{name}` processes a whitespace-separated list of integer tokens and folds \
         them into {fold}. Rules, in the order they apply:\n\
         - An input containing no tokens returns `Err(PipelineError::Empty)`.\n\
         - {policy}\n\
         - After parsing, each value must {rule}; if it does not, return \
         `Err(PipelineError::Bound(value))` with the offending value.\n\
         - Otherwise fold the value into the accumulator, left to right.\n\
         - When every token has been processed, return `Ok(acc)`.\n\
         The first failure wins: stop at it.\n{from_note}\
         - Do not use `unsafe`.\n\
         \n\
         Signature:\n\
         ```rust\n\
         pub fn {name}(input: &str) -> Result<i64, PipelineError>\n\
         ```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        fold = fold_prose(spec.fold),
        policy = policy_prose(spec.policy),
        rule = rule_prose(spec.rule),
        from_note = from_note,
        examples = examples,
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
    let mut body = format!("use task::{{PipelineError, {}}};\n\n", spec.fn_name);
    for (i, (input, res)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   assert_eq!({name}({input:?}), {expect});\n\
             }}\n\n",
            name = spec.fn_name,
            expect = render_expected(res),
        ));
    }
    body
}

/// The inlined differential reference: a copy of the emitted reference with the
/// parse step converted explicitly (`map_err` + `?` on the already-`PipelineError`
/// result) so it needs no `From` impl from the answer under test, and with the
/// pinned items imported from `task` instead of redeclared.
fn differential_reference_src(spec: &Spec) -> String {
    let parse_line = match spec.policy {
        Policy::Propagate => "let v = parse_token(tok).map_err(|e| PipelineError::Bad(e.0))?;",
        Policy::Skip => {
            "let v = match parse_token(tok) {\n\
             \x20           Ok(v) => v,\n\
             \x20           Err(_) => continue,\n\
             \x20       };"
        }
    };
    format!(
        "fn reference(input: &str) -> Result<i64, PipelineError> {{\n\
         \x20   let toks: Vec<&str> = input.split_whitespace().collect();\n\
         \x20   if toks.is_empty() {{\n\
         \x20       return Err(PipelineError::Empty);\n\
         \x20   }}\n\
         \x20   let mut acc: i64 = {init};\n\
         \x20   for tok in toks {{\n\
         \x20       {parse_line}\n\
         \x20       if !({rule}) {{\n\
         \x20           return Err(PipelineError::Bound(v));\n\
         \x20       }}\n\
         \x20       acc = {step};\n\
         \x20   }}\n\
         \x20   Ok(acc)\n\
         }}\n",
        init = init_expr(spec.fold),
        parse_line = parse_line,
        rule = rule_cond(spec.rule),
        step = step_expr(spec.fold),
    )
}

fn differential_test_src(spec: &Spec) -> String {
    format!(
        "use task::{{PipelineError, parse_token, {name}}};\n\
         \n\
         const GARBAGE: [&str; 4] = [\"x\", \"1.5\", \"n/a\", \"-\"];\n\
         \n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_01F4;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 9) as usize;\n\
         \x20       let mut input = String::new();\n\
         \x20       for _ in 0..len {{\n\
         \x20           if next() % 10 < 7 {{\n\
         \x20               // Values stay within ±12 so no fold overflows i64.\n\
         \x20               let v = (next() % 25) as i64 - 12;\n\
         \x20               input.push_str(&v.to_string());\n\
         \x20           }} else {{\n\
         \x20               input.push_str(GARBAGE[(next() % 4) as usize]);\n\
         \x20           }}\n\
         \x20           input.push(' ');\n\
         \x20       }}\n\
         \x20       assert_eq!({name}(&input), reference(&input), \"mismatch on {{input:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = differential_reference_src(spec),
    )
}

/// Degenerate: always `Err(PipelineError::Empty)`. Fails the canonical example.
fn const_empty(spec: &Spec) -> String {
    format!(
        "{pinned}\n\
         {from_impl}\n\
         pub fn {name}(input: &str) -> Result<i64, PipelineError> {{\n\
         \x20   let _ = input;\n\
         \x20   Err(PipelineError::Empty)\n\
         }}\n",
        pinned = PINNED_SRC,
        from_impl = from_impl_src(),
        name = spec.fn_name,
    )
}

/// Degenerate: always `Err(PipelineError::Bound(0))`. Fails the canonical example.
fn const_bound_zero(spec: &Spec) -> String {
    format!(
        "{pinned}\n\
         {from_impl}\n\
         pub fn {name}(input: &str) -> Result<i64, PipelineError> {{\n\
         \x20   let _ = input;\n\
         \x20   Err(PipelineError::Bound(0))\n\
         }}\n",
        pinned = PINNED_SRC,
        from_impl = from_impl_src(),
        name = spec.fn_name,
    )
}

/// Degenerate: the full reference minus the empty-input check, so `""` yields
/// `Ok(init)` where every spec demands `Err(PipelineError::Empty)`.
fn no_empty(spec: &Spec) -> String {
    let parse_line = match spec.policy {
        Policy::Propagate => "let v = parse_token(tok)?;",
        Policy::Skip => {
            "let v = match parse_token(tok) {\n\
             \x20           Ok(v) => v,\n\
             \x20           Err(_) => continue,\n\
             \x20       };"
        }
    };
    format!(
        "{pinned}\n\
         {from_impl}\n\
         pub fn {name}(input: &str) -> Result<i64, PipelineError> {{\n\
         \x20   let mut acc: i64 = {init};\n\
         \x20   for tok in input.split_whitespace() {{\n\
         \x20       {parse_line}\n\
         \x20       if !({rule}) {{\n\
         \x20           return Err(PipelineError::Bound(v));\n\
         \x20       }}\n\
         \x20       acc = {step};\n\
         \x20   }}\n\
         \x20   Ok(acc)\n\
         }}\n",
        pinned = PINNED_SRC,
        from_impl = from_impl_src(),
        name = spec.fn_name,
        init = init_expr(spec.fold),
        parse_line = parse_line,
        rule = rule_cond(spec.rule),
        step = step_expr(spec.fold),
    )
}

pub struct ErrChainFamily;

impl Generator for ErrChainFamily {
    fn id(&self) -> &str {
        "err-chain"
    }
    fn category(&self) -> &str {
        "error-handling"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("err-chain", seed);

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
            id: format!("err-chain/{seed:016x}"),
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
            ("const-bound0".to_string(), const_bound_zero(&spec)),
            ("no-empty".to_string(), no_empty(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is the (fold, rule type, parse policy). Rule bounds are
        // constant parameters of the same skill (Q31); the function name is
        // cosmetic — both excluded.
        let spec = sample(seed);
        let fold = match spec.fold {
            Fold::Sum => "sum",
            Fold::Product => "product",
            Fold::AbsSum => "abs_sum",
        };
        let rule = match spec.rule {
            Rule::Positive => "positive",
            Rule::AtMost(_) => "at_most",
            Rule::InRange(_, _) => "in_range",
            Rule::Even => "even",
        };
        let policy = match spec.policy {
            Policy::Propagate => "propagate",
            Policy::Skip => "skip",
        };
        vec![
            format!("fold:{fold}"),
            format!("rule:{rule}"),
            format!("policy:{policy}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = ErrChainFamily;
        assert_eq!(g.generate(29).prompt, g.generate(29).prompt);
        assert_eq!(g.generate(29).hidden, g.generate(29).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        let mk = |fold, rule, policy| Spec {
            fold,
            rule,
            policy,
            fn_name: "f",
        };
        // Sum + Positive over "2 3 4" = 9.
        assert_eq!(
            eval(&mk(Fold::Sum, Rule::Positive, Policy::Propagate), "2 3 4"),
            Ok(9)
        );
        // Product + Positive = 24.
        assert_eq!(
            eval(
                &mk(Fold::Product, Rule::Positive, Policy::Propagate),
                "2 3 4"
            ),
            Ok(24)
        );
        // AbsSum folds magnitudes: -9 contributes 9.
        assert_eq!(
            eval(
                &mk(Fold::AbsSum, Rule::InRange(-9, 9), Policy::Skip),
                "-9 1"
            ),
            Ok(10)
        );
        // Parse failure propagates as Bad(token) under Propagate.
        assert_eq!(
            eval(&mk(Fold::Sum, Rule::Positive, Policy::Propagate), "2 x 4"),
            Err("Bad(x)".to_string())
        );
        // ...and is skipped under Skip.
        assert_eq!(
            eval(&mk(Fold::Sum, Rule::Positive, Policy::Skip), "2 x 4"),
            Ok(6)
        );
        // Rule failure short-circuits at the first violating value, after parse.
        assert_eq!(
            eval(&mk(Fold::Sum, Rule::Even, Policy::Propagate), "2 3 4"),
            Err("Bound(3)".to_string())
        );
        // Empty input is Empty before any parsing.
        assert_eq!(
            eval(&mk(Fold::Product, Rule::Positive, Policy::Propagate), ""),
            Err("Empty".to_string())
        );
        assert_eq!(
            eval(&mk(Fold::Product, Rule::Positive, Policy::Propagate), "   "),
            Err("Empty".to_string())
        );
    }

    #[test]
    fn seeds_vary_fold_rule_and_policy() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..400u64 {
            let s = sample(seed);
            variants.insert(format!(
                "{:?}/{}/{:?}",
                s.fold,
                match s.rule {
                    Rule::Positive => "p".to_string(),
                    Rule::AtMost(_) => "a".to_string(),
                    Rule::InRange(_, _) => "r".to_string(),
                    Rule::Even => "e".to_string(),
                },
                s.policy
            ));
        }
        assert_eq!(variants.len(), 24, "every (fold, rule, policy) must occur");
    }

    #[test]
    fn canonical_is_ok_under_every_combination() {
        // The const baselines are caught only if the canonical "2 4 2" is Ok(v)
        // with v ∉ {0} under every fold/rule/policy; no-empty is caught only if
        // the empty example is Err(Empty); the rule-violation example must be Err.
        let canonical = "2 4 2";
        for &fold in &[Fold::Sum, Fold::Product, Fold::AbsSum] {
            for &rule in &[
                Rule::Positive,
                Rule::AtMost(5),
                Rule::AtMost(10),
                Rule::AtMost(20),
                Rule::InRange(0, 10),
                Rule::InRange(-5, 5),
                Rule::InRange(1, 8),
                Rule::Even,
            ] {
                for &policy in &[Policy::Propagate, Policy::Skip] {
                    let spec = Spec {
                        fold,
                        rule,
                        policy,
                        fn_name: "f",
                    };
                    match eval(&spec, canonical) {
                        Ok(v) => assert_ne!(v, 0, "canonical is Ok(0) under {fold:?}/{rule:?}"),
                        Err(e) => panic!("canonical rejected under {fold:?}/{rule:?}: {e}"),
                    }
                    // The rule-violation example must actually be Err(Bound).
                    let viol = violating_value(rule);
                    let rv = format!("2 {viol} 4");
                    assert_eq!(
                        eval(&spec, &rv),
                        Err(format!("Bound({viol})")),
                        "rule-violation example is not Bound under {fold:?}/{rule:?}"
                    );
                    // Empty stays Empty under every combination.
                    assert_eq!(eval(&spec, ""), Err("Empty".to_string()));
                }
            }
        }
    }

    #[test]
    fn reference_matches_native_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (input, res) in worked_examples(&spec, seed) {
                assert_eq!(eval(&spec, &input), res, "seed {seed}");
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = ErrChainFamily;
        let t = g.generate(14);
        assert!(t.prompt.contains(&t.canary));
    }

    #[test]
    fn differential_reference_matches_reference_semantics() {
        // The differential's inlined copy must agree with the native eval on the
        // worked examples even though it converts parse errors explicitly.
        for seed in [0u64, 5, 11, 123] {
            let spec = sample(seed);
            let ref_src = differential_reference_src(&spec);
            // Textual mirror sanity: the body carries the same rule and step
            // expressions as the emitted reference.
            let full = reference_src(&spec);
            for frag in [rule_cond(spec.rule).as_str(), step_expr(spec.fold)] {
                assert!(ref_src.contains(frag), "differential mirror lost {frag}");
                assert!(full.contains(frag), "reference lost {frag}");
            }
            for (input, res) in worked_examples(&spec, seed) {
                assert_eq!(eval(&spec, &input), res, "seed {seed}");
            }
        }
    }
}

//! The `result-collect` family (category `error-handling`) — fold an iterator of fallible
//! steps under a seed-selected **error policy**.
//!
//! The four existing `error-handling` families are about producing errors, `?` across types and
//! being an error. This one is the everyday plumbing in between: you have a slice of inputs, each
//! step can fail in two different ways, and the function must decide what a failure *means* for
//! the whole result. The pinned `parse_item` fails with `ItemError::Bad`; the model adds a
//! per-value **rule** check that fails with `ItemError::Rule(v)`, then combines the per-item
//! `Result`s under one of four policies:
//!
//! * **FailFast** — `Result<Vec<i64>, ItemError>`: the first error wins
//!   (`collect::<Result<_, _>>`).
//! * **Partition** — `(Vec<i64>, Vec<ItemError>)`: keep every success *and* every error, in order.
//! * **AllOrNothing** — `Result<i64, Vec<ItemError>>`: the sum if nothing failed, otherwise *all*
//!   the errors (so the first one cannot just short-circuit).
//! * **FirstOk** — `Result<i64, ItemError>`: the first success, else the *last* error (an empty
//!   input is `Err(Bad(""))`).
//!
//! Seed-selected on two axes: **Policy** (4) and **Rule** (3): `Positive` (`v > 0`), `Even`,
//! `AtMost(b)` (`v <= b`). 4 x 3 = **12 distinct skills**; the bound `b` and the function name
//! are cosmetic and excluded from `spec_signature` (Q31). Solution-first (ADR-0003): the native
//! `outcome` and the emitted reference are mirrored, and the differential fuzzes 3000 token lists
//! (valid numbers, padded numbers, non-numbers, empty strings) against an inlined copy of the
//! reference. The pinned items are imported from the model's crate, so the comparison is pure
//! behaviour.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Policy {
    FailFast,
    Partition,
    AllOrNothing,
    FirstOk,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Rule {
    Positive,
    Even,
    AtMost(i64),
}

struct Spec {
    policy: Policy,
    rule: Rule,
    fn_name: &'static str,
}

const NAMES: &[&str] = &[
    "load_all",
    "ingest",
    "read_values",
    "collect_items",
    "scan_items",
    "fold_inputs",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let policy = match rng.below(4) {
        0 => Policy::FailFast,
        1 => Policy::Partition,
        2 => Policy::AllOrNothing,
        _ => Policy::FirstOk,
    };
    let rule = match rng.below(3) {
        0 => Rule::Positive,
        1 => Rule::Even,
        _ => Rule::AtMost(30 + rng.below(31) as i64),
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        policy,
        rule,
        fn_name,
    }
}

// ---- native reference -------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum NE {
    Bad(String),
    Rule(i64),
}

fn rule_ok(rule: Rule, v: i64) -> bool {
    match rule {
        Rule::Positive => v > 0,
        Rule::Even => v % 2 == 0,
        Rule::AtMost(b) => v <= b,
    }
}

/// One item under the full pipeline: pinned parse, then the rule.
fn one(rule: Rule, s: &str) -> Result<i64, NE> {
    let v = s
        .trim()
        .parse::<i64>()
        .map_err(|_| NE::Bad(s.to_string()))?;
    if rule_ok(rule, v) {
        Ok(v)
    } else {
        Err(NE::Rule(v))
    }
}

/// Which behaviour to evaluate: the answer, or one of the two degenerate baselines.
/// (`SkipBad`/`Empty` are the native mirrors of the emitted baselines, exercised by the tests
/// that prove the canonical list defeats them.)
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Correct,
    /// Ignores the rule and drops every failure (keeps only what parses).
    SkipBad,
    /// Returns the policy's empty value.
    Empty,
}

/// The rendered Rust expression for the outcome of `f(items)`.
fn outcome(spec: &Spec, items: &[&str], mode: Mode) -> String {
    let results: Vec<Result<i64, NE>> = items
        .iter()
        .map(|s| match mode {
            Mode::Correct => one(spec.rule, s),
            _ => s.trim().parse::<i64>().map_err(|_| NE::Bad(s.to_string())),
        })
        .collect();
    let oks: Vec<i64> = results
        .iter()
        .filter_map(|r| r.as_ref().ok().copied())
        .collect();
    let errs: Vec<NE> = results
        .iter()
        .filter_map(|r| r.as_ref().err().cloned())
        .collect();
    // The skip-bad baseline drops every failure.
    let (results, errs): (Vec<Result<i64, NE>>, Vec<NE>) = if mode == Mode::SkipBad {
        (oks.iter().map(|&v| Ok(v)).collect(), Vec::new())
    } else {
        (results, errs)
    };
    let vec_lit = |v: &[i64]| format!("vec!{v:?}");
    let err_lit = |e: &NE| match e {
        NE::Bad(s) => format!("ItemError::Bad({s:?}.to_string())"),
        NE::Rule(v) => format!("ItemError::Rule({v})"),
    };
    let errs_lit = |es: &[NE]| {
        format!(
            "vec![{}]",
            es.iter().map(&err_lit).collect::<Vec<_>>().join(", ")
        )
    };
    match (spec.policy, mode) {
        (Policy::FailFast, Mode::Empty) => "Ok(vec![])".to_string(),
        (Policy::Partition, Mode::Empty) => "(vec![], vec![])".to_string(),
        (Policy::AllOrNothing, Mode::Empty) => "Ok(0)".to_string(),
        (Policy::FirstOk, Mode::Empty) => "Err(ItemError::Bad(String::new()))".to_string(),
        (Policy::FailFast, _) => match results.iter().find_map(|r| r.as_ref().err()) {
            Some(e) => format!("Err({})", err_lit(e)),
            None => format!("Ok({})", vec_lit(&oks)),
        },
        (Policy::Partition, _) => format!("({}, {})", vec_lit(&oks), errs_lit(&errs)),
        (Policy::AllOrNothing, _) => {
            if errs.is_empty() {
                format!("Ok({})", oks.iter().sum::<i64>())
            } else {
                format!("Err({})", errs_lit(&errs))
            }
        }
        (Policy::FirstOk, _) => match oks.first() {
            Some(v) => format!("Ok({v})"),
            None => match errs.last() {
                Some(e) => format!("Err({})", err_lit(e)),
                None => "Err(ItemError::Bad(String::new()))".to_string(),
            },
        },
    }
}

// ---- emitted source -------------------------------------------------------------------

const PRELUDE: &str = "#[derive(Debug, Clone, PartialEq)]\n\
    pub enum ItemError {\n\
    \x20   /// The token is not an integer (carries the original token).\n\
    \x20   Bad(String),\n\
    \x20   /// The integer parsed but breaks the rule (carries the value).\n\
    \x20   Rule(i64),\n\
    }\n\
    \n\
    /// Parse one token. Surrounding whitespace is ignored.\n\
    pub fn parse_item(s: &str) -> Result<i64, ItemError> {\n\
    \x20   s.trim()\n\
    \x20       .parse::<i64>()\n\
    \x20       .map_err(|_| ItemError::Bad(s.to_string()))\n\
    }\n";

fn out_ty(policy: Policy) -> &'static str {
    match policy {
        Policy::FailFast => "Result<Vec<i64>, ItemError>",
        Policy::Partition => "(Vec<i64>, Vec<ItemError>)",
        Policy::AllOrNothing => "Result<i64, Vec<ItemError>>",
        Policy::FirstOk => "Result<i64, ItemError>",
    }
}

fn cond_src(rule: Rule) -> String {
    match rule {
        Rule::Positive => "v > 0".to_string(),
        Rule::Even => "v % 2 == 0".to_string(),
        Rule::AtMost(b) => format!("v <= {b}"),
    }
}

fn rule_prose(rule: Rule) -> String {
    match rule {
        Rule::Positive => "must be positive (`> 0`)".to_string(),
        Rule::Even => "must be even".to_string(),
        Rule::AtMost(b) => format!("must be at most {b} (`<= {b}`)"),
    }
}

fn policy_prose(policy: Policy) -> &'static str {
    match policy {
        Policy::FailFast => "Return `Ok` with the values of every item, in order, or — if any item failed — `Err` with the **first** error (items after it are not examined for the result).",
        Policy::Partition => "Return every successfully parsed value, in order, **and** every error, in order: `(values, errors)`. Nothing is dropped and nothing short-circuits.",
        Policy::AllOrNothing => "If every item succeeded return `Ok` with the **sum** of the values (an empty slice sums to `0`). If any item failed return `Err` with **all** the errors, in order — not just the first.",
        Policy::FirstOk => "Return `Ok` with the **first** item that succeeds. If none does, return `Err` with the **last** error. An empty slice returns `Err(ItemError::Bad(String::new()))`.",
    }
}

fn body_src(policy: Policy) -> &'static str {
    match policy {
        Policy::FailFast => "    items.iter().map(|s| parse_item(s).and_then(check)).collect()\n",
        Policy::Partition => {
            "    let mut values = Vec::new();\n\
             \x20   let mut errors = Vec::new();\n\
             \x20   for s in items {\n\
             \x20       match parse_item(s).and_then(check) {\n\
             \x20           Ok(v) => values.push(v),\n\
             \x20           Err(e) => errors.push(e),\n\
             \x20       }\n\
             \x20   }\n\
             \x20   (values, errors)\n"
        }
        Policy::AllOrNothing => {
            "    let mut sum = 0;\n\
             \x20   let mut errors = Vec::new();\n\
             \x20   for s in items {\n\
             \x20       match parse_item(s).and_then(check) {\n\
             \x20           Ok(v) => sum += v,\n\
             \x20           Err(e) => errors.push(e),\n\
             \x20       }\n\
             \x20   }\n\
             \x20   if errors.is_empty() {\n\
             \x20       Ok(sum)\n\
             \x20   } else {\n\
             \x20       Err(errors)\n\
             \x20   }\n"
        }
        Policy::FirstOk => {
            "    let mut last = ItemError::Bad(String::new());\n\
             \x20   for s in items {\n\
             \x20       match parse_item(s).and_then(check) {\n\
             \x20           Ok(v) => return Ok(v),\n\
             \x20           Err(e) => last = e,\n\
             \x20       }\n\
             \x20   }\n\
             \x20   Err(last)\n"
        }
    }
}

fn check_src(rule: Rule) -> String {
    format!(
        "fn check(v: i64) -> Result<i64, ItemError> {{\n\
         \x20   if {} {{\n\
         \x20       Ok(v)\n\
         \x20   }} else {{\n\
         \x20       Err(ItemError::Rule(v))\n\
         \x20   }}\n\
         }}\n",
        cond_src(rule)
    )
}

fn reference_src(spec: &Spec) -> String {
    format!(
        "{PRELUDE}\n{check}\npub fn {name}(items: &[&str]) -> {ty} {{\n{body}}}\n",
        check = check_src(spec.rule),
        name = spec.fn_name,
        ty = out_ty(spec.policy),
        body = body_src(spec.policy),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .1
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Implement `{name}` below. `ItemError` and `parse_item` are provided — keep them.\n\
         //!\n\
         {doc}\n\
         {PRELUDE}\n\
         pub fn {name}(items: &[&str]) -> {ty} {{\n\
         \x20   todo!()\n\
         }}\n",
        name = spec.fn_name,
        ty = out_ty(spec.policy),
    )
}

// ---- worked examples ------------------------------------------------------------------

const POOL: &[&str] = &[
    "0", "1", "-3", "12", "7", "42", "99", "100", "-50", " 4 ", "+8", "abc", "", "1.5", "0x10",
];

/// The canonical list: constructed per rule so that the **first parseable value breaks the
/// rule** (so a rule-ignoring answer returns a different first success), with at least one
/// non-number, one rule violation and two successes — what both baselines need to fail under
/// every policy.
fn canonical(rule: Rule) -> Vec<String> {
    let viol = match rule {
        Rule::Positive => "-4".to_string(),
        Rule::Even => "7".to_string(),
        Rule::AtMost(b) => (b + 9).to_string(),
    };
    ["oops", viol.as_str(), "12", viol.as_str(), "10"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn worked_examples(spec: &Spec, seed: u64) -> (Vec<Vec<String>>, String) {
    let mut rng = Rng::new(seed ^ 0xC011_0000_0000_0E55);
    let mut lists = vec![canonical(spec.rule)];
    for _ in 0..2 {
        let len = rng.below(6) as usize;
        lists.push(
            (0..len)
                .map(|_| POOL[rng.below(POOL.len() as u64) as usize].to_string())
                .collect(),
        );
    }
    let mut prose = String::new();
    for l in &lists {
        let refs: Vec<&str> = l.iter().map(String::as_str).collect();
        prose.push_str(&format!(
            "  {}({})  ->  {}\n",
            spec.fn_name,
            items_lit(&refs),
            outcome(spec, &refs, Mode::Correct)
        ));
    }
    (lists, prose)
}

fn items_lit(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|s| format!("{s:?}")).collect();
    format!("&[{}]", inner.join(", "))
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (_, examples) = worked_examples(spec, seed);
    format!(
        "Implement `{name}` in `src/lib.rs`. The `ItemError` enum and the `parse_item` function \
         are provided — keep them unchanged.\n\
         \n\
         Each token is processed in two steps: `parse_item` (fails with `ItemError::Bad`), then a \
         rule on the parsed value, which {rule}; a value that breaks it is the error \
         `ItemError::Rule(value)`. {policy}\n\
         \n\
         Constraints:\n\
         - Keep the signature `pub fn {name}(items: &[&str]) -> {ty}` exactly.\n\
         - Process items in order. Do not use `unsafe`, `unwrap` or `expect`.\n\
         \n\
         Provided in `src/lib.rs`:\n\
         ```rust\n\
         {PRELUDE}```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        rule = rule_prose(spec.rule),
        policy = policy_prose(spec.policy),
        ty = out_ty(spec.policy),
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
    let (lists, _) = worked_examples(spec, seed);
    let mut body = format!("use task::{{ItemError, {}}};\n\n", spec.fn_name);
    for (i, l) in lists.iter().enumerate() {
        let refs: Vec<&str> = l.iter().map(String::as_str).collect();
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    assert_eq!({}({}), {});\n}}\n\n",
            spec.fn_name,
            items_lit(&refs),
            outcome(spec, &refs, Mode::Correct)
        ));
    }
    body.push_str(&format!(
        "#[test]\nfn empty_input() {{\n    assert_eq!({}(&[]), {});\n}}\n",
        spec.fn_name,
        outcome(spec, &[], Mode::Correct)
    ));
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let pool: Vec<String> = POOL.iter().map(|s| format!("{s:?}")).collect();
    format!(
        "use task::{{parse_item, ItemError, {name}}};\n\n\
         {check}\n\
         fn reference(items: &[&str]) -> {ty} {{\n{body}}}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let pool: [&str; {n}] = [{pool}];\n\
         \x20   let mut state: u64 = 0xC011_ED00_0000_0048;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 9) as usize;\n\
         \x20       let items: Vec<&str> = (0..len).map(|_| pool[(next() % {n}) as usize]).collect();\n\
         \x20       assert_eq!({name}(&items), reference(&items), \"{{items:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        check = check_src(spec.rule),
        ty = out_ty(spec.policy),
        body = body_src(spec.policy),
        n = POOL.len(),
        pool = pool.join(", "),
    )
}

/// Degenerate: the policy's empty value.
fn empty_baseline(spec: &Spec) -> String {
    let value = match spec.policy {
        Policy::FailFast => "Ok(vec![])",
        Policy::Partition => "(vec![], vec![])",
        Policy::AllOrNothing => "Ok(0)",
        Policy::FirstOk => "Err(ItemError::Bad(String::new()))",
    };
    format!(
        "{PRELUDE}\npub fn {name}(items: &[&str]) -> {ty} {{\n    let _ = items;\n    {value}\n}}\n",
        name = spec.fn_name,
        ty = out_ty(spec.policy),
    )
}

/// Degenerate: ignores the rule and drops every failure.
fn skip_bad(spec: &Spec) -> String {
    let body = match spec.policy {
        Policy::FailFast => "    Ok(items.iter().filter_map(|s| parse_item(s).ok()).collect())\n",
        Policy::Partition => {
            "    (items.iter().filter_map(|s| parse_item(s).ok()).collect(), Vec::new())\n"
        }
        Policy::AllOrNothing => "    Ok(items.iter().filter_map(|s| parse_item(s).ok()).sum())\n",
        Policy::FirstOk => {
            "    match items.iter().find_map(|s| parse_item(s).ok()) {\n\
             \x20       Some(v) => Ok(v),\n\
             \x20       None => Err(ItemError::Bad(String::new())),\n\
             \x20   }\n"
        }
    };
    format!(
        "{PRELUDE}\npub fn {name}(items: &[&str]) -> {ty} {{\n{body}}}\n",
        name = spec.fn_name,
        ty = out_ty(spec.policy),
    )
}

pub struct ResultCollectFamily;

impl Generator for ResultCollectFamily {
    fn id(&self) -> &str {
        "result-collect"
    }
    fn category(&self) -> &str {
        "error-handling"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("result-collect", seed);

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
            id: format!("result-collect/{seed:016x}"),
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
            // The prompt forbids `unwrap`/`expect`, as `error-handling` does (docs/04).
            forbidden_paths: vec!["unwrap".to_string(), "expect".to_string()],
            check_clippy: false,
            clippy_allow: Vec::new(),
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
            ("empty".to_string(), empty_baseline(&spec)),
            ("skip-bad".to_string(), skip_bad(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let policy = match spec.policy {
            Policy::FailFast => "fail_fast",
            Policy::Partition => "partition",
            Policy::AllOrNothing => "all_or_nothing",
            Policy::FirstOk => "first_ok",
        };
        let rule = match spec.rule {
            Rule::Positive => "positive",
            Rule::Even => "even",
            Rule::AtMost(_) => "at_most",
        };
        vec![format!("policy:{policy}"), format!("rule:{rule}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICIES: [Policy; 4] = [
        Policy::FailFast,
        Policy::Partition,
        Policy::AllOrNothing,
        Policy::FirstOk,
    ];

    fn spec(policy: Policy, rule: Rule) -> Spec {
        Spec {
            policy,
            rule,
            fn_name: "f",
        }
    }

    fn refs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    #[test]
    fn generation_is_deterministic() {
        let g = ResultCollectFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn outcome_matches_intent_for_each_policy() {
        let items = ["12", "oops", "-4", "7"];
        let ff = spec(Policy::FailFast, Rule::Positive);
        assert_eq!(
            outcome(&ff, &items, Mode::Correct),
            "Err(ItemError::Bad(\"oops\".to_string()))"
        );
        assert_eq!(outcome(&ff, &["12", "7"], Mode::Correct), "Ok(vec![12, 7])");
        let p = spec(Policy::Partition, Rule::Positive);
        assert_eq!(
            outcome(&p, &items, Mode::Correct),
            "(vec![12, 7], vec![ItemError::Bad(\"oops\".to_string()), ItemError::Rule(-4)])"
        );
        let a = spec(Policy::AllOrNothing, Rule::Positive);
        assert_eq!(outcome(&a, &["12", "7"], Mode::Correct), "Ok(19)");
        assert_eq!(
            outcome(&a, &items, Mode::Correct),
            "Err(vec![ItemError::Bad(\"oops\".to_string()), ItemError::Rule(-4)])"
        );
        let f = spec(Policy::FirstOk, Rule::Even);
        assert_eq!(outcome(&f, &["oops", "7", "12"], Mode::Correct), "Ok(12)");
        // No success: the LAST error. Empty: Bad("").
        assert_eq!(
            outcome(&f, &["oops", "7"], Mode::Correct),
            "Err(ItemError::Rule(7))"
        );
        assert_eq!(
            outcome(&f, &[], Mode::Correct),
            "Err(ItemError::Bad(String::new()))"
        );
    }

    #[test]
    fn parse_pads_and_signs_like_the_pinned_parser() {
        let r = Rule::Positive;
        assert_eq!(one(r, " 4 "), Ok(4));
        assert_eq!(one(r, "+8"), Ok(8));
        assert_eq!(one(r, "1.5"), Err(NE::Bad("1.5".to_string())));
        // The Bad payload is the ORIGINAL token (padding preserved), not the trimmed one.
        assert_eq!(one(r, " x "), Err(NE::Bad(" x ".to_string())));
    }

    #[test]
    fn canonical_defeats_both_baselines_under_every_policy_and_rule() {
        for &policy in &POLICIES {
            for rule in [
                Rule::Positive,
                Rule::Even,
                Rule::AtMost(30),
                Rule::AtMost(60),
            ] {
                let s = spec(policy, rule);
                let c = canonical(rule);
                let items = refs(&c);
                let correct = outcome(&s, &items, Mode::Correct);
                assert_ne!(
                    correct,
                    outcome(&s, &items, Mode::Empty),
                    "{policy:?}/{rule:?}: empty"
                );
                assert_ne!(
                    correct,
                    outcome(&s, &items, Mode::SkipBad),
                    "{policy:?}/{rule:?}: skip-bad"
                );
            }
        }
    }

    #[test]
    fn canonical_has_the_required_ingredients() {
        for rule in [
            Rule::Positive,
            Rule::Even,
            Rule::AtMost(30),
            Rule::AtMost(60),
        ] {
            let c = canonical(rule);
            let rs: Vec<_> = c.iter().map(|s| one(rule, s)).collect();
            assert!(
                rs.iter().any(|r| matches!(r, Err(NE::Bad(_)))),
                "{rule:?}: no Bad"
            );
            assert!(
                rs.iter().any(|r| matches!(r, Err(NE::Rule(_)))),
                "{rule:?}: no Rule"
            );
            assert!(
                rs.iter().filter(|r| r.is_ok()).count() >= 2,
                "{rule:?}: <2 ok"
            );
            // The first parseable value breaks the rule.
            let first_parsed = c.iter().find_map(|s| s.trim().parse::<i64>().ok()).unwrap();
            assert!(
                !rule_ok(rule, first_parsed),
                "{rule:?}: first parsed value passes"
            );
        }
    }

    #[test]
    fn rule_bound_is_in_the_documented_range() {
        for seed in 0..200u64 {
            if let Rule::AtMost(b) = sample(seed).rule {
                assert!((30..=60).contains(&b));
            }
        }
    }

    #[test]
    fn seeds_vary_both_axes() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!(
                "{:?}/{}",
                s.policy,
                ResultCollectFamily.spec_signature(seed)[1]
            ));
        }
        assert_eq!(variants.len(), 12);
    }

    #[test]
    fn unwrap_and_expect_are_forbidden_and_canary_present() {
        let t = ResultCollectFamily.generate(3);
        assert!(t.forbidden_paths.contains(&"unwrap".to_string()));
        assert!(t.prompt.contains(&t.canary));
    }
}

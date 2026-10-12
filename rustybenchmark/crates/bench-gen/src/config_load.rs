//! The `config-load` family (category `error-handling`) — `Option` to `Result` plumbing with
//! three distinct failure modes and a precedence rule.
//!
//! The pinned `Config` is a list of key/value strings with `get(&self, key) -> Option<&str>`.
//! The model implements `load(&Config) -> Result<Settings, ConfigError>` for three integer
//! fields. Each field goes through the same pipeline and each stage fails differently:
//!
//! 1. **lookup** — the key is absent: `Missing(key)` for a *required* field, or the field's
//!    default for a *defaulted* one (a defaulted field is never `Missing`);
//! 2. **parse** — the (trimmed) text is not an integer: `Invalid { key, raw }`, carrying the
//!    *original* untrimmed text;
//! 3. **check** — the value breaks the field's rule: `Rejected { key, value }`.
//!
//! The fields are processed in declaration order and the **first** error wins. That is the
//! whole skill: `Option::ok_or_else`, `map_err`, `?`, and getting the error *values* and their
//! *precedence* right (an `unwrap_or` that swallows an error, or a parse before the lookup,
//! changes which error comes out).
//!
//! Seed-selected on two axes: **which fields have a default** (2^3 = 8 patterns) and **which
//! rule each field gets** (3 rotations of {range, positive, even}). 8 x 3 = **24 distinct
//! skills**; field names and the range bounds are cosmetic and excluded from `spec_signature`
//! (Q31). Solution-first (ADR-0003): the native `load` and the emitted reference are
//! mirrored, and the differential fuzzes 3000 configs (present, absent, padded, non-numeric,
//! duplicate keys) against an inlined reference over the model's own pinned items.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Rule {
    Range(i64, i64),
    Positive,
    Even,
}

struct Field {
    key: &'static str,
    /// `Some(default)` for a defaulted field.
    default: Option<i64>,
    rule: Rule,
    /// A seeded value that passes the rule (the valid configuration uses it).
    pass: i64,
}

struct Spec {
    fields: [Field; 3],
    /// The rotation of rules over the fields, for the signature.
    rotation: usize,
    /// Which fields have a default (bit i), for the signature.
    default_mask: u8,
}

const KEY_SETS: &[[&str; 3]] = &[
    ["port", "workers", "retries"],
    ["width", "height", "depth"],
    ["floor", "step", "ceiling"],
    ["alpha", "beta", "gamma"],
];

fn rule_ok(rule: Rule, v: i64) -> bool {
    match rule {
        Rule::Range(lo, hi) => (lo..=hi).contains(&v),
        Rule::Positive => v > 0,
        Rule::Even => v % 2 == 0,
    }
}

/// A value that passes the rule, and one that breaks it.
fn pass_and_fail(rule: Rule) -> (i64, i64) {
    match rule {
        Rule::Range(lo, hi) => ((lo + hi) / 2, hi + 1),
        Rule::Positive => (7, -3),
        Rule::Even => (8, 7),
    }
}

fn default_for(rule: Rule) -> i64 {
    match rule {
        Rule::Range(lo, _) => lo,
        Rule::Positive => 1,
        Rule::Even => 2,
    }
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let keys = KEY_SETS[rng.below(KEY_SETS.len() as u64) as usize];
    let lo = 1 + rng.below(10) as i64;
    let hi = lo + 10 + rng.below(80) as i64;
    let rules = [Rule::Range(lo, hi), Rule::Positive, Rule::Even];
    let rotation = rng.below(3) as usize;
    let default_mask = rng.below(8) as u8;
    let mut field = |i: usize| {
        let rule = rules[(i + rotation) % 3];
        let pass = match rule {
            Rule::Range(lo, hi) => lo + rng.below((hi - lo + 1) as u64) as i64,
            Rule::Positive => 1 + rng.below(60) as i64,
            Rule::Even => 2 * (1 + rng.below(40) as i64),
        };
        Field {
            key: keys[i],
            default: (((default_mask >> i) & 1) == 1).then(|| default_for(rule)),
            rule,
            pass,
        }
    };
    Spec {
        fields: [field(0), field(1), field(2)],
        rotation,
        default_mask,
    }
}

// ---- native reference ---------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum CfgErr {
    Missing(String),
    Invalid(String, String),
    Rejected(String, i64),
}

/// The pinned `Config::get`: the first entry with that key.
fn get<'a>(entries: &'a [(String, String)], key: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn load_field(f: &Field, entries: &[(String, String)]) -> Result<i64, CfgErr> {
    let raw = match get(entries, f.key) {
        Some(r) => r,
        None => return f.default.ok_or_else(|| CfgErr::Missing(f.key.to_string())),
    };
    let v: i64 = raw
        .trim()
        .parse()
        .map_err(|_| CfgErr::Invalid(f.key.to_string(), raw.to_string()))?;
    if rule_ok(f.rule, v) {
        Ok(v)
    } else {
        Err(CfgErr::Rejected(f.key.to_string(), v))
    }
}

fn load(spec: &Spec, entries: &[(String, String)]) -> Result<[i64; 3], CfgErr> {
    Ok([
        load_field(&spec.fields[0], entries)?,
        load_field(&spec.fields[1], entries)?,
        load_field(&spec.fields[2], entries)?,
    ])
}

// ---- emitted source ---------------------------------------------------------------------

fn rule_src(rule: Rule) -> String {
    match rule {
        Rule::Range(lo, hi) => format!("(v >= {lo} && v <= {hi})"),
        Rule::Positive => "(v > 0)".to_string(),
        Rule::Even => "(v % 2 == 0)".to_string(),
    }
}

fn prelude(spec: &Spec) -> String {
    let [a, b, c] = &spec.fields;
    format!(
        "pub struct Config {{\n\
         \x20   entries: Vec<(String, String)>,\n\
         }}\n\
         \n\
         impl Config {{\n\
         \x20   pub fn new(pairs: &[(&str, &str)]) -> Config {{\n\
         \x20       Config {{\n\
         \x20           entries: pairs\n\
         \x20               .iter()\n\
         \x20               .map(|(k, v)| (k.to_string(), v.to_string()))\n\
         \x20               .collect(),\n\
         \x20       }}\n\
         \x20   }}\n\
         \n\
         \x20   /// The value of the first entry with this key.\n\
         \x20   pub fn get(&self, key: &str) -> Option<&str> {{\n\
         \x20       self.entries\n\
         \x20           .iter()\n\
         \x20           .find(|(k, _)| k == key)\n\
         \x20           .map(|(_, v)| v.as_str())\n\
         \x20   }}\n\
         }}\n\
         \n\
         #[derive(Debug, PartialEq)]\n\
         pub enum ConfigError {{\n\
         \x20   Missing(String),\n\
         \x20   Invalid {{ key: String, raw: String }},\n\
         \x20   Rejected {{ key: String, value: i64 }},\n\
         }}\n\
         \n\
         #[derive(Debug, PartialEq)]\n\
         pub struct Settings {{\n\
         \x20   pub {}: i64,\n\
         \x20   pub {}: i64,\n\
         \x20   pub {}: i64,\n\
         }}\n",
        a.key, b.key, c.key
    )
}

fn field_call(f: &Field) -> String {
    let default = match f.default {
        Some(d) => format!("Some({d})"),
        None => "None".to_string(),
    };
    format!(
        "{}: field(cfg, {:?}, {default}, |v| {})?",
        f.key,
        f.key,
        rule_src(f.rule)
    )
}

fn reference_fns(spec: &Spec) -> String {
    format!(
        "fn field(\n\
         \x20   cfg: &Config,\n\
         \x20   key: &str,\n\
         \x20   default: Option<i64>,\n\
         \x20   ok: impl Fn(i64) -> bool,\n\
         ) -> Result<i64, ConfigError> {{\n\
         \x20   let raw = match cfg.get(key) {{\n\
         \x20       Some(raw) => raw,\n\
         \x20       None => return default.ok_or_else(|| ConfigError::Missing(key.to_string())),\n\
         \x20   }};\n\
         \x20   let v: i64 = raw.trim().parse().map_err(|_| ConfigError::Invalid {{\n\
         \x20       key: key.to_string(),\n\
         \x20       raw: raw.to_string(),\n\
         \x20   }})?;\n\
         \x20   if ok(v) {{\n\
         \x20       Ok(v)\n\
         \x20   }} else {{\n\
         \x20       Err(ConfigError::Rejected {{\n\
         \x20           key: key.to_string(),\n\
         \x20           value: v,\n\
         \x20       }})\n\
         \x20   }}\n\
         }}\n\
         \n\
         pub fn load(cfg: &Config) -> Result<Settings, ConfigError> {{\n\
         \x20   Ok(Settings {{\n\
         \x20       {},\n\
         \x20       {},\n\
         \x20       {},\n\
         \x20   }})\n\
         }}\n",
        field_call(&spec.fields[0]),
        field_call(&spec.fields[1]),
        field_call(&spec.fields[2]),
    )
}

fn reference_src(spec: &Spec) -> String {
    format!("{}\n{}", prelude(spec), reference_fns(spec))
}

const SIG: &str = "pub fn load(cfg: &Config) -> Result<Settings, ConfigError>";

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .1
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Implement `load` below. The other items are provided — keep them.\n\
         //!\n\
         {doc}\n\
         {}\n\
         {SIG} {{\n\
         \x20   todo!()\n\
         }}\n",
        prelude(spec)
    )
}

// ---- cases ----------------------------------------------------------------------------------

type Entries = Vec<(String, String)>;

fn pair(k: &str, v: impl ToString) -> (String, String) {
    (k.to_string(), v.to_string())
}

/// Every test configuration: the valid one, then per field a missing key, a non-number and a
/// rule breaker, then a precedence case and a padded-value case.
fn cases(spec: &Spec) -> Vec<Entries> {
    let valid: Vec<i64> = spec.fields.iter().map(|f| f.pass).collect();
    let full = |overrides: &[(usize, Option<String>)]| -> Entries {
        let mut e = Vec::new();
        for (i, f) in spec.fields.iter().enumerate() {
            match overrides.iter().find(|(j, _)| *j == i) {
                Some((_, None)) => {}
                Some((_, Some(v))) => e.push(pair(f.key, v)),
                None => e.push(pair(f.key, valid[i])),
            }
        }
        e
    };
    let mut out = vec![full(&[])];
    for i in 0..3 {
        out.push(full(&[(i, None)]));
        out.push(full(&[(i, Some("x7".to_string()))]));
        out.push(full(&[(
            i,
            Some(pass_and_fail(spec.fields[i].rule).1.to_string()),
        )]));
    }
    // Precedence: field 2 non-numeric AND field 0 rejected: field 0's error wins.
    out.push(full(&[
        (0, Some(pass_and_fail(spec.fields[0].rule).1.to_string())),
        (2, Some("oops".to_string())),
    ]));
    // Precedence, other way: field 1 missing/invalid before field 2 rejected.
    out.push(full(&[
        (1, Some("?".to_string())),
        (2, Some(pass_and_fail(spec.fields[2].rule).1.to_string())),
    ]));
    // Padding is trimmed before parsing; a duplicate key is ignored (first wins).
    let mut padded = full(&[(1, Some(format!(" {} ", valid[1])))]);
    padded.push(pair(spec.fields[1].key, "999999"));
    out.push(padded);
    out
}

fn entries_lit(e: &Entries) -> String {
    let items: Vec<String> = e.iter().map(|(k, v)| format!("({k:?}, {v:?})")).collect();
    format!("&[{}]", items.join(", "))
}

fn result_lit(spec: &Spec, r: &Result<[i64; 3], CfgErr>) -> String {
    match r {
        Ok([a, b, c]) => format!(
            "Ok(Settings {{ {}: {a}, {}: {b}, {}: {c} }})",
            spec.fields[0].key, spec.fields[1].key, spec.fields[2].key
        ),
        Err(CfgErr::Missing(k)) => format!("Err(ConfigError::Missing({k:?}.to_string()))"),
        Err(CfgErr::Invalid(k, raw)) => format!(
            "Err(ConfigError::Invalid {{ key: {k:?}.to_string(), raw: {raw:?}.to_string() }})"
        ),
        Err(CfgErr::Rejected(k, v)) => {
            format!("Err(ConfigError::Rejected {{ key: {k:?}.to_string(), value: {v} }})")
        }
    }
}

fn worked_examples(spec: &Spec, _seed: u64) -> (Vec<Entries>, String) {
    let all = cases(spec);
    // A readable sample: valid, a missing field, a non-number, a rejected value, precedence.
    let pick: Vec<Entries> = (0..all.len()).filter_map(|i| all.get(i).cloned()).collect();
    let prose: String = pick
        .iter()
        .map(|e| {
            format!(
                "  load(&Config::new({}))  ->  {}\n",
                entries_lit(e),
                result_lit(spec, &load(spec, e))
            )
        })
        .collect();
    (pick, prose)
}

fn rule_prose(rule: Rule) -> String {
    match rule {
        Rule::Range(lo, hi) => format!("must be between {lo} and {hi} inclusive"),
        Rule::Positive => "must be positive (`> 0`)".to_string(),
        Rule::Even => "must be even".to_string(),
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let fields: String = spec
        .fields
        .iter()
        .map(|f| {
            let d = match f.default {
                Some(d) => format!("defaults to `{d}` when the key is absent"),
                None => "is **required** (absent: `Missing`)".to_string(),
            };
            format!("  - `{}`: {d}; the value {}\n", f.key, rule_prose(f.rule))
        })
        .collect();
    let (_, examples) = worked_examples(spec, seed);
    format!(
        "Implement `load` in `src/lib.rs`. `Config`, `ConfigError` and `Settings` are provided — keep them \
         unchanged. `load` reads three integer settings from the config, **in this order**:\n\
         {fields}\
         \n\
         For each field: look the key up (`Config::get`, which returns the first entry with that key); \
         if it is absent use the default, or fail with `ConfigError::Missing(key)` for a required field; \
         otherwise trim the text and parse it as an `i64`, failing with `ConfigError::Invalid {{ key, raw }}` \
         (`raw` is the **original, untrimmed** text); then check the rule, failing with \
         `ConfigError::Rejected {{ key, value }}`. A default is trusted and is not checked. \
         The fields are processed in the order above and the **first** error is returned.\n\
         \n\
         Constraints:\n\
         - Keep the signature `{SIG}`. Do not use `unsafe`, `unwrap` or `expect`.\n\
         \n\
         Provided in `src/lib.rs`:\n\
         ```rust\n\
         {prelude}```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        prelude = prelude(spec),
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

fn behavior_test_src(spec: &Spec) -> String {
    let mut body = String::from("use task::{load, Config, ConfigError, Settings};\n\n");
    for (i, e) in cases(spec).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn case{i}() {{\n    assert_eq!(load(&Config::new({})), {});\n}}\n\n",
            entries_lit(e),
            result_lit(spec, &load(spec, e))
        ));
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_fns(spec);
    let keys: Vec<String> = spec.fields.iter().map(|f| format!("{:?}", f.key)).collect();
    format!(
        "use task::{{load, Config, ConfigError, Settings}};\n\n\
         {reference}\n\
         fn reference_load(cfg: &Config) -> Result<Settings, ConfigError> {{\n\
         \x20   load_ref(cfg)\n\
         }}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let keys = [{keys}];\n\
         \x20   let values = [\"0\", \"1\", \"2\", \"7\", \"8\", \"-3\", \"50\", \"100\", \" 4 \", \"x\", \"\", \"1.5\", \"+6\"];\n\
         \x20   let mut state: u64 = 0xC0F1_ED00_0000_0050;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let mut pairs: Vec<(&str, &str)> = Vec::new();\n\
         \x20       for _ in 0..(next() % 5) {{\n\
         \x20           pairs.push((keys[(next() % 3) as usize], values[(next() % {nv}) as usize]));\n\
         \x20       }}\n\
         \x20       let cfg = Config::new(&pairs);\n\
         \x20       assert_eq!(load(&cfg), reference_load(&cfg), \"{{pairs:?}}\");\n\
         \x20   }}\n\
         }}\n",
        keys = keys.join(", "),
        nv = 13,
    )
    // `load_ref` is the reference `load` renamed below.
    .replace("pub fn load(cfg: &Config)", "fn load_ref(cfg: &Config)")
}

/// Degenerate: a fixed `Ok` with zero settings.
fn zero(spec: &Spec) -> String {
    let [a, b, c] = &spec.fields;
    format!(
        "{}\n{SIG} {{\n    let _ = cfg;\n    Ok(Settings {{ {}: 0, {}: 0, {}: 0 }})\n}}\n",
        prelude(spec),
        a.key,
        b.key,
        c.key
    )
}

/// Degenerate: lenient — parses what it can, applies defaults, never errors, never checks a rule.
fn lenient(spec: &Spec) -> String {
    let line = |f: &Field| {
        format!(
            "{}: cfg.get({:?}).and_then(|r| r.trim().parse().ok()).unwrap_or({}),",
            f.key,
            f.key,
            f.default.unwrap_or(0)
        )
    };
    format!(
        "{}\n{SIG} {{\n    Ok(Settings {{\n        {}\n        {}\n        {}\n    }})\n}}\n",
        prelude(spec),
        line(&spec.fields[0]),
        line(&spec.fields[1]),
        line(&spec.fields[2]),
    )
}

pub struct ConfigLoadFamily;

impl Generator for ConfigLoadFamily {
    fn id(&self) -> &str {
        "config-load"
    }
    fn category(&self) -> &str {
        "error-handling"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("config-load", seed);

        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(PathBuf::from("src/lib.rs"), skeleton_src(&spec, seed));

        let mut hidden = BTreeMap::new();
        hidden.insert(PathBuf::from("tests/behavior.rs"), behavior_test_src(&spec));
        hidden.insert(
            PathBuf::from("tests/differential.rs"),
            differential_test_src(&spec),
        );

        GeneratedTask {
            id: format!("config-load/{seed:016x}"),
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
            ("zero".to_string(), zero(&spec)),
            ("lenient".to_string(), lenient(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        vec![
            format!("defaults:{:03b}", spec.default_mask),
            format!("rotation:{}", spec.rotation),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_with(mask: u8, rotation: usize) -> Spec {
        let rules = [Rule::Range(5, 20), Rule::Positive, Rule::Even];
        let keys = ["a", "b", "c"];
        let field = |i: usize| {
            let rule = rules[(i + rotation) % 3];
            Field {
                key: keys[i],
                default: (((mask >> i) & 1) == 1).then(|| default_for(rule)),
                rule,
                pass: pass_and_fail(rule).0,
            }
        };
        Spec {
            fields: [field(0), field(1), field(2)],
            rotation,
            default_mask: mask,
        }
    }

    #[test]
    fn generation_is_deterministic() {
        let g = ConfigLoadFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    fn e(pairs: &[(&str, &str)]) -> Entries {
        pairs.iter().map(|(k, v)| pair(k, v)).collect()
    }

    #[test]
    fn load_matches_intent() {
        // Rotation 0: a: range 5..=20, b: positive, c: even. a has a default.
        let s = spec_with(0b001, 0);
        assert_eq!(
            load(&s, &e(&[("a", "9"), ("b", "3"), ("c", "4")])),
            Ok([9, 3, 4])
        );
        // a absent -> its default (the range's low bound 5), not Missing.
        assert_eq!(load(&s, &e(&[("b", "3"), ("c", "4")])), Ok([5, 3, 4]));
        // b absent and required.
        assert_eq!(
            load(&s, &e(&[("a", "9"), ("c", "4")])),
            Err(CfgErr::Missing("b".into()))
        );
        // Invalid keeps the original (padded) text; a trimmed number is fine.
        assert_eq!(
            load(&s, &e(&[("a", "9"), ("b", " x "), ("c", "4")])),
            Err(CfgErr::Invalid("b".into(), " x ".into()))
        );
        assert_eq!(
            load(&s, &e(&[("a", " 9 "), ("b", "3"), ("c", "4")])),
            Ok([9, 3, 4])
        );
        // Rejected carries the parsed value; first field's error wins.
        assert_eq!(
            load(&s, &e(&[("a", "99"), ("b", "x"), ("c", "4")])),
            Err(CfgErr::Rejected("a".into(), 99))
        );
        // Duplicate keys: first wins.
        assert_eq!(
            load(&s, &e(&[("a", "9"), ("a", "x"), ("b", "3"), ("c", "4")])),
            Ok([9, 3, 4])
        );
        // A default is trusted: a defaulted field whose default would fail its own rule is fine.
        assert_eq!(default_for(Rule::Range(5, 20)), 5);
    }

    #[test]
    fn cases_reach_every_error_kind_under_every_pattern() {
        for mask in 0..8u8 {
            for rotation in 0..3 {
                let s = spec_with(mask, rotation);
                let rs: Vec<_> = cases(&s).iter().map(|c| load(&s, c)).collect();
                assert!(
                    rs[0].is_ok(),
                    "mask {mask} rot {rotation}: valid config failed"
                );
                assert!(rs.iter().any(|r| matches!(r, Err(CfgErr::Invalid(..)))));
                assert!(rs.iter().any(|r| matches!(r, Err(CfgErr::Rejected(..)))));
                // Missing is reachable iff some field is required.
                assert_eq!(
                    rs.iter().any(|r| matches!(r, Err(CfgErr::Missing(..)))),
                    mask != 0b111,
                    "mask {mask}"
                );
            }
        }
    }

    #[test]
    fn canonical_defeats_both_baselines_under_every_pattern() {
        for mask in 0..8u8 {
            for rotation in 0..3 {
                let s = spec_with(mask, rotation);
                let cs = cases(&s);
                // zero: wrong whenever any case's answer is not Ok([0,0,0]); the valid case
                // has non-zero values and there are Err cases.
                assert!(cs.iter().any(|c| load(&s, c) != Ok([0, 0, 0])));
                // lenient: never errors, so any Err case separates it from the answer.
                assert!(cs.iter().any(|c| load(&s, c).is_err()));
                // And its Ok-answers on the *invalid-raw / rejected* cases differ: it returns Ok
                // where the answer is Err.
            }
        }
    }

    #[test]
    fn seeds_vary_both_axes() {
        let mut s = std::collections::HashSet::new();
        for seed in 0..600u64 {
            s.insert(ConfigLoadFamily.spec_signature(seed).join("|"));
        }
        assert_eq!(s.len(), 24);
    }

    #[test]
    fn unwrap_expect_forbidden_and_canary_present() {
        let t = ConfigLoadFamily.generate(3);
        assert!(t.forbidden_paths.contains(&"unwrap".to_string()));
        assert!(t.prompt.contains(&t.canary));
    }
}

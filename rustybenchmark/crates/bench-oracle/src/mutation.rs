//! L4 mutation: a deterministic, source-level mutator and a sandboxed survival check
//! (docs/03 §L4).
//!
//! # What this is, and what it is deliberately not
//!
//! docs/03 names `cargo-mutants`, which is not installed here and which docs/03 itself calls
//! non-deterministic (so L4 is "not replay-verifiable" and stays T0 confidence). This module is a
//! **minimal replacement for the part that is well defined**: the `test-authoring` reading —
//! *did the model's tests kill the mutants of the reference implementation?* — with these
//! properties the tool it replaces lacks:
//!
//! * **Deterministic.** Mutants are enumerated in source order from a fixed operator table;
//!   bounding a run (`max_mutants`) is deterministic stride sampling, never random.
//! * **Bounded.** A cap on mutants and a harness-owned wall-clock limit per step.
//! * **Contained.** Every compile and every test run goes through `bench-sandbox` (network
//!   denied, writes confined to the workspace, process-group wall-clock kill). A mutant that
//!   loops forever is killed by the wall clock and counted as killed, the cargo-mutants rule.
//! * **Equivalent-mutant aware** ([`mutation_score`]). A mutant the *reference* (hidden) tests
//!   cannot kill is either equivalent to the original or untested by the oracle; either way the
//!   model cannot be blamed for not killing it, so it is excluded from the denominator and
//!   reported separately instead of silently lowering the score.
//!
//! What it does **not** do — recorded as open in OPEN-QUESTIONS Q33 rather than guessed:
//! the other reading in docs/03 ("for other categories it measures whether the solution is
//! meaningfully specified") scores the *oracle's* weakness, not the model, and is not built;
//! no scoring weight is applied and nothing here feeds `OracleVector` (Q28 keeps quality out of
//! the pass predicate and no `test-authoring` family exists yet to supply model-authored tests).

use bench_sandbox::{Limits, Policy};
use proc_macro2::Span;
use std::path::Path;
use std::time::Duration;
use syn::spanned::Spanned;
use syn::visit::Visit;

/// One source edit: replace `start..end` of the original text with `replacement`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mutant {
    /// Index in canonical (source) order, stable for a given source text.
    pub id: usize,
    /// `binop`, `compare`, `logic`, `assign`, `bool-literal`, `not`, `fn-body`.
    pub kind: &'static str,
    /// 1-based line and 0-based column (chars) of the edit.
    pub line: u32,
    pub col: u32,
    pub from: String,
    pub to: String,
    /// Enclosing function, when there is one.
    pub function: Option<String>,
    start: usize,
    end: usize,
}

impl Mutant {
    /// `src/lib.rs:12:9 compare in clamp: < -> <=` style description (no source text beyond the
    /// replaced token).
    pub fn describe(&self) -> String {
        format!(
            "{}:{} {}{}: `{}` -> `{}`",
            self.line,
            self.col,
            self.kind,
            self.function
                .as_deref()
                .map(|f| format!(" in {f}"))
                .unwrap_or_default(),
            self.from,
            self.to
        )
    }
}

/// Byte offset of a (1-based line, 0-based char column) position.
fn offset(src: &str, line_starts: &[usize], line: usize, col: usize) -> Option<usize> {
    let ls = *line_starts.get(line.checked_sub(1)?)?;
    let rest = &src[ls..];
    let mut chars = rest.char_indices();
    match chars.nth(col) {
        Some((i, _)) => Some(ls + i),
        None if rest.chars().count() == col => Some(src.len().min(ls + rest.len())),
        None => None,
    }
}

struct Collector<'a> {
    src: &'a str,
    line_starts: Vec<usize>,
    out: Vec<Mutant>,
    fns: Vec<String>,
}

fn is_test_attr(a: &syn::Attribute) -> bool {
    if a.path().is_ident("test") {
        return true;
    }
    if let syn::Meta::List(l) = &a.meta {
        return l.path.is_ident("cfg") && l.tokens.to_string().contains("test");
    }
    false
}

fn int_type(ty: &syn::Type) -> Option<&'static str> {
    let syn::Type::Path(p) = ty else { return None };
    let id = p.path.get_ident()?.to_string();
    match id.as_str() {
        "bool" => Some("bool"),
        "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128"
        | "isize" => Some("int"),
        _ => None,
    }
}

impl Collector<'_> {
    fn range(&self, span: Span) -> Option<(usize, usize, u32, u32)> {
        let (s, e) = (span.start(), span.end());
        let a = offset(self.src, &self.line_starts, s.line, s.column)?;
        let b = offset(self.src, &self.line_starts, e.line, e.column)?;
        (a < b).then_some((a, b, s.line as u32, s.column as u32))
    }

    fn push(&mut self, kind: &'static str, span: Span, to: &str) {
        if let Some((a, b, line, col)) = self.range(span) {
            self.out.push(Mutant {
                id: 0,
                kind,
                line,
                col,
                from: self.src[a..b].to_string(),
                to: to.to_string(),
                function: self.fns.last().cloned(),
                start: a,
                end: b,
            });
        }
    }

    fn fn_body(&mut self, name: &str, sig: &syn::Signature, block: &syn::Block) {
        if name == "main" || sig.constness.is_some() {
            return;
        }
        let values: &[&str] = match &sig.output {
            syn::ReturnType::Default => &["()"],
            syn::ReturnType::Type(_, ty) => match int_type(ty) {
                Some("bool") => &["true", "false"],
                Some(_) => &["0", "1"],
                None => return,
            },
        };
        let span = block.brace_token.span.join();
        let Some((a, b, line, col)) = self.range(span) else {
            return;
        };
        let original = self.src[a..b].to_string();
        let squashed: String = original.chars().filter(|c| !c.is_whitespace()).collect();
        for v in values {
            // Skip a replacement identical to what the body already is.
            if squashed == format!("{{{v}}}") || (*v == "()" && squashed == "{}") {
                continue;
            }
            self.out.push(Mutant {
                id: 0,
                kind: "fn-body",
                line,
                col,
                from: if original.chars().count() > 40 {
                    "{ ... }".to_string()
                } else {
                    original.split_whitespace().collect::<Vec<_>>().join(" ")
                },
                to: format!("{{ {v} }}"),
                function: Some(name.to_string()),
                start: a,
                end: b,
            });
        }
    }
}

impl<'ast> Visit<'ast> for Collector<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if f.attrs.iter().any(is_test_attr) {
            return;
        }
        let name = f.sig.ident.to_string();
        self.fn_body(&name, &f.sig, &f.block);
        self.fns.push(name);
        syn::visit::visit_item_fn(self, f);
        self.fns.pop();
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if f.attrs.iter().any(is_test_attr) {
            return;
        }
        let name = f.sig.ident.to_string();
        self.fn_body(&name, &f.sig, &f.block);
        self.fns.push(name);
        syn::visit::visit_impl_item_fn(self, f);
        self.fns.pop();
    }

    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if m.attrs.iter().any(is_test_attr) {
            return;
        }
        syn::visit::visit_item_mod(self, m);
    }

    fn visit_expr_binary(&mut self, e: &'ast syn::ExprBinary) {
        use syn::BinOp::*;
        let span = e.op.span();
        let (kind, to): (&'static str, &[&str]) = match e.op {
            Add(_) => ("binop", &["-", "*"]),
            Sub(_) => ("binop", &["+", "/"]),
            Mul(_) => ("binop", &["+", "/"]),
            Div(_) => ("binop", &["%", "*"]),
            Lt(_) => ("compare", &["<=", ">"]),
            Le(_) => ("compare", &["<", ">"]),
            Gt(_) => ("compare", &[">=", "<"]),
            Ge(_) => ("compare", &[">", "<"]),
            Eq(_) => ("compare", &["!="]),
            Ne(_) => ("compare", &["=="]),
            And(_) => ("logic", &["||"]),
            Or(_) => ("logic", &["&&"]),
            AddAssign(_) => ("assign", &["-="]),
            SubAssign(_) => ("assign", &["+="]),
            MulAssign(_) => ("assign", &["+="]),
            _ => ("", &[]),
        };
        for t in to {
            self.push(kind, span, t);
        }
        syn::visit::visit_expr_binary(self, e);
    }

    fn visit_expr_lit(&mut self, e: &'ast syn::ExprLit) {
        if let syn::Lit::Bool(b) = &e.lit {
            self.push(
                "bool-literal",
                b.span(),
                if b.value { "false" } else { "true" },
            );
        }
        syn::visit::visit_expr_lit(self, e);
    }

    fn visit_expr_unary(&mut self, e: &'ast syn::ExprUnary) {
        if let syn::UnOp::Not(t) = &e.op {
            self.push("not", t.span(), "");
        }
        syn::visit::visit_expr_unary(self, e);
    }
}

/// Every mutant of `source`, in canonical order, with stable ids. `None` if `source` does not
/// parse as a Rust file.
pub fn enumerate(source: &str) -> Option<Vec<Mutant>> {
    let file = syn::parse_file(source).ok()?;
    let mut line_starts = vec![0usize];
    for (i, b) in source.bytes().enumerate() {
        if b == b'\n' {
            line_starts.push(i + 1);
        }
    }
    let mut c = Collector {
        src: source,
        line_starts,
        out: Vec::new(),
        fns: Vec::new(),
    };
    c.visit_file(&file);
    let mut v = c.out;
    v.sort_by(|a, b| (a.start, a.end, &a.to).cmp(&(b.start, b.end, &b.to)));
    v.dedup_by(|a, b| a.start == b.start && a.end == b.end && a.to == b.to);
    for (i, m) in v.iter_mut().enumerate() {
        m.id = i;
    }
    Some(v)
}

/// The mutated source text.
pub fn apply(source: &str, m: &Mutant) -> String {
    let mut s = String::with_capacity(source.len() + m.to.len());
    s.push_str(&source[..m.start]);
    s.push_str(&m.to);
    s.push_str(&source[m.end..]);
    s
}

/// Deterministic bound: at most `max` mutants, spread evenly over the source order.
pub fn select(all: &[Mutant], max: usize) -> Vec<Mutant> {
    if max == 0 {
        return Vec::new();
    }
    if all.len() <= max {
        return all.to_vec();
    }
    (0..max).map(|i| all[i * all.len() / max].clone()).collect()
}

// ---------------------------------------------------------------------------
// Running mutants
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The test target failed.
    Killed,
    /// The test target hit the wall-clock limit (counted as killed, the cargo-mutants rule).
    Timeout,
    /// The tests passed: the mutant survived.
    Survived,
    /// The mutant does not compile; it says nothing about the tests and is excluded.
    Unviable,
}

impl Verdict {
    pub fn is_kill(self) -> bool {
        matches!(self, Verdict::Killed | Verdict::Timeout)
    }
}

#[derive(Clone, Debug)]
pub struct MutationConfig {
    pub max_mutants: usize,
    /// Compile step limit (per mutant, per test target).
    pub compile_wall: Duration,
    /// Test-run step limit: the infinite-loop killer.
    pub run_wall: Duration,
}

impl Default for MutationConfig {
    fn default() -> Self {
        MutationConfig {
            max_mutants: 40,
            compile_wall: Duration::from_secs(120),
            run_wall: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MutationError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("the source does not parse, so it cannot be mutated")]
    Unparseable,
    #[error("the unmutated source does not pass the `{0}` tests, so mutants prove nothing")]
    BaselineFails(String),
}

/// Restores the original source however the run ends.
struct Restore<'a> {
    path: &'a Path,
    original: &'a str,
}
impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let _ = std::fs::write(self.path, self.original);
    }
}

fn policy(ws: &Path, wall: Duration) -> std::io::Result<Policy> {
    Ok(Policy::for_workspace(ws)?.with_limits(Limits {
        wall,
        ..Limits::default()
    }))
}

fn cargo(ws: &Path, wall: Duration, args: &[&str]) -> std::io::Result<bench_sandbox::Outcome> {
    // The target dir is pinned inside the workspace: it is the only place the sandbox lets the build
    // write, and an inherited `CARGO_TARGET_DIR` shared by two workspaces made one mutant's artifacts
    // stand in for another's (found by the first scoring runs: survivors that should have been
    // killed). Non-incremental so each mutant is compiled from the source it was given.
    let target_dir = ws.join("target");
    bench_sandbox::run(
        &policy(ws, wall)?,
        "cargo",
        args,
        &[
            ("CARGO_TERM_COLOR", "never"),
            ("CARGO_TARGET_DIR", &target_dir.to_string_lossy()),
            ("CARGO_INCREMENTAL", "0"),
        ],
    )
}

/// Compile the test target and return its executable path; `None` if it does not compile.
fn build_test_exe(
    ws: &Path,
    target: &str,
    cfg: &MutationConfig,
) -> std::io::Result<Option<String>> {
    let build = cargo(
        ws,
        cfg.compile_wall,
        &[
            "test",
            "--offline",
            "--no-run",
            "--test",
            target,
            "--message-format=json",
        ],
    )?;
    if !build.success() {
        return Ok(None);
    }
    for line in build.stdout.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v["reason"] == "compiler-artifact"
            && v["target"]["name"] == target
            && v["profile"]["test"] == true
        {
            if let Some(exe) = v["executable"].as_str() {
                return Ok(Some(exe.to_string()));
            }
        }
    }
    Ok(None)
}

/// Compile then run one test target against whatever `lib_rel` currently contains. The *run*
/// executes the built test binary directly (not `cargo test`), so the run wall-clock measures the
/// tests and not cargo's start-up, and a loaded machine does not turn a healthy mutant into a
/// timeout.
fn run_target(ws: &Path, target: &str, cfg: &MutationConfig) -> std::io::Result<Verdict> {
    let Some(exe) = build_test_exe(ws, target, cfg)? else {
        return Ok(Verdict::Unviable);
    };
    let run = bench_sandbox::run(
        &policy(ws, cfg.run_wall)?,
        &exe,
        &["--quiet", "--test-threads=1"],
        &[
            ("CARGO_TERM_COLOR", "never"),
            ("CARGO_MANIFEST_DIR", &ws.to_string_lossy()),
        ],
    )?;
    Ok(if run.timed_out {
        Verdict::Timeout
    } else if run.success() {
        Verdict::Survived
    } else {
        Verdict::Killed
    })
}

/// Run `target` against each mutant of the file at `workspace/lib_rel`. The original is restored
/// afterwards. Verifies first that the unmutated source passes `target`.
pub fn run_mutants(
    workspace: &Path,
    lib_rel: &Path,
    muts: &[Mutant],
    target: &str,
    cfg: &MutationConfig,
) -> Result<Vec<Verdict>, MutationError> {
    let path = workspace.join(lib_rel);
    let original = std::fs::read_to_string(&path)?;
    let _guard = Restore {
        path: &path,
        original: &original,
    };
    if run_target(workspace, target, cfg)? != Verdict::Survived {
        return Err(MutationError::BaselineFails(target.to_string()));
    }
    let mut out = Vec::with_capacity(muts.len());
    for m in muts {
        std::fs::write(&path, apply(&original, m))?;
        out.push(run_target(workspace, target, cfg)?);
    }
    Ok(out)
}

/// The outcome of scoring a model's tests against the reference implementation's mutants.
#[derive(Clone, Debug, PartialEq)]
pub struct MutationScore {
    pub generated: usize,
    pub tested: usize,
    /// Do not compile: excluded.
    pub unviable: usize,
    /// Survived the *reference* tests: equivalent or untested by the oracle; excluded from the
    /// denominator, never held against the model.
    pub unkillable_by_reference: usize,
    /// Killed by the reference tests: the denominator.
    pub killable: usize,
    pub killed_by_model: usize,
    pub timeouts: usize,
    /// `killed_by_model / killable`; `None` when nothing was killable (no evidence either way).
    pub score: Option<f64>,
    /// One line per mutant the model's tests failed to kill.
    pub survivors: Vec<String>,
}

/// Score `model_target` (tests the model wrote, as an integration test file under `tests/`)
/// against mutants of the reference implementation at `workspace/lib_rel`, using `reference_target`
/// (the hidden oracle tests) to decide which mutants are killable at all.
///
/// Returns an error if the reference tests fail on the unmutated source, or if the model's
/// tests do: tests that fail on the reference implementation would "kill" every mutant and must
/// not be rewarded for it.
pub fn mutation_score(
    workspace: &Path,
    lib_rel: &Path,
    reference_target: &str,
    model_target: &str,
    cfg: &MutationConfig,
) -> Result<MutationScore, MutationError> {
    let path = workspace.join(lib_rel);
    let original = std::fs::read_to_string(&path)?;
    let all = enumerate(&original).ok_or(MutationError::Unparseable)?;
    let chosen = select(&all, cfg.max_mutants);
    let _guard = Restore {
        path: &path,
        original: &original,
    };
    for t in [reference_target, model_target] {
        if run_target(workspace, t, cfg)? != Verdict::Survived {
            return Err(MutationError::BaselineFails(t.to_string()));
        }
    }
    let mut s = MutationScore {
        generated: all.len(),
        tested: chosen.len(),
        unviable: 0,
        unkillable_by_reference: 0,
        killable: 0,
        killed_by_model: 0,
        timeouts: 0,
        score: None,
        survivors: Vec::new(),
    };
    for m in &chosen {
        std::fs::write(&path, apply(&original, m))?;
        match run_target(workspace, reference_target, cfg)? {
            Verdict::Unviable => s.unviable += 1,
            Verdict::Survived => s.unkillable_by_reference += 1,
            ref_v => {
                s.killable += 1;
                if ref_v == Verdict::Timeout {
                    s.timeouts += 1;
                }
                match run_target(workspace, model_target, cfg)? {
                    v if v.is_kill() => s.killed_by_model += 1,
                    _ => s.survivors.push(m.describe()),
                }
            }
        }
    }
    s.score = (s.killable > 0).then(|| s.killed_by_model as f64 / s.killable as f64);
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = r#"
pub fn clamp_add(a: i64, b: i64, hi: i64) -> i64 {
    let s = a + b;
    if s > hi { hi } else { s }
}

pub fn both(a: bool, b: bool) -> bool {
    a && !b
}

pub fn noop(v: &mut Vec<i32>) {
    v.push(1);
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        assert!(1 + 1 == 2);
    }
}

#[test]
fn also_skipped() {
    let _ = 2 * 3;
}
"#;

    fn kinds(ms: &[Mutant]) -> Vec<(&'static str, String, String)> {
        ms.iter()
            .map(|m| (m.kind, m.from.clone(), m.to.clone()))
            .collect()
    }

    #[test]
    fn enumerates_in_source_order_with_stable_ids_and_skips_test_code() {
        let a = enumerate(SRC).unwrap();
        let b = enumerate(SRC).unwrap();
        assert_eq!(a, b, "deterministic");
        assert!(a.iter().enumerate().all(|(i, m)| m.id == i));
        let k = kinds(&a);
        // clamp_add: body -> 0/1, `+`, `>`
        assert!(k.contains(&("binop", "+".into(), "-".into())));
        assert!(k.contains(&("binop", "+".into(), "*".into())));
        assert!(k.contains(&("compare", ">".into(), ">=".into())));
        assert!(k.contains(&("compare", ">".into(), "<".into())));
        // both: `&&` -> `||`, `!` removed, bool body
        assert!(k.contains(&("logic", "&&".into(), "||".into())));
        assert!(k.contains(&("not", "!".into(), "".into())));
        assert!(a.iter().any(|m| m.kind == "fn-body"
            && m.to == "{ true }"
            && m.function.as_deref() == Some("both")));
        // unit fn: body -> ()
        assert!(a.iter().any(|m| m.kind == "fn-body"
            && m.to == "{ () }"
            && m.function.as_deref() == Some("noop")));
        // nothing from #[cfg(test)] mod or #[test] fn: their `1 + 1`, `==`, `2 * 3` never appear
        assert!(
            !a.iter().any(|m| m.line >= 15),
            "{:?}",
            a.iter()
                .filter(|m| m.line >= 15)
                .map(Mutant::describe)
                .collect::<Vec<_>>()
        );
        // sorted by position
        assert!(a
            .windows(2)
            .all(|w| (w[0].line, w[0].col) <= (w[1].line, w[1].col)));
    }

    #[test]
    fn every_mutant_is_a_one_edit_change_that_still_parses_when_syntactically_valid() {
        let ms = enumerate(SRC).unwrap();
        assert_eq!(ms.len(), 11, "{}", ms.len());
        for m in &ms {
            let out = apply(SRC, m);
            assert_ne!(out, SRC, "{}", m.describe());
            assert!(
                syn::parse_file(&out).is_ok(),
                "mutant {} produced unparseable Rust:\n{out}",
                m.describe()
            );
            // exactly the recorded span was replaced
            assert_eq!(
                out.len() as isize - SRC.len() as isize,
                m.to.len() as isize - (m.end - m.start) as isize
            );
        }
    }

    #[test]
    fn positions_report_line_and_column_of_the_operator() {
        let ms = enumerate("fn f(a: i32, b: i32) -> i32 {\n    a + b\n}\n").unwrap();
        let plus = ms.iter().find(|m| m.from == "+" && m.to == "-").unwrap();
        assert_eq!((plus.line, plus.col), (2, 6));
        assert_eq!(plus.function.as_deref(), Some("f"));
        assert!(
            plus.describe().contains("binop in f: `+` -> `-`"),
            "{}",
            plus.describe()
        );
    }

    #[test]
    fn multibyte_source_maps_columns_to_the_right_bytes() {
        let src = "fn f(a: i32) -> bool {\n    let _s = \"héllo → wörld\"; a < 3\n}\n";
        let ms = enumerate(src).unwrap();
        let lt = ms.iter().find(|m| m.from == "<" && m.to == "<=").unwrap();
        assert_eq!(apply(src, lt), src.replacen("a < 3", "a <= 3", 1));
    }

    #[test]
    fn trivial_and_unsupported_function_bodies_are_not_mutated() {
        let src = "fn t() -> bool { true }\nfn u() {}\nfn s() -> String { String::new() }\nfn main() { let _ = 1 + 1; }\n";
        let ms = enumerate(src).unwrap();
        let bodies: Vec<_> = ms
            .iter()
            .filter(|m| m.kind == "fn-body")
            .map(|m| (m.function.clone().unwrap(), m.to.clone()))
            .collect();
        assert_eq!(
            bodies,
            vec![("t".to_string(), "{ false }".to_string())],
            "{bodies:?}"
        );
        // `main` is never mutated at the body level, but its operators are still fair game
        assert!(ms
            .iter()
            .any(|m| m.from == "+" && m.function.as_deref() == Some("main")));
    }

    #[test]
    fn unparseable_source_yields_none() {
        assert!(enumerate("fn (((").is_none());
    }

    #[test]
    fn selection_is_a_deterministic_even_spread() {
        let ms = enumerate(SRC).unwrap();
        let n = ms.len();
        assert_eq!(select(&ms, n + 5).len(), n);
        assert!(select(&ms, 0).is_empty());
        let s = select(&ms, 5);
        assert_eq!(s.len(), 5);
        assert_eq!(s, select(&ms, 5));
        assert_eq!(s[0].id, 0);
        assert!(
            s.windows(2).all(|w| w[0].id < w[1].id),
            "spread, in order, no repeats"
        );
    }
}

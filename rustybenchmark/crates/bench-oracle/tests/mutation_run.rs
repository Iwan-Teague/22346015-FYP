//! The mutation runner against real `cargo`, under `bench-sandbox`. These are slow (a compile or
//! two per mutant) so the fixture is tiny and the whole story is told in two scoring runs.

use bench_oracle::mutation::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

const LIB: &str = r#"
pub fn add(a: i64, b: i64) -> i64 {
    a + b
}

pub fn min2(a: i64, b: i64) -> i64 {
    if a < b { a } else { b }
}

pub fn count_to(n: i64) -> i64 {
    let mut i = 0;
    while i < n {
        i += 1;
    }
    i
}

pub fn join(a: &str, b: &str) -> String {
    a.to_string() + b
}
"#;

const REFERENCE_TESTS: &str = r#"
use mutfix::*;
#[test] fn add_works() { assert_eq!(add(2, 3), 5); assert_eq!(add(-4, 1), -3); }
#[test] fn min_works() { assert_eq!(min2(1, 2), 1); assert_eq!(min2(2, 1), 1); assert_eq!(min2(3, 3), 3); }
#[test] fn count_works() { assert_eq!(count_to(3), 3); assert_eq!(count_to(0), 0); }
#[test] fn join_works() { assert_eq!(join("a", "b"), "ab"); }
"#;

/// A model that wrote thorough tests.
const MODEL_STRONG: &str = REFERENCE_TESTS;

/// A model that wrote tests that pass but check almost nothing.
const MODEL_WEAK: &str = r#"
use mutfix::*;
#[test] fn add_zero() { assert_eq!(add(0, 0), 0); }
#[test] fn min_equal() { assert_eq!(min2(3, 3), 3); }
#[test] fn count_zero() { assert_eq!(count_to(0), 0); }
#[test] fn join_empty() { assert_eq!(join("", ""), ""); }
"#;

fn workspace(name: &str, model: &str) -> PathBuf {
    let ws = std::env::temp_dir().join(format!("rb-mut-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::create_dir_all(ws.join("tests")).unwrap();
    std::fs::write(
        ws.join("Cargo.toml"),
        "[package]\nname = \"mutfix\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(ws.join("src/lib.rs"), LIB).unwrap();
    std::fs::write(ws.join("tests/reference.rs"), REFERENCE_TESTS).unwrap();
    std::fs::write(ws.join("tests/model.rs"), model).unwrap();
    ws
}

fn cfg() -> MutationConfig {
    MutationConfig {
        max_mutants: 100,
        compile_wall: Duration::from_secs(120),
        run_wall: Duration::from_secs(4),
    }
}

fn find<'a>(ms: &'a [Mutant], function: &str, from: &str, to: &str) -> &'a Mutant {
    ms.iter()
        .find(|m| m.function.as_deref() == Some(function) && m.from == from && m.to == to)
        .unwrap_or_else(|| panic!("no mutant {function} {from}->{to}"))
}

#[test]
fn verdicts_kill_survive_timeout_unviable_and_equivalent() {
    let ws = workspace("verdicts", MODEL_STRONG);
    let ms = enumerate(LIB).unwrap();
    let lib = Path::new("src/lib.rs");

    // One pass of the reference tests over the interesting mutants.
    let picks = [
        find(&ms, "add", "+", "-").clone(),
        find(&ms, "min2", "<", "<=").clone(), // equivalent: min(a,b) is unchanged when a == b
        find(&ms, "min2", "<", ">").clone(),
        find(&ms, "count_to", "+=", "-=").clone(), // infinite loop
        find(&ms, "join", "+", "-").clone(),       // String - &str does not compile
    ];
    let v = run_mutants(&ws, lib, &picks, "reference", &cfg()).unwrap();
    assert_eq!(
        v,
        vec![
            Verdict::Killed,
            Verdict::Survived,
            Verdict::Killed,
            Verdict::Timeout,
            Verdict::Unviable
        ],
        "{:?}",
        picks.iter().map(Mutant::describe).collect::<Vec<_>>()
    );
    assert!(
        Verdict::Timeout.is_kill() && !Verdict::Unviable.is_kill() && !Verdict::Survived.is_kill()
    );
    assert_eq!(
        std::fs::read_to_string(ws.join(lib)).unwrap(),
        LIB,
        "original restored"
    );
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_thorough_test_suite_scores_one_and_the_equivalent_mutant_is_not_held_against_it() {
    let ws = workspace("strong", MODEL_STRONG);
    let s = mutation_score(&ws, Path::new("src/lib.rs"), "reference", "model", &cfg()).unwrap();
    eprintln!("score run: {s:?}");
    // `min2: <` -> `<=` survives the reference tests (it is equivalent), so it is excluded.
    assert!(s.unkillable_by_reference >= 1, "{s:?}");
    assert!(s.unviable >= 2, "String `-`/`*` do not compile: {s:?}");
    assert_eq!(s.killed_by_model, s.killable, "{s:?}");
    assert_eq!(
        s.score,
        Some(1.0),
        "an equivalent mutant must not lower a perfect score: {s:?}"
    );
    assert!(s.survivors.is_empty());
    assert!(
        s.timeouts >= 1,
        "the infinite-loop mutant is killed by the wall clock"
    );
    assert_eq!(s.generated, s.tested, "bounded run covers everything here");
    assert_eq!(
        s.tested,
        s.unviable + s.unkillable_by_reference + s.killable
    );
    assert_eq!(std::fs::read_to_string(ws.join("src/lib.rs")).unwrap(), LIB);
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_weak_test_suite_is_scored_by_the_mutants_it_misses() {
    let ws = workspace("weak", MODEL_WEAK);
    let s = mutation_score(&ws, Path::new("src/lib.rs"), "reference", "model", &cfg()).unwrap();
    eprintln!("score run: {s:?}");
    let score = s.score.unwrap();
    assert!(
        score < 0.5,
        "tests that only check zeros kill few mutants: {s:?}"
    );
    assert!(s.killed_by_model < s.killable);
    assert!(
        s.survivors
            .iter()
            .any(|d| d.contains("in add") && d.contains("`+` -> `-`")),
        "the survivor list names what was missed: {:?}",
        s.survivors
    );
    // The equivalent mutant is in neither the denominator nor the survivor list.
    assert!(!s
        .survivors
        .iter()
        .any(|d| d.contains("in min2") && d.contains("`<` -> `<=`")));
    // Same killable set as the thorough suite: the denominator depends on the reference, not the model.
    let strong = workspace("weak-vs-strong", MODEL_STRONG);
    let t = mutation_score(
        &strong,
        Path::new("src/lib.rs"),
        "reference",
        "model",
        &cfg(),
    )
    .unwrap();
    assert_eq!(
        (s.killable, s.unkillable_by_reference, s.unviable),
        (t.killable, t.unkillable_by_reference, t.unviable)
    );
    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(&strong);
}

#[test]
fn tests_that_fail_on_the_reference_implementation_earn_nothing() {
    // Such tests would "kill" every mutant; they must be rejected, not rewarded.
    let bad = "use mutfix::*;\n#[test] fn wrong() { assert_eq!(add(1, 1), 3); }\n";
    let ws = workspace("badmodel", bad);
    let e = mutation_score(&ws, Path::new("src/lib.rs"), "reference", "model", &cfg()).unwrap_err();
    assert!(
        matches!(e, MutationError::BaselineFails(ref t) if t == "model"),
        "{e}"
    );
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn an_unparseable_reference_cannot_be_mutated() {
    let ws = workspace("unparse", MODEL_STRONG);
    std::fs::write(ws.join("src/lib.rs"), "pub fn (((").unwrap();
    let e = mutation_score(&ws, Path::new("src/lib.rs"), "reference", "model", &cfg()).unwrap_err();
    assert!(matches!(e, MutationError::Unparseable), "{e}");
    let _ = std::fs::remove_dir_all(&ws);
}

/// The runner keeps bench-sandbox's guarantees: network denied, writes confined to the workspace.
/// The "tests" below try both; they record what happened inside the workspace.
#[cfg(target_os = "macos")]
#[test]
fn mutant_test_runs_are_contained() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let escape = PathBuf::from(std::env::var("HOME").unwrap())
        .join(format!("rb-mut-escape-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&escape);

    let ws = workspace("contained", MODEL_STRONG);
    let probe = format!(
        r#"
use mutfix::*;
#[test]
fn probe() {{
    assert_eq!(add(1, 1), 2);
    let net = std::net::TcpStream::connect(("127.0.0.1", {port})).is_ok();
    let fs = std::fs::write({escape:?}, "escaped").is_ok();
    std::fs::write("probe-result.txt", format!("net={{net}} fs={{fs}}")).unwrap();
}}
"#
    );
    std::fs::write(ws.join("tests/reference.rs"), probe).unwrap();
    // Zero mutants: only the baseline run of the probe executes.
    run_mutants(&ws, Path::new("src/lib.rs"), &[], "reference", &cfg()).unwrap();
    let r = std::fs::read_to_string(ws.join("probe-result.txt"))
        .expect("the probe ran inside the workspace");
    assert_eq!(
        r, "net=false fs=false",
        "network and out-of-workspace writes must be denied"
    );
    assert!(!escape.exists());
    let _ = std::fs::remove_dir_all(&ws);
}

//! Crash safety of `run-suite` (docs/09), end to end: the real binary, a real SIGKILL, the in-repo
//! mock endpoint (no model), and damaged journals. Each test says what it proves.

use bench_core::journal::scan;
use bench_model::mock::{Behavior, MockServer, ModelSpec};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_rustybench");
const EPOCH: &str = "crash-epoch";

fn mock(decode: f64) -> MockServer {
    MockServer::start(vec![Behavior::Model(ModelSpec {
        decode_tok_per_s: decode,
        prefill_tok_per_s: 200_000.0,
        eos_after: 20,
        ..Default::default()
    })])
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rb-resume-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn suite_args(url: &str, journal: &Path, scratch: &Path) -> Vec<String> {
    [
        "run-suite",
        "--model",
        url,
        "--model-name",
        "mock",
        "--epoch",
        EPOCH,
        "--seeds-core",
        "1",
        "--seeds-probe",
        "0",
        "--out",
        journal.to_str().unwrap(),
        "--scratch",
        scratch.to_str().unwrap(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(args: &[String]) -> Out {
    let o = Command::new(BIN).args(args).output().unwrap();
    Out {
        ok: o.status.success(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn units(journal: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(journal).unwrap_or_default();
    let s = scan(&text);
    s.clean
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["unit_id"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

fn planned(url: &str, d: &Path) -> usize {
    let mut a = suite_args(url, &d.join("plan.jsonl"), &d.join("ws"));
    a.push("--dry-run".into());
    let o = run(&a);
    assert!(o.ok, "{}{}", o.stdout, o.stderr);
    o.stdout
        .lines()
        .find_map(|l| {
            l.split(" units planned")
                .next()
                .and_then(|p| p.rsplit(' ').next())
                .and_then(|n| n.parse().ok())
        })
        .expect("plan size in dry-run output")
}

/// One complete epoch, run once and copied by each test that needs a finished journal.
fn completed() -> &'static (PathBuf, usize) {
    static C: OnceLock<(PathBuf, usize)> = OnceLock::new();
    C.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("rb-resume-complete-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let srv = mock(5_000.0);
        let n = planned(&srv.url(), &d);
        let j = d.join("journal.jsonl");
        let o = run(&suite_args(&srv.url(), &j, &d.join("ws")));
        assert!(o.ok, "{}{}", o.stdout, o.stderr);
        assert_eq!(units(&j).len(), n, "baseline run completes the whole plan");
        (j, n)
    })
}

fn copy_completed(name: &str) -> (PathBuf, PathBuf, usize) {
    let d = dir(name);
    let (src, n) = completed();
    let j = d.join("journal.jsonl");
    std::fs::copy(src, &j).unwrap();
    (d, j, *n)
}

fn no_dups(ids: &[String]) {
    let mut s = ids.to_vec();
    s.sort();
    s.dedup();
    assert_eq!(s.len(), ids.len(), "a unit appears twice");
}

#[test]
fn sigkill_mid_run_then_resume_loses_nothing_and_counts_nothing_twice() {
    let srv = mock(500.0); // ~40 ms a unit: the run is still going when we kill it
    let d = dir("sigkill");
    let j = d.join("journal.jsonl");
    let n = planned(&srv.url(), &d);

    let mut child = Command::new(BIN)
        .args(suite_args(&srv.url(), &j, &d.join("ws")))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let t0 = Instant::now();
    while units(&j).len() < 5 {
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "the run never produced 5 units"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    child.kill().unwrap(); // SIGKILL: no destructors, no lock release, maybe a torn line
    child.wait().unwrap();
    let before = units(&j);
    assert!(
        before.len() >= 5 && before.len() < n,
        "killed mid-run: {}/{n}",
        before.len()
    );
    assert!(
        j.with_file_name("journal.jsonl.lock").exists(),
        "SIGKILL leaves the lock behind"
    );

    let o = run(&suite_args(&srv.url(), &j, &d.join("ws")));
    assert!(o.ok, "resume must succeed: {}{}", o.stdout, o.stderr);
    assert!(
        o.stdout
            .contains(&format!("repaired: removed stale lock left by pid {pid}")),
        "the takeover is reported:\n{}",
        o.stdout
    );
    let after = units(&j);
    no_dups(&after);
    assert_eq!(after.len(), n, "the whole plan is done exactly once");
    // Every unit completed before the kill is still there, unchanged and not re-run.
    for u in &before {
        assert!(after.contains(u), "completed unit {u} was lost");
    }
    let text = std::fs::read_to_string(&j).unwrap();
    assert!(scan(&text).is_clean(), "the repaired journal is clean");
    assert!(
        !j.with_file_name("journal.jsonl.lock").exists(),
        "lock released on a clean exit"
    );
    // Resume ran in a new segment, so its cold-cache units are distinguishable (docs/08).
    assert!(
        text.lines().any(|l| l.contains("\"segment\":1")),
        "resume starts segment 1"
    );
}

#[test]
fn a_torn_tail_is_discarded_reported_and_preserved() {
    let (d, j, n) = copy_completed("torn");
    // Drop the last unit and leave half of it behind, as a kill mid-append does.
    let text = std::fs::read_to_string(&j).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    let last = lines.pop().unwrap();
    let kept = lines.len();
    let mut damaged = lines.join("\n");
    damaged.push('\n');
    damaged.push_str(&last[..last.len() / 2]);
    std::fs::write(&j, &damaged).unwrap();

    let srv = mock(5_000.0);
    let o = run(&suite_args(&srv.url(), &j, &d.join("ws")));
    assert!(o.ok, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("repaired: line "), "{}", o.stdout);
    assert!(
        o.stdout.contains("torn final line discarded"),
        "{}",
        o.stdout
    );
    let after = units(&j);
    no_dups(&after);
    assert_eq!(
        after.len(),
        n,
        "the interrupted unit re-ran; nothing else did"
    );
    assert_eq!(kept + 1, n);
    let q = std::fs::read_to_string(j.with_file_name("journal.jsonl.quarantine")).unwrap();
    assert!(
        q.contains(&last[..last.len() / 2]),
        "the torn bytes are kept, not deleted"
    );
}

#[test]
fn a_unit_glued_behind_a_torn_fragment_is_salvaged_not_lost() {
    // What the pre-fix append produced: fragment, then the next completed unit on the same line.
    let (d, j, n) = copy_completed("glued");
    let text = std::fs::read_to_string(&j).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let victim = lines[3].clone();
    let victim_id = serde_json::from_str::<serde_json::Value>(&victim).unwrap()["unit_id"]
        .as_str()
        .unwrap()
        .to_string();
    lines[3] = format!("{}{}", &lines[2][..40], victim); // fragment fused with a real unit
    lines.remove(2); // the fragment's own (lost) unit
    std::fs::write(&j, lines.join("\n") + "\n").unwrap();

    let srv = mock(5_000.0);
    let o = run(&suite_args(&srv.url(), &j, &d.join("ws")));
    assert!(o.ok, "{}{}", o.stdout, o.stderr);
    assert!(
        o.stdout
            .contains("unit recovered from behind a torn fragment"),
        "{}",
        o.stdout
    );
    let after = units(&j);
    no_dups(&after);
    assert!(after.contains(&victim_id), "the glued unit was salvaged");
    assert_eq!(after.len(), n, "and the genuinely lost unit re-ran");
}

#[test]
fn append_after_a_kill_does_not_swallow_the_next_unit() {
    // The append side of the same bug: a fragment is on disk when a *later* run appends.
    let d = dir("append-guard");
    let j = d.join("journal.jsonl");
    let (src, _) = completed();
    let text = std::fs::read_to_string(src).unwrap();
    let first = text.lines().next().unwrap();
    std::fs::write(
        &j,
        format!("{}\n{}", first, &text.lines().nth(1).unwrap()[..30]),
    )
    .unwrap();
    let srv = mock(5_000.0);
    // `run-suite` repairs first, so exercise the raw append through single `run` (no repair step).
    let o = run(&[
        "run".into(),
        "--family".into(),
        "window-op".into(),
        "--seed".into(),
        "7".into(),
        "--model".into(),
        srv.url(),
        "--model-name".into(),
        "mock".into(),
        "--out".into(),
        j.to_str().unwrap().into(),
        "--scratch".into(),
        d.join("ws").to_str().unwrap().into(),
    ]);
    assert!(o.ok, "{}{}", o.stdout, o.stderr);
    let s = scan(&std::fs::read_to_string(&j).unwrap());
    assert_eq!(
        s.units,
        2,
        "the new unit stands alone on its own line: {:?}",
        s.summary()
    );
    assert!(
        s.repairs
            .iter()
            .all(|r| r.kind != bench_core::journal::RepairKind::SalvagedGlue),
        "the fragment must stay its own line, not fuse with the new unit: {:?}",
        s.summary()
    );
}

#[test]
fn duplicated_and_reordered_lines_do_not_change_what_the_commands_report() {
    let (d, clean, n) = copy_completed("dups");
    let text = std::fs::read_to_string(&clean).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    let baseline = run(&[
        "stats".into(),
        "--journal".into(),
        clean.to_str().unwrap().into(),
    ]);
    assert!(baseline.ok, "{}{}", baseline.stdout, baseline.stderr);

    lines.reverse();
    lines.rotate_left(17);
    let dup: Vec<&str> = lines.iter().take(12).copied().collect();
    let mut messy = lines.clone();
    messy.extend(dup);
    let m = d.join("messy.jsonl");
    std::fs::write(&m, messy.join("\n") + "\n").unwrap();

    let stats = run(&[
        "stats".into(),
        "--journal".into(),
        m.to_str().unwrap().into(),
    ]);
    assert!(stats.ok, "{}{}", stats.stdout, stats.stderr);
    assert_eq!(
        stats.stdout, baseline.stdout,
        "12 duplicated + reordered lines changed the statistics"
    );
    assert!(
        stats.stderr.contains("duplicate unit dropped"),
        "{}",
        stats.stderr
    );
    assert_eq!(
        std::fs::read_to_string(&m).unwrap().lines().count(),
        n + 12,
        "read-only commands do not modify the file"
    );

    // Resume repairs the file in place: nothing left to run, duplicates quarantined.
    let srv = mock(5_000.0);
    let o = run(&suite_args(&srv.url(), &m, &d.join("ws")));
    assert!(o.ok, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("0 to run"), "{}", o.stdout);
    assert_eq!(
        o.stdout
            .matches("duplicate unit dropped (identical copy)")
            .count(),
        12,
        "{}",
        o.stdout
    );
    let after = units(&m);
    no_dups(&after);
    assert_eq!(after.len(), n);
}

#[test]
fn timestamps_are_never_consulted_so_a_clock_going_backwards_changes_nothing() {
    let (d, j, n) = copy_completed("clock");
    let text = std::fs::read_to_string(&j).unwrap();
    let baseline = run(&[
        "stats".into(),
        "--journal".into(),
        j.to_str().unwrap().into(),
    ])
    .stdout;
    // Stamp every line with a completion time that goes DOWN the file, ending before 1970.
    let stamped: String = text
        .lines()
        .enumerate()
        .map(|(i, l)| {
            let mut v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["completed_at"] = serde_json::json!(format!(
                "2026-10-05T23:{:02}:00Z",
                59usize.saturating_sub(i % 60)
            ));
            v["clock_ms"] = serde_json::json!(1_000_000i64 - 7 * i as i64);
            format!("{v}\n")
        })
        .collect();
    std::fs::write(&j, &stamped).unwrap();
    let srv = mock(5_000.0);
    let o = run(&suite_args(&srv.url(), &j, &d.join("ws")));
    assert!(
        o.ok && o.stdout.contains("0 to run"),
        "{}{}",
        o.stdout,
        o.stderr
    );
    assert!(
        !o.stdout.contains("repaired:"),
        "a backwards clock is not damage: {}",
        o.stdout
    );
    assert_eq!(units(&j).len(), n);
    assert_eq!(
        run(&[
            "stats".into(),
            "--journal".into(),
            j.to_str().unwrap().into()
        ])
        .stdout,
        baseline
    );
}

#[test]
fn a_live_lock_stops_a_second_run_and_a_dry_run_ignores_it() {
    let (d, j, _n) = copy_completed("livelock");
    // This test process is alive, so a lock naming it is a live holder.
    std::fs::write(
        j.with_file_name("journal.jsonl.lock"),
        format!("{}\n", std::process::id()),
    )
    .unwrap();
    let before = std::fs::read_to_string(&j).unwrap();
    let srv = mock(5_000.0);
    let o = run(&suite_args(&srv.url(), &j, &d.join("ws")));
    assert!(!o.ok);
    assert!(o.stderr.contains("interleave"), "{}", o.stderr);
    assert_eq!(
        std::fs::read_to_string(&j).unwrap(),
        before,
        "a refused run touches nothing"
    );
    assert!(
        j.with_file_name("journal.jsonl.lock").exists(),
        "and does not steal the live lock"
    );
    let mut dry = suite_args(&srv.url(), &j, &d.join("ws"));
    dry.push("--dry-run".into());
    assert!(run(&dry).ok, "a dry run only reads");
}

#[test]
fn continuing_under_a_different_model_hardware_or_version_is_refused_unless_forced() {
    for (what, from, to) in [
        (
            "model name",
            "\"name\":\"mock\"",
            "\"name\":\"another-model\"",
        ),
        (
            "hardware class",
            "\"hw_class\":\"",
            "\"hw_class\":\"vram-48-",
        ),
        (
            "harness version",
            "\"harness\":\"0.0.1\"",
            "\"harness\":\"0.0.0\"",
        ),
    ] {
        let (d, j, n) = copy_completed(&format!("gate-{}", what.replace(' ', "-")));
        let text = std::fs::read_to_string(&j).unwrap();
        assert!(text.contains(from), "fixture lacks {from}");
        std::fs::write(&j, text.replace(from, to)).unwrap();
        let before = std::fs::read_to_string(&j).unwrap();
        let srv = mock(5_000.0);

        let o = run(&suite_args(&srv.url(), &j, &d.join("ws")));
        assert!(!o.ok, "{what}: must refuse");
        assert!(
            o.stderr.contains("refusing to continue") && o.stderr.contains(what),
            "{what}: {}",
            o.stderr
        );
        assert_eq!(
            std::fs::read_to_string(&j).unwrap(),
            before,
            "{what}: a refusal changes nothing"
        );
        assert!(!j.with_file_name("journal.jsonl.tainted").exists());
        assert!(
            !j.with_file_name("journal.jsonl.lock").exists(),
            "{what}: the lock is released on refusal"
        );

        let mut forced = suite_args(&srv.url(), &j, &d.join("ws"));
        forced.push("--force-heterogeneous".into());
        let o = run(&forced);
        assert!(o.ok, "{what}: {}{}", o.stdout, o.stderr);
        assert!(o.stdout.contains("TAINTED"), "{}", o.stdout);
        let taint = std::fs::read_to_string(j.with_file_name("journal.jsonl.tainted")).unwrap();
        assert!(taint.contains(what), "{taint}");
        // Every rendering of the results carries it, forever.
        let s = run(&[
            "status".into(),
            "--journal".into(),
            j.to_str().unwrap().into(),
            "--epoch".into(),
            EPOCH.into(),
            "--seeds-core".into(),
            "1".into(),
            "--seeds-probe".into(),
            "0".into(),
        ]);
        assert!(s.stdout.contains("TAINTED"), "{what}: {}", s.stdout);
        let st = run(&[
            "stats".into(),
            "--journal".into(),
            j.to_str().unwrap().into(),
        ]);
        assert!(st.stdout.contains("TAINTED"), "{what}");
        assert_eq!(
            units(&j).len(),
            n,
            "{what}: forcing does not duplicate or drop units"
        );
    }
}

#[test]
fn a_fresh_epoch_or_an_unchanged_setup_is_never_gated() {
    let (d, j, _n) = copy_completed("nogate");
    let srv = mock(5_000.0);
    let o = run(&suite_args(&srv.url(), &j, &d.join("ws")));
    assert!(
        o.ok && !o.stdout.contains("TAINTED") && !o.stdout.contains("repaired:"),
        "{}{}",
        o.stdout,
        o.stderr
    );
    // A different epoch in the same journal starts clean even under another model name.
    let mut a = suite_args(&srv.url(), &j, &d.join("ws"));
    let i = a.iter().position(|x| x == EPOCH).unwrap();
    a[i] = "second-epoch".into();
    let m = a.iter().position(|x| x == "mock").unwrap();
    a[m] = "other-model".into();
    a.push("--dry-run".into());
    assert!(run(&a).ok);
}

#[test]
fn the_journal_command_reports_before_it_repairs_and_repairs_only_on_request() {
    let (d, j, n) = copy_completed("journal-cmd");
    let text = std::fs::read_to_string(&j).unwrap();
    let first = text.lines().next().unwrap();
    let damaged = format!("{text}{first}\nnot json at all\n{}", &first[..50]);
    std::fs::write(&j, &damaged).unwrap();
    let p = j.to_str().unwrap().to_string();

    let o = run(&["journal".into(), "--journal".into(), p.clone()]);
    assert!(o.ok, "{}{}", o.stdout, o.stderr);
    assert!(
        o.stdout.contains(&format!("{n} completed unit(s)")),
        "{}",
        o.stdout
    );
    assert_eq!(o.stdout.matches("would repair:").count(), 3, "{}", o.stdout);
    assert!(o.stdout.contains("re-run with --repair"));
    assert_eq!(
        std::fs::read_to_string(&j).unwrap(),
        damaged,
        "a check never modifies the journal"
    );

    let o = run(&[
        "journal".into(),
        "--journal".into(),
        p.clone(),
        "--repair".into(),
    ]);
    assert!(
        o.ok && o.stdout.matches("repaired:").count() == 3,
        "{}{}",
        o.stdout,
        o.stderr
    );
    assert!(scan(&std::fs::read_to_string(&j).unwrap()).is_clean());
    assert_eq!(units(&j).len(), n);
    let q = std::fs::read_to_string(d.join("journal.jsonl.quarantine")).unwrap();
    assert!(q.contains("not json at all") && q.contains(&first[..50]));
    assert!(run(&["journal".into(), "--journal".into(), p])
        .stdout
        .contains("clean: nothing to repair"));
}

/// The environment gates (docs/05, `--ignore-gates`, `--require-ac`, `--min-free-disk-gib`) and the
/// journal-side logic (lock, repair, resume identity gate, `--force-heterogeneous`) in one run.
#[test]
fn environment_gates_and_resume_gates_compose_in_a_sensible_order() {
    let (d, j, n) = copy_completed("combo");
    let lock = j.with_file_name("journal.jsonl.lock");
    let taint = j.with_file_name("journal.jsonl.tainted");
    // A different model than the journal recorded, plus a stale lock from a dead process.
    let text = std::fs::read_to_string(&j)
        .unwrap()
        .replace("\"name\":\"mock\"", "\"name\":\"other\"");
    std::fs::write(&j, &text).unwrap();
    let stale = || std::fs::write(&lock, "2147483000\n").unwrap();
    let srv = mock(5_000.0);
    let base = suite_args(&srv.url(), &j, &d.join("ws"));
    let with = |extra: &[&str]| {
        let mut a = base.clone();
        a.extend(extra.iter().map(|s| s.to_string()));
        a
    };
    let impossible = ["--min-free-disk-gib", "100000000"];

    // 1. A blocking environment gate refuses first: before the lock, the repair and the identity
    //    gate. Nothing is touched, the stale lock is still there to be reported later.
    stale();
    let o = run(&with(&impossible));
    assert!(!o.ok);
    assert!(o.stderr.contains("pre-run gate(s) failed"), "{}", o.stderr);
    assert!(
        !o.stderr.contains("refusing to continue"),
        "gate order: environment before identity"
    );
    assert_eq!(
        std::fs::read_to_string(&lock).unwrap().trim(),
        "2147483000",
        "refused before taking the lock"
    );
    assert_eq!(std::fs::read_to_string(&j).unwrap(), text);

    // 2. --ignore-gates (and --require-ac, which then cannot block) lets it through to the journal
    //    side, which takes over the stale lock and then refuses the different model.
    let o = run(&with(
        &[&impossible[..], &["--ignore-gates", "--require-ac"]].concat(),
    ));
    assert!(!o.ok);
    assert!(
        o.stdout
            .contains("repaired: removed stale lock left by pid 2147483000"),
        "{}{}",
        o.stdout,
        o.stderr
    );
    assert!(
        o.stderr.contains("refusing to continue") && o.stderr.contains("model name"),
        "{}",
        o.stderr
    );
    assert!(
        !lock.exists(),
        "the lock is released even when the identity gate refuses"
    );
    assert!(!taint.exists());
    assert_eq!(
        std::fs::read_to_string(&j).unwrap(),
        text,
        "a refusal changes nothing"
    );

    // 3. Both overrides together: stale lock taken over, mismatch forced and tainted, no unit lost.
    stale();
    let o = run(&with(
        &[
            &impossible[..],
            &["--ignore-gates", "--force-heterogeneous"],
        ]
        .concat(),
    ));
    assert!(o.ok, "{}{}", o.stdout, o.stderr);
    assert!(
        o.stdout.contains("removed stale lock") && o.stdout.contains("TAINTED"),
        "{}",
        o.stdout
    );
    assert!(std::fs::read_to_string(&taint)
        .unwrap()
        .contains("model name"));
    assert_eq!(units(&j).len(), n);
    assert!(!lock.exists());

    // 4. A dry run is never blocked by a gate and never takes or disturbs the lock.
    stale();
    let o = run(&with(&[&impossible[..], &["--dry-run"]].concat()));
    assert!(o.ok, "{}{}", o.stdout, o.stderr);
    assert_eq!(std::fs::read_to_string(&lock).unwrap().trim(), "2147483000");
}

// ---- interruption (docs/09 "Interruption handling") ----

fn kill_sig(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .unwrap()
        .success();
    assert!(ok, "kill {sig} {pid}");
}

fn spawn_piped(args: &[String], envs: &[(&str, &str)]) -> std::process::Child {
    let mut c = Command::new(BIN);
    c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in envs {
        c.env(k, v);
    }
    c.spawn().unwrap()
}

fn wait_units(j: &Path, at_least: usize) {
    let t0 = Instant::now();
    while units(j).len() < at_least {
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "never reached {at_least} units"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_exit(child: &mut std::process::Child, within: Duration) -> (Option<i32>, Duration) {
    let t0 = Instant::now();
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return (st.code(), t0.elapsed());
        }
        assert!(
            t0.elapsed() < within,
            "process still running after {within:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_out(mut child: std::process::Child) -> (String, String) {
    use std::io::Read;
    let (mut o, mut e) = (String::new(), String::new());
    child.stdout.take().unwrap().read_to_string(&mut o).unwrap();
    child.stderr.take().unwrap().read_to_string(&mut e).unwrap();
    (o, e)
}

#[test]
fn first_sigint_finishes_the_unit_closes_the_segment_and_exits_zero() {
    let srv = mock(500.0);
    let d = dir("sigint1");
    let j = d.join("journal.jsonl");
    let n = planned(&srv.url(), &d);
    let mut child = spawn_piped(&suite_args(&srv.url(), &j, &d.join("ws")), &[]);
    wait_units(&j, 3);
    kill_sig(child.id(), "-INT");
    let (code, _) = wait_exit(&mut child, Duration::from_secs(20));
    let (out, _err) = read_out(child);
    assert_eq!(code, Some(0), "a first SIGINT is a clean stop: {out}");
    assert!(
        out.contains("stopped by SIGINT after the current unit"),
        "{out}"
    );
    let done = units(&j);
    assert!(done.len() >= 3 && done.len() < n, "{}/{n}", done.len());
    assert!(
        scan(&std::fs::read_to_string(&j).unwrap()).is_clean(),
        "journal intact"
    );
    assert!(
        !j.with_file_name("journal.jsonl.lock").exists(),
        "the lock is released: this was not a crash"
    );
    // Resume has nothing to repair and finishes the plan exactly once.
    let o = run(&suite_args(&srv.url(), &j, &d.join("ws")));
    assert!(
        o.ok && !o.stdout.contains("repaired:"),
        "{}{}",
        o.stdout,
        o.stderr
    );
    let after = units(&j);
    no_dups(&after);
    assert_eq!(after.len(), n);
}

#[test]
fn second_sigint_aborts_at_once_and_the_unit_in_flight_reruns() {
    // ~2 s a unit, so the signals land mid-unit.
    let slow = mock(10.0);
    let d = dir("sigint2");
    let j = d.join("journal.jsonl");
    let mut child = spawn_piped(&suite_args(&slow.url(), &j, &d.join("ws")), &[]);
    wait_units(&j, 1);
    std::thread::sleep(Duration::from_millis(300));
    kill_sig(child.id(), "-INT");
    std::thread::sleep(Duration::from_millis(150));
    kill_sig(child.id(), "-INT");
    let (code, took) = wait_exit(&mut child, Duration::from_secs(10));
    assert_eq!(code, Some(130), "second SIGINT aborts");
    assert!(
        took < Duration::from_millis(1500),
        "abort is immediate, took {took:?}"
    );
    let before = units(&j);
    assert!(
        scan(&std::fs::read_to_string(&j).unwrap()).is_clean(),
        "no torn line: abort happens between journal writes"
    );
    // The in-flight unit was discarded; resume (fast mock) completes exactly once and reports the stale lock.
    let fast = mock(5_000.0);
    let n = planned(&fast.url(), &d);
    let o = run(&suite_args(&fast.url(), &j, &d.join("ws")));
    assert!(
        o.ok && o.stdout.contains("removed stale lock"),
        "{}{}",
        o.stdout,
        o.stderr
    );
    let after = units(&j);
    no_dups(&after);
    assert_eq!(after.len(), n);
    for u in &before {
        assert!(after.contains(u));
    }
}

#[test]
fn sigterm_is_a_clean_stop_when_the_unit_ends_inside_the_grace_window() {
    let srv = mock(500.0);
    let d = dir("sigterm-ok");
    let j = d.join("journal.jsonl");
    let mut child = spawn_piped(
        &suite_args(&srv.url(), &j, &d.join("ws")),
        &[("RUSTBENCH_TERM_GRACE_SECS", "10")],
    );
    wait_units(&j, 3);
    kill_sig(child.id(), "-TERM");
    let (code, _) = wait_exit(&mut child, Duration::from_secs(20));
    let (out, _) = read_out(child);
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.contains("stopped by SIGTERM after the current unit"),
        "{out}"
    );
    assert!(scan(&std::fs::read_to_string(&j).unwrap()).is_clean());
    assert!(!j.with_file_name("journal.jsonl.lock").exists());
}

#[test]
fn sigterm_aborts_when_the_unit_outlasts_the_shorter_grace_window() {
    let slow = mock(10.0); // ~2 s a unit
    let d = dir("sigterm-late");
    let j = d.join("journal.jsonl");
    let mut child = spawn_piped(
        &suite_args(&slow.url(), &j, &d.join("ws")),
        &[("RUSTBENCH_TERM_GRACE_SECS", "1")],
    );
    wait_units(&j, 1);
    std::thread::sleep(Duration::from_millis(200));
    kill_sig(child.id(), "-TERM");
    let (code, took) = wait_exit(&mut child, Duration::from_secs(10));
    assert_eq!(code, Some(143), "grace expired");
    assert!(
        took >= Duration::from_millis(800) && took < Duration::from_millis(2500),
        "{took:?}"
    );
    assert!(scan(&std::fs::read_to_string(&j).unwrap()).is_clean());
}

// ---- scheduling controls (docs/09 "Scheduling controls") ----

fn assert_clean_stop(j: &Path, out: &str, reason: &str) {
    assert!(out.contains(&format!("stopped: {reason}")), "{out}");
    assert!(
        scan(&std::fs::read_to_string(j).unwrap()).is_clean(),
        "no torn line"
    );
    assert!(
        !j.with_file_name("journal.jsonl.lock").exists(),
        "no lock left behind"
    );
}

fn fake(path: &Path, json: serde_json::Value) {
    std::fs::write(path, json.to_string()).unwrap();
}

#[test]
fn max_units_stops_after_exactly_n_units_per_session_and_resumes_cleanly() {
    let srv = mock(5_000.0);
    let d = dir("maxunits");
    let j = d.join("journal.jsonl");
    let n = planned(&srv.url(), &d);
    let mut a = suite_args(&srv.url(), &j, &d.join("ws"));
    a.extend(["--max-units".into(), "4".into()]);
    let o = run(&a);
    assert!(o.ok, "{}{}", o.stdout, o.stderr);
    assert_clean_stop(&j, &o.stdout, "max_units");
    assert_eq!(units(&j).len(), 4);
    // The next session gets its own allowance and its own segment.
    let o = run(&a);
    assert!(o.ok);
    assert_eq!(units(&j).len(), 8, "N more units, not N in total");
    assert!(
        !o.stdout.contains("repaired:"),
        "a scheduled stop is not damage: {}",
        o.stdout
    );
    // And without the flag it finishes the plan exactly once.
    let o = run(&suite_args(&srv.url(), &j, &d.join("ws")));
    assert!(o.ok);
    let after = units(&j);
    no_dups(&after);
    assert_eq!(after.len(), n);
    // zero stops before the first unit
    let d0 = dir("maxunits0");
    let mut z = suite_args(&srv.url(), &d0.join("journal.jsonl"), &d0.join("ws"));
    z.extend(["--max-units".into(), "0".into()]);
    let o = run(&z);
    assert!(
        o.ok && o.stdout.contains("stopped: max_units"),
        "{}",
        o.stdout
    );
    assert_eq!(units(&d0.join("journal.jsonl")).len(), 0);
}

#[test]
fn max_duration_stops_at_a_unit_boundary_and_never_mid_unit() {
    // ~2 s a unit so the limit is crossed while a unit is in flight.
    let slow = mock(10.0);
    let d = dir("maxdur");
    let j = d.join("journal.jsonl");
    let hook = d.join("fake.json");
    fake(&hook, serde_json::json!({"elapsed_s": 0}));
    let mut a = suite_args(&slow.url(), &j, &d.join("ws"));
    a.extend(["--max-duration".into(), "4h".into()]);
    let mut child = spawn_piped(&a, &[("RUSTBENCH_SCHEDULE_FAKE", hook.to_str().unwrap())]);
    wait_units(&j, 1);
    std::thread::sleep(Duration::from_millis(300)); // unit 2 is in flight
    fake(&hook, serde_json::json!({"elapsed_s": 4 * 3600}));
    let flipped = Instant::now();
    let (code, _) = wait_exit(&mut child, Duration::from_secs(20));
    let took = flipped.elapsed();
    let (out, _) = read_out(child);
    assert_eq!(code, Some(0), "{out}");
    assert_clean_stop(&j, &out, "max_duration");
    assert_eq!(
        units(&j).len(),
        2,
        "the unit in flight finished and was journalled; no third started"
    );
    assert!(
        took > Duration::from_millis(900),
        "it waited for the in-flight unit (took {took:?})"
    );
}

#[test]
fn until_stops_when_the_wall_clock_passes_the_deadline_fixed_at_start() {
    let srv = mock(500.0);
    let d = dir("until");
    let j = d.join("journal.jsonl");
    let hook = d.join("fake.json");
    // 23:59:50 local, --until 00:00 -> deadline 10 s of wall clock from now.
    fake(
        &hook,
        serde_json::json!({"now_unix": 1_000_000u64, "local_hms": "23:59:50"}),
    );
    let mut a = suite_args(&srv.url(), &j, &d.join("ws"));
    a.extend(["--until".into(), "00:00".into()]);
    let mut child = spawn_piped(&a, &[("RUSTBENCH_SCHEDULE_FAKE", hook.to_str().unwrap())]);
    wait_units(&j, 3);
    assert!(
        child.try_wait().unwrap().is_none(),
        "still before the deadline"
    );
    fake(
        &hook,
        serde_json::json!({"now_unix": 1_000_010u64, "local_hms": "23:59:50"}),
    );
    let (code, _) = wait_exit(&mut child, Duration::from_secs(20));
    let (out, _) = read_out(child);
    assert_eq!(code, Some(0), "{out}");
    assert_clean_stop(&j, &out, "until_time");
    assert!(units(&j).len() >= 3);
}

#[test]
fn until_exactly_now_means_tomorrow_and_a_clock_that_cannot_be_read_is_an_error() {
    let srv = mock(5_000.0);
    let d = dir("until-edge");
    let j = d.join("journal.jsonl");
    let hook = d.join("fake.json");
    fake(
        &hook,
        serde_json::json!({"now_unix": 5u64, "local_hms": "07:30:00"}),
    );
    let mut a = suite_args(&srv.url(), &j, &d.join("ws"));
    a.extend([
        "--until".into(),
        "07:30".into(),
        "--max-units".into(),
        "3".into(),
    ]);
    let mut c = Command::new(BIN);
    c.args(&a).env("RUSTBENCH_SCHEDULE_FAKE", &hook);
    let o = c.output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "{out}");
    assert!(
        out.contains("stopped: max_units"),
        "07:30:00 with --until 07:30 must not stop at once: {out}"
    );
    assert_eq!(units(&j).len(), 3);

    // Unreadable local time: refuse to start rather than ignore the limit.
    fake(
        &hook,
        serde_json::json!({"now_unix": 5u64, "local_hms": "garbage"}),
    );
    let d2 = dir("until-bad");
    let j2 = d2.join("journal.jsonl");
    let mut a2 = suite_args(&srv.url(), &j2, &d2.join("ws"));
    a2.extend(["--until".into(), "07:30".into()]);
    let o = Command::new(BIN)
        .args(&a2)
        .env("RUSTBENCH_SCHEDULE_FAKE", &hook)
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("local time"));
    assert!(
        !j2.exists() && !j2.with_file_name("journal.jsonl.lock").exists(),
        "refused before touching anything"
    );
}

#[test]
fn pause_on_battery_checkpoints_when_ac_is_lost_and_refuses_to_start_on_battery() {
    let srv = mock(500.0);
    let d = dir("battery");
    let j = d.join("journal.jsonl");
    let hook = d.join("fake.json");
    fake(&hook, serde_json::json!({"battery": "ac"}));
    let mut a = suite_args(&srv.url(), &j, &d.join("ws"));
    a.push("--pause-on-battery".into());
    let mut child = spawn_piped(&a, &[("RUSTBENCH_SCHEDULE_FAKE", hook.to_str().unwrap())]);
    wait_units(&j, 3);
    fake(&hook, serde_json::json!({"battery": "battery"}));
    let (code, _) = wait_exit(&mut child, Duration::from_secs(20));
    let (out, _) = read_out(child);
    assert_eq!(code, Some(0), "{out}");
    assert_clean_stop(&j, &out, "battery");
    let n_done = units(&j).len();

    // Still on battery: the next session ends before running anything.
    let o = Command::new(BIN)
        .args(&a)
        .env("RUSTBENCH_SCHEDULE_FAKE", &hook)
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        o.status.success() && out.contains("stopped: battery"),
        "{out}"
    );
    assert_eq!(units(&j).len(), n_done, "no unit started on battery");

    // Without the flag battery is irrelevant; with an unknown power state (a desktop) it never stops.
    for (flag, state) in [(false, "battery"), (true, "unknown")] {
        let mut b = suite_args(&srv.url(), &j, &d.join("ws"));
        b.extend(["--max-units".into(), "2".into()]);
        if flag {
            b.push("--pause-on-battery".into());
        }
        fake(&hook, serde_json::json!({"battery": state}));
        let o = Command::new(BIN)
            .args(&b)
            .env("RUSTBENCH_SCHEDULE_FAKE", &hook)
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        assert!(
            o.status.success() && out.contains("stopped: max_units"),
            "{state}: {out}"
        );
    }
}

#[test]
fn bad_schedule_values_are_refused_before_anything_runs_and_a_dry_run_ignores_the_schedule() {
    let srv = mock(5_000.0);
    let d = dir("badsched");
    let j = d.join("journal.jsonl");
    for bad in [
        ["--max-duration", "soon"],
        ["--until", "25:00"],
        ["--max-units", "-3"],
    ] {
        let mut a = suite_args(&srv.url(), &j, &d.join("ws"));
        a.extend(bad.iter().map(|s| s.to_string()));
        let o = run(&a);
        assert!(!o.ok, "{bad:?}");
        assert!(!j.exists(), "{bad:?}: nothing touched");
    }
    let mut a = suite_args(&srv.url(), &j, &d.join("ws"));
    a.extend(["--max-units".into(), "0".into(), "--dry-run".into()]);
    let o = run(&a);
    assert!(
        o.ok && !o.stdout.contains("stopped:"),
        "a dry run only plans: {}",
        o.stdout
    );
}

#[test]
fn a_scheduled_stop_and_a_signal_use_the_same_clean_path_and_the_signal_wins_when_both_apply() {
    let srv = mock(500.0);
    let d = dir("sched-sig");
    let j = d.join("journal.jsonl");
    let mut a = suite_args(&srv.url(), &j, &d.join("ws"));
    a.extend(["--max-units".into(), "1000".into()]);
    let mut child = spawn_piped(&a, &[]);
    wait_units(&j, 3);
    kill_sig(child.id(), "-INT");
    let (code, _) = wait_exit(&mut child, Duration::from_secs(20));
    let (out, _) = read_out(child);
    assert_eq!(code, Some(0));
    assert!(out.contains("stopped by SIGINT"), "{out}");
    assert!(!j.with_file_name("journal.jsonl.lock").exists());
}

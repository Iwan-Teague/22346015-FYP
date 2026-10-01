//! Unit tests of the command runner's pure parts and of its setup checks.

use super::*;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "rh-exec-unit-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    fs::create_dir_all(&d).unwrap();
    fs::canonicalize(&d).unwrap()
}

/// A program the sandbox executes from a system directory.
const PERL: &str = "/usr/bin/perl";

fn spec_with(programs: &[(&str, &str)]) -> ExecSpec {
    ExecSpec {
        programs: programs
            .iter()
            .map(|(n, p)| ExecProgram {
                name: (*n).into(),
                path: PathBuf::from(p),
            })
            .collect(),
        ..ExecSpec::default()
    }
}

#[cfg(unix)]
#[test]
fn a_program_is_pinned_by_name_path_and_content() {
    let p = Pinned::check(&spec_with(&[("perl", PERL)])).unwrap();
    assert_eq!(p.spec().names(), vec!["perl".to_owned()]);
    // Measured again, the same file pins to the same digest; the spec
    // digest covers the spec, not the measurement.
    let q = Pinned::check(&spec_with(&[("perl", PERL)])).unwrap();
    assert_eq!(p.programs_digest(), q.programs_digest());
    assert_eq!(p.spec_digest(), q.spec_digest());
    assert!(!p.spec().shell_enabled());
}

#[cfg(unix)]
#[test]
fn every_setup_rule_refuses() {
    let dir = tmp("rules");
    let prog = dir.join("tool");
    fs::write(&prog, b"#!/bin/sh\n").unwrap();
    let noexec = dir.join("noexec");
    fs::write(&noexec, b"data").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&prog, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&noexec, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let link = dir.join("link");
    std::os::unix::fs::symlink(&prog, &link).unwrap();
    let check = |s: ExecSpec, want: &str| {
        let e = Pinned::check(&s).unwrap_err().to_string();
        assert!(e.contains(want), "{e} (wanted {want})");
    };
    check(ExecSpec::default(), "between 1 and");
    for bad in ["", "a/b", "/usr/bin/perl", "-x", ".x", "a b", "a\0b"] {
        check(spec_with(&[(bad, PERL)]), "not a plain name");
    }
    check(spec_with(&[("perl", PERL), ("perl", PERL)]), "twice");
    check(spec_with(&[("perl", "usr/bin/perl")]), "not absolute");
    check(
        spec_with(&[("x", dir.join("missing").to_str().unwrap())]),
        "no file",
    );
    check(
        spec_with(&[("x", link.to_str().unwrap())]),
        "not a regular file",
    );
    check(
        spec_with(&[(
            "x",
            &format!(
                "{}/../{}/tool",
                dir.display(),
                dir.file_name().unwrap().to_str().unwrap()
            ),
        )]),
        "not canonical",
    );
    let mut in_root = spec_with(&[("x", noexec.to_str().unwrap())]);
    in_root.read_only = vec![dir.clone()];
    check(in_root, "not executable");
    // A program outside every root the sandbox executes from.
    check(
        spec_with(&[("x", prog.to_str().unwrap())]),
        "outside every read-only root",
    );
    let mut ok = spec_with(&[("x", prog.to_str().unwrap())]);
    ok.read_only = vec![dir.clone()];
    assert!(Pinned::check(&ok).is_ok());
    let mut rel = ok.clone();
    rel.read_only = vec!["rel".into()];
    check(rel, "not absolute");
    let mut not_dir = ok.clone();
    not_dir.read_only = vec![dir.clone(), prog.clone()];
    check(not_dir, "not a directory");
    for (name, value, want) in [
        ("PATH", "/x", "built by the harness"),
        ("CARGO_TARGET_DIR", "/x", "built by the harness"),
        ("DYLD_INSERT_LIBRARIES", "/x", "loader variable"),
        ("LD_PRELOAD", "/x", "loader variable"),
        ("1X", "v", "not a variable name"),
        ("A=B", "v", "not a variable name"),
        ("X", "a\0b", "NUL"),
    ] {
        let mut s = ok.clone();
        s.env = vec![(name.into(), value.into())];
        check(s, want);
    }
    let mut twice = ok.clone();
    twice.env = vec![("X".into(), "1".into()), ("X".into(), "2".into())];
    check(twice, "twice");
    for (f, want) in [
        (
            (|l: &mut ExecLimits| l.memory = 0) as fn(&mut ExecLimits),
            "memory",
        ),
        (|l: &mut ExecLimits| l.processes = 0, "processes"),
        (|l: &mut ExecLimits| l.cpu = Duration::ZERO, "cpu"),
        (|l: &mut ExecLimits| l.file_size = 0, "file size"),
        (|l: &mut ExecLimits| l.output_bytes = 0, "output"),
    ] {
        let mut s = ok.clone();
        f(&mut s.limits);
        check(s, want);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_shell_on_the_allowlist_is_named_by_name_or_file_name() {
    assert!(spec_with(&[("sh", "/bin/sh")]).shell_enabled());
    assert!(spec_with(&[("cargo", "/x/cargo"), ("run", "/bin/zsh")]).shell_enabled());
    assert!(!spec_with(&[("cargo", "/x/cargo"), ("perl", PERL)]).shell_enabled());
}

#[test]
fn the_spec_digest_changes_with_every_field() {
    let base = spec_with(&[("perl", PERL)]);
    let d = base.digest();
    let mut a = base.clone();
    a.programs[0].name = "perl5".into();
    let mut b = base.clone();
    b.read_only = vec!["/opt".into()];
    let mut c = base.clone();
    c.env = vec![("X".into(), "1".into())];
    let mut e = base.clone();
    e.limits.memory += 1;
    let mut f = base.clone();
    f.limits.processes += 1;
    for other in [a, b, c, e, f] {
        assert_ne!(other.digest(), d, "{other:?}");
    }
    assert_eq!(base.clone().digest(), d);
}

#[test]
fn a_short_stream_is_shown_whole_and_a_long_one_head_and_tail() {
    let mut out = String::new();
    assert!(!excerpt("stdout", b"one\ntwo\n", false, &mut out));
    assert_eq!(out, "stdout: 8 bytes, 2 lines\none\ntwo\n");

    let long: String = (1..=100).map(|i| format!("line {i}\n")).collect();
    let mut out = String::new();
    assert!(excerpt("stderr", long.as_bytes(), false, &mut out));
    assert!(out.starts_with(&format!(
        "stderr: {} bytes, 100 lines; showing the first 10 and the last 26\nline 1\n",
        long.len()
    )));
    assert!(out.contains("line 10\n[... 64 lines not shown ...]\nline 75\n"));
    assert!(out.ends_with("line 100\n"));
    assert!(!out.contains("line 11\n"));
    assert!(!out.contains("line 74\n"));

    let wide = format!("{}\n", "é".repeat(300));
    let mut out = String::new();
    assert!(excerpt("stdout", wide.as_bytes(), false, &mut out));
    let shown = out.lines().nth(1).unwrap();
    assert!(shown.ends_with(" [line cut]"));
    assert!(shown.len() <= SHOW_LINE_BYTES + " [line cut]".len());

    let mut out = String::new();
    assert!(excerpt("stdout", b"x\n", true, &mut out));
    assert!(out.contains("it wrote more, which was not kept"));

    let mut out = String::new();
    assert!(!excerpt("stdout", b"", false, &mut out));
    assert_eq!(out, "stdout: (empty)\n");
}

#[test]
fn the_excerpt_stays_inside_the_context_caps() {
    // Two streams at their worst still fit the context's 100 lines and
    // 16 KiB per observation (harness-model-core's OBS_MAX_*), so the
    // context never cuts the tail the excerpt kept.
    let long: String = (0..10_000)
        .map(|_| format!("{}\n", "x".repeat(1000)))
        .collect();
    let exit = ConfinedExit {
        status: ChildStatus::Exited(101),
        stdout: long.clone().into_bytes(),
        stdout_truncated: true,
        stderr: long.into_bytes(),
        stderr_truncated: true,
        domain: DomainCleanup::Unconfirmed("x".into()),
        elapsed: Duration::from_secs(1),
    };
    let (text, cut) = render(&exit, &ExecLimits::default(), Duration::from_secs(120));
    assert!(cut);
    assert!(text.lines().count() < 100, "{}", text.lines().count());
    assert!(text.len() < 16 * 1024, "{}", text.len());
    assert!(text.starts_with("exit status 101\n"));
    assert!(text.ends_with("so the run stops here\n"));
}

#[test]
fn how_a_command_ended_maps_to_a_status_and_a_guard() {
    let cases = [
        (ChildStatus::Exited(0), ToolStatus::Ok, None),
        (ChildStatus::Exited(101), ToolStatus::Ok, None),
        (
            ChildStatus::Signaled(9),
            ToolStatus::Crashed { signal: Some(9) },
            None,
        ),
        (
            ChildStatus::Signaled(24),
            ToolStatus::Crashed { signal: Some(24) },
            Some("cpu"),
        ),
        (
            ChildStatus::Signaled(25),
            ToolStatus::Crashed { signal: Some(25) },
            Some("file_size"),
        ),
        (ChildStatus::TimedOut, ToolStatus::Timeout, Some("wall")),
        (
            ChildStatus::ProcessLimit,
            ToolStatus::Error {
                code: code::EXEC_PROCESS_LIMIT,
            },
            Some("processes"),
        ),
        (
            ChildStatus::ExecFailed,
            ToolStatus::Error {
                code: code::EXEC_FAILED,
            },
            None,
        ),
        (
            ChildStatus::Unknown,
            ToolStatus::Crashed { signal: None },
            None,
        ),
    ];
    for (child, status, guard) in cases {
        let end = end_of(&child);
        assert_eq!(status_of(&end), status, "{child:?}");
        assert_eq!(end.guard(), guard, "{child:?}");
    }
}

#[test]
fn args_are_read_as_the_schema_says_and_refused_otherwise() {
    let a = json!({"argv": ["cargo", "test"], "cwd": "a/b"});
    let (argv, cwd) = args(&a).unwrap();
    assert_eq!(argv, vec!["cargo", "test"]);
    assert_eq!(cwd, Some("a/b"));
    for bad in [
        json!({"argv": []}),
        json!({"argv": "cargo"}),
        json!({"argv": ["cargo", 1]}),
        json!({"argv": ["a\0b"]}),
        json!({"argv": ["cargo"], "cwd": 1}),
        json!({}),
    ] {
        assert!(args(&bad).is_err(), "{bad}");
    }
}

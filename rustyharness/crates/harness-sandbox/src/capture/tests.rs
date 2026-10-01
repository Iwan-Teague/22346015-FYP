//! Tests of the bounded capture. A test file: purity.sh §2f lets it spawn
//! freely, because `capture.rs` declares it `#[cfg(test)]`.

use super::*;

#[test]
fn a_clean_exit_returns_its_output_with_a_c_locale_and_no_inherited_env() {
    let mut c = Command::new("/bin/sh");
    c.args(["-c", "echo \"$LC_ALL:${HOME:-unset}\""]);
    assert_eq!(capture(c, CAPTURE_DEADLINE).unwrap(), b"C:unset\n");
}

#[test]
fn failure_oversize_and_a_hang_are_errors() {
    let mut c = Command::new("/bin/sh");
    c.args(["-c", "exit 3"]);
    assert!(capture(c, CAPTURE_DEADLINE).unwrap_err().contains("exited"));

    let mut c = Command::new("/bin/sh");
    c.args(["-c", "head -c 5000000 /dev/zero"]);
    let big = capture(c, CAPTURE_DEADLINE).unwrap_err();
    assert!(big.contains("over the cap"), "{big}");

    let t = Instant::now();
    let mut c = Command::new("/bin/sh");
    c.args(["-c", "exec sleep 30"]);
    let hung = capture(c, Duration::from_millis(200)).unwrap_err();
    assert!(hung.contains("deadline"), "{hung}");
    assert!(t.elapsed() < Duration::from_secs(10));

    // Output complete, but the child lingers: still an error.
    let mut c = Command::new("/bin/sh");
    c.args(["-c", "echo x; exec 1>&- sleep 30"]);
    let lingering = capture(c, Duration::from_millis(300)).unwrap_err();
    assert!(lingering.contains("did not exit"), "{lingering}");
}

#[test]
fn each_query_is_its_fixed_program_and_argv() {
    let shape = |q: Query| {
        let c = q.command();
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        (c.get_program().to_string_lossy().into_owned(), args)
    };
    assert_eq!(shape(Query::Mount), ("/sbin/mount".into(), vec![]));
    assert_eq!(
        shape(Query::Sysctl),
        (
            "/usr/sbin/sysctl".into(),
            vec![
                "-n".into(),
                "vm.loadavg".into(),
                "hw.memsize".into(),
                "hw.logicalcpu".into()
            ]
        )
    );
    assert_eq!(shape(Query::VmStat), ("/usr/bin/vm_stat".into(), vec![]));
}

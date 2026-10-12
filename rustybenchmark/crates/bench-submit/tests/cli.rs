//! The consent gate and the file-level behaviour of `export`, exercised through the same
//! functions the `rustybench` binary calls.

mod common;
use bench_submit::cli::{
    consent_cmd, export, export_to, prepare, ConsentAction, ConsentArgs, ExportArgs,
};
use bench_submit::verify::{verify_bytes, VerifyOptions};
use common::*;
use std::path::{Path, PathBuf};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rb-submit-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn args(dir: &Path) -> ExportArgs {
    std::fs::write(dir.join("journal.jsonl"), sample_journal()).unwrap();
    std::fs::write(dir.join("hw.json"), hw_profile_json()).unwrap();
    ExportArgs {
        journal: dir.join("journal.jsonl"),
        hw: dir.join("hw.json"),
        identity: None,
        run_id: None,
        out: Some(dir.join("bundle.json")),
        force: false,
        dry_run: false,
        consent: vec![],
        remember_consent: false,
        consent_file: dir.join("consent.json"),
        no_submit: false,
    }
}

fn files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn export_refuses_without_consent_and_writes_nothing() {
    let d = tmp("noconsent");
    let a = args(&d);
    let e = export(&a).unwrap_err().to_string();
    assert!(e.contains("no consent recorded"), "{e}");
    assert!(!d.join("bundle.json").exists());
    assert!(
        !d.join("consent.json").exists(),
        "a refusal must not record anything"
    );
}

#[test]
fn explicit_consent_exports_a_bundle_that_verifies() {
    let d = tmp("consent");
    let mut a = args(&d);
    a.consent = vec!["public-scores".into()];
    export(&a).unwrap();
    let bytes = std::fs::read(d.join("bundle.json")).unwrap();
    let r = verify_bytes(&bytes, &VerifyOptions::default());
    assert!(r.ok(), "{}", r.render());
    // A flag grants this export only; nothing is remembered unless asked.
    assert!(!d.join("consent.json").exists());
    // What a dry run would print is what the real export wrote.
    assert_eq!(prepare(&a).unwrap().bytes, bytes);
}

#[test]
fn will_not_overwrite_without_force() {
    let d = tmp("overwrite");
    let mut a = args(&d);
    a.consent = vec!["public-scores".into()];
    export(&a).unwrap();
    let e = export(&a).unwrap_err().to_string();
    assert!(e.contains("exists"), "{e}");
    a.force = true;
    export(&a).unwrap();
}

#[test]
fn remembered_consent_covers_later_exports_until_revoked() {
    let d = tmp("remember");
    let mut a = args(&d);
    a.consent = vec!["public-scores".into()];
    a.remember_consent = true;
    export(&a).unwrap();
    assert!(d.join("consent.json").exists());

    let mut b = args(&d);
    b.out = Some(d.join("second.json"));
    export(&b).expect("stored consent applies");

    consent_cmd(&ConsentArgs {
        action: ConsentAction::Revoke,
        file: d.join("consent.json"),
    })
    .unwrap();
    b.out = Some(d.join("third.json"));
    let e = export(&b).unwrap_err().to_string();
    assert!(e.contains("revoked"), "{e}");
    assert!(!d.join("third.json").exists());
}

#[test]
fn grant_command_records_consent() {
    let d = tmp("grant");
    consent_cmd(&ConsentArgs {
        action: ConsentAction::Grant { yes: true },
        file: d.join("c.json"),
    })
    .unwrap();
    let mut a = args(&d);
    a.consent_file = d.join("c.json");
    export(&a).expect("granted via `consent grant`");
}

#[test]
fn no_submit_beats_every_consent() {
    let d = tmp("nosubmit");
    let mut a = args(&d);
    a.consent = vec!["public-scores".into()];
    a.no_submit = true;
    let e = export(&a).unwrap_err().to_string();
    assert!(e.contains("--no-submit"), "{e}");
    assert!(!d.join("bundle.json").exists());
}

#[test]
fn dry_run_needs_no_consent_and_writes_nothing() {
    let d = tmp("dry");
    let mut a = args(&d);
    a.dry_run = true;
    let before = files(&d);
    let mut printed = Vec::new();
    export_to(&a, &mut printed).unwrap();
    assert_eq!(files(&d), before, "dry run must not create any file");
    // Even with --out given and consent granted: still nothing written.
    a.consent = vec!["public-scores".into()];
    a.remember_consent = true;
    let mut printed2 = Vec::new();
    export_to(&a, &mut printed2).unwrap();
    assert_eq!(files(&d), before);
    assert_eq!(printed, printed2);
    // What the dry run printed is byte for byte what a real export writes.
    a.dry_run = false;
    export(&a).unwrap();
    assert_eq!(std::fs::read(d.join("bundle.json")).unwrap(), printed);
}

#[test]
fn unavailable_consents_are_refused() {
    let d = tmp("unavail");
    for k in ["replay-artifacts", "audit-contact", "bogus"] {
        let mut a = args(&d);
        a.consent = vec!["public-scores".into(), k.into()];
        assert!(export(&a).is_err(), "{k}");
        assert!(!d.join("bundle.json").exists());
    }
}

#[test]
fn missing_out_or_inputs_are_clear_errors() {
    let d = tmp("missing");
    let mut a = args(&d);
    a.consent = vec!["public-scores".into()];
    a.out = None;
    assert!(export(&a).unwrap_err().to_string().contains("--out"));
    let mut a = args(&d);
    a.consent = vec!["public-scores".into()];
    a.hw = d.join("nope.json");
    assert!(export(&a).unwrap_err().to_string().contains("hw file"));
}

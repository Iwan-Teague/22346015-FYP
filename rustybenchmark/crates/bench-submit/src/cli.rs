//! The `rustybench export`, `verify-bundle` and `consent` subcommands. Argument structs live
//! here (not in `bench-cli`) so wiring them into the binary is three enum variants and three
//! match arms, which keeps `main.rs` merges small.

use crate::bundle::{build, BuildInputs, BuildOptions, Built};
use crate::consent::{self, Basis, Consent, ConsentRecord, TERMS_TEXT, TERMS_VERSION};
use crate::error::SubmitError;
use crate::redact::LocalFacts;
use crate::verify::{verify_bytes, VerifyOptions};
use clap::{Args, Subcommand};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Graded journal written by `run` / `run-suite`.
    #[arg(long, default_value = "runs/journal.jsonl")]
    pub journal: PathBuf,
    /// Hardware profile from `rustybench hw --json > runs/hw.json` (only its bucketed public
    /// view is ever used; the raw profile is never copied).
    #[arg(long, default_value = "runs/hw.json")]
    pub hw: PathBuf,
    /// Optional identity description: a `state.json` (docs/12) or its `identity` object.
    #[arg(long)]
    pub identity: Option<PathBuf>,
    /// Explicit run id; otherwise derived from the units.
    #[arg(long)]
    pub run_id: Option<String>,
    /// Where to write the bundle. Required unless `--dry-run`. Refuses to overwrite.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Overwrite `--out` if it exists.
    #[arg(long)]
    pub force: bool,
    /// Print exactly the bytes that would be exported to stdout, a summary to stderr, and write
    /// nothing. Needs no consent: this is how you review before consenting.
    #[arg(long)]
    pub dry_run: bool,
    /// Grant a consent for this export (`public-scores`).
    #[arg(long = "consent", value_name = "KIND")]
    pub consent: Vec<String>,
    /// With `--consent public-scores`: also record it in `--consent-file`.
    #[arg(long)]
    pub remember_consent: bool,
    #[arg(long, default_value = "runs/consent.json")]
    pub consent_file: PathBuf,
    /// Never export. Wins over every consent (as does `RUSTBENCH_SUBMIT=0`).
    #[arg(long)]
    pub no_submit: bool,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// A bundle written by `rustybench export`.
    pub file: PathBuf,
    /// Skip re-running bench-stats over the units (the slow check).
    #[arg(long)]
    pub no_rederive: bool,
}

#[derive(Args, Debug)]
pub struct ConsentArgs {
    #[command(subcommand)]
    pub action: ConsentAction,
    #[arg(long, global = true, default_value = "runs/consent.json")]
    pub file: PathBuf,
}

#[derive(Subcommand, Debug)]
pub enum ConsentAction {
    /// Print the consent text and the stored decision.
    Show,
    /// Record consent 1 (publish redacted scores + licence). Asks for `yes` unless `--yes`.
    Grant {
        #[arg(long)]
        yes: bool,
    },
    /// Record that consent is withdrawn.
    Revoke,
}

type CliResult = Result<(), Box<dyn std::error::Error>>;

fn read(path: &Path, what: &str) -> Result<String, SubmitError> {
    std::fs::read_to_string(path)
        .map_err(|e| SubmitError::Io(format!("{what} {}: {e}", path.display())))
}

fn human_bytes(n: usize) -> String {
    if n >= 1 << 20 {
        format!("{:.2} MiB ({n} bytes)", n as f64 / (1 << 20) as f64)
    } else if n >= 1 << 10 {
        format!("{:.1} KiB ({n} bytes)", n as f64 / 1024.0)
    } else {
        format!("{n} bytes")
    }
}

fn summary(b: &Built) -> String {
    let r = &b.redactions;
    let kinds = if r.0.is_empty() {
        "none needed".to_string()
    } else {
        r.0.iter()
            .map(|(k, n)| format!("{k}={n}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    for n in &b.journal_notes {
        eprintln!("journal: {n}");
    }
    format!(
        "units {} ({} core, {} probe) · size {} · hash {} · redactions: {} · unrecorded fields: {}",
        b.units,
        b.core,
        b.probe,
        human_bytes(b.bytes.len()),
        b.bundle.content_hash,
        kinds,
        b.bundle.body.unrecorded.len()
    )
}

/// Read the inputs and build the bundle (no consent logic, no writing). Both the dry run and the
/// real export go through here, so what `--dry-run` prints is what a real export writes.
pub fn prepare(a: &ExportArgs) -> Result<Built, SubmitError> {
    let journal = read(&a.journal, "journal")?;
    let hw = read(&a.hw, "hw file")?;
    let identity = a
        .identity
        .as_deref()
        .map(|p| read(p, "identity file"))
        .transpose()?;
    build(
        &BuildInputs {
            journal: &journal,
            hw_json: &hw,
            identity_json: identity.as_deref(),
            run_id: a.run_id.as_deref(),
        },
        &BuildOptions {
            facts: LocalFacts::detect(),
            ..Default::default()
        },
    )
}

pub fn export(a: &ExportArgs) -> CliResult {
    export_to(a, &mut std::io::stdout())
}

/// As [`export`], with the dry-run payload going to `stdout` (so tests can capture it).
pub fn export_to(a: &ExportArgs, stdout: &mut dyn Write) -> CliResult {
    let flags = a
        .consent
        .iter()
        .map(|s| Consent::parse(s))
        .collect::<Result<Vec<_>, _>>()?;
    let env = std::env::var("RUSTBENCH_SUBMIT").ok();

    // The gate comes first for a real export: nothing is read or built for a user who has
    // not agreed. A dry run needs no consent (it is how the user decides) and writes nothing.
    let basis = if a.dry_run {
        None
    } else {
        let stored = consent::load(&a.consent_file)?;
        Some(consent::decide(
            a.no_submit,
            env.as_deref(),
            &flags,
            stored.as_ref(),
        )?)
    };
    let out = match (&a.out, a.dry_run) {
        (_, true) => None,
        (Some(p), false) => Some(p.clone()),
        (None, false) => {
            return Err(SubmitError::Input("--out is required (or use --dry-run)".into()).into())
        }
    };

    let built = prepare(a)?;

    if a.dry_run {
        // stdout is exactly the upload bytes, so `--dry-run > f` equals a real export to `f`.
        stdout.write_all(&built.bytes)?;
        eprintln!("--- dry run: nothing written, nothing sent ---");
        eprintln!("{}", summary(&built));
        eprintln!(
            "consents block in this bundle: public_scores=true (terms {TERMS_VERSION}); a real export requires you to grant it \
             (`--consent public-scores` or `rustybench consent grant`). Read the terms: `rustybench consent show`."
        );
        if a.no_submit || std::env::var("RUSTBENCH_SUBMIT").is_ok_and(|v| v.trim() == "0") {
            eprintln!("note: submission is switched off (--no-submit / RUSTBENCH_SUBMIT=0); a real export would be refused.");
        }
        return Ok(());
    }

    if let Some(path) = out {
        write_new(&path, &built.bytes, a.force)?;
        eprintln!("wrote {}", path.display());
    }
    // Only after the bundle exists: a failed export must not leave a consent record behind.
    if a.remember_consent && basis == Some(Basis::Flag) {
        consent::save(&a.consent_file, &ConsentRecord::grant_now())?;
        eprintln!("consent recorded in {}", a.consent_file.display());
    }
    eprintln!("{}", summary(&built));
    eprintln!(
        "Nothing was sent: this build has no network path. Verify with `rustybench verify-bundle`."
    );
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], force: bool) -> Result<(), SubmitError> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            SubmitError::Io(format!(
                "{} exists (use --force to overwrite)",
                path.display()
            ))
        } else {
            SubmitError::Io(format!("{}: {e}", path.display()))
        }
    })?;
    f.write_all(bytes)?;
    Ok(())
}

pub fn verify_bundle(a: &VerifyArgs) -> CliResult {
    let bytes = std::fs::read(&a.file)
        .map_err(|e| SubmitError::Io(format!("{}: {e}", a.file.display())))?;
    let report = verify_bytes(
        &bytes,
        &VerifyOptions {
            facts: LocalFacts::detect(),
            rederive: !a.no_rederive,
        },
    );
    print!("{}", report.render());
    if report.ok() {
        Ok(())
    } else {
        Err(SubmitError::Refused("bundle failed verification".into()).into())
    }
}

pub fn consent_cmd(a: &ConsentArgs) -> CliResult {
    match &a.action {
        ConsentAction::Show => {
            println!("{TERMS_TEXT}");
            match consent::load(&a.file)? {
                None => println!("stored decision: none ({})", a.file.display()),
                Some(r) => println!(
                    "stored decision: public_scores={} under terms {} ({})",
                    r.public_scores,
                    r.terms_version,
                    if r.terms_version == TERMS_VERSION && r.terms_hash == consent::terms_hash() {
                        "current"
                    } else {
                        "STALE: re-consent required"
                    }
                ),
            }
            Ok(())
        }
        ConsentAction::Grant { yes } => {
            if !yes {
                println!("{TERMS_TEXT}");
                eprint!("Type `yes` to grant consent 1: ");
                std::io::stderr().flush().ok();
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line)?;
                if line.trim() != "yes" {
                    return Err(SubmitError::Consent(
                        "not granted (expected exactly `yes`)".into(),
                    )
                    .into());
                }
            }
            consent::save(&a.file, &ConsentRecord::grant_now())?;
            eprintln!(
                "consent 1 recorded in {} (terms {TERMS_VERSION})",
                a.file.display()
            );
            Ok(())
        }
        ConsentAction::Revoke => {
            consent::save(&a.file, &ConsentRecord::revoked_now())?;
            eprintln!(
                "consent withdrawn in {}. Already-published CC BY 4.0 data cannot be recalled; deletion of \
                 server-side rows needs the submission service, which this build does not have.",
                a.file.display()
            );
            Ok(())
        }
    }
}

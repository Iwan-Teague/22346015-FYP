//! The run bundle (P-14, OD-5(d)): after a `run` commits, its resolved
//! task, profile and policy — the exact bytes the run was given — are
//! copied into `runs/<id>/inputs/` (0600, digests equal to the header's),
//! with a `bundle.json` recording the endpoint, workspace and the three
//! input digests. `replay --run <id>` and `resume --run <id>` then need no
//! other flags: missing flags are filled from the bundle, and whatever the
//! flags or the config still choose is refused unless it digests to the
//! recorded values (the audit's own header comparison stays the second
//! line of defence). A bundle is convenience, never evidence: writing one
//! that fails its self-check only reports, and a bundle whose digests do
//! not match what it would feed is refused before anything runs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use harness_core::{sha256, Digest, RunId};
use harness_journal::layout;

use crate::cmd_profile::write_private;
use crate::config;
use crate::inputs::{self, InputDigests};
use crate::report::{exit, refused, Outcome};
use crate::Cx;

/// The bundle manifest's name inside `runs/<id>/inputs/`.
const BUNDLE_FILE: &str = "bundle.json";
const TASK_FILE: &str = "task.json";
const PROFILE_FILE: &str = "profile.json";
const POLICY_FILE: &str = "policy.json";
/// The bundle format tag, refused if it is anything else.
const FORMAT: &str = "rh-bundle/1";
/// The paths the bundle can fill in, in fill order.
const FILLABLE: [&str; 3] = ["task", "profile", "policy"];

/// `bundle.json` as it is stored (strict JSON on read, bounded).
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct BundleDoc {
    format: String,
    endpoint: String,
    workspace: String,
    /// `"policy.json"` or `"default"` (the run used the default policy).
    policy: String,
    task_sha256: String,
    profile_sha256: String,
    policy_sha256: String,
}

/// A bundle read from `runs/<id>/inputs/`.
struct Bundle {
    inputs_dir: PathBuf,
    endpoint: String,
    workspace: String,
    /// `Some(POLICY_FILE)` when the run used a policy file, `None` for the
    /// default policy.
    policy_file: Option<String>,
    task: Digest,
    profile: Digest,
    policy: Digest,
}

fn digest_field(what: &str, hex: &str) -> Result<Digest, String> {
    hex.parse()
        .map_err(|_| format!("{BUNDLE_FILE}: {what}_sha256 is not a sha256 in hex"))
}

impl Bundle {
    /// The bundle for `inputs_dir`, or `None` when there is none. A bundle
    /// that is there but unusable is an error, never a silent absence.
    fn load(inputs_dir: &Path) -> Result<Option<Bundle>, String> {
        let path = inputs_dir.join(BUNDLE_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        if bytes.len() > inputs::INPUT_MAX_BYTES as usize {
            return Err(format!("{} is larger than 1 MiB", path.display()));
        }
        let bad = |e: String| format!("{}: {e}", path.display());
        let v = harness_core::strict_json::parse(&bytes)
            .map_err(|e| bad(format!("not strict JSON: {e}")))?;
        let doc: BundleDoc =
            serde_json::from_value(v).map_err(|e| bad(format!("unexpected shape: {e}")))?;
        if doc.format != FORMAT {
            return Err(bad(format!("format is {:?}, not {FORMAT:?}", doc.format)));
        }
        let policy_file = match doc.policy.as_str() {
            POLICY_FILE => Some(POLICY_FILE.to_owned()),
            "default" => None,
            other => {
                return Err(bad(format!(
                    "policy is {other:?}, not a bundle file or \"default\""
                )))
            }
        };
        let endpoint = non_empty(&doc.endpoint).map_err(|e| bad(format!("endpoint: {e}")))?;
        let workspace = non_empty(&doc.workspace).map_err(|e| bad(format!("workspace: {e}")))?;
        Ok(Some(Bundle {
            inputs_dir: inputs_dir.to_owned(),
            endpoint,
            workspace,
            policy_file,
            task: digest_field("task", &doc.task_sha256).map_err(bad)?,
            profile: digest_field("profile", &doc.profile_sha256).map_err(bad)?,
            policy: digest_field("policy", &doc.policy_sha256).map_err(bad)?,
        }))
    }

    /// The recorded digest for one of the `FILLABLE` inputs.
    fn digest_of(&self, key: &str) -> Digest {
        match key {
            "task" => self.task,
            "profile" => self.profile,
            _ => self.policy,
        }
    }

    /// The file an input would be read from after the fill: the bundle's
    /// copy, for the keys it can fill.
    fn fill_path(&self, key: &str) -> Option<String> {
        let name = match (key, &self.policy_file) {
            ("task", _) => TASK_FILE,
            ("profile", _) => PROFILE_FILE,
            ("policy", Some(f)) => f.as_str(),
            _ => return None,
        };
        Some(self.inputs_dir.join(name).to_string_lossy().into_owned())
    }
}

fn non_empty(s: &str) -> Result<String, String> {
    if s.is_empty() {
        Err("must not be empty".into())
    } else {
        Ok(s.to_owned())
    }
}

fn unreadable(e: String) -> Outcome {
    refused(exit::UNREADABLE_INPUT, e)
}

/// Where a run's bundle lives.
fn inputs_dir(state_root: &Path, run: &RunId) -> PathBuf {
    layout::run_dir(state_root, run).join("inputs")
}

/// The workspace a run recorded, for `sessions`' listing. Display only:
/// anything unreadable is no workspace shown.
pub(crate) fn recorded_workspace(inputs_dir: &Path) -> Option<String> {
    Bundle::load(inputs_dir).ok().flatten().map(|b| b.workspace)
}

/// The run's first user text (the bundle's task copy), for `sessions`.
/// Display only: the journal carries its digest, never the text.
pub(crate) fn recorded_task_text(inputs_dir: &Path) -> Option<String> {
    let bytes = inputs::read_input(&inputs_dir.join(TASK_FILE).to_string_lossy()).ok()?;
    inputs::task_text(&bytes).ok()
}

/// Fill `o` from the run's bundle, for `resume` and `replay`: every fillable
/// flag that neither the command line nor the config provides is taken from
/// `runs/<id>/inputs/`, and `resume` also gets the endpoint and workspace.
/// Flags and config win; what they choose must digest to the bundle's
/// recorded values, or this is unreadable input (exit 4). A plain `run` (no
/// `--run`) and runs without a bundle are left as they were.
pub(crate) fn fill(
    cx: &Cx<'_>,
    o: &mut BTreeMap<&str, String>,
    cfg: &Option<config::UserConfig>,
) -> Result<(), Outcome> {
    let Some(run) = o.get("run").and_then(|r| RunId::parse(r)) else {
        return Ok(());
    };
    let view: BTreeMap<&str, &str> = o.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let state_root = match config::state_root(&view, cfg) {
        Ok(Some(s)) => s.into_owned(),
        Ok(None) => return Ok(()),
        Err(e) => {
            note!(cx, "{e}");
            return Err(unreadable(e));
        }
    };
    let bundle = match Bundle::load(&inputs_dir(Path::new(&state_root), &run)) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(()),
        Err(e) => {
            note!(cx, "{e}");
            return Err(unreadable(e));
        }
    };
    let fills: Vec<(&'static str, String)> = FILLABLE
        .iter()
        .filter_map(|key| {
            if config::value(&view, cfg, key).is_none() {
                bundle.fill_path(key).map(|p| (*key, p))
            } else {
                None
            }
        })
        .collect();
    let extras: Vec<(&'static str, String)> = ["endpoint", "workspace"]
        .iter()
        .filter_map(|key| {
            if config::value(&view, cfg, key).is_none() {
                let v = match *key {
                    "endpoint" => bundle.endpoint.clone(),
                    _ => bundle.workspace.clone(),
                };
                Some((*key, v))
            } else {
                None
            }
        })
        .collect();
    for (k, v) in fills {
        o.insert(k, v);
    }
    for (k, v) in extras {
        o.insert(k, v);
    }
    check_against_bundle(cx, o, cfg, &bundle)
}

/// Whatever the filled options and the config now choose must digest to the
/// bundle's recorded values (which equal the header's): a different task,
/// profile or policy is refused by name before anything runs.
fn check_against_bundle(
    cx: &Cx<'_>,
    o: &BTreeMap<&str, String>,
    cfg: &Option<config::UserConfig>,
    bundle: &Bundle,
) -> Result<(), Outcome> {
    let view: BTreeMap<&str, &str> = o.iter().map(|(k, v)| (*k, v.as_str())).collect();
    // The run digested its effective policy (P-12), so the deny overlay is
    // on here unless the flag that turned it off for the run is on too;
    // the accept-edits overlay (P-23) rides the same rule.
    let overlay = !o.contains_key("no-default-denies");
    let accept_edits = o.contains_key("accept-edits");
    let mismatch = |key: &str, path: &str| {
        let why = format!("{key} {path} does not match the digests recorded in the run's bundle");
        note!(cx, "{why}");
        unreadable(why)
    };
    for key in FILLABLE {
        let digest = match config::value(&view, cfg, key) {
            Some(path) => {
                let bytes = inputs::read_input(path).map_err(|e| {
                    let e = format!("{key} {e}");
                    note!(cx, "{e}");
                    unreadable(e)
                })?;
                match parse_digest(key, &bytes, overlay, accept_edits) {
                    Ok(d) => d,
                    Err(e) => {
                        note!(cx, "{e}");
                        return Err(unreadable(e));
                    }
                }
            }
            None if key == "policy" => {
                // The default policy as the run itself built it (the P-12
                // overlay applied unless `--no-default-denies`, the P-23
                // accept-edits overlay when that flag is on): one
                // spelling with `inputs`, so a recomputed digest differs
                // only on a real mismatch, refused below by name.
                crate::inputs::default_policy(
                    o.contains_key("no-default-denies"),
                    o.contains_key("accept-edits"),
                )
                .map_err(|e| {
                    note!(cx, "{e}");
                    unreadable(e)
                })?
                .digest()
            }
            // `--task`/`--profile` missing everything is the verb's usage
            // error; nothing here to compare.
            None => continue,
        };
        let recorded = bundle.digest_of(key);
        let path = config::value(&view, cfg, key).unwrap_or("the default policy");
        if digest != recorded {
            return Err(mismatch(key, path));
        }
    }
    Ok(())
}

/// The input digest `key` names, from the file's bytes. The policy is
/// digested the way the run digested it: under the same overlay settings.
fn parse_digest(
    key: &str,
    bytes: &[u8],
    overlay: bool,
    accept_edits: bool,
) -> Result<Digest, String> {
    match key {
        "task" => inputs::task_text(bytes).map(|t| sha256(t.as_bytes())),
        "profile" => inputs::profile_digest(bytes),
        _ => inputs::policy_digest(bytes, overlay, accept_edits),
    }
}

/// The paths the run's inputs came from (`None` policy: the default policy).
pub(crate) struct BundleSource<'a> {
    task: Option<&'a str>,
    profile: Option<&'a str>,
    policy: Option<&'a str>,
}

impl<'a> BundleSource<'a> {
    pub(crate) fn new(
        task: Option<&'a str>,
        profile: Option<&'a str>,
        policy: Option<&'a str>,
    ) -> Self {
        Self {
            task,
            profile,
            policy,
        }
    }
}

/// Write the run's bundle into `run_dir/inputs/` (0600 files, 0700 dir) and
/// self-check it: every copied file is re-read, re-parsed and digested, and
/// must equal the digests the run used (`expected`) and the header's own
/// `task`/`profile`/`policy` fields. The policy is digested under the run's
/// own overlay settings (`overlay`, P-12; `accept_edits`, P-23). Any
/// mismatch or write failure removes `bundle.json` (the copy is never
/// half-trusted) and says why. The run itself is already committed; the
/// bundle is convenience, so the caller only reports.
pub(crate) fn write_run_bundle(
    run_dir: &Path,
    src: &BundleSource<'_>,
    endpoint: &str,
    workspace: &str,
    expected: &InputDigests,
    overlay: bool,
    accept_edits: bool,
) -> Result<(), String> {
    let inputs_dir = run_dir.join("inputs");
    config::create_private_dir(&inputs_dir)?;
    let copy = |name: &str, key: &str, path: &str, want: Digest| -> Result<(), String> {
        let bytes = inputs::read_input(path)?;
        write_private(&inputs_dir.join(name), &bytes)?;
        let d = parse_digest(key, &bytes, overlay, accept_edits)?;
        if d != want {
            return Err(format!("{name} digests to {d}, not the run's {want}"));
        }
        Ok(())
    };
    let task_path = src.task.ok_or("the run's task file is unknown")?;
    let profile_path = src.profile.ok_or("the run's profile file is unknown")?;
    copy(TASK_FILE, "task", task_path, expected.task)?;
    copy(PROFILE_FILE, "profile", profile_path, expected.profile)?;
    let policy_kind = match src.policy {
        Some(p) => {
            copy(POLICY_FILE, "policy", p, expected.policy)?;
            POLICY_FILE.to_owned()
        }
        None => "default".to_owned(),
    };
    let doc = BundleDoc {
        format: FORMAT.to_owned(),
        endpoint: endpoint.to_owned(),
        workspace: workspace.to_owned(),
        policy: policy_kind,
        task_sha256: expected.task.to_string(),
        profile_sha256: expected.profile.to_string(),
        policy_sha256: expected.policy.to_string(),
    };
    let manifest =
        serde_json::to_vec_pretty(&doc).map_err(|e| format!("cannot render {BUNDLE_FILE}: {e}"))?;
    write_private(&inputs_dir.join(BUNDLE_FILE), &manifest)?;
    match self_check(run_dir, &inputs_dir, expected, overlay, accept_edits) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Never leave a manifest that does not describe its copies.
            let _ = std::fs::remove_file(inputs_dir.join(BUNDLE_FILE));
            Err(e)
        }
    }
}

/// Re-read what was written and compare it, digest by digest, with what the
/// run used and with the header.
fn self_check(
    run_dir: &Path,
    inputs_dir: &Path,
    expected: &InputDigests,
    overlay: bool,
    accept_edits: bool,
) -> Result<(), String> {
    let check = |name: &str, parse: &dyn Fn(&[u8]) -> Result<Digest, String>, want: Digest| {
        let bytes = inputs::read_input(&inputs_dir.join(name).to_string_lossy())
            .map_err(|e| format!("bundle self-check: {e}"))?;
        let d = parse(&bytes).map_err(|e| format!("bundle self-check: {e}"))?;
        if d != want {
            return Err(format!(
                "bundle self-check: {name} digests to {d}, not the run's {want}"
            ));
        }
        Ok(())
    };
    check(TASK_FILE, &task_digest, expected.task)?;
    check(PROFILE_FILE, &inputs::profile_digest, expected.profile)?;
    if inputs_dir.join(POLICY_FILE).exists() {
        check(
            POLICY_FILE,
            &|b| inputs::policy_digest(b, overlay, accept_edits),
            expected.policy,
        )?;
    }
    header_check(run_dir, expected)
}

/// The task text's digest, the way the header computes it.
fn task_digest(bytes: &[u8]) -> Result<Digest, String> {
    inputs::task_text(bytes).map(|t| sha256(t.as_bytes()))
}
fn header_check(run_dir: &Path, expected: &InputDigests) -> Result<(), String> {
    let n = layout::latest_attempt(run_dir)
        .map_err(|e| format!("bundle header check: {e}"))?
        .ok_or("bundle header check: no attempt directory")?;
    let v = harness_journal::JournalReader::open(&layout::attempt_dir(run_dir, n))
        .map_err(|e| format!("bundle header check: {e}"))?;
    let header = v
        .records
        .first()
        .ok_or("bundle header check: empty journal")?;
    let body_digest = |key: &str| -> Result<Digest, String> {
        header
            .body
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(format!("bundle header check: header has no {key}"))?
            .parse()
            .map_err(|_| format!("bundle header check: header {key} is not a digest"))
    };
    let pairs = [
        ("task", expected.task),
        ("profile", expected.profile),
        ("policy", expected.policy),
    ];
    for (key, want) in pairs {
        let d = body_digest(key)?;
        if d != want {
            return Err(format!(
                "bundle header check: header {key} is {d}, not the run's {want}"
            ));
        }
    }
    Ok(())
}

//! Adversarial redaction proofs. The property under test is end to end:
//!
//! > For every journal we can build, `build()` either REFUSES, or the produced bundle bytes
//! > contain none of the sensitive needles planted anywhere in the journal -- including inside
//! > nested model-derived text (violations, flags, error codes), the model name, extra fields
//! > the allow-list never reads, and the raw hardware profile.
//!
//! The needle list is written independently of the scrubber's implementation, so a gap in the
//! scrubber shows up here rather than being tautologically "redacted".

mod common;
use bench_submit::{build, BuildInputs};
use common::*;
use serde_json::{json, Value};

/// (fragment as it might appear in model/tool text, lower-case needles that must not survive)
const FRAGMENTS: &[(&str, &[&str])] = &[
    (
        "/Users/jdoe42/proj/src/lib.rs:12:5",
        &["jdoe42", "/users/", "src/lib.rs"],
    ),
    (
        "/home/alice/.cargo/registry/src/index.crates.io-6f17d22bba15001f/foo-1.0.0/src/lib.rs",
        &["alice", "/home/", ".cargo", "foo-1.0.0"],
    ),
    ("C:\\Users\\Bob\\Desktop\\a.rs", &["bob", "c:\\", "desktop"]),
    ("\\\\fileserver\\share\\x", &["fileserver"]),
    ("file:///Users/jdoe42/x", &["jdoe42", "file:"]),
    ("192.168.1.77", &["192.168.1.77"]),
    ("10.0.0.5:8080", &["10.0.0.5"]),
    ("[fe80::1c2b:3dff:fe4a:9b01]:443", &["fe80::1c2b", "9b01"]),
    ("2001:db8::ff00:42:8329", &["2001:db8", "8329"]),
    ("aa:bb:cc:dd:ee:ff", &["aa:bb:cc"]),
    ("AA-BB-CC-DD-EE-FF", &["aa-bb-cc"]),
    ("aabb.ccdd.eeff", &["aabb.ccdd"]),
    ("Jdoes-MacBook-Pro", &["macbook", "jdoes"]),
    ("Alices-MacBook-Air.local", &["macbook", "alices"]),
    ("mac-mini.lan", &["mac-mini"]),
    ("buildbox.corp.example.com", &["buildbox", "example.com"]),
    ("DESKTOP-AB12CD3", &["desktop-ab12"]),
    ("C02XG0FDH7JY", &["c02xg0fdh7jy"]),
    ("serial: F5K12345ABC", &["f5k12345abc"]),
    ("550e8400-e29b-41d4-a716-446655440000", &["550e8400"]),
    ("HOME=/Users/jdoe42", &["jdoe42", "/users/"]),
    ("RUST_LOG=trace", &["rust_log"]),
    ("PATH=/usr/local/bin:/usr/bin", &["/usr/"]),
    ("$HOME/.ssh/id_rsa", &["$home", ".ssh", "id_rsa"]),
    ("${XDG_CONFIG_HOME}/x", &["xdg_config"]),
    ("%USERPROFILE%\\x", &["userprofile"]),
    ("jdoe42@corp.example.com", &["jdoe42", "corp.example"]),
    (
        "https://user:pw@git.internal.corp/repo.git",
        &["git.internal", "pw@"],
    ),
    ("~/secrets/key.pem", &["secrets", "key.pem"]),
    ("jdoe42", &["jdoe42"]),
    ("JDOE42-finetune", &["jdoe42"]),
    ("user=alice", &["alice"]),
    ("hostname: ci-runner-17", &["ci-runner"]),
    (
        "--manifest-path=/Users/jdoe42/Cargo.toml",
        &["jdoe42", "cargo.toml"],
    ),
    ("0x7ffee4b3c8a0f1d2e3b4", &["7ffee4b3"]),
    ("--target-dir=/tmp/x", &["/tmp"]),
    ("j\u{200B}doe42", &["jdoe42", "j\u{200B}doe"]),
];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const TEMPLATES: &[&str] = &[
    "{}",
    "error: {} while building",
    "({})",
    "see {}.",
    "{}:12:5",
    "note: `{}` is not allowed",
    "\"{}\"",
    "a{}z",
    "path {} and {}",
];

fn dress(rng: &mut Rng, frags: &[usize]) -> (String, Vec<&'static str>) {
    let mut t = TEMPLATES[rng.below(TEMPLATES.len())];
    // `serial: X`, `hostname: X`, `user=X` are recognised by their keyword, bare serials and
    // `DESKTOP-XXXXXXX` by their exact shape; gluing letters onto the
    // keyword (`aserial: Xz`) leaves nothing to recognise, a documented limit of any scrubber.
    if t == "a{}z"
        && frags.iter().any(|&f| {
            ["serial:", "hostname:", "user=", "DESKTOP-", "C02XG"]
                .iter()
                .any(|k| FRAGMENTS[f].0.starts_with(k))
        })
    {
        t = " {} ";
    }
    let mut text = t.to_string();
    let mut needles: Vec<&'static str> = Vec::new();
    for &f in frags.iter().cycle().take(t.matches("{}").count()) {
        text = text.replacen("{}", FRAGMENTS[f].0, 1);
        needles.extend(FRAGMENTS[f].1.iter().copied());
    }
    (text, needles)
}

fn visible(bytes: &[u8]) -> String {
    // The `withheld` list legitimately names fields such as `seed`; nothing else may be
    // reflected. Needles are specific enough not to collide with it.
    String::from_utf8_lossy(bytes).to_lowercase()
}

fn assert_clean(bytes: &[u8], needles: &[&str], ctx: &str) {
    let text = visible(bytes);
    for n in needles {
        if let Some(pos) = text.find(&n.to_lowercase()) {
            let lo = pos.saturating_sub(80);
            let hi = (pos + 80).min(text.len());
            panic!("needle {n:?} survived ({ctx}) in ...{}...", &text[lo..hi]);
        }
    }
}

/// Every planted fragment, in every nested text field, in one journal.
#[test]
fn nested_model_text_is_scrubbed_everywhere() {
    for (i, (frag, needles)) in FRAGMENTS.iter().enumerate() {
        let mut ls = sample_lines();
        // Nested model/tool-derived text.
        ls[0]["oracle"]["constraint"]["violations"] = json!([format!("clippy: {frag}"), (*frag)]);
        ls[0]["oracle"]["flags"] = json!([format!("timeout:{frag}"), (*frag)]);
        ls[2]["oracle"]["error_codes"] = json!([*frag, "E0499"]);
        // Fields the allow-list never reads.
        for l in ls.iter_mut() {
            l["model"]["base_url"] = json!(format!("http://{frag}:8080"));
            l["cwd"] = json!(*frag);
            l["notes"] = json!({"deep": {"nested": [*frag]}});
            l["model"]["model_path"] = json!(*frag);
        }
        // The user-typed model name.
        for l in ls.iter_mut() {
            l["model"]["name"] = json!(format!("{frag}/model.gguf"));
        }
        let b = build(
            &BuildInputs {
                journal: &journal(&ls),
                hw_json: &hw_profile_json(),
                identity_json: None,
                run_id: None,
            },
            &opts(),
        );
        match b {
            Ok(b) => assert_clean(&b.bytes, needles, &format!("fragment #{i} {frag:?}")),
            Err(e) => {
                // Refusing is acceptable, but must not echo the value.
                let m = e.to_string().to_lowercase();
                for n in needles.iter() {
                    assert!(!m.contains(&n.to_lowercase()), "error echoed {n:?}: {m}");
                }
            }
        }
    }
}

/// The scrubbed fields are scrubbed, not merely refused: the common cases must succeed.
#[test]
fn free_text_fields_are_redacted_not_refused() {
    let mut ok = 0;
    for (frag, _) in FRAGMENTS {
        let mut ls = sample_lines();
        ls[0]["oracle"]["constraint"]["violations"] = json!([format!("violation {frag} here")]);
        ls[0]["oracle"]["flags"] = json!([format!("timeout:{frag}")]);
        ls[0]["oracle"]["error_codes"] = json!([*frag]);
        let b = build(
            &BuildInputs {
                journal: &journal(&ls),
                hw_json: &hw_profile_json(),
                identity_json: None,
                run_id: None,
            },
            &opts(),
        );
        match b {
            Ok(_) => ok += 1,
            Err(e) => eprintln!("REFUSED {frag:?}: {e}"),
        }
    }
    assert_eq!(
        ok,
        FRAGMENTS.len(),
        "free-text fields must never cause a refusal"
    );
}

/// Randomised: 1500 journals with 1-3 fragments dropped into random text fields.
#[test]
fn property_no_needle_survives_random_journals() {
    // RB_PROP_SEEDS=N widens the search (default 5 seeds x 300 journals).
    let n_seeds: u64 = std::env::var("RB_PROP_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let mut built = 0;
    for (seed, it) in (0..n_seeds).flat_map(|s| (0..300u64).map(move |i| (0xA11CE5EEDu64 + s, i))) {
        let mut rng = Rng(seed.wrapping_mul(1_000_003).wrapping_add(it));
        let mut ls = sample_lines();
        let mut all_needles: Vec<&'static str> = Vec::new();
        let n_edits = 1 + rng.below(4);
        for _ in 0..n_edits {
            let nf = 1 + rng.below(3);
            let frags: Vec<usize> = (0..nf).map(|_| rng.below(FRAGMENTS.len())).collect();
            let (text, needles) = dress(&mut rng, &frags);
            all_needles.extend(needles);
            let li = rng.below(ls.len());
            match rng.below(8) {
                0 => ls[li]["oracle"]["constraint"]["violations"] = json!([text]),
                1 => ls[li]["oracle"]["flags"] = json!([text]),
                2 => ls[li]["oracle"]["error_codes"] = json!([text]),
                3 => {
                    for l in ls.iter_mut() {
                        // A path-like name keeps its final component by design (a GGUF file name
                        // is the model name), so plant the fragment above a fixed basename.
                        l["model"]["name"] = json!(format!("{text}/model.gguf"));
                    }
                }
                4 => ls[li]["model"]["base_url"] = json!(text),
                5 => ls[li]["extra_free_text"] = json!(text),
                6 => ls[li]["oracle"]["constraint"]["violations"] = json!([text.clone(), text]),
                // Identifier-shaped fields: refused or clean, never silently "cleaned". Planted
                // bare: a fragment glued into a valid-looking token (`ac02xg0fdh7jyz`) is by
                // construction indistinguishable from a legitimate identifier, which is why these
                // fields come from the harness and not from user text (docs/12 note).
                _ => {
                    let field = [
                        "category", "hw_class", "sandbox", "unit_id", "epoch", "task_id",
                    ][rng.below(6)];
                    ls[li][field] = json!(FRAGMENTS[frags[0]].0);
                }
            }
        }
        let hw = hw_profile_json();
        let j = journal(&ls);
        if let Ok(b) = build(
            &BuildInputs {
                journal: &j,
                hw_json: &hw,
                identity_json: None,
                run_id: None,
            },
            &opts(),
        ) {
            built += 1;
            assert_clean(&b.bytes, &all_needles, &format!("iteration {it}"));
        }
    }
    assert!(
        built > 100 * n_seeds as usize,
        "property test would be vacuous: only {built} journals built"
    );
}

/// The raw hardware profile is the biggest fingerprint on disk; only the public view survives.
#[test]
fn raw_hw_profile_never_reaches_the_bundle() {
    let b = build(
        &BuildInputs {
            journal: &sample_journal(),
            hw_json: &hw_profile_json(),
            identity_json: None,
            run_id: None,
        },
        &opts(),
    )
    .unwrap();
    assert_clean(
        &b.bytes,
        &[
            "m5 max",
            "c02xg0fdh7jy",
            "9.9.9-secret",
            "25f74",
            "26.5.1",
            "darwin",
            "25769803776",
            "20000000000",
            "123456789012",
            "jdoe42",
            "jdoes",
            "rustysuite",
            "nvme",
            "sysctl",
            "physical_cores",
            "logical_cores",
            "mem_total",
            "driver",
        ],
        "hw profile",
    );
    let v: Value = serde_json::from_slice(&b.bytes).unwrap();
    let keys: Vec<_> = v["body"]["hw_public"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        keys,
        [
            "chassis",
            "cpu_class",
            "generation",
            "hw_class",
            "power_source",
            "schema",
            "unified_memory",
            "vendor"
        ]
    );
}

/// Even if the allow-list is bypassed by a bug, the final scan refuses rather than ships.
#[test]
fn final_scan_fails_closed() {
    use bench_submit::bundle::leak_check;
    use bench_submit::redact::Redactor;
    let r = Redactor::new(&facts());
    let mut v = json!({"units": [{"family": "fine", "violations": ["ok"]}], "report": {}});
    assert!(leak_check(&r, &v).is_ok());
    v["units"][0]["violations"][0] = json!("/Users/jdoe42/x");
    let e = leak_check(&r, &v).unwrap_err().to_string();
    assert!(
        e.contains("/units/0/violations/0") && e.contains("path"),
        "{e}"
    );
    assert!(!e.contains("jdoe42"), "leak report must not echo the value");
    v["units"][0]["violations"][0] = json!("ok");
    v["report"] = json!({"jdoe42": 1});
    assert!(
        leak_check(&r, &v).is_err(),
        "report map keys are data and are scanned"
    );
}

/// A username that is also an ordinary word must not break exports (short names are word-only).
#[test]
fn awkward_local_facts_do_not_shred_the_bundle() {
    let mut o = opts();
    o.facts.usernames = vec!["al".into(), "x".into()];
    o.facts.hostnames = vec!["a".into()];
    let b = build(
        &BuildInputs {
            journal: &sample_journal(),
            hw_json: &hw_profile_json(),
            identity_json: None,
            run_id: None,
        },
        &o,
    )
    .unwrap();
    assert!(String::from_utf8(b.bytes).unwrap().contains("unified-32"));
}

/// Robustness: arbitrary unicode / junk in free-text fields never panics and never leaks the
/// planted username.
#[test]
fn junk_input_never_panics() {
    let mut rng = Rng(0xBADC0DE);
    let alphabet: Vec<char> = "abcXYZ019 /\\:.-_=@$%~<>[](){}\"'\n\t\u{200B}\u{202E}é日本😀jdoe42"
        .chars()
        .collect();
    for _ in 0..300 {
        let len = rng.below(60);
        let s: String = (0..len)
            .map(|_| alphabet[rng.below(alphabet.len())])
            .collect();
        let mut ls = sample_lines();
        ls[0]["oracle"]["constraint"]["violations"] = json!([s.clone()]);
        ls[0]["oracle"]["flags"] = json!([s.clone()]);
        let hw = hw_profile_json();
        let j = journal(&ls);
        if let Ok(b) = build(
            &BuildInputs {
                journal: &j,
                hw_json: &hw,
                identity_json: None,
                run_id: None,
            },
            &opts(),
        ) {
            assert_clean(&b.bytes, &["jdoe42"], "junk");
        }
    }
}

//! The built-in dispatch table (P-02): the manifest, the tools dispatch
//! table and the policy registration table must list the same fifteen coding
//! tools in the same order (the policy table adds the two research-only web
//! ids, P-39b), and the workspace-constructed entries must build a provider
//! that serves its id over a real workspace root.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};

use harness_manifest::builtin as manifest_builtin;
use harness_manifest::{SemVer, ValidationContext};
use harness_policy::builtin as policy_builtin;
use harness_tools::registry::{self, ProviderCtor};

fn ctx() -> ValidationContext {
    ValidationContext::new(
        SemVer {
            major: 0,
            minor: 0,
            patch: 1,
        },
        &[],
    )
    .unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("registry-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// All three tables agree: fifteen coding tools, manifest order. The policy
/// registration table is the union (P-39b): the same fifteen in order, then
/// the two web ids the research manifest declares, which no tool provider
/// serves yet. A new built-in registers in all of them or the run cannot
/// dispatch what it grants.
#[test]
fn builtin_registry_lists_fifteen_tools_in_order() {
    let m = manifest_builtin::manifest(&ctx()).unwrap();
    let manifest_ids: Vec<&str> = m.capabilities().iter().map(|c| c.id().as_str()).collect();
    let policy_ids: Vec<&str> = policy_builtin::BUILTIN_TOOLS.iter().map(|t| t.id).collect();
    let tool_ids: Vec<&str> = registry::BUILTIN_TOOLS.iter().map(|t| t.id).collect();
    assert_eq!(manifest_ids.len(), 15);
    assert_eq!(tool_ids, manifest_ids);
    assert_eq!(&policy_ids[..15], manifest_ids.as_slice());
    assert_eq!(
        &policy_ids[15..],
        ["harness.web.fetch", "harness.web.search"]
    );

    // The workspace-constructed entries build providers that serve their
    // id; the run-owned and run-loop entries name their state instead.
    let ws = scratch("ws");
    for t in registry::BUILTIN_TOOLS {
        match t.ctor {
            ProviderCtor::Workspace(_) => {
                let p = registry::build(t.id, &ws).unwrap().unwrap();
                assert!(p.serves(t.id), "{} does not serve itself", t.id);
            }
            ProviderCtor::Exec => assert_eq!(t.id, "harness.exec.run"),
            ProviderCtor::RunLoop => assert!(t.id.starts_with("harness.task.")),
        }
    }
    assert!(matches!(
        registry::entry("harness.exec.run").map(|t| &t.ctor),
        Some(ProviderCtor::Exec)
    ));
    assert!(matches!(
        registry::entry("harness.task.todo").map(|t| &t.ctor),
        Some(ProviderCtor::RunLoop)
    ));
    assert!(matches!(
        registry::entry("harness.task.delegate").map(|t| &t.ctor),
        Some(ProviderCtor::RunLoop)
    ));
    assert!(matches!(
        registry::entry("harness.task.submit").map(|t| &t.ctor),
        Some(ProviderCtor::RunLoop)
    ));
    // Unknown ids have no entry and build nothing.
    assert!(registry::entry("fixture.item.read").is_none());
    assert!(registry::build("fixture.item.read", &ws).unwrap().is_none());
}

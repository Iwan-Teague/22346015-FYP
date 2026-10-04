#!/bin/sh
# Refusal witnesses for scripts/ci/purity.sh (design §10: INV-28's
# falsifying test is "the build fails on a planted one").
#
# Each case copies the source tree to a temporary directory, plants ONE
# violation (or breaks one tool), runs the copy's purity.sh, and requires a
# non-zero exit WITH the expected reason. A clean copy must pass first, so a
# purity.sh that refuses everything cannot satisfy this script. The real
# tree is never modified.
set -eu

cd "$(dirname "$0")/../.."

fail() {
    printf 'purity selftest FAILED: %s\n' "$1" >&2
    exit 1
}

tmpdir=$(mktemp -d) || fail "mktemp failed"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

real_cargo=$(command -v cargo) || fail "cargo not found on PATH"

# One source snapshot, without VCS metadata or build output.
COPYFILE_DISABLE=1 tar -cf "$tmpdir/src.tar" --exclude=./.git --exclude=./target . ||
    fail "could not snapshot the source tree"

n=0
# fresh: extract a clean copy; prints nothing, sets $copy.
fresh() {
    n=$((n + 1))
    copy="$tmpdir/case$n"
    mkdir "$copy" || fail "mkdir $copy failed"
    tar -xf "$tmpdir/src.tar" -C "$copy" || fail "could not extract the snapshot"
    [ -f "$copy/scripts/ci/purity.sh" ] && [ -f "$copy/crates/harness-core/src/lib.rs" ] ||
        fail "snapshot is missing files (read nothing?)"
}

# run_purity [ENV...]: run the copy's purity.sh; sets $rc, output in $tmpdir/out.
run_purity() {
    rc=0
    env "$@" sh "$copy/scripts/ci/purity.sh" >"$tmpdir/out" 2>&1 || rc=$?
}

# expect_refusal NAME WANT [ENV...]: purity.sh must exit non-zero and say WANT.
expect_refusal() {
    name=$1
    want=$2
    shift 2
    run_purity "$@"
    [ "$rc" -ne 0 ] || fail "$name: purity.sh ACCEPTED the planted violation:
$(cat "$tmpdir/out")"
    grep -qF -- "$want" "$tmpdir/out" || fail "$name: refused for the wrong reason (wanted '$want'):
$(cat "$tmpdir/out")"
    printf 'ok refused: %s\n' "$name"
}

# plant REL-PATH CONTENT: create a file in the current copy.
plant() {
    mkdir -p "$(dirname "$copy/$1")" || fail "mkdir for $1 failed"
    printf '%b' "$2" >"$copy/$1" || fail "could not plant $1"
}

# --- control: the clean tree passes ------------------------------------------
fresh
run_purity
[ "$rc" -eq 0 ] || fail "clean copy does not pass purity.sh (rc=$rc):
$(cat "$tmpdir/out")"
printf 'ok accepted: clean tree\n'

# --- pure-content plants (harness-core, a new uncompiled file) ---------------
content_case() {
    fresh
    plant crates/harness-core/src/zz_plant.rs "$2"
    expect_refusal "$1" "pure sources name forbidden facilities"
}
content_case "use std::fs" 'use std::fs;\n'
content_case "brace group with fs" 'use std::{collections::HashMap, fs};\n'
content_case "renamed group" 'use std::{fs as f, net as n, process as p, env as e};\n'
content_case "multi-line group" 'use std::{\n    collections::HashMap,\n    fs,\n};\n'
content_case "spaced path" 'use std :: fs;\n'
content_case "std::io stdout" 'fn f() { let _ = std::io::stdout(); }\n'
content_case "println" 'fn f() { println!("x"); }\n'
content_case "use std as" 'use std as s;\n'
content_case "std self rename" 'use std::{self as s};\n'
content_case "clock read" 'fn f() { let _ = std::time::Instant::now(); }\n'
content_case "async fn" 'async fn f() {}\n'
# H1 phase-exit review F-6: OS-seeded hashing in a pure crate (the loop
# detector used HashMap/HashSet before H2b).
content_case "HashSet in harness-core" 'pub(crate) struct Z { s: std::collections::HashSet<u8> }\n'
fresh
plant crates/harness-policy/src/zz_plant.rs 'use std::collections::hash_map::RandomState;\npub(crate) fn zz() -> RandomState { RandomState::new() }\n'
expect_refusal "RandomState in harness-policy" "OS-seeded hashing"
fresh
plant crates/gate-outcome/tests/zz_plant.rs 'use std::{env, fmt};\n'
expect_refusal "gate-outcome integration test uses env" "pure sources name forbidden facilities"
# The two H1b pure crates are scanned too (a plant in each must be refused).
fresh
plant crates/harness-manifest/src/zz_plant.rs 'fn f() { let _ = std::fs::read("m.json"); }\n'
expect_refusal "harness-manifest reads a file" "pure sources name forbidden facilities"
fresh
plant crates/harness-policy/src/zz_plant.rs 'use std::time::SystemTime;\n'
expect_refusal "harness-policy reads the clock" "pure sources name forbidden facilities"
# Review F-2: filesystem I/O through std::path methods never names std::fs.
fresh
plant crates/harness-policy/src/zz_plant.rs 'use std::path::Path;\npub(crate) fn zz(p: &Path) -> bool { p.exists() || p.canonicalize().is_ok() || p.read_dir().is_ok() }\n'
expect_refusal "harness-policy does I/O through Path methods" "pure sources name forbidden facilities"
fresh
plant crates/harness-manifest/src/zz_plant.rs 'fn zz(p: &str) -> bool { let q = std::path::PathBuf::from(p); q.is_file() }\n'
expect_refusal "harness-manifest does I/O through PathBuf::is_file" "pure sources name forbidden facilities"
fresh
plant crates/harness-core/src/zz_plant.rs 'fn zz(p: &::std::path::Path) -> bool { p.try_exists().is_ok() || p.symlink_metadata().is_ok() || p.read_link().is_ok() || p.metadata().is_ok() || p.is_dir() }\n'
expect_refusal "harness-core does I/O through Path methods" "pure sources name forbidden facilities"
# The method scan alone (the receiver's type is never named here).
fresh
plant crates/harness-policy/src/zz_plant.rs 'fn zz<P: Sized>(p: P, f: impl Fn(&P) -> bool) -> bool { f(&p) }\nfn yy(q: &Q) -> bool { q.canonicalize ().is_ok() }\n'
expect_refusal "Path I/O method on an unnamed receiver type" "path I/O method"

# --- INV-28 plants ------------------------------------------------------------
inv28_case() {
    fresh
    plant "$2" "$3"
    expect_refusal "$1" "INV-28"
}
inv28_case "enum RunOutcome" crates/harness-core/src/zz_plant.rs 'pub enum RunOutcome { A }\n'
inv28_case "enum<TAB>RunOutcome" crates/harness-core/src/zz_plant.rs 'pub enum\tRunOutcome { A }\n'
inv28_case "enum<NL>RunVerdict" crates/harness-core/src/zz_plant.rs 'pub enum\nRunVerdict { A }\n'
inv28_case "enum in benches/" crates/harness-core/benches/zz_plant.rs 'enum RunOutcome { A }\n'
inv28_case "enum in another harness crate" crates/harness-tools/src/zz_plant.rs 'enum ToolVerdict { A }\n'
inv28_case "enum in harness-policy" crates/harness-policy/src/zz_plant.rs 'pub enum PolicyOutcome { Allow }\n'

# --- dependency plant ---------------------------------------------------------
# The planted edge is to a planted I/O crate that depends on nothing in the
# workspace (every harness crate now reaches a pure crate, so planting one of
# them would make a cycle, not an intruder: since H1e-2c even harness-sandbox
# depends on harness-policy).
plant_io_dep() {
    fresh
    mkdir -p "$copy/crates/zz-io/src" || fail "mkdir failed"
    printf '[package]\nname = "zz-io"\nversion = "0.0.0"\nedition = "2021"\npublish = false\nlicense = "MIT"\n' \
        >"$copy/crates/zz-io/Cargo.toml" || fail "could not plant zz-io"
    printf 'pub fn read() -> std::io::Result<Vec<u8>> { std::fs::read("x") }\n' \
        >"$copy/crates/zz-io/src/lib.rs" || fail "could not plant zz-io lib"
    awk '{ print } /^\[dependencies\]/ { print "zz-io = { path = \"../zz-io\" }" }' \
        "$copy/crates/$1/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
        fail "awk failed planting a dependency"
    mv "$tmpdir/Cargo.toml.planted" "$copy/crates/$1/Cargo.toml" || fail "mv failed"
    grep -qF 'zz-io = { path' "$copy/crates/$1/Cargo.toml" || fail "dependency plant did not land"
    expect_refusal "$1 depends on an I/O crate" "$1 pulled in non-allowlisted crates"
}
plant_io_dep harness-core
plant_io_dep harness-policy

# The test-only journal seam must not be enabled by a normal dependency.
fresh
awk '{ print } /^\[dependencies\]/ { print "harness-journal = { path = \"../harness-journal\", features = [\"fault-injection\"] }" }' \
    "$copy/crates/harness-sandbox/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
    fail "awk failed planting a dependency"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-sandbox/Cargo.toml" || fail "mv failed"
grep -qF 'features = ["fault-injection"]' "$copy/crates/harness-sandbox/Cargo.toml" ||
    fail "fault-injection plant did not land"
expect_refusal "harness-sandbox enables the journal's fault-injection seam" \
    "a normal dependency edge enables harness-journal/fault-injection"

# The sandbox's own test-only remap seam (P-39f) must not be enabled by a
# normal dependency. harness-mcp already depends on the sandbox (P-37h),
# so the plant REWRITES that line to turn the feature on (no duplicate
# key); the crate is under no allowlist-checked tree, and the content
# scans read source files, not manifests.
fresh
awk '{ if ($0 ~ /^harness-sandbox[ \t]*=/)
           print "harness-sandbox = { path = \"../harness-sandbox\", features = [\"remap\"] }"
       else print }' \
    "$copy/crates/harness-mcp/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
    fail "awk failed planting a dependency"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-mcp/Cargo.toml" || fail "mv failed"
grep -qF 'features = ["remap"]' "$copy/crates/harness-mcp/Cargo.toml" ||
    fail "remap plant did not land"
expect_refusal "harness-mcp enables the sandbox's remap seam" \
    "a normal dependency edge enables harness-sandbox/remap"

# The MCP provider's own test-only testing seam (P-37h) must not be enabled
# by a normal dependency either. Planted into harness-run: it has no normal
# edge to harness-mcp (no duplicate key), harness-mcp does not depend back
# (no cycle).
fresh
awk '{ print } /^\[dependencies\]/ { print "harness-mcp = { path = \"../harness-mcp\", features = [\"testing\"] }" }' \
    "$copy/crates/harness-run/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
    fail "awk failed planting a dependency"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-run/Cargo.toml" || fail "mv failed"
grep -qF 'features = ["testing"]' "$copy/crates/harness-run/Cargo.toml" ||
    fail "testing plant did not land"
expect_refusal "harness-run enables the provider's testing seam" \
    "a normal dependency edge enables harness-mcp/testing"

# ... and a workspace feature that FORWARDS to harness-mcp/testing (cargo
# tree shows only active features). harness-cli already has a [features]
# table (net), so the plant adds a line to it — a second table would not
# even parse.
fresh
awk '{ print } /^net[ \t]*=/ { print "mcp-chaos = [\"harness-mcp/testing\"]" }' \
    "$copy/crates/harness-cli/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
    fail "awk failed planting the mcp-chaos feature"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-cli/Cargo.toml" || fail "mv failed"
grep -qF 'mcp-chaos = ["harness-mcp/testing"]' "$copy/crates/harness-cli/Cargo.toml" ||
    fail "mcp-chaos plant did not land"
expect_refusal "a chaos feature forwards to harness-mcp/testing" \
    "a workspace feature forwards to harness-mcp/testing"

# ... and the seam rule fails closed if the feature is renamed away.
fresh
awk '!/^testing[ \t]*=/' "$copy/crates/harness-mcp/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
    fail "awk failed stripping the testing feature"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-mcp/Cargo.toml" || fail "mv failed"
! grep -qE '^testing[ \t]*=' "$copy/crates/harness-mcp/Cargo.toml" ||
    fail "testing feature strip did not land"
expect_refusal "harness-mcp without its testing feature" \
    "harness-mcp does not declare its test-only testing feature"

# INV-24: a TLS crate in the default build is refused (planted as a local
# crate named `rustls`, depended on by harness-model).
fresh
mkdir -p "$copy/crates/zz-rustls/src" || fail "mkdir failed"
printf '[package]\nname = "rustls"\nversion = "0.0.0"\nedition = "2021"\npublish = false\nlicense = "MIT"\n' \
    >"$copy/crates/zz-rustls/Cargo.toml" || fail "could not plant rustls"
printf '' >"$copy/crates/zz-rustls/src/lib.rs" || fail "could not plant rustls lib"
awk '{ print } /^\[dependencies\]/ { print "rustls = { path = \"../zz-rustls\" }" }' \
    "$copy/crates/harness-model/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
    fail "awk failed planting a dependency"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-model/Cargo.toml" || fail "mv failed"
expect_refusal "harness-model depends on a TLS crate" "INV-24: TLS/HTTP-client crates in the default build"

# INV-52 (P-39n): a TLS crate must be refused from harness-cli in ANY feature
# combination. The plant is an OPTIONAL `rustls` path dependency enabled by a
# feature, so the default build (INV-24's tree) stays clean and the check
# that fires is the cli one (--all-features). The crate is planted OUTSIDE
# the copy (so outside the workspace directory): cargo makes every path
# dependency INSIDE the workspace directory an automatic member, and a member
# rooted at `rustls` would put the name in INV-24's tree with the edge off —
# refusing for the wrong reason.
fresh
mkdir -p "$tmpdir/zz-rustls-outside/src" || fail "mkdir failed"
printf '[package]\nname = "rustls"\nversion = "0.0.0"\nedition = "2021"\npublish = false\nlicense = "MIT"\n' \
    >"$tmpdir/zz-rustls-outside/Cargo.toml" || fail "could not plant rustls"
printf '' >"$tmpdir/zz-rustls-outside/src/lib.rs" || fail "could not plant rustls lib"
awk '{ print } /^\[dependencies\]/ { print "rustls = { path = \"../../../zz-rustls-outside\", optional = true }" }' \
    "$copy/crates/harness-cli/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
    fail "awk failed planting a dependency"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-cli/Cargo.toml" || fail "mv failed"
# harness-cli already has a [features] table (net); the plant adds to it.
awk '{ print } /^net[ \t]*=/ { print "zz-tls = [\"dep:rustls\"]" }' \
    "$copy/crates/harness-cli/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
    fail "awk failed planting the zz-tls feature"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-cli/Cargo.toml" || fail "mv failed"
grep -qF 'zz-tls = ["dep:rustls"]' "$copy/crates/harness-cli/Cargo.toml" ||
    fail "INV-52 plant did not land"
expect_refusal "harness-cli links a TLS crate behind a feature" \
    "INV-52: TLS/HTTP-client crates linked into harness-cli"

# The pure model crate naming an I/O facility is refused like any pure crate.
fresh
printf 'fn zz() { let _ = std::net::TcpStream::connect("x"); }\n' >>"$copy/crates/harness-model-core/src/wire.rs" ||
    fail "could not plant into wire.rs"
expect_refusal "harness-model-core's wire.rs opens a socket" "pure sources name forbidden facilities"

# --- H1e-1 plants --------------------------------------------------------------

# H1d review F-3 / H1e-1 review NF-A: the pure model code is its own crate.
# The only way for it to reach I/O code is a dependency on an I/O crate
# (harness-model itself would be a cycle), which the allowlist refuses; and
# harness-model may not grow a non-I/O module again. (`use crate::*;
# http::exchange` inside the pure crate does not compile: there is no `http`
# there.)
fresh
awk '{ print } /^\[dependencies\]/ { print "harness-journal = { path = \"../harness-journal\" }" }' \
    "$copy/crates/harness-model-core/Cargo.toml" >"$tmpdir/Cargo.toml.planted" || fail "awk failed"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-model-core/Cargo.toml" || fail "mv failed"
expect_refusal "harness-model-core depends on an I/O crate" "harness-model-core pulled in non-allowlisted crates"
# H1e-2: harness-model-core may use harness-manifest (tool definitions from
# admitted capabilities) but not harness-policy.
fresh
awk '{ print } /^\[dependencies\]/ { print "harness-policy = { path = \"../harness-policy\" }" }' \
    "$copy/crates/harness-model-core/Cargo.toml" >"$tmpdir/Cargo.toml.planted" || fail "awk failed"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-model-core/Cargo.toml" || fail "mv failed"
expect_refusal "harness-model-core depends on harness-policy" "harness-model-core pulled in non-allowlisted crates"
fresh
printf 'pub mod zz;\n' >>"$copy/crates/harness-model/src/lib.rs" || fail "could not plant a module"
printf 'use crate::*;\npub fn zz() { let _ = http::exchange; }\n' >"$copy/crates/harness-model/src/zz.rs" ||
    fail "could not plant zz.rs"
expect_refusal "a non-I/O module in harness-model" "is not one of its I/O modules"

# H1d review F-4: any crate outside harness-model's allowlist, whatever its name.
fresh
mkdir -p "$copy/crates/zz-extra/src" || fail "mkdir failed"
printf '[package]\nname = "zz-innocuous"\nversion = "0.0.0"\nedition = "2021"\npublish = false\nlicense = "MIT"\n' \
    >"$copy/crates/zz-extra/Cargo.toml" || fail "could not plant zz-innocuous"
printf '' >"$copy/crates/zz-extra/src/lib.rs" || fail "could not plant zz-innocuous lib"
awk '{ print } /^\[dependencies\]/ { print "zz-innocuous = { path = \"../zz-extra\" }" }' \
    "$copy/crates/harness-model/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
    fail "awk failed planting a dependency"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-model/Cargo.toml" || fail "mv failed"
expect_refusal "harness-model depends on a crate outside its allowlist" "harness-model pulled in non-allowlisted crates"

# H1c confirming review NF-1: a workspace feature that forwards to fault-injection.
fresh
# (harness-cli already depends on harness-journal since H1e-2b, and already
# has a [features] table — the plant adds a line to it.)
awk '{ print } /^net[ \t]*=/ { print "chaos = [\"harness-journal/fault-injection\"]" }' \
    "$copy/crates/harness-cli/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
    fail "awk failed planting the chaos feature"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-cli/Cargo.toml" || fail "mv failed"
grep -qF 'chaos = ["harness-journal/fault-injection"]' "$copy/crates/harness-cli/Cargo.toml" ||
    fail "chaos plant did not land"
expect_refusal "a chaos feature forwards to fault-injection" "a workspace feature forwards to harness-journal/fault-injection"
# ... and the compile_error! that keeps it out of optimised builds.
fresh
awk '!/^compile_error!\(/ && !/test-only and refused in optimised builds"$/ && !/^\);$/' \
    "$copy/crates/harness-journal/src/lib.rs" >"$tmpdir/lib.rs.planted" || fail "awk failed"
mv "$tmpdir/lib.rs.planted" "$copy/crates/harness-journal/src/lib.rs" || fail "mv failed"
grep -q 'compile_error' "$copy/crates/harness-journal/src/lib.rs" &&
    fail "compile_error! plant did not land"
expect_refusal "the fault-injection compile_error! removed" "an optimised build with harness-journal/fault-injection compiles"

# H1e-2b review F-2 / confirming review NF-2: the shipped binary uses the
# real probe, by content, not by name.
probe_case() {
    fresh
    awk -v from="$2" -v to="$3" '{ i = index($0, from); if (i) $0 = substr($0, 1, i - 1) to substr($0, i + length(from)); print }' \
        "$copy/crates/harness-cli/src/main.rs" >"$tmpdir/main.rs.planted" || fail "awk failed"
    mv "$tmpdir/main.rs.planted" "$copy/crates/harness-cli/src/main.rs" || fail "mv failed"
    grep -qF "$4" "$copy/crates/harness-cli/src/main.rs" || fail "probe plant '$1' did not land"
    expect_refusal "$1" "the rustyharness binary must use exactly the production probe"
}
probe_case "the binary gains a second probe" 'probe: &SystemProbe,' \
    'probe: &SystemProbe, probe: &Other,' 'probe: &Other'
probe_case "the binary uses a permissive probe" 'probe: &SystemProbe,' \
    'probe: &PermissiveProbe,' 'probe: &PermissiveProbe'
probe_case "a local struct shadows the probe's name (NF-2)" \
    'use harness_sandbox::locality::SystemProbe;' \
    'struct SystemProbe; impl harness_policy::locality::LocalityProbe for SystemProbe { fn query(&self, _: &str) -> harness_policy::locality::FsQuery { harness_policy::locality::FsQuery::Unmeasured } }' \
    'struct SystemProbe;'
probe_case "the probe imported from another path" \
    'use harness_sandbox::locality::SystemProbe;' \
    'use harness_policy::locality::NoProbe as SystemProbe;' 'NoProbe as SystemProbe'
probe_case "a let binding shadows the probe" 'let cx' \
    'let SystemProbe = harness_policy::locality::NoProbe; let cx' 'let SystemProbe'

# INV-23: every spawn goes through capture.rs's closed query set (purity.sh
# §2f). Each case names the sub-rule that must fire (H1f-4 review F-8).
spawn_case() {
    fresh
    plant crates/harness-sandbox/src/zz_spawn.rs "$2"
    expect_refusal "$1" "INV-23: a spawn outside crates/harness-sandbox/src/capture.rs"
}
# The call shapes the first version of the gate matched...
spawn_case "a program from a variable" \
    'pub fn zz(p: &str) { let _ = std::process::Command::new(p); }\n'
spawn_case "an argument from a variable" \
    'pub fn zz(t: &str) { let _ = std::process::Command::new("/bin/echo").arg(t); }\n'
spawn_case "Command renamed on import" \
    'use std::process::Command as Spawn;\npub fn zz() { let _ = Spawn::new("/bin/true"); }\n'
spawn_case "fixed literals are still a spawn outside the module" \
    'pub fn zz() {\n    let _ = std::process::Command::new("/usr/bin/true").args(["-n"]).arg("y");\n}\n'
# ...and the spellings that defeated it (H1f-4 review F-1).
spawn_case "turbofish" \
    'pub fn zz(p: &str, t: &str) { let _ = std::process::Command::new::<&str>(p).arg::<&str>(t); }\n'
spawn_case "UFCS" \
    'pub fn zz(c: &mut std::process::Command, t: &str) { std::process::Command::arg(c, t); }\n'
spawn_case "a raw identifier" \
    'pub fn zz(p: &str) { let _ = std::process::r#Command::r#new(p); }\n'
spawn_case "qualified self" \
    'pub fn zz(p: &str) { let _ = <std::process::Command>::new(p); }\n'
spawn_case "a function path" \
    'pub fn zz(p: &str) { let _ = Some(p).map(std::process::Command::new); }\n'
spawn_case "a type alias" \
    'type C = std::process::Command;\npub fn zz(p: &str) { let _ = C::new(p); }\n'
spawn_case "a macro splicing the name" \
    'macro_rules! sp { ($t:ident, $p:expr) => { std::process::$t::new($p) }; }\npub fn zz(p: &str) { let _ = sp!(Command, p); }\n'
spawn_case "CommandExt::arg0" \
    'use std::os::unix::process::CommandExt;\npub fn zz(c: &mut X, t: &str) { c.arg0(t); }\n'
spawn_case "raw_arg" \
    'pub fn zz(c: &mut X, t: &str) { c.raw_arg(t); }\n'
# A raw C string that an escape-aware stripper would read as unterminated
# (H1f-4 review F-2): the code after it must stay visible.
spawn_case "a spawn after a raw C string" \
    'pub fn zz(t: &str) { let _ = cr"\\"; let _ = std::process::Command::new(t); // "\n}\n'
# A production module that is merely NAMED tests.rs is scanned (F-4).
fresh
plant crates/harness-sandbox/src/zzdir/tests.rs 'pub fn zz(p: &str) { let _ = std::process::Command::new(p); }\n'
expect_refusal "a production module named tests.rs" "INV-23: a spawn outside crates/harness-sandbox/src/capture.rs"
# Code brought in from outside the scan (F-4).
fresh
plant crates/harness-sandbox/src/zz_spawn.rs '#[path = "../zzhidden/a.rs"]\nmod hidden;\n'
expect_refusal "a #[path] module" "INV-23: #[path] module"
fresh
plant crates/harness-sandbox/src/zz_spawn.rs 'include!("../zzhidden/b.rs");\n'
expect_refusal "include! of another file" "INV-23: compile-time include"
fresh
plant crates/harness-sandbox/zzhidden/c.rs 'pub fn zz(p: &str) { let _ = std::process::Command::new(p); }\n'
ln -s ../zzhidden/c.rs "$copy/crates/harness-sandbox/src/zz_spawn.rs" || fail "ln failed"
expect_refusal "a symlinked source" "INV-23: symlinks under crates/"
# A NUL byte would make grep read the file as binary (F-3).
fresh
plant crates/harness-sandbox/src/zz_spawn.rs 'pub fn zz() {} // \0\n'
expect_refusal "a NUL byte in a source" "INV-23: a NUL byte in a source file"
# capture.rs itself: only §4.5's programs, its tests only under cfg(test) (F-5).
fresh
awk '{ print } /^impl Query \{/ { print "    #[allow(dead_code)]"; print "    fn zz() -> Command { Command::new(\"/bin/sh\") }" }' \
    "$copy/crates/harness-sandbox/src/capture.rs" >"$tmpdir/capture.planted" || fail "awk failed"
mv "$tmpdir/capture.planted" "$copy/crates/harness-sandbox/src/capture.rs" || fail "mv failed"
grep -qF '"/bin/sh"' "$copy/crates/harness-sandbox/src/capture.rs" || fail "capture plant did not land"
expect_refusal "another program in capture.rs" 'program "/bin/sh" is not one'
fresh
awk '!/^#\[cfg\(test\)\]$/' "$copy/crates/harness-sandbox/src/capture.rs" >"$tmpdir/capture.planted" ||
    fail "awk failed"
mv "$tmpdir/capture.planted" "$copy/crates/harness-sandbox/src/capture.rs" || fail "mv failed"
expect_refusal "capture.rs tests not cfg(test)" "its tests are not declared #[cfg(test)] mod tests;"
# A grep that fails on the INV-23 word scan must fail the gate, not pass it (F-3).
mkdir -p "$tmpdir/grepshim" || fail "mkdir grepshim failed"
real_grep=$(command -v grep) || fail "grep not found on PATH"
printf '#!/bin/sh\ncase "$*" in\n    *CommandExt*) echo "grep: simulated failure" >&2; exit 2 ;;\nesac\nexec "%s" "$@"\n' \
    "$real_grep" >"$tmpdir/grepshim/grep" || fail "could not write the grep shim"
chmod +x "$tmpdir/grepshim/grep" || fail "chmod grepshim failed"
fresh
expect_refusal "grep fails on the INV-23 scan" "grep error" PATH="$tmpdir/grepshim:$PATH"
# Control: the word in a comment or a string literal elsewhere is not code.
fresh
plant crates/harness-sandbox/src/zz_spawn.rs '// Command::new(p) lives in capture.rs only.\npub fn zz() -> &'"'"'static str { "Command" }\n'
run_purity
[ "$rc" -eq 0 ] || fail "the word Command in a comment or string was refused (rc=$rc):
$(cat "$tmpdir/out")"
printf 'ok accepted: Command in a comment and a string literal\n'

# INV-23 (purity.sh §2f, §5): the binary is built only from what the gate
# reads (H1f-4 confirming review NF-1..NF-3), and capture.rs is pinned (NF-2).
# plant_dep CRATE LINE: add LINE under CRATE's [dependencies].
plant_dep() {
    awk -v line="$2" '{ print } /^\[dependencies\]/ { print line }' \
        "$copy/crates/$1/Cargo.toml" >"$tmpdir/Cargo.toml.planted" ||
        fail "awk failed planting a dependency"
    mv "$tmpdir/Cargo.toml.planted" "$copy/crates/$1/Cargo.toml" || fail "mv failed"
    grep -qxF "$2" "$copy/crates/$1/Cargo.toml" || fail "dependency plant did not land"
}
# The review's plant: a spawning path dependency outside crates/.
fresh
plant vendorlib/zz-spawner/Cargo.toml \
    '[package]\nname = "zz-spawner"\nversion = "0.0.0"\nedition = "2021"\npublish = false\nlicense = "MIT"\n'
plant vendorlib/zz-spawner/src/lib.rs \
    'pub fn run(p: &str, a: &[&str]) { let _ = std::process::Command::new(p).args(a).status(); }\n'
plant_dep harness-cli 'zz-spawner = { path = "../../vendorlib/zz-spawner" }'
expect_refusal "a spawning path dependency outside crates/" \
    "INV-23: crates in the build whose source this gate does not read"
# A listed crate's name does not admit its source: a [patch] onto a path.
fresh
itoa_v=$(awk '/^name = "itoa"$/ { getline; sub(/^version = "/, ""); sub(/"$/, ""); print; exit }' \
    "$copy/Cargo.lock") || fail "awk failed reading Cargo.lock"
[ -n "$itoa_v" ] || fail "no itoa in Cargo.lock (the patch plant needs a listed crate in the tree)"
plant vendorlib/itoa/Cargo.toml \
    "[package]\nname = \"itoa\"\nversion = \"$itoa_v\"\nedition = \"2021\"\npublish = false\nlicense = \"MIT\"\n"
plant vendorlib/itoa/src/lib.rs 'pub fn zz() {}\n'
printf '\n[patch.crates-io]\nitoa = { path = "vendorlib/itoa" }\n' >>"$copy/Cargo.toml" ||
    fail "could not plant the patch"
expect_refusal "a [patch] of a listed crate onto a path" \
    "INV-23: crates in the build whose source this gate does not read"
# A crates.io crate that is not on the reviewed list (added to the tree by a
# cargo shim: the selftest runs offline, so it cannot fetch a real one).
mkdir "$tmpdir/treeshim" || fail "mkdir treeshim failed"
cat >"$tmpdir/treeshim/cargo" <<EOF
#!/bin/sh
# Adds a crates.io crate to the workspace's normal and build tree; everything
# else is real cargo.
if [ "\$*" = "tree --workspace --target all -e normal,build --prefix none" ]; then
    "$real_cargo" "\$@" || exit \$?
    echo "duct v0.13.7"
    exit 0
fi
exec "$real_cargo" "\$@"
EOF
chmod +x "$tmpdir/treeshim/cargo" || fail "chmod treeshim failed"
fresh
expect_refusal "a crates.io crate not on the reviewed list" \
    "INV-23: crates.io crates in the build that are not on this gate's reviewed list" \
    PATH="$tmpdir/treeshim:$PATH"

# --- tool failures must fail closed -------------------------------------------
# Created here, before its first use (the net-tree case below); the later
# cases reuse it.
mkdir "$tmpdir/shim" || fail "mkdir shim failed"
cat >"$tmpdir/shim/cargo" <<EOF
#!/bin/sh
# Fails 'cargo tree' when an argument equals \$SHIM_FAIL_ARG; with
# SHIM_EMPTY=1 it prints nothing and succeeds. Everything else is real cargo.
if [ "\$1" = tree ]; then
    for a in "\$@"; do
        if [ "\$a" = "\${SHIM_FAIL_ARG:-}" ]; then
            echo "error: simulated cargo tree failure" >&2
            exit 101
        fi
    done
    [ "\${SHIM_EMPTY:-0}" = 1 ] && exit 0
fi
exec "$real_cargo" "\$@"
EOF
chmod +x "$tmpdir/shim/cargo" || fail "chmod shim failed"
shim_path="$tmpdir/shim:$PATH"

# P-39n: the net tree of harness-fetch is allowlisted exactly like the
# default tree. A crates.io crate appearing only there (shim: appended after
# the fetch-net invocation) is refused under the net tree's own name.
mkdir "$tmpdir/nettreeshim" || fail "mkdir nettreeshim failed"
cat >"$tmpdir/nettreeshim/cargo" <<EOF
#!/bin/sh
# With SHIM_NET_FAIL=1, fails exactly the harness-fetch net-feature tree
# read; with SHIM_NET_FAIL unset, adds a crates.io crate to it. Everything
# else is real cargo.
if [ "\$*" = "tree --target all -e normal,build --prefix none -p harness-fetch --features net" ]; then
    if [ "\${SHIM_NET_FAIL:-0}" = 1 ]; then
        echo "error: simulated cargo tree failure" >&2
        exit 101
    fi
    "$real_cargo" "\$@" || exit \$?
    echo "duct v0.13.7"
    exit 0
fi
exec "$real_cargo" "\$@"
EOF
chmod +x "$tmpdir/nettreeshim/cargo" || fail "chmod nettreeshim failed"
fresh
expect_refusal "a crates.io crate in the net tree alone" \
    "harness-fetch (net) pulled in non-allowlisted crates" \
    PATH="$tmpdir/nettreeshim:$PATH"
# ... and the net tree read failing must fail the gate, not skip the check.
fresh
expect_refusal "cargo tree fails (net tree only)" \
    "cargo tree failed: -p harness-fetch --features net" \
    PATH="$tmpdir/nettreeshim:$PATH" SHIM_NET_FAIL=1
# Targets whose code the scan does not read (NF-3).
fresh
mkdir -p "$copy/crates/harness-cli/hidden" || fail "mkdir failed"
cp "$copy/crates/harness-cli/src/main.rs" "$copy/crates/harness-cli/hidden/main.rs" || fail "cp failed"
awk '{ if ($0 == "path = \"src/main.rs\"") print "path = \"hidden/main.rs\""; else print }' \
    "$copy/crates/harness-cli/Cargo.toml" >"$tmpdir/Cargo.toml.planted" || fail "awk failed"
mv "$tmpdir/Cargo.toml.planted" "$copy/crates/harness-cli/Cargo.toml" || fail "mv failed"
grep -qxF 'path = "hidden/main.rs"' "$copy/crates/harness-cli/Cargo.toml" || fail "target plant did not land"
expect_refusal "the binary's root outside src/" "INV-23: targets this gate does not read or allow"
fresh
plant crates/harness-cli/build.rs 'fn main() {}\n'
expect_refusal "a build script" "INV-23: targets this gate does not read or allow"
fresh
plant crates/zz-pm/Cargo.toml \
    '[package]\nname = "zz-pm"\nversion = "0.0.0"\nedition = "2021"\npublish = false\nlicense = "MIT"\n\n[lib]\nproc-macro = true\n'
plant crates/zz-pm/src/lib.rs '#![forbid(unsafe_code)]\n'
expect_refusal "a proc-macro crate" "INV-23: targets this gate does not read or allow"
# Foreign code: every crate root forbids unsafe code, first thing.
forbid_case() {
    fresh
    awk -v to="$3" '{ if ($0 == "#![forbid(unsafe_code)]") { if (to != "") print to } else print }' \
        "$copy/crates/$2" >"$tmpdir/root.planted" || fail "awk failed"
    mv "$tmpdir/root.planted" "$copy/crates/$2" || fail "mv failed"
    grep -qxF '#![forbid(unsafe_code)]' "$copy/crates/$2" && fail "forbid plant '$1' did not land"
    expect_refusal "$1" "does not open with #![forbid(unsafe_code)]"
}
forbid_case "a crate root without forbid(unsafe_code)" harness-sandbox/src/lib.rs ''
forbid_case "forbid(unsafe_code) switched off by cfg_attr" harness-tools/src/lib.rs \
    '#![cfg_attr(any(), forbid(unsafe_code))]'
# Cargo configuration can add linker arguments.
fresh
plant .cargo/config.toml '[build]\n'
expect_refusal "cargo configuration in the repository" "INV-23: cargo configuration in the repository"
# capture.rs is pinned: what the literal check cannot see (NF-2).
capture_case() {
    fresh
    awk -v from="$2" -v to="$3" '{ i = index($0, from); if (i) $0 = substr($0, 1, i - 1) to substr($0, i + length(from)); print }' \
        "$copy/crates/harness-sandbox/src/capture.rs" >"$tmpdir/capture.planted" || fail "awk failed"
    mv "$tmpdir/capture.planted" "$copy/crates/harness-sandbox/src/capture.rs" || fail "mv failed"
    grep -qF "$3" "$copy/crates/harness-sandbox/src/capture.rs" || fail "capture plant '$1' did not land"
    expect_refusal "$1" "crates/harness-sandbox/src/capture.rs is not the reviewed version"
}
capture_case "a relative program in capture.rs" 'Command::new("/sbin/mount")' 'Command::new("mount")'
capture_case "an extra argument in capture.rs" '"hw.logicalcpu"]' '"hw.logicalcpu", "-a"]'
# The confined spawn (H2a): only its three programs, and pinned.
confine_case() {
    fresh
    awk -v from="$2" -v to="$3" '{ i = index($0, from); if (i) $0 = substr($0, 1, i - 1) to substr($0, i + length(from)); print }' \
        "$copy/crates/harness-sandbox/src/confine_spawn.rs" >"$tmpdir/confine.planted" || fail "awk failed"
    mv "$tmpdir/confine.planted" "$copy/crates/harness-sandbox/src/confine_spawn.rs" || fail "mv failed"
    grep -qF "$3" "$copy/crates/harness-sandbox/src/confine_spawn.rs" || fail "confine plant '$1' did not land"
    expect_refusal "$1" "$4"
}
confine_case "another program in confine_spawn.rs" 'Command::new("/bin/kill")' 'Command::new("/bin/sh")' \
    'program "/bin/sh" is not one the confined spawn may run'
confine_case "a relative program in confine_spawn.rs" 'Command::new("/bin/kill")' 'Command::new("kill")' \
    "crates/harness-sandbox/src/confine_spawn.rs is not the reviewed version"
confine_case "the start canary removed in confine_spawn.rs" "if(\$pp<=1 || kill(0,\$pp) || (\$!+0)!=1)" "if(0)" \
    "crates/harness-sandbox/src/confine_spawn.rs is not the reviewed version"
confine_case "the per-pass canary weakened in confine_spawn.rs" "if(\$hit ? getppid()==\$pp : (\$en!=1 && \$en!=3))" "if(0)" \
    "crates/harness-sandbox/src/confine_spawn.rs is not the reviewed version"
# The file-op stub (P-36d): pinned, spawns nothing. Any change without a
# re-pin is refused by the pin; a fork in the stub text is refused by the
# same pin (the stub holds no spawn facility the word scan could miss:
# the pin IS the fork control).
fileop_case() {
    fresh
    awk -v from="$2" -v to="$3" '{ i = index($0, from); if (i) $0 = substr($0, 1, i - 1) to substr($0, i + length(from)); print }' \
        "$copy/crates/harness-sandbox/src/fileop_stub.rs" >"$tmpdir/fileop.planted" || fail "awk failed"
    mv "$tmpdir/fileop.planted" "$copy/crates/harness-sandbox/src/fileop_stub.rs" || fail "mv failed"
    grep -qF "$3" "$copy/crates/harness-sandbox/src/fileop_stub.rs" || fail "fileop plant '$1' did not land"
    expect_refusal "$1" "$4"
}
fileop_case "the fileop stub changed without re-pin" \
    'rh-stub/1 confirmed status=0 end=exit kills=0 exec=ok' \
    'rh-stub/1 confirmed status=0 end=stop kills=0 exec=ok' \
    "crates/harness-sandbox/src/fileop_stub.rs is not the reviewed version"
fileop_case "a fork added to the fileop stub" \
    'use strict;' \
    'use strict; fork || exit 1;' \
    "crates/harness-sandbox/src/fileop_stub.rs is not the reviewed version"
# cargo metadata failing, or printing targets in a shape the gate does not
# read, fails the gate.
mkdir "$tmpdir/metashim" || fail "mkdir metashim failed"
cat >"$tmpdir/metashim/cargo" <<EOF
#!/bin/sh
# SHIM_META=fail: cargo metadata fails. SHIM_META=reshape: its first target
# has a field renamed. Everything else is real cargo.
if [ "\$1" = metadata ]; then
    case \${SHIM_META:-} in
        fail) echo "error: simulated cargo metadata failure" >&2; exit 101 ;;
        reshape)
            "$real_cargo" "\$@" >"$tmpdir/meta-real" || exit \$?
            sed 's/"crate_types":/"crate_kinds":/' "$tmpdir/meta-real"
            exit \$? ;;
    esac
fi
exec "$real_cargo" "\$@"
EOF
chmod +x "$tmpdir/metashim/cargo" || fail "chmod metashim failed"
fresh
expect_refusal "cargo metadata fails" "cargo metadata failed (INV-23)" \
    PATH="$tmpdir/metashim:$PATH" SHIM_META=fail
fresh
expect_refusal "cargo metadata prints a target in another shape" "a field order it does not know?" \
    PATH="$tmpdir/metashim:$PATH" SHIM_META=reshape

# H1a review N-3: the remaining name-scan gaps.
n3_case() {
    fresh
    plant crates/harness-core/src/zz_plant.rs "$2"
    expect_refusal "$1" "pure sources name forbidden facilities"
}
n3_case "a comment between path segments" 'fn f() { let _ = std::/*x*/fs::read("a"); }\n'
n3_case "#[path] module" '#[path = "../../harness-journal/src/writer.rs"]\nmod w;\n'
n3_case "include_str!" 'const X: &str = include_str!("lib.rs");\n'
n3_case "env!" 'const X: &str = env!("HOME");\n'
n3_case "macro_rules!" 'macro_rules! m { ($a:ident) => { std::$a::read("a") } }\n'
n3_case "static global" 'static COUNTER: u32 = 0;\n'
fresh
plant crates/harness-core/src/zz_plant.rs 'pub enum /*c*/ RunOutcome { A }\n'
expect_refusal "INV-28 with a comment inside" "INV-28"

# H1c review F-6 / H1e-1 review NF-C: TrustedName is sealed (the compiler
# refuses outside impls); the gate also refuses the token outside its owner,
# however it is imported. And no `.leak()` (runtime text to &'static str).
fresh
plant crates/harness-tools/src/zz_plant.rs 'struct S(String);\nimpl harness_core::TrustedName for S { fn trusted_name(&self) -> &str { &self.0 } }\n'
expect_refusal "TrustedName named outside its owner" "TrustedName outside its owner"
fresh
plant crates/harness-tools/src/zz_plant.rs 'use harness_core::TrustedName as Tn;\nstruct S(String);\nimpl Tn for S { fn trusted_name(&self) -> &str { &self.0 } }\n'
expect_refusal "TrustedName through an alias" "TrustedName outside its owner"
fresh
plant crates/harness-tools/src/zz_plant.rs 'pub fn zz(s: String) -> &'"'"'static str { Box::leak(s.into_boxed_str()) }\n'
expect_refusal "Box::leak of runtime text" "leak"
fresh
plant crates/harness-tools/src/zz_plant.rs 'pub fn zz(s: String) -> &'"'"'static str { s.leak() }\n'
expect_refusal "String .leak()" "leak"
# One Meter, built by the run driver only.
fresh
plant crates/harness-tools/src/zz_plant.rs 'pub fn zz(l: harness_core::MeterLimits, c: Box<dyn harness_core::MonoClock>) -> harness_core::Meter { harness_core::Meter::new(l, None, c) }\n'
expect_refusal "a second Meter construction site" "Meter construction"
# ...and inside the run crate only driver.rs is exempt (H1e-2: its tests
# call the driver's own constructor, never Meter::new).
fresh
plant crates/harness-run/tests/zz_plant.rs 'pub fn zz(l: harness_core::MeterLimits, c: Box<dyn harness_core::MonoClock>) -> harness_core::Meter { harness_core::Meter::new(l, None, c) }\n'
expect_refusal "a Meter built in the run crate outside driver.rs" "Meter construction"
# ...including the resumed-attempt constructor (H1e-2b).
fresh
plant crates/harness-tools/src/zz_plant.rs 'pub fn zz(l: harness_core::MeterLimits, c: Box<dyn harness_core::MonoClock>) -> harness_core::Meter { harness_core::Meter::new_resumed(l, None, c, std::time::Duration::ZERO) }\n'
expect_refusal "a resumed Meter built outside the driver" "Meter construction"
# P-38b: a live run measures the child's spend from the child meter; the
# journal re-feed constructor ChildSpend::recorded is confined to the run
# driver and the replay, like Meter::new_resumed.
child_spend_recorded_outside_driver_refused() {
    fresh
    plant crates/harness-tools/src/zz_plant.rs 'pub fn zz() -> harness_core::ChildSpend { harness_core::ChildSpend::recorded(1, 2, 3, false, std::time::Duration::ZERO) }\n'
    expect_refusal "child_spend_recorded_outside_driver_refused (another crate)" "ChildSpend::recorded"
    fresh
    plant crates/harness-run/tests/zz_plant.rs 'pub fn zz() -> harness_core::ChildSpend { harness_core::ChildSpend::recorded(1, 2, 3, false, std::time::Duration::ZERO) }\n'
    expect_refusal "child_spend_recorded_outside_driver_refused (run crate, outside driver and replay)" "ChildSpend::recorded"
    fresh
    plant crates/harness-run/src/session.rs 'fn zz() { let _ = harness_core::ChildSpend::recorded(1, 2, 3, false, std::time::Duration::ZERO); }\n'
    expect_refusal "child_spend_recorded_outside_driver_refused (run crate source outside driver and replay)" "ChildSpend::recorded"
}
child_spend_recorded_outside_driver_refused

# H1e-1 review NF-B: literals must not hide code from the code-only scans.
n3b_case() {
    fresh
    plant crates/harness-core/src/zz_plant.rs "$2"
    expect_refusal "$1" "pure sources name forbidden facilities"
}
n3b_case "static between \"/*\" and \"*/\" strings" 'pub const A: &str = "/*"; pub static G: u8 = 0; pub const B: &str = "*/";\n'
n3b_case "static after a \"//\" string" 'pub const A: &str = "//"; pub static G: u8 = 0;\n'
n3b_case "include_str! between raw strings" 'pub const A: &str = r"/*"; pub const X: &str = include_str!("lib.rs"); pub const B: &str = r"*/";\n'
n3b_case "macro_rules! between byte strings" 'pub const A: &[u8] = b"/*"; macro_rules! m { () => {} } pub const B: &[u8] = b"*/";\n'
n3b_case "static after a quote char" 'pub const Q: char = '"'"'"'"'"'; pub static G: u8 = 0; pub const R: &str = "x";\n'

# H1e-1 review NF-D: target-specific and build dependencies are allowlisted too.
fresh
mkdir -p "$copy/crates/zz-extra/src" || fail "mkdir failed"
printf '[package]\nname = "zz-innocuous"\nversion = "0.0.0"\nedition = "2021"\npublish = false\nlicense = "MIT"\n' \
    >"$copy/crates/zz-extra/Cargo.toml" || fail "could not plant zz-innocuous"
printf '' >"$copy/crates/zz-extra/src/lib.rs" || fail "could not plant zz-innocuous lib"
printf '\n[target.'"'"'cfg(windows)'"'"'.dependencies]\nzz-innocuous = { path = "../zz-extra" }\n' \
    >>"$copy/crates/harness-model/Cargo.toml" || fail "could not plant a windows dependency"
expect_refusal "a Windows-only dependency of harness-model" "harness-model pulled in non-allowlisted crates"
fresh
mkdir -p "$copy/crates/zz-extra/src" || fail "mkdir failed"
printf '[package]\nname = "zz-innocuous"\nversion = "0.0.0"\nedition = "2021"\npublish = false\nlicense = "MIT"\n' \
    >"$copy/crates/zz-extra/Cargo.toml" || fail "could not plant zz-innocuous"
printf '' >"$copy/crates/zz-extra/src/lib.rs" || fail "could not plant zz-innocuous lib"
printf '\n[build-dependencies]\nzz-innocuous = { path = "../zz-extra" }\n' \
    >>"$copy/crates/harness-core/Cargo.toml" || fail "could not plant a build dependency"
printf 'fn main() {}\n' >"$copy/crates/harness-core/build.rs" || fail "could not plant build.rs"
expect_refusal "a build dependency of harness-core" "harness-core pulled in non-allowlisted crates"

# H1a review N-6: a compile_fail doctest without its error code.
fresh
printf '/// ```compile_fail\n/// let x: u8 = "a";\n/// ```\npub fn zz() {}\n' >>"$copy/crates/harness-tools/src/lib.rs" ||
    fail "could not plant a doctest"
expect_refusal "compile_fail without an error code" "compile_fail doctests without an expected error code"

# --- S-La: the ONE named unsafe exception (purity.sh §5b) --------------------
# The exception crate must open with the allowance, by content.
fresh
awk '{ if ($0 ~ /^#!\[allow\(unsafe_code\)\]/) next; print }' \
    "$copy/crates/harness-sandbox-linux/src/lib.rs" >"$copy/zz-mut" ||
    fail "awk failed (unsafe allowance removed)"
mv "$copy/zz-mut" "$copy/crates/harness-sandbox-linux/src/lib.rs" ||
    fail "mv failed (unsafe allowance removed)"
expect_refusal "the named unsafe crate without its allowance" \
    "must open with #![allow(unsafe_code)]"

# unsafe_site_count_matches_ratchet: the ratchet is 0, so ONE planted
# `unsafe` site must refuse, naming the ratchet.
fresh
printf '\nunsafe fn zz() {}\n' >>"$copy/crates/harness-sandbox-linux/src/lib.rs" ||
    fail "could not plant an unsafe site"
expect_refusal "unsafe_site_count_matches_ratchet: one planted site" \
    "unsafe sites (ratchet"

# purity_allows_the_named_linux_unsafe_crate_only: no OTHER crate root may
# lower `forbid` to `allow` — the exception is named, not patterned.
fresh
awk '{ sub(/#!\[forbid\(unsafe_code\)\]/, "#![allow(unsafe_code)]"); print }' \
    "$copy/crates/harness-run/src/lib.rs" >"$copy/zz-mut" ||
    fail "awk failed (forbid lowered in harness-run)"
mv "$copy/zz-mut" "$copy/crates/harness-run/src/lib.rs" ||
    fail "mv failed (forbid lowered in harness-run)"
expect_refusal "purity_allows_the_named_linux_unsafe_crate_only" \
    "does not open with #![forbid(unsafe_code)]"

# --- tool failures must fail closed -------------------------------------------
fresh
expect_refusal "cargo tree fails (default tree)" "cargo tree failed: -p gate-outcome" \
    PATH="$shim_path" SHIM_FAIL_ARG=gate-outcome
fresh
expect_refusal "cargo tree fails (json tree only)" "cargo tree failed: -p gate-outcome --features json" \
    PATH="$shim_path" SHIM_FAIL_ARG=json
fresh
expect_refusal "cargo tree fails (harness-core tree only)" "cargo tree failed: -p harness-core" \
    PATH="$shim_path" SHIM_FAIL_ARG=harness-core
fresh
expect_refusal "cargo tree fails (harness-manifest tree only)" "cargo tree failed: -p harness-manifest" \
    PATH="$shim_path" SHIM_FAIL_ARG=harness-manifest
fresh
expect_refusal "cargo tree fails (harness-policy tree only)" "cargo tree failed: -p harness-policy" \
    PATH="$shim_path" SHIM_FAIL_ARG=harness-policy
fresh
expect_refusal "cargo tree prints nothing" "read nothing" \
    PATH="$shim_path" SHIM_EMPTY=1

# An unreadable pure source must fail, not be skipped (not testable as root,
# who can read any file).
if [ "$(id -u)" != 0 ]; then
    fresh
    chmod 000 "$copy/crates/harness-core/src/lib.rs" || fail "chmod failed"
    expect_refusal "unreadable pure source" "could not read"
    chmod 644 "$copy/crates/harness-core/src/lib.rs" || fail "chmod restore failed"
fi

printf 'purity selftest OK: %s cases refused or accepted as required.\n' "$n"

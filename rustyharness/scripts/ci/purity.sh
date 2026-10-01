#!/bin/sh
# Purity + INV-28 gates (rustyharness design docs/01-design-v0.1.md §1.2).
#
# Five pure crates: gate-outcome, harness-core, harness-manifest,
# harness-policy and harness-model-core. Purity means no I/O, no async, no clock reads, no global
# state — checked two ways:
#
#   1. dependency shape: `cargo tree --target all -e normal,build` of each
#      pure crate (and of harness-model) must stay
#      inside its reviewed allowlist (gate-outcome has ZERO default deps);
#   2. content: the pure crates' Rust files must not so much as NAME an I/O,
#      process, environment, thread, console, or clock facility.
#
# INV-28: exactly one outcome type in the suite. No `enum …Outcome` /
# `enum …Verdict` may appear in any Rust file under crates/harness-* — the
# verdict lives in gate-outcome (gate-outcome itself is exempt: it IS the
# outcome crate).
#
# INV-23 (sections 2f and 5): every spawn in the harness is one of the
# fixed queries in crates/harness-sandbox/src/capture.rs, so no payload
# reaches an argv; and the binary is built from nothing these scans do not
# read or this gate has not reviewed.
#
# Fail closed: every tool call is checked. A tool that errors, or a check
# that read nothing, fails the gate; it never prints OK.
# scripts/ci/purity-selftest.sh plants violations and proves each refusal.
set -eu

cd "$(dirname "$0")/../.."

fail() {
    printf 'purity gate FAILED: %s\n' "$1" >&2
    exit 1
}

tmpdir=$(mktemp -d) || fail "mktemp failed"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

# --- 1. dependency shape ---------------------------------------------------

# tree_names OUT CRATE [ARGS...]: the sorted crate names in CRATE's normal
# AND build dependency tree for EVERY target (H1e-1 review NF-D: a
# Windows-only, Linux-only or build dependency must not pass because the
# gate host does not build it), written to OUT. No pipelines: POSIX sh has no pipefail,
# so each step writes a file and its exit status is checked.
tree_names() {
    out=$1
    crate=$2
    shift 2
    cargo tree --target all -e normal,build --prefix none -p "$crate" "$@" >"$tmpdir/tree-raw" ||
        fail "cargo tree failed: -p $crate $*"
    awk '{print $1}' "$tmpdir/tree-raw" >"$tmpdir/tree-names" ||
        fail "awk failed on cargo tree output for $crate"
    sort -u "$tmpdir/tree-names" >"$out" ||
        fail "sort failed on cargo tree output for $crate"
    # Content, not presence: the tree must at least contain the crate itself.
    grep -qxF "$crate" "$out" ||
        fail "cargo tree output for $crate does not name $crate (read nothing?)"
}

# refuse_intruders TREE ALLOWED WHAT: fail if TREE names a crate not in ALLOWED.
refuse_intruders() {
    comm -23 "$1" "$2" >"$tmpdir/intruders" || fail "comm failed ($3)"
    if [ -s "$tmpdir/intruders" ]; then
        fail "$3 pulled in non-allowlisted crates:
$(cat "$tmpdir/intruders")"
    fi
}

# gate-outcome is the bottom of the crate lattice: ZERO normal dependencies
# on default features.
tree_names "$tmpdir/gate-default" gate-outcome
printf '%s\n' gate-outcome >"$tmpdir/allowed-default"
refuse_intruders "$tmpdir/gate-default" "$tmpdir/allowed-default" "gate-outcome (default)"

# With the json feature (§6 child protocol) only the reviewed serde stack is
# allowed. serde_derive's proc-macro deps appear here when a feature turns
# them on; the allowlist admits the whole reviewed stack, not just today's
# shape, so a serde build-detail change cannot silently re-fail the gate
# (memchr and zmij arrive with serde_json >= 1.0.14x: both pure Rust, no
# links, no cc; zmij's build.rs only probes the rustc version) — but ANY
# OTHER crate still fails it.
tree_names "$tmpdir/gate-json" gate-outcome --features json
grep -qxF serde_json "$tmpdir/gate-json" ||
    fail "gate-outcome --features json tree does not contain serde_json (feature renamed?)"
printf '%s\n' \
    gate-outcome serde serde_core serde_derive proc-macro2 quote syn \
    unicode-ident serde_json itoa ryu memchr zmij >"$tmpdir/allowed-json-raw"
sort -u "$tmpdir/allowed-json-raw" >"$tmpdir/allowed-json" || fail "sort failed"
refuse_intruders "$tmpdir/gate-json" "$tmpdir/allowed-json" "gate-outcome (json)"

# harness-core may depend only on gate-outcome and the ONE SHA-256
# implementation (design §1.2, §1.4: `harness_core::sha256`). serde and
# serde_json (with memchr and zmij, as for gate-outcome's json feature) are
# admitted: since H1d harness-core hosts the shared strict JSON reader
# (`harness_core::strict_json`). Any new dependency must be added to this
# allowlist BY REVIEW.
#   sha2 0.11 (RustCrypto, pure Rust, default features off) and its tree:
#     digest, block-buffer, hybrid-array, typenum, crypto-common, cfg-if,
#     cpufeatures (runtime CPU-feature detection for the SHA extensions),
#     libc (FFI declarations only, no C is compiled; cpufeatures uses it on
#     some targets, e.g. aarch64 macOS and Linux). No `cc`, no `asm` feature.
tree_names "$tmpdir/core" harness-core
grep -qxF gate-outcome "$tmpdir/core" ||
    fail "harness-core tree does not contain gate-outcome (read the wrong tree?)"
grep -qxF sha2 "$tmpdir/core" ||
    fail "harness-core tree does not contain sha2 (read the wrong tree?)"
printf '%s\n' \
    harness-core gate-outcome serde serde_core serde_derive proc-macro2 \
    quote syn unicode-ident serde_json itoa ryu memchr zmij \
    sha2 digest block-buffer hybrid-array typenum crypto-common cfg-if \
    cpufeatures libc >"$tmpdir/allowed-core-raw"
sort -u "$tmpdir/allowed-core-raw" >"$tmpdir/allowed-core" || fail "sort failed"
refuse_intruders "$tmpdir/core" "$tmpdir/allowed-core" "harness-core"

# harness-manifest and harness-policy (design §1.2): serde, serde_json,
# thiserror (+ its proc-macro), policy -> manifest, and (since H1d, for the
# shared strict JSON reader harness_core::strict_json) manifest -> core,
# which brings gate-outcome and the reviewed sha2 tree above. No ed25519
# crate yet (signing is H4); adding one is a review decision recorded here
# with its reason.
#   serde stack (serde, serde_core, serde_derive, proc-macro2, quote, syn,
#     unicode-ident, serde_json, itoa, ryu, memchr, zmij): as above;
#   thiserror, thiserror-impl: derive-only error Display, no runtime code;
#   harness-core, gate-outcome and the sha2 tree: harness-core's allowlist.
tree_names "$tmpdir/manifest" harness-manifest
grep -qxF serde_json "$tmpdir/manifest" ||
    fail "harness-manifest tree does not contain serde_json (read the wrong tree?)"
printf '%s\n' \
    harness-manifest serde serde_core serde_derive proc-macro2 quote syn \
    unicode-ident serde_json itoa ryu memchr zmij thiserror thiserror-impl \
    harness-core gate-outcome sha2 digest block-buffer hybrid-array typenum \
    crypto-common cfg-if cpufeatures libc >"$tmpdir/allowed-manifest-raw"
sort -u "$tmpdir/allowed-manifest-raw" >"$tmpdir/allowed-manifest" || fail "sort failed"
refuse_intruders "$tmpdir/manifest" "$tmpdir/allowed-manifest" "harness-manifest"

tree_names "$tmpdir/policy" harness-policy
grep -qxF harness-manifest "$tmpdir/policy" ||
    fail "harness-policy tree does not contain harness-manifest (read the wrong tree?)"
printf '%s\n' harness-policy >>"$tmpdir/allowed-manifest-raw" || fail "printf failed"
sort -u "$tmpdir/allowed-manifest-raw" >"$tmpdir/allowed-policy" || fail "sort failed"
refuse_intruders "$tmpdir/policy" "$tmpdir/allowed-policy" "harness-policy"

# harness-model-core (H1e-1 review NF-A: the pure half of the model layer as
# its own crate, so no I/O module is ever a sibling): exactly the manifest
# allowlist's reviewed crates plus harness-manifest itself (since H1e-2: a
# tool definition is built from an admitted Capability, never from loose
# text), and never harness-policy or anything else.
tree_names "$tmpdir/modelcore" harness-model-core
grep -qxF harness-core "$tmpdir/modelcore" ||
    fail "harness-model-core tree does not contain harness-core (read the wrong tree?)"
grep -vxF harness-policy "$tmpdir/allowed-manifest-raw" >"$tmpdir/allowed-modelcore-raw" || true
printf '%s\n' harness-model-core >>"$tmpdir/allowed-modelcore-raw" || fail "printf failed"
sort -u "$tmpdir/allowed-modelcore-raw" >"$tmpdir/allowed-modelcore" || fail "sort failed"
refuse_intruders "$tmpdir/modelcore" "$tmpdir/allowed-modelcore" "harness-model-core"

# --- INV-24 / H1d review F-4: harness-model's dependency tree is allowlisted --
# harness-model is the crate that talks to the network. Its normal tree may
# contain only the reviewed crates below; anything else (a TLS stack, an HTTP
# client, anything) fails here, whatever its name. The denylist that follows
# stays as a second, clearer message for the well-known TLS names.
tree_names "$tmpdir/model" harness-model
grep -qxF harness-journal "$tmpdir/model" ||
    fail "harness-model tree does not contain harness-journal (read the wrong tree?)"
printf '%s\n' \
    harness-model harness-model-core harness-core harness-journal harness-manifest gate-outcome \
    serde serde_core serde_derive proc-macro2 quote syn unicode-ident \
    serde_json itoa ryu memchr zmij thiserror thiserror-impl \
    sha2 digest block-buffer hybrid-array typenum crypto-common cfg-if \
    cpufeatures libc >"$tmpdir/allowed-model-raw"
sort -u "$tmpdir/allowed-model-raw" >"$tmpdir/allowed-model" || fail "sort failed"

# --- INV-24: no TLS in the default build ------------------------------------
# The default build connects only to loopback over plain HTTP (design §3.2);
# TLS arrives only with a future, off-by-default `hosted` feature. No crate
# of a TLS or HTTP-client stack may appear on a normal edge anywhere in the
# workspace. The tree must name harness-model, so the check reads something.
cargo tree --workspace --target all -e normal,build --prefix none >"$tmpdir/ws-raw" ||
    fail "cargo tree failed: --workspace --target all -e normal,build"
awk '{print $1}' "$tmpdir/ws-raw" >"$tmpdir/ws-names" || fail "awk failed on the workspace tree"
grep -qxF harness-model "$tmpdir/ws-names" ||
    fail "the workspace tree does not name harness-model (read nothing?)"
: >"$tmpdir/tls-hits"
for c in rustls rustls-webpki webpki webpki-roots ring aws-lc-rs aws-lc-sys openssl openssl-sys \
    native-tls tokio-rustls hyper-rustls reqwest hyper ureq curl curl-sys; do
    if grep -qxF "$c" "$tmpdir/ws-names"; then
        printf '%s\n' "$c" >>"$tmpdir/tls-hits"
    fi
done
if [ -s "$tmpdir/tls-hits" ]; then
    fail "INV-24: TLS/HTTP-client crates in the default build:
$(cat "$tmpdir/tls-hits")"
fi
refuse_intruders "$tmpdir/model" "$tmpdir/allowed-model" "harness-model"

# --- test-only seams stay out of normal builds (H1c review F-3) -------------
# harness-journal's `fault-injection` feature compiles a JournalFile that
# fails (or succeeds) on demand. The seam is sealed, and only
# [dev-dependencies] may enable the feature: no NORMAL edge anywhere in the
# workspace may. The all-edges tree must name the feature, so a rename
# cannot make this check vacuous.
cargo tree --workspace -e all,features >"$tmpdir/feat-all" ||
    fail "cargo tree failed: --workspace -e all,features"
grep -qF 'harness-journal feature "fault-injection"' "$tmpdir/feat-all" ||
    fail "the fault-injection feature is not in the all-edges tree (renamed? read nothing?)"
cargo tree --workspace --target all -e normal,build,features >"$tmpdir/feat-normal" ||
    fail "cargo tree failed: --workspace --target all -e normal,build,features"
grep -q 'harness-journal' "$tmpdir/feat-normal" ||
    fail "the normal feature tree does not name harness-journal (read nothing?)"
if grep -qF 'fault-injection' "$tmpdir/feat-normal"; then
    fail "a normal dependency edge enables harness-journal/fault-injection"
fi
# H1c confirming review NF-1: `cargo tree` shows only ACTIVE features, so a
# workspace feature that merely FORWARDS to fault-injection (e.g.
# `chaos = ["harness-journal/fault-injection"]`) is invisible above. No
# `[features]` table in the workspace may mention it, except the feature's
# own definition in harness-journal.
: >"$tmpdir/fwd-hits"
for toml in crates/*/Cargo.toml; do
    awk -v f="$toml" '
        /^[ \t]*\[/ { sec = $0 }
        sec ~ /^[ \t]*\[features\]/ && /fault-injection/ {
            if (!(f ~ /harness-journal/ && $0 ~ /^[ \t]*fault-injection[ \t]*=[ \t]*\[[ \t]*\][ \t]*$/))
                print f ": " $0
        }' "$toml" >>"$tmpdir/fwd-hits" || fail "awk failed on $toml"
done
if [ -s "$tmpdir/fwd-hits" ]; then
    fail "a workspace feature forwards to harness-journal/fault-injection:
$(cat "$tmpdir/fwd-hits")"
fi

# --- shared: file lists and normalisation -----------------------------------

# rust_files OUT DIR...: every .rs file under DIR... (src, tests, benches,
# examples, build scripts), failing on a find error or an empty result.
rust_files() {
    out=$1
    shift
    find "$@" -type f -name '*.rs' >"$tmpdir/found" || fail "find $* failed"
    sort "$tmpdir/found" >"$out" || fail "sort failed"
    [ -s "$out" ] || fail "no Rust files found under $*"
}

# normalise FILE OUT: the file as ONE line, every run of whitespace (space,
# tab, CR, newline) collapsed to one space and the spaces around `::`
# removed, so `use std :: fs`, `use std::{\n fs,\n}` and `enum<TAB>X` all
# read like their one-line forms.
normalise() {
    awk '{ printf "%s ", $0 } END { printf "\n" }' "$1" >"$tmpdir/joined" ||
        fail "awk could not read $1"
    awk '{ gsub(/[ \t\r]+/, " "); gsub(/ ?:: ?/, "::"); print }' \
        "$tmpdir/joined" >"$2" || fail "awk could not normalise $1"
}

# strip_comments FILE OUT: the file's CODE: `//` line comments and nested
# `/* */` block comments removed, and the contents of string, raw-string,
# byte-string and char literals removed (the delimiters stay). H1a review
# N-3 added the comment stripping; H1e-1 review NF-B showed a plain stripper
# can be fooled by `"/*"` … `"*/"` or `"//"` inside literals, so this one
# tracks literals: `"…"` with escapes, `r#*"…"#*`, `br…` and `cr…` (H1f-4 review
# F-2: a raw C string read as an escaped one hid code), `b"…"`, `c"…"`, and
# `'x'`/`'\n'`/`'é'` char literals (a `'` not closing within one character
# is a lifetime). Every scan runs on BOTH the raw text and this code view.
strip_comments() {
    LC_ALL=C awk '
    function ident_before(line, i,    pc) {
        if (i <= 1) return 0
        pc = substr(line, i - 1, 1)
        return pc ~ /[A-Za-z0-9_]/
    }
    BEGIN { mode = "code"; depth = 0; hashes = 0; hs = "" }
    {
        line = $0; n = length(line); out = ""; i = 1
        while (i <= n) {
            c = substr(line, i, 1); c2 = substr(line, i, 2)
            if (mode == "block") {
                if (c2 == "/*") { depth++; i += 2; continue }
                if (c2 == "*/") { depth--; i += 2; if (depth == 0) { mode = "code"; out = out " " }; continue }
                i++; continue
            }
            if (mode == "str") {
                if (c == "\\") { i += 2; continue }
                if (c == "\"") { out = out "\""; mode = "code"; i++; continue }
                i++; continue
            }
            if (mode == "raw") {
                if (c == "\"" && substr(line, i + 1, hashes) == hs) {
                    out = out "\"" hs; i += 1 + hashes; mode = "code"; continue
                }
                i++; continue
            }
            if (c2 == "//") break
            if (c2 == "/*") { mode = "block"; depth = 1; i += 2; continue }
            if (c == "\"") { out = out "\""; mode = "str"; i++; continue }
            if ((c == "r" || c2 == "br" || c2 == "cr") && !ident_before(line, i)) {
                j = i + ((c == "b" || c == "c") ? 2 : 1); h = 0
                while (substr(line, j, 1) == "#") { h++; j++ }
                if (substr(line, j, 1) == "\"") {
                    hashes = h; hs = ""; for (k = 0; k < h; k++) hs = hs "#"
                    out = out substr(line, i, j - i + 1); mode = "raw"; i = j + 1; continue
                }
            }
            if (c == "\047") {
                if (substr(line, i + 1, 1) == "\\") {
                    k = i + 3
                    while (k <= n && substr(line, k, 1) != "\047") { if (substr(line, k, 1) == "\\") k++; k++ }
                    out = out "\047\047"; i = k + 1; continue
                }
                if (substr(line, i + 2, 1) == "\047") { out = out "\047\047"; i += 3; continue }
                if (match(substr(line, i + 1, 6), /^[\200-\377]+\047/)) { out = out "\047\047"; i += 1 + RLENGTH; continue }
                out = out c; i++; continue
            }
            out = out c; i++
        }
        print out
    }' "$1" >"$2" || fail "awk could not read $1 (stripping comments)"
}

# scan WHAT PATTERN NORMALISED FILE: record a hit if the ERE matches.
# grep's exit status is read directly: 0 = hit, 1 = clean, anything else =
# an error, which fails the gate.
scan() {
    rc=0
    grep -aoE "$2" "$3" >"$tmpdir/match" || rc=$?
    case $rc in
        0) while IFS= read -r m; do
               printf '%s: %s: %s\n' "$4" "$1" "$m" >>"$tmpdir/hits"
           done <"$tmpdir/match" ;;
        1) ;;
        *) fail "grep error (rc=$rc) scanning $4" ;;
    esac
}

# Identifier boundary (grep -E has no portable \b).
nb='[^A-Za-z0-9_]'

# --- 2. content ------------------------------------------------------------

# Refuse I/O, process, environment, thread, console, and clock facilities BY
# NAME in the pure crates. (std::time::Duration is fine: it is a length of
# time, not a clock read — time is passed IN, design §2.4.)
# `path` is in the list (review F-2): std::path::Path does filesystem I/O
# through methods (exists, canonicalize, read_dir, ...) that never name
# std::fs, so the pure crates may not import std::path at all.
facility='(fs|net|process|env|io|os|thread|path)'
rust_files "$tmpdir/pure-files" crates/gate-outcome crates/harness-core \
    crates/harness-manifest crates/harness-policy crates/harness-model-core
for must in crates/gate-outcome/src/lib.rs crates/harness-core/src/lib.rs \
    crates/harness-manifest/src/lib.rs crates/harness-policy/src/lib.rs \
    crates/harness-model-core/src/lib.rs crates/harness-model-core/src/wire.rs; do
    grep -qxF "$must" "$tmpdir/pure-files" || fail "pure-content scan would miss $must"
done
: >"$tmpdir/hits"
while IFS= read -r f; do
  strip_comments "$f" "$tmpdir/stripped"
  normalise "$tmpdir/stripped" "$tmpdir/norm-code"
  for view in raw code; do
    if [ "$view" = raw ]; then normalise "$f" "$tmpdir/norm"; else cp "$tmpdir/norm-code" "$tmpdir/norm" || fail "cp failed"; fi
    # std::fs, ::std::io::stdout, std :: net ...
    scan "std path" "(^|$nb)std::$facility($nb|\$)" "$tmpdir/norm" "$f"
    # use std::{collections::HashMap, fs}; use std::{fs as f, net as n};
    # (anything inside a std::{…} group up to the end of the use item)
    scan "std group import" "(^|$nb)std::\{([^;]*[^A-Za-z0-9_;])?$facility($nb|\$)" \
        "$tmpdir/norm" "$f"
    # use std as s; use std::{self as s}; extern crate std as s;
    scan "renamed std" "(^|$nb)std as($nb|\$)" "$tmpdir/norm" "$f"
    scan "renamed std" "(^|$nb)std::\{([^;]*[^A-Za-z0-9_;])?self($nb|\$)" "$tmpdir/norm" "$f"
    scan "clock" "(^|$nb)(SystemTime|Instant|UNIX_EPOCH)($nb|\$)" "$tmpdir/norm" "$f"
    # Path/PathBuf I/O methods, however the receiver was obtained (belt and
    # braces for the `path` facility above).
    scan "path I/O method" "\.(exists|try_exists|metadata|symlink_metadata|canonicalize|read_dir|read_link|is_file|is_dir|is_symlink) ?\(" "$tmpdir/norm" "$f"
    scan "console" "(^|$nb)(print|println|eprint|eprintln|dbg)!" "$tmpdir/norm" "$f"
    scan "thread" "(^|$nb)thread::spawn($nb|\$)" "$tmpdir/norm" "$f"
    scan "async" "(^|$nb)async ?(fn|move|\{)" "$tmpdir/norm" "$f"
    scan "runtime crate" "(^|$nb)(tokio|mio|async_std)($nb|\$)" "$tmpdir/norm" "$f"
  done
  # Code-only scans (comments stripped, so prose mentioning the words is
  # fine). H1a review N-3: module and file inclusion from elsewhere,
  # compile-time reads, macros that could splice a forbidden path, and
  # global state.
  scan "#[path] module" "#\[ ?path ?=" "$tmpdir/norm-code" "$f"
  scan "compile-time read" "(^|$nb)(include|include_str|include_bytes|env|option_env) ?!" "$tmpdir/norm-code" "$f"
  scan "macro_rules" "(^|$nb)macro_rules ?!" "$tmpdir/norm-code" "$f"
  scan "static item" "(^|[^A-Za-z0-9_'])static (mut )?[A-Za-z_]" "$tmpdir/norm-code" "$f"
done <"$tmpdir/pure-files"
if [ -s "$tmpdir/hits" ]; then
    fail "pure sources name forbidden facilities:
$(cat "$tmpdir/hits")"
fi


# --- 2b. harness-model: no pure file shares a crate with sockets ----------------
# H1d review F-3 / H1e-1 review NF-A: the pure half of the model layer is the
# separate pure crate harness-model-core (scanned and allowlisted above), so
# it has no I/O sibling to reach by any path, alias or glob. harness-model
# itself must not grow pure-looking modules again: its modules are exactly
# the I/O ones.
grep -oE '^(pub(\(crate\))? )?mod [a-z_]+;' crates/harness-model/src/lib.rs >"$tmpdir/model-mods-raw" ||
    fail "no module declarations found in harness-model/src/lib.rs (read nothing?)"
awk '{ print $NF }' "$tmpdir/model-mods-raw" | tr -d ';' >"$tmpdir/model-mods" ||
    fail "awk failed on the module list"
while IFS= read -r m; do
    case " http client replay smoke scripted " in
        *" $m "*) ;;
        *) fail "harness-model module '$m' is not one of its I/O modules (pure code belongs in harness-model-core)" ;;
    esac
done <"$tmpdir/model-mods"

# --- 2c. typed provenance and single construction sites ----------------------
# `harness_core::TrustedName` is SEALED (H1e-1 review NF-C): the compiler
# refuses an implementation outside harness-core whatever the trait is called.
# As a second, readable fence the token itself may appear in CODE only in
# the trait's owner and its one consumer. `Box::leak`/`.leak()` is refused
# everywhere: it is how runtime text could become the `&'static str` that
# `Ident::of` takes. `Meter::new` appears only where the one real Meter is
# built (the run driver, with the real clock) and in the meter's own tests.
rust_files "$tmpdir/all-files" crates
: >"$tmpdir/hits"
while IFS= read -r f; do
    strip_comments "$f" "$tmpdir/stripped"
    normalise "$tmpdir/stripped" "$tmpdir/norm"
    case "$f" in
        crates/harness-core/src/lib.rs|crates/harness-journal/src/canon.rs) ;;
        *) scan "TrustedName outside its owner" "(^|$nb)TrustedName($nb|\$)" "$tmpdir/norm" "$f" ;;
    esac
    scan "leak" "(^|$nb)(Box::leak|String::leak|Vec::leak)($nb|\$)" "$tmpdir/norm" "$f"
    scan "leak" "\.leak ?\(" "$tmpdir/norm" "$f"
    case "$f" in
        crates/harness-core/src/lib.rs|crates/harness-model-core/src/protocol.rs|crates/harness-run/src/driver.rs) ;;
        *) scan "Meter construction" "(^|$nb)Meter::new(_resumed)? ?\(" "$tmpdir/norm" "$f" ;;
    esac
done <"$tmpdir/all-files"
if [ -s "$tmpdir/hits" ]; then
    fail "provenance or construction-site fence:
$(cat "$tmpdir/hits")"
fi

# --- 2e. the shipped binary uses the real locality probe (INV-35) ----------
# `rustyharness` must use exactly the production probe,
# `harness_sandbox::locality::SystemProbe` (spike S-F1), and nothing in any
# build of it may choose another (H1e-2b review F-2). Checked by content,
# not by name (H1e-2b confirming review NF-2: a local `struct` with the
# production name passed a name-only check): main.rs must import the probe
# from its real path, name it exactly twice (that import and the one
# `probe:` field), and define or alias nothing (no struct, enum, trait,
# impl, mod, type, const, static, macro or `as` rename) that could shadow
# it. (Tests pass their own probe to the CLI library in process; the
# binary has no switch.)
strip_comments crates/harness-cli/src/main.rs "$tmpdir/cli-main"
normalise "$tmpdir/cli-main" "$tmpdir/cli-main-norm"
count() { grep -o -- "$1" "$tmpdir/cli-main-norm" | wc -l | tr -d ' '; }
cli_bad=""
[ "$(count 'probe:')" = 1 ] || cli_bad="$cli_bad; not exactly one probe field"
grep -qF 'probe: &SystemProbe,' "$tmpdir/cli-main-norm" || cli_bad="$cli_bad; the probe field is not &SystemProbe"
grep -qF 'use harness_sandbox::locality::SystemProbe;' "$tmpdir/cli-main-norm" ||
    cli_bad="$cli_bad; SystemProbe is not imported from harness_sandbox::locality"
[ "$(count 'SystemProbe')" = 2 ] || cli_bad="$cli_bad; SystemProbe is named other than by its import and its use"
if grep -qE "(^|$nb)(struct|enum|trait|impl|mod|type|const|static|macro_rules)($nb|\$)| as " "$tmpdir/cli-main-norm"; then
    cli_bad="$cli_bad; main.rs defines or renames an item"
fi
if [ -n "$cli_bad" ]; then
    fail "the rustyharness binary must use exactly the production probe, harness_sandbox::locality::SystemProbe (crates/harness-cli/src/main.rs)$cli_bad"
fi

# --- 2f. INV-23: one spawn module, three fixed programs ---------------------
# Prompts, task text and approval payloads never appear on any argv (design
# §10 INV-23, R3 H-08). Structural, not by call shape (H1f-4 review F-1:
# turbofish, UFCS, aliases, raw identifiers and macros all defeat a pattern
# for `Command::new(`): every spawn in the harness goes through the closed
# `Query` enum in crates/harness-sandbox/src/capture.rs, which fixes each
# program and argv. So:
#   - no symlink under crates/, and no `#[path]` or `include!` in any source
#     under crates/*/src (they could bring in code this scan never reads);
#   - no source file with a NUL byte (a NUL makes grep read a file as binary);
#   - the words `Command`, `CommandExt` and `raw_arg` appear in code (comments
#     and literal contents stripped) in no source under crates/*/src except
#     capture.rs and its `#[cfg(test)]` tests (capture/tests.rs); any spelling
#     of a spawn has to write one of them;
#   - capture.rs declares its tests `#[cfg(test)]`, names `Command` (so the
#     scan read it), and every absolute-path literal in it is one of the
#     programs §4.5 lists: /sbin/mount, /usr/sbin/sysctl, /usr/bin/vm_stat;
#   - capture.rs is pinned by its SHA-256 (H1f-4 confirming review NF-2: a
#     relative program name or an extra argument passed the literal check),
#     so its programs, argv and bounds change only with this gate, by review.
# Section 5 below closes what these scans cannot read: dependencies,
# targets outside src/, foreign code, cargo configuration. Integration tests
# (crates/*/tests/) are separate test crates and may spawn freely. Fails
# closed on legitimate code too: prose inside code, a type or method named
# `Command` elsewhere, or any change to capture.rs are all refused, and
# need a review of this gate to allow.
spawn_file=crates/harness-sandbox/src/capture.rs
spawn_tests=crates/harness-sandbox/src/capture/tests.rs
find crates -type l >"$tmpdir/links" || fail "find failed (INV-23 symlinks)"
if [ -s "$tmpdir/links" ]; then
    fail "INV-23: symlinks under crates/ (a source could hide behind one):
$(cat "$tmpdir/links")"
fi
find crates -path '*/src/*' -type f -name '*.rs' >"$tmpdir/argv-found" || fail "find failed (INV-23)"
sort "$tmpdir/argv-found" >"$tmpdir/argv-files" || fail "sort failed (INV-23)"
for must in "$spawn_file" "$spawn_tests" crates/harness-sandbox/src/locality.rs; do
    grep -qxF "$must" "$tmpdir/argv-files" || fail "INV-23 scan would miss $must"
done
: >"$tmpdir/hits"
while IFS= read -r f; do
  tr -d '\000' <"$f" >"$tmpdir/argv-nonul" || fail "tr failed on $f (INV-23)"
  rc=0
  cmp -s "$tmpdir/argv-nonul" "$f" || rc=$?
  case $rc in
      0) ;;
      1) printf '%s: INV-23: a NUL byte in a source file\n' "$f" >>"$tmpdir/hits" ;;
      *) fail "cmp failed on $f (INV-23)" ;;
  esac
  strip_comments "$f" "$tmpdir/argv-stripped"
  normalise "$tmpdir/argv-stripped" "$tmpdir/argv-code"
  scan "INV-23: #[path] module" '#\[ ?path ?=' "$tmpdir/argv-code" "$f"
  scan "INV-23: compile-time include" "(^|$nb)(include|include_str|include_bytes) ?!" "$tmpdir/argv-code" "$f"
  case $f in
      "$spawn_file" | "$spawn_tests") continue ;;
  esac
  scan "INV-23: a spawn outside $spawn_file" "(^|$nb)(Command|CommandExt|raw_arg)($nb|\$)" "$tmpdir/argv-code" "$f"
done <"$tmpdir/argv-files"
strip_comments "$spawn_file" "$tmpdir/spawn-stripped"
normalise "$tmpdir/spawn-stripped" "$tmpdir/spawn-code"
grep -qF '#[cfg(test)] mod tests;' "$tmpdir/spawn-code" ||
    printf '%s: INV-23: its tests are not declared #[cfg(test)] mod tests;\n' "$spawn_file" >>"$tmpdir/hits"
grep -qE "(^|$nb)Command($nb|\$)" "$tmpdir/spawn-code" ||
    fail "INV-23: $spawn_file names no Command (read nothing?)"
normalise "$spawn_file" "$tmpdir/spawn-raw"
rc=0
grep -aoE '"/[^"]*"' "$tmpdir/spawn-raw" >"$tmpdir/spawn-programs" || rc=$?
case $rc in
    0) ;;
    1) fail "INV-23: $spawn_file names no program (read nothing?)" ;;
    *) fail "grep error (rc=$rc) listing programs in $spawn_file" ;;
esac
while IFS= read -r prog; do
    case $prog in
        '"/sbin/mount"' | '"/usr/sbin/sysctl"' | '"/usr/bin/vm_stat"') ;;
        *) printf '%s: INV-23: program %s is not one §4.5 lists\n' "$spawn_file" "$prog" >>"$tmpdir/hits" ;;
    esac
done <"$tmpdir/spawn-programs"
if [ -s "$tmpdir/hits" ]; then
    fail "INV-23: spawns are confined to the closed query set in $spawn_file:
$(cat "$tmpdir/hits")"
fi
# The one spawn site, pinned. Update only with a review of the change.
capture_sha256=820d1e817b7430149ca644d4b8014636761facc17298b2e86a5883b0f14b0049
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum <"$spawn_file" >"$tmpdir/capture-sha" || fail "sha256sum failed on $spawn_file"
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 <"$spawn_file" >"$tmpdir/capture-sha" || fail "shasum failed on $spawn_file"
else
    fail "INV-23: neither sha256sum nor shasum is on PATH (cannot check $spawn_file)"
fi
read -r capture_got _ <"$tmpdir/capture-sha" || fail "could not read the digest of $spawn_file"
[ "$capture_got" = "$capture_sha256" ] ||
    fail "INV-23: $spawn_file is not the reviewed version (sha256 $capture_got, pinned $capture_sha256): the one spawn site changes only with this gate; review the change, then update capture_sha256 in scripts/ci/purity.sh"

# --- 2d. compile-fail doctests pin their reason (H1a review N-6) -------------
# Every compile_fail doctest names its expected error code; gates.sh runs the
# doctests with RUSTC_BOOTSTRAP=1 so rustdoc enforces the codes.
grep -rn '```compile_fail' crates >"$tmpdir/cf" || fail "no compile_fail doctests found (read nothing?)"
grep -vE '```compile_fail,E[0-9]{4}' "$tmpdir/cf" >"$tmpdir/cf-bad" || true
if [ -s "$tmpdir/cf-bad" ]; then
    fail "compile_fail doctests without an expected error code:
$(cat "$tmpdir/cf-bad")"
fi

# --- 3. INV-28: exactly one outcome type -----------------------------------

rust_files "$tmpdir/harness-files" crates/harness-*
grep -qxF crates/harness-core/src/lib.rs "$tmpdir/harness-files" ||
    fail "INV-28 scan would miss crates/harness-core/src/lib.rs"
: >"$tmpdir/hits"
while IFS= read -r f; do
    normalise "$f" "$tmpdir/norm"
    # Prefix match on purpose: `enum RunOutcomeKind` is refused too.
    scan "INV-28" "(^|$nb)enum [A-Za-z0-9_]*(Outcome|Verdict)" "$tmpdir/norm" "$f"
    # And with comments stripped (`enum /*c*/ RunOutcome`, H1a review N-3).
    strip_comments "$f" "$tmpdir/stripped"
    normalise "$tmpdir/stripped" "$tmpdir/norm"
    scan "INV-28" "(^|$nb)enum [A-Za-z0-9_]*(Outcome|Verdict)" "$tmpdir/norm" "$f"
done <"$tmpdir/harness-files"
if [ -s "$tmpdir/hits" ]; then
    fail "INV-28: verdict enums must live in gate-outcome, not harness-*:
$(cat "$tmpdir/hits")"
fi

# --- 4. no optimised build contains the journal's test seams (H1c NF-1) ------
# harness-journal has a compile_error! for `fault-injection` without debug
# assertions. Check that it FIRES (content, not presence of the line) by
# expanding the crate root with rustc directly: macro expansion reports the
# compile_error! before any dependency is resolved, so this needs no build,
# and nothing is cached between runs (a cached `cargo check` could report a
# stale result for a tree copied with old mtimes). Control: with debug
# assertions on (test builds) it must NOT fire.
command -v rustc >/dev/null 2>&1 || fail "rustc not found on PATH"
# fi_check DEBUG CRATE FEATURE: expand CRATE's root with FEATURE on and
# debug assertions DEBUG; count the compile_error! message.
fi_check() {
    rustc --edition 2021 --crate-type lib --crate-name "$(printf '%s' "$2" | tr - _)" \
        --cfg "feature=\"$3\"" -C "debug-assertions=$1" --emit=metadata \
        -o "$tmpdir/fi.rmeta" "crates/$2/src/lib.rs" >"$tmpdir/fi-$1" 2>&1 || true
    grep -c "test-only and refused in optimised builds" "$tmpdir/fi-$1" >"$tmpdir/fi-count" || true
    read -r fi_n <"$tmpdir/fi-count" || fi_n=0
}
for seam in harness-journal:fault-injection; do
    crate=${seam%%:*}
    feature=${seam#*:}
    fi_check off "$crate" "$feature"
    [ "${fi_n:-0}" -gt 0 ] ||
        fail "an optimised build with $crate/$feature compiles (the compile_error! is gone):
$(cat "$tmpdir/fi-off")"
    fi_check on "$crate" "$feature"
    [ "${fi_n:-0}" -eq 0 ] ||
        fail "the $crate/$feature compile_error! also fires with debug assertions on (tests would break)"
done

# --- 5. INV-23: the binary is built only from what this gate reads ----------
# §2f reads the workspace's own sources, so a spawn in code it never reads
# passed it (H1f-4 confirming review NF-1: a path dependency outside crates/
# spawned with the task text on its argv, and purity passed). So:
#   - every package in the normal and build tree, for every target, is a
#     workspace crate at crates/<name> (read by §2f) or a crates.io crate on
#     the reviewed list below. None of those can start a process (libc only
#     through unsafe code, see below). A path dependency outside crates/, a
#     [patch] onto a path, a git or another registry's crate is refused;
#   - every target is a lib or bin whose root is under crates/*/src/ (read
#     by §2f) or a test under crates/*/tests/ (a separate crate, never
#     shipped). No build script (it can add linker arguments or generate
#     code), proc macro (it writes code no scan reads), bench, example or
#     other crate type (NF-3);
#   - every lib and bin root opens with `#![forbid(unsafe_code)]`, which no
#     inner attribute can lower: no crate calls foreign code (libc's exec
#     family, a declared extern), uses `global_asm!` or places a static in
#     a link section;
#   - no `.cargo` directory in the repository (its config can add linker
#     arguments or rustc flags).
# Out of scope, named: the toolchain, the build environment (RUSTFLAGS, the
# user's own cargo config, the libraries on the linker's path: a `#[link]`
# can name one, and only its load-time code would run, since calling into it
# needs unsafe), and the listed crates' own code at their locked versions
# (supply chain, design §8; cargo-deny checks their advisories).
# (Dev-dependencies are not in this tree: only tests can use them.)

# grab OUT ERE FILE WHAT: every match of ERE in FILE, one per line; none, or
# a grep error, fails the gate.
grab() {
    rc=0
    grep -aoE "$2" "$3" >"$1" || rc=$?
    case $rc in
        0) ;;
        1) fail "INV-23: $4: nothing found (read nothing?)" ;;
        *) fail "grep error (rc=$rc) reading $4" ;;
    esac
}
cargo metadata --no-deps --format-version 1 >"$tmpdir/meta" || fail "cargo metadata failed (INV-23)"
grab "$tmpdir/meta-root" '"workspace_root":"[^"]*"' "$tmpdir/meta" "cargo metadata's workspace_root"
ws_root=$(awk -F'"' 'NR == 1 { print $4 } END { if (NR != 1) exit 1 }' "$tmpdir/meta-root") ||
    fail "INV-23: cargo metadata names more than one workspace_root"
case $ws_root in
    /*) ;;
    *) fail "INV-23: the workspace root is not an absolute path: $ws_root" ;;
esac
case $ws_root in
    *\\*) fail "INV-23: the workspace root has an escaped character this gate does not read: $ws_root" ;;
esac

# Packages. $tmpdir/ws-raw is the INV-24 section's tree (normal and build
# edges, every target). cargo tree prints a crates.io crate as `name vX`,
# any other source in parentheses: a path, a git URL, another registry.
ws_root=$ws_root awk '
    BEGIN { root = ENVIRON["ws_root"] }
    NF == 0 { next }
    {
        line = $0
        if (substr(line, length(line) - 3) == " (*)") line = substr(line, 1, length(line) - 4)
        head = $1 " " $2
        pm = head " (proc-macro)"
        here = " (" root "/crates/" $1 ")"
        if ($2 !~ /^v[0-9]/) print "other\t" $0
        else if (line == head || line == pm) print "registry\t" $1
        else if (line == head here || line == pm here) print "workspace\t" $1
        else print "other\t" $0
    }' "$tmpdir/ws-raw" >"$tmpdir/ws-class" || fail "awk failed classifying the workspace tree (INV-23)"
awk -F'\t' '$1 == "other" { print $2 }' "$tmpdir/ws-class" >"$tmpdir/ws-other" || fail "awk failed (INV-23)"
if [ -s "$tmpdir/ws-other" ]; then
    fail "INV-23: crates in the build whose source this gate does not read (only crates.io crates on its list and workspace crates at crates/<name> are allowed):
$(cat "$tmpdir/ws-other")"
fi
awk -F'\t' '$1 == "workspace" { print $2 }' "$tmpdir/ws-class" >"$tmpdir/ws-members" || fail "awk failed (INV-23)"
for must in harness-cli harness-sandbox; do
    grep -qxF "$must" "$tmpdir/ws-members" ||
        fail "INV-23: the workspace tree does not show $must at crates/$must (read nothing?)"
done
awk -F'\t' '$1 == "registry" { print $2 }' "$tmpdir/ws-class" >"$tmpdir/ws-registry-raw" || fail "awk failed (INV-23)"
sort -u "$tmpdir/ws-registry-raw" >"$tmpdir/ws-registry" || fail "sort failed (INV-23)"
# The reviewed crates.io crates: the union of the pure crates' allowlists
# above. None has a process API; a new one needs a review that it has none.
printf '%s\n' \
    serde serde_core serde_derive proc-macro2 quote syn unicode-ident \
    serde_json itoa ryu memchr zmij thiserror thiserror-impl \
    sha2 digest block-buffer hybrid-array typenum crypto-common cfg-if \
    cpufeatures libc >"$tmpdir/allowed-registry-raw"
sort -u "$tmpdir/allowed-registry-raw" >"$tmpdir/allowed-registry" || fail "sort failed (INV-23)"
comm -23 "$tmpdir/ws-registry" "$tmpdir/allowed-registry" >"$tmpdir/ws-unlisted" || fail "comm failed (INV-23)"
if [ -s "$tmpdir/ws-unlisted" ]; then
    fail "INV-23: crates.io crates in the build that are not on this gate's reviewed list (each needs a review that it cannot start a process):
$(cat "$tmpdir/ws-unlisted")"
fi

# Targets, from cargo metadata. Each is read in one shape; the count check
# fails closed if cargo prints its fields in another order.
grab "$tmpdir/meta-src" '"src_path":' "$tmpdir/meta" "cargo metadata's targets"
grab "$tmpdir/meta-targets" '"kind":\[[^]]*\],"crate_types":\[[^]]*\],"name":"[^"]*","src_path":"[^"]*"' \
    "$tmpdir/meta" "cargo metadata's targets"
n_src=$(awk 'END { print NR }' "$tmpdir/meta-src") || fail "awk failed (INV-23)"
n_read=$(awk 'END { print NR }' "$tmpdir/meta-targets") || fail "awk failed (INV-23)"
[ "$n_src" = "$n_read" ] ||
    fail "INV-23: cargo metadata lists $n_src targets and this gate read $n_read (a field order it does not know?)"
ws_root=$ws_root awk '
    BEGIN { root = ENVIRON["ws_root"] "/crates/" }
    {
        kind = $0; sub(/^"kind":\[/, "", kind); sub(/\],"crate_types":.*$/, "", kind)
        ct = $0; sub(/^.*"crate_types":\[/, "", ct); sub(/\],"name":.*$/, "", ct)
        path = $0; sub(/^.*"src_path":"/, "", path); sub(/"$/, "", path)
        what = kind " target " path
        if (kind == "\"lib\"" && ct == "\"lib\"") dir = "src/"
        else if (kind == "\"bin\"" && ct == "\"bin\"") dir = "src/"
        else if (kind == "\"test\"" && ct == "\"bin\"") dir = "tests/"
        else { print "bad\t" what; next }
        if (index(path, "\\") || index(path, "/../") || index(path, "/./") || index(path, root) != 1) {
            print "bad\t" what; next
        }
        rest = substr(path, length(root) + 1)
        slash = index(rest, "/")
        if (slash < 2 || index(substr(rest, slash + 1), dir) != 1) { print "bad\t" what; next }
        if (dir == "src/") print "root\t" path
    }' "$tmpdir/meta-targets" >"$tmpdir/meta-class" || fail "awk failed classifying targets (INV-23)"
awk -F'\t' '$1 == "bad" { print $2 }' "$tmpdir/meta-class" >"$tmpdir/meta-bad" || fail "awk failed (INV-23)"
if [ -s "$tmpdir/meta-bad" ]; then
    fail "INV-23: targets this gate does not read or allow (only lib and bin roots under crates/*/src/ and tests under crates/*/tests/):
$(cat "$tmpdir/meta-bad")"
fi
awk -F'\t' '$1 == "root" { print $2 }' "$tmpdir/meta-class" >"$tmpdir/meta-roots" || fail "awk failed (INV-23)"
grep -qxF "$ws_root/crates/harness-cli/src/main.rs" "$tmpdir/meta-roots" ||
    fail "INV-23: no target has its root at crates/harness-cli/src/main.rs (read nothing?)"
: >"$tmpdir/hits"
while IFS= read -r f; do
    strip_comments "$f" "$tmpdir/root-stripped"
    normalise "$tmpdir/root-stripped" "$tmpdir/root-code"
    awk '{ sub(/^ +/, ""); if (index($0, "#![forbid(unsafe_code)]") != 1) exit 1 }' "$tmpdir/root-code" ||
        printf '%s: INV-23: does not open with #![forbid(unsafe_code)]\n' "$f" >>"$tmpdir/hits"
done <"$tmpdir/meta-roots"
if [ -s "$tmpdir/hits" ]; then
    fail "INV-23: every crate root forbids unsafe code, first thing (no foreign code, no assembly):
$(cat "$tmpdir/hits")"
fi

# Cargo configuration in the repository.
find . \( -path ./target -o -path ./.git \) -prune -o -name .cargo -print >"$tmpdir/cargo-config" ||
    fail "find failed (INV-23 cargo configuration)"
if [ -s "$tmpdir/cargo-config" ]; then
    fail "INV-23: cargo configuration in the repository (it can add linker arguments or rustc flags):
$(cat "$tmpdir/cargo-config")"
fi

printf 'purity gate OK: dependency shape, pure-content, INV-23 argv, INV-28 all clean.\n'

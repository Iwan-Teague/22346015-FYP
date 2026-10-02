//! The built-in manifest (design §4.8): the read tools, the edit tools
//! (H2b), the confined command runner (H2d) and the submit sentinel.
//!
//! The built-ins are declared by a `harness` manifest and take the same
//! validation and policy path as any provider, with no special case beyond
//! the origin: this text is compiled in, so it alone may use the reserved
//! `harness` namespace and the `builtin` transport.
//!
//! It declares the read tools (`harness.fs.read`, `harness.fs.search`,
//! `harness.fs.list`, `harness.fs.glob` and, since P-24,
//! `harness.fs.outline`), the two edit tools
//! `harness.edit.replace` and `harness.edit.write` (§4.9, H2b), the
//! command runner `harness.exec.run` (§4.8, H2d) and the submit sentinel
//! `harness.task.submit` (§2.5, H1e-2). `harness.notes.write` arrives with
//! the slice that implements it.
//!
//! Read tools: read / operational / own / none, as §4.8's table says;
//! `content` is `third_party` because file contents in a workspace are other
//! people's text by default (§5.4). That changes no default decision (§5.2
//! allows both read rows) and only makes the trifecta label honest.
//!
//! Edit tools: write / operational / own / none (§4.8), `content: own` (an
//! edit's result is the harness's report of what it changed: a path, line
//! numbers and digests, never file text), confirmation `none` as declared.
//! What policy decides for them is `harness-policy`'s (§5.2): allowed by a
//! user allow rule, otherwise an ask, and with no approver a deny. Their
//! schemas are §4.9's `{path, old, new, count = 1}` and §4.8's
//! `{path, content}`; the string caps sit above the 64 KiB action cap
//! (`harness_model_core::protocol::ACTION_MAX_BYTES`), which binds first.
//!
//! The command runner: execute / operational / own / none (§4.8), `content:
//! third_party` (its output quotes workspace text: compiler messages, test
//! names), confirmation `none` as declared; the derived floor makes it need
//! a conformed sandbox (§4.2), and policy asks by default (H2d). Its schema
//! is `{argv: [string], cwd?: string}`: `argv[0]` names a program on the
//! task's exec allowlist, never a path the model chooses (§4.8, INV-13).
//!
//! The sentinel: write / public / own / none (§4.8), `content: own`. It
//! changes nothing but the run's phase; policy allows it by one named rule
//! (`allow.task-submit`).
//!
//! H2e (design rows H2e): `harness.fs.search` matches a literal substring
//! by default, as before, and a regular expression with `regex: true`,
//! with `include` / `exclude` globs and `context` lines; `harness.fs.glob`
//! finds files by a glob pattern (read / operational / own / none, like the
//! other read tools); the `lines` of `harness.fs.read` may go up to 2000,
//! the widest read window a profile may set, while each run's window (100
//! by default) is what the model is shown and what a read returns.
//! `harness.edit.multi {path, edits: [{old, new}]}` makes several exact
//! replacements in one file, all or none, with the edit tools' labels.
//! `harness.task.todo {items?: [{text, status}]}` keeps the model's
//! checklist in the run's state: write / public / own / none, `content:
//! own` (its result echoes the model's own list), like the sentinel; policy
//! allows it by one named rule (`allow.task-todo`). The number of edits and
//! items is bounded by the tools (the schema subset has no `maxItems`).

mod edit_multi;
mod edit_replace;
mod edit_write;
mod exec_run;
mod fs_glob;
mod fs_list;
mod fs_outline;
mod fs_read;
mod fs_search;
mod head;
mod tail;
mod task_submit;
mod task_todo;

use crate::{parse_with_origin, Manifest, ManifestError, Origin, ValidationContext};

/// The built-in manifest text (JSON, manifest v1).
///
/// Assembled at runtime from per-capability fragment literals under
/// `builtin/`, in manifest order; the concatenation is byte-identical to the
/// former single literal (pinned by
/// `tests::builtin_manifest_bytes_unchanged`). A new capability is one
/// fragment module plus one line here. The crate is pure (§1.2: no
/// compile-time file read, no `static`), so the text is rebuilt per call.
pub fn builtin_manifest_json() -> String {
    [
        head::HEAD,
        fs_read::FS_READ,
        fs_search::FS_SEARCH,
        fs_glob::FS_GLOB,
        fs_list::FS_LIST,
        fs_outline::FS_OUTLINE,
        edit_replace::EDIT_REPLACE,
        edit_write::EDIT_WRITE,
        edit_multi::EDIT_MULTI,
        exec_run::EXEC_RUN,
        task_todo::TASK_TODO,
        task_submit::TASK_SUBMIT,
        tail::TAIL,
    ]
    .concat()
}

/// The built-in manifest, validated like any other (plus: it is the only
/// manifest allowed the `harness` namespace and the `builtin` transport).
pub fn manifest(ctx: &ValidationContext) -> Result<Manifest, ManifestError> {
    parse_with_origin(builtin_manifest_json().as_bytes(), ctx, Origin::Compiled)
}

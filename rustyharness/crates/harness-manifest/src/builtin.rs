//! The built-in manifest (design §4.8): the read tools, the edit tools
//! (H2b), the confined command runner (H2d) and the submit sentinel.
//!
//! The built-ins are declared by a `harness` manifest and take the same
//! validation and policy path as any provider, with no special case beyond
//! the origin: this text is compiled in, so it alone may use the reserved
//! `harness` namespace and the `builtin` transport.
//!
//! It declares the read tools (`harness.fs.read`, `harness.fs.search`,
//! `harness.fs.glob`, `harness.fs.list` and, since P-24,
//! `harness.fs.outline`), the two edit tools
//! `harness.edit.replace` and `harness.edit.write` (§4.9, H2b), the edit
//! script `harness.edit.patch`, the file operations `harness.edit.delete`
//! and `harness.edit.move` (P-25), the
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
//! `harness.task.delegate {task}` (P-38) starts a read-only helper run:
//! read / operational / own / none, `content: third_party` (its report is
//! other people's text by default, like the read tools' results).

mod edit_delete;
mod edit_move;
mod edit_multi;
mod edit_patch;
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
mod task_delegate;
mod task_submit;
mod task_todo;
mod web_fetch;
mod web_search;

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
        edit_patch::EDIT_PATCH,
        edit_delete::EDIT_DELETE,
        edit_move::EDIT_MOVE,
        exec_run::EXEC_RUN,
        task_todo::TASK_TODO,
        task_delegate::TASK_DELEGATE,
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

/// The research manifest text (JSON, manifest v1; P-39b, §2.2): the web
/// airlock's two tools plus the checklist and the submit sentinel, in
/// manifest order. Assembled from the same fragment literals as the coding
/// manifest (`task_todo` and `task_submit` reused byte for byte); the
/// concatenation is pinned by `tests::research_manifest_bytes_pinned`, and
/// the coding manifest's by `tests::builtin_manifest_bytes_unchanged`, so
/// neither can drift under the other.
pub fn research_manifest_json() -> String {
    [
        head::HEAD,
        web_fetch::WEB_FETCH,
        web_search::WEB_SEARCH,
        task_todo::TASK_TODO,
        task_submit::TASK_SUBMIT,
        tail::TAIL,
    ]
    .concat()
}

/// The research manifest, validated like any other (plus: it shares the
/// reserved `harness` namespace and the `builtin` transport with the coding
/// manifest, and a registry admits one or the other, never both, P-39b §2.2).
pub fn research_manifest(ctx: &ValidationContext) -> Result<Manifest, ManifestError> {
    parse_with_origin(research_manifest_json().as_bytes(), ctx, Origin::Compiled)
}

/// The terse tool docs (P-53): one fixed sentence per built-in capability,
/// naming each of its arguments, for profiles with `tool_docs: "terse"`
/// (small local models read shorter tool declarations better). The table is
/// fixed: entries are shorter than the manifest summaries and name every
/// argument the schema has (both pinned by tests). A capability without an
/// entry here keeps its full summary, so a provider capability is untouched.
const TERSE_TABLE: [(&str, &str); 15] = [
    (
        "harness.fs.read",
        "Read a window of lines from a file: path, start (the first line, 1-based), lines (at most the run's read window)",
    ),
    (
        "harness.fs.search",
        "Search files line by line for pattern (a regex when regex is true): path, include and exclude globs, context lines",
    ),
    ("harness.fs.glob", "Find files whose paths match the glob pattern, below path"),
    ("harness.fs.list", "List a directory: path, depth"),
    ("harness.fs.outline", "Outline a file or directory's symbols: path, kind"),
    (
        "harness.edit.replace",
        "Replace old with new in path, matching exactly count times (default 1)",
    ),
    ("harness.edit.write", "Create a new file or rewrite a whole file: path, content"),
    (
        "harness.edit.multi",
        "Make several exact replacements in one file, all or none: path, edits (each old and new)",
    ),
    (
        "harness.edit.patch",
        "Apply a `*** Begin Patch` script across files, all or none: patch (Add File, Update File and Delete File sections)",
    ),
    (
        "harness.edit.delete",
        "Delete one read file, keeping a pre-image: path",
    ),
    (
        "harness.edit.move",
        "Move one read file to a new path, refusing an existing target: path, to",
    ),
    (
        "harness.exec.run",
        "Run one allowed program with no network: argv (the first item names it), cwd",
    ),
    (
        "harness.task.todo",
        "Keep your checklist: items replaces the list, each item a text and a status; without items it is only shown",
    ),
    ("harness.task.submit", "Submit the task for verification: note"),
    (
        "harness.task.delegate",
        "Ask a read-only helper to explore and answer one question: task",
    ),
];

/// The terse sentence for a built-in capability id, or `None` (keep the
/// manifest summary) when the id is unknown to the table.
pub fn terse_summary(id: &str) -> Option<&'static str> {
    TERSE_TABLE
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, doc)| *doc)
}

/// The terse table in a canonical text form, one `id\tterse` line per
/// entry in table order: what the run header's `tool_docs` digest is taken
/// over, so a journal from a build whose table differs is refused by name
/// (the same rule the `builtin_manifest` digest follows).
pub fn terse_table_text() -> String {
    let mut s = String::new();
    for (id, doc) in TERSE_TABLE {
        s.push_str(id);
        s.push('\t');
        s.push_str(doc);
        s.push('\n');
    }
    s
}

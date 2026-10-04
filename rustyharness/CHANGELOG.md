# Changelog

All notable changes to rustyharness are listed here.
Versions follow the workspace manifest's `version`.

## [0.2.0] — 2026-10

The interactive era, still fail-closed. Highlights since the first
internal releases (0.0.x):

- **Interactive sessions.** `chat`, the line REPL: follow-up messages,
  slash commands (`/status`, `/tools`, `/diff`, `/undo`, `/rewind`,
  `/plan`, `/build`, `/fork`, `/apply`, ...), streaming through the
  display sanitizer, session resume (`--resume`, `--continue`) and fork
  (`--fork RUN@STEP`). `acp` serves the Agent Client Protocol v1 over
  stdio for editors.
- **Workspace modes.** `--workspace-mode scratch` (with
  `--scratch-with-git`) runs on a copy; `apply` and `/apply` copy the
  edits back after a diff and a typed confirmation.
- **Tools.** `harness.fs.glob` and `harness.fs.outline`,
  `harness.edit.multi`, `harness.edit.patch`, `harness.edit.delete` and
  `harness.edit.move`, `harness.task.todo`, `harness.task.delegate`
  (read-only subagents, P-38), background commands
  (`harness.exec.start`, loopback port grants, P-36), web fetch through
  a host airlock (P-39), MCP client and stdio-server capabilities
  (P-37), and the terse tool-documentation table for small models
  (P-53).
- **Hosted models.** A loopback proxy recipe, hosted-profile
  declarations (`upstream`, `price_table`), disclosure, personal-data
  refusals and a cost budget; usage and cost footers.
- **Unattended runs.** `schedule` installs user-level launchd/systemd
  timers that re-check every digest before running; asks are always
  denied there.
- **Policy and approvals.** Session grants, `--accept-edits`, the
  default deny list for sensitive files (`--no-default-denies` turns it
  off).
- **Evidence.** Every feature above journals; `replay` audit recomputes
  each of them, and `compare` judges models with facts only.
- **Docs.** This changelog, the user guide (`docs/USER-GUIDE.md`),
  per-verb `--help` (every verb answers `--help` with exit 0), and
  tests that hold the usage text against the parser and the README
  quickstart against the dispatch.

No run ends `Passed` yet: verification (H3) is not built, so every run
still ends `Indeterminate { NothingChecked }` (exit 5) by design.

## [0.0.x] — 2026-09

Internal releases: the read-only agent loop (H1) against a local
OpenAI-compatible model on loopback, hash-chained journals with audit
replay and resume, edits with a person's permission, commands in the
macOS Seatbelt sandbox, the extended read/edit/search tool set, the
`run`/`resume`/`replay`/`profile check`/`manifest check`/`doctor` verbs,
and the parity roadmap that became the slice track this release closes
out.

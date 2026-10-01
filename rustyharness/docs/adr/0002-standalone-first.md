# ADR-0002 — Standalone first; rustysuite capabilities are optional

- **Status:** Accepted (Iwan, 2026-09-23)
- **Recorded in the suite as:** ADR-024 (`charter/decisions/decision-log.md`), answering suite owner questions OI-34 and OI-35.

## Decision

In the owner's words: *"I still want someone to be able to use rustyharness for an
agent they have and not need anything else with rustysuite. It should just be a good
harness that has all the capability of the rustysuite stuff too. Can be used without
rustysuite."*

1. **Standalone first.** rustyharness is a general agent harness. Someone with their
   own agent and their own model can use it with nothing else from rustysuite
   installed: no suite crate, service, repo layout, tool or mesh is required to build
   or run it.
2. **Suite capabilities are optional add-ons.** Integration with rustysuite apps
   (their capability manifests and adapters), suitectl, the suite's gates and the
   rustynet mesh ships with the harness but is off unless enabled (cargo features
   and/or adapters loaded at runtime — the v0.1 design chooses).
3. **Separate from the charter's `rustyai`.** rustyharness never runs as the
   suite's confined AI over personal data; that remains the personal-data app's own confined router.
4. **Suite membership:** present-non-member dev/ops tool until the design is reviewed
   SOUND, then revisited by a superseding suite ADR.

## Consequences for the design

- **Security defaults are the harness's own, for every user.** Fail-closed
  confinement, untrusted tool output, human approval for irreversible effects and
  evidence-based "done" hold in standalone use, not only inside the suite.
- **No hard dependency on suite crates.** Where the harness shares a type with the
  suite — most importantly the suite's single gate-outcome type — that type must live
  in a small standalone crate both can depend on, rather than the harness depending
  on the suite. The v0.1 design settles how.
- **The capability-manifest schema is general.** It is how any tool provider plugs
  in; rustysuite apps are the first providers, not the only ones.
- **Protocols are open standards first** (e.g. MCP, per R1), so standalone users can
  bring existing tools.

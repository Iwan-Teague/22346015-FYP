# Research pipeline

Research fed the v0.1 design (now v0.2, reviewed SOUND). Research specific to rustysuite's own apps is kept in the rustysuite repository, not here; this repo stays general (ADR-0002). Every input is kept here with its sources. The
design is reviewed independently before it is called SOUND.

| Stream | Question | Status |
|---|---|---|
| R1 prior art | What makes a good harness — SWE-agent, mini-SWE-agent, OpenHands, Aider, Claude Code, Codex CLI, opencode, Goose; failure modes; confinement; MCP and plugin models; Rust crates; local-model tool calling | **done** — [R1-prior-art-2026-09-23.md](R1-prior-art-2026-09-23.md) (17 ranked principles, 12 open questions) |
| R2 suite inventory | What already exists in rustysuite that the harness reuses, must comply with, or replaces | **done** — rustysuite-specific, so it lives in the (private) rustysuite repository, not here |
| R3 fleet lessons | Every failure the suite's own agent fleet has hit, turned into a requirement the harness meets by construction | **done** — [R3-fleet-lessons-2026-09-23.md](R3-fleet-lessons-2026-09-23.md) (10 root-cause classes, 24 requirements) |
| R4 Component D review | First independent review of the 2026-09-14 agent-harness draft: what carries forward | **done** — verdict NEEDS-FIXES; the draft is not reworked, its carry-forward list (review §5) feeds the v0.1 design. Review lives in the suite: `charter/reviews/REVIEW-component-d-agent-harness-2026-09-23.md` |
| R5 integration map | Per app: what an agent would do with it, effect classes, the capabilities it would declare | **done** — rustysuite-specific, so it lives in the (private) suite repo, not here |
| R6 threat model | The harness's own threat model — standalone and in-suite deployments | **done** — kept in the suite repo for now; its generic parts move into the v0.1 design |

Then: v0.1 design ([01-design-v0.1.md](../01-design-v0.1.md), 2026-09-23) → adversarial review → rework → confirming review → SOUND (v0.2). H1 is built on it.

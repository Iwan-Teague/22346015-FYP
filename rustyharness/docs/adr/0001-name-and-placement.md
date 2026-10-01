# ADR-0001 — Name and placement

- **Status:** Accepted (Iwan, 2026-09-23)
- **Decider:** the owner, answering two direct questions in session.

## Decision

1. The project is named **rustyharness** (binary `rustyharness`, crates `harness-*`).
2. It lives in its **own git repository from day one**, checked out at
   `projects/rustyharness` in the suite and added as a submodule (the ADR-019 model),
   rather than starting in-tree and splitting later.

## Options considered

| Option | For | Against |
|---|---|---|
| **rustyharness** (chosen) | Says what it is: the runtime around a swappable model. Matches the suite's lowercase what-it-does names and rustybenchmark's "pinned harness" vocabulary | Jargon to non-developers — a user-facing assistant built on it can take a friendlier name |
| rustyai | Friendly; broad enough for model serving and an assistant UI | Vague; implies the project is a model; "AI" dates |
| rustyagent | Names what it runs | Less precise about the runtime, checks and confinement |
| In-tree, split later | Nothing to publish yet; the personal-data app precedent | History has to be carried over at the split |
| **Own repo now** (chosen) | Clean history from the first commit | The suite's gitlink cannot be fetched by anyone until the owner publishes the repo (the same "not our ref" condition rustybenchmark has today) |

## Finding after the decision (R2 inventory, same day)

"rustyai" is ALREADY a charter term: the confined AI that works over users' personal
data (the personal-data app's typed-function router), on the suite's maximal-sensitivity floor
(T0 threat model; T1 P10; risk row R-AI-1; definition of ready). Naming the harness
rustyAI would have either pulled that floor onto a dev tool or blurred two trust
domains. rustyharness keeps them distinct; how the two relate (is rustyharness the
runtime under rustyai, or separate?) is an open question, not assumed.
(From the rustysuite inventory, which is kept in the rustysuite repository.)

## Consequences

- Publishing the repo (creating the GitHub remote and pushing) is the owner's action; until then the submodule URL names the intended remote and fresh clones cannot fetch it.
- The suite's member lists and membership gates must learn about the new project (tracked in the suite action queue).
- The suite's readiness bar (owner decision OI-29) blocks product code before designs meet the bar. This scaffold contains no product behaviour — only the settled invariants, as types and refusals — and was started on the owner's explicit instruction; harness behaviour waits for the reviewed design.

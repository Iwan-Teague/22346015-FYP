# ADR-0003 — Licence: PolyForm Noncommercial 1.0.0 (source-available)

- **Status:** Accepted (Iwan, 2026-09-23)

## Decision

rustyharness is published publicly under the **PolyForm Noncommercial License 1.0.0**
(`LICENSE.md`). The owner's requirement: *"I don't want it used by businesses without
my permission."*

- Anyone may read, use, modify and share it for any **noncommercial** purpose —
  personal use, hobby projects, research, education, charities, public bodies.
- **Commercial use needs a separate licence from the author.**
- Third-party dependencies stay on permissive licences (Apache-2.0, MIT), gated by
  `cargo deny check licenses`.

## Why not an open-source licence

Every OSI-approved open-source licence (AGPL, GPL, MPL, Apache, MIT) permits
commercial use by definition; copyleft only obliges businesses to share their
changes, it does not stop them using the software. Only a noncommercial licence meets
the requirement. The project is therefore described as **source-available**, not
"open source", so no one mistakes it for an OSI-licensed project.

This matches rustynet and rustybenchmark, which already use PolyForm Noncommercial.

## Consequences

- Code from other suite projects under the same licence and the same author can be
  reused. Code under other licences can be used only as permissive dependencies.
- Commercial licensing requests go to the author through the GitHub profile that owns
  the repository.

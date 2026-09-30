# Data licence — the published results corpus

**The published results corpus is licensed [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).**
Full text: <https://creativecommons.org/licenses/by/4.0/legalcode>

## What this covers

- The public dump: `GET /dump/<epoch>.jsonl` and every mirrored release of it
- Aggregated leaderboard data derived from it
- The data dictionary and schema definitions describing it

## What this does NOT cover

- **The harness and the synthetic task corpus** — those are
  [PolyForm Noncommercial 1.0.0](LICENSE.md). Running the benchmark is governed by that licence;
  *using the published results* is governed by this one.
- **The mined `wild` corpus**, which derives from third-party repositories under their own terms and
  cannot be relicensed by this project. See [OPEN-QUESTIONS](docs/OPEN-QUESTIONS.md) Q21.
- **Model output artifacts**, which are never published at all (encrypted, retained privately for the
  audit window, then deleted — see [docs/11](docs/11-submission-and-privacy.md)).

## Attribution

> Rustybenchmark results corpus, epoch `<epoch>`, CC BY 4.0.
> https://github.com/Iwan-Teague/Rustybenchmark

## Why CC BY 4.0

- **4.0 is the first CC version that expressly licenses *sui generis database rights*** — the right
  that plausibly attaches to a table of measured facts under UK and EU law. The project is
  UK-based; a US-style copyright-only grant would leave that right unlicensed and the question open.
- **Not NonCommercial.** The parties with both the motive and the budget to audit a competitor's
  row — GPU vendors, quantisation publishers, inference-engine projects — are commercial. An NC data
  licence would make the project's strongest stated integrity control, independent re-derivation,
  legally available only to hobbyists.
- **Not ShareAlike.** SA is viral onto any downstream aggregator merging these rows into a wider
  table, which is precisely the reuse that makes the dataset worth publishing.

## The grant this depends on

Publishing under CC BY means sublicensing onward, which requires that submitters granted that right.
Consent #1 in [docs/11](docs/11-submission-and-privacy.md) carries it explicitly, and every
submission records `terms_version` and `terms_hash` so the grant a row was collected under is a
recorded fact.

**This had to be in place before the first accepted submission.** The project deliberately holds no
accounts and mints `machine_uuid` locally with no contactable identity attached
([OPEN-QUESTIONS](docs/OPEN-QUESTIONS.md) Q23), so there is nobody to retroactively ask. A missing
grant would be unrecoverable by construction.

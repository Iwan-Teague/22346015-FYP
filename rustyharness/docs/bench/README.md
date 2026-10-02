# Recorded bench results

One TSV per recording, named `<date>-<model>-<protocol>.tsv`. Each file is
what `harness-minibench` writes (`--out FILE`): a header, then one row per
run — per attempt under `--repeat`. A file recorded this way can be fed
back as `--baseline FILE`: a task that passed there and fails now, or
steps grown by more than 50% and at least 3, fails the gate; rows
recorded by another harness version are compared but flagged.

| file | model | protocol | profile_sha | how |
| --- | --- | --- | --- | --- |
| `2026-10-02-scripted-text.tsv` | `minibench` (scripted) | text | `a1b873a7…225579a` | the scripted self-test (`minibench_scripted_all_pass`), harness 0.0.1 |

The scripted file is the deterministic baseline: the fixtures replayed
through their own `script` solutions with the conservative default
profile (`Profile::conservative_default("minibench")`, text protocol, the
sha in the rows), no model server needed. Live recordings follow the same
naming and are appended to this table when they are made.

# Recipe: a hosted model through your own loopback proxy

rustyharness talks to OpenAI-compatible HTTP endpoints on `127.0.0.1`
only. To use a hosted provider (a commercial API), run your own small
proxy on loopback that forwards to it and holds the provider key. The
harness never sees that key beyond the optional `ApiKey` handle it passes
to your proxy, and every byte of the context still goes through the
endpoint you chose.

## 1. What "hosted" means here

A profile that says `"upstream": "hosted"` is your attestation that the
endpoint forwards to a hosted provider, so the session's context — the
task, the rules, every observation — leaves your machine. The harness
then:

- prints `context is sent to a hosted provider` in the `chat`/ACP banner
  and in `/status`;
- records `endpoint_class: loopback-proxy-hosted` in the run's journal
  header (an audit recomputes it);
- refuses any grant whose capability is marked at personal sensitivity or
  above (no personal data to a hosted upstream);
- refuses to start at all unless the profile also carries a price table,
  and charges the price table × tokens against the run's cost budget
  (`budget.cost_micros` in the task file); the run stops with
  `Budget(Cost)` when the budget is spent.

A profile WITHOUT the declaration is just a local loopback model, whatever
its endpoint really is: the harness cannot detect a proxy, so the
declaration is on you. Undeclared, you get no disclosure and no cost
budget — that residual risk is documented, not solved.

## 2. The profile

```json
{
  "profile_version": 1,
  "id": "hosted-m",
  "model": "m",
  "context_window": 32768,
  "fill_ratio": 0.6,
  "protocol": "text",
  "tool_choice_required_ok": false,
  "grammar": "none",
  "max_active_tools": 6,
  "edit_format": "replace",
  "recent_turns": 5,
  "sampling": {"temperature": 0.2, "top_p": 0.95, "max_tokens": 2048},
  "upstream": "hosted",
  "price_table": {"in_micro_per_ktok": 3000, "out_micro_per_ktok": 15000}
}
```

`price_table` is micro-USD per kilo-token (here $3 per million input
tokens, $15 per million output). It is required for a hosted profile's
runs; prices that are not whole micro-USD per token floor.

## 3. The task's cost budget

```json
{
  "task": "What does a.txt say?",
  "grants": ["harness.fs.read", "harness.fs.list"],
  "budget": {"cost_micros": 100000}
}
```

`cost_micros` is the most the run may spend ($0.10 here). Without it, a
priced hosted run stops at the first charge — a hosted run needs a budget
you set.

## 4. The proxy

Anything that speaks the OpenAI-compatible `/v1/chat/completions` (and
`/v1/models`) on `127.0.0.1:<port>` and forwards to your provider works;
no harness code is involved. Keep the provider key in the proxy's
environment, not in any harness file. Then run:

```
rustyharness run --profile hosted-m.json --task task.json \
  --endpoint http://127.0.0.1:<port>/v1 ...
```

## 5. Audit and resume

Audits and resumes must be given the same hosted profile (its digest is a
header input) and the same budget. `replay --run <id>`/`resume --run <id>`
read the run bundle's copies (`runs/<id>/inputs/`) by default.

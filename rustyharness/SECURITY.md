# Security policy

rustyharness runs language models that act through tools. Its security posture:
confinement fails closed, tool and model output is untrusted data, irreversible
actions need a human yes, and results are decided by evidence. A way around any of
these is a security bug.

**Status:** H1, the read-only agent (design `docs/01-design-v0.1.md` §9). The
`rustyharness` binary drives a model on loopback through read-only workspace tools
and writes a hash-chained journal. Nothing the agent asks for executes: no sandbox
backend has passed conformance, so no execute capability can be granted, and no
provider outside the built-in one can be admitted.

In scope for reports today, a way to:

- make model or tool output act as an instruction (only the model's own reply is
  parsed for an action, INV-29);
- invoke a capability the task did not grant or user policy denies, get a
  provider other than the built-in one admitted, or cause any workspace write
  through the agent (H1 is read-only; the one write-class capability is the
  submit sentinel `harness.task.submit`, granted to every session, which only
  ends the loop, §2.5);
- read outside the workspace, beyond the residuals the design names (hard links
  and the check-then-open window, the design's H1e-2 "Read tools" row);
- reach a model endpoint that is not loopback;
- run with a `state_root` on a filesystem not identified as local (INV-35),
  beyond the residuals the design names (the H1e-2c row: a mount placed over the
  path between the probe's reads; §11: local filesystems on network block
  storage); `replay`'s missing check is a known open question, not a finding;
- outlast a budget (INV-14), beyond the residual the design names (§11: an
  in-process read blocked in the kernel, e.g. on a network mount inside the
  workspace, is not interrupted until H2); or get outside text into a trusted
  journal field;
- alter or forge a journal undetectably beyond the residuals the design names
  (§7.1, §11, and the anchor-only residuals in rows H1e-2b and H1f-3);
- make a run report a pass;
- put a payload on an argv (INV-23), or redraw the terminal from a manifest,
  a model reply or a tool result (§7.1 display paths).

**Reporting:** do not open a public issue. Contact the maintainer privately
(Iwan Teague, via the GitHub profile that owns this repository) with a description
and, if possible, a reproduction. **Service levels (T2-A8):** acknowledgement
within 72 hours of a report; fixes targeted within 48 hours for critical,
7 days for high, 30 days for medium/low. Fixes land with a regression test.

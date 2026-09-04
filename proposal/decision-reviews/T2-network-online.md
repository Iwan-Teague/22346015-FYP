# T2 review: network, ports, online access and prompt-injection safety

Adversarial review, 24 Sep 2026. Decisions: **D12, D26, D30, D31, D32, P10.**

**Read.**
- `REGISTER.md`.
- The design at `origin/main` `4ad8847`: OD-1..OD-7, §0, §3.2, §4.1-4.2, §4.8, §5.2-5.4, §6.2-6.6, §9, §10 and §11.
- `OPEN-QUESTIONS.md`, and R1 §3 (prior art).
- The measurement plan v0.10: §0, §3, §4 and §12 item 18. The contract v0.4.
- The drafts: [AB] `od5-ab-ports-and-background-processes.md` and [CD] `od5-cd-confinement-inputs-and-gc.md` (the environment rules), plus `REVIEW-od5-delta.md` and the owner-questions memo.
- The coordinator's pointers into the suite charter: `reviews/SPIKE-S-L1-linux-sandbox-2026-09-23.md`, `decisions/decision-log.md` (OI-38, OI-41, ADR-012 X3, ADR-024), `governance/action-queue.md` (AQ-208, AQ-230) and `principles/T1-principles.md` P8.
- `od5-delta-v2.md` did not exist when this was written.

**Method.** Primary sources were fetched online, and every prior-art claim below carries its URL. I also ran local probes on the owner's MacBook (macOS 26.5.1, arm64):
- My shell was not sandboxed (`sandbox_check(self) = 0`).
- The probes were a Rust `cdylib` DYLD interposer, a std server, a server that follows mio's socket call order, and an offline cargo project with no dependencies. Nothing was downloaded.
- Only 127.0.0.1 ports that the probe itself bound were used. No firewall or system setting was changed.
- Every probe file was deleted at the end (see Hygiene).

Where I infer rather than measure or cite, I say so.

## Local measurements (T2-M)

| # | Question | Result |
|---|---|---|
| T2-M1 | What is `cargo` on this machine? | `~/.cargo/bin/cargo` and `rustc` are **`#!/bin/bash` scripts**: `exec -a cargo /opt/homebrew/Cellar/rustup/1.29.0_2/libexec/bin/rustup "$@"` (Homebrew's rustup). `PATH` resolves `cargo` to Homebrew's `rust` 1.97.0 binary first |
| T2-M2 | Code signatures (`codesign -dv`) | Homebrew `cargo`, `rustc` and `rustup`, and every rustup toolchain `cargo`/`rustc` (1.85 to 1.98.1, nightly): ad-hoc (linker-signed), no hardened runtime, so DYLD variables are honoured. `/bin/bash`, `/bin/sh`, `/usr/bin/env`, `/usr/bin/sandbox-exec`, `/usr/bin/cc` and `/usr/bin/python3`: Apple platform binaries |
| T2-M3 | Does `DYLD_INSERT_LIBRARIES` reach the server? | Directly: **yes**, and the swap served a client. Through `/bin/bash -c`, as `/usr/bin/env prog`, through **`/usr/bin/sandbox-exec`**, and through the bash `cargo` shim for both `cargo run` and `cargo test`: **purged** (the program saw it unset, and its bind failed) |
| T2-M4 | Re-adding it after the protected hop | `sandbox-exec -p … /usr/bin/env DYLD_INSERT_LIBRARIES=<lib> prog`: **works** (the variable is passed as an argument, so nothing is purged) |
| T2-M5 | Through real cargo binaries | Homebrew `cargo run`, the toolchain `cargo run` (invoked directly) and Homebrew `cargo test`: the interposer loaded in the target, the inherited listener arrived, and the client got the greeting. The interposer also loaded into cargo and every rustc, with no harm |
| T2-M6 | Under Seatbelt `(deny network-bind)(deny network-inbound)` | No interposer: std `bind` gives **EPERM** (fail-closed). Bind-only swap: the program's own **`listen()` on the swapped socket gives EPERM**, so `TcpListener::bind` fails. Swap plus a swallowed `listen()`: **works**, and accept on the inherited listener works |
| T2-M7 | Descriptor flags after the `dup2` swap | Socket set up in mio's order (nonblocking, then close-on-exec, `SO_REUSEADDR`, bind): `nonblock=true cloexec=true` before the swap, **`false false` after it**. A std listener after the swap: `cloexec=false` |
| T2-M8 | Overhead | A std-based interposer adds **≈2.4 ms per process** (300 runs; 4.07 → 6.49 ms per spawn and exit) |
| T2-M9 | Can the harness see pf's state? | `/dev/pf` is `crw------- root`, and `pfctl -s info` as the user gives "Permission denied". **An unprivileged harness cannot check that pf is enabled or an anchor loaded** |
| T2-M10 | pf on this Mac (read-only) | `/etc/pf.conf` holds only the `com.apple` anchors. The `com.apple.pfctl` LaunchDaemon runs `pfctl -f /etc/pf.conf` and does not enable pf. The local pf.conf(5) documents a **`user <user>`** match: for incoming connections, "the user that listens on the destination port"; IDs are "stored when a socket is created". pfctl(8): `-E` increments an enable reference count, `-X token` releases it, `-d` disables pf |
| T2-M11 | Loopback addresses | `lo0` carries only 127.0.0.1 and ::1 (netmask /8), so any other 127/8 address needs a root `ifconfig` alias. Not bound, to keep to the probe rules |
| T2-M12 | Local man pages | sandbox-exec(1): "DEPRECATED". launch(3): `launch_activate_socket()` serves only a launchd job whose plist has a `Sockets` entry |

Earlier measurements I rely on, all from `REVIEW-od5-delta.md`:
- **M-7:** a Seatbelt `localhost:P` bind rule allows exactly P; `network-inbound` is checked at `listen()`; an inherited listener accepts with no bind rule.
- **M-5:** a `setsid()` child escapes a group kill.
- **M-10:** a handed-over listener cannot be revoked.

## New facts from the coordinator

These are folded into the verdicts below.
1. **Linux may have no network namespace.** Ubuntu 24.04 blocks unprivileged user namespaces through AppArmor (S-L1). The accepted grading sandbox uses Landlock ABI 4 with seccomp and no netns. Its "no TCP" means `socket()` is denied outright.
   - Landlock network rules name **only a port, never an address** ([kernel docs](https://docs.kernel.org/userspace-api/landlock.html): `landlock_net_port_attr` is `allowed_access` plus `port`).
   - So on such a host, a Landlock port grant is a **LAN-visible bind** and **internet egress to that port number on any IP**. That is worse than macOS.
   - Claude Code documents the same Ubuntu restriction. Its fix is an admin-installed AppArmor profile for `bwrap` ([sandboxing docs](https://code.claude.com/docs/en/sandboxing)).
2. **OI-38.** rustybenchmark already accepted a dedicated OS user created at install (AQ-230). That makes "admin once at install" an accepted precedent. The uid-scoped pf option is examined under D32.
3. **T1 P8.** Service-hosting listeners bind `127.0.0.1`/`::1` or an address on the rustynet interface, "no LAN escape hatch". P8 also forbids sudoers edits, and root helpers must be small and argv-only. ADR-024 applies suite floors to the suite's own use of the harness. This constrains D31 and D32's root helper, and it rules out the review's F-2 option B as written, because that option needs a sudoers rule.

**For the D29 and D33 reviewers:** [AB]'s "Linux loopback is private" (§4.6, INV-54 "Linux private workspace plus ports → admitted") is false on stock Ubuntu 24.04 unless the harness ships a userns profile. D33's "allow any port inside the per-run private namespace" assumes a namespace that may not exist.

---

## D12: one device

1. **Restate.** The model is served on loopback (llama.cpp, Ollama, vLLM, LM Studio), and the harness and the agent's code run on the same machine.

2. **Prior art.**

| Harness or server | How it handles model location | Source |
|---|---|---|
| Claude Code | Hosted models. Cloud sessions run in VMs with network limited by default | [security](https://code.claude.com/docs/en/security) |
| Codex CLI | Hosted by default. Commands run with "network access turned off"; web search defaults to a "cached" index | [agent approvals & security](https://learn.chatgpt.com/docs/agent-approvals-security) |
| opencode | Local servers over plain HTTP (`http://localhost:11434/v1`, `http://127.0.0.1:1234/v1`, `http://127.0.0.1:8080/v1`), with no transport warning | [providers](https://opencode.ai/docs/providers) |
| llama.cpp server | Default host 127.0.0.1. Supports `--api-key` and TLS (`--ssl-key-file`, `--ssl-cert-file`). **CORS by default "reflects any `Origin` header back with credentials allowed"**; `--cors-origins localhost` narrows it | [server README](https://raw.githubusercontent.com/ggml-org/llama.cpp/master/tools/server/README.md) |
| Ollama | CVE-2024-28224, DNS rebinding: a web page could chat with models and "exfiltrate file data". Fixed in 0.1.29 with a Host-header check | [NCC Group](https://www.nccgroup.com/research-blog/technical-advisory-ollama-dns-rebinding-attack-cve-2024-28224/) |
| Cline, Continue, Aider with remote Ollama | UNVERIFIED (not fetched) | — |

No harness I checked requires one device. The local-first ones accept any base URL, plain HTTP included. rustyharness's default (loopback only, cleartext to anything else refused, INV-24) is stricter than all of them. That is right for prompts that carry private code.

3. **Attack.**
- **Remote-inference users lose the most.** Examples are a DGX Spark, a GPU box on the LAN, or the GPU PC serving the Mac. The plan anticipates this in D14 ("done on a DGX Spark").
  - The default build cannot connect at all.
  - With the `hosted` feature, the user's **own** box is classed as "hosted": it brings rustls and the C tax (§3.2), and P10's disclosure rule applies to it.
  - The easy workaround, `ssh -L`, makes a remote server look like loopback. The harness then records `loopback` in the journal: the one-device claim becomes silently false. Only rustybenchmark's topology probe (plan §3.5) would notice.
- **The model server is a shared-loopback neighbour holding P.** It receives the whole context every turn. It is also reachable from web pages: llama.cpp reflects any Origin with credentials by default (above), and Ollama had a rebinding CVE.
  - §11's model-server residual covers only the server's own egress, not this.
  - Browsers without Local Network Access can call it cross-origin. Chrome 142+ asks the user first ([Chrome LNA](https://developer.chrome.com/blog/local-network-access)).
- **Contention.** H2+'s background servers run during model calls, which adds timing noise ([AB] RR-6). The benchmark should record it, as D14 already implies.
- Schedule and FYP: no cost; every FYP run is same-device.

4. **Better.**
- Keep one device as the default and as the FYP's only topology.
- **Model-server exposure probe (cheap, no new dependency).** At startup, send the `/v1/models` check a second time with `Origin: http://probe.invalid`. If the server reflects it, journal and warn: "your model server answers cross-origin browser requests; start llama.cpp with `--cors-origins localhost`". In the benchmark's *managed* attach mode, start the server that way. Name this in §11.
- **Post-FYP: a `remote-self-hosted` endpoint class**, separate from `hosted`:
  - TLS with a pinned certificate or SPKI hash plus an API-key handle, recorded in `ModelIdentity`;
  - the user declares the box trusted, so P10's hosted rule does not apply;
  - a `topology: tunnel` declaration for `ssh -L` users, because the harness cannot detect a tunnel.
- Trade-offs: security improves (an exposure the user never sees is named), UX improves for remote users, and schedule impact is nil.

5. **Verdict: KEEP** (high confidence) as the v1 default and the FYP topology. Add the startup exposure probe and its residual now; the remote class can wait.

---

## D26: the trifecta rule, plus a "safe path" in H4

1. **Restate.** Refuse private + untrusted + egress (P ∧ U ∧ E) in one session, and in H4 build a safe path (a quarantined reader or dual LLM) next to the egress proxy, so private repos can go online.

2. **Prior art.**
- **The lethal trifecta:**
  - Willison names private data, untrusted content, and "the ability to externally communicate" in ways that enable theft.
  - His advice is to "avoid that lethal trifecta combination entirely".
  - He says guardrail products are unreliable ([post, 16 Jun 2025](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)).
- **Meta, "Agents Rule of Two"** (31 Oct 2025, verified to exist): [A] "process untrustworthy inputs", [B] "access to sensitive systems or private data", [C] "change state or communicate externally". At most two per session. When all three are needed, "without starting a new session", the agent needs "human-in-the-loop approval or another reliable means of validation" ([Meta AI](https://ai.meta.com/blog/practical-ai-agent-security/)). Willison notes that it adds state change, which the trifecta leaves out ([commentary](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)).
- **Dual LLM:**
  - A privileged LLM sees only symbolic `$VAR`s; a quarantined LLM reads untrusted text and has no tools.
  - Willison himself calls it "pretty bad!", a safer subset rather than a solution ([2023](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/)).
- **CaMeL (Google DeepMind):**
  - Solves "77% of tasks with provable security (compared to 84% with an undefended system)" on AgentDojo ([arXiv 2503.18813](https://arxiv.org/abs/2503.18813)).
  - It needs 2.82× the input tokens and 2.73× the output tokens.
  - Its stated limits: policy writing, side channels, user fatigue, and "P-LLM cannot write a plan based on data it can't read".
  - Evaluated only with frontier models (Gemini 2.5, Claude). Code is released ([paper HTML](https://arxiv.org/html/2503.18813v2)).
- **Design patterns (Beurer-Kellner et al.):**
  - Six patterns: action-selector, plan-then-execute, map-reduce, dual LLM, code-then-execute, context-minimisation ([arXiv 2506.08837](https://arxiv.org/abs/2506.08837)).
  - Its **software-engineering case**: a quarantined LLM turns untrusted docs into "a formal API description" with strict formats, e.g. "method names limited to 30 characters" ([Willison's summary](https://simonwillison.net/2025/Jun/13/prompt-injection-design-patterns/)).
- **Microsoft:**
  - Spotlighting cut attack success "from greater than 50% to below 2%" in their experiments ([arXiv 2403.14720](https://arxiv.org/abs/2403.14720)).
  - FIDES tracks confidentiality and integrity labels, with primitives "for selectively hiding information" ([arXiv 2505.23643](https://arxiv.org/abs/2505.23643)).
  - MSRC's defence in depth includes deterministic blocking of markdown-image exfiltration, and says "some injections might evade these defenses" ([MSRC, 29 Jul 2025](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks)).
- **Detection loses to adaptive attacks.** "The Attacker Moves Second" broke 12 defences with adaptive attacks at above 90% success for most of them, and a human red team reached 100% ([arXiv 2510.09023, via Willison](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)).
- **Open-weight models on AgentDojo:** Llama 3 70B has 34.0% benign utility and 25.6% targeted attack success, against Claude 3.7 Sonnet's 88.7% utility ([results](https://agentdojo.spylab.ai/results/)). There are no current Qwen-class rows, and I found no study of a CaMeL-style planner on 7-30B models (UNVERIFIED either way).
- **What harnesses actually ship:**

| Harness | Online access and injection handling | Source |
|---|---|---|
| Claude Code | No domain pre-allowed; the first use of a new domain prompts; `strictAllowlist` option. Warns that broad domains enable exfiltration and domain fronting. "Web fetch uses a separate context window" | [sandboxing](https://code.claude.com/docs/en/sandboxing), [security](https://code.claude.com/docs/en/security) |
| Codex CLI | Network off by default. `network_access = true` or a domain proxy; web search defaults to a cached OpenAI index | [agent approvals & security](https://learn.chatgpt.com/docs/agent-approvals-security) |
| GitHub Copilot coding agent | Firewall on by default, with a **recommended allowlist including language registries (Rust among them)**; runs on private repos. "Should not be considered a comprehensive security solution" | [firewall docs](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall) |
| Cursor | Sandbox network default is "your allowlist plus Cursor's built-in defaults for common package managers" | [run modes](https://cursor.com/docs/agent/security/run-modes) |
| Gemini CLI | `web_fetch` asks for confirmation and synthesises through the Gemini API's `urlContext`. Its default Seatbelt profile is `permissive-open` (network allowed) | [web-fetch](https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/web-fetch.md), [sandbox](https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/sandbox.md) |
| OpenHands | An LLM risk analyzer; `ConfirmRisky` pauses on HIGH. "Not a complete prompt-injection solution" | [security](https://docs.openhands.dev/sdk/guides/security.md) |
| Goose | "Autonomous Mode is applied by default"; the permission docs mention no sandbox | [permissions](https://goose-docs.ai/docs/guides/managing-tools/goose-permissions/) |
| opencode, Cline | Permission prompts only. opencode defaults most permissions to "allow"; Cline advises leaving the browser tool off | [opencode](https://opencode.ai/docs/permissions), [Cline](https://docs.cline.bot/features/auto-approve) |

   **No shipped harness runs CaMeL or a dual LLM for coding.** The shipped "quarantined reader" is a summarising fetch whose output returns to the privileged context: a filter, not isolation. The industry accepts P ∧ U ∧ E(allowlist), as Copilot and Cursor do. rustyharness's refusal is stricter and matches Willison and Meta.

3. **Attack.**
- **A dual-LLM or CaMeL path is not realistic for 7-30B models.**
  - The planner must write programs over opaque values. That was shown only with frontier models, and it cost 7 points of utility even there.
  - It needs about 2.8× the tokens, and on local hardware tokens are wall time.
  - The one open-weight AgentDojo row manages 34% utility with no defence at all.
  - This part is inference, not measured.
- **Coding is "data requires action".** The docs you read decide the code you write, which is CaMeL's own named limitation. A privileged model acting on `$VAR` handles can paste a snippet, but it cannot use an API it has not read.
- **Removing E does not cover integrity.** Injected docs can make the agent write code into the private repo that exfiltrates later, when the user runs it outside the harness. This is Meta's [C], "change state". The trifecta rule is silent on it, and it is where docs injection hurts a coding agent most.
- **Free-text reader output is U again.** Only schema-constrained output (typed fields, length caps, enforced by grammar) makes a reader's output "not U". That depends on spike S-P1, where lazy grammars over the OpenAI-compatible API are still UNVERIFIED.
- **The practical hole is gaming.** Today the only way to get online crates on a private repo is to declare the workspace `public`. That drops P for every capability, internet egress included. Users who just want `cargo add` will be pushed to lie, which weakens the rule more than any injection trick. A proxy allowlist also gives *sandboxed code* sockets to the allowlisted hosts: build scripts could exfiltrate through them, and Claude Code documents domain fronting.
- **Schedule.** H4 comes after H3, so the FYP is unaffected (benchmark mode has no E). OD-1's online coding stays unmet until then.

4. **Better: remove E for the common case instead of filtering U.**
- **(a) Harness-mediated, typed crate fetches.** The harness runs `cargo fetch --locked` outside the sandbox, with cwd outside the workspace and a harness-generated config (P1). A `harness.crates.fetch {name, version}` tool is the other form. In either form:
  - Validate the lockfile: registry sources only, no git.
  - Verify the index checksum, cache each crate once per machine, and journal it.
  - Allow only crates already in `Cargo.lock`, a popular-crate list, or crates the user approves one at a time.
  - Sandboxed code never gets a socket.
  - The attacker-readable signal left is public per-version download counters. That channel is narrow and noisy (my analysis; counter latency UNVERIFIED).
  - Define E the way Willison frames it, "can send attacker-chosen data to an attacker-readable sink", and label this capability by that test.
- **(b) Local docs instead of docs.rs.** Run `cargo doc` or rustdoc JSON over the fetched sources, offline and in the sandbox. This covers most "read the docs" needs with no network.
- **(c) Open-web research stays a separate session.** This is Meta's "new session", as §5.4 already says. Later, add the patterns paper's SWE extractor: a quarantined reader that must emit a grammar-enforced schema (API names of at most N characters, types, versions). It is the one reader form a small model can do, because the harness enforces the format.
- **(d) Human-approved fetches as the explicit Rule-of-Two exception**, interactive only. Restrict URL grammar (no query strings, no free-form paths) so the user can actually judge what they approve. No approver means deny.
- **Don't build CaMeL-style planning for small models in H4**; revisit only if a study shows it works at 7-30B.
- Trade-offs:
  - soundness improves: the controls are deterministic, and no security property depends on a model;
  - security holds: E is almost removed rather than U filtered;
  - performance improves: no second model call, and crates are cached;
  - UX improves: private repos get online crates without lying;
  - speed improves: this is days of work, where a dual LLM plus its evaluation is weeks.
- Also name the integrity residual (injected code shipped into the repo), and keep diff review and the reviewer run as its controls.

5. **Verdict: MODIFY** (medium-high confidence).
- Keep the trifecta rule and INV-9.
- Replace "quarantined reader or dual LLM" as H4's safe path with E-elimination: typed, harness-mediated, cached registry fetches plus offline rustdoc.
- Treat the structured extractor as an optional later step.
- Stop `public` being the only way out.

---

## D30: a granted loopback port counts as egress (E)

1. **Restate.** A granted loopback port adds E to the trifecta, because a browser could be steered to it (DNS rebinding).

2. **Prior art.**
- **No harness I found counts a listening port as egress.**
  - Claude Code's sandbox-runtime has `allowLocalBinding` (default false). When set, it emits `(allow network-bind (local ip "*:*"))`, `(allow network-inbound (local ip "*:*"))` and `(allow network-outbound (remote ip "localhost:*"))`: any address, any local port ([source, verified verbatim](https://raw.githubusercontent.com/anthropic-experimental/sandbox-runtime/main/src/sandbox/macos-sandbox-utils.ts); [README](https://github.com/anthropic-experimental/sandbox-runtime); [settings](https://code.claude.com/docs/en/settings-reference)).
  - Codex blocks local and private reach by default; set `allow_local_binding = true` "only when you intentionally want wider local/private reach" ([docs](https://learn.chatgpt.com/docs/agent-approvals-security)).
  - Gemini CLI's `web_fetch` refuses loopback and private destinations ([docs](https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/web-fetch.md)).
  - Cursor's sandbox docs do not address localhost ([run modes](https://cursor.com/docs/agent/security/run-modes)).
- **The threat is real for local dev servers:**
  - **Vite, CVE-2025-24010** (Jan 2025): any website could "send any requests to the development server and read the response", through CORS, the WebSocket origin and the Host header ([advisory](https://github.com/vitejs/vite/security/advisories/GHSA-vg6x-rcgg-rjx6)). Its docs now warn that turning the host check off lets any site "download your source code" through DNS rebinding ([server options](https://vite.dev/config/server-options)).
  - **webpack-dev-server, CVE-2025-30360:** source code stolen through IP-address origins in non-Chromium browsers ([advisory](https://github.com/webpack/webpack-dev-server/security/advisories/GHSA-9jgg-88mc-972h)).
  - **Jupyter:** `allow_remote_access` defaults to False against "DNS rebinding attacks" ([config](https://jupyter-server.readthedocs.io/en/latest/other/full-config.html)), and token authentication is "on by default" ([security](https://jupyter-server.readthedocs.io/en/latest/operators/security.html)).
  - **MCP 2025-06-18:** servers "MUST validate the `Origin` header … to prevent DNS rebinding attacks" ([spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)).
  - **Ollama, CVE-2024-28224** (see D12).
- **Browsers.** Chrome 142 asks the user before public→local and public→loopback requests; loopback→anything is not gated ([Chrome](https://developer.chrome.com/blog/local-network-access), [explainer](https://github.com/WICG/local-network-access/blob/main/explainer.md)). Firefox and Safari: UNVERIFIED. The webpack advisory says non-Chromium browsers lacked Private Network Access.
- **Suite P8:** beyond loopback, local control APIs need CSRF protection plus a token or peer credentials (charter `principles/T1-principles.md`).

3. **Attack.**
- **Too strict in effect.** On macOS, and on Linux without a netns (fact 1), every private-repo session with a dev server is refused, with no override. That is the most common reason to open a port (web development on your own code). The escape users will take is `workspace_public: true`, which drops P for every capability (see D26). A blunt rule here buys less safety than a narrow one.
- **The rebinding route is narrow.** It needs all four of:
  - an injection that makes the agent serve private data;
  - an attacker page open in the user's browser *during* the run;
  - a port the attacker knows or finds;
  - a browser without LNA, or a user who clicks "Allow".
  - Most Rust frameworks likely do no Host check (UNVERIFIED).
- **Too loose elsewhere, with two stronger routes left out of E:**
  - **Preview.** When the user opens what the agent built (served JavaScript, an HTML file, a README rendered with remote images), the *browser or IDE* sends data out. No port grant is needed; `file://` or a markdown preview is enough. MSRC treats markdown-image exfiltration as a primary channel.
  - **The model server** holds the full context, and llama.cpp reflects any Origin (D12).
- **Other local principals** (RR-2, RR-7) can connect to the listener: on a single-user Mac, the user's own apps and the model server's tools.
- **Linux without netns is not "shared loopback".** Landlock is port-only, so a grant gives LAN-visible binds and internet egress on the granted port numbers (fact 1). [AB]'s claims "Linux never E from ports" (§4.6) and INV-54 are false on stock Ubuntu 24.04.

4. **Better.**
- Keep the label, but call it `host-exposure` (not "internet"), and compute it from the **recorded** loopback kind: `shared` (macOS, Windows, Linux without netns) or `private` (Linux netns).
- In a P ∧ U session, a shared-loopback grant needs a **per-session human approval** instead of a refusal. That is Meta's Rule-of-Two remedy. The prompt says what is exposed: "Programs on this Mac, including your browser, can read what the agent serves on 127.0.0.1:41000-41003 while the run lasts." No approver means deny. Benchmark workspaces are public, so the benchmark is unaffected.
  - If the owner prefers to keep the hard refusal, keep it, but then also count the preview route in the same way, so the rule is consistent.
- Add a harness fact telling the agent to check `Host` ∈ {`localhost`, `127.0.0.1`, `[::1]`} in servers it writes, as Vite, Jupyter and MCP do. The reviewer can check it.
- Name the preview and model-server routes as §11 residuals. Add D12's Origin probe.
- On Linux without netns, **refuse** port grants until D32's Linux mechanism exists; do not label them E.

5. **Verdict: MODIFY** (medium confidence).
- Keep a shared-loopback grant as an exposure source.
- Replace the hard refusal in private sessions with a per-session approval.
- Scope the label by the measured loopback kind.
- Name the two stronger routes.

---

## D31: network-visible (LAN) ports, not in v1

1. **Restate.** Ports reachable from the network are not in v1. They are designed now as a separate, high-risk opt-in grant.

2. **Prior art.**
- Claude Code's single `allowLocalBinding` switch grants `*:*` binds, which are LAN-visible, with no separate LAN grant (source above).
- Codex has `allow_local_binding` for "wider local/private reach" ([docs](https://learn.chatgpt.com/docs/agent-approvals-security)).
- OpenHands exposes the agent-server and worker ports (8011 and 8012) on host ports, fixed in host-network mode ([docker sandbox](https://docs.openhands.dev/openhands/usage/sandboxes/docker.md)).
- Vite binds `localhost` by default, and `0.0.0.0` or `true` means "all addresses, including LAN and public addresses" ([docs](https://vite.dev/config/server-options)).
- Suite P8 forbids LAN binds for service-hosting listeners, with "no LAN escape hatch" (charter).
- Mechanically, neither a Seatbelt `localhost:P` bind rule ([AB] §4.3; M-7) nor a Landlock port rule ([kernel docs](https://docs.kernel.org/userspace-api/landlock.html)) scopes the address.

   rustyharness is stricter than every harness checked; it agrees with P8 and with Vite's default.

3. **Attack.**
- "Not in v1" holds only if **no confinement layer ever receives a bind permission on a shared network stack**. Any Seatbelt `network-bind` rule, or any Landlock `BIND_TCP` without a netns, silently puts LAN ports in v1. With fact 1, a Landlock-only Linux backend with ports would do exactly that.
- **Suite deployments.** A future grant must never be usable for the LAN in suite mode, only on the rustynet interface address (P8). "LAN" and "mesh" have to be different grants.
- The later forwarder design ([AB] §4.7) is right. Its source-address allowlist matters because hostile Wi-Fi peers are LAN peers.
- There is no FYP cost and no schedule risk.

4. **Better.**
- Add now an **invariant plus an FT row per backend**: binding `0.0.0.0`, `[::]` or the LAN address from inside is refused (on Linux without netns too), and no layer grants bind on a shared stack.
- Specify the later grant as a harness-side forwarder with:
  - an interface selector (`mesh`, `lan`);
  - a source allowlist;
  - an `Ingress` journal record;
  - egress `lan`, and a `protected_action` floor so every run asks;
  - the `lan` variant forbidden in suite mode (P8);
  - [AB] C-9 settled (the derived floor for `lan`).

5. **Verdict: KEEP** (high confidence), with the no-bind-on-a-shared-stack invariant added now.

---

## D32: macOS network tasks through a DYLD interposer, with a pf fallback

1. **Restate.**
- A harness-owned `DYLD_INSERT_LIBRARIES` interposer catches `bind()` on a granted port and `dup2`s a harness-made 127.0.0.1 listener into place, so normal server code works.
- Fallback: a pf anchor that blocks the granted ports on non-loopback interfaces, set up with admin rights once at install.

2. **Prior art.**
- **No coding harness I found interposes sockets.**
  - Claude Code simply grants `*:*` binds (D30).
  - Codex's `process-hardening` goes the other way: it *removes* `LD_PRELOAD` and `DYLD_*` from its own process ([README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/process-hardening/README.md)).
- **Apple:**
  - "Any dynamic linker (dyld) environment variables … are purged when launching protected processes" ([SIP guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/RuntimeProtections/RuntimeProtections.html)).
  - Under the hardened runtime, dyld reads `DYLD_` variables only with the entitlement, and an injected library may also need `Disable Library Validation` ([entitlement](https://developer.apple.com/tutorials/data/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables.json)).
- **Socket activation:**
  - `listenfd` drops the PID check when `LISTEN_PID` is unset, for wrappers like cargo-watch ([docs](https://docs.rs/listenfd/latest/listenfd/)).
  - axum's auto-reload example uses `systemfd --no-pid … -- cargo watch -x run` ([example](https://raw.githubusercontent.com/tokio-rs/axum/main/examples/auto-reload/README.md)).
  - launchd sockets serve launchd jobs only (T2-M12).
- **pf with uid rules ships in real products.** Mullvad's macOS firewall is PF, and in its connecting state "only allows packets from processes running as `root`". Its daemon is installed as root ([security.md](https://raw.githubusercontent.com/mullvad/mullvadvpn-app/main/docs/security.md)). The `user` match is documented in pf.conf(5) (T2-M10).
- **Network Extension content filters** need the Content Filter capability, a signed extension and user approval ([Apple](https://developer.apple.com/tutorials/data/documentation/networkextension/nefilterdataprovider.json)). Whether they see loopback traffic is UNVERIFIED.
- **Linux analogues:**
  - The seccomp notify `ADDFD`/`SETFD` operations (Linux 5.9 and 5.14) let a supervisor emulate socket calls. The man page warns that it "can not be used to implement a security policy!" when the supervisor lets the original call continue ([seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)).
  - bypass4netns uses exactly this, and names a TOCTOU risk on `sockaddr` ([repo](https://github.com/rootless-containers/bypass4netns)).
  - Claude Code's admin-installed AppArmor profile is the precedent for getting a userns on Ubuntu 24.04 (fact 1).

3. **Attack (T2-M measurements).**
- **SIP strips the interposer at every protected hop**, including `sandbox-exec` itself (T2-M3). As specified, it never reaches a sandboxed program. It works only when re-added after the hop (T2-M4), or from a harness trampoline that applies the profile with `sandbox_init` (P5) and then execs.
- **The owner's own `~/.cargo/bin/cargo` is a bash script** (T2-M1). Through it, `cargo run` and `cargo test` lose the interposer (T2-M3). Through real cargo binaries they work (T2-M5).
  - Shims are common: Homebrew's rustup, and version managers (their shim format is UNVERIFIED).
  - The exec allowlist must pin the real toolchain binary. Otherwise Level-2 servers fail with a confusing EPERM.
- **A bind-only swap fails:** the program's `listen()` gets EPERM under Seatbelt (T2-M6). `listen` must be interposed too.
- **`dup2` drops `O_NONBLOCK` and `FD_CLOEXEC`** (T2-M7).
  - tokio and mio set nonblocking *before* bind (the order measured with raw calls). After the swap, `accept` blocks the runtime thread: a hang, not an error. Inferred; not run with tokio, since that meant downloading crates.
  - The lost close-on-exec leaks the listener into the server's children, the survivor case of review F-5.
  - Also lost or needing emulation: `setsockopt` calls made before bind; IPv6 and dual-stack binds; port-0 test binds (RR-8); repeated binds; `getsockname`.
  - The shim becomes a stateful socket emulator: fragile, but **fail-closed**. Without it, Seatbelt refuses the bind (T2-M6).
- **Governance collisions:**
  - The interposer needs `unsafe`, `no_mangle` and `link_section`, which the purity gate's `forbid(unsafe_code)` rule forbids. It needs a second audited unsafe crate and a gate change.
  - It contradicts [CD] INV-38 and FT-23 (the harness-built environment must hold no loader names; the DYLD canary must never load). Amend both, and update [CD]'s "SIP stripping is UNVERIFIED", which T2-M3 has now measured.
- **Other costs:** it needs a universal dylib, because an x86_64 process under Rosetta needs x86_64 code. Hardened-runtime programs ignore it; every Rust toolchain binary here is ad-hoc (T2-M2). It costs ≈2.4 ms per process (T2-M8).
- **The pf fallback cannot fail closed in an unprivileged harness:**
  - `/dev/pf` is root-only (T2-M9), so the harness cannot check the guard before a run.
  - Persistence needs a root LaunchDaemon that loads the anchor and enables pf at every boot (T2-M10). "Admin once" really means "a root component forever", and P8 governs it.
  - Any root process can run `pfctl -d`, and VPNs use pf too; coexistence is UNVERIFIED.
  - A port-range rule still fails port-0 tests.
- **Linux shares the problem when there is no netns** (fact 1). An `LD_PRELOAD` analogue would miss static (musl) binaries (inference).

4. **Better.**
- **Keep the swap as the v1 macOS default, re-specified to the measurements:**
  - spawn through a harness trampoline, with `sandbox_init` (P5) or the `/usr/bin/env` hop, and set `DYLD_INSERT_LIBRARIES` only there;
  - interpose `bind`, `listen`, `getsockname`, `setsockopt` (replayed on the swapped socket) and `close`, and restore `O_NONBLOCK` and `FD_CLOEXEC`;
  - map `0.0.0.0`, `::`, `::1` and port 0 onto the granted pool;
  - resolve pinned programs past interpreter shims, and refuse protected-interpreter chains with a named error when ports are granted;
  - build a universal dylib in its own audited unsafe crate, and amend [CD] INV-38 and FT-23;
  - test it: std, tokio/mio, socket2/actix, hyper, `cargo test` with port 0, double binds. The negative test: interposer absent → EPERM.
  - It stays an availability shim; Seatbelt remains the boundary.
- **Replace the pf port-range fallback with two things:**
  - **(a) An explicit handover, always available on every OS:** `LISTEN_FDS` and `LISTEN_FDNAMES` set and `LISTEN_PID` unset, compatible with listenfd and `systemfd --no-pid`. No admin and no magic, but the model must use it (review F-3's RQ1 confound).
  - **(b) An optional dedicated-agent-user host mode**, created with admin rights once and shared in design with rustybenchmark's OI-38 user. Use separate agent and grader users.
    - A pf anchor with uid rules: block inbound on interfaces other than `lo0` to sockets the agent uid owns, and block the agent uid's traffic to model ports.
    - Unmodified code on any port, port 0 included, works through shells and shims.
    - It also closes D21's `setsid` gap (`kill -1` as the agent uid, no private SPI) and the same-uid signal and chmod residuals.
    - The costs are real: a P8-compliant root helper (spawn-as-uid, pf attestation before each run; no sudoers), and pf coexistence with VPNs.
    - Spike it on a **disposable** Mac: inbound `user` matching on macOS 26 is UNVERIFIED (documented, and Mullvad uses it for outbound).
- **Linux on a shared stack:** either a netns obtained through a shipped AppArmor profile (admin once, Claude Code's precedent), or a spike of seccomp-notify *emulation* of `bind`/`connect` (the supervisor does the call and injects the descriptor, never CONTINUE). Until then, no port grants on hosts without userns.
- Record `network.mechanism` (`interposer`, `handover`, `agent-user` or `netns`) in the header, so benchmark rows can be split by it.
- Trade-offs:
  - interposer: soundness is fair (fail-closed, fragile edges), UX is best, FYP speed is fair (about a week with tests);
  - agent-user: soundness and UX are best, but it takes admin rights, root code, and a spike first;
  - handover: the soundest and cheapest, at the cost of UX and the RQ1 confound.

5. **Verdict: MODIFY** (medium confidence).
- Keep the swap as the primary mechanism, re-specified as measured.
- Replace the pf port-range fallback with the explicit handover plus an optional dedicated-agent-user pf mode, spiked first.
- Carry the same analysis to Linux hosts without a network namespace.

---

## P10: a hosted model may not see personal data (v1)

1. **Restate.** A hosted model never sees `personal`-sensitivity data in v1.

2. **Prior art.**
- Hosted-first harnesses send whatever the agent reads. Their controls are path rules and contracts.
  - Claude Code: `Read(./.env)` and `Read(./secrets/**)` deny rules ([permissions](https://code.claude.com/docs/en/permissions)).
  - GitHub Copilot content exclusion, which is "currently not supported in Edit and Agent modes" in VS Code ([docs](https://docs.github.com/en/copilot/concepts/context/content-exclusion)).
  - Cursor Privacy Mode and zero-data-retention terms: UNVERIFIED (not fetched).
- rustyharness is local-first. Its "no" costs nothing today (INV-24: no hosted endpoints in the default build).

3. **Attack.**
- The rule keys on **capability labels, not content**. Workspace files are read by `operational` built-ins, so personal data inside a repo (exports, fixtures, `.env`) reaches a hosted model anyway. It protects only against *declared* personal providers.
- It classes the user's own remote box as "hosted" (D12).
- There is no FYP cost and no schedule risk.

4. **Better.**
- Keep "no".
- Add a task-level `workspace.sensitivity` field (default `operational`; `personal` refuses hosted endpoints).
- Add a default protected-read list for hosted sessions (`.env*`, `*.pem`, `id_*`, credential files), enforced by the sandbox's read-deny, so an agent's shell cannot bypass it (Copilot's exclusions can be bypassed that way).
- Use D12's `remote-self-hosted` class for the user's own box.

5. **Verdict: KEEP** (high confidence), with the two small additions after the FYP.

---

## Top changes I'd make

1. **D32: rebuild the macOS plan on the measurements.**
   - The interposer needs a trampoline to survive SIP.
   - It must also interpose `listen`, restore descriptor flags, and handle IPv6 and port 0.
   - It must resolve shims, because the owner's own `cargo` is a bash script.
   - It needs an audited unsafe crate and an amendment to [CD] INV-38 and FT-23.
   - Drop the pf port-range fallback, which the harness cannot even check without root. In its place, ship the explicit `LISTEN_FDS` handover and spike an optional dedicated-agent-user pf mode that also fixes D21 and the OI-38 residuals.
2. **Ports follow the *measured* loopback kind (fact 1).**
   - On Linux without a network namespace, refuse port grants: Landlock is port-only, so a grant means LAN binds plus internet egress.
   - Add the invariant that no confinement layer grants bind on a shared stack.
   - Turn D30's hard refusal of private + shared-loopback sessions into a per-session approval.
   - Name the preview and model-server routes.
3. **D26: make H4's safe path E-elimination.** Harness-mediated, typed, cached crate fetches, plus offline rustdoc, plus separate research sessions; a structured extractor later. Do not build CaMeL or dual-LLM planning for 7-30B models. Stop `workspace_public` being the only way to get online crates.
4. **D12 and P10 hygiene.** Add a startup probe for model servers that reflect any Origin (llama.cpp's default), and name that residual. Later, add a `remote-self-hosted` TLS endpoint class and a `workspace.sensitivity` declaration.
5. **One install-time privilege policy for both OSes**, P8-compliant (small, argv-only root helpers, no sudoers): an AppArmor userns profile on Ubuntu 24.04 or later, and the agent user plus pf anchor on macOS. Record `network.mechanism` in every journal header, so benchmark rows can be split by mechanism.

## Hygiene

- **Probe files.** Everything lived in `scratchpad/t2-probes/`: the interposer, the servers, the cargo probe and its build output. The directory is deleted at the end of this review.
- **Processes.** Every signal and process belonged to the probes, and none outlived them (`ps` check).
- **Changes.** No system, firewall or repository change was made.

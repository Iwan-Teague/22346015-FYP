> Research helper for the 24 Sep 2026 decision reviews (agent a9577c3c603d523b0, Opus). Saved verbatim from its final report.

**Research report (fetched 2026-09-24).** Prose sources are paraphrased because I'm limited to one short quote in total. Code, config and log strings are given verbatim. I saw no text aimed at AI agents in any fetched page. I used up the WebSearch budget (200/200) partway through, so some items could not be confirmed. WebFetch automatically saved one PDF to the local tool-results folder: Apple-Sandbox-Guide-v1.0.pdf from reverse.put.as. I did not open it.

## 1. DYLD_INSERT_LIBRARIES vs SIP, hardened runtime and architecture

- **SIP guide (updated 2015-09-16):** a child started with exec or NSTask from a SIP-restricted process has its Mach special ports reset. dyld environment variables are purged when a protected process is launched. https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/RuntimeProtections/RuntimeProtections.html
- **Protected paths:** /bin, /sbin, /usr (but not /usr/local), /System, and Apple's preinstalled apps. https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/FileSystemProtections/FileSystemProtections.html
- **dyld(1) man page (dyld repo, main):** with SIP on, DYLD_* variables are ignored for SIP-protected binaries. https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/doc/man/man1/dyld.1
- **Why children lose the variable.**
  - In dyld4's `DyldProcessConfig.cpp`, `pruneEnvVars()` deletes `DYLD_*` from envp; the code comment says this is so child processes don't see them.
  - It runs only on macOS-family platforms, and only when AMFI grants none of `allowEnvVarsPrint`, `allowEnvVarsPath` or `allowEnvVarsSharedCache` (the "process is restricted" case).
  - **Inference:** /bin/sh, bash, zsh, /usr/bin/env, /usr/bin/arch, /usr/bin/sandbox-exec and the xcrun shims in /usr/bin strip the variable for their entire subtree.
  - https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/dyld/DyldProcessConfig.cpp
- **Field reports.**
  - Hynek Schlawack (2023-01-09): Apple's /bin/sh, bash and zsh don't pass on DYLD_LIBRARY_PATH; Homebrew's bash does. make runs recipes through /bin/sh, so they are sanitized. https://hynek.me/articles/macos-dyld-env/
  - mirrord (2024-08-22): npm's `#!/usr/bin/env node` shebang defeats injection. https://dev.to/aviramha/fun-with-macoss-sip-2646
  - npm's `script-shell` defaults to `/bin/sh` for `npm run` and `npm exec`. https://docs.npmjs.com/cli/v10/using-npm/config
- **Putting the variable back after a SIP process only works through argv.** UnityDoorstop PR #118 (open, 2026-09-23) passes DYLD_INSERT_LIBRARIES through `arch -e` because dyld drops it otherwise. https://github.com/NeighTools/UnityDoorstop/pull/118
- **Hardened runtime.**
  - The entitlement `com.apple.security.cs.allow-dyld-environment-variables` makes dyld read DYLD_*. `disable-library-validation` is also needed if the injected library isn't signed with the expected Team ID. https://developer.apple.com/tutorials/data/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables.json
  - Library validation is on by default: only Apple-signed or same-Team-ID libraries load. https://developer.apple.com/tutorials/data/documentation/bundleresources/entitlements/com.apple.security.cs.disable-library-validation.json
  - Full list of runtime exceptions: https://developer.apple.com/tutorials/data/documentation/security/hardened-runtime.json
- **Apple DTS (Quinn, Jun 2023):** protected means App Store apps, hardened-runtime programs and built-in components. With SIP on, the variable is silently ignored; the entitlement is the opt-out. https://developer.apple.com/forums/thread/731358
- **Hardened but opted in:** Node's `tools/osx-entitlements.plist` and OpenJDK's `default.plist` both set `allow-dyld-environment-variables` and `disable-library-validation` to true. https://raw.githubusercontent.com/nodejs/node/main/tools/osx-entitlements.plist and https://raw.githubusercontent.com/openjdk/jdk/master/make/data/macosxsigning/default.plist
- **Gotcha:** mirrord PR #4851 (open, 2026-09-23) reports that on macOS 26.2, /usr/bin/aa, aea and yaa are hardened and list the DYLD entitlement set to `false`. The key being present does not mean it is granted. https://github.com/metalbear-co/mirrord/pull/4851
- **What happens when an inserted library fails to load.**
  - In dyld4's `DyldRuntimeState.cpp` (`loadInsertedLibraries`): if loading fails and `!config.security.allowInsertFailures`, dyld logs `terminating because inserted dylib '%s' could not be loaded: %s` and returns an error, so the launch fails.
  - That flag is set in `DyldProcessConfig.cpp` as `allowInsertFailures = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION)`.
  - https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/dyld/DyldRuntimeState.cpp
- **Architecture.**
  - An arm64-only dylib inserted into an arm64e process is fatal.
    - ruby-build discussion #1930 (2022-02-04): `have 'arm64', need 'arm64e'`.
    - UnityDoorstop #107 (2026-07-29): /usr/bin/arch was killed with `have 'x86_64,arm64', need 'arm64e'`. The issue gives the environment as "macOS 27.0 (build 26A5388g)" and does not say whether SIP was on.
    - https://github.com/rbenv/ruby-build/discussions/1930 and https://github.com/NeighTools/UnityDoorstop/issues/107
  - Quinn: most built-in components are arm64e. The failure shows up when SIP is disabled, because dyld then actually tries to load the library. The arm64e ABI isn't stable, so independently shipped arm64e code is likely to break. https://developer.apple.com/forums/thread/731358
  - mirrord PR #4892 (merged 2026-09-15) handles a new `arm64e.x1` Mach-O subtype (12) found on SIP binaries. https://github.com/metalbear-co/mirrord/pull/4892
  - **Rosetta:** a universal executable runs as x86_64 whenever its parent does (PR #118 above), so the dylib needs an x86_64 slice (inference). Apple (page dated 2026-09-21): Rosetta is generally available through macOS 27; macOS 28 limits it to certain older games. https://support.apple.com/en-us/102527

## 2. Rust toolchain, Homebrew and version-manager shims

- **Rust releases are not signed or notarized.** promote-release #34 (opened 2020-12-11, still open) says Rust releases are neither codesigned nor notarized. https://github.com/rust-lang/promote-release/issues/34
- rustup #3422 (2023-07-29, closed as not planned): the installer downloads un-notarized binaries into the home directory. https://github.com/rust-lang/rustup/issues/3422
- rust #114796 (2023-08-14, closed as not planned): the .pkg installer fails Gatekeeper. https://github.com/rust-lang/rust/issues/114796
- **Inference:** rustup, cargo and rustc have no hardened runtime, so DYLD_* is honored. On arm64 the linker applies an ad-hoc signature automatically (Homebrew #9082). https://github.com/Homebrew/brew/issues/9082
- **Homebrew bottles are ad-hoc re-signed after relocation.**
  - PR #9102 (merged 2020-11-14) re-signs on Apple Silicon. https://github.com/Homebrew/brew/pull/9102
  - PR #15903 (merged 2023-08-27) re-signs on Intel only when the signature is broken, with `codesign --sign - --force --preserve-metadata=entitlements,requirements,flags,runtime`. https://github.com/Homebrew/brew/pull/15903
- **Homebrew rustup formula (1.29.1, `keg_only "it conflicts with rust"`):** it renames rustup-init to rustup, then runs `bin.install_symlink bin/"rustup" => name` for cargo, rustc, rustdoc, rustfmt, clippy-driver and others. These are **symlinks, not `#!/bin/bash exec -a` scripts**, so the premise in question 2 does not hold. https://raw.githubusercontent.com/Homebrew/homebrew-core/master/Formula/r/rustup.rb
- **pyenv:** shims are `#!/usr/bin/env bash` scripts ending in `exec "$(command -v pyenv)" exec "$program" "$@"`. https://raw.githubusercontent.com/pyenv/pyenv/master/libexec/pyenv-rehash
- **asdf (Go version):** shims are `#!/usr/bin/env bash` scripts ending in `exec asdf exec "%s" "$@"`. https://raw.githubusercontent.com/asdf-vm/asdf/master/internal/shims/shims.go
- **mise:** shims are symlinks to the mise binary (e.g. `shims/node -> ~/.local/bin/mise`). https://mise.jdx.dev/dev-tools/shims.html
- **nvm:** no shims. It is installed per user, runs per shell, and changes PATH. https://raw.githubusercontent.com/nvm-sh/nvm/master/README.md
- **Inference:** pyenv and asdf shims pass through /usr/bin/env, so DYLD_* is stripped (see question 1).

## 3. Interposition mechanics

- **`DYLD_INTERPOSE`** places a {replacement, replacee} pair in section `__DATA,__interpose,interposing`. https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/include/mach-o/dyld-interposing.h
- **How dyld4 applies it:**
  - It builds interposing tuples from the `__interpose` sections of dylibs loaded at launch.
  - A separate per-image tuple set stops the interposer from interposing itself, so its own calls reach the real function.
  - AMFI can ban interposing (`allowInterposing`).
  - It records original addresses in the shared cache so it can patch other parts of the cache to use the interposer.
  - https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/dyld/DyldRuntimeState.cpp
- **Shared-cache caveat.**
  - The cache builder removes stubs from calls between dylibs, except for `neverStubEliminateSymbols`. The comment says those are functions interposed by Instruments.app, ASan or libRPAC.dylib.
  - The list includes `_accept`, `_recv*` and `_send*`. My fetch tool's reading found no `_bind`, `_listen`, `_socket` or `_connect`.
  - **Inference:** a bind() call made inside shared-cache frameworks (Network.framework, CFNetwork) likely bypasses the interposer.
  - https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/cache_builder/Optimizers.cpp
  - Older dyld-852.2 had the same idea: functions that tools may need to override keep their stubs. https://raw.githubusercontent.com/apple-oss-distributions/dyld/dyld-852.2/dyld3/shared-cache/OptimizerBranches.cpp
- **Raw syscalls are rare.** Apple does not support statically linked binaries because the kernel syscall interface isn't guaranteed stable (QA1118, 2011-09-20). https://developer.apple.com/library/archive/qa/qa1118/_index.html
- **Go:**
  - Go 1.11: the runtime uses libSystem.dylib, but the `syscall` package still made direct system calls. https://go.dev/doc/go1.11
  - Go 1.12: syscalls on Darwin go through libSystem. https://go.dev/doc/go1.12
- **proxychains-ng README:** it hooks libc network functions in dynamically linked programs only. SIP (from El Capitan) blocks hooking system apps; the workarounds are partly disabling SIP or copying the binaries. 4.16 added a new DYLD hooking method for Monterey; 4.17 added a fat-binary option for M1. https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README
- **mirrord (2024-08-22):** uses DYLD injection. For SIP binaries it extracts the x86_64 slice, re-signs it, and hooks execve to swap it in on the fly, because arm64e slices can't be reused. This depends on Rosetta (see question 1). https://dev.to/aviramha/fun-with-macoss-sip-2646
- **Quinn (Jun 2023):** inserting a library into /usr/bin/env is not expected to work. https://developer.apple.com/forums/thread/730998

## 4. Socket activation

- **systemd `sd_listen_fds(3)`** (systemd 262~devel, man7 page dated 2026-08-03):
  - The first fd is 3 (`SD_LISTEN_FDS_START`).
  - It returns immediately if `$LISTEN_PID` is not the caller's PID.
  - `$LISTEN_FDNAMES` is colon-separated; missing names default to "unknown".
  - `unset_environment` clears `LISTEN_FDS`, `LISTEN_PID`, `LISTEN_PIDFDID` and `LISTEN_FDNAMES`.
  - It sets `FD_CLOEXEC` on the passed fds.
  - https://man7.org/linux/man-pages/man3/sd_listen_fds.3.html
- **launchd:** the plist `Sockets` key defines launch-on-demand sockets, and the job must fetch them with `launch_activate_socket(3)`. https://keith.github.io/xcode-man-pages/launchd.plist.5.html
- **`launch_activate_socket(3)` errors:** `ESRCH` means the caller is not managed by launchd; `ENOENT` means the socket name isn't in its plist; `EALREADY` means it was already activated. So this only works for launchd-managed jobs. https://keith.github.io/xcode-man-pages/launch_activate_socket.3.html
- **listenfd (`src/unix.rs`, "modified systemd protocol").**
  - It accepts the fds if `LISTEN_PID` is absent, empty, or equal to `getpid()`; a mismatch returns None.
  - The first fd comes from `LISTEN_FDS_FIRST_FD`, defaulting to 3.
  - It removes `LISTEN_PID` and `LISTEN_FDS` after reading them.
  - It does not read `LISTEN_FDNAMES`.
  - Its listener helpers set `FD_CLOEXEC`.
  - https://raw.githubusercontent.com/mitsuhiko/listenfd/master/src/unix.rs
  - The README says it supports systemd on Unix and systemfd on Unix and Windows. https://raw.githubusercontent.com/mitsuhiko/listenfd/master/README.md
- **systemfd:** uses `LISTEN_FDS` and `LISTEN_PID` on macOS and Linux, and a custom protocol on Windows. `--no-pid` exists because the pid check fails when cargo-watch sits in between. https://raw.githubusercontent.com/mitsuhiko/systemfd/master/README.md and https://github.com/mitsuhiko/systemfd
- **axum `examples/auto-reload`:** run with `systemfd --no-pid -s http::3000 -- cargo watch -x run`. The code calls `ListenFd::from_env()` and `take_tcp_listener(0)` (first passed fd), then `set_nonblocking(true)`, and falls back to `TcpListener::bind("127.0.0.1:3000")`. https://raw.githubusercontent.com/tokio-rs/axum/main/examples/auto-reload/README.md and https://raw.githubusercontent.com/tokio-rs/axum/main/examples/auto-reload/src/main.rs
- **actix-web docs:** an older version of the page recommended systemfd with listenfd; it now lists gotchas and recommends watchexec. The gotchas are:
  - it needs code changes;
  - it needs `--no-pid` when a watcher sits in between;
  - systemd socket activation itself is Linux-only;
  - the port can look open while a rebuild is still running.
  - https://actix.rs/docs/autoreload/
- **Implication:** unmodified servers ignore `LISTEN_FDS`; socket activation needs code changes in the server.

## 5. pf on macOS

- **Default /etc/pf.conf:**
  - Contents: `scrub-anchor`, `nat-anchor`, `rdr-anchor`, `dummynet-anchor` and `anchor` for `"com.apple/*"`, plus `load anchor "com.apple" from "/etc/pf.anchors/com.apple"`. There is **no `set skip on lo0`**.
  - macOS upgrades revert the file to its defaults.
  - Source: blog post dated 2018-11-03, tested through Ventura. https://blog.neilsabol.site/post/quickly-easily-adding-pf-packet-filter-firewall-rules-macos-osx/
- **Header comment (OS X 10.9/10.10):**
  - pf is not enabled automatically; each component enables and disables it with -E and -X.
  - The com.apple anchor loads `200.AirDrop/*` and `250.ApplicationFirewall/*`.
  - `set skip on lo0` appears only as a suggested addition.
  - https://manjusri.ucsc.edu/2015/03/10/PF-on-Mac-OS-X/
  - The Application Firewall appears to enable pf with -E. https://github.com/shawfdong/hyades/wiki/PF-on-Mac-OS-X
- **pfctl(8):** `-E` enables pf and increments the reference count; `-X token` releases that reference; `-d` disables pf; `-s References` shows who enabled it. https://keith.github.io/xcode-man-pages/pfctl.8.html
- **xnu `pf_ioctl.c`.**
  - `DIOCSTOP` (what `pfctl -d` sends) calls `pf_stop()`, sets `pf_enabled_ref_count = 0` and calls `invalidate_all_tokens()`. Any root process can therefore switch pf off for everyone.
  - `DIOCSTOPREF` stops pf only when the count reaches 0.
  - `/dev/pf` is created root-owned with mode 0600, and `pfioctl` returns `EPERM` unless `kauth_cred_issuser`. **Every rule or table change needs root.**
  - https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/pf_ioctl.c
- **Mullvad:**
  - Uses anchor `mullvad` and adds explicit `pass quick` rules on lo0.
  - Enables pf through pfctl-rs `try_enable`, which is `DIOCSTART` (not reference-counted).
  - On reset, if pf was off when Mullvad started, it calls `try_disable`, i.e. `DIOCSTOP`.
  - **Inference:** that would also switch pf off for any other user of pf.
  - https://raw.githubusercontent.com/mullvad/mullvadvpn-app/main/talpid-core/src/firewall/macos.rs and https://raw.githubusercontent.com/mullvad/pfctl-rs/main/src/ffi/mod.rs
- **IVPN:**
  - Uses anchor `ivpn_firewall`. It runs `pfctl -E`, stores the token in scutil at `State:/Network/IVPN/PacketFilter`, and releases it with `pfctl -X`.
  - It attaches its anchor by dumping `pfctl -sr`, appending `anchor ivpn_firewall all`, and reloading with `pfctl -R -f -`, which rewrites the live main ruleset.
  - It also adds `pass quick on lo0`.
  - https://raw.githubusercontent.com/ivpn/desktop-app/master/daemon/References/macOS/etc/firewall.sh
  - Its KB says it can't guarantee protection if third-party software changes the firewall rules directly. https://www.ivpn.net/knowledgebase/general/do-you-offer-a-kill-switch-or-vpn-firewall/
- **Murus** is a GUI front end for pf; the 3.0 beta supports the macOS 27 beta. https://www.murusfirewall.com/murus/
- **Documented breakage.**
  - macOS 14 betas: pf rules were not applied properly (2023-09-13). Fixed in RC2 (23A344); it only affected `quick` rules. https://mullvad.net/en/blog/bug-in-macos-14-sonoma-prevents-our-app-from-working and https://mullvad.net/en/blog/macos-14-sonoma-firewall-bug-fixed
  - macOS 14.6 through a 15.1 beta: pf ignored rules after system updates until a reboot (2024-10-16). https://mullvad.net/en/blog/macos-sometimes-leaks-traffic-after-system-updates
  - Private Relay traffic bypasses pf rules (2022-04-25). https://mullvad.net/en/blog/apples-private-relay-can-cause-the-system-to-ignore-firewall-rules
  - Since Ventura, flushed anchors persist until reboot (Jan 2024, no Apple reply). https://developer.apple.com/forums/thread/745158
- **Dynamic Apple anchors.**
  - `com.apple.internet-sharing/base_v4` is inserted when Internet Sharing starts; there is no public API to control it (Aug 2020). https://developer.apple.com/forums/thread/656877
  - The same anchor is attached for the shared networking used by Parallels, Docker Desktop, OrbStack and UTM, and a full pf.conf reload drops it (Sep 2026). https://github.com/tobomobo/mullvad-tailscale-macos/pull/17
- **tono #420 (2026-09-23):** a kill switch silently stops filtering when another program releases its pf reference; the issue proposes holding its own -E token and supervising pf liveness. https://github.com/raydocs/tono/issues/420
- **Implication (inference):**
  - "Admin once at install" doesn't cover per-grant changes, since those need root each time.
  - pf state doesn't survive a reboot, so a LaunchDaemon would be needed.
  - The harness must also monitor that pf is still enabled and its anchor still present.

## 6. Network Extension content filters

- **NEFilterDataProvider:** each flow corresponds to one connection opened by an app; the filter can allow, drop or ask to see more data. https://developer.apple.com/tutorials/data/documentation/networkextension/nefilterdataprovider.json
- **NEFilterFlow:**
  - `direction` is incoming or outgoing.
  - `sourceAppAuditToken` is available on macOS 10.15+.
  - `sourceProcessAuditToken` is available on macOS 13+; it differs from the app token when a system process connects on the app's behalf.
  - `sourceAppIdentifier` is **not available on macOS**.
  - https://developer.apple.com/tutorials/data/documentation/networkextension/nefilterflow.json, https://developer.apple.com/tutorials/data/documentation/networkextension/nefilterflow/sourceprocessaudittoken.json, https://developer.apple.com/tutorials/data/documentation/networkextension/nefilterflow/sourceappidentifier.json
- **NEFilterPacketProvider:** the packet handler gets context, interface, direction and bytes, with no process identity. https://developer.apple.com/tutorials/data/documentation/networkextension/nefilterpackethandler.json
- **Entitlement:** `content-filter-provider`, or `content-filter-provider-systemextension` when signed with a Developer ID profile. https://developer.apple.com/tutorials/data/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension.json
- **TN3134 (rev 2025-08-19):** on macOS a content filter must be a system extension, requires 10.15+, and can ship via the App Store or Developer ID. https://developer.apple.com/tutorials/data/documentation/technotes/tn3134-network-extension-provider-deployment.json
- **User approval:**
  - WWDC19 session 714: system extensions need the user's permission, and filters get read-only access to flows. https://developer.apple.com/videos/play/wwdc2019/714/
  - Little Snitch 6 install needs two non-default approvals: network filter and System Extension. https://help.obdev.at/littlesnitch6/intro-install
- **Loopback.**
  - Apple's docs are silent: a nil remote network matches any remote network, with no mention of loopback. https://developer.apple.com/tutorials/data/documentation/networkextension/nenetworkrule/init(remotenetwork:remoteprefix:localnetwork:localprefix:protocol:direction:).json
  - LuLu adds explicit `127.0.0.0/8` and `::1` rules and labels its wildcard rule "non-loopback". It notes that inbound flows sometimes arrive even with outbound-only rules, and it gets the pid from the audit token. https://raw.githubusercontent.com/objective-see/LuLu/master/LuLu/Extension/FilterDataProvider.m
  - A developer forum thread (Oct 2025) needed an explicit 127.0.0.1 rule to see loopback flows. https://developer.apple.com/forums/thread/803694
- **LuLu** blocks outgoing connections only and needs macOS 10.15+. https://objective-see.org/products/lulu.html
- **Little Snitch** rules cover both incoming and outgoing connections. https://www.obdev.at/products/littlesnitch/index.html

## 7. Loopback aliases

- **ifconfig(8):** `alias` adds an extra address to an interface; only the superuser may change interface configuration. https://keith.github.io/xcode-man-pages/ifconfig.8.html
- **lo(4):** addresses must be assigned for each address family. https://keith.github.io/xcode-man-pages/lo.4.html
- **Wikipedia (Localhost):** 127.0.0.1 is standard; other 127/8 addresses aren't supported by all operating systems. https://en.wikipedia.org/wiki/Localhost
- **docker/for-mac #4607 (2020-05-26, macOS 10.15.4):** the repro steps first run `sudo ifconfig lo0 alias 127.0.0.2 up`. https://github.com/docker/for-mac/issues/4607

## 8. Seatbelt network rules

- **No Apple SBPL documentation found.** Evidence comes from other projects.
- **sandbox-runtime PR #127 (merged 2026-02-10):**
  - IP filters accept only two host values, `localhost` and `*`.
  - `localhost` matches 127.0.0.1 and ::1, but not `::ffff:127.0.0.1`, so dual-stack Java gets EPERM.
  - The fix switched the bind and inbound rules to `*:*`.
  - https://github.com/anthropic-experimental/sandbox-runtime/pull/127
- **sandbox-runtime, current code.**
  - With `allowLocalBinding` it emits `(allow network-bind (local ip "*:*"))`, `(allow network-inbound (local ip "*:*"))` and `(allow network-outbound (remote ip "localhost:*"))`.
  - Proxy ports get `localhost:${port}` rules.
  - Commands launch as `env … /usr/bin/sandbox-exec -p <profile> <shell> -c <cmd>`.
  - A code comment names a "DYLD interposer" as a planned later step.
  - https://raw.githubusercontent.com/anthropic-experimental/sandbox-runtime/main/src/sandbox/macos-sandbox-utils.ts
- **sandbox-runtime PR #530 (open, 2026-09-12):**
  - Adds per-port `localhost:N` rules for bind, inbound and outbound.
  - It argues that `*:N` would also admit a LAN-facing bind, which implies `localhost:N` is narrower. That contradicts the premise in your plan; the PR description quotes no 0.0.0.0 test.
  - https://github.com/anthropic-experimental/sandbox-runtime/pull/530
- **sandbox-runtime #225 (2026-04-23):** `(allow network-outbound (local ip "*:*"))` allowed all egress, because every outbound socket has a local endpoint. https://github.com/anthropic-experimental/sandbox-runtime/issues/225
  - Related: PR #302 https://github.com/anthropic-experimental/sandbox-runtime/pull/302 and issue #188 https://github.com/anthropic-experimental/sandbox-runtime/issues/188
- **codex (`codex-rs/sandboxing/src/seatbelt.rs`):**
  - With `allow_local_binding` it emits `(allow network-bind (local ip "*:*"))`, `(allow network-inbound (local ip "localhost:*"))` and `(allow network-outbound (remote ip "localhost:*"))`.
  - With full network it emits `(allow network-outbound)` and `(allow network-inbound)`.
  - No comment explains why bind uses `*:*`.
  - The executable is hard-coded as `/usr/bin/sandbox-exec`.
  - The base policy is `(deny default)` and says it is inspired by Chrome's policy.
  - https://raw.githubusercontent.com/openai/codex/main/codex-rs/sandboxing/src/seatbelt.rs and https://raw.githubusercontent.com/openai/codex/main/codex-rs/sandboxing/src/seatbelt_base_policy.sbpl
- **Chromium network service:** `(allow network-bind network-inbound (local tcp) (local udp))`. https://raw.githubusercontent.com/chromium/chromium/main/sandbox/policy/mac/network.sb

## 9. sandbox-exec and sandbox_init status

- **Both are deprecated but still present.**
  - The sandbox-exec(1) page (dated 2017-03-09) marks it deprecated. It is still in the man-page set built from Xcode 27.2 beta 1 (27B5019j); this is a third-party mirror, not an Apple-hosted page. https://keith.github.io/xcode-man-pages/sandbox-exec.1.html and https://keith.github.io/xcode-man-pages/
  - sandbox_init(3) also marks `sandbox_init` and `sandbox_free_error` deprecated.
- **New in 2026:** the named `kSBXProfile*` profiles must not be used when building against macOS SDK 27.0 or later: "Processes opting into them will be killed on attempt to do so." Custom profile strings are not mentioned. https://keith.github.io/xcode-man-pages/sandbox_init.3.html
- **sandbox(7) (2010):** children inherit the sandbox; limits apply when a resource is acquired, and fds opened earlier stay usable. https://keith.github.io/xcode-man-pages/sandbox.7.html
- **Still in use:** codex and sandbox-runtime (current main, Sept 2026) both call `/usr/bin/sandbox-exec` (links in question 8).

## UNVERIFIED

1. The plan's premise that a `network-bind (local ip "localhost:PORT")` rule also allows 0.0.0.0 or LAN binds. PR #530's author implies the opposite; this needs an empirical test.
2. Whether `network-inbound (local ip "localhost:*")` is checked on each accepted connection (which would block LAN clients even on a 0.0.0.0 bind) or only at listen().
3. That /usr/bin/sandbox-exec itself strips DYLD_* before exec'ing its target. This is inferred from the SIP path plus `pruneEnvVars`. If true, `DYLD_INSERT_LIBRARIES=… sandbox-exec … cmd` loses the variable, and `sandbox-exec … /usr/bin/env DYLD_INSERT_LIBRARIES=… cmd` would restore it for one hop.
4. That hardened-runtime intermediates without the entitlement also prune DYLD_* for their descendants (inferred from the dyld pruning condition).
5. Whether bind() calls from shared-cache frameworks (e.g. NWListener) escape the interposer on current macOS. The absence of `_bind` from the stub list was read by the fetch tool's summarizer.
6. The exact conditions under which AMFI sets `ALLOW_FAILED_LIBRARY_INSERTION`, e.g. for a hardened process that has the DYLD entitlement but still enforces library validation.
7. That macOS lo0 has only 127.0.0.1 by default and that binding 127.0.0.2 returns EADDRNOTAVAIL.
8. Whether UnityDoorstop #107's machine had SIP disabled, or whether macOS 27 changed the ignore behavior.
9. That the Rust dist binaries are linker ad-hoc signed specifically (not checked on real binaries).
10. Whether the mise binary is hardened or notarized, and the hardened status of python.org Python and the Command Line Tools python3.
11. Whether `pfctl -f /etc/pf.conf` drops third-party anchors nested under `com.apple/*`.
12. Vagrant's use of pf anchors (seen only in search snippets, not fetched); tsocks on macOS (not researched).
13. Whether `sandbox-exec -n` (named profiles) is killed on macOS 27.

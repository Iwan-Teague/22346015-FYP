# Web research through your own proxy (`mode: user-proxy`)

Status: slice P-39o. Design: `docs/slices/P-39-web-airlock.md` section 5.5, decision #2 option A.

The default build has no direct network egress and no TLS. `user-proxy` mode lets a research
session fetch web pages anyway, by handing the connection to a forward proxy that **you** run on
your own machine. This page says what that changes, what it costs you in assurance, and how to set
it up.

## What you are trusting

In the direct mode (`net` builds) the harness resolves the host name itself, classifies every
address in the answer (no loopback, private, link-local, metadata or other non-global address),
and dials exactly the address it classified. In `user-proxy` mode it cannot do that: the harness
never sees the origin's address, because your proxy does the DNS and the TLS.

So these checks **move to your proxy, and you are trusting it to do them**:

- classify-after-resolve (refuse a name that resolves to a private or metadata address);
- the DNS-rebinding defence (use the address it classified, never a second answer).

The journal says so. Every fetch hop's `Egress` record has `mode: "user-proxy"` and
`ip: "delegated"` instead of an address, the session header names the mode, and the chat banner
prints a line that the IP checks are delegated to your proxy.

The harness does keep the fetcher on a leash. The relay between the fetcher and your proxy parses
the fetcher's one request, requires it to be exactly the request for the allowlisted URL of that
hop (same scheme, host, port and target; same `Host` header), forwards only those bytes, and
refuses anything else: a different host or an IP literal, a second or pipelined request, `CONNECT`,
`Upgrade`, a request body. So a compromised fetcher cannot ask your proxy for
`http://169.254.169.254/` or `http://10.0.0.5/`. What the harness cannot control is what your proxy
does with the allowlisted **name** it was given: if that name resolves (or is rebound) to a private,
loopback, link-local or metadata address, only your proxy's own ACL stops the request. Configure it
to deny those ranges (see the Squid recipe).

What does **not** change: the session allowlist (host and port, checked at policy, again by the
provider, and again on every redirect), the per-session budgets, the per-hop wall and byte caps,
the content-type and charset verdicts, the untrusted marking of everything fetched, and the offline
audit.

## Configuration

In the user config (`<config dir>/config.json`; it is read only from the config directory, never
from the workspace):

```json
{
  "web": {
    "mode": "user-proxy",
    "user_proxy": "http://127.0.0.1:3128",
    "user_proxy_ack": "ip-checks-delegated"
  }
}
```

- `user_proxy` must be loopback by the same rule as the model endpoint: `http://127.0.0.1[:port]`,
  `http://[::1][:port]` or `http://localhost[:port]`, with no user info, path, query or fragment.
  A LAN or public proxy address is refused.
- `user_proxy_ack` must be exactly `ip-checks-delegated`. Without it the mode is refused. The
  string is there so that handing the IP checks to another program is a deliberate, written act.
- `user_proxy` or `user_proxy_ack` on any other mode is refused as a stray key.

## What the harness sends

The fetcher process only ever talks to a one-shot loopback relay the harness opens for the hop
(with a bearer token). The relay dials your proxy and nothing else. Over that relay the fetcher
sends one plain-HTTP request in absolute form, the shape a forward proxy expects:

```
GET https://docs.example.org/guide?x=1 HTTP/1.1
Host: docs.example.org
User-Agent: rustyharness-fetch
Accept: */*
Accept-Encoding: identity
Connection: close
```

No `CONNECT` goes to your proxy, and the fetcher does no TLS: your proxy opens the TLS connection to
the origin and returns the plaintext response. (The one `CONNECT` in a hop is the fetcher's
handshake with the harness's own relay, which checks the token and the host it was told to expect.
The relay then checks that the request above is the one it expects before passing it on.)
Redirects are reported, never followed; the harness re-checks each target against the allowlist and
opens a fresh hop.

## A recipe: Squid

Squid documents forward-proxying of absolute-form requests. A minimal local-only setup:

```
# squid.conf: listen on loopback only
http_port 127.0.0.1:3128
acl localnet_dst dst 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 ::1 fc00::/7 fe80::/10
http_access deny localnet_dst
http_access allow localhost
http_access deny all
```

The `deny localnet_dst` line is the point of the exercise: it is the check the harness no longer
does. Squid evaluates `dst` against the address it resolved, so this is the classify-after-resolve
defence moved into your proxy. Extend the list to cover your own networks.

**UNVERIFIED.** Whether a given proxy accepts an absolute-form `https://` request over a plaintext
connection and then does TLS to the origin is a property of that proxy and its configuration. Squid
is the proxy this recipe names because its documentation describes absolute-form forward requests,
but this repository has not run the shape above against a real Squid, and other proxies (mitmproxy,
tinyproxy, privoxy) may refuse or rewrite it. Nothing in the test suite talks to
a real proxy: the tests use a scripted loopback fixture that records the request it receives.
Verify your proxy by hand first:

```
curl -x http://127.0.0.1:3128 -v https://example.org/
```

curl uses `CONNECT` for https, so that does **not** prove absolute-form support. To test the exact
shape the harness sends, use a raw request:

```
printf 'GET https://example.org/ HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n' | nc 127.0.0.1 3128
```

A page back means the proxy accepts it. A 4xx or a closed connection means it does not, and
research fetches through it will fail with a typed fetcher error (never silently).

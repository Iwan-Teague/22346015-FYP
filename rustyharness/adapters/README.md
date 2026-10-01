# adapters/

Fixtures only (design §1.3, §4.10). Real providers ship their capability
manifests **with themselves**, so adding a provider never touches this
repository: the user admits it, and the harness core does not change.

`example/manifest.json` is a schema illustration, not a real app: a v1
manifest (schema: `crates/harness-manifest`, design §4.1) for an imaginary
MCP stdio server with one read and one write capability. Its
`schema_sha256` / `description_sha256` pins are placeholders (all zeros):
what they pin, the schema and description the server presents at connect
time, is compared from H4 on (§4.4).

Check a manifest the way admission reads it:

```bash
cargo run -p harness-cli -- manifest check adapters/example/manifest.json
```

It prints each capability's effective class (§4.2) and what this build's
admission does with the manifest. A valid manifest is not an admitted one:
this build admits only the built-in `harness` provider; signed and pinned
providers arrive with H4.

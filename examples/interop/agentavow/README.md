# AgentAvow tool-manifest-digest-v0: APS-side consumer

An APS-side consumer for AgentAvow's
[tool-manifest-digest-vectors-v0](https://github.com/AgentAvow/AgentAvow/tree/4404df2c/docs/standards/tool-manifest-digest-vectors-v0)
fixture. It reads the vector file unchanged and computes each of AgentAvow's five axes with
`agent-passport-system` 7.2.0 primitives: `canonicalizeJCS` for canonical bytes, and strict Ed25519 `verify` with
the issuer key pinned by `kid` and `alg`. Each axis is compared with the fixture's expected result separately.

This is a second implementation of the fixture's checks, run by the consuming project. It is a reproduction, not an
independent verification record.

## Run

```sh
cd examples/interop/agentavow
npm install
curl -sL -o vectors.json \
  https://raw.githubusercontent.com/AgentAvow/AgentAvow/4404df2c/docs/standards/tool-manifest-digest-vectors-v0/tool-manifest-digest-v0-vectors.json
shasum -a 256 vectors.json
# expect 2f4632b03305471b3262109dce7db2cf71d029fe6d9ec85fe54e9bf5c82bb9df
node run.mjs vectors.json
```

Expected: 30 of 30 expected axis results match, exit 0. Each negative case fails exactly its own axis.

| case | signature_valid | canonical_bytes | subject_binds | digest_binds | fresh | rely |
|---|---|---|---|---|---|---|
| digest-match | true | true | true | true | true | true |
| digest-mismatch | true | true | true | false | true | false |
| past-expiry | true | true | true | true | false | false |
| wrong-subject | true | true | false | true | true | false |
| tampered-payload | false | true | true | true | true | false |

## What this does not establish

- **No per-tool authority claim.** The attestation's subject is a repository or server (`github:github/github-mcp-server`).
  `scan.toolDigests` is keyed by definition file path, not by tool name, so nothing binds a specific APS tool
  (`requestedToolName`) to that subject. The consumer reports that binding as `not_evaluated`.
- **The manifest digest is not an APS metadata pin.** `toolManifestDigest` is folded over the digests of every definition
  file the scan observed. APS `capabilityMetadataDigest` hashes one tool's declared metadata under a required domain
  label. Treating one as the other is a `false_analog`, so the consumer keeps them separate.
- Nothing about runtime behavior, per the fixture's own claim ceiling.

AgentAvow owns the fixture and its claim ceiling. APS owns this consumer. Both boundaries above were confirmed by the
fixture's author on [agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177).

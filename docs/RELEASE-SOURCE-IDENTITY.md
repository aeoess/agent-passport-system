# Release source identity

Draft. Not linked from the README or any other document yet.

This repository moves from one GitHub owner to another. The package name on npm,
the repository id and the git history do not change. What changes is the source
identity that provenance and attestations name, and that is the part a verifier
reads.

## The two identities

Before the transfer:

- `github.com/aeoess/agent-passport-system`
- signer workflow `aeoess/agent-passport-system/.github/workflows/release.yml`

After the transfer:

- `github.com/agent-passport-system/agent-passport-system`
- signer workflow `agent-passport-system/agent-passport-system/.github/workflows/release.yml`

The repository id stays **1161268529** across the move. That is identity
continuity and nothing more. It does not establish that permissions, app
installations, org policy or any integration behave the same after the move,
because none of those are derived from the id alone. Whether a given service
keeps working is a separate question that has to be checked against that
service.

Owner name and owner id do change, and those are what the release guards and
the OIDC claims compare.

## Verifying a version released before the move

Releases published from the old owner carry provenance naming that old source
identity. They stay valid as the record of where that version was built. Nothing
about them is rewritten, and nothing should be.

Version 7.2.0 is the worked example. Its tag `v7.2.0` resolves to commit
`bf7b9824cb6ee82a46f0d5d333b0e7a7ccbed787`, and its GitHub release carries the
tarball, the SPDX SBOM and the attestation bundle. Download
`agent-passport-system-7.2.0.tgz` and `agent-passport-system-7.2.0.intoto.jsonl`
from that release, then verify against the old owner:

```sh
gh attestation verify agent-passport-system-7.2.0.tgz \
  --repo aeoess/agent-passport-system \
  --bundle agent-passport-system-7.2.0.intoto.jsonl \
  --signer-workflow aeoess/agent-passport-system/.github/workflows/release.yml \
  --source-digest bf7b9824cb6ee82a46f0d5d333b0e7a7ccbed787 \
  --source-ref refs/tags/v7.2.0 \
  --deny-self-hosted-runners
```

The old owner path in `--repo` and `--signer-workflow` is correct and stays
correct. Substituting the new owner for a pre-transfer version is expected to
fail, because the identity in the bundle is the old one.

Do not read 7.2.0 as a rule covering everything before it. Attestation coverage
is per version, so each version has to be checked on its own.

Three of the 17 GitHub releases published up to 7.2.0 carry no attestation
bundle asset. Those are v5.0.0, v4.5.0 and v4.1.0. That was read off the release
assets, and it says only what those releases have attached to them. GitHub keeps
attestations in its own attestations API, separate from release assets, and that
API was not queried for those three versions. Whether an attestation for them
exists anywhere is **not known** here.

Changing the source identity does not create an attestation for any version.
Verifying a version means locating the attestation that actually matches that
version's artifact, from the release assets or from the attestations API, and
verifying against the identity that attestation names.

## Verifying a version released after the move

Versions released from the new owner name the new source identity. Use the new
owner path in `--repo` and `--signer-workflow`, and the tag and commit of that
version.

A verifier pinned to `aeoess/agent-passport-system` will reject every version
released after the move. That rejection is the verifier working as configured,
not a defect in the release. Anyone enforcing a source identity needs to decide
which identity applies to which version range, or accept both.

## What this document does not cover

Only the GitHub source identity and attestation verification. It makes no claim
about how any other service treats the change.

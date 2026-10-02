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

The repository id stays **1161268529** across the move. GitHub keeps it, so
anything keyed on the id rather than the owner path is unaffected. Owner name
and owner id do change, and those are what the release guards and the OIDC
claims compare.

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
is per version. Of the 17 GitHub releases published up to 7.2.0, three carry no
attestation bundle asset at all: v5.0.0, v4.5.0 and v4.1.0. Check the release a
version actually has before writing a verification command for it. A change of
source identity policy does not create an attestation for a version that never
had one.

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

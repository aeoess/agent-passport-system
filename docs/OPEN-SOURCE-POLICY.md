# Open Source Policy

Program document for OpenChain ISO/IEC 5230 (open source license compliance).
Scope, the Supplied Software of the Agent Passport System project: the npm
package agent-passport-system, the PyPI package agent-passport-system, the MCP
package, and the source repositories listed in the README's Project codebases
section.

## Policy

All Supplied Software is licensed under Apache-2.0. Every source file carries
an SPDX license identifier and a copyright line. Third-party components are
accepted only under licenses compatible with Apache-2.0, are tracked in the
package manifests and committed lockfiles, and are disclosed in the SBOM
shipped with each release.

## Roles and responsibilities

The maintainer (Tymofii Pidlisnyi, @aeoess) holds all program roles: FOSS
liaison for external license inquiries, compliance responsibility, and release
authority. Public questions arrive via GitHub issues; private ones via the
contact in SECURITY.md. The maintainer is the sole program participant;
competence is evidenced by authorship of the compliance tooling itself
(per-file SPDX headers, SBOM generation, REUSE conformance work) and by this
documented program. This policy and CONTRIBUTING.md are the awareness vehicle;
CONTRIBUTING.md is the entry point every contributor reads.

## License identification and inbound contributions

Licenses are identified per file via SPDX identifiers and verified with REUSE
tooling. Inbound contributions are accepted under the inbound equals outbound
rule stated in CONTRIBUTING.md: submitters assert the right to contribute
under Apache-2.0, and review checks provenance and format before merge
(CONTRIBUTING.md, Code review section).

## Outbound obligations

Released artifacts include the Apache-2.0 LICENSE and NOTICE. Each release
ships an SPDX SBOM as a release asset, and npm releases carry SLSA build
provenance. The runtime dependencies carry permissive licenses recorded in the
SBOM; their obligations are satisfied by license inclusion and disclosure.

## Program review

Reviewed at least annually, alongside the dated security review, or upon any
compliance inquiry.

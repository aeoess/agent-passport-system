# Security Assurance Program

Program document for OpenChain ISO/IEC 18974 (open source security assurance).
Scope: the same Supplied Software as the Open Source Policy.

## Policy

Known vulnerabilities in Supplied Software and its components are identified,
assessed, and remediated within documented timeframes. SECURITY.md is the
public statement of the policy: a private reporting channel, acknowledgment
within 48 hours, and a fix timeline within 7 days.

## Roles, competence, awareness

The maintainer holds all program roles and is the security contact. Competence
is evidenced by the published security work: the threat model with its
assurance argument (THREAT_MODEL.md), the dated security review
(docs/SECURITY-REVIEW-2026.md), and the fuzzing campaign with fixed findings
(fuzz/FINDINGS.md). This document and SECURITY.md are the awareness vehicle.

## Detection of known vulnerabilities

Dependabot monitors npm and GitHub Actions dependencies. npm audit gates every
release. GitHub private vulnerability reporting is enabled on all six project
repositories for external reports. CodeQL with the security-extended query set
runs on every change, and coverage-guided fuzzing runs per pull request and on
a daily schedule.

## Handling and communication

Findings are triaged against the threat model and fixed with a failing test
first, per CONTRIBUTING.md. Fixes are disclosed in CHANGELOG.md and, when
applicable, in GitHub security advisories with reporter credit per
SECURITY.md. Fuzzing findings keep their reproducing inputs as corpus
regression seeds.

## Program continuity and review

The program is reviewed with each dated security review, at least annually.

## Program procedures

- Required competency for the security role: vulnerability triage against the
  threat model, dependency audit tooling, and the release gate. Assessed
  competence is evidenced above.
- Awareness record, sole participant: the maintainer acknowledges this program
  and its location, its objective (no known unaddressed vulnerability ships),
  the contribution expected (run the gates on every release), and that failure
  to follow it blocks release.
- Program metrics: open alert count and age, time to acknowledge and time to
  fix against the 48 hour and 7 day targets, and fuzzing findings per cycle.
- Vulnerability records: Dependabot alert history, npm audit output in the
  release gate, and the dated security reviews record identified
  vulnerabilities and their disposition, including determinations that no
  action was required.
- Each dated security review records what changed since the prior one; that
  series is the evidence of periodic review and continuous improvement.
- Conformance is tracked against the ISO/IEC 18974 self-certification
  checklist; the completed checklist is retained at docs/openchain/.

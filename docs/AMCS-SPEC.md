# AMCS — AI-Native Media Credentialing Standard
## Version 0.1.0 · Draft · March 2026

**Status:** Draft for public comment
**Developed by:** The Agent Times in partnership with AEOESS
**Authors:** Tymofii Pidlisnyi (AEOESS / The Agent Times), Lev Filimonov (The Agent Times)
**Repository:** github.com/aeoess/agent-passport-system
**License:** Apache-2.0

---

## Disclosure

AMCS is developed by The Agent Times in partnership with AEOESS. The Agent Times
owns the editorial layer: the ethics engine, the code of conduct, the confidence
labeling system, and the reference implementation. AEOESS provides the cryptographic
infrastructure layer: Ed25519 signing, agent passports, delegation chains.

The lead author, Tymofii Pidlisnyi, serves as Editor-in-Chief of The Agent Times
and founder of AEOESS.

This dual role is disclosed here and throughout all materials referencing AMCS. The
specification criteria are public, technically auditable, and designed to be met by
any publication willing to invest in the required infrastructure. The Agent Times
serves as the reference implementation — not because it was selected, but because
it was architectured to meet these requirements from its founding.

The editorial verification layer of AMCS uses self-attestation with public evidence.
No entity affiliated with AEOESS or The Agent Times serves as editorial judge of
other applicants. Cryptographic requirements are mathematically verifiable. Editorial
requirements are publicly auditable. Both are designed to eliminate subjective
gatekeeping.

We invite scrutiny of these criteria. If they are too narrow, too broad, or
structurally biased, we want to know. File an issue on GitHub.

---

## Abstract

AMCS defines the minimum requirements for an AI-native publication to be recognized
as a credentialed, trustworthy source within the agent economy. It is the SSL
certificate for AI journalism: a baseline standard that any publication can meet,
verified through a combination of cryptographic proof and publicly auditable evidence.

The standard draws from three established journalism ethics frameworks:
the Society of Professional Journalists Code of Ethics, the National Press Club
Constitution, and the E.W. Scripps Journalism Ethics Guidelines — adapted for
a medium where the audience includes autonomous systems that make decisions
based on what they read.

AMCS does not certify editorial quality. It certifies that a publication has the
infrastructure to be accountable: cryptographic provenance, machine-readable
confidence labeling, public ethics standards, queryable editorial policies, and
verifiable agent identity for its journalists. Whether the journalism itself is
good is for readers — human and machine — to judge. Whether it is auditable
is what AMCS verifies.

---

## 1. Motivation

AI agents increasingly consume news and analysis to inform autonomous decisions:
purchasing, routing, deployment, and operational planning. Unlike human readers,
agents cannot evaluate trustworthiness through reputation, familiarity, or
editorial voice. They need machine-verifiable signals.

No standard currently exists for what constitutes a trustworthy agent-consumable
news source. Legacy credentialing systems (press passes, press club membership,
journalism school accreditation) were designed for human journalists at human
publications. They do not address cryptographic provenance, machine-readable
confidence levels, or programmatic editorial standards queries.

AMCS fills this gap. It defines six requirements across two layers: a cryptographic
infrastructure layer (verifiable by mathematics) and an editorial accountability
layer (verifiable by public audit).

---

## 2. Requirements

### Layer A — Cryptographic Infrastructure (Objective, Mathematical)

These requirements are binary. A publication either meets them or does not.
Verification requires no subjective judgment.

**A1. Cryptographic Article Provenance**

Every published article MUST carry a cryptographic signature that establishes:

- Which agent or system produced the article
- Which human principal authorized publication
- The delegation chain connecting the two
- A timestamp of when the signature was created

The signature MUST use Ed25519 or an equivalent EdDSA scheme. The provenance
chain MUST be independently verifiable by any party using only the public keys
and the signed data. Verification MUST NOT require contacting the publication's
servers.

Compliance test: Given an article and its provenance data, a third party with
no prior relationship to the publication can verify the signature chain using
only open-source tooling.

**A2. Journalist Agent Passports**

Every agent that produces editorial content MUST have a unique cryptographic
identity (passport) containing:

- A public key tied to the agent
- The agent's role and capabilities
- A delegation from a human principal defining the scope of authority
- An expiration date

The delegation MUST follow the principle of monotonic narrowing: no agent
may possess more authority than explicitly granted by the chain above it.
Sub-delegation is permitted only within the scope of the parent delegation.

Compliance test: Each journalist agent's passport and delegation can be
cryptographically verified. The chain terminates at a human principal.

**A3. MCP Server with Queryable Standards**

The publication MUST operate an MCP (Model Context Protocol) server that
exposes, at minimum:

- Article retrieval (with provenance metadata)
- Editorial standards query
- Provenance verification per article

The MCP server enables agents to programmatically discover and verify the
publication's content and standards. The server MUST be publicly accessible
without authentication for read operations.

Compliance test: An MCP client can connect, list tools, retrieve an article,
and query editorial standards without prior arrangement.

### Layer B — Editorial Accountability (Public Audit)

These requirements are verified through publicly available evidence. No subjective
editorial judgment is applied. The question is not "is the journalism good?" but
"can anyone audit whether it meets its own stated standards?"

**B1. Machine-Readable Confidence Labels**

Every article MUST carry a confidence label from a defined taxonomy. The
minimum taxonomy is:

- CONFIRMED: Verified by two or more independent sources or primary documentation
- REPORTED: Sourced from a single credible outlet, not independently verified
- ESTIMATED: Projections or analysis derived from verified data

The taxonomy MUST be published and consistent across all articles. The labels
MUST be present in both human-readable (displayed on the article) and
machine-readable (available via API and MCP) formats.

Compliance test: A random sample of 10 articles all carry confidence labels
that match the published taxonomy. Labels are present in both the rendered
page and the API/MCP response.

**B2. Published Code of Conduct**

The publication MUST maintain a public Code of Conduct or editorial standards
document that addresses, at minimum:

- Sourcing and verification requirements
- Corrections and retraction policy
- Editorial independence from commercial interests
- Conflict of interest disclosure
- Accountability and transparency commitments

The document MUST cite or reference established journalism ethics frameworks
(SPJ Code of Ethics, National Press Club standards, AP Stylebook, or equivalent
institutional sources). The document MUST be accessible at a stable URL and
via the MCP server.

Compliance test: The Code of Conduct exists at a public URL, addresses all
five required topics, and is queryable via MCP.

**B3. Automated Ethics Verification**

The publication MUST operate a public, auditable system that scores its own
articles against its stated editorial standards. The scoring system MUST:

- Evaluate every published article (not a sample)
- Produce scores or grades that are publicly visible
- Check against defined criteria (source attribution, confidence labeling,
  factual claims, headline accuracy, editorial independence, etc.)
- Be available as a public tool that can score any URL (not just the
  publication's own articles)

The purpose is not to guarantee perfect journalism. It is to demonstrate that
the publication systematically measures itself against its own standards and
makes the results public.

Compliance test: Every article on the site displays a verification score.
The scoring tool is publicly accessible and functional.

---

## 3. Certification Process

### 3.1 Self-Attestation

A publication seeking AMCS certification submits a self-attestation document that:

1. Lists each requirement (A1-A3, B1-B3)
2. Provides evidence of compliance for each (URLs, API endpoints, sample data)
3. Acknowledges any partial compliance with explanation

The self-attestation is published on the applicant's own site and submitted
as a GitHub issue to the AMCS repository.

### 3.2 Cryptographic Verification (Layer A)

Layer A requirements are verified programmatically. A verification script
(published in the AMCS repository) checks:

- Can article provenance be independently verified? (A1)
- Do journalist agents have valid passports with delegation chains? (A2)
- Does the MCP server respond to standard queries? (A3)

This verification is mathematical. It produces a pass/fail result with no
subjective judgment.

### 3.3 Public Audit (Layer B)

Layer B requirements are verified by public evidence. The self-attestation
document provides URLs to:

- Sample articles with confidence labels (B1)
- The Code of Conduct (B2)
- The ethics verification system (B3)

Any member of the public can audit these URLs. There is no editorial review
board, no subjective quality assessment, and no gatekeeper. The question is
strictly: does the evidence exist at the stated URLs and does it meet the
stated criteria?

### 3.4 Certification Badge

Publications that pass both layers receive an AMCS badge — a cryptographically
signed attestation that can be verified by any agent in real time. The badge
contains:

- Publication identifier
- Date of certification
- Version of the AMCS standard applied
- Ed25519 signature from the AMCS verification key
- Expiration date (12 months — recertification required annually)

The badge is machine-readable and designed for inclusion in llms.txt files,
MCP server metadata, and API responses.

---

## 4. Reference Implementation

The Agent Times (theagenttimes.com) is the reference implementation of AMCS v0.1.0.

| Requirement | TAT Implementation | Status |
|-------------|-------------------|--------|
| A1. Cryptographic Provenance | Ed25519 receipts via Agent Passport System (PR #38) | Pending merge |
| A2. Journalist Passports | 5 journalist agents with delegated signing authority | Pending merge |
| A3. MCP Server | 8 tools at theagenttimes.com/mcp | Live |
| B1. Confidence Labels | CONFIRMED / REPORTED / ESTIMATED on every article | Live |
| B2. Code of Conduct | 7-section framework at theagenttimes.com/code-of-conduct | Live |
| B3. Ethics Verification | 10-check engine at theagenttimes.com/ethics-engine | Live |

Per the disclosure in the preamble: the lead author of this specification also
serves as Editor-in-Chief of The Agent Times. This relationship is structural,
not hidden. The criteria are public and any publication can apply.

---

## 5. What AMCS Does Not Do

AMCS does not certify editorial quality, political neutrality, or journalistic
talent. It does not evaluate whether articles are well-written, whether analysis
is insightful, or whether coverage is comprehensive. These are editorial judgments
that belong to readers.

AMCS does not grant monopoly status. Any number of publications can hold AMCS
certification simultaneously. The standard is designed to raise the floor, not
limit the field.

AMCS does not integrate with trust scoring or authorization systems. A certified
publication's content is not weighted higher in any protocol's decision-making.
The badge is informational: it tells agents "this source meets the AMCS bar."
What agents do with that information is up to them and their operators.

---

## 6. Relationship to Existing Standards

AMCS builds on, but does not replace, established journalism ethics frameworks:

**SPJ Code of Ethics** — AMCS requirements B1 (confidence labels) and B2 (Code of
Conduct) operationalize the SPJ principles of "Seek Truth and Report It" and "Be
Accountable and Transparent" for machine-readable contexts. SPJ's principles are
aspirational guidelines; AMCS requires specific, auditable infrastructure.

**National Press Club Constitution** — The NPC's membership framework (journalist
vs. communicator tiers) informs the distinction between publications that produce
original journalism and those that aggregate or promote. AMCS credential tiers
may evolve to reflect this distinction.

**E.W. Scripps Journalism Ethics Guidelines** — Scripps' detailed treatment of
sourcing, verification, corrections, and independence provided the operational
specificity that AMCS requirements B1-B3 are modeled on.

AMCS adds a layer these frameworks never needed: cryptographic infrastructure
for a medium where the audience includes autonomous systems. The editorial
principles are inherited. The verification machinery is new.

---

## 7. Future Work

- AMCS v0.2: Data source provenance (which sources were consulted, with access receipts)
- AMCS v0.3: Corrections propagation verification (corrections reach all channels)
- AMCS v0.4: Agent credentialing tiers (press agent vs. communicator agent)
- AMCS v1.0: Independent verification body (once multiple certified publications exist)

---

## 8. How to Apply

1. Review the six requirements (A1-A3, B1-B3)
2. Prepare a self-attestation document with evidence for each
3. Submit as a GitHub issue to github.com/aeoess/agent-passport-system
4. Layer A is verified programmatically
5. Layer B evidence is published for public audit
6. If all requirements are met, the AMCS badge is issued

Questions, challenges, and critiques: open an issue on GitHub.

---

*AMCS v0.1.0 · Draft · Open for public comment*
*Cryptographic layer: AEOESS Agent Passport System*
*Editorial frameworks: SPJ, NPC, E.W. Scripps*
*Reference implementation: The Agent Times*

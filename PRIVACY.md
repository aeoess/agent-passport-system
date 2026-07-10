# Privacy

The Agent Passport System SDK is a software library. It collects no personal
data, stores no personal data, holds no user accounts, and emits no
telemetry. There is nothing to opt out of.

Identifiers in protocol artifacts (passports, delegations, receipts) are
decentralized identifiers derived from public keys, supplied by the deployer.
The protocol is designed for data minimization: records carry what is needed
to verify an authorization decision and nothing else, and THREAT_MODEL.md
states what receipts do and do not contain.

Deployers who process personal data in systems built on this protocol act as
the data controllers or processors for their deployments and are responsible
for compliance with the laws that apply to them (for example the GDPR or the
CCPA). The project's own security and disclosure practices are documented in
SECURITY.md, including a secrets policy and coordinated vulnerability
disclosure with stated timeframes.

Questions: open a GitHub issue or use the contact in SECURITY.md.

# Contributing to Agent Passport System

Thanks for your interest in contributing to the Agent Passport System! This project implements an open protocol for AI agent identity, trust, governance, and commerce.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<your-username>/agent-passport-system.git`
3. Install dependencies: `npm install`
4. Run the test suite: `npm test`

## Development

The SDK is organized into 8 protocol layers plus 35 v2 constitutional modules. See `ARCHITECTURE.md` for the full layer-to-file-to-test mapping.

### Running Tests

```bash
npm test
```

All 2,763 tests across 714 suites (1 skipped) must pass before submitting a PR. TypeScript strict mode must compile clean.

### Code Style

- TypeScript throughout
- Ed25519 cryptography via `@noble/ed25519`
- No additional runtime dependencies — keep the dependency footprint minimal

## Submitting Changes

1. Create a feature branch from `main`
2. Make your changes with clear, descriptive commits
3. Ensure all tests pass (`npm test`) and `tsc --noEmit` is clean
4. Open a pull request with a description of what you changed and why

## Reporting Issues

Open an issue on GitHub with:

- A clear title and description
- Steps to reproduce (if applicable)
- Expected vs actual behavior
- Your environment (Node.js version, OS)

## Protocol Contributions

If you're proposing changes to the protocol itself (new layers, modified signature schemes, governance changes), please open a discussion issue first so we can align on the design before implementation.

---

## Quick start checklist

**For a bug fix:**
1. A failing test that reproduces the bug (added in the existing test suite where it logically belongs)
2. The minimal fix that makes the test pass without breaking other tests
3. No scope expansion — fix the bug, don't refactor adjacent code in the same PR

**For a feature addition:**
1. Issue first — get a thumbs-up on direction before sinking work into a PR
2. Tests cover the new behavior at the same density as adjacent code
3. No breaking changes to published API without a major version bump and migration note
4. TypeScript strict mode compiles clean
5. Format consistent with adjacent modules (naming, error handling, test density)

**For documentation:** straight PR is fine. No issue needed first.

## What makes a PR mergeable

1. **Tests pass** — `npm test` green, count stays at or above current level
2. **TypeScript clean** — strict mode, no new `any` in public surface
3. **API stability** — no breaking changes to published exports without a major version bump
4. **Format consistency** — matches existing module layout, naming, error handling
5. **Scope discipline** — PR stays focused on its stated purpose; refactors ride alongside in separate PRs

## Stability expectations

The SDK follows semantic versioning. Changes to public API surface require a major version bump with migration notes. Internal refactors can land in patch releases. Three new primitives shipping per month is normal velocity; each arrives with tests and documentation together.

## Out of scope

- **Breaking changes to published API surface** without major version bump and migration documentation
- **New signature algorithms in core identity primitives** (Ed25519 is load-bearing). Alternative algorithms can ride alongside via extension, not replace
- **Vendored dependencies or large binary artifacts** without specific justification
- **Named integrations woven into core module exports** — integration code belongs in `INTEGRATION.md`, `examples/`, or a sibling adapter repo
- **Disabling tests** without a documented reason

---

## How review works

Every PR is evaluated against five questions, applied to every contributor equally:

1. **Identity.** Is the contributor identifiable, with a real GitHub presence?
2. **Format.** Does the change match existing patterns (module layout, naming, error handling, test density)?
3. **Substance.** Do tests actually exercise the claimed behavior?
4. **Scope.** Does the PR stay scoped to its stated purpose?
5. **Reversibility.** Can the change be reverted cleanly if a downstream issue surfaces?

Substantive declines include the reason. Review comments aim to be concrete and actionable.

---

## Practical details

- **Maintainer:** [@aeoess](https://github.com/aeoess) (Tymofii Pidlisnyi)
- **Review timing:** maintainer-bandwidth dependent. If a PR has had no response after 5 business days, ping it — the notification may have been missed.
- **CLA / DCO:** no CLA is required. Contributions accepted on the understanding that the submitter has the right to contribute under the Apache 2.0 license. Signed-off-by commits are welcome but not required.
- **Publishing:** maintainers handle npm release publishing. Please do not bump version numbers in PRs. If your change requires a version bump, call that out in the PR description so we can sequence the release.
- **Security issues:** open a private security advisory via GitHub rather than a public issue.
- **Code of Conduct:** Contributor Covenant 2.1 — see [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

---

## Licensing

Apache License 2.0 (see [`LICENSE`](./LICENSE)). By contributing, you agree that your contributions will be licensed under the project's existing license.

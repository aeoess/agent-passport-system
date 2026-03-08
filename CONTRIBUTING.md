# Contributing to Agent Passport System

Thanks for your interest in contributing to the Agent Passport System! This project implements an open protocol for AI agent identity, trust, governance, and commerce.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<your-username>/agent-passport-system.git`
3. Install dependencies: `npm install`
4. Run the test suite: `npm test`

## Development

The SDK is organized into 8 protocol layers. See `ARCHITECTURE.md` for the full layer-to-file-to-test mapping.

### Running Tests

```bash
npm test
```

All 196 tests across 51 suites must pass before submitting a PR.

### Code Style

- TypeScript throughout
- Ed25519 cryptography via `@noble/ed25519`
- No additional runtime dependencies — keep the dependency footprint minimal

## Submitting Changes

1. Create a feature branch from `main`
2. Make your changes with clear, descriptive commits
3. Ensure all tests pass (`npm test`)
4. Open a pull request with a description of what you changed and why

## Reporting Issues

Open an issue on GitHub with:

- A clear title and description
- Steps to reproduce (if applicable)
- Expected vs actual behavior
- Your environment (Node.js version, OS)

## Protocol Contributions

If you're proposing changes to the protocol itself (new layers, modified signature schemes, governance changes), please open a discussion issue first so we can align on the design before implementation.

## License

By contributing, you agree that your contributions will be licensed under the project's existing license.

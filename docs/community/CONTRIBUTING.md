# Contributing to Yutha

Thanks for considering a contribution. Yutha is stewarded by a single maintainer right now ([@abhinavg6](https://github.com/abhinavg6)). The guidelines below are intentionally light to match that reality; they'll grow if and when the project does.

## What kind of contribution are you bringing?

| Kind | Where to start |
|------|----------------|
| Bug report | Open an issue. Include version, reproduction, expected vs. actual. |
| Documentation fix | Open a PR. No issue needed. |
| Quickstart or example improvement | Open a PR. Test it on a fresh machine if you can. |
| New feature touching a spec or wire format | File an RFC first. See [RFC 0001](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0001-rfc-process.md). |
| New backend implementation | Read the relevant spec, pass the conformance suite, open a PR under `/backends/`. |
| New SDK adapter for a new framework | Read [`/sdks/python/README.md`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/README.md), follow the existing LangGraph/CrewAI adapter pattern, open a PR. |
| Security disclosure | Do **not** open a public issue. See [SECURITY.md](./SECURITY.md). |

## Before you start

For non-trivial work, it's faster to open a draft issue describing what you want to do and why. Five minutes of "does this direction make sense?" can save a week of writing something that won't land.

For RFC-bearing work, file the RFC before writing the implementation. The discussion often changes the implementation.

## Pull request flow

1. Fork. Branch from `main`. Branch names are unprescribed — call it whatever makes sense.
2. Keep PRs small and focused. One conceptual change per PR. If you find yourself titling it with "and," split it.
3. Run the relevant tests locally. CI runs them too, but local feedback is faster.
4. Open the PR with a description that explains *what* and *why*. The diff explains *how*.
5. Address review comments. Push more commits; we squash on merge.

All PRs require one approval from [@abhinavg6](https://github.com/abhinavg6) before merging. Status checks (fmt, clippy, build, test, conformance, audit, deny, interop) must pass. There is no auto-merge.

## Local development

- Rust toolchain: stable; MSRV is `1.75`.
- A local clone of [`MystenLabs/sui-rust-sdk`](https://github.com/MystenLabs/sui-rust-sdk) sitting as a sibling to this repo. The workspace `Cargo.toml` has path deps at `../sui-rust-sdk/crates/*`; CI clones the same pinned commit. The exact rev is in `.github/workflows/ci.yml` (`SUI_RUST_SDK_REV`).
- For the Python SDK and adapters: `uv sync` under `sdks/python/`.
- Conformance suite: `cargo test -p yutha-conformance`.

## Writing style

Short paragraphs. Concrete examples. No jargon without definition. If a sentence can be cut, cut it. No emojis in code or docs unless explicitly requested.

## License

Yutha is released under the [Apache License 2.0](https://github.com/abhinavg6/yutha/blob/main/LICENSE). Contributions are accepted under the same license. There is no CLA.

## Code of conduct

The [Contributor Covenant](./CODE_OF_CONDUCT.md) applies to every interaction in project spaces.

## A few requests

- Tool-assisted contribution is fine. Spammy AI-generated noise is not. Low-quality PRs will be closed without extensive feedback.
- The project doesn't accept logos, sponsor placements, or other promotional content.
- "Urgent" PRs aren't a thing. The project moves at the pace of one person reviewing carefully.

Welcome.

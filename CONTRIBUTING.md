# Contributing to rustEnrich

The goal is a reproducible enrichment service that other developers can run and extend with their own report providers. AbuseIPDB and VirusTotal are the included demo adapters. Read [SPEC.md](SPEC.md) for behavior and [BEST_PRACTICES.md](BEST_PRACTICES.md) for implementation rules; use [PROVIDERS.md](PROVIDERS.md) when adding an integration.

## Access and local setup

This repository is private. Ask the owner for GitHub access before cloning. A collaborator with write access can push a feature branch and open a pull request; use a private fork only if the repository's fork policy permits it. Do not change repository visibility to contribute.

```sh
gh repo clone alephnan/rustEnrich
cd rustEnrich
git switch -c add-provider-name
cargo build --locked
cargo test --locked
```

Install Rust through rustup and the platform's compiler/linker prerequisites as described in [README.md](README.md#reproduce-from-a-fresh-clone). The repository pins its toolchain and includes `Cargo.lock`. Use `--locked` for builds and tests; update dependency versions only as an intentional, reviewed change. Python 3 runs the documentation and client checks. No provider credentials, running service or live network provider is needed for the test suite.

For a live demo, follow [the startup instructions](README.md#run-locally) using your own eligible accounts. Keep API keys and service tokens in the ignored `secrets/` directory; keep operational inputs, databases and responses in the ignored `data/` directory. Never add these to a commit or PR, even in this private repository. Test fixtures must be synthetic or sanitized.

## Make a focused change

Keep one crate and a thin executable entry point. Make provider mappings explicit and keep HTTP handlers small. Preserve bounded work, fixed provider origins, report provenance, missing-evidence semantics and durable quota reservations before dispatch.

For provider additions, include the adapter, registration, strict configuration, typed public summary, quota migration where required, mock tests and setup instructions together. Update the specification when the contract changes. Describe compatibility effects for clients, persisted cache and existing quota state.

Use Rust unit tests, local mock HTTP servers, controlled clocks and temporary SQLite files. Test observable behavior rather than mirroring field assignments. Keep live checks opt-in and account for their quota consumption; never require real API keys in CI.

## Validate and open a pull request

Run from the repository root (use `py -3` instead of `python3` on Windows):

```sh
cargo build --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo install cargo-audit --version 0.22.2 --locked
cargo audit
python3 tools/check_docs.py
python3 tools/test_smoke_client.py
docker compose config --quiet
docker compose -f compose.yaml -f compose.virustotal.yaml config --quiet
```

The Compose configuration checks require the Compose plugin but do not start the service or consume quota. A container build/run additionally requires Docker and your local secret files. Dependency auditing needs current advisory data; report an unavailable check accurately instead of marking it passed. For documentation-only changes, validate examples, links and configuration consistency. The [GitHub Actions workflow](.github/workflows/ci.yml) repeats the checks for pushes and pull requests.

Review the staged files before pushing. Use an imperative commit subject, such as `Add provider-name report adapter`. Then, with collaborator write access:

```sh
git push -u origin add-provider-name
gh pr create --base main --fill
```

Write the PR title and description for a reviewer who has not seen your development session. Explain the concrete problem, resulting behavior, relevant checks and any remaining limitations. Link related issues and call out API, configuration and storage compatibility changes. Record measured verification separately from expectations in [VERIFICATION.md](VERIFICATION.md).

## License

Contributions to this project are made under its [MIT License](LICENSE). Include that license with redistributed copies. Provider APIs, returned data and third-party dependencies retain their own applicable terms.

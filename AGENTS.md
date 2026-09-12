# Repository Guidelines

## Project Structure & Module Organization

This repository contains one Rust service crate. [SPEC.md](SPEC.md) defines behavior, configuration, and acceptance criteria; [BEST_PRACTICES.md](BEST_PRACTICES.md) defines implementation and review rules. Read both before changing the design.

Keep one Rust crate with a thin binary entry point and testable library modules under `src/`: HTTP, domain, enrichment, providers, storage, and configuration. Put integration tests in `tests/` and sanitized provider fixtures in `tests/fixtures/`.

## Build, Test, and Development Commands

Use the pinned toolchain and committed lockfile:

- `cargo build --locked`: build with recorded dependency versions.
- `cargo run --locked`: run locally with the configuration required by `SPEC.md`.
- `cargo fmt --all -- --check`: verify formatting.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: reject lint warnings.
- `cargo test --locked`: run automated tests.
- `cargo audit`: check dependencies; install a pinned audit tool separately.

For documentation changes, validate JSON examples, links, and consistency with the specification.

## Coding Style & Naming Conventions

Use Rust edition 2024, rustfmt, and four-space indentation. Use `snake_case` for modules/functions, `PascalCase` for types, and `SCREAMING_SNAKE_CASE` for constants.

Keep handlers thin, provider mappings explicit, and errors typed. Prefer ordinary modules and composition over generic frameworks. Avoid panics in request paths and locks or transactions spanning network calls.

## Testing Guidelines

Use Rust unit tests and Tokio async tests, local mock HTTP servers, controlled clocks, and temporary SQLite files. Name tests after observable behavior, such as `coalesces_duplicate_lookups`.

Cover the specification's acceptance criteria, especially partial failures, concurrency bounds, cache persistence, cancellation, and restart-safe quotas. No numerical coverage target is required. Live-provider tests remain opt-in.

## Commit & Pull Request Guidelines

No Git history is available, so no established commit convention can be inferred. Use short imperative subjects, such as `Document provider timeout behavior`.

Keep changes focused. PRs should explain the problem, resulting behavior, validation, and compatibility effects; link related issues when applicable. Update contracts and fixtures alongside behavior changes.

## Security & Configuration

Use documented `ENRICH_` variables and secret-file options. Never commit or log credentials, indicators, or raw reports. Preserve TLS verification, fixed provider origins, bounded work, and durable quota reservations before dispatch.

# rustEnrich engineering practices

This document governs implementation and review of rustEnrich. [SPEC.md](SPEC.md) is the source of truth for externally visible behavior, limits, defaults, and acceptance criteria. Change that contract deliberately when behavior changes; avoid duplicating its configuration tables here.

## 1. Keep the design small and explicit

- Start with one Rust crate and ordinary modules for HTTP handling, indicator validation, orchestration, providers, storage, and configuration. Split crates only when an established ownership, reuse, or compilation need justifies it.
- Use Axum, Tokio, Reqwest, Serde, tracing, and SQLx with SQLite as specified. Prefer their existing facilities over custom routing, executors, HTTP stacks, or database wrappers.
- Keep HTTP handlers thin: authenticate and validate input, call orchestration, and serialize the public response. Keep vendor-specific behavior inside its adapter and persistence details inside storage.
- Introduce an abstraction at an actual boundary, such as the provider interface or a controllable clock for tests. Do not build generic repositories, dependency-injection containers, plugin runtimes, event buses, or configurable REST engines in anticipation of future needs.
- Construct dependencies explicitly at startup and pass shared state through typed application state. Avoid mutable global state and hidden dependency lookups.
- Make each provider a small compiled adapter. Adding a provider should require its configuration, adapter, registration, typed public summary, and tests; it should not require rewriting orchestration.
- Prefer direct composition and straightforward control flow. A few similar lines are preferable to an abstraction that obscures different provider semantics.

## 2. Make contracts and evidence easy to audit

- Separate inbound HTTP types, validated indicator types, vendor response types, storage records, and public response types. Convert at the relevant boundary; do not expose upstream payload structs as the public API.
- Use enums and typed fields for indicators, outcomes, summaries, and errors. Reserve arbitrary JSON for the complete raw provider report and explicitly designated upstream extension data.
- Represent absent evidence as absent or unknown. Never silently replace missing reputation, detection counts, or timestamps with zero or a benign conclusion.
- Preserve provider-specific meanings, units, and timestamps. Document a field's upstream origin when the mapping is not obvious. Do not merge vendor scores into an invented verdict.
- Treat provider text as untrusted data. In an AI workflow, pass it as evidence with its source, and ensure it cannot introduce instructions or override the workflow's trusted prompt.
- Use typed errors internally, and map them to stable, safe public codes at a single boundary. Keep internal causes available only in sanitized diagnostics.
- Avoid `unwrap`, `expect`, `panic!`, unchecked indexing, and silently ignored results in request processing. Tests may use explicit assertions. A startup failure should return a clear configuration or storage error rather than panic.
- Validate the complete request before dispatching any provider lookup. Do not mix parsing, normalization, authorization, and upstream I/O in the same function.
- Explain non-obvious decisions in comments: quota reservation timing, cancellation ownership, URL identity preservation, and retry restrictions are worth explaining. Do not narrate self-evident code.

## 3. Bound asynchronous work and define ownership

- Reuse HTTP clients and connection pools. Keep admission, global outbound concurrency, provider concurrency, and waiting work bounded by the contract in `SPEC.md`.
- Give each network attempt and shared lookup a finite lifetime. Propagate remaining deadlines; a retry must not reset the overall deadline.
- Do not spawn detached work without an owner, a bound, and a shutdown path. Track shared lookups so their completion removes the corresponding in-flight entry on success, error, timeout, or cancellation.
- A shared lookup belongs to the orchestration layer, not its first caller. Dropping one subscriber must not cancel work still needed by another; the shared lookup must still have a finite deadline.
- Never hold an application mutex, semaphore-protected storage critical section, or database transaction across a network operation. Hold outbound attempt permits for the short final quota reservation and ensuing network attempt, as specified; release them before retry delays or cache writes.
- Do not block Tokio workers with synchronous disk I/O, long CPU work, or sleeps. Use SQLx's SQLite interface for database work and narrowly scoped blocking work only where necessary.
- Enforce body and serialization limits while consuming or producing data, rather than after unbounded accumulation. Include raw JSON copies and duplicate response entries in memory and output budgeting.
- Retry only the failures allowed by the specification, and only while budget and quota remain. Do not retry authentication errors, invalid input, missing reports, or arbitrary status codes.
- Keep shutdown explicit: stop admission, track remaining requests and lookups, drain within the configured bound, then cancel and clean up.

## 4. Keep cache and quota behavior consistent

- Use the single shared SQLite connection through SQLx's worker-backed interface. Keep transactions short and explicit. Do not add an external database, queue, or repository framework for this deployment shape.
- Reserve and persist quota before every outbound attempt, including retries. Dispatch only after the reservation commits. A failed reservation or unknown commit outcome must not fall back to an unmetered request.
- Treat reservations conservatively when a process exits or a request is cancelled after reservation. An unused reservation may reduce availability; it must not be refunded on an unproven assumption that no request was sent.
- Persist cooldowns and retain local quota accounting across restarts. Account separately for service-local bookkeeping and the provider's authoritative enforcement, particularly when credentials are shared elsewhere.
- Centralize cache-key construction. Include every lookup-affecting option and adapter payload version. Keep `include_raw` out of lookup identity so changing response presentation cannot generate another provider call.
- Cache only the outcomes permitted by the specification. Never turn an expired entry into an implicit stale fallback or interpret an uncached failure as a not-found report.
- Retain raw reports with their typed summaries. Evict entries consistently with the documented count and payload limits; database file size includes overhead beyond cached payloads.
- A cache-write failure must not discard a report already fetched successfully. Storage errors affecting quota enforcement must prevent new network dispatch. Distinguish those paths visibly in typed errors and sanitized logs.
- Make schema changes explicit and versioned. Keep transactions and migrations understandable, and test an upgrade from the previous supported schema when introducing a migration.

## 5. Protect credentials and indicator data

- Validate configuration once at startup. Enable providers explicitly, require credentials for each enabled provider, and reject inconsistent bounds or unusable storage.
- Support the documented secret injection mechanism. Never commit credentials, place them in request examples, bake them into container images, or include them in `Debug` output.
- Enforce bearer authentication for enrichment requests. Keep any public health responses limited to the operational information defined by the specification.
- Send requests only to the compiled provider origins and documented lookup paths. Disable redirects and retain TLS certificate verification. Test endpoints must be supplied through test-only construction, not through caller-controlled URLs.
- Never fetch or resolve an indicator URL. Encode indicator values as the adapter requires; never interpolate an indicator into an outbound origin or concatenate unescaped path segments.
- Keep API keys, bearer tokens, indicator values, raw reports, and upstream request URLs out of logs and metric labels. Third-party errors may contain URLs or response bodies; sanitize them before logging.
- Emit structured events with server-generated request IDs, provider identity, outcome, latency, cache behavior, quota events, and safe error codes. Avoid high-cardinality metric labels such as request IDs.
- Restrict access to the persistent volume: cached URLs and reports can contain sensitive operational data. Do not assume that omitting raw JSON from an API response means it is absent from storage.

## 6. Test behavior, not implementation trivia

- Derive tests from the acceptance criteria in `SPEC.md`. Cover observable contracts, provider mapping, bounded work, persistence, cancellation, and failure handling; do not enforce arbitrary line-count or coverage quotas.
- Use redacted, representative provider fixtures and local mock HTTP servers. Include missing optional fields, additional upstream fields, malformed responses, authentication failures, not-found results, quota responses, and oversized bodies.
- Use controlled clocks for TTLs, retries, quotas, and deadlines. Use barriers or explicit events for concurrency tests rather than relying on wall-clock sleeps and lucky scheduling.
- Test that invalid batches cause no provider calls, duplicate misses share work, one caller's cancellation does not disrupt another, and all permit and in-flight entries are eventually released.
- Use temporary on-disk databases for restart, expiry, eviction, quota, and migration tests. An in-memory database alone cannot verify persistence or startup failure behavior.
- Exercise partial-result handling with an n8n-shaped request and verify stable JSON fields, input order, duplicate entries, and raw-report omission metadata.
- Keep live-provider checks opt-in, outside the default test suite. Require explicit credentials and account for their quota use; ordinary development and CI must work without provider secrets.
- Add regression tests for meaningful bugs at the narrowest useful level. Avoid tests that merely repeat field assignments or lock in private implementation details.

## 7. Keep changes and dependencies reviewable

- Pin a supported stable Rust toolchain when implementation begins, commit `Cargo.lock`, and use reproducible locked dependency resolution. Re-evaluate the toolchain during deliberate maintenance changes.
- Enable only dependency features actually needed. Explain why each new dependency is preferable to existing facilities or a small amount of direct code.
- Keep pull requests focused on one coherent behavior change. Avoid unrelated formatting, renaming, and architectural cleanup in a functional change.
- Update public contracts, configuration documentation, fixtures, and acceptance tests together when behavior changes. Call out compatibility effects explicitly.
- Describe the concrete problem, resulting behavior, validation performed, and any remaining limitation in the review description. Document significant architectural departures with their reason and tradeoff; do not create a ceremony for routine choices.
- Avoid new `unsafe` code unless a demonstrated requirement cannot be met with safe Rust. Any exception needs a documented invariant and focused review.
- Run these checks once the Rust application exists, and make them the CI baseline:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo audit
```

`cargo audit` requires a separately installed, pinned tool and current advisory data. A failed or unavailable audit is not a passing result. Investigate findings; any accepted exception must record the advisory, exposure assessment, owner, reason, and review date. Do not silence lints or advisories globally to make checks pass.

For documentation-only changes, check examples, links, terminology, configuration consistency, and requirement-to-test traceability. Do not claim that build or application tests ran before application code exists.

## Review checklist

- [ ] The change has a clear purpose and follows `SPEC.md`, or explicitly updates the contract.
- [ ] Responsibilities stay in the correct modules; any new abstraction or dependency has a concrete reason.
- [ ] Public fields and errors are typed and stable; missing evidence remains unknown.
- [ ] All work, bodies, retries, deadlines, and serialization remain bounded.
- [ ] Locks, transactions, shared lookups, cancellation, and shutdown have clear ownership and cleanup.
- [ ] Quota is committed before dispatch; cache and storage failures cannot bypass enforcement.
- [ ] Provider requests stay on approved origins; secrets and indicator data cannot enter logs.
- [ ] Tests cover the changed behavior and relevant failure cases without live-provider dependencies.
- [ ] Documentation and fixtures match the behavior; required checks passed or limitations are stated accurately.

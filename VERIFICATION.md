# Implementation verification

Recorded on 2026-09-12 with Rust 1.98.1 on x86_64 Arch Linux under WSL2. Tests use loopback provider servers, synthetic fixtures and temporary SQLite databases. No live provider requests were made.

## Checks

| Check | Result |
| --- | --- |
| `cargo build --locked` | Passed |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed |
| `cargo test --locked` | 95 tests passed; no ignored tests |
| `cargo audit` using pinned cargo-audit 0.22.2 | Passed; 229 dependencies checked against 1,243 RustSec advisories |
| `docker compose config --quiet` (base and VirusTotal overlay) | Passed for both configurations |
| Markdown examples, local links and provider fixtures | Passed: 8 JSON examples, 56 local file links, 4 fixtures |
| `python3 tools/test_smoke_client.py` | 9 tests passed without live provider calls |
| Docker image build/run | Not performed: the local Docker daemon is stopped |

The lockfile is included. CI repeats the Rust checks and audit without credentials. Future advisory results may change as the advisory database changes.

The build, formatting, Clippy, 95 Rust tests and pinned dependency audit were rerun when preparing the private GitHub repository on 2026-09-12. Setup, contribution and provider-extension documentation were checked against the implementation. Both Compose configurations were validated; the optional VirusTotal overlay preserves the base deployment's private network and persistent volume. The initial tracked-file review excluded local credentials, `.env`, runtime data and build output, and found no matches for local secret values or common private-key/token patterns in the text files selected for upload. This review is not a general security audit.

## Load and concurrency

[validation/load.json](validation/load.json) records the measured 32 simultaneous requests, each containing 20 IP indicators and selecting both providers with default concurrency and quota limits. The measurement runs the service and mock providers together in an isolated debug test process on a 16-logical-CPU host. It includes harness setup and cleanup in process elapsed time. The test separately reports the enrichment interval, provider calls and simultaneous-call maxima.

The recorded run completed enrichment in 438 ms (524 ms including the test harness) with 22,528 KiB peak resident memory (22 MiB). It made 20 AbuseIPDB calls and four VirusTotal calls. Its fast mock responses reached one simultaneous call; the separately gated test below proves actual overlap at the configured limit.

Reproduce on Linux or WSL with:

```sh
python3 tools/measure_load.py
```

The load assertions verify all 640 input results, both provider slots per input, no more than 20 AbuseIPDB calls and four VirusTotal calls, outbound/provider bounds, and release of all 32 admission permits. The identical batches intentionally exercise reuse and default quota exhaustion.

A separate gated concurrency test holds real mock HTTP requests open and observes exactly three overlapping attempts with a configured global bound of three and provider bounds of two. It verifies all 16 reports complete without exceeding those bounds. Slow-response and shutdown tests use the production connection server, including an approximately 8 MiB response to a client that initially reads no bytes.

These are host-specific test measurements, not a production throughput or memory guarantee.

## Acceptance coverage

| SPEC IDs | Automated coverage |
| --- | --- |
| A01–A02 | Strict JSON and duplicate-key parsing; ordered details; all indicator types and hash algorithms; URL identity; limits; provider selection; disabled precedence; invalid batches make no provider calls |
| A03 | Authentication before parsing; exact token bytes including UTF-8; service errors and headers; real TCP body timeout; readiness, admission and response limits |
| A04 | Sanitized fixtures for both adapters and all supported kinds; missing versus zero evidence; signed reputation; hash and URL identity; encoded fixed endpoints; complete raw reports |
| A05–A06 | Partial results across provider statuses; TLS rejection; malformed, truncated, oversized and compressed bodies; forged/missing length headers; redirects; redacted upstream errors |
| A07–A08 | Gated HTTP overlap; provider/global/shared/admission limits; independent caller deadlines; retry quota; Retry-After; no timeout/auth/TLS/429 retry; bounded slow response writing |
| A09–A10 | SQLite reopen persistence; all TTL categories and expiry equality; TTL reduction/zero; FIFO count/byte eviction and startup capacity reduction; provider/options/version/algorithm/URL cache identity; raw reuse |
| A11 | Concurrent duplicate reuse; abandoned caller and subsequent subscriber; work retained after callers leave; shared capacity recovery; bounded shutdown cleanup |
| A12–A13 | Concurrent durable reservations; rolling-minute and UTC-day boundaries; restarts; rollback high-water marks; conservative out-of-order remaining headers; unknown resets; retained feedback after failed persistence |
| A14 | Ownership conflicts, corrupt/foreign/newer schemas and missing quota history; bounded write-lock failures; readiness recovery; successful report retained after cache-write failure; no late dispatch after failed quota reservation |
| A15 | Nullable public fields; complete or omitted raw reports; deterministic raw budget, including duplicate slots and smaller later reports; summary and envelope caps; valid complete JSON |
| A16 | Fixed production origins; no redirects; local health checks consume no quota; redacted credentials and errors; separate probe admission; shutdown and slow-client connection cleanup |
| A17 | n8n-shaped request through the production HTTP server preserves partial evidence and retry metadata; bounded pair-level retry/merge guidance is documented in README |
| A18 | Pinned toolchain and auditor, lockfile, build/format/lint/test/audit, configuration documentation and deployment files |

Domain/provider/storage tests live beside their modules. HTTP, output and transport tests live under [tests](tests) and are included only in library test builds. This lets them inject loopback origins without exposing a production endpoint override or a public test feature.

## Verification limits and implementation decisions

- Process interruption at the exact SQLite COMMIT boundary, disk-full/fsync failures and a forcibly panicking shared owner have not been fault-injected. Reservation cancellation, storage locks, persistence/reopen and shutdown are tested; unknown commit outcomes fail closed and are never refunded.
- The cache registration race has an owner-side cache recheck and atomic in-flight registration/publication. Simultaneous requests exercise reuse, but the exact pre-registration timing has not been forced by a dedicated test hook.
- There is only the initial schema, so no migration from an earlier released application schema exists. Startup rejects unknown newer schemas and does not recreate missing quota history.
- The n8n application itself and real provider accounts were not used. Operators must supply eligible provider credentials before deployment. Windows-native compilation and a Docker image build remain unverified on this host.
- Production uses HTTP/1.1 with one request per connection. The connection owns admission through response flush or disconnect and can be closed at the write deadline even when its response body is not being polled. Hyper supplies this transport beneath Axum routing; upstream Reqwest clients still reuse their pools.
- The first AbuseIPDB remaining-quota observation leaves conservative headroom for other active attempts. This can underuse a few requests near provider exhaustion; it never restores consumed quota.
- The OS lock resolves the database path and prevents a second owner through that canonical path. Operators must still provide local storage; arbitrary mount types cannot be reliably classified by the application.

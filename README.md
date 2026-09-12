# rustEnrich

A self-hosted Rust HTTP service for enriching IP addresses, exact HTTP(S) URL strings, and MD5/SHA-1/SHA-256 hashes with existing threat-intelligence reports. Results retain each provider's evidence, provenance, and independent outcome, with persistent caching, quota accounting, and bounded concurrent lookups. The service does not scan, submit files or URLs, resolve indicator hosts, or calculate an aggregate verdict.

AbuseIPDB and VirusTotal are the included demo adapters because their free API quotas make small, eligible experiments accessible. The project is intended to be extended with your own compiled Rust provider adapters; see [Adding a provider](PROVIDERS.md) and [Contributing](CONTRIBUTING.md). No provider account or API key is needed to build or run the automated tests.

| Included provider | IP | URL | File hash | Local demo quota defaults |
| --- | --- | --- | --- | --- |
| AbuseIPDB | IPv4 / IPv6 | No | No | 1,000 attempts per UTC day |
| VirusTotal | IPv4 / IPv6 | HTTP(S) | MD5 / SHA-1 / SHA-256 | 4 attempts per rolling minute; 500 per UTC day |

These are configurable local budgets. Check your account's entitlement and permitted use before making live calls: [AbuseIPDB limits](https://docs.abuseipdb.com/#api-daily-rate-limits), [VirusTotal Public/Premium API](https://docs.virustotal.com/reference/public-vs-premium-api). VirusTotal's Public API excludes commercial products/services and business workflows that do not contribute new files. Use an eligible plan for those deployments.

[SPEC.md](SPEC.md) defines the API, configuration, and acceptance requirements. [BEST_PRACTICES.md](BEST_PRACTICES.md) defines implementation and review rules.

## Reproduce from a fresh clone

The repository is private. The owner must grant your GitHub account access before you can clone it or contribute. Once access is granted:

```sh
gh repo clone alephnan/rustEnrich
cd rustEnrich
```

Choose either a native build using [rustup](https://rustup.rs/) and a platform C compiler/linker, or Docker with the Compose plugin. Linux/WSL is the recorded Rust validation environment; native Windows builds need the Microsoft C++ build tools. Python 3 runs the documentation/client checks; Bash and curl are needed only for the optional indicator-file client. Keep [Cargo.lock](Cargo.lock) and the pinned [Rust toolchain](rust-toolchain.toml) unchanged for a repeatable dependency build.

For a credential-free first check, run `cargo build --locked` and `cargo test --locked`. The tests supply their own mock credentials, loopback providers and temporary databases. To run the actual service, prepare your own secrets and follow either the local or Docker steps below; the repository contains no working credentials or cached reports.

## Run locally

Install the pinned Rust toolchain through rustup. Create a local `secrets` directory and place an operator-generated service token of at least 32 bytes in `secrets/service_token` and your AbuseIPDB key in `secrets/abuseipdb_api_key`. Restrict access to those files. These files and the data directory are ignored by Git; credentials are never needed for builds or tests.

You can generate the service token without printing it using this Python 3 command (`py -3` instead of `python3` on Windows). It creates the file exclusively and fails if a token already exists:

```sh
python3 -c "import os,secrets; os.makedirs('secrets', mode=0o700, exist_ok=True); fd=os.open('secrets/service_token', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600); f=os.fdopen(fd,'w',encoding='utf-8'); f.write(secrets.token_hex(32)); f.close()"
```

Obtain your own key from the [AbuseIPDB account dashboard](https://www.abuseipdb.com/account/api). Save only the key as UTF-8 without a byte-order mark in `secrets/abuseipdb_api_key`. For VirusTotal, follow its [getting started guide](https://docs.virustotal.com/reference/getting-started) and save the key in `secrets/virustotal_api_key`. On Windows, restrict these files through their NTFS permissions; the POSIX mode arguments above do not configure Windows ACLs.

PowerShell:

```powershell
$env:ENRICH_SERVICE_TOKEN_FILE = "$PWD/secrets/service_token"
$env:ENRICH_ABUSEIPDB_ENABLED = 'true'
$env:ENRICH_ABUSEIPDB_API_KEY_FILE = "$PWD/secrets/abuseipdb_api_key"
cargo run --locked
```

POSIX shell:

```sh
ENRICH_SERVICE_TOKEN_FILE=./secrets/service_token \
ENRICH_ABUSEIPDB_ENABLED=true \
ENRICH_ABUSEIPDB_API_KEY_FILE=./secrets/abuseipdb_api_key \
cargo run --locked
```

The default listener is `127.0.0.1:8080`; persistent state defaults to `./data/rustenrich.sqlite`. Startup validates settings, acquires the exclusive process lock, applies embedded migrations, and reconciles cache limits before serving. No provider call is used to validate credentials at startup. At least one provider must be explicitly enabled.

To enable VirusTotal, set `ENRICH_VIRUSTOTAL_ENABLED=true` and `ENRICH_VIRUSTOTAL_API_KEY_FILE` to a readable key file. The free-tier local defaults are 4 attempts per rolling minute and 500 per UTC day; AbuseIPDB defaults to 1,000 per UTC day. Configure quotas for the account's actual entitlement. VirusTotal public API restrictions apply to commercial and report-only business use; use an eligible account for production as described in the specification.

For example, add these settings before the local `cargo run --locked` command to enable VirusTotal alongside AbuseIPDB:

```powershell
$env:ENRICH_VIRUSTOTAL_ENABLED = 'true'
$env:ENRICH_VIRUSTOTAL_API_KEY_FILE = "$PWD/secrets/virustotal_api_key"
$env:ENRICH_VIRUSTOTAL_REQUESTS_PER_MINUTE = '4'
$env:ENRICH_VIRUSTOTAL_REQUESTS_PER_DAY = '500'
```

```sh
export ENRICH_VIRUSTOTAL_ENABLED=true
export ENRICH_VIRUSTOTAL_API_KEY_FILE=./secrets/virustotal_api_key
export ENRICH_VIRUSTOTAL_REQUESTS_PER_MINUTE=4
export ENRICH_VIRUSTOTAL_REQUESTS_PER_DAY=500
```

To use VirusTotal alone locally, leave AbuseIPDB disabled and unset its key settings. To verify startup without using quota, run `curl http://127.0.0.1:8080/health/ready` (`curl.exe` in Windows PowerShell); expect HTTP 200 with `status: ready`. Then use the opt-in indicator-file client below for a live report.

All configuration is read once from `ENRICH_` environment variables. See [the complete settings and bounds](SPEC.md#6-configuration-and-deployment). `.env.example` contains non-secret Docker Compose overrides; the application itself does not load dotenv files. Unknown `ENRICH_` names, invalid values, conflicting secret sources, missing enabled-provider keys, and inconsistent limits fail startup. Unrelated environment variables are ignored.

Each secret accepts either the value variable or its matching `_FILE` variable, never both. Secret files must be UTF-8; one final line ending is removed, and remaining line breaks or invalid HTTP header values are rejected. Environment values are not trimmed. Restart to rotate keys; quota history is retained.

## Test an indicator file from Bash / WSL

With the service running, use [tools/test_indicators.sh](tools/test_indicators.sh) to submit a UTF-8 text file. Each non-comment line is a type (`ip`, `url`, or `hash`), followed by spaces or a tab, then the exact indicator value. Blank lines, `#` comment lines, Windows CRLF endings and a leading UTF-8 BOM are supported. Inline comments and whitespace inside values are not supported. The client preserves URL spelling and duplicate entries.

```text
ip 8.8.8.8
ip 2606:4700:4700::1111
url https://example.com/
hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The Bash command uses Python 3 (standard library only) for file/JSON handling and `curl` for HTTP. If needed, install them with `sudo pacman -S --needed python curl` on Arch, then run from the repository:

```bash
# Check the sample format without reading credentials or contacting the service.
bash tools/test_indicators.sh examples/indicators.txt --dry-run

# Live test: uses secrets/service_token and all enabled providers.
bash tools/test_indicators.sh examples/indicators.txt

# Keep your own indicator file in the Git-ignored data directory.
mkdir -p data
cp examples/indicators.txt data/indicators.txt
# Edit data/indicators.txt before running:
bash tools/test_indicators.sh data/indicators.txt --providers abuseipdb,virustotal
```

The script reads only the service token; provider keys remain configured in the running service. It sends one indicator per request and waits 31 seconds after each response before sending the next. This leaves room for one service retry under the default VirusTotal rolling-minute cap, but shared account usage, lower limits and daily exhaustion can still cause rate limiting. Each uncached supported indicator/provider pair can use one upstream attempt, or two with a service retry. Cache hits, disabled selections and unsupported pairs consume none. The API does not expose actual upstream attempt counts; consult provider dashboards for exact consumption. The sample includes a duplicate IP to exercise caching.

Responses are saved in a new `data/test-results/run-*` directory, with `index.tsv` mapping each numbered JSON file to the input line and service HTTP status. Terminal output shows status, cache hits and safe error codes without printing indicators, reports or tokens. Responses are local artifacts and can contain sensitive data; the output directory is Git-ignored. The script requests private file permissions, subject to the WSL mount's Windows ACL behavior.

The client makes no retries. It preserves partial successes and stops on transport failures, non-200 HTTP responses, unexpected response formats, or provider outcomes `disabled`, `rate_limited`, `timeout` or `error`. `not_found` and `unsupported` are valid outcomes and do not stop the run. Exit codes are 0 for completion/dry run, 1 for request/provider failure and 2 for setup/input errors. Full-file format and hash checks run before sending anything; the service validates IP and URL syntax separately for each submitted entry, so an invalid later entry can follow earlier completed lookups.

Use `--raw` to retain available raw reports, `--token-file` for another service token file, `--base-url` for another service origin, and `--output-dir` for a different parent output directory. `--delay 0` is useful with mock providers or cached results; the default delay is intended for small live checks. Inputs are limited to 1,000 entries, 1 MiB per file and 4,096 bytes per value. `--help` lists all options. For client regression checks without live quota, run `python3 tools/test_smoke_client.py`.

## Docker and n8n

The supplied Compose deployment enables AbuseIPDB, runs as UID/GID 10001, keeps the root filesystem read-only, stores SQLite in a named local volume, and mounts secrets read-only. It publishes no host port. The Docker bridge network `rustenrich_private` allows provider egress while keeping the service off the host's published ports.

After creating the two secret files described above, optionally copy [.env.example](.env.example) to `.env` and adjust the non-secret overrides, then run:

```sh
docker compose up --build --detach
docker compose logs --follow rustenrich
```

The secret files must be readable by the container's UID 10001. On Linux, restrict the parent directory to the operator and arrange file ownership/group permissions for that UID; Compose file-backed secrets inherit the source file's permissions. Do not make a secrets directory publicly accessible merely to fix permissions. The image creates `/data` with owner 10001 and mode 0700; a replacement bind mount must have compatible ownership. Preserve the directory's database, WAL, and shared-memory files together. Use one service process and local storage only.

For a separate n8n Compose project, attach its n8n service to this existing network:

```yaml
services:
  n8n:
    networks:
      - default
      - enrichment
networks:
  enrichment:
    external: true
    name: rustenrich_private
```

To add VirusTotal, create `secrets/virustotal_api_key` with the same permissions and include the supplied [VirusTotal overlay](compose.virustotal.yaml):

```sh
docker compose -f compose.yaml -f compose.virustotal.yaml config --quiet
docker compose -f compose.yaml -f compose.virustotal.yaml up --build --detach
docker compose -f compose.yaml -f compose.virustotal.yaml exec rustenrich curl --fail --silent http://127.0.0.1:8080/health/ready
```

Use the same two `-f` arguments for subsequent Compose operations on this deployment. The overlay adds VirusTotal's key mount and configurable quotas while preserving AbuseIPDB, the persistent volume and private network. Setting a variable in `.env` only reaches the container if a Compose file forwards it; add other [documented settings](SPEC.md#6-configuration-and-deployment) to the service's `environment` when needed. The base Compose deployment always mounts the AbuseIPDB key file, even if that provider is disabled.

Configure an n8n HTTP Request node:

1. POST to `http://rustenrich:8080/v1/enrich`.
2. Store `Authorization: Bearer <service-token>` in a Generic Header Auth credential.
3. Send JSON, use response format JSON, enable **Include Response Headers and Status** and **Never Error**.
4. Set timeout to 25,000 ms and disable automatic retries and pagination.
5. Submit at most 20 indicators, for example:

```json
{
  "indicators": [
    {"type": "ip", "value": "8.8.8.8"},
    {"type": "url", "value": "https://example.com/"}
  ],
  "providers": ["abuseipdb", "virustotal"],
  "include_raw": false
}
```

With the default Compose configuration, explicit VirusTotal selections return `disabled`; omitting `providers` selects enabled providers. Private indicators and URL query strings are disclosed to selected provider APIs. Filter them before submission when they must remain internal.

HTTP 200 can contain provider failures. Iterate `body.results[].providers[]`, preserve successful evidence, and branch on each `status`. For a retryable failed pair, use a Wait step and its known `error.retry_after_seconds`, with at most two workflow retries; if the delay is unknown, wait 60 seconds then 120 seconds. Retry only the failed indicator/provider pair and merge it using the original index and provider ID. For service 503, use `Retry-After` within the same retry budget. Route authentication and validation errors to workflow error handling.

Missing evidence remains unknown. In AI triage, retain the source and timestamps and pass provider text as untrusted evidence separate from trusted instructions. See [the full request and response examples](SPEC.md#2-http-interface).

## Operations

`GET /health/live` and `GET /health/ready` return minimal JSON with a generated request ID without authentication on the private network. Readiness checks local writable storage without provider calls or quota consumption. Depleted quotas and provider outages do not make healthy local storage unready. These probes have separate bounded admission.

Use a TLS-terminating proxy whenever traffic crosses the private network boundary. Keep upstream TLS verification enabled. The provided container has a readiness health check and a 25-second stop grace period, longer than the default 20-second application drain. If the drain setting increases, increase the container stop grace as well.

Structured JSON logs go to stdout. They contain safe operational metadata and omit indicators, request/response bodies, provider URLs, secrets, and cache digests. Protect the persistent volume and backups: raw cached reports may contain sensitive indicators. Cache limits bound logical payload size, while database overhead and WAL require additional disk space. Never run multiple replicas against the same volume.

AbuseIPDB remaining-quota feedback is reconciled conservatively with requests already reserved concurrently. The first observed upstream remainder can be reduced by up to the provider concurrency limit minus one; this may leave a few requests unused near exhaustion, especially when other applications share the key.

Back up and restore SQLite consistently using an operator-managed SQLite backup or a stopped service. Retain quota tables. An old snapshot or a recreated volume may undercount usage; withhold fresh calls until the affected provider quota windows reset. Cache expiry does not guarantee physical data erasure.

## Development and verification

The crate uses Rust edition 2024 and the stable version pinned in [rust-toolchain.toml](rust-toolchain.toml). It keeps HTTP, domain, enrichment, adapters, storage, and configuration in separate library modules with a thin executable entry point. Embedded migrations live in [migrations](migrations).

```sh
cargo build --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo install cargo-audit --version 0.22.2 --locked
cargo audit
python3 tools/check_docs.py
python3 tools/test_smoke_client.py
```

Default tests use local mock providers, synthetic fixtures, and temporary SQLite databases. No default test consumes live provider quota or fetches an indicator host. CI runs the commands above; an unavailable dependency audit is a failed or unverified check, not a pass. The Docker image can be checked separately with `docker compose build` after dependencies and Docker are available.

The [acceptance table](SPEC.md#8-acceptance-tests-and-completion-criteria) is the review checklist. Configuration tests cover strict parsing, enabled-provider credentials, timeout/capacity constraints, redacted secret failures, and secret-file handling. Domain/provider, HTTP/enrichment, and storage tests cover their contracts alongside the implementing modules. Test presence does not imply that every acceptance scenario has been verified on every deployment host; retain actual check output and record any environment-dependent limitations when reviewing a change.

See [VERIFICATION.md](VERIFICATION.md) for the recorded checks, measured load, acceptance coverage and remaining verification limits. Linux/WSL users can reproduce the load measurement with `python3 tools/measure_load.py`.

The specification selects Axum, Tokio, Reqwest, Serde, tracing and SQLx. Hyper and its body/runtime helpers let the service enforce deadlines through the actual socket write; Tokio utilities track owned work and cancellation. SHA-256 provides cache identities and fixed-size token comparison inputs, `subtle` performs the constant-time comparison, and `fs2` provides OS-held ownership locks. URL/base64, UUID, Chrono and HTTP-date libraries implement the specified encodings and timestamp contracts. Test-only dependencies provide temporary databases, direct router calls and compressed mock responses.

## Extend and contribute

[PROVIDERS.md](PROVIDERS.md) walks through provider registration, strict configuration, typed response mapping, cache versions, restart-safe quota migrations and mock tests using the current implementation. [CONTRIBUTING.md](CONTRIBUTING.md) explains the branch/PR workflow and required checks. New providers require a rebuild; environment variables configure adapters already compiled into the service.

## License

This project's code and documentation are available under the [MIT License](LICENSE), copyright 2026 AlephNaN. Provider API access and returned data remain subject to their respective terms; the software license does not grant provider accounts, quota or data rights.

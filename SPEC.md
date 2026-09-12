# rustEnrich service specification

Status: v1 implementation contract. The Rust service, deployment files, and automated tests are included in this repository; see [README.md](README.md) for startup and verification.
Version: 1.0. Provider documentation checked: 2026-09-12.

This file defines observable behavior and operating defaults. [BEST_PRACTICES.md](BEST_PRACTICES.md) defines implementation and review expectations. MUST denotes an acceptance requirement; defaults can change through the configuration described below.

## 1. Purpose and boundaries

rustEnrich is a private Rust HTTP service that retrieves existing IP, URL, and file-hash intelligence from REST providers and returns JSON to automation clients such as n8n. It MUST accept concurrent requests, reuse repeated lookups, preserve evidence provenance, and return useful results when individual providers fail.

The first deployment is one service process in one Docker container with a local persistent SQLite volume. It is a single-tenant service using operator-managed provider credentials.

| Provider ID | IP | URL | Hash | Initial operation |
| --- | --- | --- | --- | --- |
| `abuseipdb` | IPv4 and IPv6 | Unsupported | Unsupported | Existing CHECK report |
| `virustotal` | IPv4 and IPv6 | HTTP(S) | MD5, SHA-1, SHA-256 | Existing v3 report |

AbuseIPDB and VirusTotal are the demo adapters, selected for their free API quotas for eligible use. Additional providers are compiled Rust adapters; [PROVIDERS.md](PROVIDERS.md) documents the required code, configuration, quota migration and test changes. Implementing another provider is outside v1.

Out of scope: active scans, URL submission, file upload/download, abuse reporting, browsing indicator URLs, DNS enrichment, domain-only indicators, relationship expansion, pagination, AI inference, combined risk scores, automated blocking, asynchronous jobs, webhooks, a UI, multi-tenancy, multiple replicas, and a configuration-driven REST integration engine. A provider's domain or hostname evidence may still appear in its report.

## 2. HTTP interface

### 2.1 Transport and authentication

- Serve JSON over HTTP on a private network. Use a TLS-terminating reverse proxy when traffic crosses that network boundary. Never disable TLS verification for upstream providers.
- `POST /v1/enrich` requires `Authorization: Bearer <service-token>` and `Content-Type: application/json`, optionally with a UTF-8 charset.
- Use one operator-configured service token, distinct from provider keys. Compare it using a constant-time comparison. Do not accept credentials in query parameters or request bodies.
- Generate a UUID v4 request ID for every response. Return it in `X-Request-ID` and `request_id`. Do not trust an incoming ID as the server ID.
- Return `Content-Type: application/json` and `Cache-Control: no-store`, including for errors. This HTTP cache directive does not disable the internal report cache.
- Accept uncompressed request bodies only; reject non-identity `Content-Encoding`. Authentication precedes request-body parsing and provider work.

### 2.2 Enrichment request

~~~json
{
  "indicators": [
    {"type": "ip", "value": "8.8.8.8"},
    {"type": "url", "value": "https://example.com/"}
  ],
  "providers": ["abuseipdb", "virustotal"],
  "include_raw": false
}
~~~

| Field | Type | Required/default | Contract |
| --- | --- | --- | --- |
| `indicators` | Array of objects | Required | Between 1 and configured maximum, default 20 |
| `indicators[].type` | String | Required | Exactly `ip`, `url`, or `hash` |
| `indicators[].value` | String | Required | Nonempty; at most 4,096 UTF-8 bytes |
| `providers` | Array of strings | All enabled providers | If present, nonempty; known IDs only; duplicates rejected |
| `include_raw` | Boolean | `false` | Return available raw reports within the response budget |

Reject unknown request fields, nulls in place of these fields, type mismatches, and duplicate JSON object keys. Do not silently coerce strings, trim inputs, infer indicator types, or accept a scalar as a batch.

Validate the complete request before reading reports or consuming quota. Report semantic validation failures with an ordered list of JSON Pointer paths, without echoing values. A mixed valid/invalid batch fails as a whole. A valid duplicate indicator remains a separate result in the original position but shares provider work.

When `providers` is omitted, select enabled providers in lexicographic ID order, including providers that do not support a particular indicator type. When explicitly listed, preserve that order in the result array. A known disabled provider is allowed in an explicit list and returns `disabled`; an unknown ID rejects the request. For a disabled and incompatible provider, `disabled` takes precedence over `unsupported`. Neither condition reads cache or contacts the provider.

### 2.3 Indicator validation and identity

| Type | Accepted | Lookup value |
| --- | --- | --- |
| `ip` | One unambiguous IPv4 or IPv6 address parsed by Rust's IP parser | Standard textual IP formatting |
| `url` | Absolute HTTP(S) URL with a host and valid port, if present | Exact submitted string, including case, escapes, query order, and fragment |
| `hash` | Exactly 32, 40, or 64 ASCII hexadecimal characters | Lowercase hexadecimal; algorithm inferred from length |

Reject CIDRs, IP ports, IPv6 zone identifiers, bracket-wrapped standalone IPv6, defanged indicators, surrounding whitespace, and raw control characters. URLs MUST have no userinfo, raw whitespace, or backslashes; reject malformed percent escapes rather than accepting parser repairs. Parse URLs for validation only; do not use the parser's reserialized URL as their identity.

All syntactically valid IP address classes are accepted, including private and reserved addresses. They are submitted only to the selected provider API; no local-IP discovery or reachability checks run. This interface does not classify address publicity. Private URLs and URL query strings are also disclosed to a selected provider if submitted: callers are responsible for filtering indicators that must remain internal.

Use the same lookup value for provider requests, duplicate detection, and cache keys. Hash algorithm is included in cache identity. Do not alias different hash algorithms, URL spellings, or IPv4-mapped IPv6 values even if a provider relates them. Output the original `input` and the actual `lookup_value`.

### 2.4 Result envelope

Every completed enrichment response has exactly `request_id` and `results` at its top level. `results` preserves input order. Each item contains `index` (zero-based), `input`, `lookup_value`, and an ordered `providers` array. There is no aggregate verdict or aggregate success flag.

Each provider entry uses the following fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `provider` | String | Stable provider ID |
| `status` | String enum | Outcome defined below |
| `summary` | Provider-specific object or null | Typed, namespaced evidence; present only for `ok` |
| `fetched_at` | RFC 3339 UTC string or null | When an `ok` or `not_found` lookup completed; unchanged on a cache hit |
| `provider_updated_at` | RFC 3339 UTC string or null | Upstream analysis/observation timestamp, not service fetch time |
| `cache` | Object | `hit` boolean and `expires_at` timestamp or null |
| `error` | Object or null | Stable error contract; populated for `rate_limited`, `timeout`, and `error` |
| `raw` | JSON object, conditionally present | Complete successful lookup response when requested and within budget |
| `raw_omitted_reason` | String, conditionally present | `not_available` or `response_size_limit` when raw was requested but is absent |

Required nullable fields MUST be emitted as null instead of disappearing. `raw` and `raw_omitted_reason` are mutually exclusive; both are omitted when `include_raw=false`. No provider headers or raw error bodies are forwarded. Raw JSON preserves semantic content, not original whitespace or key ordering.

`cache.hit` is true only when that caller receives an unexpired SQLite entry. Joined concurrent lookups use false. `cache.expires_at` is the persisted entry's effective expiry, or null when persistence was not confirmed. A write failure may therefore yield `ok` with `cache.hit=false` and `cache.expires_at=null`.

| Status | Meaning |
| --- | --- |
| `ok` | A valid provider report was retrieved; this does not assert the indicator is benign or malicious |
| `not_found` | The provider explicitly says the report does not exist |
| `unsupported` | The enabled provider has no lookup for this indicator type |
| `disabled` | The explicitly selected provider is disabled |
| `rate_limited` | A local quota or upstream quota/cooldown prevents completing the lookup |
| `timeout` | This caller's deadline or the provider lookup deadline expired |
| `error` | Another provider, storage, capacity, or response-processing failure |

`unsupported` and `disabled` have null summary, timestamps, expiry, and error, with `cache.hit=false`. `not_found` has null summary, provider timestamp, and error; it has a fetch time and can be cached. Other failures carry no report or report timestamps. A numeric zero is evidence only when actually returned upstream; missing scores and counts are null.

### 2.5 Typed summaries

Upstream wrapper and identity fields must be valid. AbuseIPDB's returned IP and VirusTotal IP object ID must parse to the requested address. VirusTotal object types must match the endpoint: `ip_address`, `url`, or `file`. File IDs must be valid SHA-256 hashes; for MD5/SHA-1 requests, require and compare the corresponding returned hash attribute. A SHA-256 request must match the file ID. These identity fields are mandatory even when other evidence is missing.

VirusTotal URL IDs in responses are canonical SHA-256 identifiers, whereas this service sends unpadded base64 identifiers. Require a valid returned SHA-256 ID and the `url` object type, but do not compare that ID to the outgoing base64 string or require the provider's canonical URL spelling to equal the input. Rely on the fixed report endpoint for this association; do not reproduce provider canonicalization.

All summary fields listed below are nullable when the provider omits them or supplies JSON null, except fields required for identity verification above. Unknown upstream fields are tolerated and remain in raw JSON. An incorrectly typed non-null known field, invalid timestamp, negative count, or invalid mandatory wrapper produces `invalid_response`, not fabricated data.

| Provider | Public summary fields | Upstream mapping |
| --- | --- | --- |
| `abuseipdb` | `abuse_confidence_score`, `total_reports`, `distinct_reporters`, `last_reported_at` | `data.abuseConfidenceScore` (0–100), `totalReports`, `numDistinctUsers`, `lastReportedAt` |
| `abuseipdb` | `country_code`, `isp`, `domain`, `usage_type`, `is_public`, `is_tor`, `is_whitelisted` | Corresponding camelCase fields under `data` |
| `virustotal` | `analysis_stats`, `reputation`, `last_analysis_at` | `data.attributes.last_analysis_stats`, `reputation` (signed integer), `last_analysis_date` (Unix seconds) |
| `virustotal` | `country`, `asn`, `as_owner` | Corresponding IP attributes; null for other kinds |
| `virustotal` | `md5`, `sha1`, `sha256`, `file_type` | Corresponding file attributes, with `file_type` from `type_description`; null for other kinds |

`analysis_stats` is null when absent; otherwise it contains nullable nonnegative counts for `malicious`, `suspicious`, `harmless`, `undetected`, `timeout`, `confirmed_timeout`, `failure`, and `type_unsupported`. Map `confirmed_timeout` from `confirmed-timeout` and `type_unsupported` from `type-unsupported`; `failure` is unchanged. Do not sum unknown counts or introduce thresholds.

Mappings follow the provider object references: [VirusTotal IP attributes](https://docs.virustotal.com/reference/ip-object), [URL attributes](https://docs.virustotal.com/reference/url-object), and [file attributes](https://docs.virustotal.com/reference/files).

`provider_updated_at` is AbuseIPDB's `lastReportedAt` or VirusTotal's `last_analysis_date`. It is null if absent and is not a promise of report freshness. Retain provider-specific timestamp fields in summaries for convenient downstream access. Summary serialization is limited to 16 KiB per provider result; exceeding it produces `response_too_large` rather than silently dropping summary evidence.

### 2.6 Complete response examples

These are synthetic fixtures demonstrating shape, not live intelligence. An IP lookup with an AbuseIPDB cache hit and a VirusTotal quota failure returns HTTP 200:

~~~json
{
  "request_id": "61c9ae92-631b-4da3-88be-f1b234fef540",
  "results": [
    {
      "index": 0,
      "input": {"type": "ip", "value": "8.8.8.8"},
      "lookup_value": "8.8.8.8",
      "providers": [
        {
          "provider": "abuseipdb",
          "status": "ok",
          "summary": {
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "distinct_reporters": 0,
            "last_reported_at": null,
            "country_code": "US",
            "isp": "Example network",
            "domain": null,
            "usage_type": null,
            "is_public": true,
            "is_tor": false,
            "is_whitelisted": null
          },
          "fetched_at": "2026-09-12T00:00:00Z",
          "provider_updated_at": null,
          "cache": {"hit": true, "expires_at": "2026-09-12T01:00:00Z"},
          "error": null
        },
        {
          "provider": "virustotal",
          "status": "rate_limited",
          "summary": null,
          "fetched_at": null,
          "provider_updated_at": null,
          "cache": {"hit": false, "expires_at": null},
          "error": {
            "code": "quota_exhausted",
            "message": "Provider request quota is exhausted.",
            "retryable": true,
            "retry_after_seconds": 42
          }
        }
      ]
    }
  ]
}
~~~

A URL request selecting both providers, with `include_raw=true` and no VirusTotal report, returns HTTP 200:

~~~json
{
  "request_id": "969d2902-7f62-45b8-a94e-2bdaaa5d6fbb",
  "results": [
    {
      "index": 0,
      "input": {"type": "url", "value": "https://example.com/"},
      "lookup_value": "https://example.com/",
      "providers": [
        {
          "provider": "abuseipdb",
          "status": "unsupported",
          "summary": null,
          "fetched_at": null,
          "provider_updated_at": null,
          "cache": {"hit": false, "expires_at": null},
          "error": null,
          "raw_omitted_reason": "not_available"
        },
        {
          "provider": "virustotal",
          "status": "not_found",
          "summary": null,
          "fetched_at": "2026-09-12T00:00:00Z",
          "provider_updated_at": null,
          "cache": {"hit": false, "expires_at": "2026-09-12T00:05:00Z"},
          "error": null,
          "raw_omitted_reason": "not_available"
        }
      ]
    }
  ]
}
~~~

A minimal upstream success containing only valid identity and one evidence field illustrates raw passthrough. The complete response for a one-IP, AbuseIPDB-only request with `include_raw=true` is:

~~~json
{
  "request_id": "085a46bf-c322-4407-8db8-0304c7307949",
  "results": [
    {
      "index": 0,
      "input": {"type": "ip", "value": "8.8.8.8"},
      "lookup_value": "8.8.8.8",
      "providers": [
        {
          "provider": "abuseipdb",
          "status": "ok",
          "summary": {
            "abuse_confidence_score": 0,
            "total_reports": null,
            "distinct_reporters": null,
            "last_reported_at": null,
            "country_code": null,
            "isp": null,
            "domain": null,
            "usage_type": null,
            "is_public": null,
            "is_tor": null,
            "is_whitelisted": null
          },
          "fetched_at": "2026-09-12T00:00:00Z",
          "provider_updated_at": null,
          "cache": {"hit": false, "expires_at": "2026-09-12T01:00:00Z"},
          "error": null,
          "raw": {"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0}}
        }
      ]
    }
  ]
}
~~~

A hash lookup selecting only VirusTotal can return this synthetic success with `include_raw=false`. The indicator is the SHA-256 of an empty file; these illustrative statistics are not a current provider report.

~~~json
{
  "request_id": "72fd4da0-1bce-4d26-9842-3ee06a04977f",
  "results": [
    {
      "index": 0,
      "input": {
        "type": "hash",
        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "lookup_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "providers": [
        {
          "provider": "virustotal",
          "status": "ok",
          "summary": {
            "analysis_stats": {
              "malicious": 0,
              "suspicious": 0,
              "harmless": 0,
              "undetected": 2,
              "timeout": 0,
              "confirmed_timeout": null,
              "failure": null,
              "type_unsupported": null
            },
            "reputation": 0,
            "last_analysis_at": "2026-09-11T23:50:00Z",
            "country": null,
            "asn": null,
            "as_owner": null,
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "file_type": "empty"
          },
          "fetched_at": "2026-09-12T00:00:00Z",
          "provider_updated_at": "2026-09-11T23:50:00Z",
          "cache": {"hit": false, "expires_at": "2026-09-13T00:00:00Z"},
          "error": null
        }
      ]
    }
  ]
}
~~~

### 2.7 HTTP and error mappings

Valid enrichment requests return HTTP 200 even when every provider entry is unsuccessful. Do not use HTTP 207 or translate one provider's HTTP 429/401 into a service-level HTTP 429/401.

| Service HTTP status | Code | Trigger |
| --- | --- | --- |
| 400 | `invalid_json` | Malformed JSON, duplicate object keys, or invalid UTF-8 |
| 401 | `unauthorized` | Missing/invalid service token; also return `WWW-Authenticate: Bearer` |
| 404 | `route_not_found` | Unknown route |
| 405 | `method_not_allowed` | Known route, unsupported HTTP method; include `Allow` |
| 408 | `request_body_timeout` | Request body did not complete before its deadline |
| 413 | `request_too_large` | Request-body byte limit exceeded |
| 415 | `unsupported_media_type` | Wrong content type or unsupported content encoding |
| 422 | `validation_error` | Well-formed JSON violates the request contract |
| 503 | `service_overloaded` | Admission capacity exhausted; `Retry-After: 1` |
| 503 | `service_unavailable` | Shutdown, or known unavailable required storage before enrichment; `Retry-After: 1` |
| 500 | `internal_error` | Unexpected failure that prevents producing an envelope |
| 500 | `response_too_large` | The non-raw envelope cannot fit its serialization limit |

A service error body contains `request_id` and `error`, except for the minimal health probe responses defined in section 2.8. Error fields are `code`, `message` (static/redacted, maximum 512 UTF-8 bytes), `retryable`, and nullable `retry_after_seconds`. Validation errors additionally contain `details` with `path`, `code`, and safe `message`. Maximum 100 details, in request order. Do not expose provider bodies, indicators, secrets, connection strings, or stack traces.

~~~json
{
  "request_id": "3c7e25e8-07e9-47f9-9f21-aa566c054032",
  "error": {
    "code": "validation_error",
    "message": "One or more request fields are invalid.",
    "retryable": false,
    "retry_after_seconds": null,
    "details": [
      {
        "path": "/indicators/0/value",
        "code": "invalid_hash",
        "message": "Expected 32, 40, or 64 hexadecimal characters."
      }
    ]
  }
}
~~~

Client errors are not retryable without changing the request. HTTP 408, 503, and `internal_error` are retryable; an oversized response is not. Known retry delays are nonnegative integer seconds, rounded up. Null means no reliable reset time, not zero.

| Provider condition | Status / error code | Retryable |
| --- | --- | --- |
| Documented report-not-found response | `not_found` / null | No automatic retry |
| Local quota/cooldown or upstream 429 | `rate_limited` / `quota_exhausted` | Yes, after delay when supplied |
| Upstream 401 | `error` / `provider_authentication_failed` | No |
| Upstream 403 | `error` / `provider_access_denied` | No |
| Timeout | `timeout` / `provider_timeout` | Yes |
| Caller request deadline | `timeout` / `request_deadline_exceeded` | Yes |
| Network failure after allowed retry | `error` / `network_error` | Yes |
| Upstream 5xx after allowed retry | `error` / `provider_unavailable` | Yes |
| Other upstream 4xx or redirects | `error` / `provider_request_rejected` | No |
| TLS/certificate validation failure | `error` / `provider_tls_error` | No |
| Malformed JSON, invalid wrapper/evidence | `error` / `invalid_response` | No |
| Oversized upstream body or summary | `error` / `response_too_large` | No |
| Shared-lookup capacity exhausted | `error` / `provider_busy` | Yes, one second |
| Storage needed for quota reservation fails | `error` / `storage_unavailable` | Yes, one second |

Map VirusTotal's documented 404 `NotFoundError` to `not_found`. An empty/zero-score AbuseIPDB CHECK success is `ok`, not `not_found`. AbuseIPDB CHECK has no documented not-found contract here: unexpected 404s are provider errors. Retain missing-data distinctions in tests. [VirusTotal errors](https://docs.virustotal.com/reference/errors)

### 2.8 Health

`GET /health/live` and `GET /health/ready` are private-network, unauthenticated probes with minimal JSON and a request ID. Liveness returns 200 while the process can serve. Readiness returns 200 only after configuration validation, migration, and a bounded local storage check succeed and shutdown has not begun; otherwise 503. Provider outages, invalid upstream keys discovered at runtime, and depleted quotas do not make a locally usable service unready.

Use `{"status":"alive","request_id":"..."}`, `{"status":"ready","request_id":"..."}`, or `{"status":"not_ready","request_id":"..."}` with a real generated ID. Readiness uses at most the configured storage timeout and confirms the local state can be read and written with a rolled-back transaction. Probes do not consume enrichment admission permits or provider quota and MUST NOT call provider APIs.

## 3. Provider contracts

| Adapter | Fixed origin and lookup | Authentication |
| --- | --- | --- |
| AbuseIPDB | `GET https://api.abuseipdb.com/api/v2/check?ipAddress=<encoded-ip>&maxAgeInDays=30` | `Key` header and `Accept: application/json` |
| VirusTotal IP | `GET https://www.virustotal.com/api/v3/ip_addresses/<encoded-ip>` | `x-apikey` header |
| VirusTotal URL | `GET https://www.virustotal.com/api/v3/urls/<url-id>` | `x-apikey` header |
| VirusTotal hash | `GET https://www.virustotal.com/api/v3/files/<lowercase-hash>` | `x-apikey` header |

Build query parameters and path segments with encoders, never unchecked concatenation. VirusTotal URL IDs are URL-safe base64 of the original URL's UTF-8 bytes without padding; do not implement VirusTotal canonicalization locally. [URL identifiers](https://docs.virustotal.com/reference/url), [URL reports](https://docs.virustotal.com/reference/url-info), [IP reports](https://docs.virustotal.com/reference/ip-info), [file reports](https://docs.virustotal.com/reference/file-info)

AbuseIPDB uses configured `maxAgeInDays` in the range 1–365; omit `verbose` entirely. The default lookback is 30 days. Raw means the result of this non-verbose CHECK request, not a history of individual abuse reports. [AbuseIPDB CHECK](https://docs.abuseipdb.com/#check-endpoint)

Each enabled adapter reuses an asynchronous Reqwest client with a two-second connect timeout, the attempt timeout, certificate validation, and redirects disabled. Send `Accept: application/json` to both providers. Provider origins are fixed in production; test constructors may inject localhost mock origins. Never accept caller-controlled API endpoints, follow response links, or forward service authentication upstream.

Read response bodies with a streaming byte cap, including non-2xx bodies; do not trust Content-Length. Apply the cap after decompression when enabled, and cap compact JSON serialization separately. An oversized body stops parsing and produces `response_too_large`. Upstream error classification uses HTTP status and recognized error codes; error text is not copied to public errors or logs.

## 4. Architecture and execution

### 4.1 Modules and dependency direction

Use Rust edition 2024 and one crate with a thin binary entry point plus testable library modules:

| Module responsibility | Owns |
| --- | --- |
| HTTP | Routing, authentication, request/response DTOs, validation responses, projection and serialization |
| Domain | Validated indicators, provider IDs, typed evidence and outcome/error types |
| Enrichment | Provider selection, shared lookups, deadlines, bounded concurrency, cache/quota coordination |
| Providers | Small provider interface, explicit registry, vendor adapters and upstream DTOs |
| Storage | Concrete SQLite cache, persistent quota operations, migrations |
| Configuration | Environment parsing and validation; immutable settings |
| Startup | Construct shared clients/state, initialize storage, serve, handle shutdown |

Dependencies point from HTTP to enrichment and domain, and from adapters/storage to domain contracts. Keep Axum, Reqwest responses, and SQL rows out of domain types. The provider interface has a stable ID, supported indicator kinds, payload version, and one asynchronous lookup operation. An adapter describes the report request and decoding; a shared outbound executor performs each HTTP attempt with permits, quota reservation, and timeouts. This ensures retries cannot bypass quota accounting.

Use Axum/Tokio, Reqwest, Serde/serde_json, tracing, and SQLx with SQLite only. Use ordinary construction and a registry of provider instances; no dependency-injection framework, generic persistence abstraction, runtime plugins, or custom workflow language.

### 4.2 Request and shared-lookup lifecycle

1. Admit an authenticated request or return 503 immediately. Read the bounded body, validate the whole batch, then construct ordered result slots.
2. Resolve disabled/unsupported pairs without I/O. For other pairs, check fresh cache before checking quota.
3. On a miss, join an existing lookup for the same cache identity or register a new bounded, service-owned lookup. The owner rechecks cache after registration to close races.
4. The owner acquires bounded provider/global HTTP capacity, reserves quota durably, dispatches, parses, and optionally retries under the same lookup deadline.
5. Store a cacheable result, publish it to waiters, and remove the shared entry. Always remove entries after errors, task failure, or cancellation.
6. Each caller assembles results received before its own deadline, marks remaining slots `request_deadline_exceeded`, and projects raw data according to its own request.

At most 32 enrichment HTTP requests are admitted by default, including body reading and response writing. At most 64 distinct shared lookups may exist by default, including waiting and running lookups. Joining an existing lookup does not consume another lookup slot. Reject a new miss as `provider_busy` when this table is full; cached and joined results remain eligible.

Within an admitted request, traverse the bounded indicator/provider pairs using bounded futures. Do not spawn unbounded tasks per entry or copy cached raw values per waiter: share immutable lookup outcomes until serialization. v1 has two registered providers, so the default maximum is 40 result slots per request.

Provider and global permits bound active HTTP attempts across the entire process. Wait for capacity only within the shared lookup's remaining deadline. Do not hold a global HTTP permit while waiting for a provider permit. Hold both during the short final quota reservation and HTTP attempt; release them before retry backoff or cache writes. Health endpoints use a separate small admission limit of two; when full, return HTTP 503 with the section 2.7 `service_overloaded` envelope.

### 4.3 Deadlines, retries, and shutdown

The default 15-second request deadline begins at admission and covers body reading plus enrichment. At expiry before body completion return HTTP 408; after a valid request exists return partial JSON with timeout slots. Response assembly/writing has a separate maximum five-second deadline, and the admission permit remains held through it. A blocked client therefore cannot retain a slot indefinitely. If writing has begun and fails or times out, close the response and log safe metadata; do not attempt a second JSON response.

Each shared lookup has its own 12-second default lifetime starting when registered, independent of any caller. Time in admission, permits, storage, network, backoff, and cache write counts against that lifetime. Each HTTP attempt is limited to the smaller of five seconds and remaining lookup time. If a report or not-found result is fully decoded before expiry but the cache write times out or is canceled at the lookup deadline, publish that completed outcome with `cache.expires_at=null`; do not replace it with a provider timeout. A caller whose own deadline already expired still keeps its caller-timeout result.

Retry only connection/DNS/reset failures and HTTP 502/503/504, at most once, using a 200 ms backoff. Retry only if enough lookup time remains for the backoff and a full configured attempt. Do not automatically retry attempt timeouts, TLS failures, authentication errors, 429, malformed bodies, or other HTTP codes. Honor any Retry-After on a retry-eligible response; if waiting would exceed the lookup deadline, return the failure instead. Retry scheduling never resets deadlines.

One caller disconnecting or timing out does not cancel a shared lookup needed by other callers. For v1, even if all waiters leave, let the lookup finish and populate cache within its existing deadline; do not add waiter-count cancellation machinery.

On shutdown, readiness becomes false and new enrichments return 503. Drain admitted requests and shared lookups for up to 20 seconds, cancel remaining work, close clients/storage, and exit. Reservations made before a canceled dispatch remain consumed; refunding uncertain requests is unsafe.

## 5. Persistent state

### 5.1 SQLite and failure behavior

Use SQLx's worker-backed SQLite connection through one shared pool capped at one connection. Enable WAL, `synchronous=FULL` because quota state is durable, and a 250 ms busy timeout. Bound pool acquisition and each storage operation by a one-second total storage deadline, also clipped to the enclosing deadline. [SQLx SQLite connection](https://docs.rs/sqlx/latest/sqlx/sqlite/struct.SqliteConnection.html)

Use local disk, not a shared/network filesystem, and enforce one process owner through an OS-held exclusive lock on a file beside the database. File existence alone is not ownership; the OS releases the lock when the process exits. SQLite serializes brief database work; external HTTP calls still overlap. No network await or retry sleep occurs inside a transaction. WAL requires disk headroom and local shared-memory support. [SQLite WAL](https://www.sqlite.org/wal.html)

Apply numbered embedded SQL migrations in order before readiness. Fail startup on a bad path, corruption, incompatible/newer schema, failed migration, or inability to acquire the process lock. Do not silently delete or recreate state. Use parameterized runtime queries; no build-time database dependency is needed.

During runtime:
- A cache read failure is a miss for that pair; record degradation. A fresh lookup still requires a successful durable quota reservation.
- If quota state cannot be read or committed, return `storage_unavailable` without dispatching. A canceled/timed-out reservation must never trigger a late HTTP call, even if the queued database commit subsequently finishes.
- A cache write failure preserves the successfully fetched report or not-found result, with no claimed persisted expiry.
- Readiness reflects local storage availability. Work already admitted can retain successes even if storage subsequently fails; do not erase partial results.

### 5.2 Cache contract

Cache `ok` and `not_found` outcomes only. Do not cache disabled/unsupported outcomes or failures. No stale fallback, refresh endpoint, cache bypass request option, or extra memory TTL cache exists in v1.

| Outcome/type | Default TTL from fetch completion |
| --- | --- |
| IP success | 3,600 seconds |
| URL success | 3,600 seconds |
| Hash success | 86,400 seconds |
| Not found | 300 seconds |

An entry is fresh only when current UTC time is strictly before its expiry. Stored expiry is also capped on read by `fetched_at + current_configured_TTL`, so reducing a TTL takes effect without extending old entries when a TTL increases. Cache metadata reports this effective expiry. Treat future-dated fetch timestamps as misses.

Use one cache table with a provider ID and SHA-256 cache-key digest as primary key, payload version, fetch/expiry timestamps, serialized payload, and payload byte count. Build the digest from a deterministic serialized tuple: provider ID, payload version, indicator type, hash algorithm if applicable, lookup value, and result-affecting lookup options. Include AbuseIPDB lookback and non-verbose mode. Credentials, request IDs, and `include_raw` are not part of this identity.

The stored payload contains typed summary, successful raw JSON, outcome, and provider timestamp. It excludes caller input, request IDs, caller deadlines, and runtime errors. On a raw request, reuse this payload; do not issue a second provider call.

Default limits are 10,000 entries and 134,217,728 bytes (128 MiB) of serialized payload. Successful raw JSON must already pass the 1 MiB provider cap. A serialized cache payload larger than the total cache budget is returned but not stored. In a short insertion transaction, delete expired entries, upsert the new entry, then evict oldest-fetched entries until both limits hold, with cache-key order as a tie-breaker. Use expiry/fetch indexes and aggregate counts/bytes; avoid separate mutable accounting machinery.

Clean expired rows at startup, on insertion, and every 60 seconds in bounded chunks of 500. Reconcile reduced capacity limits before readiness. FIFO eviction avoids writing on every cache hit. SQLite may retain freed pages and its WAL may grow temporarily: these are logical cache limits, not a filesystem-size guarantee. Do not run VACUUM in a request handler.

### 5.3 Quota accounting and cooldowns

Concurrency limits control simultaneous work; quotas control attempt counts over time. A cache hit or joined lookup consumes no quota. Check quotas immediately before dispatch; never wait for a quota window to reset inside a synchronous request.

Free-tier testing profile:

| Provider quota group | Rolling 60-second cap | UTC-day cap |
| --- | --- | --- |
| VirusTotal, shared across IP/URL/hash | 4 | 500 |
| AbuseIPDB CHECK | No additional local minute cap | 1,000 |

These are configurable testing defaults, not a promise about a particular account. VirusTotal's public API also restricts commercial use and report-only business workflows. Production must use an eligible account and its licensed limits. Do not add scanning or rotate accounts to evade these restrictions. [VirusTotal plans](https://docs.virustotal.com/reference/public-vs-premium-api), [AbuseIPDB limits](https://docs.abuseipdb.com/#api-daily-rate-limits)

Persist a quota-state row per stable quota group: `virustotal` and `abuseipdb_check`. Store UTC day, consumed daily count, cooldown-until timestamp, and latest observed provider remaining/reset information. Use a small attempt-timestamp table per group for rolling-minute reservations, deleting timestamps at least 60 seconds old during reservations. Day counters reset at 00:00 UTC only after the old day ends.

In one transaction, check cooldown and applicable limits, increment the daily counter, append the minute timestamp when enabled, and commit before the HTTP attempt. Every attempt counts, including retries, failed connections, and requests whose outcome becomes uncertain. Do not refund. Delete only old minute records, never current-day usage to make room. Adapter upgrades, cache eviction, TTL changes, credential rotation, and process restarts MUST NOT reset quota usage. Quota scope does not include adapter version, cache identity, or an API key.

Parse Retry-After as delta seconds or an HTTP date. Honor a longer upstream cooldown even when local quota remains. For AbuseIPDB, reconcile its remaining/reset headers conservatively: a response may reduce local availability but must not increase it within the current window; out-of-order responses must not resurrect consumed quota.

A 429 with a valid reset establishes that cooldown. Without one, use a 60-second local cooldown; expose null retry delay when the actual quota reset is unknown. This fallback paces later probes, not an assertion that quota will be available in a minute. Return the longest known applicable local/upstream delay when it can be established. Unknown provider daily/monthly exhaustion may still be authoritative after a local minute window opens.

If saving a newly observed cooldown fails, retain it in memory and stop fresh dispatches for that group until the retained state is successfully persisted; storage recovery alone does not reopen dispatch. Log degradation. Previously reserved usage is already durable. Provider-side consumption by other applications is unknowable in advance: dedicate keys to this service where practical, and treat provider limits as authoritative.

Use monotonic time for in-process deadlines and UTC for persisted timestamps. Maintain a conservative in-process effective UTC clock that never moves backward; persist its high-water mark with quota updates. If wall time is behind that mark after restart, delay new quota admissions until it catches up. Operate with a synchronized clock; clock rollback must not create a fresh quota window.

## 6. Configuration and deployment

Configuration is read once at startup from environment variables; no runtime reload or generic configuration framework. All names below begin with `ENRICH_`. Unset values take the documented defaults. Invalid values fail startup; do not silently clamp them. Booleans accept `true` or `false`; sizes/counts/time values use unsigned decimal integers in the stated units.

### 6.1 Core settings

| Variable suffix | Default | Meaning |
| --- | --- | --- |
| `BIND_ADDR` | `127.0.0.1:8080` | Override to `0.0.0.0:8080` inside Docker |
| `SERVICE_TOKEN` / `SERVICE_TOKEN_FILE` | Required | At least 32 bytes of operator-generated secret material |
| `DATABASE_PATH` | `./data/rustenrich.sqlite` | In Docker set to `/data/rustenrich.sqlite` |
| `MAX_BATCH_SIZE` | 20 | Range 1–20 in v1 |
| `MAX_REQUEST_BYTES` | 131072 | 128 KiB body limit |
| `MAX_CONCURRENT_REQUESTS` | 32 | Admitted enrichment requests |
| `MAX_SHARED_LOOKUPS` | 64 | Waiting plus active unique lookups |
| `MAX_OUTBOUND_REQUESTS` | 16 | Global HTTP attempt concurrency |
| `REQUEST_TIMEOUT_MS` | 15000 | Body reading and enrichment deadline |
| `LOOKUP_TIMEOUT_MS` | 12000 | Independent shared-lookup lifetime |
| `PROVIDER_TIMEOUT_MS` | 5000 | Single upstream attempt |
| `CONNECT_TIMEOUT_MS` | 2000 | Upstream connection establishment |
| `RESPONSE_WRITE_TIMEOUT_MS` | 5000 | Assembly and client response writing |
| `STORAGE_TIMEOUT_MS` | 1000 | Complete storage operation, including pool wait |
| `SHUTDOWN_GRACE_MS` | 20000 | Maximum drain |
| `MAX_PROVIDER_BYTES` | 1048576 | 1 MiB decoded/serialized provider-body cap |
| `MAX_RAW_RESPONSE_BYTES` | 8388608 | 8 MiB total serialized raw fields |
| `CACHE_MAX_ENTRIES` | 10000 | Persisted cache entry cap |
| `CACHE_MAX_BYTES` | 134217728 | 128 MiB logical cache payload cap |
| `CACHE_IP_TTL_SECONDS` | 3600 | IP success cache TTL |
| `CACHE_URL_TTL_SECONDS` | 3600 | URL success cache TTL |
| `CACHE_HASH_TTL_SECONDS` | 86400 | Hash success cache TTL |
| `CACHE_NOT_FOUND_TTL_SECONDS` | 300 | Not-found cache TTL |
| `LOG_LEVEL` | `info` | `error`, `warn`, `info`, `debug`, or `trace` |

Unless stated otherwise, capacities and deadlines must be positive. A cache TTL of zero disables storage/use for that category without disabling shared concurrent lookup reuse. Require `CONNECT_TIMEOUT_MS <= PROVIDER_TIMEOUT_MS <= LOOKUP_TIMEOUT_MS <= REQUEST_TIMEOUT_MS` and `STORAGE_TIMEOUT_MS <= LOOKUP_TIMEOUT_MS`. Provider concurrency cannot exceed global outbound capacity. Database storage must be writable and local; secret files need only be readable and should be mounted read-only. Do not print path details containing credentials.

### 6.2 Provider settings

For `P` equal to `ABUSEIPDB` or `VIRUSTOTAL`:

| Variable suffix | Default | Meaning |
| --- | --- | --- |
| `P_ENABLED` | `false` | Explicit provider opt-in |
| `P_API_KEY` / `P_API_KEY_FILE` | Required when enabled | Secret; only one source permitted |
| `P_MAX_CONCURRENCY` | 4 | Provider HTTP attempt cap |
| `P_REQUESTS_PER_MINUTE` | AbuseIPDB: 0; VirusTotal: 4 | Rolling-minute cap; zero means no added local minute cap |
| `P_REQUESTS_PER_DAY` | AbuseIPDB: 1000; VirusTotal: 500 | Positive UTC-day budget |
| `ABUSEIPDB_MAX_AGE_DAYS` | 30 | Range 1–365 |

Expand literally, for example `ENRICH_VIRUSTOTAL_ENABLED`. At least one provider must be enabled. Validate enabled providers' keys and all supplied configuration; missing credentials must not silently disable an enabled provider. Startup does not validate keys by spending provider requests.

For each secret, accept its environment value or a UTF-8 file path in the matching `_FILE` variable, never both. Strip one terminal line ending from secret-file contents; reject empty values, embedded line breaks, and invalid header values. Environment secrets are not trimmed. Never dump the loaded configuration with secrets. Rotation takes effect on restart and does not clear quota history.

### 6.3 Response limits

Measure UTF-8 bytes in compact JSON, independent of pretty printing. Non-raw envelope content has a fixed 1 MiB cap; summary objects have a fixed 16 KiB cap, input strings 4,096 bytes, and error messages 512 bytes. These are v1 contract bounds, not additional environment knobs.

For `include_raw=true`, traverse input results in order, then providers in their defined order. Add a complete raw value only if its serialized byte length fits the remaining raw budget; otherwise emit `raw_omitted_reason=response_size_limit`. Continue considering subsequent smaller values. Repeated input slots count repeatedly in the output budget even when they share a lookup. Do not truncate raw objects or change an `ok` status solely because raw output was omitted.

Count wrappers, commas, and omission metadata toward the non-raw envelope cap. Total output is bounded by that 1 MiB cap plus configured raw bytes, default 9 MiB. If the non-raw envelope cannot fit, return a small HTTP 500 `response_too_large` envelope before sending headers. With two providers and the default batch cap, summaries are designed to fit; adding providers must revalidate this bound.

### 6.4 Deployment and n8n

The application provides a non-root container image, a persistent volume mounted at `/data`, secret-file mounts, and documented local startup commands in [README.md](README.md). Preserve the database, WAL, and shared-memory files together through the mounted directory. Do not run replicas against it. Restrict host permissions and budget disk headroom above logical cache capacity.

Expose the service only on n8n's private container network; an externally exposed deployment needs a TLS proxy. Keep the container port private by default. Use a stop grace period longer than 20 seconds, such as 25 seconds. On restore, keep quota tables: restoring an older snapshot can undercount usage, so conservatively withhold fresh calls until the affected provider windows reset. Recreating the volume also loses accounting; it is not a quota-reset operation.

Configure n8n's HTTP Request node as follows:
1. Method POST; URL `http://rustenrich:8080/v1/enrich` on the shared private network.
2. Generic Header Auth credential: `Authorization` with the service bearer token.
3. Send JSON using the request example in section 2.2; group at most 20 indicators per request.
4. Response Format JSON; enable Include Response Headers and Status and Never Error to branch on HTTP failures explicitly.
5. Set Timeout to 25,000 ms; disable node-wide automatic retries and pagination. Leave certificate verification enabled when using HTTPS.

n8n supports these request/response settings through its [HTTP Request node](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.httprequest/).

For HTTP 200, iterate `body.results[].providers[]` and branch on `status`, not HTTP success alone. Preserve successful evidence immediately. Retry only failed provider/indicator pairs with `error.retryable=true`, using a Wait step for known delays and at most two workflow retries. With no known delay, use 60 seconds then 120 seconds. Never sleep/retry rapidly for exhausted daily quotas. Use request/provider IDs and original indices to merge retried evidence back into the original alert.

For service 503, use its Retry-After with the same bounded workflow retry budget. Route authentication/validation errors to workflow error handling. Missing evidence must remain unknown in any AI triage prompt. Supply source and timestamps with evidence, and keep raw/provider text separate from instructions.

## 7. Operations and auditability

Emit structured JSON logs to stdout using tracing. Include request ID, route template, status, duration, indicator count/types, provider, outcome/error code, cache hit/miss, shared-lookup join, retry count, quota denials, storage failures, and admission rejection as applicable. A shared lookup gets its own opaque lookup ID, with caller request IDs associated when they join.

Never log indicator values, cache-key digests, request/response bodies, URL paths or query strings from outbound calls, secrets, raw Reqwest error display strings, or full configuration. Apply this rule at every log level, including dependency tracing. Provider text is untrusted evidence and must not control prompts, commands, URLs, or configuration.

Log startup validation/migration results without secrets, and log shutdown drain/cancellation counts. Report cache failure separately from provider failure. Logs and health probes are sufficient for v1; an external metrics backend is not required. Do not add a metrics system, audit database, circuit-breaker framework, or tracing collector merely for anticipated scale.

Cache content is sensitive local data even when lookup values are hashed: raw reports may contain them. Restrict the volume and backups to the service operator; the service does not promise application-level encryption or secure forensic deletion. Expiration is logical retention plus bounded cleanup, not immediate physical erasure.

## 8. Acceptance tests and completion criteria

Automated application tests use mock providers, sanitized fixtures, temporary SQLite files, and controllable clocks. No default test spends live quota or resolves/visits an indicator host. Live smoke tests are explicitly opt-in and report quota consumption.

| ID | Requirement and acceptance scenario |
| --- | --- |
| A01 | Request contract: valid IPv4/IPv6, exact URL spelling, all three hash lengths/cases, preserved order/duplicates, omitted/explicit providers, disabled-before-unsupported precedence |
| A02 | Validation: malformed JSON/duplicate keys, unknown fields/provider IDs, nulls/types, invalid URL/IP/hash, empty/oversized batches and byte limits; any invalid item causes zero provider calls |
| A03 | Authentication/HTTP: correct service 401/400/404/405/408/413/415/422/503/500 envelopes, headers, token redaction; no raw data or provider credentials in errors |
| A04 | Provider mapping: redacted fixtures for both providers and all supported kinds; optional/unknown fields, signed reputation, unknown versus zero, canonical file hash identity, non-verbose AbuseIPDB, URL-safe base64 IDs |
| A05 | Outcome isolation: one success survives another provider's 401/403/404/429/5xx/network failure/timeout; all-provider failures still return HTTP 200 with individual outcomes |
| A06 | Provider body handling: malformed/truncated JSON, wrong known types, invalid identity/timestamps, 3xx, forged Content-Length, streamed/decompressed oversized bodies, no copied upstream error text |
| A07 | Concurrency: overlapping mock calls prove actual concurrency; active requests, shared lookups, provider/global HTTP calls and health calls never exceed limits; overload is prompt and permits are released |
| A08 | Deadlines/retries: queue/lock waits count; one transient retry maximum, every retry reserves quota, no retry on 429/auth/TLS/timeout, caller/shared deadlines independent, slow client response bounded |
| A09 | Cache: repeat lookup makes no second call; IP/URL/hash/not-found TTLs, equality at expiry, TTL reduction/zero, no stale fallback, no transient-error caching; reopen database to prove restart persistence |
| A10 | Cache identity/limits: provider/options/version/hash algorithm isolation, original URL spelling, summary-then-raw reuse, 10,000-entry/byte caps using smaller test settings, deterministic eviction, cleanup and reduced-capacity startup |
| A11 | Shared work: simultaneous identical misses make one upstream attempt; registration race recheck, one/all callers disconnect, owner failure, and shutdown leave no stranded lookup entries |
| A12 | Quotas: rolling-minute and UTC-day boundaries, simultaneous reservations, counters/cooldowns surviving restart/key rotation/version changes, retries/canceled dispatches consumed, no refund, no HTTP call after storage failure |
| A13 | Provider quota feedback: Retry-After seconds/date, unknown 429 reset, longer cooldown, out-of-order AbuseIPDB headers, externally consumed quota, and clock rollback do not create local allowance |
| A14 | Storage: startup migration/lock/corruption/newer schema failures, lock wait bounds, read failures, failed reservations, timed-out commits with no late dispatch, write failure preserving fetched success, local readiness transitions |
| A15 | Output: exact nullable fields/status set, valid JSON examples, raw complete/omitted cases, deterministic 8 MiB raw budget, duplicates counted, summary and total-envelope limits, no truncated JSON |
| A16 | Lifecycle/security: probes use no provider quota; private token/auth boundaries, no redirects or arbitrary origins, no indicator DNS/fetching, no sensitive logs, one-process ownership, bounded graceful shutdown |
| A17 | n8n flow: real HTTP request against mock providers yields the documented shape; downstream branching retains partial results and retries only eligible pairs with bounded waits |
| A18 | Repeatable build/review: formatting, Clippy, tests, dependency audit, committed lockfile, minimal features, and documentation changes follow BEST_PRACTICES.md |

For concurrency verification, record mock simultaneous-call maxima and compare them to configured bounds; do not set live-provider throughput promises. A load check with 32 simultaneous default-sized requests must finish or return bounded failures without task growth, panic, deadlock, or leaked permits. Record elapsed time and peak memory on the test host; do not claim a hardware-independent memory/latency SLA.

Implementation verification must retain the checks and measured load results, validate fenced JSON examples and local links, and identify any unverified environment-dependent scenarios. See [VERIFICATION.md](VERIFICATION.md) for the implementation's recorded checks and acceptance coverage.

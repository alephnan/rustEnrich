# Adding a provider

rustEnrich includes AbuseIPDB and VirusTotal as demo integrations. You can add another report source by extending the compiled Rust adapters and rebuilding. There is no runtime plugin loader, arbitrary endpoint setting, provider trait to implement, or configuration-only REST adapter in the current release.

Read [SPEC.md](SPEC.md) and [BEST_PRACTICES.md](BEST_PRACTICES.md) first. The walkthrough below uses the fictional ID `acme` and prefix `ENRICH_ACME_`; these are proposed additions, not settings or a provider supported by the current binary. Use the existing adapters as working examples and the new provider's official API documentation for its actual request, authentication, fields, quotas and terms.

## 1. Define the report contract

Choose a stable lowercase provider ID, supported indicator kinds (`ip`, `url`, `hash`), fixed HTTPS origin, and one existing-report operation per supported kind. Document authentication, lookup-affecting options, report identity validation, timestamps, nullable summary fields, documented not-found responses, quota windows and quota feedback headers in the specification. Record the upstream documentation links and date checked.

The current service retrieves reports only. Adding scans, submissions, domain-only inputs, relationship pagination or a new quota model requires a deliberate specification and implementation change. Do not hide several network calls inside one adapter request: each outbound attempt must reserve quota through the executor.

## 2. Register the ID and typed evidence

In [src/domain.rs](src/domain.rs):

- Add `Acme` to `ProviderId`, its `ALL` array, `as_str()` and `parse()`. Preserve stable IDs and lexicographic order for default selection.
- Define an `AcmeSummary` struct with typed, provider-specific fields and add a variant to `Summary`. Use `Option<T>` for absent evidence, preserve numeric zero when supplied, and emit required nullable fields as null. Do not combine vendor scores.
- Keep upstream DTOs separate from the public summary. Validate known fields and required report identity; unknown upstream fields may survive in the raw JSON.

`Summary` currently uses Serde's **untagged** representation and is also persisted in cache payloads. Its existing summary structs use `deny_unknown_fields`. Design the new serialized shape so it cannot deserialize as another variant, and verify round trips, including all-null optional evidence. If shapes overlap, change the persisted representation deliberately while preserving the public response and versioning the affected cache payloads.

## 3. Add startup configuration

In [src/config.rs](src/config.rs), add an `acme: ProviderConfig` field to `Config` and register these exact names in the `SETTINGS` allowlist:

```text
ENRICH_ACME_ENABLED
ENRICH_ACME_API_KEY
ENRICH_ACME_API_KEY_FILE
ENRICH_ACME_MAX_CONCURRENCY
ENRICH_ACME_REQUESTS_PER_MINUTE
ENRICH_ACME_REQUESTS_PER_DAY
```

Extend `Config::from_map()` with explicit parsing and documented defaults. Add the provider to `Config::validate()`'s provider loop and its at-least-one-enabled condition. Update `Config::for_tests()` and direct configuration construction in tests as needed. Providers default to disabled; enabled providers require credentials. Use the existing `Secret` and `read_secret()` handling so `_API_KEY` and `_API_KEY_FILE` remain mutually exclusive and diagnostics remain redacted.

Choose limits for the actual account: concurrency must be positive and no greater than global outbound capacity; the daily budget must be positive; a zero minute budget means no additional local minute cap. The existing model supports a rolling minute and a UTC day. Monthly, weighted or non-UTC quota models need an explicit accounting design before integration.

Add provider-specific lookup options with strict validation. Do not add a production origin override or accept API endpoints from the enrichment request.

## 4. Implement request construction and decoding

[src/providers.rs](src/providers.rs) currently contains one concrete `Adapter` selected by `ProviderId`. Extend its explicit branches, or extract a small vendor module when useful; a generic plugin framework is unnecessary.

| Adapter method | Required change |
| --- | --- |
| `new()` | Add the compiled HTTPS origin and any required typed construction options. Preserve sensitive headers, certificate verification, HTTPS-only production requests, disabled redirects and client reuse. |
| `supports()` | Replace the current two-provider boolean expression with an exhaustive match on provider ID and explicitly allow only supported kinds. |
| `payload_version()` | Return the adapter's version, starting at 1 for a new provider. Use a per-provider match so future changes invalidate only the affected provider's cache. |
| `cache_options()` | Return a deterministic JSON object containing all report-affecting options. Exclude credentials, request IDs and `include_raw`. |
| `request()` | Build a `RequestBuilder` for the fixed report endpoint using encoded query parameters/path segments and `indicator.lookup_value`. Apply only provider authentication. |
| `decode()` | Map documented HTTP/error outcomes and dispatch successful raw JSON to a vendor-specific decoder. Preserve the common summary byte cap and outcome construction. |

For an IP-only `acme` adapter, the capability change would look like this **after registering `Acme`**:

```rust
pub fn supports(&self, kind: IndicatorKind) -> bool {
    match self.id {
        ProviderId::Abuseipdb | ProviderId::Acme => kind == IndicatorKind::Ip,
        ProviderId::Virustotal => true,
    }
}
```

Derive Serde DTOs for the upstream envelope and write a decoder returning the existing `DecodedSummary` type. Require an identity matching the lookup according to the provider's documented semantics. Reject invalid wrappers, wrong known types, invalid timestamps and invalid count ranges with `InvalidResponse`. Map a missing report only from an explicit documented outcome; a zero score is still a successful report. Keep upstream error text out of public errors and logs.

The adapter constructs and decodes requests; **it must not call `.send()` itself**. [src/enrichment.rs](src/enrichment.rs) owns transport, streamed body limits, retries, shared work, deadlines, permits and quota reservations. This ensures every attempt, including a retry, is accounted for before dispatch. Continue using `Adapter::for_test()` to supply loopback origins only in test builds.

## 5. Wire execution, cache and durable quotas

In [src/enrichment.rs](src/enrichment.rs), add the provider to `Enrichment::new()`'s construction list, `with_adapters()`'s configuration match and `enabled()`'s ordered selection. Default selection must stay lexicographic; explicit request order must remain unchanged. Review `feedback_from_headers()` for vendor-specific remaining/reset headers; generic Retry-After handling already exists.

Use the existing cache-key builder. It includes provider ID, payload version, indicator kind, hash algorithm, lookup value and adapter options. A result-affecting option or payload mapping change must alter this identity appropriately. Never fetch again solely to satisfy `include_raw=true`.

In [src/storage.rs](src/storage.rs), add the new provider's `QuotaLimits` field, initialize it from configuration in `Storage::open()`, include it in limit validation, and extend `limits()`, `provider_name()` and `quota_group()`. Pick a stable quota group such as `acme_reports`; kinds sharing an upstream budget must share that group. Quota identity must not change with credentials, cache versions or provider releases.

**Database upgrades are part of adding a provider.** `Storage::initialize()` currently initializes and validates the two existing quota groups explicitly. On an existing version-1 database, merely adding `acme_reports` to those validation loops will fail because the row does not exist. The current initializer embeds the initial SQL directly; it is not a general migration runner.

Add a numbered migration under [migrations](migrations), advance `SCHEMA_VERSION`, and extend initialization to apply that upgrade transactionally to existing databases and to fresh databases after the initial schema. Insert only the newly introduced group's state, using the service clock for its initial UTC day, and preserve existing usage, attempt timestamps, cooldowns and clock high-water state. Add the new group to post-migration validation. Do not rewrite the original migration or use a general upsert that silently recreates missing historical quota rows. Missing established quota history must still fail startup.

Test migration from an actual version-1 database with existing consumed quota and a cooldown, then reopen it after upgrade. Existing provider allowances must not increase. Also test a fresh database, a second open after upgrade, and a database missing an established quota row. Existing cache entries should remain readable or miss safely according to their payload versions.

Adding providers increases the number of result slots. Recheck the 20-indicator batch against the fixed 16 KiB summary cap, 1 MiB non-raw envelope cap and configured raw budget, including duplicate entries. Update [SPEC.md](SPEC.md) where it describes two providers or 40 default result slots; do not silently raise response or concurrency limits.

## 6. Make the provider configurable for other users

After implementation, document a working local launch with the new provider. For example, this POSIX configuration would enable only the new adapter in a shell without other `ENRICH_` overrides:

```sh
ENRICH_SERVICE_TOKEN_FILE=./secrets/service_token \
ENRICH_ACME_ENABLED=true \
ENRICH_ACME_API_KEY_FILE=./secrets/acme_api_key \
ENRICH_ACME_MAX_CONCURRENCY=2 \
ENRICH_ACME_REQUESTS_PER_MINUTE=4 \
ENRICH_ACME_REQUESTS_PER_DAY=100 \
cargo run --locked
```

The numeric values above illustrate local budgets only; replace them with documented limits for the new integration. In PowerShell, set the same variables through `$env:NAME = 'value'` before running Cargo. Explain how to obtain the key, supported kinds, lookup options and the provider's permitted usage.

For Docker, follow [compose.virustotal.yaml](compose.virustotal.yaml): forward non-secret variables in `environment`, use an `_API_KEY_FILE` path under `/run/secrets/`, add the service's secret mount and declare a top-level secret backed by `./secrets/acme_api_key`. Include only non-secret overrides in [.env.example](.env.example). Changes to `.env` alone do not add environment variables to a container. Rebuild and recreate the container with `docker compose ... up --build --detach`, retaining its volume.

An implemented provider can then be selected explicitly in a request (this example is rejected until `acme` is compiled in):

```json
{
  "indicators": [{"type": "ip", "value": "192.0.2.10"}],
  "providers": ["acme"],
  "include_raw": false
}
```

Omitting `providers` selects all enabled providers. A compiled but disabled provider returns `disabled` when selected explicitly; an enabled provider with an incompatible indicator returns `unsupported`. Both cases must make zero provider calls.

Update `PROVIDERS`, command help, validation messages and response checks in [tools/smoke_client.py](tools/smoke_client.py), whose accepted IDs are currently restricted to the two demo providers. Update [tools/test_smoke_client.py](tools/test_smoke_client.py) alongside it so the supplied indicator-file client can exercise the new adapter.

## Verify before a pull request

Add synthetic fixtures under [tests/fixtures](tests/fixtures) and explain their provenance in the fixture README. Fixtures must contain no real credentials, private indicators or captured raw operational reports. The application and upstream harnesses have two-provider assumptions (provider indexes, counters, routing and constructed adapters) in [tests/application/mod.rs](tests/application/mod.rs) and [tests/upstream/mod.rs](tests/upstream/mod.rs); extend them explicitly. These modules are included through the crate's test-only wiring in [src/lib.rs](src/lib.rs).

Verify observable behavior, including:

- Supported/unsupported kinds, strict request encoding and fixed origin, matching identity, omitted versus zero fields, unknown upstream fields and complete raw preservation.
- Missing reports, authentication/access errors, 429 and Retry-After, transient failures, malformed/oversized bodies, redirects, TLS failure and timeouts, while another provider succeeds.
- Invalid requests, disabled providers and unsupported pairs making zero calls; stable input/provider ordering and correct default provider selection.
- Duplicate lookup coalescing, concurrency limits, cancellation, cache reuse/reopen, payload/option isolation and output budgets with the additional provider.
- Durable reservations on every attempt; no dispatch on storage failure; quota/cooldown persistence across restart, migration, key rotation and cache version changes.

Run the checks in [CONTRIBUTING.md](CONTRIBUTING.md) and update the provider/configuration tables, examples and verification record with what was actually tested. Default tests and CI must continue to run without provider credentials or live quota.

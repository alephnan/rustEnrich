//! Upstream transport regressions using loopback sockets and durable local quota state.

use super::*;
use crate::{
    clock::TestClock,
    domain::{IndicatorKind, validate_indicator},
};
use flate2::{Compression, write::GzEncoder};
use serde_json::json;
use std::{
    io::Write,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

struct WireServer {
    origin: String,
    calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl WireServer {
    async fn new(replies: Vec<Vec<u8>>, tls: bool) -> Self {
        assert!(!replies.is_empty());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = calls.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let index = recorded
                    .fetch_add(1, Ordering::SeqCst)
                    .min(replies.len() - 1);
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    let count = socket.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if tls || request.windows(4).any(|part| part == b"\r\n\r\n") {
                        break;
                    }
                    assert!(request.len() <= 16 * 1024);
                }
                // The client can stop consuming as soon as its byte cap is crossed.
                let _ = socket.write_all(&replies[index]).await;
                let _ = socket.shutdown().await;
            }
        });
        Self {
            origin: format!("{}://{address}", if tls { "https" } else { "http" }),
            calls,
            task,
        }
    }

    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for WireServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Harness {
    service: Arc<Enrichment>,
    clock: Arc<TestClock>,
    mock: WireServer,
    _directory: tempfile::TempDir,
}

impl Harness {
    async fn new(mut config: Config, replies: Vec<Vec<u8>>, tls: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        config.database_path = directory.path().join("upstream.sqlite");
        config.validate().unwrap();
        let clock = Arc::new(TestClock(Mutex::new(
            DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )));
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        let mock = WireServer::new(replies, tls).await;
        let adapter = Adapter::for_test(ProviderId::Abuseipdb, &mock.origin);
        let service =
            Enrichment::with_adapters(Arc::new(config), storage, clock.clone(), vec![adapter]);
        Self {
            service,
            clock,
            mock,
            _directory: directory,
        }
    }

    async fn lookup(&self, value: &str) -> LookupResult {
        self.service
            .lookup(
                ProviderId::Abuseipdb,
                validate_indicator(IndicatorKind::Ip, value).unwrap(),
                Instant::now() + Duration::from_secs(5),
                "upstream-test",
            )
            .await
    }

    async fn close(&self) {
        self.service.begin_shutdown();
        self.service
            .drain(Instant::now() + Duration::from_secs(2))
            .await;
        self.service.storage.close().await;
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.service.cancel();
    }
}

fn config() -> Config {
    let mut config = Config::for_tests();
    config.virustotal.enabled = false;
    config.connect_timeout = Duration::from_millis(200);
    config.provider_timeout = Duration::from_millis(500);
    config.lookup_timeout = Duration::from_secs(2);
    config.request_timeout = Duration::from_secs(3);
    config
}

fn report(ip: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"data":{"ipAddress":ip,"abuseConfidenceScore":0}})).unwrap()
}

fn response(
    status: u16,
    headers: &[(&str, String)],
    body: &[u8],
    declared_length: Option<usize>,
) -> Vec<u8> {
    let mut reply = format!(
        "HTTP/1.1 {status} Synthetic\r\nContent-Type: application/json\r\nConnection: close\r\n"
    );
    for (name, value) in headers {
        reply.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(length) = declared_length {
        reply.push_str(&format!("Content-Length: {length}\r\n"));
    }
    reply.push_str("\r\n");
    let mut bytes = reply.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn successful(ip: &str) -> Vec<u8> {
    let body = report(ip);
    response(200, &[], &body, Some(body.len()))
}

#[tokio::test]
async fn gzip_limit_applies_to_decoded_bytes_for_success_and_error_bodies() {
    let body =
        serde_json::to_vec(&json!({"data":{"ipAddress":"8.8.8.8"},"extension":"x".repeat(8192)}))
            .unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&body).unwrap();
    let compressed = encoder.finish().unwrap();
    assert!(compressed.len() < 256);
    for status in [200, 503] {
        let mut config = config();
        config.max_provider_bytes = 256;
        let wire = response(
            status,
            &[("Content-Encoding", "gzip".to_owned())],
            &compressed,
            Some(compressed.len()),
        );
        let harness = Harness::new(config, vec![wire], false).await;
        let result = harness.lookup("8.8.8.8").await;
        assert_eq!(
            result.outcome.error.as_ref().unwrap().code,
            ErrorCode::ResponseTooLarge
        );
        assert!(result.outcome.raw.is_none());
        assert!(result.outcome.summary.is_none());
        assert_eq!(
            harness.mock.count(),
            1,
            "oversized errors must not be retried"
        );
        harness.close().await;
    }
}

#[tokio::test]
async fn malformed_and_truncated_bodies_fail_without_retry_or_sensitive_error_text() {
    let valid = report("8.8.8.8");
    let malformed = b"{\"data\":{\"ipAddress\":\"8.8.8.8\",\"isp\":\"private-upstream-text\"";
    for reply in [
        response(200, &[], malformed, Some(malformed.len())),
        response(200, &[], &valid, Some(valid.len() + 10_000)),
        response(200, &[], &valid, Some(1)),
        response(
            200,
            &[],
            br#"{"data":{"ipAddress":"8.8.8.8","totalReports":"private-upstream-text"}}"#,
            None,
        ),
    ] {
        let harness = Harness::new(config(), vec![reply], false).await;
        let result = harness.lookup("8.8.8.8").await;
        assert_eq!(
            result.outcome.error.as_ref().unwrap().code,
            ErrorCode::InvalidResponse
        );
        assert!(result.outcome.raw.is_none());
        assert!(result.outcome.fetched_at.is_none());
        assert!(
            !serde_json::to_string(&*result.outcome)
                .unwrap()
                .contains("private-upstream-text")
        );
        assert_eq!(harness.mock.count(), 1);
        harness.close().await;
    }
}

#[tokio::test]
async fn missing_length_header_cannot_bypass_streamed_body_cap() {
    let body =
        serde_json::to_vec(&json!({"data":{"ipAddress":"8.8.8.8"},"extension":"a".repeat(2048)}))
            .unwrap();
    let mut config = config();
    config.max_provider_bytes = 256;
    let harness = Harness::new(config, vec![response(200, &[], &body, None)], false).await;
    let result = harness.lookup("8.8.8.8").await;
    assert_eq!(
        result.outcome.error.as_ref().unwrap().code,
        ErrorCode::ResponseTooLarge
    );
    assert_eq!(harness.mock.count(), 1);
    harness.close().await;
}

#[tokio::test]
async fn compact_raw_serialization_is_capped_independently_of_received_bytes() {
    // 1e1 is three input bytes, but serde emits 10.0 as four bytes.
    let body = format!(
        "{{\"data\":{{\"ipAddress\":\"8.8.8.8\"}},\"extension\":[{}]}}",
        vec!["1e1"; 128].join(",")
    )
    .into_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(serde_json::to_vec(&parsed).unwrap().len() > body.len());
    let mut config = config();
    config.max_provider_bytes = body.len();
    let harness = Harness::new(
        config,
        vec![response(200, &[], &body, Some(body.len()))],
        false,
    )
    .await;
    let result = harness.lookup("8.8.8.8").await;
    assert_eq!(
        result.outcome.error.as_ref().unwrap().code,
        ErrorCode::ResponseTooLarge
    );
    assert_eq!(harness.mock.count(), 1);
    harness.close().await;
}

#[tokio::test]
async fn long_retry_after_prevents_an_attempt_that_cannot_fit_and_persists_cooldown() {
    let harness = Harness::new(
        config(),
        vec![
            response(
                503,
                &[("Retry-After", "60".to_owned())],
                b"upstream unavailable",
                Some(20),
            ),
            successful("1.1.1.1"),
        ],
        false,
    )
    .await;
    let first = harness.lookup("8.8.8.8").await;
    assert_eq!(
        first.outcome.error.as_ref().unwrap().code,
        ErrorCode::ProviderUnavailable
    );
    assert_eq!(harness.mock.count(), 1);
    let second = harness.lookup("1.1.1.1").await;
    let error = second.outcome.error.as_ref().unwrap();
    assert_eq!(error.code, ErrorCode::QuotaExhausted);
    assert_eq!(error.retry_after_seconds, Some(60));
    assert_eq!(harness.mock.count(), 1);
    *harness.clock.0.lock().unwrap() += chrono::Duration::seconds(60);
    assert_eq!(harness.lookup("1.1.1.1").await.outcome.status, Status::Ok);
    assert_eq!(harness.mock.count(), 2);
    harness.close().await;
}

#[tokio::test]
async fn transient_failure_retries_once_and_each_attempt_consumes_durable_quota() {
    let mut config = config();
    config.abuseipdb.requests_per_day = 2;
    let harness = Harness::new(
        config,
        vec![
            response(503, &[], b"unavailable", Some(11)),
            successful("8.8.8.8"),
        ],
        false,
    )
    .await;
    assert_eq!(harness.lookup("8.8.8.8").await.outcome.status, Status::Ok);
    assert_eq!(harness.mock.count(), 2);
    let second = harness.lookup("1.1.1.1").await;
    assert_eq!(
        second.outcome.error.as_ref().unwrap().code,
        ErrorCode::QuotaExhausted
    );
    assert_eq!(harness.mock.count(), 2);
    harness.close().await;
}

#[tokio::test]
async fn unknown_429_reset_is_not_retried_and_remains_unknown_during_fallback_cooldown() {
    let body = b"unknown provider monthly quota";
    let harness = Harness::new(
        config(),
        vec![
            response(429, &[], body, Some(body.len())),
            successful("1.1.1.1"),
        ],
        false,
    )
    .await;
    for ip in ["8.8.8.8", "1.1.1.1"] {
        let result = harness.lookup(ip).await;
        let error = result.outcome.error.as_ref().unwrap();
        assert_eq!(error.code, ErrorCode::QuotaExhausted);
        assert!(error.retry_after_seconds.is_none());
    }
    assert_eq!(harness.mock.count(), 1);
    *harness.clock.0.lock().unwrap() += chrono::Duration::seconds(60);
    assert_eq!(harness.lookup("1.1.1.1").await.outcome.status, Status::Ok);
    assert_eq!(harness.mock.count(), 2);
    harness.close().await;
}

#[tokio::test]
async fn tls_failure_is_not_retried_or_returned_with_transport_details() {
    // A loopback TLS peer sends a fatal bad_certificate alert to the ClientHello.
    // Certificate verification stays enabled in the adapter's real Reqwest client.
    let alert = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2a];
    let harness = Harness::new(config(), vec![alert], true).await;
    let result = harness.lookup("8.8.8.8").await;
    let error = result.outcome.error.as_ref().unwrap();
    assert_eq!(error.code, ErrorCode::ProviderTlsError);
    assert!(!error.retryable);
    assert_eq!(harness.mock.count(), 1);
    assert!(!error.message.contains(&harness.mock.origin));
    harness.close().await;
}

#[test]
fn retry_after_parses_dates_and_seconds_and_rounds_up() {
    let now = DateTime::from_timestamp(1_800_000_000, 250_000_000).unwrap();
    assert_eq!(
        parse_retry_after(Some("60"), now),
        Some(Duration::from_secs(60))
    );
    let future = DateTime::from_timestamp(1_800_000_010, 0).unwrap();
    let http_date = httpdate::fmt_http_date(future.into());
    assert_eq!(
        parse_retry_after(Some(&http_date), now),
        Some(Duration::from_secs(10))
    );
    let past = DateTime::from_timestamp(1_799_999_990, 0).unwrap();
    assert_eq!(
        parse_retry_after(Some(&httpdate::fmt_http_date(past.into())), now),
        Some(Duration::ZERO)
    );
    for invalid in ["", "-1", "1.5", "unknown", "999999999999999999999999999"] {
        assert!(parse_retry_after(Some(invalid), now).is_none());
    }
}

#[test]
fn cache_identity_isolates_provider_options_and_versions_but_not_credentials_or_presentation() {
    let adapter = |provider, key, days, version| {
        Adapter::new(
            provider,
            key,
            days,
            Duration::from_secs(2),
            Duration::from_secs(5),
        )
        .unwrap()
        .with_test_payload_version(version)
    };
    let abuse = adapter(ProviderId::Abuseipdb, "original-test-key", 30, 1);
    let ip = validate_indicator(IndicatorKind::Ip, "2001:db8::1").unwrap();
    let key = cache_key(&abuse, &ip).unwrap();
    assert_eq!(key.len(), 64);
    for different in [
        adapter(ProviderId::Virustotal, "original-test-key", 30, 1),
        adapter(ProviderId::Abuseipdb, "original-test-key", 90, 1),
        adapter(ProviderId::Abuseipdb, "original-test-key", 30, 2),
    ] {
        assert_ne!(key, cache_key(&different, &ip).unwrap());
    }
    let rotated = adapter(ProviderId::Abuseipdb, "rotated-test-key", 30, 1);
    assert_eq!(key, cache_key(&rotated, &ip).unwrap());
    let equivalent = validate_indicator(IndicatorKind::Ip, "2001:0db8:0:0:0:0:0:1").unwrap();
    assert_eq!(key, cache_key(&abuse, &equivalent).unwrap());
    let mapped = validate_indicator(IndicatorKind::Ip, "::ffff:192.0.2.1").unwrap();
    let ipv4 = validate_indicator(IndicatorKind::Ip, "192.0.2.1").unwrap();
    assert_ne!(
        cache_key(&abuse, &mapped).unwrap(),
        cache_key(&abuse, &ipv4).unwrap()
    );

    let vt = adapter(ProviderId::Virustotal, "test-key", 30, 1);
    let url =
        validate_indicator(IndicatorKind::Url, "https://example.com/?a=1&b=2#fragment").unwrap();
    let url_key = cache_key(&vt, &url).unwrap();
    for spelling in [
        "https://EXAMPLE.com/?a=1&b=2#fragment",
        "https://example.com/?b=2&a=1#fragment",
        "https://example.com/?a=1&b=2#other",
    ] {
        assert_ne!(
            url_key,
            cache_key(
                &vt,
                &validate_indicator(IndicatorKind::Url, spelling).unwrap()
            )
            .unwrap()
        );
    }
    let md5 = validate_indicator(IndicatorKind::Hash, "d41d8cd98f00b204e9800998ecf8427e").unwrap();
    let uppercase =
        validate_indicator(IndicatorKind::Hash, "D41D8CD98F00B204E9800998ECF8427E").unwrap();
    let sha1 = validate_indicator(
        IndicatorKind::Hash,
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    )
    .unwrap();
    let sha256 = validate_indicator(
        IndicatorKind::Hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    assert_eq!(
        cache_key(&vt, &md5).unwrap(),
        cache_key(&vt, &uppercase).unwrap()
    );
    assert_ne!(
        cache_key(&vt, &md5).unwrap(),
        cache_key(&vt, &sha1).unwrap()
    );
    assert_ne!(
        cache_key(&vt, &md5).unwrap(),
        cache_key(&vt, &sha256).unwrap()
    );

    let raw_request = |include_raw| {
        crate::domain::validate_request(
        &serde_json::to_vec(&json!({"indicators":[{"type":"ip","value":"2001:db8::1"}],"include_raw":include_raw})).unwrap(),
        20, &ProviderId::ALL).unwrap()
    };
    assert_eq!(
        cache_key(&abuse, &raw_request(false).indicators[0]).unwrap(),
        cache_key(&abuse, &raw_request(true).indicators[0]).unwrap()
    );
}

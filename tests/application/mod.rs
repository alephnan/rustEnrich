//! Application acceptance tests use local provider endpoints and temporary state.

use crate::{
    clock::TestClock,
    config::Config,
    domain::{IndicatorKind, ProviderId, Status, validate_indicator},
    enrichment::Enrichment,
    http::{HttpState, router},
    providers::Adapter,
    storage::Storage,
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
};
use chrono::DateTime;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Semaphore, task::JoinHandle, time::Instant};
use tower::ServiceExt;

struct MockReply {
    status: u16,
    body: Vec<u8>,
    headers: HeaderMap,
}

impl MockReply {
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(&value).unwrap(),
            headers: HeaderMap::new(),
        }
    }
}

type ReplyFactory = dyn Fn(ProviderId, &str, usize) -> MockReply + Send + Sync;

struct MockState {
    replies: Arc<ReplyFactory>,
    gate: Option<Arc<Semaphore>>,
    calls: [AtomicUsize; 2],
    active: [AtomicUsize; 2],
    peak: [AtomicUsize; 2],
    all_active: AtomicUsize,
    all_peak: AtomicUsize,
    started: tokio::sync::Notify,
}

impl MockState {
    fn calls(&self, provider: ProviderId) -> usize {
        self.calls[provider_index(provider)].load(Ordering::SeqCst)
    }

    async fn wait_for_calls(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let notified = self.started.notified();
                if self
                    .calls
                    .iter()
                    .map(|value| value.load(Ordering::SeqCst))
                    .sum::<usize>()
                    >= count
                {
                    break;
                }
                notified.await;
            }
        })
        .await
        .expect("mock provider calls did not begin");
    }

    fn release(&self, count: usize) {
        self.gate
            .as_ref()
            .expect("test requires a gate")
            .add_permits(count);
    }
}

fn provider_index(provider: ProviderId) -> usize {
    match provider {
        ProviderId::Abuseipdb => 0,
        ProviderId::Virustotal => 1,
    }
}

struct ActiveCall {
    state: Arc<MockState>,
    index: usize,
}

impl Drop for ActiveCall {
    fn drop(&mut self) {
        self.state.active[self.index].fetch_sub(1, Ordering::SeqCst);
        self.state.all_active.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn mock_provider(State(state): State<Arc<MockState>>, request: Request) -> Response {
    let uri = request.uri().to_string();
    let provider = if request.uri().path() == "/api/v2/check" {
        ProviderId::Abuseipdb
    } else {
        ProviderId::Virustotal
    };
    let index = provider_index(provider);
    let attempt = state.calls[index].fetch_add(1, Ordering::SeqCst) + 1;
    let active = state.active[index].fetch_add(1, Ordering::SeqCst) + 1;
    state.peak[index].fetch_max(active, Ordering::SeqCst);
    let all_active = state.all_active.fetch_add(1, Ordering::SeqCst) + 1;
    state.all_peak.fetch_max(all_active, Ordering::SeqCst);
    let _guard = ActiveCall {
        state: state.clone(),
        index,
    };
    assert_eq!(request.method(), Method::GET);
    assert_eq!(request.headers()["accept"], "application/json");
    assert!(!request.headers().contains_key("authorization"));
    assert_eq!(
        request.headers()[if index == 0 { "key" } else { "x-apikey" }],
        "sanitized-test-key"
    );
    state.started.notify_one();
    if let Some(gate) = &state.gate {
        gate.acquire().await.unwrap().forget();
    } else {
        tokio::task::yield_now().await;
    }
    let reply = (state.replies)(provider, &uri, attempt);
    // Always stream chunks: tests exercise byte consumption instead of relying
    // on provider Content-Length declarations.
    let chunks: Vec<_> = reply
        .body
        .chunks(128)
        .map(|chunk| Ok::<_, Infallible>(Bytes::copy_from_slice(chunk)))
        .collect();
    let mut response = Response::new(Body::from_stream(futures_util::stream::iter(chunks)));
    *response.status_mut() = StatusCode::from_u16(reply.status).unwrap();
    *response.headers_mut() = reply.headers;
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    response
}

struct MockServer {
    origin: String,
    state: Arc<MockState>,
    task: JoinHandle<()>,
}

impl MockServer {
    async fn new(replies: Arc<ReplyFactory>, gated: bool) -> Self {
        let state = Arc::new(MockState {
            replies,
            gate: gated.then(|| Arc::new(Semaphore::new(0))),
            calls: [AtomicUsize::new(0), AtomicUsize::new(0)],
            active: [AtomicUsize::new(0), AtomicUsize::new(0)],
            peak: [AtomicUsize::new(0), AtomicUsize::new(0)],
            all_active: AtomicUsize::new(0),
            all_peak: AtomicUsize::new(0),
            started: tokio::sync::Notify::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .fallback(mock_provider)
            .with_state(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            origin,
            state,
            task,
        }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Harness {
    state: HttpState,
    service: Arc<Enrichment>,
    mock: MockServer,
    clock: Arc<TestClock>,
    _directory: tempfile::TempDir,
}

impl Harness {
    async fn new(mut config: Config, replies: Arc<ReplyFactory>, gated: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        config.database_path = directory.path().join("state.sqlite");
        config.validate().unwrap();
        let clock = Arc::new(TestClock(Mutex::new(
            DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )));
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        let mock = MockServer::new(replies, gated).await;
        let adapters = [
            (ProviderId::Abuseipdb, config.abuseipdb.enabled),
            (ProviderId::Virustotal, config.virustotal.enabled),
        ]
        .into_iter()
        .filter(|(_, enabled)| *enabled)
        .map(|(provider, _)| Adapter::for_test(provider, &mock.origin))
        .collect();
        let service = Enrichment::with_adapters(Arc::new(config), storage, clock.clone(), adapters);
        Self {
            state: HttpState::new(service.clone()),
            service,
            mock,
            clock,
            _directory: directory,
        }
    }

    async fn standard() -> Self {
        Self::new(Config::for_tests(), Arc::new(success_reply), false).await
    }

    fn request(&self, body: Body) -> Request {
        Request::builder()
            .method("POST")
            .uri("/v1/enrich")
            .header(
                "authorization",
                format!(
                    "Bearer {}",
                    self.service.config.service_token.expose_secret()
                ),
            )
            .header("content-type", "application/json")
            .body(body)
            .unwrap()
    }

    async fn post(&self, value: Value) -> (StatusCode, HeaderMap, Value) {
        let response = router(self.state.clone())
            .oneshot(self.request(Body::from(serde_json::to_vec(&value).unwrap())))
            .await
            .unwrap();
        read_response(response).await
    }

    async fn finish(&self) {
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

async fn read_response(response: Response) -> (StatusCode, HeaderMap, Value) {
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parts.headers["content-type"], "application/json");
    assert_eq!(parts.headers["cache-control"], "no-store");
    let request_id = value["request_id"].as_str().unwrap();
    assert_eq!(parts.headers["x-request-id"], request_id);
    assert_eq!(
        uuid::Uuid::parse_str(request_id).unwrap().get_version_num(),
        4
    );
    (parts.status, parts.headers, value)
}

fn lookup_value(provider: ProviderId, uri: &str) -> String {
    let parsed = url::Url::parse(&format!("http://127.0.0.1{uri}")).unwrap();
    if provider == ProviderId::Abuseipdb {
        assert_eq!(parsed.path(), "/api/v2/check");
        assert!(!parsed.query_pairs().any(|(name, _)| name == "verbose"));
        assert!(
            parsed
                .query_pairs()
                .any(|(name, value)| name == "maxAgeInDays" && value == "30")
        );
        parsed
            .query_pairs()
            .find(|(name, _)| name == "ipAddress")
            .unwrap()
            .1
            .into_owned()
    } else {
        let segment = parsed.path_segments().unwrap().next_back().unwrap();
        url::form_urlencoded::parse(format!("value={segment}").as_bytes())
            .next()
            .unwrap()
            .1
            .into_owned()
    }
}

fn success_raw(provider: ProviderId, uri: &str) -> Value {
    let value = lookup_value(provider, uri);
    match provider {
        ProviderId::Abuseipdb => {
            json!({"data":{"ipAddress":value,"abuseConfidenceScore":0,"isPublic":true}})
        }
        ProviderId::Virustotal if uri.contains("/urls/") => {
            json!({"data":{"id":"a".repeat(64),"type":"url","attributes":{"reputation":-2}}})
        }
        ProviderId::Virustotal => {
            json!({"data":{"id":value,"type":"ip_address","attributes":{"reputation":-2,"last_analysis_stats":{"malicious":0}}}})
        }
    }
}

fn success_reply(provider: ProviderId, uri: &str, _attempt: usize) -> MockReply {
    MockReply::json(200, success_raw(provider, uri))
}

fn one_ip(ip: &str, provider: &str) -> Value {
    json!({"indicators":[{"type":"ip","value":ip}],"providers":[provider]})
}

fn quick_config() -> Config {
    let mut config = Config::for_tests();
    config.connect_timeout = Duration::from_millis(30);
    config.provider_timeout = Duration::from_millis(100);
    config.lookup_timeout = Duration::from_millis(800);
    config.request_timeout = Duration::from_secs(2);
    config.storage_timeout = Duration::from_millis(300);
    config.virustotal.requests_per_minute = 100;
    config
}

#[tokio::test]
async fn ordered_duplicates_share_work_and_raw_requests_reuse_the_cached_report() {
    let harness = Harness::standard().await;
    let body = json!({"indicators":[{"type":"ip","value":"2001:0db8::1"},{"type":"ip","value":"2001:db8::1"},{"type":"url","value":"HTTPS://EXAMPLE.com:443/a?b=%2f#Frag"}],"providers":["virustotal","abuseipdb"]});
    let (status, _, first) = harness.post(body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first.as_object().unwrap().len(), 2);
    let results = first["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    for (index, result) in results.iter().enumerate() {
        assert_eq!(result["index"], index);
        assert_eq!(result["providers"][0]["provider"], "virustotal");
        assert_eq!(result["providers"][1]["provider"], "abuseipdb");
        for provider in result["providers"].as_array().unwrap() {
            for field in [
                "summary",
                "fetched_at",
                "provider_updated_at",
                "cache",
                "error",
            ] {
                assert!(
                    provider.get(field).is_some(),
                    "missing nullable field {field}"
                );
            }
            assert!(provider.get("raw").is_none());
            assert!(provider.get("raw_omitted_reason").is_none());
        }
    }
    assert_eq!(results[0]["input"]["value"], "2001:0db8::1");
    assert_eq!(results[0]["lookup_value"], "2001:db8::1");
    assert_eq!(results[2]["lookup_value"], body["indicators"][2]["value"]);
    assert_eq!(results[2]["providers"][1]["status"], "unsupported");
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
    assert_eq!(harness.mock.state.calls(ProviderId::Virustotal), 2);
    let mut raw_body = body;
    raw_body["include_raw"] = json!(true);
    let (_, _, second) = harness.post(raw_body).await;
    for index in 0..2 {
        for provider in 0..2 {
            assert_eq!(
                second["results"][index]["providers"][provider]["cache"]["hit"],
                true
            );
            assert_eq!(
                second["results"][index]["providers"][provider]["fetched_at"],
                first["results"][index]["providers"][provider]["fetched_at"]
            );
            assert!(second["results"][index]["providers"][provider]["raw"].is_object());
        }
    }
    assert_eq!(
        second["results"][2]["providers"][1]["raw_omitted_reason"],
        "not_available"
    );
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
    assert_eq!(harness.mock.state.calls(ProviderId::Virustotal), 2);
    harness.finish().await;
}

#[tokio::test]
async fn disabled_precedes_unsupported_and_omitted_providers_select_enabled_only() {
    let mut config = Config::for_tests();
    config.abuseipdb.enabled = false;
    let harness = Harness::new(config, Arc::new(success_reply), false).await;
    let (_, _, response) = harness.post(json!({"indicators":[{"type":"url","value":"https://example.com/"}],"providers":["abuseipdb"],"include_raw":true})).await;
    let result = &response["results"][0]["providers"][0];
    assert_eq!(result["status"], "disabled");
    assert_eq!(result["raw_omitted_reason"], "not_available");
    assert!(result["error"].is_null());
    assert!(result["summary"].is_null());
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 0);
    let (_, _, response) = harness
        .post(json!({"indicators":[{"type":"ip","value":"8.8.8.8"}]}))
        .await;
    assert_eq!(
        response["results"][0]["providers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        response["results"][0]["providers"][0]["provider"],
        "virustotal"
    );
    harness.finish().await;
}

#[tokio::test]
async fn authentication_precedes_parsing_and_invalid_batches_never_call_providers() {
    let harness = Harness::standard().await;
    let unauthenticated = Request::builder()
        .method("POST")
        .uri("/v1/enrich")
        .body(Body::from("invalid and sensitive body"))
        .unwrap();
    let (status, headers, error) = read_response(
        router(harness.state.clone())
            .oneshot(unauthenticated)
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers["www-authenticate"], "Bearer");
    assert_eq!(error["error"]["code"], "unauthorized");
    for body in [
        br#"{"indicators":[],"indicators":[]}"#.as_slice(),
        br#"{"indicators":[{"type":"ip","type":"url","value":"8.8.8.8"}]}"#,
        b"not json",
        &[0xff],
    ] {
        let (status, _, error) = read_response(
            router(harness.state.clone())
                .oneshot(harness.request(Body::from(body.to_vec())))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error["error"]["code"], "invalid_json");
    }
    for body in [
        json!({"indicators":[{"type":"ip","value":"8.8.8.8"},{"type":"ip","value":"private-invalid-value"}]}),
        json!({"indicators":[{"type":"url","value":"https://example.com/%xx"}]}),
        json!({"indicators":[],"extra":"private-marker"}),
        json!({"indicators":null}),
        json!({"indicators":[{"type":"ip","value":"8.8.8.8"}],"providers":["unknown"]}),
        json!({"indicators":[{"type":"ip","value":"8.8.8.8"}],"providers":["abuseipdb","abuseipdb"]}),
        json!({"indicators":[{"type":"ip","value":"8.8.8.8"}],"include_raw":null}),
        json!({"indicators":vec![json!({"type":"ip","value":"8.8.8.8"});21]}),
    ] {
        let (status, _, error) = harness.post(body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error["error"]["code"], "validation_error");
        assert!(error["error"]["details"].is_array());
        let text = error.to_string();
        assert!(!text.contains("private-marker"));
        assert!(!text.contains("private-invalid-value"));
        assert!(!text.contains("8.8.8.8"));
    }
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 0);
    assert_eq!(harness.mock.state.calls(ProviderId::Virustotal), 0);
    harness.finish().await;
}

#[tokio::test]
async fn header_safe_non_ascii_service_token_is_compared_as_exact_bytes() {
    let mut config = Config::for_tests();
    config.service_token =
        crate::config::Secret::new("synthetic-operator-secret-longer-than-32-bytes-é".to_owned())
            .unwrap();
    let harness = Harness::new(config, Arc::new(success_reply), false).await;
    let (status, _, response) = harness.post(one_ip("8.8.8.8", "abuseipdb")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["results"][0]["providers"][0]["status"], "ok");
    let mut wrong = harness.request(Body::from("{}"));
    wrong.headers_mut().insert(
        "authorization",
        HeaderValue::from_static("Bearer synthetic-operator-secret-longer-than-32-bytes-e"),
    );
    let (status, _, _) =
        read_response(router(harness.state.clone()).oneshot(wrong).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
    harness.finish().await;
}

#[tokio::test]
async fn http_errors_have_safe_envelopes_headers_and_fresh_request_ids() {
    let harness = Harness::standard().await;
    for (method, uri, expected, allow) in [
        ("GET", "/unknown/private-path", 404, None),
        ("GET", "/v1/enrich", 405, Some("POST")),
        ("POST", "/health/live", 405, Some("GET")),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-request-id", "untrusted-client-id")
            .body(Body::empty())
            .unwrap();
        let (status, headers, body) = read_response(
            router(harness.state.clone())
                .oneshot(request)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status.as_u16(), expected);
        if let Some(allow) = allow {
            assert_eq!(headers["allow"], allow);
        }
        assert_ne!(body["request_id"], "untrusted-client-id");
        assert!(!body.to_string().contains("private-path"));
    }
    for (content_type, encoding) in [
        ("text/plain", None),
        ("application/json; charset=latin1", None),
        ("application/json; charset=\"\"utf-8\"\"", None),
        ("application/json; charset=\"utf-8", None),
        ("application/json", Some("gzip")),
        ("application/json; unknown=value", None),
    ] {
        let mut request = harness.request(Body::from("{}"));
        request
            .headers_mut()
            .insert("content-type", HeaderValue::from_str(content_type).unwrap());
        if let Some(encoding) = encoding {
            request
                .headers_mut()
                .insert("content-encoding", HeaderValue::from_static(encoding));
        }
        let (status, _, error) = read_response(
            router(harness.state.clone())
                .oneshot(request)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(error["error"]["code"], "unsupported_media_type");
    }
    for value in ["bearer incorrect", "Bearer incorrect", "Basic incorrect"] {
        let mut request = harness.request(Body::from("{}"));
        request
            .headers_mut()
            .insert("authorization", HeaderValue::from_static(value));
        let (status, _, _) = read_response(
            router(harness.state.clone())
                .oneshot(request)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let mut duplicated_auth = harness.request(Body::from("{}"));
    duplicated_auth
        .headers_mut()
        .append("authorization", HeaderValue::from_static("Bearer other"));
    assert_eq!(
        read_response(
            router(harness.state.clone())
                .oneshot(duplicated_auth)
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    harness.finish().await;
}

#[tokio::test]
async fn request_body_bytes_and_incomplete_body_deadline_are_enforced() {
    let mut config = quick_config();
    config.max_request_bytes = 64;
    config.request_timeout = Duration::from_millis(800);
    let harness = Harness::new(config, Arc::new(success_reply), false).await;
    let oversized = harness.request(Body::from(vec![b' '; 65]));
    let (status, _, body) = read_response(
        router(harness.state.clone())
            .oneshot(oversized)
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"]["code"], "request_too_large");
    let pending = Body::from_stream(futures_util::stream::pending::<Result<Bytes, Infallible>>());
    let (status, _, body) = read_response(
        router(harness.state.clone())
            .oneshot(harness.request(pending))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(body["error"]["code"], "request_body_timeout");
    assert_eq!(
        harness.state.admission.available_permits(),
        harness.service.config.max_concurrent_requests
    );
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 0);
    harness.finish().await;
}

#[tokio::test]
async fn individual_provider_failures_preserve_success_and_never_echo_provider_text() {
    for (status, expected_code, expected_calls) in [
        (401, "provider_authentication_failed", 1),
        (403, "provider_access_denied", 1),
        (429, "quota_exhausted", 1),
        (500, "provider_unavailable", 1),
        (502, "provider_unavailable", 2),
        (503, "provider_unavailable", 2),
        (504, "provider_unavailable", 2),
        (301, "provider_request_rejected", 1),
    ] {
        let harness = Harness::new(
            quick_config(),
            Arc::new(move |provider, uri, attempt| {
                if provider == ProviderId::Abuseipdb {
                    success_reply(provider, uri, attempt)
                } else {
                    MockReply::json(
                        status,
                        json!({"error":{"message":"sensitive-upstream-provider-message"}}),
                    )
                }
            }),
            false,
        )
        .await;
        let (http_status, _, response) = harness
            .post(json!({"indicators":[{"type":"ip","value":"8.8.8.8"}]}))
            .await;
        assert_eq!(http_status, StatusCode::OK);
        assert_eq!(response["results"][0]["providers"][0]["status"], "ok");
        assert_eq!(
            response["results"][0]["providers"][1]["error"]["code"], expected_code,
            "status {status}"
        );
        assert_eq!(
            harness.mock.state.calls(ProviderId::Virustotal),
            expected_calls,
            "status {status}"
        );
        assert!(
            !response
                .to_string()
                .contains("sensitive-upstream-provider-message")
        );
        harness.finish().await;
    }
}

#[tokio::test]
async fn not_found_is_cached_and_all_provider_errors_still_return_http_200() {
    let harness = Harness::new(
        Config::for_tests(),
        Arc::new(|provider, _, _| {
            if provider == ProviderId::Virustotal {
                MockReply::json(
                    404,
                    json!({"error":{"code":"NotFoundError","message":"private"}}),
                )
            } else {
                MockReply::json(401, json!({"error":"private"}))
            }
        }),
        false,
    )
    .await;
    let body = json!({"indicators":[{"type":"ip","value":"8.8.8.8"}],"include_raw":true});
    let (status, _, first) = harness.post(body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["results"][0]["providers"][0]["status"], "error");
    let not_found = &first["results"][0]["providers"][1];
    assert_eq!(not_found["status"], "not_found");
    assert!(not_found["summary"].is_null());
    assert!(not_found["error"].is_null());
    assert!(not_found["provider_updated_at"].is_null());
    assert!(not_found["fetched_at"].is_string());
    assert_eq!(not_found["raw_omitted_reason"], "not_available");
    let (_, _, second) = harness.post(body).await;
    assert_eq!(second["results"][0]["providers"][1]["cache"]["hit"], true);
    assert_eq!(harness.mock.state.calls(ProviderId::Virustotal), 1);
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 2);
    harness.finish().await;
}

#[tokio::test]
async fn retries_once_after_transient_failure_and_reserves_quota_for_the_retry() {
    let mut config = quick_config();
    config.abuseipdb.requests_per_day = 2;
    let harness = Harness::new(
        config,
        Arc::new(|provider, uri, attempt| {
            if attempt == 1 {
                MockReply::json(503, json!({"error":"retry"}))
            } else {
                success_reply(provider, uri, attempt)
            }
        }),
        false,
    )
    .await;
    let (_, _, first) = harness.post(one_ip("8.8.8.8", "abuseipdb")).await;
    assert_eq!(first["results"][0]["providers"][0]["status"], "ok");
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 2);
    let (_, _, second) = harness.post(one_ip("1.1.1.1", "abuseipdb")).await;
    assert_eq!(
        second["results"][0]["providers"][0]["error"]["code"],
        "quota_exhausted"
    );
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 2);
    harness.finish().await;
}

#[tokio::test]
async fn cache_hits_precede_quota_checks_and_rolling_boundary_reopens_dispatch() {
    let mut config = Config::for_tests();
    config.virustotal.requests_per_minute = 1;
    let harness = Harness::new(config, Arc::new(success_reply), false).await;
    let (_, _, first) = harness.post(one_ip("8.8.8.8", "virustotal")).await;
    assert_eq!(first["results"][0]["providers"][0]["status"], "ok");
    let (_, _, cached) = harness.post(one_ip("8.8.8.8", "virustotal")).await;
    assert_eq!(cached["results"][0]["providers"][0]["cache"]["hit"], true);
    let (_, _, denied) = harness.post(one_ip("1.1.1.1", "virustotal")).await;
    assert_eq!(
        denied["results"][0]["providers"][0]["status"],
        "rate_limited"
    );
    assert_eq!(
        denied["results"][0]["providers"][0]["error"]["retry_after_seconds"],
        60
    );
    assert_eq!(harness.mock.state.calls(ProviderId::Virustotal), 1);
    *harness.clock.0.lock().unwrap() += chrono::Duration::seconds(60);
    let (_, _, next) = harness.post(one_ip("1.1.1.1", "virustotal")).await;
    assert_eq!(next["results"][0]["providers"][0]["status"], "ok");
    assert_eq!(harness.mock.state.calls(ProviderId::Virustotal), 2);
    harness.finish().await;
}

#[tokio::test]
async fn upstream_cooldown_is_not_retried_and_unknown_reset_stays_unknown() {
    for known in [false, true] {
        let harness = Harness::new(
            Config::for_tests(),
            Arc::new(move |_, _, _| {
                let mut response = MockReply::json(
                    429,
                    json!({"error":{"code":"QuotaExceededError","message":"private"}}),
                );
                if known {
                    response
                        .headers
                        .insert("retry-after", HeaderValue::from_static("120"));
                }
                response
            }),
            false,
        )
        .await;
        let (_, _, first) = harness.post(one_ip("8.8.8.8", "virustotal")).await;
        let delay = &first["results"][0]["providers"][0]["error"]["retry_after_seconds"];
        if known {
            assert_eq!(*delay, json!(120));
        } else {
            assert!(delay.is_null());
        }
        let (_, _, denied) = harness.post(one_ip("1.1.1.1", "virustotal")).await;
        assert_eq!(
            denied["results"][0]["providers"][0]["status"],
            "rate_limited"
        );
        assert_eq!(harness.mock.state.calls(ProviderId::Virustotal), 1);
        harness.finish().await;
    }
}

#[tokio::test]
async fn active_attempts_overlap_without_exceeding_global_or_provider_limits() {
    let mut config = Config::for_tests();
    config.max_outbound_requests = 3;
    config.abuseipdb.max_concurrency = 2;
    config.virustotal.max_concurrency = 2;
    config.virustotal.requests_per_minute = 100;
    let harness = Arc::new(Harness::new(config, Arc::new(success_reply), true).await);
    let worker = {
        let harness = harness.clone();
        tokio::spawn(async move {
            harness.post(json!({"indicators":(1..=8).map(|index| json!({"type":"ip","value":format!("10.0.0.{index}")})).collect::<Vec<_>>()})).await
        })
    };
    harness.mock.state.wait_for_calls(3).await;
    assert_eq!(harness.mock.state.all_active.load(Ordering::SeqCst), 3);
    assert_eq!(harness.mock.state.all_peak.load(Ordering::SeqCst), 3);
    harness.mock.state.release(16);
    let (status, _, response) = worker.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert!(
        response["results"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|result| result["providers"].as_array().unwrap())
            .all(|provider| provider["status"] == "ok")
    );
    assert!(
        harness
            .mock
            .state
            .peak
            .iter()
            .all(|peak| peak.load(Ordering::SeqCst) <= 2)
    );
    assert!(harness.mock.state.all_peak.load(Ordering::SeqCst) <= 3);
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 8);
    assert_eq!(harness.mock.state.calls(ProviderId::Virustotal), 8);
    harness.finish().await;
}

#[tokio::test]
async fn abandoned_callers_do_not_cancel_shared_work_or_strand_lookup_capacity() {
    let mut config = Config::for_tests();
    config.max_shared_lookups = 1;
    let harness = Harness::new(config, Arc::new(success_reply), true).await;
    let indicator = validate_indicator(IndicatorKind::Ip, "8.8.8.8").unwrap();
    let abandoned = {
        let service = harness.service.clone();
        let indicator = indicator.clone();
        tokio::spawn(async move {
            service
                .lookup(
                    ProviderId::Abuseipdb,
                    indicator,
                    Instant::now() + Duration::from_secs(5),
                    "caller-one",
                )
                .await
        })
    };
    harness.mock.state.wait_for_calls(1).await;
    abandoned.abort();
    assert!(matches!(abandoned.await, Err(error) if error.is_cancelled()));
    // With no caller left, the owner still completes and populates the cache.
    harness.mock.state.release(1);
    let surviving = harness
        .service
        .lookup(
            ProviderId::Abuseipdb,
            indicator,
            Instant::now() + Duration::from_secs(5),
            "caller-two",
        )
        .await;
    assert_eq!(surviving.outcome.status, Status::Ok);
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
    let cached = harness
        .service
        .lookup(
            ProviderId::Abuseipdb,
            validate_indicator(IndicatorKind::Ip, "8.8.8.8").unwrap(),
            Instant::now() + Duration::from_secs(5),
            "caller-three",
        )
        .await;
    assert!(cached.cache_hit);
    harness.mock.state.release(1);
    let next = harness
        .service
        .lookup(
            ProviderId::Abuseipdb,
            validate_indicator(IndicatorKind::Ip, "1.1.1.1").unwrap(),
            Instant::now() + Duration::from_secs(5),
            "caller-four",
        )
        .await;
    assert_eq!(next.outcome.status, Status::Ok);
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 2);
    harness.finish().await;
}

#[tokio::test]
async fn callers_have_independent_deadlines_and_provider_timeouts_are_not_retried() {
    let harness = Harness::new(Config::for_tests(), Arc::new(success_reply), true).await;
    let short = {
        let service = harness.service.clone();
        tokio::spawn(async move {
            service
                .lookup(
                    ProviderId::Abuseipdb,
                    validate_indicator(IndicatorKind::Ip, "8.8.8.8").unwrap(),
                    Instant::now() + Duration::from_millis(150),
                    "short-caller",
                )
                .await
        })
    };
    harness.mock.state.wait_for_calls(1).await;
    let timed_out = short.await.unwrap();
    assert_eq!(
        timed_out.outcome.error.as_ref().unwrap().code.as_str(),
        "request_deadline_exceeded"
    );
    harness.mock.state.release(1);
    let later = harness
        .service
        .lookup(
            ProviderId::Abuseipdb,
            validate_indicator(IndicatorKind::Ip, "8.8.8.8").unwrap(),
            Instant::now() + Duration::from_secs(5),
            "long-caller",
        )
        .await;
    assert_eq!(later.outcome.status, Status::Ok);
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
    harness.finish().await;

    let harness = Harness::new(quick_config(), Arc::new(success_reply), true).await;
    let (_, _, response) = harness.post(one_ip("8.8.8.8", "abuseipdb")).await;
    assert_eq!(response["results"][0]["providers"][0]["status"], "timeout");
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
    harness.mock.state.release(1);
    harness.finish().await;
}

#[tokio::test]
async fn full_shared_lookup_table_rejects_new_misses_but_preserves_joined_work() {
    let mut config = Config::for_tests();
    config.max_shared_lookups = 1;
    let harness = Arc::new(Harness::new(config, Arc::new(success_reply), true).await);
    let worker = {
        let harness = harness.clone();
        tokio::spawn(async move { harness.post(one_ip("8.8.8.8", "abuseipdb")).await })
    };
    harness.mock.state.wait_for_calls(1).await;
    let (_, _, busy) = harness.post(one_ip("1.1.1.1", "abuseipdb")).await;
    assert_eq!(
        busy["results"][0]["providers"][0]["error"]["code"],
        "provider_busy"
    );
    harness.mock.state.release(1);
    let (_, _, finished) = worker.await.unwrap();
    assert_eq!(finished["results"][0]["providers"][0]["status"], "ok");
    let (_, _, cached) = harness.post(one_ip("8.8.8.8", "abuseipdb")).await;
    assert_eq!(cached["results"][0]["providers"][0]["cache"]["hit"], true);
    harness.finish().await;
}

#[tokio::test]
async fn admission_is_held_through_response_consumption_and_health_has_separate_capacity() {
    let mut config = Config::for_tests();
    config.max_concurrent_requests = 1;
    let harness = Harness::new(config, Arc::new(success_reply), false).await;
    let app = router(harness.state.clone());
    let request_body = serde_json::to_vec(&one_ip("8.8.8.8", "abuseipdb")).unwrap();
    let held = app
        .clone()
        .oneshot(harness.request(Body::from(request_body.clone())))
        .await
        .unwrap();
    assert_eq!(harness.state.admission.available_permits(), 0);
    let (status, headers, busy) = read_response(
        app.clone()
            .oneshot(harness.request(Body::from(request_body)))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers["retry-after"], "1");
    assert_eq!(busy["error"]["code"], "service_overloaded");
    let probe = || {
        Request::builder()
            .uri("/health/ready")
            .body(Body::empty())
            .unwrap()
    };
    let probe_one = app.clone().oneshot(probe()).await.unwrap();
    let probe_two = app.clone().oneshot(probe()).await.unwrap();
    assert_eq!(probe_one.status(), StatusCode::OK);
    assert_eq!(probe_two.status(), StatusCode::OK);
    let (status, _, third) = read_response(app.clone().oneshot(probe()).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(third["error"]["code"], "service_overloaded");
    drop((held, probe_one, probe_two));
    assert_eq!(harness.state.admission.available_permits(), 1);
    assert_eq!(
        read_response(app.oneshot(probe()).await.unwrap()).await.0,
        StatusCode::OK
    );
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
    harness.service.begin_shutdown();
    let (status, _, unavailable) = harness.post(one_ip("1.1.1.1", "abuseipdb")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unavailable["error"]["code"], "service_unavailable");
    let (status, _, readiness) = read_response(
        router(harness.state.clone())
            .oneshot(probe())
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(readiness["status"], "not_ready");
    harness.finish().await;
}

#[tokio::test]
async fn raw_budget_counts_duplicates_and_continues_with_later_smaller_reports() {
    let large = json!({"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":0},"extension":"x".repeat(256)});
    let small = json!({"data":{"ipAddress":"1.1.1.1"}});
    let mut config = Config::for_tests();
    config.max_raw_response_bytes =
        serde_json::to_vec(&large).unwrap().len() + serde_json::to_vec(&small).unwrap().len();
    let harness = Harness::new(
        config,
        Arc::new(move |provider, uri, _| {
            MockReply::json(
                200,
                if lookup_value(provider, uri) == "8.8.8.8" {
                    large.clone()
                } else {
                    small.clone()
                },
            )
        }),
        false,
    )
    .await;
    let (_, _, response) = harness.post(json!({"indicators":[{"type":"ip","value":"8.8.8.8"},{"type":"ip","value":"8.8.8.8"},{"type":"ip","value":"1.1.1.1"}],"providers":["abuseipdb"],"include_raw":true})).await;
    let results = response["results"].as_array().unwrap();
    assert!(results[0]["providers"][0]["raw"].is_object());
    assert!(
        results[0]["providers"][0]
            .get("raw_omitted_reason")
            .is_none()
    );
    assert!(results[1]["providers"][0].get("raw").is_none());
    assert_eq!(
        results[1]["providers"][0]["raw_omitted_reason"],
        "response_size_limit"
    );
    assert!(results[2]["providers"][0]["raw"].is_object());
    assert!(
        results
            .iter()
            .all(|result| result["providers"][0]["status"] == "ok")
    );
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 2);
    harness.finish().await;
}

#[tokio::test]
async fn streamed_oversized_provider_bodies_are_bounded_for_success_and_errors() {
    for status in [200, 500] {
        let mut config = Config::for_tests();
        config.max_provider_bytes = 256;
        let harness = Harness::new(
            config,
            Arc::new(move |_, _, _| {
                MockReply::json(
                    status,
                    json!({"data":{"ipAddress":"8.8.8.8"},"extension":"a".repeat(1024)}),
                )
            }),
            false,
        )
        .await;
        let (_, _, response) = harness.post(one_ip("8.8.8.8", "abuseipdb")).await;
        assert_eq!(
            response["results"][0]["providers"][0]["error"]["code"],
            "response_too_large"
        );
        assert!(response["results"][0]["providers"][0]["summary"].is_null());
        assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
        harness.finish().await;
    }
}

#[tokio::test]
async fn decompressed_provider_bytes_are_capped_after_gzip_decoding() {
    let mut config = Config::for_tests();
    config.max_provider_bytes = 256;
    let harness = Harness::new(
        config,
        Arc::new(|_, _, _| {
            let compressed = include_bytes!("../fixtures/oversized-provider.json.gz");
            assert!(compressed.len() < 256);
            let mut headers = HeaderMap::new();
            headers.insert("content-encoding", HeaderValue::from_static("gzip"));
            MockReply {
                status: 200,
                body: compressed.to_vec(),
                headers,
            }
        }),
        false,
    )
    .await;
    let (_, _, response) = harness.post(one_ip("8.8.8.8", "abuseipdb")).await;
    assert_eq!(
        response["results"][0]["providers"][0]["error"]["code"],
        "response_too_large"
    );
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_32_simultaneous_default_batches_stays_bounded_and_releases_admission() {
    let harness = Arc::new(Harness::standard().await);
    let payload = json!({"indicators":(1..=20).map(|index| json!({"type":"ip","value":format!("10.1.0.{index}")})).collect::<Vec<_>>()});
    let barrier = Arc::new(tokio::sync::Barrier::new(33));
    let mut workers = Vec::new();
    for _ in 0..32 {
        let harness = harness.clone();
        let payload = payload.clone();
        let barrier = barrier.clone();
        workers.push(tokio::spawn(async move {
            barrier.wait().await;
            harness.post(payload).await
        }));
    }
    let started = Instant::now();
    barrier.wait().await;
    for worker in workers {
        let (status, _, response) = tokio::time::timeout(Duration::from_secs(25), worker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["results"].as_array().unwrap().len(), 20);
        assert!(
            response["results"]
                .as_array()
                .unwrap()
                .iter()
                .all(|result| result["providers"].as_array().unwrap().len() == 2)
        );
    }
    let mock = &harness.mock.state;
    eprintln!(
        "LOAD_32X20 elapsed_ms={} mock_peak={} abuse_peak={} vt_peak={} abuse_calls={} vt_calls={}",
        started.elapsed().as_millis(),
        mock.all_peak.load(Ordering::SeqCst),
        mock.peak[0].load(Ordering::SeqCst),
        mock.peak[1].load(Ordering::SeqCst),
        mock.calls(ProviderId::Abuseipdb),
        mock.calls(ProviderId::Virustotal)
    );
    assert!(mock.all_peak.load(Ordering::SeqCst) <= 16);
    assert!(
        mock.peak
            .iter()
            .all(|peak| peak.load(Ordering::SeqCst) <= 4)
    );
    assert!(mock.calls(ProviderId::Abuseipdb) <= 20);
    assert!(mock.calls(ProviderId::Virustotal) <= 4);
    assert_eq!(harness.state.admission.available_permits(), 32);
    harness.finish().await;
}

#[tokio::test]
async fn n8n_request_over_real_http_preserves_partial_results_and_operational_headers() {
    let harness = Harness::new(
        Config::for_tests(),
        Arc::new(|provider, uri, attempt| {
            if provider == ProviderId::Abuseipdb {
                success_reply(provider, uri, attempt)
            } else {
                MockReply::json(
                    403,
                    json!({"error":{"code":"ForbiddenError","message":"untrusted upstream text"}}),
                )
            }
        }),
        false,
    )
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = harness.state.clone();
    let stop = tokio_util::sync::CancellationToken::new();
    let stopped = stop.clone();
    let server = tokio::spawn(async move {
        crate::server::serve(listener, state, stopped.cancelled())
            .await
            .unwrap()
    });
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{address}/v1/enrich"))
        .bearer_auth(harness.service.config.service_token.expose_secret())
        .header("content-type", "application/json; charset=utf-8")
        .body(
            serde_json::to_vec(
                &json!({"indicators":[{"type":"ip","value":"8.8.8.8"}],"include_raw":false}),
            )
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let result: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(result["request_id"], request_id);
    let evidence = &result["results"][0]["providers"];
    assert_eq!(evidence[0]["provider"], "abuseipdb");
    assert_eq!(evidence[0]["status"], "ok");
    assert_eq!(evidence[0]["summary"]["abuse_confidence_score"], 0);
    assert!(evidence[0]["summary"]["total_reports"].is_null());
    assert_eq!(evidence[1]["error"]["retryable"], false);
    assert!(!result.to_string().contains("untrusted upstream text"));
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    assert!(harness.service.stopping.is_cancelled());
}

#[tokio::test]
async fn slow_response_reader_cannot_keep_an_admission_slot_indefinitely() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut config = Config::for_tests();
    config.max_concurrent_requests = 1;
    config.response_write_timeout = Duration::from_secs(2);
    let harness = Harness::new(
        config,
        Arc::new(|_, _, _| {
            MockReply::json(
                200,
                json!({"data":{"ipAddress":"8.8.8.8"},"extension":"a".repeat(900_000)}),
            )
        }),
        true,
    )
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = harness.state.clone();
    let stop = tokio_util::sync::CancellationToken::new();
    let stopped = stop.clone();
    let server = tokio::spawn(async move {
        crate::server::serve(listener, state, stopped.cancelled())
            .await
            .unwrap()
    });
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let body = serde_json::to_vec(&json!({"indicators":vec![json!({"type":"ip","value":"8.8.8.8"});20],"providers":["abuseipdb"],"include_raw":true})).unwrap();
    let headers = format!(
        "POST /v1/enrich HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        harness.service.config.service_token.expose_secret(),
        body.len()
    );
    socket.write_all(headers.as_bytes()).await.unwrap();
    socket.write_all(&body).await.unwrap();
    harness.mock.state.wait_for_calls(1).await;
    assert_eq!(harness.state.admission.available_permits(), 0);
    harness.mock.state.release(1);
    // Do not read any response bytes until the server releases the slot. The
    // response is about 8 MiB, larger than an ordinary local TCP send buffer.
    let permit = tokio::time::timeout(Duration::from_secs(6), harness.state.admission.acquire())
        .await
        .expect("slow reader retained admission beyond its deadline")
        .unwrap();
    drop(permit);
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert!(received.starts_with(b"HTTP/1.1 200"));
    assert_eq!(harness.state.admission.available_permits(), 1);
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn production_shutdown_cancels_pending_lookups_and_releases_admission_within_grace() {
    let mut config = Config::for_tests();
    config.shutdown_grace = Duration::from_millis(250);
    let harness = Harness::new(config, Arc::new(success_reply), true).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = harness.state.clone();
    let stop = tokio_util::sync::CancellationToken::new();
    let stopped = stop.clone();
    let server = tokio::spawn(async move {
        crate::server::serve(listener, state, stopped.cancelled())
            .await
            .unwrap()
    });
    let token = harness
        .service
        .config
        .service_token
        .expose_secret()
        .to_owned();
    let request = tokio::spawn(async move {
        reqwest::Client::new()
            .post(format!("http://{address}/v1/enrich"))
            .bearer_auth(token)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&one_ip("8.8.8.8", "abuseipdb")).unwrap())
            .send()
            .await
    });
    harness.mock.state.wait_for_calls(1).await;
    assert_eq!(harness.state.admission.available_permits(), 31);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("shutdown exceeded its bounded grace")
        .unwrap();
    assert!(harness.service.stopping.is_cancelled());
    assert_eq!(harness.state.admission.available_permits(), 32);
    let completed_request = tokio::time::timeout(Duration::from_secs(2), request)
        .await
        .unwrap()
        .unwrap();
    if let Ok(response) = completed_request {
        assert!(response.status().is_success() || response.status().is_server_error());
    }
    // A stranded shared entry would expose its old timeout outcome. With the
    // entry removed, the already-cancelled service refuses a fresh registration.
    let after = harness
        .service
        .lookup(
            ProviderId::Abuseipdb,
            validate_indicator(IndicatorKind::Ip, "8.8.8.8").unwrap(),
            Instant::now() + Duration::from_secs(1),
            "after-shutdown",
        )
        .await;
    assert_eq!(
        after.outcome.error.as_ref().unwrap().code.as_str(),
        "service_unavailable"
    );
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
    harness.mock.state.release(1);
}

#[tokio::test]
async fn incomplete_body_over_real_tcp_returns_json_408_and_releases_the_slot() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut config = quick_config();
    config.request_timeout = Duration::from_millis(300);
    config.lookup_timeout = Duration::from_millis(250);
    config.storage_timeout = Duration::from_millis(200);
    let harness = Harness::new(config, Arc::new(success_reply), false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = harness.state.clone();
    let stop = tokio_util::sync::CancellationToken::new();
    let stopped = stop.clone();
    let server = tokio::spawn(async move {
        crate::server::serve(listener, state, stopped.cancelled())
            .await
            .unwrap()
    });
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = format!(
        "POST /v1/enrich HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n",
        harness.service.config.service_token.expose_secret()
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(received).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(headers.starts_with("HTTP/1.1 408"));
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("content-type: application/json")
    );
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store")
    );
    let body: Value = serde_json::from_str(body).unwrap();
    assert_eq!(body["error"]["code"], "request_body_timeout");
    assert!(headers.contains(body["request_id"].as_str().unwrap()));
    assert_eq!(harness.state.admission.available_permits(), 32);
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 0);
    assert_eq!(harness.mock.state.calls(ProviderId::Virustotal), 0);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

async fn hold_external_write_lock(harness: &Harness) -> sqlx::SqliteConnection {
    use sqlx::{ConnectOptions, Connection};
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&harness.service.config.database_path)
        .create_if_missing(false)
        .busy_timeout(Duration::from_millis(400))
        .disable_statement_logging();
    let mut connection = tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::SqliteConnection::connect_with(&options),
    )
    .await
    .unwrap()
    .unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut connection)
        .await
        .unwrap();
    connection
}

#[tokio::test]
async fn decoded_report_survives_cache_write_failure_and_readiness_recovers() {
    use sqlx::Connection;
    let mut config = Config::for_tests();
    config.storage_timeout = Duration::from_millis(400);
    let harness = Arc::new(Harness::new(config, Arc::new(success_reply), true).await);
    let pending = {
        let harness = harness.clone();
        tokio::spawn(async move { harness.post(one_ip("8.8.8.8", "abuseipdb")).await })
    };
    // A mock call can begin only after quota has committed. Lock the database
    // at this point to fail the later cache write without blocking reservation.
    harness.mock.state.wait_for_calls(1).await;
    let mut writer = hold_external_write_lock(&harness).await;
    harness.mock.state.release(1);
    let (status, _, response) = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .expect("cache write failure did not complete within its bound")
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    let provider = &response["results"][0]["providers"][0];
    assert_eq!(provider["status"], "ok");
    assert_eq!(provider["summary"]["abuse_confidence_score"], 0);
    assert!(provider["fetched_at"].is_string());
    assert!(provider["error"].is_null());
    assert_eq!(provider["cache"]["hit"], false);
    assert!(provider["cache"]["expires_at"].is_null());
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 1);
    assert!(!harness.service.storage.is_healthy());

    let probe = || {
        Request::builder()
            .uri("/health/ready")
            .body(Body::empty())
            .unwrap()
    };
    let (status, _, readiness) = read_response(
        router(harness.state.clone())
            .oneshot(probe())
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(readiness["status"], "not_ready");
    sqlx::query("ROLLBACK").execute(&mut writer).await.unwrap();
    writer.close().await.unwrap();
    let (status, _, readiness) = read_response(
        router(harness.state.clone())
            .oneshot(probe())
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(readiness["status"], "ready");
    assert!(harness.service.storage.is_healthy());
    harness.finish().await;
}

#[tokio::test]
async fn failed_quota_reservation_never_dispatches_even_after_storage_unlocks() {
    use sqlx::Connection;
    let mut config = Config::for_tests();
    config.storage_timeout = Duration::from_millis(400);
    let harness = Harness::new(config, Arc::new(success_reply), false).await;
    let mut writer = hold_external_write_lock(&harness).await;
    // Call orchestration directly so this exercises durable reservation rather
    // than the HTTP admission shortcut for already-known unavailable storage.
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        harness.service.lookup(
            ProviderId::Abuseipdb,
            validate_indicator(IndicatorKind::Ip, "8.8.8.8").unwrap(),
            Instant::now() + Duration::from_secs(2),
            "failed-reservation",
        ),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome.status, Status::Error);
    assert_eq!(
        result.outcome.error.as_ref().unwrap().code.as_str(),
        "storage_unavailable"
    );
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 0);
    sqlx::query("ROLLBACK").execute(&mut writer).await.unwrap();
    writer.close().await.unwrap();
    harness
        .service
        .storage
        .health(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    // Draining waits for any owner still completing its cleanup; recovery must
    // never resume the failed attempt or turn an uncertain commit into dispatch.
    harness
        .service
        .drain(Instant::now() + Duration::from_secs(1))
        .await;
    assert_eq!(harness.mock.state.calls(ProviderId::Abuseipdb), 0);
    assert_eq!(harness.mock.state.calls(ProviderId::Virustotal), 0);
    harness.finish().await;
}

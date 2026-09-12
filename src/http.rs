use crate::{
    domain::{
        ErrorCode, InputIndicator, ProviderId, PublicError, RequestValidationError, Status,
        Summary, ValidatedRequest, ValidationDetail, validate_request,
    },
    enrichment::{Enrichment, LookupResult},
    serialization::{CountingWriter, LimitedWriter},
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::Response,
};
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, stream};
use http_body::{Body as HttpBody, Frame, SizeHint};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    time::{Instant, timeout_at},
};

const ENVELOPE_LIMIT: usize = 1024 * 1024;

#[derive(Clone)]
pub struct HttpState {
    pub service: Arc<Enrichment>,
    pub admission: Arc<Semaphore>,
    health_admission: Arc<Semaphore>,
    token_digest: [u8; 32],
}

impl HttpState {
    pub fn new(service: Arc<Enrichment>) -> Self {
        Self {
            admission: Arc::new(Semaphore::new(service.config.max_concurrent_requests)),
            health_admission: Arc::new(Semaphore::new(2)),
            token_digest: Sha256::digest(service.config.service_token.expose_secret().as_bytes())
                .into(),
            service,
        }
    }
}

/// The production connection owns admission until all bytes have been written.
#[derive(Clone)]
pub(crate) struct ConnectionContext {
    pub deadline: watch::Sender<Option<Instant>>,
    pub permit: Arc<Mutex<Option<OwnedSemaphorePermit>>>,
}

pub fn router(state: HttpState) -> Router {
    Router::new().fallback(handle).with_state(state)
}

async fn handle(State(state): State<HttpState>, request: Request) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    let started = Instant::now();
    let path = request.uri().path();
    let route = match path {
        "/v1/enrich" => "/v1/enrich",
        "/health/live" => "/health/live",
        "/health/ready" => "/health/ready",
        _ => "unmatched",
    };
    let connection = request.extensions().get::<ConnectionContext>().cloned();
    let response = match route {
        "unmatched" => error_response(&id, StatusCode::NOT_FOUND, ErrorCode::RouteNotFound, None),
        "/health/live" | "/health/ready" => {
            if request.method() != Method::GET {
                method_error(&id, "GET")
            } else {
                health(&state, &id, route == "/health/ready", connection.as_ref()).await
            }
        }
        _ => {
            if request.method() != Method::POST {
                method_error(&id, "POST")
            } else if !authorized(&state, &request) {
                error_response(&id, StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, None)
            } else {
                enrich(&state, request, &id, connection.as_ref()).await
            }
        }
    };
    if let Some(context) = connection {
        // Health/errors also have finite response writes. Enrichment starts this before assembly.
        if context.deadline.borrow().is_none() {
            context.deadline.send_replace(Some(
                Instant::now() + state.service.config.response_write_timeout,
            ));
        }
    }
    tracing::info!(
        request_id = id,
        route,
        status = response.status().as_u16(),
        duration_ms = started.elapsed().as_millis() as u64,
        "request_complete"
    );
    response
}

fn authorized(state: &HttpState, request: &Request) -> bool {
    let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
    let value = values
        .next()
        .and_then(|value| value.as_bytes().strip_prefix(b"Bearer "));
    if values.next().is_some() {
        return false;
    }
    let candidate: [u8; 32] = Sha256::digest(value.unwrap_or(b"")).into();
    bool::from(candidate.ct_eq(&state.token_digest)) && value.is_some()
}

async fn health(
    state: &HttpState,
    id: &str,
    readiness: bool,
    connection: Option<&ConnectionContext>,
) -> Response {
    let Ok(permit) = state.health_admission.clone().try_acquire_owned() else {
        return error_response(
            id,
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ServiceOverloaded,
            None,
        );
    };
    let ready = !readiness
        || (!state.service.stopping.is_cancelled()
            && state
                .service
                .storage
                .health(Instant::now() + state.service.config.storage_timeout)
                .await
                .is_ok());
    #[derive(Serialize)]
    struct Health<'a> {
        status: &'a str,
        request_id: &'a str,
    }
    let body = Health {
        status: if !readiness {
            "alive"
        } else if ready {
            "ready"
        } else {
            "not_ready"
        },
        request_id: id,
    };
    let response = json_response(
        id,
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        &body,
    );
    attach_permit(
        response,
        permit,
        connection,
        state.service.config.response_write_timeout,
    )
}

async fn enrich(
    state: &HttpState,
    request: Request,
    id: &str,
    connection: Option<&ConnectionContext>,
) -> Response {
    if state.service.stopping.is_cancelled() || !state.service.storage.is_healthy() {
        return error_response(
            id,
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ServiceUnavailable,
            None,
        );
    }
    let Ok(permit) = state.admission.clone().try_acquire_owned() else {
        tracing::warn!(
            request_id = id,
            code = "service_overloaded",
            "admission_rejected"
        );
        return error_response(
            id,
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ServiceOverloaded,
            None,
        );
    };
    let deadline = Instant::now() + state.service.config.request_timeout;
    if let Some(connection) = connection {
        connection
            .deadline
            .send_replace(Some(deadline + state.service.config.response_write_timeout));
    }
    let response = enrich_admitted(state, request, id, deadline, connection).await;
    attach_permit(
        response,
        permit,
        connection,
        state.service.config.response_write_timeout,
    )
}

async fn enrich_admitted(
    state: &HttpState,
    request: Request,
    id: &str,
    deadline: Instant,
    connection: Option<&ConnectionContext>,
) -> Response {
    if !supported_media_type(&request) {
        return error_response(
            id,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            None,
        );
    }
    let mut body = request.into_body().into_data_stream();
    let mut bytes = Vec::new();
    loop {
        match timeout_at(deadline, body.next()).await {
            Err(_) => {
                return error_response(
                    id,
                    StatusCode::REQUEST_TIMEOUT,
                    ErrorCode::RequestBodyTimeout,
                    None,
                );
            }
            Ok(None) => break,
            Ok(Some(Err(_))) => {
                return error_response(id, StatusCode::BAD_REQUEST, ErrorCode::InvalidJson, None);
            }
            Ok(Some(Ok(chunk))) => {
                if chunk.len()
                    > state
                        .service
                        .config
                        .max_request_bytes
                        .saturating_sub(bytes.len())
                {
                    return error_response(
                        id,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        ErrorCode::RequestTooLarge,
                        None,
                    );
                }
                bytes.extend_from_slice(&chunk);
            }
        }
    }
    let request = match validate_request(
        &bytes,
        state.service.config.max_batch_size,
        &state.service.enabled(),
    ) {
        Ok(request) => request,
        Err(RequestValidationError::InvalidJson) => {
            return error_response(id, StatusCode::BAD_REQUEST, ErrorCode::InvalidJson, None);
        }
        Err(RequestValidationError::Semantic(details)) => {
            return error_response(
                id,
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::ValidationError,
                Some(details),
            );
        }
    };
    let ip_count = request
        .indicators
        .iter()
        .filter(|i| i.input.kind == crate::domain::IndicatorKind::Ip)
        .count();
    let url_count = request
        .indicators
        .iter()
        .filter(|i| i.input.kind == crate::domain::IndicatorKind::Url)
        .count();
    tracing::info!(
        request_id = id,
        indicator_count = request.indicators.len(),
        ip_count,
        url_count,
        hash_count = request.indicators.len() - ip_count - url_count,
        "validated_request"
    );
    let mut unique = HashMap::new();
    let mut pairs = Vec::new();
    let mut positions = Vec::new();
    for indicator in &request.indicators {
        for provider in &request.providers {
            let identity = (
                *provider,
                indicator.input.kind,
                indicator.hash_algorithm,
                indicator.lookup_value.clone(),
            );
            let position = *unique.entry(identity).or_insert_with(|| {
                let position = pairs.len();
                pairs.push((*provider, indicator.clone()));
                position
            });
            positions.push(position);
        }
    }
    // At most 40 futures per admitted v1 request; no per-pair tasks are spawned.
    let unique_results: Vec<_> = stream::iter(pairs)
        .map(|(provider, indicator)| state.service.lookup(provider, indicator, deadline, id))
        .buffered(40)
        .collect()
        .await;
    // Duplicate cached pairs also share their immutable raw report until serialization.
    let results: Vec<_> = positions
        .into_iter()
        .map(|position| {
            unique_results
                .get(position)
                .cloned()
                .unwrap_or_else(|| LookupResult::failure(ErrorCode::InternalError))
        })
        .collect();
    let write_deadline = Instant::now() + state.service.config.response_write_timeout;
    if let Some(context) = connection {
        context.deadline.send_replace(Some(write_deadline));
    }
    match project(
        id,
        &request,
        &results,
        state.service.config.max_raw_response_bytes,
    ) {
        Ok(bytes) if Instant::now() < write_deadline => response_bytes(id, StatusCode::OK, bytes),
        _ => error_response(
            id,
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::ResponseTooLarge,
            None,
        ),
    }
}

fn supported_media_type(request: &Request) -> bool {
    let headers = request.headers();
    let mut content_types = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = content_types.next().and_then(|v| v.to_str().ok()) else {
        return false;
    };
    if content_types.next().is_some() {
        return false;
    }
    let mut segments = value.split(';').map(str::trim);
    if !segments
        .next()
        .is_some_and(|v| v.eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    let parameters: Vec<_> = segments.collect();
    if parameters.len() > 1
        || parameters.first().is_some_and(|value| {
            !value.split_once('=').is_some_and(|(key, value)| {
                key.trim().eq_ignore_ascii_case("charset")
                    && (value.trim().eq_ignore_ascii_case("utf-8")
                        || value.trim().eq_ignore_ascii_case("\"utf-8\""))
            })
        })
    {
        return false;
    }
    headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .all(|v| v.to_str().is_ok_and(|v| v.eq_ignore_ascii_case("identity")))
}

#[derive(Serialize)]
struct Envelope<'a> {
    request_id: &'a str,
    results: Vec<ResultItem<'a>>,
}
#[derive(Serialize)]
struct ResultItem<'a> {
    index: usize,
    input: &'a InputIndicator,
    lookup_value: &'a str,
    providers: Vec<ProviderEntry<'a>>,
}
#[derive(Serialize)]
struct ProviderEntry<'a> {
    provider: ProviderId,
    status: Status,
    summary: &'a Option<Summary>,
    fetched_at: Option<DateTime<Utc>>,
    provider_updated_at: Option<DateTime<Utc>>,
    cache: Cache,
    error: &'a Option<PublicError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_omitted_reason: Option<&'static str>,
}
#[derive(Serialize)]
struct Cache {
    hit: bool,
    expires_at: Option<DateTime<Utc>>,
}

fn project(
    id: &str,
    request: &ValidatedRequest,
    outcomes: &[LookupResult],
    raw_budget: usize,
) -> Result<Vec<u8>, ErrorCode> {
    let mut remaining = raw_budget;
    let mut entries = outcomes.iter();
    let mut results = Vec::new();
    let mut raw_values = Vec::new();
    let mut selected = 0usize;
    for (index, indicator) in request.indicators.iter().enumerate() {
        let mut providers = Vec::new();
        for provider in &request.providers {
            let result = entries.next().ok_or(ErrorCode::InternalError)?;
            let outcome = &result.outcome;
            let (raw, reason) = if !request.include_raw {
                (None, None)
            } else if let Some(value) = &outcome.raw {
                let mut counter = CountingWriter(0);
                serde_json::to_writer(&mut counter, value)
                    .map_err(|_| ErrorCode::ResponseTooLarge)?;
                if counter.0 <= remaining {
                    remaining -= counter.0;
                    selected += 1;
                    (Some(value), None)
                } else {
                    (None, Some("response_size_limit"))
                }
            } else {
                (None, Some("not_available"))
            };
            raw_values.push(raw);
            providers.push(ProviderEntry {
                provider: *provider,
                status: outcome.status,
                summary: &outcome.summary,
                fetched_at: outcome.fetched_at,
                provider_updated_at: outcome.provider_updated_at,
                cache: Cache {
                    hit: result.cache_hit,
                    expires_at: result.expires_at,
                },
                error: &outcome.error,
                raw: None,
                raw_omitted_reason: reason,
            });
        }
        results.push(ResultItem {
            index,
            input: &indicator.input,
            lookup_value: &indicator.lookup_value,
            providers,
        });
    }
    let mut envelope = Envelope {
        request_id: id,
        results,
    };
    let mut counter = CountingWriter(0);
    serde_json::to_writer(&mut counter, &envelope).map_err(|_| ErrorCode::ResponseTooLarge)?;
    // Each included value adds the seven structural bytes ,"raw": outside the raw budget.
    if counter.0.saturating_add(selected.saturating_mul(7)) > ENVELOPE_LIMIT {
        return Err(ErrorCode::ResponseTooLarge);
    }
    for (entry, raw) in envelope
        .results
        .iter_mut()
        .flat_map(|r| &mut r.providers)
        .zip(raw_values)
    {
        entry.raw = raw;
    }
    let mut writer = LimitedWriter::new(ENVELOPE_LIMIT.saturating_add(raw_budget));
    serde_json::to_writer(&mut writer, &envelope).map_err(|_| ErrorCode::ResponseTooLarge)?;
    Ok(writer.bytes)
}

fn method_error(id: &str, allow: &'static str) -> Response {
    let mut response = error_response(
        id,
        StatusCode::METHOD_NOT_ALLOWED,
        ErrorCode::MethodNotAllowed,
        None,
    );
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allow));
    response
}

fn error_response(
    id: &str,
    status: StatusCode,
    code: ErrorCode,
    details: Option<Vec<ValidationDetail>>,
) -> Response {
    #[derive(Serialize)]
    struct ErrorDetails {
        #[serde(flatten)]
        error: PublicError,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<Vec<ValidationDetail>>,
    }
    #[derive(Serialize)]
    struct ErrorEnvelope<'a> {
        request_id: &'a str,
        error: ErrorDetails,
    }
    let mut response = json_response(
        id,
        status,
        &ErrorEnvelope {
            request_id: id,
            error: ErrorDetails {
                error: PublicError::new(code),
                details,
            },
        },
    );
    if status == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

fn json_response(id: &str, status: StatusCode, value: &impl Serialize) -> Response {
    let mut writer = LimitedWriter::new(ENVELOPE_LIMIT);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => response_bytes(id, status, writer.bytes),
        Err(_) => {
            // Only static text and a generated UUID enter this last-resort response.
            let body = format!(
                "{{\"request_id\":\"{id}\",\"error\":{{\"code\":\"internal_error\",\"message\":\"The request could not be completed.\",\"retryable\":true,\"retry_after_seconds\":null}}}}"
            );
            response_bytes(id, StatusCode::INTERNAL_SERVER_ERROR, body.into_bytes())
        }
    }
}

fn response_bytes(id: &str, status: StatusCode, bytes: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(id) = HeaderValue::from_str(id) {
        response.headers_mut().insert("x-request-id", id);
    }
    response
}

fn attach_permit(
    response: Response,
    permit: OwnedSemaphorePermit,
    connection: Option<&ConnectionContext>,
    duration: Duration,
) -> Response {
    if let Some(connection) = connection {
        *connection.permit.lock().unwrap_or_else(|e| e.into_inner()) = Some(permit);
        response
    } else {
        let (parts, body) = response.into_parts();
        Response::from_parts(
            parts,
            Body::new(PermitBody {
                inner: body,
                permit: Some(permit),
                timer: Box::pin(tokio::time::sleep(duration)),
            }),
        )
    }
}

struct PermitBody {
    inner: Body,
    permit: Option<OwnedSemaphorePermit>,
    timer: Pin<Box<tokio::time::Sleep>>,
}
impl HttpBody for PermitBody {
    type Data = Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        use std::future::Future;
        if self.timer.as_mut().poll(cx).is_ready() {
            self.permit.take();
            return Poll::Ready(None);
        }
        let frame = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(frame, Poll::Ready(None)) {
            self.permit.take();
        }
        frame
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

#[cfg(test)]
#[path = "../tests/output/mod.rs"]
mod output_tests;

use crate::{
    clock::Clock,
    config::Config,
    domain::{ErrorCode, Outcome, ProviderId, Status, ValidatedIndicator},
    providers::Adapter,
    storage::{QuotaFeedback, ReservationError, Storage},
};
use chrono::{DateTime, Utc};
use futures_util::{FutureExt, StreamExt};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{Semaphore, watch},
    time::{Instant, timeout_at},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use uuid::Uuid;

#[derive(Clone)]
pub struct LookupResult {
    pub outcome: Arc<Outcome>,
    pub cache_hit: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

impl LookupResult {
    pub fn failure(code: ErrorCode) -> Self {
        Self::uncached(Outcome::failure(code))
    }

    fn uncached(outcome: Outcome) -> Self {
        Self {
            outcome: Arc::new(outcome),
            cache_hit: false,
            expires_at: None,
        }
    }
}

struct Provider {
    adapter: Adapter,
    permits: Arc<Semaphore>,
}

type FlightKey = (ProviderId, String);
type FlightReceiver = watch::Receiver<Option<LookupResult>>;
struct Flight {
    receiver: FlightReceiver,
    lookup_id: String,
}

pub struct Enrichment {
    pub config: Arc<Config>,
    pub storage: Arc<Storage>,
    clock: Arc<dyn Clock>,
    providers: HashMap<ProviderId, Arc<Provider>>,
    outbound: Arc<Semaphore>,
    flights: Mutex<HashMap<FlightKey, Flight>>,
    tasks: TaskTracker,
    pub stopping: CancellationToken,
    cancel: CancellationToken,
}

impl Enrichment {
    pub fn new(
        config: Arc<Config>,
        storage: Arc<Storage>,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, crate::providers::AdapterBuildError> {
        let mut adapters = Vec::new();
        for (id, provider) in [
            (ProviderId::Abuseipdb, &config.abuseipdb),
            (ProviderId::Virustotal, &config.virustotal),
        ] {
            if provider.enabled
                && let Some(key) = &provider.api_key
            {
                adapters.push(Adapter::new(
                    id,
                    key.expose_secret(),
                    config.abuseipdb_max_age_days,
                    config.connect_timeout,
                    config.provider_timeout,
                )?);
            }
        }
        Ok(Self::with_adapters(config, storage, clock, adapters))
    }

    pub(crate) fn with_adapters(
        config: Arc<Config>,
        storage: Arc<Storage>,
        clock: Arc<dyn Clock>,
        adapters: Vec<Adapter>,
    ) -> Arc<Self> {
        let providers = adapters
            .into_iter()
            .map(|adapter| {
                let id = adapter.id();
                let settings = match id {
                    ProviderId::Abuseipdb => &config.abuseipdb,
                    ProviderId::Virustotal => &config.virustotal,
                };
                (
                    id,
                    Arc::new(Provider {
                        adapter,
                        permits: Arc::new(Semaphore::new(settings.max_concurrency)),
                    }),
                )
            })
            .collect();
        Arc::new(Self {
            outbound: Arc::new(Semaphore::new(config.max_outbound_requests)),
            config,
            storage,
            clock,
            providers,
            flights: Mutex::new(HashMap::new()),
            tasks: TaskTracker::new(),
            stopping: CancellationToken::new(),
            cancel: CancellationToken::new(),
        })
    }

    pub fn enabled(&self) -> Vec<ProviderId> {
        [ProviderId::Abuseipdb, ProviderId::Virustotal]
            .into_iter()
            .filter(|id| self.providers.contains_key(id))
            .collect()
    }

    pub fn begin_shutdown(&self) {
        self.stopping.cancel();
    }

    pub async fn drain(&self, deadline: Instant) {
        self.tasks.close();
        if timeout_at(deadline, self.tasks.wait()).await.is_err() {
            tracing::warn!(remaining_lookups = self.tasks.len(), "shutdown_cancel");
            self.cancel.cancel();
            self.tasks.wait().await;
        }
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub async fn lookup(
        self: &Arc<Self>,
        id: ProviderId,
        indicator: ValidatedIndicator,
        caller_deadline: Instant,
        request_id: &str,
    ) -> LookupResult {
        let Some(provider) = self.providers.get(&id).cloned() else {
            return LookupResult::uncached(Outcome::empty(Status::Disabled));
        };
        if !provider.adapter.supports(indicator.input.kind) {
            return LookupResult::uncached(Outcome::empty(Status::Unsupported));
        }
        match timeout_at(
            caller_deadline,
            self.subscribe(id, provider, indicator, caller_deadline, request_id),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err((mut receiver, joined))) => {
                let waiting = async {
                    loop {
                        if let Some(mut result) = receiver.borrow().clone() {
                            if joined {
                                result.cache_hit = false;
                            }
                            return result;
                        }
                        if receiver.changed().await.is_err() {
                            return LookupResult::failure(ErrorCode::InternalError);
                        }
                    }
                };
                timeout_at(caller_deadline, waiting)
                    .await
                    .unwrap_or_else(|_| LookupResult::failure(ErrorCode::RequestDeadlineExceeded))
            }
            Err(_) => LookupResult::failure(ErrorCode::RequestDeadlineExceeded),
        }
    }

    async fn subscribe(
        self: &Arc<Self>,
        id: ProviderId,
        provider: Arc<Provider>,
        indicator: ValidatedIndicator,
        caller_deadline: Instant,
        request_id: &str,
    ) -> Result<LookupResult, (FlightReceiver, bool)> {
        let key = match cache_key(&provider.adapter, &indicator) {
            Ok(key) => key,
            Err(_) => return Ok(LookupResult::failure(ErrorCode::InternalError)),
        };
        match self
            .storage
            .cache_get(id, &key, indicator.input.kind, caller_deadline)
            .await
        {
            Ok(Some(cached)) => {
                tracing::info!(
                    request_id,
                    provider = id.as_str(),
                    cache_hit = true,
                    "cache_lookup"
                );
                return Ok(LookupResult {
                    outcome: Arc::new(cached.outcome),
                    cache_hit: true,
                    expires_at: Some(cached.expires_at),
                });
            }
            Err(_) => tracing::warn!(
                request_id,
                provider = id.as_str(),
                code = "storage_unavailable",
                "cache_read_failed"
            ),
            Ok(None) => {}
        }
        let flight_key = (id, key.clone());
        // No await while registering. The lookup belongs to the service, not this caller.
        let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(flight) = flights.get(&flight_key) {
            tracing::info!(
                request_id,
                lookup_id = flight.lookup_id,
                provider = id.as_str(),
                shared_join = true,
                "lookup_join"
            );
            return Err((flight.receiver.clone(), true));
        }
        if flights.len() >= self.config.max_shared_lookups {
            return Ok(LookupResult::failure(ErrorCode::ProviderBusy));
        }
        if self.cancel.is_cancelled() {
            return Ok(LookupResult::failure(ErrorCode::ServiceUnavailable));
        }
        let deadline = Instant::now() + self.config.lookup_timeout;
        let (sender, receiver) = watch::channel(None);
        let lookup_id = Uuid::new_v4().to_string();
        flights.insert(
            flight_key.clone(),
            Flight {
                receiver: receiver.clone(),
                lookup_id: lookup_id.clone(),
            },
        );
        let this = Arc::clone(self);
        let request_id = request_id.to_owned();
        self.tasks.spawn(async move {
            let started = Instant::now();
            tracing::info!(%lookup_id, request_id, provider = id.as_str(), cache_hit = false, "lookup_start");
            let work = AssertUnwindSafe(this.perform(provider, &key, &indicator, deadline)).catch_unwind();
            let result = tokio::select! {
                _ = this.cancel.cancelled() => LookupResult::failure(ErrorCode::ProviderTimeout),
                completed = work => completed.unwrap_or_else(|_| LookupResult::failure(ErrorCode::InternalError)),
            };
            tracing::info!(%lookup_id, provider = id.as_str(), status = result.outcome.status.as_str(), error_code = result.outcome.error.as_ref().map(|error| error.code.as_str()), elapsed_ms = started.elapsed().as_millis() as u64, "lookup_complete");
            // Publishing and removal are atomic with respect to joining a flight.
            let mut flights = this.flights.lock().unwrap_or_else(|e| e.into_inner());
            sender.send_replace(Some(result));
            flights.remove(&flight_key);
        });
        Err((receiver, false))
    }

    async fn perform(
        &self,
        provider: Arc<Provider>,
        key: &str,
        indicator: &ValidatedIndicator,
        deadline: Instant,
    ) -> LookupResult {
        let id = provider.adapter.id();
        // A completed previous owner may have inserted between the caller's read and registration.
        if let Ok(Some(cached)) = self
            .storage
            .cache_get(id, key, indicator.input.kind, deadline)
            .await
        {
            return LookupResult {
                outcome: Arc::new(cached.outcome),
                cache_hit: true,
                expires_at: Some(cached.expires_at),
            };
        }
        let result = timeout_at(deadline, self.fetch(&provider, indicator, deadline)).await;
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(_) => Outcome::failure(ErrorCode::ProviderTimeout),
        };
        let mut result = LookupResult::uncached(outcome);
        if matches!(result.outcome.status, Status::Ok | Status::NotFound) {
            // A cache timeout must not erase a report that was already fully decoded.
            match timeout_at(
                deadline,
                self.storage.cache_put(
                    id,
                    key,
                    provider.adapter.payload_version(),
                    indicator.input.kind,
                    &result.outcome,
                    deadline,
                ),
            )
            .await
            {
                Ok(Ok(expiry)) => result.expires_at = expiry,
                _ => tracing::warn!(
                    provider = id.as_str(),
                    code = "storage_unavailable",
                    "cache_write_failed"
                ),
            }
        }
        result
    }

    async fn fetch(
        &self,
        provider: &Provider,
        indicator: &ValidatedIndicator,
        deadline: Instant,
    ) -> Outcome {
        let id = provider.adapter.id();
        for attempt in 0..=1 {
            let attempt_result = async {
                // Provider capacity first: a saturated provider never monopolizes global permits.
                let _provider_permit = provider
                    .permits
                    .acquire()
                    .await
                    .map_err(|_| ErrorCode::ProviderBusy)?;
                let _global_permit = self
                    .outbound
                    .acquire()
                    .await
                    .map_err(|_| ErrorCode::ProviderBusy)?;
                match self.storage.reserve(id, deadline).await {
                    Ok(()) => {}
                    Err(ReservationError::Limited(delay)) => {
                        let mut outcome = Outcome::failure(ErrorCode::QuotaExhausted);
                        if let Some(error) = outcome.error.as_mut() {
                            error.retry_after_seconds = delay;
                        }
                        return Ok(Attempt {
                            outcome,
                            retry: false,
                            retry_after: None,
                        });
                    }
                    Err(ReservationError::Storage(_)) => return Err(ErrorCode::StorageUnavailable),
                }
                // Cancellation of this future after an uncertain commit can never dispatch later.
                if Instant::now() >= deadline {
                    return Err(ErrorCode::ProviderTimeout);
                }
                let attempt_deadline = deadline.min(Instant::now() + self.config.provider_timeout);
                match timeout_at(
                    attempt_deadline,
                    self.send(&provider.adapter, indicator, deadline),
                )
                .await
                {
                    Ok(result) if Instant::now() < attempt_deadline => result,
                    Ok(_) => Err(ErrorCode::ProviderTimeout),
                    Err(_) => Err(ErrorCode::ProviderTimeout),
                }
            }
            .await;
            let result = match attempt_result {
                Ok(result) => result,
                Err(code) => return Outcome::failure(code),
            };
            let delay = result
                .retry_after
                .unwrap_or(Duration::from_millis(200))
                .max(Duration::from_millis(200));
            if attempt == 0
                && result.retry
                && deadline.saturating_duration_since(Instant::now())
                    >= delay.saturating_add(self.config.provider_timeout)
            {
                tracing::info!(provider = id.as_str(), retry_count = 1, "provider_retry");
                tokio::time::sleep(delay).await;
            } else {
                return result.outcome;
            }
        }
        Outcome::failure(ErrorCode::InternalError)
    }

    async fn send(
        &self,
        adapter: &Adapter,
        indicator: &ValidatedIndicator,
        deadline: Instant,
    ) -> Result<Attempt, ErrorCode> {
        let response = match adapter.request(indicator)?.send().await {
            Ok(response) => response,
            Err(error) => {
                let tls = is_tls_error(&error);
                let code = if tls {
                    ErrorCode::ProviderTlsError
                } else if error.is_timeout() {
                    ErrorCode::ProviderTimeout
                } else {
                    ErrorCode::NetworkError
                };
                return Ok(Attempt {
                    outcome: Outcome::failure(code),
                    retry: !tls
                        && !error.is_timeout()
                        && (error.is_connect() || is_connection_reset(&error)),
                    retry_after: None,
                });
            }
        };
        let status = response.status().as_u16();
        let now = self.clock.now();
        let feedback = feedback_from_headers(adapter.id(), status, response.headers(), now);
        let retry_after = parse_retry_after(
            response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            now,
        );
        // Record feedback even if the body is malformed or oversized.
        let feedback_delay = feedback
            .cooldown_until
            .map(|until| seconds_until(until, now));
        let unknown_reset = feedback.unknown_reset;
        if (feedback.cooldown_until.is_some() || feedback.remaining.is_some())
            && self
                .storage
                .feedback(adapter.id(), feedback, deadline)
                .await
                .is_err()
        {
            tracing::warn!(
                provider = adapter.id().as_str(),
                "quota_feedback_persistence_failed"
            );
        }
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) if is_connection_reset(&error) => {
                    return Ok(Attempt {
                        outcome: Outcome::failure(ErrorCode::NetworkError),
                        retry: true,
                        retry_after: None,
                    });
                }
                Err(error) => {
                    return Err(if error.is_timeout() {
                        ErrorCode::ProviderTimeout
                    } else {
                        ErrorCode::InvalidResponse
                    });
                }
            };
            if chunk.len() > self.config.max_provider_bytes.saturating_sub(body.len()) {
                return Err(ErrorCode::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        let mut outcome = match adapter.decode(status, &body, indicator, self.clock.now()) {
            Ok(outcome) => outcome,
            Err(code) => Outcome::failure(code),
        };
        if let Some(raw) = &outcome.raw {
            let mut writer =
                crate::serialization::LimitedWriter::new(self.config.max_provider_bytes);
            serde_json::to_writer(&mut writer, raw).map_err(|_| ErrorCode::ResponseTooLarge)?;
        }
        if matches!(outcome.status, Status::Ok | Status::NotFound) {
            outcome.fetched_at = Some(self.clock.now());
        }
        if status == 429
            && let Some(error) = outcome.error.as_mut()
        {
            error.retry_after_seconds = match self.storage.retry_after(adapter.id(), deadline).await
            {
                Ok(delay) => delay,
                Err(_) => {
                    if unknown_reset {
                        None
                    } else {
                        feedback_delay
                    }
                }
            };
        }
        Ok(Attempt {
            outcome,
            retry: matches!(status, 502..=504),
            retry_after,
        })
    }
}

struct Attempt {
    outcome: Outcome,
    retry: bool,
    retry_after: Option<Duration>,
}

pub fn cache_key(
    adapter: &Adapter,
    indicator: &ValidatedIndicator,
) -> Result<String, serde_json::Error> {
    let tuple = (
        adapter.id(),
        adapter.payload_version(),
        indicator.input.kind,
        indicator.hash_algorithm,
        &indicator.lookup_value,
        adapter.cache_options(),
    );
    let bytes = serde_json::to_vec(&tuple)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn parse_retry_after(value: Option<&str>, now: DateTime<Utc>) -> Option<Duration> {
    let value = value?;
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        return value.parse::<u64>().ok().map(Duration::from_secs);
    }
    let date: DateTime<Utc> = httpdate::parse_http_date(value).ok()?.into();
    Some(Duration::from_secs(seconds_until(date, now)))
}

fn seconds_until(until: DateTime<Utc>, now: DateTime<Utc>) -> u64 {
    let milliseconds = (until - now).num_milliseconds().max(0) as u64;
    milliseconds.div_ceil(1000)
}

fn feedback_from_headers(
    id: ProviderId,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    now: DateTime<Utc>,
) -> QuotaFeedback {
    let retry = parse_retry_after(
        headers.get("retry-after").and_then(|v| v.to_str().ok()),
        now,
    );
    let number = |name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v <= i64::MAX as u64)
    };
    let (remaining, reset_at) = if id == ProviderId::Abuseipdb {
        (
            number("x-ratelimit-remaining"),
            number("x-ratelimit-reset")
                .and_then(|seconds| i64::try_from(seconds).ok())
                .and_then(|seconds| DateTime::from_timestamp(seconds, 0)),
        )
    } else {
        (None, None)
    };
    let retry_until = retry
        .and_then(|duration| chrono::Duration::from_std(duration).ok())
        .and_then(|duration| now.checked_add_signed(duration));
    let known = retry_until
        .into_iter()
        .chain(if status == 429 || remaining == Some(0) {
            reset_at
        } else {
            None
        })
        .max();
    let cooldown_until = if status == 429 {
        known.or_else(|| now.checked_add_signed(chrono::Duration::seconds(60)))
    } else {
        known
    };
    QuotaFeedback {
        cooldown_until,
        unknown_reset: status == 429 && known.is_none(),
        remaining,
        reset_at,
    }
}

fn is_tls_error(error: &reqwest::Error) -> bool {
    use std::error::Error;
    let mut source = error.source();
    while let Some(cause) = source {
        // Used for classification only. Never emit third-party display strings.
        let message = cause.to_string().to_ascii_lowercase();
        if message.contains("certificate") || message.contains("tls") || message.contains("ssl") {
            return true;
        }
        source = cause.source();
    }
    false
}

fn is_connection_reset(error: &reqwest::Error) -> bool {
    use std::error::Error;
    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(io) = cause.downcast_ref::<std::io::Error>()
            && matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            )
        {
            return true;
        }
        source = cause.source();
    }
    false
}

#[cfg(test)]
#[path = "../tests/upstream/mod.rs"]
mod upstream_tests;

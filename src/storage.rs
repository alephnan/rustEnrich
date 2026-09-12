//! Durable local cache and conservative per-provider attempt accounting.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use fs2::FileExt;
use sqlx::{
    ConnectOptions, Row, Sqlite, SqlitePool, Transaction,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use tokio::{sync::Mutex as AsyncMutex, time::Instant};

use crate::{
    clock::Clock,
    config::Config,
    domain::{IndicatorKind, Outcome, ProviderId, Status},
};

const SCHEMA_VERSION: i64 = 1;
const CLEANUP_CHUNK: i64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("Storage is unavailable.")]
    Unavailable,
    #[error("Storage operation exceeded its deadline.")]
    Timeout,
    #[error("Another process owns the database.")]
    AlreadyOwned,
    #[error("Database schema is newer than this service supports.")]
    NewerSchema,
    #[error("Database contents or schema are invalid.")]
    InvalidData,
}

impl From<sqlx::Error> for StorageError {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationError {
    Storage(StorageError),
    Limited(Option<u64>),
}

impl From<StorageError> for ReservationError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

#[derive(Clone)]
pub struct CachedOutcome {
    pub outcome: Outcome,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default)]
pub struct QuotaFeedback {
    pub cooldown_until: Option<DateTime<Utc>>,
    pub unknown_reset: bool,
    pub remaining: Option<u64>,
    pub reset_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
struct PendingFeedback {
    generation: u64,
    feedback: QuotaFeedback,
}

struct RuntimeState {
    high_water: i64,
    next_generation: u64,
    pending: BTreeMap<&'static str, PendingFeedback>,
}

#[derive(Clone, Copy)]
struct QuotaLimits {
    minute: u64,
    day: u64,
    unobserved_attempts: u64,
}

pub struct Storage {
    pool: SqlitePool,
    ownership: Mutex<Option<File>>,
    gate: AsyncMutex<()>,
    runtime: Mutex<RuntimeState>,
    available: AtomicBool,
    clock: Arc<dyn Clock>,
    timeout: Duration,
    max_entries: i64,
    max_bytes: i64,
    ip_ttl: i64,
    url_ttl: i64,
    hash_ttl: i64,
    not_found_ttl: i64,
    abuseipdb_limits: QuotaLimits,
    virustotal_limits: QuotaLimits,
}

impl Storage {
    pub async fn open(config: &Config, clock: Arc<dyn Clock>) -> Result<Arc<Self>, StorageError> {
        let path = config.database_path.clone();
        // The lock is OS-owned: a stale filename never prevents recovery after exit.
        let (ownership, path) = tokio::task::spawn_blocking(move || {
            if path.to_string_lossy().starts_with("\\\\") || path.as_os_str() == ":memory:" {
                return Err(StorageError::Unavailable);
            }
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|_| StorageError::Unavailable)?;
            }
            let path = if path.exists() {
                std::fs::canonicalize(&path).map_err(|_| StorageError::Unavailable)?
            } else {
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| std::path::Path::new("."));
                std::fs::canonicalize(parent)
                    .map_err(|_| StorageError::Unavailable)?
                    .join(path.file_name().ok_or(StorageError::Unavailable)?)
            };
            let mut lock_path = path.as_os_str().to_os_string();
            lock_path.push(".lock");
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(lock_path)
                .map_err(|_| StorageError::Unavailable)?;
            FileExt::try_lock_exclusive(&file).map_err(|_| StorageError::AlreadyOwned)?;
            Ok::<_, StorageError>((file, path))
        })
        .await
        .map_err(|_| StorageError::Unavailable)??;

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_millis(250))
            .disable_statement_logging();
        let pool = tokio::time::timeout(
            config.storage_timeout,
            SqlitePoolOptions::new()
                .max_connections(1)
                .min_connections(1)
                .acquire_timeout(config.storage_timeout)
                .connect_with(options),
        )
        .await
        .map_err(|_| StorageError::Timeout)??;

        let this = Arc::new(Self {
            pool,
            ownership: Mutex::new(Some(ownership)),
            gate: AsyncMutex::new(()),
            runtime: Mutex::new(RuntimeState {
                high_water: i64::MIN,
                next_generation: 0,
                pending: BTreeMap::new(),
            }),
            available: AtomicBool::new(false),
            clock,
            timeout: config.storage_timeout,
            max_entries: i64::try_from(config.cache_max_entries)
                .map_err(|_| StorageError::InvalidData)?,
            max_bytes: i64::try_from(config.cache_max_bytes)
                .map_err(|_| StorageError::InvalidData)?,
            ip_ttl: ttl_millis(config.cache_ip_ttl)?,
            url_ttl: ttl_millis(config.cache_url_ttl)?,
            hash_ttl: ttl_millis(config.cache_hash_ttl)?,
            not_found_ttl: ttl_millis(config.cache_not_found_ttl)?,
            abuseipdb_limits: QuotaLimits {
                minute: config.abuseipdb.requests_per_minute,
                day: config.abuseipdb.requests_per_day,
                unobserved_attempts: config.abuseipdb.max_concurrency.saturating_sub(1) as u64,
            },
            virustotal_limits: QuotaLimits {
                minute: config.virustotal.requests_per_minute,
                day: config.virustotal.requests_per_day,
                unobserved_attempts: config.virustotal.max_concurrency.saturating_sub(1) as u64,
            },
        });
        for limits in [this.abuseipdb_limits, this.virustotal_limits] {
            if limits.day > i64::MAX as u64 || limits.minute > i64::MAX as u64 {
                return Err(StorageError::InvalidData);
            }
        }
        this.bounded(Instant::now() + this.timeout, this.initialize())
            .await?;
        Ok(this)
    }

    async fn initialize(&self) -> Result<(), StorageError> {
        let mut connection = self.pool.acquire().await?;
        let schema: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut *connection)
            .await?;
        if schema > SCHEMA_VERSION {
            return Err(StorageError::NewerSchema);
        }
        if schema < 0 {
            return Err(StorageError::InvalidData);
        }
        let integrity: String = sqlx::query_scalar("PRAGMA quick_check(1)")
            .fetch_one(&mut *connection)
            .await?;
        if integrity != "ok" {
            return Err(StorageError::InvalidData);
        }
        drop(connection);
        let now = self.clock.now();
        if schema == 0 {
            let mut tx = self.pool.begin().await?;
            let existing_tables: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").fetch_one(&mut *tx).await?;
            if existing_tables != 0 {
                return Err(StorageError::InvalidData);
            }
            sqlx::raw_sql(include_str!("../migrations/0001_initial.sql"))
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO storage_metadata (singleton, clock_high_water) VALUES (1, ?)")
                .bind(now.timestamp_millis())
                .execute(&mut *tx)
                .await?;
            for group in ["abuseipdb_check", "virustotal"] {
                sqlx::query("INSERT INTO quota_state (quota_group, utc_day) VALUES (?, ?)")
                    .bind(group)
                    .bind(now.date_naive().to_string())
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("PRAGMA user_version = 1")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT provider, cache_key, payload_version, kind, outcome, fetched_at, expires_at, payload, payload_bytes FROM cache_entries LIMIT 0").execute(&mut *tx).await?;
        sqlx::query("SELECT id, quota_group, reserved_at FROM quota_attempts LIMIT 0")
            .execute(&mut *tx)
            .await?;
        let high_water: i64 =
            sqlx::query_scalar("SELECT clock_high_water FROM storage_metadata WHERE singleton = 1")
                .fetch_one(&mut *tx)
                .await?;
        if DateTime::from_timestamp_millis(high_water).is_none() {
            return Err(StorageError::InvalidData);
        }
        self.runtime
            .lock()
            .map_err(|_| StorageError::Unavailable)?
            .high_water = high_water;
        for group in ["abuseipdb_check", "virustotal"] {
            let state = QuotaState::read(&mut tx, group).await?;
            chrono::NaiveDate::parse_from_str(&state.day, "%Y-%m-%d")
                .map_err(|_| StorageError::InvalidData)?;
            for timestamp in [state.cooldown_until, state.provider_reset_at]
                .into_iter()
                .flatten()
            {
                if DateTime::from_timestamp_millis(timestamp).is_none() {
                    return Err(StorageError::InvalidData);
                }
            }
        }
        let (wall, effective) = self.observe_time()?;
        while self.delete_expired(&mut tx, wall, effective).await? == CLEANUP_CHUNK as u64 {}
        self.evict(&mut tx).await?;
        tx.commit().await?;
        tracing::info!(schema_version = SCHEMA_VERSION, "storage initialized");
        Ok(())
    }

    async fn bounded<T>(
        &self,
        deadline: Instant,
        operation: impl Future<Output = Result<T, StorageError>>,
    ) -> Result<T, StorageError> {
        let deadline = deadline.min(Instant::now() + self.timeout);
        let mut result = if Instant::now() >= deadline {
            Err(StorageError::Timeout)
        } else {
            tokio::time::timeout_at(deadline, operation)
                .await
                .unwrap_or(Err(StorageError::Timeout))
        };
        if Instant::now() >= deadline {
            result = Err(StorageError::Timeout);
        }
        self.available.store(result.is_ok(), Ordering::Release);
        if result.is_err() {
            tracing::warn!(
                error_code = "storage_unavailable",
                "storage operation failed"
            );
        }
        result
    }

    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    pub fn is_healthy(&self) -> bool {
        self.is_available()
    }

    fn observe_time(&self) -> Result<(i64, i64), StorageError> {
        let wall = self.clock.now().timestamp_millis();
        let mut runtime = self.runtime.lock().map_err(|_| StorageError::Unavailable)?;
        runtime.high_water = runtime.high_water.max(wall);
        Ok((wall, runtime.high_water))
    }

    fn ttl(&self, kind: IndicatorKind, status: Status) -> i64 {
        if status == Status::NotFound {
            return self.not_found_ttl;
        }
        match kind {
            IndicatorKind::Ip => self.ip_ttl,
            IndicatorKind::Url => self.url_ttl,
            IndicatorKind::Hash => self.hash_ttl,
        }
    }

    pub async fn cache_get(
        &self,
        provider: ProviderId,
        key: &str,
        kind: IndicatorKind,
        deadline: Instant,
    ) -> Result<Option<CachedOutcome>, StorageError> {
        self.bounded(deadline, async {
            let _guard = self.gate.lock().await;
            let row = sqlx::query("SELECT outcome, fetched_at, expires_at, payload FROM cache_entries WHERE provider = ? AND cache_key = ? AND kind = ?")
                .bind(provider_name(provider)).bind(key).bind(kind_name(kind)).fetch_optional(&self.pool).await?;
            let (wall, now) = self.observe_time()?;
            let Some(row) = row else { return Ok(None); };
            let status: String = row.try_get("outcome")?;
            let status = match status.as_str() { "ok" => Status::Ok, "not_found" => Status::NotFound, _ => return Err(StorageError::InvalidData) };
            let ttl = self.ttl(kind, status);
            if ttl == 0 { return Ok(None); }
            let fetched: i64 = row.try_get("fetched_at")?;
            let expires: i64 = row.try_get("expires_at")?;
            let effective_expiry = expires.min(fetched.checked_add(ttl).ok_or(StorageError::InvalidData)?);
            if now >= effective_expiry {
                // Persist observed expiry on a miss so a restart followed by clock
                // rollback cannot resurrect this row. Fresh hits remain read-only.
                sqlx::query("DELETE FROM cache_entries WHERE provider = ? AND cache_key = ?")
                    .bind(provider_name(provider)).bind(key).execute(&self.pool).await?;
                return Ok(None);
            }
            if fetched > wall { return Ok(None); }
            let payload: Vec<u8> = row.try_get("payload")?;
            let outcome: Outcome = serde_json::from_slice(&payload).map_err(|_| StorageError::InvalidData)?;
            if outcome.status != status || outcome.fetched_at.map(|t| t.timestamp_millis()) != Some(fetched) || outcome.error.is_some() {
                return Err(StorageError::InvalidData);
            }
            Ok(Some(CachedOutcome { outcome, expires_at: DateTime::from_timestamp_millis(effective_expiry).ok_or(StorageError::InvalidData)? }))
        }).await
    }

    pub async fn cache_put(
        &self,
        provider: ProviderId,
        key: &str,
        version: u32,
        kind: IndicatorKind,
        outcome: &Outcome,
        deadline: Instant,
    ) -> Result<Option<DateTime<Utc>>, StorageError> {
        let deadline = deadline.min(Instant::now() + self.timeout);
        if !matches!(outcome.status, Status::Ok | Status::NotFound) {
            return Ok(None);
        }
        let ttl = self.ttl(kind, outcome.status);
        if ttl == 0 {
            return Ok(None);
        }
        let fetched = outcome
            .fetched_at
            .ok_or(StorageError::InvalidData)?
            .timestamp_millis();
        if outcome.error.is_some() || fetched > self.clock.now().timestamp_millis() {
            return Ok(None);
        }
        let expires = fetched.checked_add(ttl).ok_or(StorageError::InvalidData)?;
        let expires_at =
            DateTime::from_timestamp_millis(expires).ok_or(StorageError::InvalidData)?;
        let mut writer = crate::serialization::LimitedWriter::new(self.max_bytes as usize);
        if let Err(error) = serde_json::to_writer(&mut writer, outcome) {
            return if error.is_io() {
                Ok(None)
            } else {
                Err(StorageError::InvalidData)
            };
        }
        let payload = writer.bytes;
        let bytes = i64::try_from(payload.len()).map_err(|_| StorageError::InvalidData)?;
        self.bounded(deadline, async {
            let _guard = self.gate.lock().await;
            let (wall, now) = self.observe_time()?;
            if fetched > wall || now >= expires { return Ok(None); }
            let mut tx = self.pool.begin().await?;
            self.delete_expired(&mut tx, wall, now).await?;
            sqlx::query("INSERT INTO cache_entries (provider, cache_key, payload_version, kind, outcome, fetched_at, expires_at, payload, payload_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (provider, cache_key) DO UPDATE SET payload_version=excluded.payload_version, kind=excluded.kind, outcome=excluded.outcome, fetched_at=excluded.fetched_at, expires_at=excluded.expires_at, payload=excluded.payload, payload_bytes=excluded.payload_bytes")
                .bind(provider_name(provider)).bind(key).bind(i64::from(version)).bind(kind_name(kind))
                .bind(if outcome.status == Status::Ok { "ok" } else { "not_found" })
                .bind(fetched).bind(expires).bind(payload).bind(bytes).execute(&mut *tx).await?;
            self.evict(&mut tx).await?;
            let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cache_entries WHERE provider = ? AND cache_key = ?")
                .bind(provider_name(provider)).bind(key).fetch_one(&mut *tx).await?;
            tx.commit().await?;
            Ok((retained == 1).then_some(expires_at))
        }).await
    }

    async fn delete_expired(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        wall: i64,
        now: i64,
    ) -> Result<u64, StorageError> {
        let result = sqlx::query("DELETE FROM cache_entries WHERE rowid IN (SELECT rowid FROM cache_entries WHERE expires_at <= ? OR fetched_at > ? OR fetched_at <= ? - CASE WHEN outcome = 'not_found' THEN ? WHEN kind = 'ip' THEN ? WHEN kind = 'url' THEN ? ELSE ? END ORDER BY expires_at, cache_key, provider LIMIT ?)")
            .bind(now).bind(wall).bind(now).bind(self.not_found_ttl).bind(self.ip_ttl).bind(self.url_ttl).bind(self.hash_ttl).bind(CLEANUP_CHUNK)
            .execute(&mut **tx).await?;
        Ok(result.rows_affected())
    }

    async fn evict(&self, tx: &mut Transaction<'_, Sqlite>) -> Result<(), StorageError> {
        let totals = sqlx::query("SELECT COUNT(*) AS entries, COALESCE(SUM(payload_bytes), 0) AS bytes FROM cache_entries").fetch_one(&mut **tx).await?;
        let mut entries: i64 = totals.try_get("entries")?;
        let mut bytes: i64 = totals.try_get("bytes")?;
        while entries > self.max_entries || bytes > self.max_bytes {
            let rows = sqlx::query("SELECT payload_bytes FROM cache_entries ORDER BY fetched_at, cache_key, provider LIMIT ?")
                .bind(CLEANUP_CHUNK).fetch_all(&mut **tx).await?;
            let mut count = 0_i64;
            for row in rows {
                if entries <= self.max_entries && bytes <= self.max_bytes {
                    break;
                }
                entries -= 1;
                bytes -= row.try_get::<i64, _>("payload_bytes")?;
                count += 1;
            }
            if count == 0 {
                return Err(StorageError::InvalidData);
            }
            sqlx::query("DELETE FROM cache_entries WHERE rowid IN (SELECT rowid FROM cache_entries ORDER BY fetched_at, cache_key, provider LIMIT ?)")
                .bind(count).execute(&mut **tx).await?;
        }
        Ok(())
    }

    pub async fn cleanup(&self, deadline: Instant) -> Result<(), StorageError> {
        self.bounded(deadline, async {
            let _guard = self.gate.lock().await;
            let mut tx = self.pool.begin().await?;
            let (wall, now) = self.observe_time()?;
            self.delete_expired(&mut tx, wall, now).await?;
            tx.commit().await?;
            Ok(())
        })
        .await
    }

    pub async fn reserve(
        &self,
        provider: ProviderId,
        deadline: Instant,
    ) -> Result<(), ReservationError> {
        self.bounded(deadline, async {
            let _guard = self.gate.lock().await;
            let wall = self.clock.now();
            let (now, pending) = {
                let mut runtime = self.runtime.lock().map_err(|_| StorageError::Unavailable)?;
                runtime.high_water = runtime.high_water.max(wall.timestamp_millis());
                (
                    runtime.high_water,
                    runtime.pending.get(quota_group(provider)).cloned(),
                )
            };
            // After rollback or restart, even the effective clock reaching a boundary
            // cannot grant quota until the real UTC clock catches the durable mark.
            if wall.timestamp_millis() < now {
                return Ok(Err(ReservationError::Limited(Some(delay_seconds(
                    now,
                    wall.timestamp_millis(),
                )))));
            }
            let group = quota_group(provider);
            let limits = self.limits(provider);
            let mut tx = self.pool.begin().await?;
            let mut state = QuotaState::read(&mut tx, group).await?;
            state.advance_day(wall)?;
            if let Some(ref pending) = pending {
                state.apply_feedback(&pending.feedback, now, limits.unobserved_attempts)?;
            }
            sqlx::query("DELETE FROM quota_attempts WHERE quota_group = ? AND reserved_at <= ?")
                .bind(group)
                .bind(now.saturating_sub(60_000))
                .execute(&mut *tx)
                .await?;

            let decision = quota_decision(&mut tx, group, limits, &state, now, now).await?;
            if !decision.blocked {
                state.daily_consumed = state
                    .daily_consumed
                    .checked_add(1)
                    .ok_or(StorageError::InvalidData)?;
                if let Some(remaining) = state.provider_remaining.as_mut() {
                    *remaining = remaining.saturating_sub(1);
                }
                state.ensure_unknown_cooldown(now);
                if limits.minute > 0 {
                    sqlx::query(
                        "INSERT INTO quota_attempts (quota_group, reserved_at) VALUES (?, ?)",
                    )
                    .bind(group)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            state.write(&mut tx, group).await?;
            persist_high_water(&mut tx, now).await?;
            // A timeout can cancel this await after SQLite commits. Its caller still
            // gets an error, and must never dispatch or refund this reservation.
            tx.commit().await?;
            self.clear_pending(group, pending.as_ref())?;
            if self
                .runtime
                .lock()
                .map_err(|_| StorageError::Unavailable)?
                .pending
                .contains_key(group)
            {
                // New feedback arrived after this transaction took its snapshot.
                // Retain the consumed reservation, but never dispatch past it.
                return Err(StorageError::Unavailable);
            }
            if decision.blocked {
                tracing::info!(
                    provider = provider_name(provider),
                    "quota reservation denied"
                );
                Ok(Err(ReservationError::Limited(decision.retry_after)))
            } else {
                Ok(Ok(()))
            }
        })
        .await?
    }

    /// The longest established wait, without consuming an attempt. Unknown
    /// provider resets remain unknown even if a local minute window is known.
    pub async fn retry_after(
        &self,
        provider: ProviderId,
        deadline: Instant,
    ) -> Result<Option<u64>, StorageError> {
        self.bounded(deadline, async {
            let _guard = self.gate.lock().await;
            let group = quota_group(provider);
            let limits = self.limits(provider);
            let wall = self.clock.now().timestamp_millis();
            let (now, pending) = {
                let runtime = self.runtime.lock().map_err(|_| StorageError::Unavailable)?;
                (
                    runtime.high_water.max(wall),
                    runtime.pending.get(group).cloned(),
                )
            };
            let effective =
                DateTime::from_timestamp_millis(now).ok_or(StorageError::InvalidData)?;
            let mut tx = self.pool.begin().await?;
            let mut state = QuotaState::read(&mut tx, group).await?;
            state.advance_day(effective)?;
            if let Some(pending) = pending {
                state.apply_feedback(&pending.feedback, now, limits.unobserved_attempts)?;
            }
            let decision = quota_decision(&mut tx, group, limits, &state, now, wall).await?;
            tx.rollback().await?;
            Ok(decision.retry_after)
        })
        .await
    }

    pub async fn feedback(
        &self,
        provider: ProviderId,
        feedback: QuotaFeedback,
        deadline: Instant,
    ) -> Result<(), StorageError> {
        let group = quota_group(provider);
        {
            let mut runtime = self.runtime.lock().map_err(|_| StorageError::Unavailable)?;
            runtime.next_generation = runtime.next_generation.wrapping_add(1);
            let generation = runtime.next_generation;
            let merged = runtime
                .pending
                .get(group)
                .map(|old| merge_feedback(&old.feedback, &feedback))
                .unwrap_or(feedback);
            // Retain before the first await, including when lock/pool/commit is canceled.
            runtime.pending.insert(
                group,
                PendingFeedback {
                    generation,
                    feedback: merged,
                },
            );
        }
        self.bounded(deadline, async {
            let _guard = self.gate.lock().await;
            let (now, pending) = {
                let mut runtime = self.runtime.lock().map_err(|_| StorageError::Unavailable)?;
                runtime.high_water = runtime.high_water.max(self.clock.now().timestamp_millis());
                (runtime.high_water, runtime.pending.get(group).cloned())
            };
            let Some(pending) = pending else {
                return Ok(());
            };
            let mut tx = self.pool.begin().await?;
            let mut state = QuotaState::read(&mut tx, group).await?;
            state.apply_feedback(
                &pending.feedback,
                now,
                self.limits(provider).unobserved_attempts,
            )?;
            state.write(&mut tx, group).await?;
            persist_high_water(&mut tx, now).await?;
            tx.commit().await?;
            self.clear_pending(group, Some(&pending))?;
            Ok(())
        })
        .await
    }

    fn clear_pending(
        &self,
        group: &'static str,
        saved: Option<&PendingFeedback>,
    ) -> Result<(), StorageError> {
        let Some(saved) = saved else {
            return Ok(());
        };
        let mut runtime = self.runtime.lock().map_err(|_| StorageError::Unavailable)?;
        if runtime
            .pending
            .get(group)
            .is_some_and(|pending| pending.generation == saved.generation)
        {
            runtime.pending.remove(group);
        }
        Ok(())
    }

    fn limits(&self, provider: ProviderId) -> QuotaLimits {
        match provider {
            ProviderId::Abuseipdb => self.abuseipdb_limits,
            ProviderId::Virustotal => self.virustotal_limits,
        }
    }

    pub async fn health(&self, deadline: Instant) -> Result<(), StorageError> {
        self.bounded(deadline, async {
            let _guard = self.gate.lock().await;
            let mut tx = self.pool.begin().await?;
            let _: i64 = sqlx::query_scalar("SELECT clock_high_water FROM storage_metadata WHERE singleton = 1").fetch_one(&mut *tx).await?;
            sqlx::query("UPDATE storage_metadata SET clock_high_water = clock_high_water WHERE singleton = 1").execute(&mut *tx).await?;
            tx.rollback().await?;
            Ok(())
        }).await
    }

    pub async fn close(&self) {
        self.available.store(false, Ordering::Release);
        self.pool.close().await;
        if let Ok(mut owner) = self.ownership.lock() {
            owner.take();
        }
    }
}

struct QuotaState {
    day: String,
    daily_consumed: u64,
    cooldown_until: Option<i64>,
    cooldown_unknown: bool,
    provider_remaining: Option<u64>,
    provider_reset_at: Option<i64>,
}

impl QuotaState {
    async fn read(tx: &mut Transaction<'_, Sqlite>, group: &str) -> Result<Self, StorageError> {
        let row = sqlx::query("SELECT * FROM quota_state WHERE quota_group = ?")
            .bind(group)
            .fetch_one(&mut **tx)
            .await?;
        let consumed: i64 = row.try_get("daily_consumed")?;
        let remaining: Option<i64> = row.try_get("provider_remaining")?;
        Ok(Self {
            day: row.try_get("utc_day")?,
            daily_consumed: u64::try_from(consumed).map_err(|_| StorageError::InvalidData)?,
            cooldown_until: row.try_get("cooldown_until")?,
            cooldown_unknown: row.try_get("cooldown_unknown")?,
            provider_remaining: remaining
                .map(u64::try_from)
                .transpose()
                .map_err(|_| StorageError::InvalidData)?,
            provider_reset_at: row.try_get("provider_reset_at")?,
        })
    }

    fn advance_day(&mut self, now: DateTime<Utc>) -> Result<(), StorageError> {
        let saved = chrono::NaiveDate::parse_from_str(&self.day, "%Y-%m-%d")
            .map_err(|_| StorageError::InvalidData)?;
        if now.date_naive() < saved {
            return Err(StorageError::InvalidData);
        }
        if now.date_naive() > saved {
            self.day = now.date_naive().to_string();
            self.daily_consumed = 0;
            if self.provider_reset_at.is_none() {
                self.provider_remaining = None;
            }
        }
        self.expire_feedback(now.timestamp_millis());
        Ok(())
    }

    fn expire_feedback(&mut self, now: i64) {
        if self.provider_reset_at.is_some_and(|reset| reset <= now) {
            self.provider_remaining = None;
            self.provider_reset_at = None;
        }
        if self.cooldown_until.is_some_and(|until| until <= now) {
            if self.provider_reset_at.is_none() && self.provider_remaining == Some(0) {
                self.provider_remaining = None;
            }
            self.cooldown_until = None;
            self.cooldown_unknown = false;
        }
    }

    fn apply_feedback(
        &mut self,
        feedback: &QuotaFeedback,
        now: i64,
        unobserved_attempts: u64,
    ) -> Result<(), StorageError> {
        self.expire_feedback(now);
        if let Some(until) = feedback
            .cooldown_until
            .map(|v| v.timestamp_millis())
            .filter(|v| *v > now)
        {
            if self.cooldown_until.is_none_or(|old| until > old) {
                self.cooldown_until = Some(until);
                self.cooldown_unknown = feedback.unknown_reset;
            } else if self.cooldown_until == Some(until) {
                self.cooldown_unknown |= feedback.unknown_reset;
            }
        }
        let reset = feedback.reset_at.map(|v| v.timestamp_millis());
        // A late response for an ended window cannot constrain or replenish the
        // current one; within a window remaining can only decrease.
        if reset.is_some_and(|v| v <= now) {
            return Ok(());
        }
        if let Some(remaining) = feedback.remaining {
            if remaining > i64::MAX as u64 {
                return Err(StorageError::InvalidData);
            }
            // The first response can precede other already-reserved attempts. Leave
            // room for every possible outstanding attempt until headers establish
            // a baseline. This intentionally favors underuse near external exhaustion.
            self.provider_remaining = Some(self.provider_remaining.map_or_else(
                || remaining.saturating_sub(unobserved_attempts),
                |old| old.min(remaining),
            ));
        }
        if let Some(reset) = reset {
            self.provider_reset_at =
                Some(self.provider_reset_at.map_or(reset, |old| old.max(reset)));
        }
        self.ensure_unknown_cooldown(now);
        Ok(())
    }

    fn ensure_unknown_cooldown(&mut self, now: i64) {
        if self.provider_remaining == Some(0)
            && self.provider_reset_at.is_none()
            && self.cooldown_until.is_none()
        {
            // Missing reset headers permit paced probes, never a promised reset.
            self.cooldown_until = Some(now.saturating_add(60_000));
            self.cooldown_unknown = true;
        }
    }

    async fn write(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        group: &str,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE quota_state SET utc_day = ?, daily_consumed = ?, cooldown_until = ?, cooldown_unknown = ?, provider_remaining = ?, provider_reset_at = ? WHERE quota_group = ?")
            .bind(&self.day).bind(i64::try_from(self.daily_consumed).map_err(|_| StorageError::InvalidData)?)
            .bind(self.cooldown_until).bind(self.cooldown_unknown)
            .bind(self.provider_remaining.map(i64::try_from).transpose().map_err(|_| StorageError::InvalidData)?)
            .bind(self.provider_reset_at).bind(group).execute(&mut **tx).await?;
        Ok(())
    }
}

struct QuotaDecision {
    blocked: bool,
    retry_after: Option<u64>,
}

async fn quota_decision(
    tx: &mut Transaction<'_, Sqlite>,
    group: &str,
    limits: QuotaLimits,
    state: &QuotaState,
    now: i64,
    actual_now: i64,
) -> Result<QuotaDecision, StorageError> {
    let mut delay = delay_seconds(now, actual_now);
    let mut blocked = actual_now < now;
    let mut unknown = false;
    if let Some(until) = state.cooldown_until.filter(|until| *until > now) {
        blocked = true;
        delay = delay.max(delay_seconds(until, actual_now));
        unknown = state.cooldown_unknown;
    }
    if state.daily_consumed >= limits.day {
        blocked = true;
        let effective = DateTime::from_timestamp_millis(now).ok_or(StorageError::InvalidData)?;
        delay = delay.max(delay_seconds(next_day_millis(effective)?, actual_now));
    }
    if state.provider_remaining == Some(0) {
        blocked = true;
        match state.provider_reset_at.filter(|reset| *reset > now) {
            Some(reset) => delay = delay.max(delay_seconds(reset, actual_now)),
            None => unknown = true,
        }
    }
    if limits.minute > 0 {
        let attempts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM quota_attempts WHERE quota_group = ? AND reserved_at > ?",
        )
        .bind(group)
        .bind(now.saturating_sub(60_000))
        .fetch_one(&mut **tx)
        .await?;
        let attempts = u64::try_from(attempts).map_err(|_| StorageError::InvalidData)?;
        if attempts >= limits.minute {
            blocked = true;
            // A reduced cap can require several reservations to age out.
            let offset =
                i64::try_from(attempts - limits.minute).map_err(|_| StorageError::InvalidData)?;
            let clears_at: i64 = sqlx::query_scalar("SELECT reserved_at FROM quota_attempts WHERE quota_group = ? AND reserved_at > ? ORDER BY reserved_at, id LIMIT 1 OFFSET ?")
                .bind(group).bind(now.saturating_sub(60_000)).bind(offset).fetch_one(&mut **tx).await?;
            delay = delay.max(delay_seconds(clears_at.saturating_add(60_000), actual_now));
        }
    }
    Ok(QuotaDecision {
        blocked,
        retry_after: if blocked && !unknown {
            Some(delay.max(1))
        } else {
            None
        },
    })
}

async fn persist_high_water(
    tx: &mut Transaction<'_, Sqlite>,
    now: i64,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE storage_metadata SET clock_high_water = MAX(clock_high_water, ?) WHERE singleton = 1").bind(now).execute(&mut **tx).await?;
    Ok(())
}

fn merge_feedback(old: &QuotaFeedback, new: &QuotaFeedback) -> QuotaFeedback {
    let (cooldown_until, unknown_reset) = match (old.cooldown_until, new.cooldown_until) {
        (Some(a), Some(b)) if a > b => (Some(a), old.unknown_reset),
        (Some(a), Some(b)) if a == b => (Some(a), old.unknown_reset || new.unknown_reset),
        (_, Some(b)) => (Some(b), new.unknown_reset),
        (Some(a), None) => (Some(a), old.unknown_reset),
        (None, None) => (None, false),
    };
    QuotaFeedback {
        cooldown_until,
        unknown_reset,
        remaining: match (old.remaining, new.remaining) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        },
        reset_at: old.reset_at.max(new.reset_at),
    }
}

fn ttl_millis(duration: Duration) -> Result<i64, StorageError> {
    i64::try_from(duration.as_millis()).map_err(|_| StorageError::InvalidData)
}
fn delay_seconds(until: i64, now: i64) -> u64 {
    until
        .saturating_sub(now)
        .max(0)
        .cast_unsigned()
        .div_ceil(1000)
}
fn next_day_millis(now: DateTime<Utc>) -> Result<i64, StorageError> {
    Ok(now
        .date_naive()
        .succ_opt()
        .and_then(|date| date.and_hms_opt(0, 0, 0))
        .ok_or(StorageError::InvalidData)?
        .and_utc()
        .timestamp_millis())
}
fn provider_name(provider: ProviderId) -> &'static str {
    match provider {
        ProviderId::Abuseipdb => "abuseipdb",
        ProviderId::Virustotal => "virustotal",
    }
}
fn quota_group(provider: ProviderId) -> &'static str {
    match provider {
        ProviderId::Abuseipdb => "abuseipdb_check",
        ProviderId::Virustotal => "virustotal",
    }
}
fn kind_name(kind: IndicatorKind) -> &'static str {
    match kind {
        IndicatorKind::Ip => "ip",
        IndicatorKind::Url => "url",
        IndicatorKind::Hash => "hash",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clock::TestClock,
        domain::{AbuseipdbSummary, ErrorCode, Summary},
    };
    use chrono::TimeDelta;
    use serde_json::json;
    use tempfile::TempDir;

    const PROVIDER: ProviderId = ProviderId::Virustotal;

    fn setup() -> (TempDir, Config, Arc<TestClock>) {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::for_tests();
        config.database_path = directory.path().join("state.sqlite");
        let clock = Arc::new(TestClock(Mutex::new(
            "2026-09-12T12:00:00Z".parse().unwrap(),
        )));
        (directory, config, clock)
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(3)
    }

    fn advance(clock: &TestClock, seconds: i64) {
        let mut now = clock.0.lock().unwrap();
        *now += TimeDelta::seconds(seconds);
    }

    fn report(clock: &TestClock) -> Outcome {
        Outcome {
            status: Status::Ok,
            summary: Some(Summary::Abuseipdb(
                serde_json::from_value::<AbuseipdbSummary>(json!({"abuse_confidence_score":0}))
                    .unwrap(),
            )),
            fetched_at: Some(clock.now()),
            provider_updated_at: None,
            error: None,
            raw: Some(
                json!({"data":{"ipAddress":"192.0.2.1","abuseConfidenceScore":0,"extra":"preserved"}}),
            ),
        }
    }

    async fn put(
        storage: &Storage,
        clock: &TestClock,
        key: &str,
        kind: IndicatorKind,
    ) -> Option<DateTime<Utc>> {
        storage
            .cache_put(PROVIDER, key, 1, kind, &report(clock), deadline())
            .await
            .unwrap()
    }

    async fn hit(storage: &Storage, key: &str, kind: IndicatorKind) -> Option<CachedOutcome> {
        storage
            .cache_get(PROVIDER, key, kind, deadline())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn preserves_payload_timestamps_and_raw_after_restart() {
        let (_dir, config, clock) = setup();
        let original = report(&clock);
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        let expires = storage
            .cache_put(
                PROVIDER,
                "identity",
                1,
                IndicatorKind::Ip,
                &original,
                deadline(),
            )
            .await
            .unwrap()
            .unwrap();
        storage.close().await;
        advance(&clock, 10);
        let reopened = Storage::open(&config, clock.clone()).await.unwrap();
        let cached = hit(&reopened, "identity", IndicatorKind::Ip).await.unwrap();
        assert_eq!(cached.outcome, original);
        assert_eq!(cached.expires_at, expires);
        reopened.close().await;
    }

    #[tokio::test]
    async fn applies_kind_and_not_found_ttls_with_exact_expiry_boundary() {
        let (_dir, mut config, clock) = setup();
        config.cache_ip_ttl = Duration::from_secs(1);
        config.cache_url_ttl = Duration::from_secs(2);
        config.cache_hash_ttl = Duration::from_secs(3);
        config.cache_not_found_ttl = Duration::from_secs(4);
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        for (key, kind) in [
            ("ip", IndicatorKind::Ip),
            ("url", IndicatorKind::Url),
            ("hash", IndicatorKind::Hash),
        ] {
            put(&storage, &clock, key, kind).await.unwrap();
        }
        storage
            .cache_put(
                PROVIDER,
                "missing",
                1,
                IndicatorKind::Ip,
                &Outcome::not_found(clock.now()),
                deadline(),
            )
            .await
            .unwrap();
        advance(&clock, 1);
        assert!(hit(&storage, "ip", IndicatorKind::Ip).await.is_none());
        assert!(hit(&storage, "url", IndicatorKind::Url).await.is_some());
        advance(&clock, 1);
        assert!(hit(&storage, "url", IndicatorKind::Url).await.is_none());
        assert!(hit(&storage, "hash", IndicatorKind::Hash).await.is_some());
        advance(&clock, 1);
        assert!(hit(&storage, "hash", IndicatorKind::Hash).await.is_none());
        assert!(hit(&storage, "missing", IndicatorKind::Ip).await.is_some());
        advance(&clock, 1);
        assert!(hit(&storage, "missing", IndicatorKind::Ip).await.is_none());
        storage.close().await;
    }

    #[tokio::test]
    async fn lower_ttl_takes_effect_without_higher_ttl_extending_saved_expiry() {
        let (_dir, mut config, clock) = setup();
        config.cache_ip_ttl = Duration::from_secs(10);
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        let original_expiry = put(&storage, &clock, "ip", IndicatorKind::Ip)
            .await
            .unwrap();
        storage.close().await;
        config.cache_ip_ttl = Duration::from_secs(100);
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        assert_eq!(
            hit(&storage, "ip", IndicatorKind::Ip)
                .await
                .unwrap()
                .expires_at,
            original_expiry
        );
        storage.close().await;
        config.cache_ip_ttl = Duration::from_secs(5);
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        assert_eq!(
            hit(&storage, "ip", IndicatorKind::Ip)
                .await
                .unwrap()
                .expires_at,
            clock.now() + TimeDelta::seconds(5)
        );
        advance(&clock, 5);
        assert!(hit(&storage, "ip", IndicatorKind::Ip).await.is_none());
        storage.close().await;
    }

    #[tokio::test]
    async fn zero_ttl_disables_cached_use_and_storage() {
        let (_dir, mut config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        put(&storage, &clock, "old", IndicatorKind::Ip)
            .await
            .unwrap();
        storage.close().await;
        config.cache_ip_ttl = Duration::ZERO;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        assert!(hit(&storage, "old", IndicatorKind::Ip).await.is_none());
        assert!(
            put(&storage, &clock, "new", IndicatorKind::Ip)
                .await
                .is_none()
        );
        assert!(
            put(&storage, &clock, "hash", IndicatorKind::Hash)
                .await
                .is_some()
        );
        storage.close().await;
    }

    #[tokio::test]
    async fn future_reports_and_transient_failures_are_not_cache_hits() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        put(&storage, &clock, "future", IndicatorKind::Ip)
            .await
            .unwrap();
        advance(&clock, -1);
        assert!(hit(&storage, "future", IndicatorKind::Ip).await.is_none());
        let failure = Outcome::failure(ErrorCode::StorageUnavailable);
        assert!(
            storage
                .cache_put(
                    PROVIDER,
                    "failure",
                    1,
                    IndicatorKind::Ip,
                    &failure,
                    deadline()
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(hit(&storage, "failure", IndicatorKind::Ip).await.is_none());
        storage.close().await;
    }

    #[tokio::test]
    async fn wall_clock_rollback_cannot_resurrect_an_expired_cache_entry() {
        let (_dir, mut config, clock) = setup();
        config.cache_ip_ttl = Duration::from_secs(10);
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        put(&storage, &clock, "expired", IndicatorKind::Ip)
            .await
            .unwrap();
        advance(&clock, 10);
        assert!(hit(&storage, "expired", IndicatorKind::Ip).await.is_none());
        advance(&clock, -5);
        assert!(hit(&storage, "expired", IndicatorKind::Ip).await.is_none());
        storage.close().await;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        assert!(hit(&storage, "expired", IndicatorKind::Ip).await.is_none());
        storage.cleanup(deadline()).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cache_entries")
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        storage.close().await;
    }

    #[tokio::test]
    async fn fifo_eviction_uses_key_tiebreak_and_reconciles_reduced_capacity() {
        let (_dir, mut config, clock) = setup();
        config.cache_max_entries = 2;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        put(&storage, &clock, "b", IndicatorKind::Ip).await.unwrap();
        put(&storage, &clock, "a", IndicatorKind::Ip).await.unwrap();
        assert!(
            put(&storage, &clock, "c", IndicatorKind::Ip)
                .await
                .is_some()
        );
        assert!(hit(&storage, "a", IndicatorKind::Ip).await.is_none());
        assert!(hit(&storage, "b", IndicatorKind::Ip).await.is_some());
        storage.close().await;
        config.cache_max_entries = 1;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        assert!(hit(&storage, "b", IndicatorKind::Ip).await.is_none());
        assert!(hit(&storage, "c", IndicatorKind::Ip).await.is_some());
        storage.close().await;
    }

    #[tokio::test]
    async fn payload_budget_evicts_and_oversized_payload_is_returned_without_storage() {
        let (_dir, mut config, clock) = setup();
        config.cache_max_bytes = serde_json::to_vec(&report(&clock)).unwrap().len();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        put(&storage, &clock, "first", IndicatorKind::Ip)
            .await
            .unwrap();
        advance(&clock, 1);
        put(&storage, &clock, "second", IndicatorKind::Ip)
            .await
            .unwrap();
        assert!(hit(&storage, "first", IndicatorKind::Ip).await.is_none());
        assert!(hit(&storage, "second", IndicatorKind::Ip).await.is_some());
        let mut too_large = report(&clock);
        too_large.raw = Some(json!({"data":"x".repeat(config.cache_max_bytes)}));
        assert!(
            storage
                .cache_put(
                    PROVIDER,
                    "large",
                    1,
                    IndicatorKind::Ip,
                    &too_large,
                    deadline()
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(hit(&storage, "large", IndicatorKind::Ip).await.is_none());
        storage.close().await;
    }

    #[tokio::test]
    async fn cleanup_deletes_expired_entries_in_bounded_chunks() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        let mut tx = storage.pool.begin().await.unwrap();
        for index in 0..501 {
            sqlx::query("INSERT INTO cache_entries VALUES ('virustotal', ?, 1, 'ip', 'not_found', 0, 1, X'7B7D', 2)")
                .bind(index.to_string()).execute(&mut *tx).await.unwrap();
        }
        tx.commit().await.unwrap();
        storage.cleanup(deadline()).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cache_entries")
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        storage.cleanup(deadline()).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cache_entries")
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        storage.close().await;
    }

    #[tokio::test]
    async fn provider_and_kind_are_separate_even_when_a_test_key_is_reused() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        put(&storage, &clock, "same", IndicatorKind::Ip)
            .await
            .unwrap();
        assert!(
            storage
                .cache_get(ProviderId::Abuseipdb, "same", IndicatorKind::Ip, deadline())
                .await
                .unwrap()
                .is_none()
        );
        assert!(hit(&storage, "same", IndicatorKind::Url).await.is_none());
        storage.close().await;
    }

    #[tokio::test]
    async fn concurrent_reservations_obey_rolling_minute_and_survive_restart() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        let results =
            futures_util::future::join_all((0..20).map(|_| storage.reserve(PROVIDER, deadline())))
                .await;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 4);
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .all(|error| *error == ReservationError::Limited(Some(60)))
        );
        storage.close().await;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        advance(&clock, 59);
        assert_eq!(
            storage.reserve(PROVIDER, deadline()).await,
            Err(ReservationError::Limited(Some(1)))
        );
        advance(&clock, 1);
        assert!(storage.reserve(PROVIDER, deadline()).await.is_ok());
        storage.close().await;
    }

    #[tokio::test]
    async fn daily_quota_survives_restart_and_resets_only_at_utc_midnight() {
        let (_dir, mut config, clock) = setup();
        config.abuseipdb.requests_per_day = 1;
        *clock.0.lock().unwrap() = "2026-09-12T23:59:59Z".parse().unwrap();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        storage
            .reserve(ProviderId::Abuseipdb, deadline())
            .await
            .unwrap();
        storage.close().await;
        config.abuseipdb.api_key =
            Some(crate::config::Secret::new("rotated-test-key".into()).unwrap());
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        assert_eq!(
            storage.reserve(ProviderId::Abuseipdb, deadline()).await,
            Err(ReservationError::Limited(Some(1)))
        );
        advance(&clock, 1);
        assert!(
            storage
                .reserve(ProviderId::Abuseipdb, deadline())
                .await
                .is_ok()
        );
        storage.close().await;
    }

    #[tokio::test]
    async fn longer_cooldown_is_preserved_and_unknown_reset_has_no_promised_delay() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        for delay in [120, 30] {
            storage
                .feedback(
                    PROVIDER,
                    QuotaFeedback {
                        cooldown_until: Some(clock.now() + TimeDelta::seconds(delay)),
                        ..Default::default()
                    },
                    deadline(),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            storage.reserve(PROVIDER, deadline()).await,
            Err(ReservationError::Limited(Some(120)))
        );
        storage.close().await;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        assert_eq!(
            storage.reserve(PROVIDER, deadline()).await,
            Err(ReservationError::Limited(Some(120)))
        );
        advance(&clock, 120);
        storage
            .feedback(
                PROVIDER,
                QuotaFeedback {
                    cooldown_until: Some(clock.now() + TimeDelta::seconds(60)),
                    unknown_reset: true,
                    ..Default::default()
                },
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(
            storage.reserve(PROVIDER, deadline()).await,
            Err(ReservationError::Limited(None))
        );
        advance(&clock, 60);
        assert!(storage.reserve(PROVIDER, deadline()).await.is_ok());
        storage.close().await;
    }

    #[tokio::test]
    async fn out_of_order_provider_remaining_never_restores_consumed_allowance() {
        let (_dir, mut config, clock) = setup();
        config.abuseipdb.max_concurrency = 1;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        let feedback = |remaining| QuotaFeedback {
            remaining: Some(remaining),
            reset_at: Some(clock.now() + TimeDelta::seconds(100)),
            ..Default::default()
        };
        storage
            .feedback(ProviderId::Abuseipdb, feedback(1), deadline())
            .await
            .unwrap();
        storage
            .reserve(ProviderId::Abuseipdb, deadline())
            .await
            .unwrap();
        storage
            .feedback(ProviderId::Abuseipdb, feedback(100), deadline())
            .await
            .unwrap();
        assert_eq!(
            storage.reserve(ProviderId::Abuseipdb, deadline()).await,
            Err(ReservationError::Limited(Some(100)))
        );
        advance(&clock, 100);
        assert!(
            storage
                .reserve(ProviderId::Abuseipdb, deadline())
                .await
                .is_ok()
        );
        storage.close().await;
    }

    #[tokio::test]
    async fn first_upstream_remaining_observation_accounts_for_concurrent_attempts() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        storage
            .feedback(
                ProviderId::Abuseipdb,
                QuotaFeedback {
                    remaining: Some(4),
                    reset_at: Some(clock.now() + TimeDelta::seconds(100)),
                    ..Default::default()
                },
                deadline(),
            )
            .await
            .unwrap();
        storage
            .reserve(ProviderId::Abuseipdb, deadline())
            .await
            .unwrap();
        assert_eq!(
            storage.reserve(ProviderId::Abuseipdb, deadline()).await,
            Err(ReservationError::Limited(Some(100)))
        );
        storage.close().await;
    }

    #[tokio::test]
    async fn unknown_zero_remaining_allows_only_a_paced_probe_after_fallback() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        storage
            .feedback(
                ProviderId::Abuseipdb,
                QuotaFeedback {
                    remaining: Some(0),
                    ..Default::default()
                },
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(
            storage.reserve(ProviderId::Abuseipdb, deadline()).await,
            Err(ReservationError::Limited(None))
        );
        assert_eq!(
            storage
                .retry_after(ProviderId::Abuseipdb, deadline())
                .await
                .unwrap(),
            None
        );
        storage.close().await;
        advance(&clock, 60);
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        storage
            .reserve(ProviderId::Abuseipdb, deadline())
            .await
            .unwrap();
        storage.close().await;
    }

    #[tokio::test]
    async fn consolidated_retry_delay_uses_longest_window_without_consuming_quota() {
        let (_dir, mut config, clock) = setup();
        config.virustotal.requests_per_day = 1;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        storage.reserve(PROVIDER, deadline()).await.unwrap();
        storage
            .feedback(
                PROVIDER,
                QuotaFeedback {
                    cooldown_until: Some(clock.now() + TimeDelta::seconds(120)),
                    ..Default::default()
                },
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(
            storage.retry_after(PROVIDER, deadline()).await.unwrap(),
            Some(43_200)
        );
        let consumed: i64 = sqlx::query_scalar(
            "SELECT daily_consumed FROM quota_state WHERE quota_group = 'virustotal'",
        )
        .fetch_one(&storage.pool)
        .await
        .unwrap();
        assert_eq!(consumed, 1);
        storage.close().await;
    }

    #[tokio::test]
    async fn reduced_minute_capacity_waits_until_enough_existing_reservations_expire() {
        let (_dir, mut config, clock) = setup();
        config.virustotal.requests_per_minute = 8;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        for _ in 0..8 {
            storage.reserve(PROVIDER, deadline()).await.unwrap();
            advance(&clock, 1);
        }
        storage.close().await;
        config.virustotal.requests_per_minute = 2;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        assert_eq!(
            storage.retry_after(PROVIDER, deadline()).await.unwrap(),
            Some(58)
        );
        assert_eq!(
            storage.reserve(PROVIDER, deadline()).await,
            Err(ReservationError::Limited(Some(58)))
        );
        advance(&clock, 58);
        storage.reserve(PROVIDER, deadline()).await.unwrap();
        storage.close().await;
    }

    #[tokio::test]
    async fn wall_clock_rollback_blocks_quota_until_durable_high_water_catches_up() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        storage.reserve(PROVIDER, deadline()).await.unwrap();
        advance(&clock, -60);
        assert_eq!(
            storage.reserve(PROVIDER, deadline()).await,
            Err(ReservationError::Limited(Some(60)))
        );
        storage.close().await;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        assert_eq!(
            storage.reserve(PROVIDER, deadline()).await,
            Err(ReservationError::Limited(Some(60)))
        );
        advance(&clock, 60);
        assert!(storage.reserve(PROVIDER, deadline()).await.is_ok());
        storage.close().await;
    }

    #[tokio::test]
    async fn lock_wait_is_bounded_and_failed_feedback_is_persisted_before_new_reservations() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        let guard = storage.gate.lock().await;
        let until = clock.now() + TimeDelta::seconds(60);
        assert_eq!(
            storage
                .feedback(
                    PROVIDER,
                    QuotaFeedback {
                        cooldown_until: Some(until),
                        ..Default::default()
                    },
                    Instant::now() + Duration::from_millis(5)
                )
                .await,
            Err(StorageError::Timeout)
        );
        assert!(!storage.is_healthy());
        drop(guard);
        storage.health(deadline()).await.unwrap();
        assert_eq!(
            storage.reserve(PROVIDER, deadline()).await,
            Err(ReservationError::Limited(Some(60)))
        );
        storage.close().await;
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        assert_eq!(
            storage.reserve(PROVIDER, deadline()).await,
            Err(ReservationError::Limited(Some(60)))
        );
        storage.close().await;
    }

    #[tokio::test]
    async fn canceled_feedback_is_retained_and_expired_reservation_never_spends_or_succeeds() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        let guard = storage.gate.lock().await;
        let blocked = storage.feedback(
            PROVIDER,
            QuotaFeedback {
                cooldown_until: Some(clock.now() + TimeDelta::seconds(60)),
                ..Default::default()
            },
            deadline(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(5), blocked)
                .await
                .is_err()
        );
        drop(guard);
        assert_eq!(
            storage.reserve(PROVIDER, Instant::now()).await,
            Err(ReservationError::Storage(StorageError::Timeout))
        );
        assert_eq!(
            storage.reserve(PROVIDER, deadline()).await,
            Err(ReservationError::Limited(Some(60)))
        );
        let used: i64 = sqlx::query_scalar(
            "SELECT daily_consumed FROM quota_state WHERE quota_group = 'virustotal'",
        )
        .fetch_one(&storage.pool)
        .await
        .unwrap();
        assert_eq!(used, 0);
        storage.close().await;
    }

    #[tokio::test]
    async fn database_write_lock_failure_never_allows_a_reservation_and_readiness_recovers() {
        let (_dir, config, clock) = setup();
        let mut storage = Storage::open(&config, clock.clone()).await.unwrap();
        Arc::get_mut(&mut storage).unwrap().timeout = Duration::from_millis(50);
        let options = SqliteConnectOptions::new()
            .filename(&config.database_path)
            .disable_statement_logging();
        let mut external = options.connect().await.unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut external)
            .await
            .unwrap();
        assert!(matches!(
            storage.reserve(PROVIDER, deadline()).await,
            Err(ReservationError::Storage(_))
        ));
        assert!(!storage.is_healthy());
        sqlx::query("ROLLBACK")
            .execute(&mut external)
            .await
            .unwrap();
        storage.health(deadline()).await.unwrap();
        assert!(storage.is_healthy());
        storage.reserve(PROVIDER, deadline()).await.unwrap();
        storage.close().await;
    }

    #[tokio::test]
    async fn cached_payload_corruption_is_a_safe_storage_error() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        put(&storage, &clock, "bad", IndicatorKind::Ip)
            .await
            .unwrap();
        sqlx::query("UPDATE cache_entries SET payload = X'7B' WHERE cache_key = 'bad'")
            .execute(&storage.pool)
            .await
            .unwrap();
        assert!(matches!(
            storage
                .cache_get(PROVIDER, "bad", IndicatorKind::Ip, deadline())
                .await,
            Err(StorageError::InvalidData)
        ));
        assert!(!storage.is_healthy());
        storage.reserve(PROVIDER, deadline()).await.unwrap();
        storage.close().await;
    }

    #[tokio::test]
    async fn startup_rejects_second_owner_newer_schema_and_corruption_without_recreating_state() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        assert!(matches!(
            Storage::open(&config, clock.clone()).await,
            Err(StorageError::AlreadyOwned)
        ));
        sqlx::query("PRAGMA user_version = 2")
            .execute(&storage.pool)
            .await
            .unwrap();
        storage.close().await;
        assert!(matches!(
            Storage::open(&config, clock.clone()).await,
            Err(StorageError::NewerSchema)
        ));
        let options = SqliteConnectOptions::new()
            .filename(&config.database_path)
            .disable_statement_logging();
        let mut connection = options.connect().await.unwrap();
        let schema: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(schema, 2);
        sqlx::Connection::close(connection).await.unwrap();
        let (_dir, config, clock) = setup();
        std::fs::write(&config.database_path, "not a SQLite database").unwrap();
        assert!(Storage::open(&config, clock).await.is_err());
        assert_eq!(
            std::fs::read(&config.database_path).unwrap(),
            b"not a SQLite database"
        );
    }

    #[tokio::test]
    async fn startup_never_recreates_missing_quota_history_or_migrates_a_foreign_database() {
        let (_dir, config, clock) = setup();
        let storage = Storage::open(&config, clock.clone()).await.unwrap();
        storage
            .reserve(ProviderId::Abuseipdb, deadline())
            .await
            .unwrap();
        sqlx::query("DELETE FROM quota_state WHERE quota_group = 'abuseipdb_check'")
            .execute(&storage.pool)
            .await
            .unwrap();
        storage.close().await;
        assert!(Storage::open(&config, clock.clone()).await.is_err());
        let options = SqliteConnectOptions::new()
            .filename(&config.database_path)
            .disable_statement_logging();
        let mut connection = options.connect().await.unwrap();
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM quota_state WHERE quota_group = 'abuseipdb_check'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(rows, 0);
        sqlx::Connection::close(connection).await.unwrap();

        let (_dir, config, clock) = setup();
        let options = SqliteConnectOptions::new()
            .filename(&config.database_path)
            .create_if_missing(true)
            .disable_statement_logging();
        let mut connection = options.connect().await.unwrap();
        sqlx::query("CREATE TABLE unrelated_application (id INTEGER)")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::Connection::close(connection).await.unwrap();
        assert!(matches!(
            Storage::open(&config, clock).await,
            Err(StorageError::InvalidData)
        ));
    }
}

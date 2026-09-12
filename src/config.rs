//! Immutable startup settings. Configuration failures never contain supplied values.

use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use reqwest::header::HeaderValue;

#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Result<Self, ConfigError> {
        validate_secret(&value, "secret")?;
        Ok(Self(value))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

#[derive(Clone, Debug)]
pub struct ProviderConfig {
    pub enabled: bool,
    pub api_key: Option<Secret>,
    pub max_concurrency: usize,
    pub requests_per_minute: u64,
    pub requests_per_day: u64,
}

// Deliberately omit Debug: even paths can contain sensitive operational details.
#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub service_token: Secret,
    pub database_path: PathBuf,
    pub max_batch_size: usize,
    pub max_request_bytes: usize,
    pub max_concurrent_requests: usize,
    pub max_shared_lookups: usize,
    pub max_outbound_requests: usize,
    pub request_timeout: Duration,
    pub lookup_timeout: Duration,
    pub provider_timeout: Duration,
    pub connect_timeout: Duration,
    pub response_write_timeout: Duration,
    pub storage_timeout: Duration,
    pub shutdown_grace: Duration,
    pub max_provider_bytes: usize,
    pub max_raw_response_bytes: usize,
    pub cache_max_entries: usize,
    pub cache_max_bytes: usize,
    pub cache_ip_ttl: Duration,
    pub cache_url_ttl: Duration,
    pub cache_hash_ttl: Duration,
    pub cache_not_found_ttl: Duration,
    pub log_level: String,
    pub abuseipdb: ProviderConfig,
    pub virustotal: ProviderConfig,
    pub abuseipdb_max_age_days: u16,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{setting}: {message}")]
pub struct ConfigError {
    setting: &'static str,
    message: &'static str,
}

impl ConfigError {
    fn new(setting: &'static str, message: &'static str) -> Self {
        Self { setting, message }
    }
}

const SETTINGS: &[&str] = &[
    "ENRICH_BIND_ADDR",
    "ENRICH_SERVICE_TOKEN",
    "ENRICH_SERVICE_TOKEN_FILE",
    "ENRICH_DATABASE_PATH",
    "ENRICH_MAX_BATCH_SIZE",
    "ENRICH_MAX_REQUEST_BYTES",
    "ENRICH_MAX_CONCURRENT_REQUESTS",
    "ENRICH_MAX_SHARED_LOOKUPS",
    "ENRICH_MAX_OUTBOUND_REQUESTS",
    "ENRICH_REQUEST_TIMEOUT_MS",
    "ENRICH_LOOKUP_TIMEOUT_MS",
    "ENRICH_PROVIDER_TIMEOUT_MS",
    "ENRICH_CONNECT_TIMEOUT_MS",
    "ENRICH_RESPONSE_WRITE_TIMEOUT_MS",
    "ENRICH_STORAGE_TIMEOUT_MS",
    "ENRICH_SHUTDOWN_GRACE_MS",
    "ENRICH_MAX_PROVIDER_BYTES",
    "ENRICH_MAX_RAW_RESPONSE_BYTES",
    "ENRICH_CACHE_MAX_ENTRIES",
    "ENRICH_CACHE_MAX_BYTES",
    "ENRICH_CACHE_IP_TTL_SECONDS",
    "ENRICH_CACHE_URL_TTL_SECONDS",
    "ENRICH_CACHE_HASH_TTL_SECONDS",
    "ENRICH_CACHE_NOT_FOUND_TTL_SECONDS",
    "ENRICH_LOG_LEVEL",
    "ENRICH_ABUSEIPDB_ENABLED",
    "ENRICH_ABUSEIPDB_API_KEY",
    "ENRICH_ABUSEIPDB_API_KEY_FILE",
    "ENRICH_ABUSEIPDB_MAX_CONCURRENCY",
    "ENRICH_ABUSEIPDB_REQUESTS_PER_MINUTE",
    "ENRICH_ABUSEIPDB_REQUESTS_PER_DAY",
    "ENRICH_ABUSEIPDB_MAX_AGE_DAYS",
    "ENRICH_VIRUSTOTAL_ENABLED",
    "ENRICH_VIRUSTOTAL_API_KEY",
    "ENRICH_VIRUSTOTAL_API_KEY_FILE",
    "ENRICH_VIRUSTOTAL_MAX_CONCURRENCY",
    "ENRICH_VIRUSTOTAL_REQUESTS_PER_MINUTE",
    "ENRICH_VIRUSTOTAL_REQUESTS_PER_DAY",
];

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut values = HashMap::new();
        for (name, value) in std::env::vars_os() {
            if !name.to_string_lossy().starts_with("ENRICH_") {
                continue;
            }
            let name = name.into_string().map_err(|_| {
                ConfigError::new("ENRICH_ configuration", "setting name must be UTF-8")
            })?;
            let value = value.into_string().map_err(|_| {
                ConfigError::new("ENRICH_ configuration", "setting value must be UTF-8")
            })?;
            values.insert(name, value);
        }
        Self::from_map(&values)
    }

    /// Parse independently supplied settings without mutating the process environment.
    pub fn from_map(values: &HashMap<String, String>) -> Result<Self, ConfigError> {
        if values
            .keys()
            .any(|name| name.starts_with("ENRICH_") && !SETTINGS.contains(&name.as_str()))
        {
            return Err(ConfigError::new(
                "ENRICH_ configuration",
                "unknown setting; check the documented configuration names",
            ));
        }
        let token = read_secret(values, "ENRICH_SERVICE_TOKEN", "ENRICH_SERVICE_TOKEN_FILE")?
            .ok_or_else(|| ConfigError::new("ENRICH_SERVICE_TOKEN", "secret is required"))?;
        let bind_addr = value_or(values, "ENRICH_BIND_ADDR", "127.0.0.1:8080")
            .parse()
            .map_err(|_| ConfigError::new("ENRICH_BIND_ADDR", "expected an IP socket address"))?;
        let result = Self {
            bind_addr,
            service_token: token,
            database_path: PathBuf::from(value_or(
                values,
                "ENRICH_DATABASE_PATH",
                "./data/rustenrich.sqlite",
            )),
            max_batch_size: number(values, "ENRICH_MAX_BATCH_SIZE", 20)?,
            max_request_bytes: number(values, "ENRICH_MAX_REQUEST_BYTES", 131_072)?,
            max_concurrent_requests: number(values, "ENRICH_MAX_CONCURRENT_REQUESTS", 32)?,
            max_shared_lookups: number(values, "ENRICH_MAX_SHARED_LOOKUPS", 64)?,
            max_outbound_requests: number(values, "ENRICH_MAX_OUTBOUND_REQUESTS", 16)?,
            request_timeout: milliseconds(values, "ENRICH_REQUEST_TIMEOUT_MS", 15_000)?,
            lookup_timeout: milliseconds(values, "ENRICH_LOOKUP_TIMEOUT_MS", 12_000)?,
            provider_timeout: milliseconds(values, "ENRICH_PROVIDER_TIMEOUT_MS", 5_000)?,
            connect_timeout: milliseconds(values, "ENRICH_CONNECT_TIMEOUT_MS", 2_000)?,
            response_write_timeout: milliseconds(
                values,
                "ENRICH_RESPONSE_WRITE_TIMEOUT_MS",
                5_000,
            )?,
            storage_timeout: milliseconds(values, "ENRICH_STORAGE_TIMEOUT_MS", 1_000)?,
            shutdown_grace: milliseconds(values, "ENRICH_SHUTDOWN_GRACE_MS", 20_000)?,
            max_provider_bytes: number(values, "ENRICH_MAX_PROVIDER_BYTES", 1_048_576)?,
            max_raw_response_bytes: number(values, "ENRICH_MAX_RAW_RESPONSE_BYTES", 8_388_608)?,
            cache_max_entries: number(values, "ENRICH_CACHE_MAX_ENTRIES", 10_000)?,
            cache_max_bytes: number(values, "ENRICH_CACHE_MAX_BYTES", 134_217_728)?,
            cache_ip_ttl: seconds(values, "ENRICH_CACHE_IP_TTL_SECONDS", 3_600)?,
            cache_url_ttl: seconds(values, "ENRICH_CACHE_URL_TTL_SECONDS", 3_600)?,
            cache_hash_ttl: seconds(values, "ENRICH_CACHE_HASH_TTL_SECONDS", 86_400)?,
            cache_not_found_ttl: seconds(values, "ENRICH_CACHE_NOT_FOUND_TTL_SECONDS", 300)?,
            log_level: value_or(values, "ENRICH_LOG_LEVEL", "info").to_owned(),
            abuseipdb: ProviderConfig {
                enabled: boolean(values, "ENRICH_ABUSEIPDB_ENABLED")?,
                api_key: read_secret(
                    values,
                    "ENRICH_ABUSEIPDB_API_KEY",
                    "ENRICH_ABUSEIPDB_API_KEY_FILE",
                )?,
                max_concurrency: number(values, "ENRICH_ABUSEIPDB_MAX_CONCURRENCY", 4)?,
                requests_per_minute: number(values, "ENRICH_ABUSEIPDB_REQUESTS_PER_MINUTE", 0)?,
                requests_per_day: number(values, "ENRICH_ABUSEIPDB_REQUESTS_PER_DAY", 1_000)?,
            },
            virustotal: ProviderConfig {
                enabled: boolean(values, "ENRICH_VIRUSTOTAL_ENABLED")?,
                api_key: read_secret(
                    values,
                    "ENRICH_VIRUSTOTAL_API_KEY",
                    "ENRICH_VIRUSTOTAL_API_KEY_FILE",
                )?,
                max_concurrency: number(values, "ENRICH_VIRUSTOTAL_MAX_CONCURRENCY", 4)?,
                requests_per_minute: number(values, "ENRICH_VIRUSTOTAL_REQUESTS_PER_MINUTE", 4)?,
                requests_per_day: number(values, "ENRICH_VIRUSTOTAL_REQUESTS_PER_DAY", 500)?,
            },
            abuseipdb_max_age_days: number(values, "ENRICH_ABUSEIPDB_MAX_AGE_DAYS", 30)?,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_secret(self.service_token.expose_secret(), "ENRICH_SERVICE_TOKEN")?;
        if self.service_token.expose_secret().len() < 32 {
            return Err(ConfigError::new(
                "ENRICH_SERVICE_TOKEN",
                "requires at least 32 UTF-8 bytes",
            ));
        }
        if self.database_path.as_os_str().is_empty() {
            return Err(ConfigError::new(
                "ENRICH_DATABASE_PATH",
                "must not be empty",
            ));
        }
        if !(1..=20).contains(&self.max_batch_size) {
            return Err(ConfigError::new(
                "ENRICH_MAX_BATCH_SIZE",
                "must be between 1 and 20",
            ));
        }
        for (setting, capacity) in [
            ("ENRICH_MAX_REQUEST_BYTES", self.max_request_bytes),
            (
                "ENRICH_MAX_CONCURRENT_REQUESTS",
                self.max_concurrent_requests,
            ),
            ("ENRICH_MAX_SHARED_LOOKUPS", self.max_shared_lookups),
            ("ENRICH_MAX_OUTBOUND_REQUESTS", self.max_outbound_requests),
            ("ENRICH_MAX_PROVIDER_BYTES", self.max_provider_bytes),
            ("ENRICH_MAX_RAW_RESPONSE_BYTES", self.max_raw_response_bytes),
            ("ENRICH_CACHE_MAX_ENTRIES", self.cache_max_entries),
            ("ENRICH_CACHE_MAX_BYTES", self.cache_max_bytes),
        ] {
            if capacity == 0 {
                return Err(ConfigError::new(setting, "must be positive"));
            }
        }
        for (setting, capacity) in [
            (
                "ENRICH_MAX_CONCURRENT_REQUESTS",
                self.max_concurrent_requests,
            ),
            ("ENRICH_MAX_SHARED_LOOKUPS", self.max_shared_lookups),
            ("ENRICH_MAX_OUTBOUND_REQUESTS", self.max_outbound_requests),
        ] {
            if capacity > tokio::sync::Semaphore::MAX_PERMITS {
                return Err(ConfigError::new(
                    setting,
                    "capacity exceeds the semaphore limit",
                ));
            }
        }
        if self.max_raw_response_bytes.checked_add(1_048_576).is_none() {
            return Err(ConfigError::new(
                "ENRICH_MAX_RAW_RESPONSE_BYTES",
                "total response size cannot be represented",
            ));
        }
        for (setting, timeout) in [
            ("ENRICH_REQUEST_TIMEOUT_MS", self.request_timeout),
            ("ENRICH_LOOKUP_TIMEOUT_MS", self.lookup_timeout),
            ("ENRICH_PROVIDER_TIMEOUT_MS", self.provider_timeout),
            ("ENRICH_CONNECT_TIMEOUT_MS", self.connect_timeout),
            (
                "ENRICH_RESPONSE_WRITE_TIMEOUT_MS",
                self.response_write_timeout,
            ),
            ("ENRICH_STORAGE_TIMEOUT_MS", self.storage_timeout),
            ("ENRICH_SHUTDOWN_GRACE_MS", self.shutdown_grace),
        ] {
            if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
                return Err(ConfigError::new(
                    setting,
                    "must be a positive representable deadline",
                ));
            }
        }
        if self.connect_timeout > self.provider_timeout
            || self.provider_timeout > self.lookup_timeout
            || self.lookup_timeout > self.request_timeout
        {
            return Err(ConfigError::new(
                "ENRICH_ timeouts",
                "require connect <= provider <= lookup <= request",
            ));
        }
        if self.storage_timeout > self.lookup_timeout {
            return Err(ConfigError::new(
                "ENRICH_STORAGE_TIMEOUT_MS",
                "must not exceed the lookup timeout",
            ));
        }
        // TTLs become persisted signed-millisecond timestamps. Reject arithmetic
        // overflow at startup instead of failing in a cache request path.
        for (setting, ttl) in [
            ("ENRICH_CACHE_IP_TTL_SECONDS", self.cache_ip_ttl),
            ("ENRICH_CACHE_URL_TTL_SECONDS", self.cache_url_ttl),
            ("ENRICH_CACHE_HASH_TTL_SECONDS", self.cache_hash_ttl),
            (
                "ENRICH_CACHE_NOT_FOUND_TTL_SECONDS",
                self.cache_not_found_ttl,
            ),
        ] {
            if chrono::Duration::from_std(ttl)
                .ok()
                .and_then(|ttl| chrono::Utc::now().checked_add_signed(ttl))
                .is_none()
            {
                return Err(ConfigError::new(setting, "duration cannot be represented"));
            }
        }
        if !matches!(
            self.log_level.as_str(),
            "error" | "warn" | "info" | "debug" | "trace"
        ) {
            return Err(ConfigError::new(
                "ENRICH_LOG_LEVEL",
                "expected error, warn, info, debug, or trace",
            ));
        }
        if !self.abuseipdb.enabled && !self.virustotal.enabled {
            return Err(ConfigError::new(
                "ENRICH_ providers",
                "at least one provider must be enabled",
            ));
        }
        for (setting, provider) in [
            ("ENRICH_ABUSEIPDB", &self.abuseipdb),
            ("ENRICH_VIRUSTOTAL", &self.virustotal),
        ] {
            if provider.enabled && provider.api_key.is_none() {
                return Err(ConfigError::new(
                    setting,
                    "enabled provider requires an API key",
                ));
            }
            if let Some(secret) = &provider.api_key {
                validate_secret(secret.expose_secret(), setting)?;
            }
            if provider.max_concurrency == 0
                || provider.max_concurrency > self.max_outbound_requests
            {
                return Err(ConfigError::new(
                    setting,
                    "concurrency must be positive and not exceed global outbound capacity",
                ));
            }
            if provider.requests_per_day == 0 {
                return Err(ConfigError::new(
                    setting,
                    "daily request budget must be positive",
                ));
            }
            if provider.requests_per_day > i64::MAX as u64
                || provider.requests_per_minute > i64::MAX as u64
            {
                return Err(ConfigError::new(
                    setting,
                    "quota must fit a signed 64-bit storage counter",
                ));
            }
        }
        if !(1..=365).contains(&self.abuseipdb_max_age_days) {
            return Err(ConfigError::new(
                "ENRICH_ABUSEIPDB_MAX_AGE_DAYS",
                "must be between 1 and 365",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        let settings = HashMap::from([
            (
                "ENRICH_SERVICE_TOKEN".into(),
                "test-service-token-with-at-least-32-bytes".into(),
            ),
            ("ENRICH_ABUSEIPDB_ENABLED".into(), "true".into()),
            (
                "ENRICH_ABUSEIPDB_API_KEY".into(),
                "test-abuseipdb-key".into(),
            ),
            ("ENRICH_VIRUSTOTAL_ENABLED".into(), "true".into()),
            (
                "ENRICH_VIRUSTOTAL_API_KEY".into(),
                "test-virustotal-key".into(),
            ),
        ]);
        Self::from_map(&settings).expect("the built-in test settings are valid")
    }
}

fn value_or<'a>(values: &'a HashMap<String, String>, setting: &str, default: &'a str) -> &'a str {
    values.get(setting).map(String::as_str).unwrap_or(default)
}

fn number<T>(
    values: &HashMap<String, String>,
    setting: &'static str,
    default: T,
) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
{
    let Some(value) = values.get(setting) else {
        return Ok(default);
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ConfigError::new(
            setting,
            "expected an unsigned decimal integer",
        ));
    }
    value
        .parse()
        .map_err(|_| ConfigError::new(setting, "integer is out of range"))
}

fn boolean(values: &HashMap<String, String>, setting: &'static str) -> Result<bool, ConfigError> {
    match values.get(setting).map(String::as_str) {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(ConfigError::new(setting, "expected true or false")),
    }
}

fn milliseconds(
    values: &HashMap<String, String>,
    setting: &'static str,
    default: u64,
) -> Result<Duration, ConfigError> {
    number(values, setting, default).map(Duration::from_millis)
}

fn seconds(
    values: &HashMap<String, String>,
    setting: &'static str,
    default: u64,
) -> Result<Duration, ConfigError> {
    number(values, setting, default).map(Duration::from_secs)
}

fn read_secret(
    values: &HashMap<String, String>,
    value_setting: &'static str,
    file_setting: &'static str,
) -> Result<Option<Secret>, ConfigError> {
    let value = values.get(value_setting);
    let file = values.get(file_setting);
    let loaded = match (value, file) {
        (Some(_), Some(_)) => {
            return Err(ConfigError::new(
                value_setting,
                "choose the value or its _FILE setting, never both",
            ));
        }
        (Some(value), None) => value.clone(),
        (None, Some(path)) => {
            let text = std::fs::read_to_string(path).map_err(|_| {
                ConfigError::new(file_setting, "secret file must be readable UTF-8")
            })?;
            text.strip_suffix("\r\n")
                .or_else(|| text.strip_suffix('\n'))
                .or_else(|| text.strip_suffix('\r'))
                .unwrap_or(&text)
                .to_owned()
        }
        (None, None) => return Ok(None),
    };
    validate_secret(&loaded, value_setting)?;
    Ok(Some(Secret(loaded)))
}

fn validate_secret(value: &str, setting: &'static str) -> Result<(), ConfigError> {
    if value.is_empty() || value.contains(['\r', '\n']) || HeaderValue::from_str(value).is_err() {
        return Err(ConfigError::new(
            setting,
            "secret must be nonempty and valid in an HTTP header without line breaks",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> HashMap<String, String> {
        HashMap::from([
            (
                "ENRICH_SERVICE_TOKEN".into(),
                "synthetic-test-secret-of-at-least-32-bytes".into(),
            ),
            ("ENRICH_ABUSEIPDB_ENABLED".into(), "true".into()),
            (
                "ENRICH_ABUSEIPDB_API_KEY".into(),
                "synthetic-provider-key".into(),
            ),
        ])
    }

    #[test]
    fn requires_explicit_provider_opt_in_and_credentials() {
        let mut values = settings();
        values.remove("ENRICH_ABUSEIPDB_ENABLED");
        assert!(Config::from_map(&values).is_err());
        values.insert("ENRICH_ABUSEIPDB_ENABLED".into(), "true".into());
        values.remove("ENRICH_ABUSEIPDB_API_KEY");
        assert!(Config::from_map(&values).is_err());
    }

    #[test]
    fn rejects_invalid_supplied_settings_even_for_disabled_providers() {
        for (name, value) in [
            ("ENRICH_VIRUSTOTAL_ENABLED", "TRUE"),
            ("ENRICH_VIRUSTOTAL_REQUESTS_PER_DAY", "0"),
            ("ENRICH_VIRUSTOTAL_MAX_CONCURRENCY", "17"),
            ("ENRICH_ABUSEIPDB_MAX_AGE_DAYS", "366"),
            ("ENRICH_MAX_BATCH_SIZE", "21"),
            ("ENRICH_MAX_REQUEST_BYTES", "0"),
            ("ENRICH_MAX_RAW_RESPONSE_BYTES", "0"),
            ("ENRICH_MAX_SHARED_LOOKUPS", "+10"),
            ("ENRICH_CACHE_IP_TTL_SECONDS", " 1"),
            ("ENRICH_REQUEST_TIMEOUT_MS", "1000"),
            ("ENRICH_STORAGE_TIMEOUT_MS", "12001"),
            ("ENRICH_PROVIDER_TIMEOUT_MS", "0"),
            ("ENRICH_LOG_LEVEL", "info,reqwest=trace"),
            ("ENRICH_DATABASE_PATH", ""),
            ("ENRICH_BIND_ADDR", "localhost:8080"),
            ("ENRICH_MISSPELLED_SETTING", "42"),
        ] {
            let mut values = settings();
            values.insert(name.into(), value.into());
            assert!(Config::from_map(&values).is_err(), "accepted {name}");
        }
    }

    #[test]
    fn accepts_zero_ttls_and_unlimited_minute_cap() {
        let mut values = settings();
        values.insert("ENRICH_CACHE_IP_TTL_SECONDS".into(), "0".into());
        values.insert("ENRICH_VIRUSTOTAL_REQUESTS_PER_MINUTE".into(), "0".into());
        let config = Config::from_map(&values).unwrap();
        assert!(config.cache_ip_ttl.is_zero());
        assert_eq!(config.virustotal.requests_per_minute, 0);
    }

    #[test]
    fn secret_sources_are_exclusive_and_errors_are_redacted() {
        let mut values = settings();
        values.insert(
            "ENRICH_SERVICE_TOKEN_FILE".into(),
            "/sensitive-path/token".into(),
        );
        let error = Config::from_map(&values).err().unwrap().to_string();
        assert!(!error.contains("sensitive-path"));
        assert!(!error.contains("synthetic-test-secret"));
        let secret = Secret::new("synthetic-secret".into()).unwrap();
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
    }

    #[test]
    fn secret_file_strips_only_one_line_ending_without_trimming() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("key");
        let mut values = settings();
        values.remove("ENRICH_ABUSEIPDB_API_KEY");
        values.insert(
            "ENRICH_ABUSEIPDB_API_KEY_FILE".into(),
            path.to_str().unwrap().into(),
        );
        std::fs::write(&path, " key with surrounding spaces \r\n").unwrap();
        let config = Config::from_map(&values).unwrap();
        assert_eq!(
            config.abuseipdb.api_key.unwrap().expose_secret(),
            " key with surrounding spaces "
        );
        for bytes in [
            b"key\n\n".as_slice(),
            b"\xff",
            b"",
            b"key\0",
            b"line\nbreak",
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(Config::from_map(&values).is_err());
        }
    }

    #[test]
    fn rejects_empty_short_or_header_injecting_secrets_without_echoing_them() {
        for value in [
            "",
            "short",
            "secret-with-at-least-32-bytes\r\nHeader: injected",
        ] {
            let mut values = settings();
            values.insert("ENRICH_SERVICE_TOKEN".into(), value.into());
            let error = Config::from_map(&values).err().unwrap().to_string();
            assert!(!error.contains("injected"));
            assert!(!error.contains("short"));
        }
        let mut values = settings();
        values.insert("ENRICH_VIRUSTOTAL_API_KEY".into(), "".into());
        assert!(Config::from_map(&values).is_err());
    }
}

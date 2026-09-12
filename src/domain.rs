//! The public evidence contract and request validation, independent of HTTP and storage.

use std::{collections::HashSet, fmt, net::IpAddr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;
use url::Url;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderId {
    Abuseipdb,
    Virustotal,
}

impl ProviderId {
    pub const ALL: [Self; 2] = [Self::Abuseipdb, Self::Virustotal];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Abuseipdb => "abuseipdb",
            Self::Virustotal => "virustotal",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "abuseipdb" => Some(Self::Abuseipdb),
            "virustotal" => Some(Self::Virustotal),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IndicatorKind {
    Ip,
    Url,
    Hash,
}

impl IndicatorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Url => "url",
            Self::Hash => "hash",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "ip" => Some(Self::Ip),
            "url" => Some(Self::Url),
            "hash" => Some(Self::Hash),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InputIndicator {
    #[serde(rename = "type")]
    pub kind: IndicatorKind,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidatedIndicator {
    pub input: InputIndicator,
    pub lookup_value: String,
    pub hash_algorithm: Option<HashAlgorithm>,
}

#[derive(Clone, Debug)]
pub struct ValidatedRequest {
    pub indicators: Vec<ValidatedIndicator>,
    pub providers: Vec<ProviderId>,
    pub include_raw: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidationDetail {
    pub path: String,
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestValidationError {
    InvalidJson,
    Semantic(Vec<ValidationDetail>),
}

// Preserve source object order so semantic errors follow the submitted request.
// Deserialize maps ourselves because serde_json::Value otherwise accepts duplicate keys.
enum RequestJson {
    Null,
    Bool(bool),
    Number,
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl<'de> Deserialize<'de> for RequestJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RequestVisitor;
        impl<'de> de::Visitor<'de> for RequestVisitor {
            type Value = RequestJson;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(RequestJson::Null)
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(RequestJson::Bool(value))
            }

            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(RequestJson::Number)
            }

            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(RequestJson::Number)
            }

            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(RequestJson::Number)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(RequestJson::String(value.to_owned()))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(RequestJson::String(value))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element()? {
                    values.push(value);
                }
                Ok(RequestJson::Array(values))
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut fields = Vec::new();
                let mut keys = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                    fields.push((key, map.next_value()?));
                }
                Ok(RequestJson::Object(fields))
            }
        }
        deserializer.deserialize_any(RequestVisitor)
    }
}

impl RequestJson {
    fn as_str(&self) -> Option<&str> {
        if let Self::String(value) = self {
            Some(value)
        } else {
            None
        }
    }
}

fn pointer(parent: &str, field: &str) -> String {
    format!("{parent}/{}", field.replace('~', "~0").replace('/', "~1"))
}

fn detail(details: &mut Vec<ValidationDetail>, path: &str, code: &str, message: &str) {
    if details.len() < 100 {
        details.push(ValidationDetail {
            path: path.to_owned(),
            code: code.to_owned(),
            message: message.to_owned(),
        });
    }
}

fn invalid_type(details: &mut Vec<ValidationDetail>, path: &str) {
    detail(
        details,
        path,
        "invalid_type",
        "The field has an invalid JSON type.",
    );
}

pub fn validate_request(
    bytes: &[u8],
    max_batch: usize,
    enabled: &[ProviderId],
) -> Result<ValidatedRequest, RequestValidationError> {
    let json: RequestJson =
        serde_json::from_slice(bytes).map_err(|_| RequestValidationError::InvalidJson)?;
    let mut details = Vec::new();
    let RequestJson::Object(fields) = json else {
        invalid_type(&mut details, "");
        return Err(RequestValidationError::Semantic(details));
    };
    let mut indicators = Vec::new();
    let mut providers = enabled.to_vec();
    providers.sort_unstable();
    providers.dedup();
    let mut include_raw = false;
    let mut has_indicators = false;
    for (key, value) in fields {
        let path = pointer("", &key);
        match key.as_str() {
            "indicators" => {
                has_indicators = true;
                if let RequestJson::Array(items) = value {
                    if items.is_empty() || items.len() > max_batch {
                        detail(
                            &mut details,
                            &path,
                            "invalid_batch_size",
                            "The indicator count is outside the permitted range.",
                        );
                    }
                    for (index, item) in items.iter().enumerate() {
                        if let Some(indicator) =
                            validate_item(item, &pointer(&path, &index.to_string()), &mut details)
                        {
                            indicators.push(indicator);
                        }
                    }
                } else {
                    invalid_type(&mut details, &path);
                }
            }
            "providers" => {
                providers.clear();
                if let RequestJson::Array(items) = value {
                    if items.is_empty() {
                        detail(
                            &mut details,
                            &path,
                            "empty_providers",
                            "Select at least one provider.",
                        );
                    }
                    let mut seen = HashSet::new();
                    for (index, item) in items.iter().enumerate() {
                        let path = pointer(&path, &index.to_string());
                        if let Some(value) = item.as_str() {
                            if let Some(id) = ProviderId::parse(value) {
                                if seen.insert(id) {
                                    providers.push(id);
                                } else {
                                    detail(
                                        &mut details,
                                        &path,
                                        "duplicate_provider",
                                        "Provider IDs must not be repeated.",
                                    );
                                }
                            } else {
                                detail(
                                    &mut details,
                                    &path,
                                    "unknown_provider",
                                    "The provider ID is not recognized.",
                                );
                            }
                        } else {
                            invalid_type(&mut details, &path);
                        }
                    }
                } else {
                    invalid_type(&mut details, &path);
                }
            }
            "include_raw" => {
                if let RequestJson::Bool(value) = value {
                    include_raw = value;
                } else {
                    invalid_type(&mut details, &path);
                }
            }
            _ => detail(
                &mut details,
                &path,
                "unknown_field",
                "This request field is not supported.",
            ),
        }
    }
    if !has_indicators {
        detail(
            &mut details,
            "/indicators",
            "required",
            "This field is required.",
        );
    }
    if details.is_empty() {
        Ok(ValidatedRequest {
            indicators,
            providers,
            include_raw,
        })
    } else {
        Err(RequestValidationError::Semantic(details))
    }
}

fn validate_item(
    item: &RequestJson,
    path: &str,
    details: &mut Vec<ValidationDetail>,
) -> Option<ValidatedIndicator> {
    let RequestJson::Object(fields) = item else {
        invalid_type(details, path);
        return None;
    };
    // Resolve the type first, but emit errors by field order below.
    let kind = fields
        .iter()
        .find(|(key, _)| key == "type")
        .and_then(|(_, value)| value.as_str())
        .and_then(IndicatorKind::parse);
    let mut has_kind = false;
    let mut has_value = false;
    let mut validated = None;
    for (key, value) in fields {
        let field_path = pointer(path, key);
        match key.as_str() {
            "type" => {
                has_kind = true;
                if value.as_str().is_none() {
                    invalid_type(details, &field_path);
                } else if kind.is_none() {
                    detail(
                        details,
                        &field_path,
                        "invalid_indicator_type",
                        "Expected ip, url, or hash.",
                    );
                }
            }
            "value" => {
                has_value = true;
                if let Some(value) = value.as_str() {
                    if value.is_empty() || value.len() > 4096 {
                        detail(
                            details,
                            &field_path,
                            "invalid_value_length",
                            "The value must contain between 1 and 4,096 UTF-8 bytes.",
                        );
                    } else if let Some(kind) = kind {
                        match validate_indicator(kind, value) {
                            Ok(indicator) => validated = Some(indicator),
                            Err((code, message)) => detail(details, &field_path, code, message),
                        }
                    }
                } else {
                    invalid_type(details, &field_path);
                }
            }
            _ => detail(
                details,
                &field_path,
                "unknown_field",
                "This request field is not supported.",
            ),
        }
    }
    if !has_kind {
        detail(
            details,
            &pointer(path, "type"),
            "required",
            "This field is required.",
        );
    }
    if !has_value {
        detail(
            details,
            &pointer(path, "value"),
            "required",
            "This field is required.",
        );
    }
    validated
}

pub fn validate_indicator(
    kind: IndicatorKind,
    value: &str,
) -> Result<ValidatedIndicator, (&'static str, &'static str)> {
    let invalid = match kind {
        IndicatorKind::Ip => ("invalid_ip", "Expected one IPv4 or IPv6 address."),
        IndicatorKind::Url => (
            "invalid_url",
            "Expected an absolute HTTP(S) URL without userinfo, whitespace, backslashes, or malformed escapes.",
        ),
        IndicatorKind::Hash => (
            "invalid_hash",
            "Expected 32, 40, or 64 hexadecimal characters.",
        ),
    };
    if value.is_empty()
        || value.len() > 4096
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(invalid);
    }
    let (lookup_value, hash_algorithm) = match kind {
        IndicatorKind::Ip => (
            value.parse::<IpAddr>().map_err(|_| invalid)?.to_string(),
            None,
        ),
        IndicatorKind::Url => {
            validate_url(value).map_err(|_| invalid)?;
            (value.to_owned(), None)
        }
        IndicatorKind::Hash => {
            if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid);
            }
            let algorithm = match value.len() {
                32 => HashAlgorithm::Md5,
                40 => HashAlgorithm::Sha1,
                64 => HashAlgorithm::Sha256,
                _ => return Err(invalid),
            };
            (value.to_ascii_lowercase(), Some(algorithm))
        }
    };
    Ok(ValidatedIndicator {
        input: InputIndicator {
            kind,
            value: value.to_owned(),
        },
        lookup_value,
        hash_algorithm,
    })
}

fn validate_url(value: &str) -> Result<(), ()> {
    if value.contains('\\') {
        return Err(());
    }
    for (index, byte) in value.bytes().enumerate() {
        if byte == b'%'
            && !value
                .as_bytes()
                .get(index + 1..index + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
        {
            return Err(());
        }
    }
    // Reject URL parser repairs such as https:example.com, empty ports and extra slashes.
    let (scheme, remainder) = value.split_once("://").ok_or(())?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(());
    }
    let authority = remainder.split(['/', '?', '#']).next().ok_or(())?;
    if authority.is_empty() || authority.contains('@') || authority.ends_with(':') {
        return Err(());
    }
    let lower_authority = authority.to_ascii_lowercase();
    if ["[.]", "(.)", "{.}", "[dot]", "(dot)", "{dot}"]
        .iter()
        .any(|marker| lower_authority.contains(marker))
    {
        return Err(());
    }
    let parsed = Url::parse(value).map_err(|_| ())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    NotFound,
    Unsupported,
    Disabled,
    RateLimited,
    Timeout,
    Error,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotFound => "not_found",
            Self::Unsupported => "unsupported",
            Self::Disabled => "disabled",
            Self::RateLimited => "rate_limited",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidJson,
    Unauthorized,
    RouteNotFound,
    MethodNotAllowed,
    RequestBodyTimeout,
    RequestTooLarge,
    UnsupportedMediaType,
    ValidationError,
    ServiceOverloaded,
    ServiceUnavailable,
    InternalError,
    ResponseTooLarge,
    QuotaExhausted,
    ProviderAuthenticationFailed,
    ProviderAccessDenied,
    ProviderTimeout,
    RequestDeadlineExceeded,
    NetworkError,
    ProviderUnavailable,
    ProviderRequestRejected,
    ProviderTlsError,
    InvalidResponse,
    ProviderBusy,
    StorageUnavailable,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid_json",
            Self::Unauthorized => "unauthorized",
            Self::RouteNotFound => "route_not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::RequestBodyTimeout => "request_body_timeout",
            Self::RequestTooLarge => "request_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::ValidationError => "validation_error",
            Self::ServiceOverloaded => "service_overloaded",
            Self::ServiceUnavailable => "service_unavailable",
            Self::InternalError => "internal_error",
            Self::ResponseTooLarge => "response_too_large",
            Self::QuotaExhausted => "quota_exhausted",
            Self::ProviderAuthenticationFailed => "provider_authentication_failed",
            Self::ProviderAccessDenied => "provider_access_denied",
            Self::ProviderTimeout => "provider_timeout",
            Self::RequestDeadlineExceeded => "request_deadline_exceeded",
            Self::NetworkError => "network_error",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::ProviderRequestRejected => "provider_request_rejected",
            Self::ProviderTlsError => "provider_tls_error",
            Self::InvalidResponse => "invalid_response",
            Self::ProviderBusy => "provider_busy",
            Self::StorageUnavailable => "storage_unavailable",
        }
    }

    pub fn status(self) -> Status {
        match self {
            Self::QuotaExhausted => Status::RateLimited,
            Self::ProviderTimeout | Self::RequestDeadlineExceeded => Status::Timeout,
            _ => Status::Error,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub retry_after_seconds: Option<u64>,
}

impl PublicError {
    pub fn new(code: ErrorCode) -> Self {
        use ErrorCode::*;
        let (message, retryable, retry_after_seconds) = match code {
            InvalidJson => ("The request body is not valid JSON.", false, None),
            Unauthorized => ("A valid service bearer token is required.", false, None),
            RouteNotFound => ("The requested route does not exist.", false, None),
            MethodNotAllowed => (
                "This HTTP method is not allowed for the route.",
                false,
                None,
            ),
            RequestBodyTimeout => ("The request body deadline expired.", true, None),
            RequestTooLarge => ("The request body exceeds its size limit.", false, None),
            UnsupportedMediaType => (
                "An uncompressed application/json request body is required.",
                false,
                None,
            ),
            ValidationError => ("One or more request fields are invalid.", false, None),
            ServiceOverloaded => (
                "The service has reached its request capacity.",
                true,
                Some(1),
            ),
            ServiceUnavailable => ("The service is temporarily unavailable.", true, Some(1)),
            InternalError => ("An internal error prevented completion.", true, None),
            ResponseTooLarge => ("The response exceeds its size limit.", false, None),
            QuotaExhausted => ("Provider request quota is exhausted.", true, None),
            ProviderAuthenticationFailed => (
                "The provider rejected its configured credentials.",
                false,
                None,
            ),
            ProviderAccessDenied => ("The provider denied access to this report.", false, None),
            ProviderTimeout => ("The provider lookup deadline expired.", true, None),
            RequestDeadlineExceeded => (
                "The request deadline expired before this lookup completed.",
                true,
                None,
            ),
            NetworkError => (
                "A network failure prevented the provider lookup.",
                true,
                None,
            ),
            ProviderUnavailable => ("The provider is temporarily unavailable.", true, None),
            ProviderRequestRejected => ("The provider rejected the lookup request.", false, None),
            ProviderTlsError => (
                "The provider TLS connection could not be validated.",
                false,
                None,
            ),
            InvalidResponse => ("The provider returned an invalid report.", false, None),
            ProviderBusy => (
                "The service has reached its shared lookup capacity.",
                true,
                Some(1),
            ),
            StorageUnavailable => (
                "Storage required for quota accounting is unavailable.",
                true,
                Some(1),
            ),
        };
        Self {
            code,
            message: message.to_owned(),
            retryable,
            retry_after_seconds,
        }
    }

    pub fn with_retry_after(mut self, seconds: Option<u64>) -> Self {
        self.retry_after_seconds = seconds;
        self
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Outcome {
    pub status: Status,
    pub summary: Option<Summary>,
    pub fetched_at: Option<DateTime<Utc>>,
    pub provider_updated_at: Option<DateTime<Utc>>,
    pub error: Option<PublicError>,
    pub raw: Option<Value>,
}

impl Outcome {
    pub fn empty(status: Status) -> Self {
        Self {
            status,
            summary: None,
            fetched_at: None,
            provider_updated_at: None,
            error: None,
            raw: None,
        }
    }

    pub fn failure(code: ErrorCode) -> Self {
        Self {
            error: Some(PublicError::new(code)),
            ..Self::empty(code.status())
        }
    }

    pub fn not_found(now: DateTime<Utc>) -> Self {
        Self {
            fetched_at: Some(now),
            ..Self::empty(Status::NotFound)
        }
    }

    pub fn is_cacheable(&self) -> bool {
        matches!(self.status, Status::Ok | Status::NotFound)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Summary {
    Abuseipdb(AbuseipdbSummary),
    Virustotal(Box<VirustotalSummary>),
}

// Unknown provider fields are retained in raw, but persisted public summaries have an
// exact shape. This also makes the untagged enum unambiguous when reopening the cache.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbuseipdbSummary {
    pub abuse_confidence_score: Option<u64>,
    pub total_reports: Option<u64>,
    pub distinct_reporters: Option<u64>,
    pub last_reported_at: Option<DateTime<Utc>>,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
    pub usage_type: Option<String>,
    pub is_public: Option<bool>,
    pub is_tor: Option<bool>,
    pub is_whitelisted: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VirustotalSummary {
    pub analysis_stats: Option<AnalysisStats>,
    pub reputation: Option<i64>,
    pub last_analysis_at: Option<DateTime<Utc>>,
    pub country: Option<String>,
    pub asn: Option<u64>,
    pub as_owner: Option<String>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub file_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisStats {
    pub malicious: Option<u64>,
    pub suspicious: Option<u64>,
    pub harmless: Option<u64>,
    pub undetected: Option<u64>,
    pub timeout: Option<u64>,
    pub confirmed_timeout: Option<u64>,
    pub failure: Option<u64>,
    pub type_unsupported: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(value: Value) -> Result<ValidatedRequest, RequestValidationError> {
        validate_request(&serde_json::to_vec(&value).unwrap(), 20, &ProviderId::ALL)
    }

    #[test]
    fn preserves_duplicates_order_and_exact_url_identity() {
        let url = "HTTPS://Example.COM:443/a%2fb?b=2&a=1#Fragment";
        let result = request(json!({"indicators": [
            {"type":"url","value":url},
            {"type":"ip","value":"2001:0db8:0000::1"},
            {"type":"ip","value":"2001:db8::1"},
            {"type":"hash","value":"A".repeat(32)}
        ], "providers":["virustotal","abuseipdb"]}))
        .unwrap();
        assert_eq!(
            result.providers,
            [ProviderId::Virustotal, ProviderId::Abuseipdb]
        );
        assert_eq!(result.indicators[0].lookup_value, url);
        assert_eq!(result.indicators[1].lookup_value, "2001:db8::1");
        assert_eq!(result.indicators[2].lookup_value, "2001:db8::1");
        assert_eq!(result.indicators[1].input.value, "2001:0db8:0000::1");
        assert_eq!(
            result.indicators[3].hash_algorithm,
            Some(HashAlgorithm::Md5)
        );
        assert_eq!(result.indicators[3].lookup_value, "a".repeat(32));
        assert!(!result.include_raw);
    }

    #[test]
    fn defaults_providers_in_lexicographic_order_and_permits_known_disabled_ids() {
        let bytes = br#"{"indicators":[{"type":"ip","value":"10.0.0.1"}]}"#;
        let result =
            validate_request(bytes, 20, &[ProviderId::Virustotal, ProviderId::Abuseipdb]).unwrap();
        assert_eq!(result.providers, ProviderId::ALL);
        let result = validate_request(
            br#"{"indicators":[{"type":"ip","value":"10.0.0.1"}],"providers":["abuseipdb"]}"#,
            20,
            &[ProviderId::Virustotal],
        )
        .unwrap();
        assert_eq!(result.providers, [ProviderId::Abuseipdb]);
    }

    #[test]
    fn rejects_duplicate_keys_at_every_depth_as_invalid_json() {
        for bytes in [
            br#"{"indicators":[],"indicators":[]}"#.as_slice(),
            br#"{"indicators":[{"type":"ip","value":"1.1.1.1","value":"8.8.8.8"}]}"#,
            br#"{"extra":{"a":1,"\u0061":2}}"#,
            br#"{"indicators":[]} trailing"#,
            &[b'{', 0xff, b'}'],
        ] {
            assert_eq!(
                validate_request(bytes, 20, &[]).unwrap_err(),
                RequestValidationError::InvalidJson
            );
        }
    }

    #[test]
    fn semantic_errors_follow_submitted_order_without_values() {
        let bytes = br#"{"providers":["unknown-sensitive-value","abuseipdb","abuseipdb"],"indicators":[{"value":"sensitive-hash","type":"hash"},{"type":"ip","value":null}],"include_raw":null,"other~/":0}"#;
        let RequestValidationError::Semantic(details) =
            validate_request(bytes, 20, &[]).unwrap_err()
        else {
            panic!()
        };
        let paths: Vec<_> = details.iter().map(|detail| detail.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/providers/0",
                "/providers/2",
                "/indicators/0/value",
                "/indicators/1/value",
                "/include_raw",
                "/other~0~1"
            ]
        );
        assert!(
            !serde_json::to_string(&details)
                .unwrap()
                .contains("sensitive")
        );
    }

    #[test]
    fn rejects_null_wrong_types_unknown_fields_and_unbounded_batches() {
        for value in [
            json!(null),
            json!([]),
            json!({}),
            json!({"indicators":null}),
            json!({"indicators":[]}),
            json!({"indicators":"8.8.8.8"}),
            json!({"indicators":[{"type":"ip","value":"8.8.8.8","extra":true}]}),
            json!({"indicators":[{"type":"IP","value":"8.8.8.8"}]}),
            json!({"indicators":[{"type":"ip","value":"8.8.8.8"}],"providers":null}),
            json!({"indicators":[{"type":"ip","value":"8.8.8.8"}],"providers":[]}),
            json!({"indicators":[{"type":"ip","value":"8.8.8.8"}],"include_raw":"false"}),
            json!({"indicators": vec![json!({"type":"ip","value":"8.8.8.8"});21]}),
            json!({"indicators":[{"type":"url","value":format!("https://example.com/{}", "é".repeat(4096))}]}),
        ] {
            assert!(matches!(
                request(value),
                Err(RequestValidationError::Semantic(_))
            ));
        }
    }

    #[test]
    fn caps_validation_details_at_one_hundred() {
        let result =
            request(json!({"indicators":vec![json!({"type":null,"value":null,"extra":0});100]}))
                .unwrap_err();
        let RequestValidationError::Semantic(details) = result else {
            panic!()
        };
        assert_eq!(details.len(), 100);
    }

    #[test]
    fn rejects_ambiguous_ips_without_restricting_address_classes() {
        for value in [
            " 8.8.8.8",
            "8.8.8.8 ",
            "8.8.8.8/32",
            "8.8.8.8:80",
            "[::1]",
            "fe80::1%eth0",
            "010.0.0.1",
            "127.1",
            "8[.]8[.]8[.]8",
            "::1\n",
        ] {
            assert!(
                validate_indicator(IndicatorKind::Ip, value).is_err(),
                "accepted {value:?}"
            );
        }
        for value in [
            "0.0.0.0",
            "255.255.255.255",
            "127.0.0.1",
            "10.0.0.1",
            "::1",
            "fe80::1",
            "::ffff:192.0.2.1",
        ] {
            assert!(
                validate_indicator(IndicatorKind::Ip, value).is_ok(),
                "rejected {value:?}"
            );
        }
    }

    #[test]
    fn rejects_url_repairs_credentials_and_malformed_escapes() {
        for value in [
            "https:example.com",
            "https:///example.com",
            "//example.com",
            "ftp://example.com",
            "https://",
            "https://example.com:",
            "https://example.com:65536",
            "https://example.com:foo",
            "https://user@example.com",
            "https://@example.com",
            "https://example.com/a b",
            "https://example.com\\a",
            "https://example.com/%",
            "https://example.com/%2",
            "https://example.com/%gg",
            "https://example.com/\n",
            "hxxps://example.com",
            "https://example[.]com",
            "https://example(.)com",
            "https://example{.}com",
            "https://example(dot)com",
            "https://example.com:/path",
            "https://example.com:#fragment",
            "https://user:@example.com/",
            "http://[fe80::1%25eth0]/",
            "https://example.com/\u{0085}",
            "https://example.com/\u{00a0}",
        ] {
            assert!(
                validate_indicator(IndicatorKind::Url, value).is_err(),
                "accepted {value:?}"
            );
        }
        for value in [
            "https://example.com/",
            "HTTP://EXAMPLE.COM:80/a%2Fb?q=a%20b#fragment",
            "http://127.0.0.1:0/",
            "https://[::1]:443/",
            "https://example.com/%00",
            "https://example.com/á",
            "https://example.com:00080/a?x=1&x=2",
            "https://example.com/literal[.]filename",
        ] {
            assert!(
                validate_indicator(IndicatorKind::Url, value).is_ok(),
                "rejected {value:?}"
            );
        }
    }

    #[test]
    fn validates_all_hash_algorithms_and_normalizes_case() {
        for (len, algorithm) in [
            (32, HashAlgorithm::Md5),
            (40, HashAlgorithm::Sha1),
            (64, HashAlgorithm::Sha256),
        ] {
            let result = validate_indicator(IndicatorKind::Hash, &"Ab".repeat(len / 2)).unwrap();
            assert_eq!(result.lookup_value, "ab".repeat(len / 2));
            assert_eq!(result.hash_algorithm, Some(algorithm));
        }
        for value in [
            "a".repeat(31),
            "a".repeat(33),
            "a".repeat(41),
            "g".repeat(64),
            "ａ".repeat(32),
        ] {
            assert!(validate_indicator(IndicatorKind::Hash, &value).is_err());
        }
    }

    #[test]
    fn indicator_length_limit_counts_utf8_bytes_at_the_exact_boundary() {
        let prefix = "https://example.com/";
        let mut value = format!("{prefix}{}é", "a".repeat(4094 - prefix.len()));
        assert_eq!(value.len(), 4096);
        assert!(validate_indicator(IndicatorKind::Url, &value).is_ok());
        value.push('a');
        assert!(validate_indicator(IndicatorKind::Url, &value).is_err());
    }

    #[test]
    fn public_errors_have_static_messages_and_nullable_delays() {
        let error = PublicError::new(ErrorCode::QuotaExhausted);
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            json!({"code":"quota_exhausted","message":"Provider request quota is exhausted.","retryable":true,"retry_after_seconds":null})
        );
        assert_eq!(
            Outcome::failure(ErrorCode::RequestDeadlineExceeded).status,
            Status::Timeout
        );
        assert_eq!(
            Outcome::failure(ErrorCode::QuotaExhausted).status,
            Status::RateLimited
        );
        assert_eq!(
            PublicError::new(ErrorCode::ProviderBusy).retry_after_seconds,
            Some(1)
        );
    }
}

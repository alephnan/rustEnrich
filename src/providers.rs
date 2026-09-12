//! Compiled report adapters. The enrichment executor owns dispatch, quota and retries.

use std::{fmt, net::IpAddr, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Datelike, Utc};
use reqwest::{
    Client, RequestBuilder,
    header::{ACCEPT, HeaderValue},
    redirect::Policy,
};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use crate::domain::{
    AbuseipdbSummary, AnalysisStats, ErrorCode, HashAlgorithm, IndicatorKind, Outcome, ProviderId,
    Status, Summary, ValidatedIndicator, VirustotalSummary,
};

const SUMMARY_BYTE_LIMIT: usize = 16 * 1024;

pub struct Adapter {
    id: ProviderId,
    client: Client,
    api_key: HeaderValue,
    origin: String,
    max_age_days: u16,
    #[cfg(test)]
    payload_version_override: Option<u32>,
}

#[derive(Debug)]
pub enum AdapterBuildError {
    InvalidCredentials,
    Client,
}

impl fmt::Display for AdapterBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCredentials => "Provider credentials are not a valid HTTP header.",
            Self::Client => "The provider HTTP client could not be initialized.",
        })
    }
}

impl std::error::Error for AdapterBuildError {}

impl Adapter {
    pub fn new(
        id: ProviderId,
        api_key: &str,
        max_age_days: u16,
        connect_timeout: Duration,
        attempt_timeout: Duration,
    ) -> Result<Self, AdapterBuildError> {
        let mut api_key =
            HeaderValue::from_str(api_key).map_err(|_| AdapterBuildError::InvalidCredentials)?;
        api_key.set_sensitive(true);
        let client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(attempt_timeout)
            .redirect(Policy::none())
            .https_only(true)
            .build()
            .map_err(|_| AdapterBuildError::Client)?;
        Ok(Self {
            id,
            client,
            api_key,
            origin: match id {
                ProviderId::Abuseipdb => "https://api.abuseipdb.com/",
                ProviderId::Virustotal => "https://www.virustotal.com/",
            }
            .to_owned(),
            max_age_days,
            #[cfg(test)]
            payload_version_override: None,
        })
    }

    /// Available only in test builds; production origins are compiled above.
    #[cfg(test)]
    pub fn for_test(id: ProviderId, origin: &str) -> Self {
        let parsed = Url::parse(origin).expect("valid mock URL");
        assert!(matches!(
            parsed.host_str(),
            Some("127.0.0.1" | "[::1]" | "localhost")
        ));
        assert!(matches!(parsed.scheme(), "http" | "https"));
        let mut adapter = Self::new(
            id,
            "sanitized-test-key",
            30,
            Duration::from_secs(2),
            Duration::from_secs(5),
        )
        .expect("mock adapter");
        adapter.client = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .expect("mock client");
        adapter.origin = origin.to_owned();
        adapter
    }

    pub fn id(&self) -> ProviderId {
        self.id
    }

    pub fn supports(&self, kind: IndicatorKind) -> bool {
        self.id == ProviderId::Virustotal || kind == IndicatorKind::Ip
    }

    pub fn payload_version(&self) -> u32 {
        #[cfg(test)]
        if let Some(version) = self.payload_version_override {
            return version;
        }
        1
    }

    /// Models an adapter release changing its compiled payload version.
    #[cfg(test)]
    pub fn with_test_payload_version(mut self, version: u32) -> Self {
        self.payload_version_override = Some(version);
        self
    }

    pub fn cache_options(&self) -> Value {
        match self.id {
            ProviderId::Abuseipdb => json!({"max_age_days":self.max_age_days,"verbose":false}),
            ProviderId::Virustotal => json!({}),
        }
    }

    pub fn request(&self, indicator: &ValidatedIndicator) -> Result<RequestBuilder, ErrorCode> {
        if !self.supports(indicator.input.kind) {
            return Err(ErrorCode::ProviderRequestRejected);
        }
        let mut url = Url::parse(&self.origin).map_err(|_| ErrorCode::InternalError)?;
        match self.id {
            ProviderId::Abuseipdb => {
                url.path_segments_mut()
                    .map_err(|_| ErrorCode::InternalError)?
                    .clear()
                    .extend(["api", "v2", "check"]);
                url.query_pairs_mut()
                    .append_pair("ipAddress", &indicator.lookup_value)
                    .append_pair("maxAgeInDays", &self.max_age_days.to_string());
                Ok(self
                    .client
                    .get(url)
                    .header("Key", self.api_key.clone())
                    .header(ACCEPT, "application/json"))
            }
            ProviderId::Virustotal => {
                let (endpoint, identifier) = match indicator.input.kind {
                    IndicatorKind::Ip => ("ip_addresses", indicator.lookup_value.clone()),
                    IndicatorKind::Url => (
                        "urls",
                        URL_SAFE_NO_PAD.encode(indicator.lookup_value.as_bytes()),
                    ),
                    IndicatorKind::Hash => ("files", indicator.lookup_value.clone()),
                };
                url.path_segments_mut()
                    .map_err(|_| ErrorCode::InternalError)?
                    .clear()
                    .extend(["api", "v3", endpoint, &identifier]);
                Ok(self
                    .client
                    .get(url)
                    .header("x-apikey", self.api_key.clone())
                    .header(ACCEPT, "application/json"))
            }
        }
    }

    pub fn decode(
        &self,
        status: u16,
        body: &[u8],
        indicator: &ValidatedIndicator,
        now: DateTime<Utc>,
    ) -> Result<Outcome, ErrorCode> {
        if !(200..300).contains(&status) {
            return match status {
                401 => Err(ErrorCode::ProviderAuthenticationFailed),
                403 => Err(ErrorCode::ProviderAccessDenied),
                429 => Err(ErrorCode::QuotaExhausted),
                404 if self.id == ProviderId::Virustotal => {
                    // Only the documented error code establishes a missing report.
                    #[derive(Deserialize)]
                    struct ErrorEnvelope {
                        error: ProviderError,
                    }
                    #[derive(Deserialize)]
                    struct ProviderError {
                        code: String,
                    }
                    let error: ErrorEnvelope = serde_json::from_slice(body)
                        .map_err(|_| ErrorCode::ProviderRequestRejected)?;
                    if error.error.code == "NotFoundError" {
                        Ok(Outcome::not_found(now))
                    } else {
                        Err(ErrorCode::ProviderRequestRejected)
                    }
                }
                500..=599 => Err(ErrorCode::ProviderUnavailable),
                _ => Err(ErrorCode::ProviderRequestRejected),
            };
        }
        let raw: Value = serde_json::from_slice(body).map_err(|_| ErrorCode::InvalidResponse)?;
        let (summary, provider_updated_at) = match self.id {
            ProviderId::Abuseipdb => decode_abuseipdb(&raw, indicator)?,
            ProviderId::Virustotal => decode_virustotal(&raw, indicator)?,
        };
        let mut summary_writer = crate::serialization::LimitedWriter::new(SUMMARY_BYTE_LIMIT);
        serde_json::to_writer(&mut summary_writer, &summary)
            .map_err(|_| ErrorCode::ResponseTooLarge)?;
        Ok(Outcome {
            status: Status::Ok,
            summary: Some(summary),
            fetched_at: Some(now),
            provider_updated_at,
            error: None,
            raw: Some(raw),
        })
    }
}

#[derive(Deserialize)]
struct AbuseEnvelope {
    data: AbuseData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseData {
    ip_address: String,
    abuse_confidence_score: Option<u64>,
    total_reports: Option<u64>,
    num_distinct_users: Option<u64>,
    last_reported_at: Option<String>,
    country_code: Option<String>,
    isp: Option<String>,
    domain: Option<String>,
    usage_type: Option<String>,
    is_public: Option<bool>,
    is_tor: Option<bool>,
    is_whitelisted: Option<bool>,
}

type DecodedSummary = Result<(Summary, Option<DateTime<Utc>>), ErrorCode>;

fn decode_abuseipdb(raw: &Value, indicator: &ValidatedIndicator) -> DecodedSummary {
    if indicator.input.kind != IndicatorKind::Ip {
        return Err(ErrorCode::InvalidResponse);
    }
    let envelope = AbuseEnvelope::deserialize(raw).map_err(|_| ErrorCode::InvalidResponse)?;
    let data = envelope.data;
    if data
        .ip_address
        .parse::<IpAddr>()
        .map_err(|_| ErrorCode::InvalidResponse)?
        != indicator
            .lookup_value
            .parse::<IpAddr>()
            .map_err(|_| ErrorCode::InvalidResponse)?
        || data.abuse_confidence_score.is_some_and(|score| score > 100)
    {
        return Err(ErrorCode::InvalidResponse);
    }
    let last_reported_at = data
        .last_reported_at
        .map(|timestamp| {
            DateTime::parse_from_rfc3339(&timestamp)
                .map(|date| date.with_timezone(&Utc))
                .map_err(|_| ErrorCode::InvalidResponse)
                .and_then(|date| {
                    if (0..=9999).contains(&date.year()) {
                        Ok(date)
                    } else {
                        Err(ErrorCode::InvalidResponse)
                    }
                })
        })
        .transpose()?;
    let summary = AbuseipdbSummary {
        abuse_confidence_score: data.abuse_confidence_score,
        total_reports: data.total_reports,
        distinct_reporters: data.num_distinct_users,
        last_reported_at,
        country_code: data.country_code,
        isp: data.isp,
        domain: data.domain,
        usage_type: data.usage_type,
        is_public: data.is_public,
        is_tor: data.is_tor,
        is_whitelisted: data.is_whitelisted,
    };
    Ok((Summary::Abuseipdb(summary), last_reported_at))
}

#[derive(Deserialize)]
struct VtEnvelope {
    data: VtData,
}

#[derive(Deserialize)]
struct VtData {
    id: String,
    #[serde(rename = "type")]
    object_type: String,
    attributes: VtAttributes,
}

#[derive(Deserialize)]
struct VtAttributes {
    last_analysis_stats: Option<VtAnalysisStats>,
    reputation: Option<i64>,
    last_analysis_date: Option<i64>,
    country: Option<String>,
    asn: Option<u64>,
    as_owner: Option<String>,
    md5: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
    type_description: Option<String>,
}

#[derive(Deserialize)]
struct VtAnalysisStats {
    malicious: Option<u64>,
    suspicious: Option<u64>,
    harmless: Option<u64>,
    undetected: Option<u64>,
    timeout: Option<u64>,
    #[serde(rename = "confirmed-timeout")]
    confirmed_timeout: Option<u64>,
    failure: Option<u64>,
    #[serde(rename = "type-unsupported")]
    type_unsupported: Option<u64>,
}

fn valid_hash(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decode_virustotal(raw: &Value, indicator: &ValidatedIndicator) -> DecodedSummary {
    let envelope = VtEnvelope::deserialize(raw).map_err(|_| ErrorCode::InvalidResponse)?;
    let VtData {
        id,
        object_type,
        attributes,
    } = envelope.data;
    match indicator.input.kind {
        IndicatorKind::Ip => {
            if object_type != "ip_address"
                || id
                    .parse::<IpAddr>()
                    .map_err(|_| ErrorCode::InvalidResponse)?
                    != indicator
                        .lookup_value
                        .parse::<IpAddr>()
                        .map_err(|_| ErrorCode::InvalidResponse)?
            {
                return Err(ErrorCode::InvalidResponse);
            }
        }
        IndicatorKind::Url => {
            // The returned ID is canonical SHA-256. The outgoing ID is base64 of
            // the exact submitted URL; they intentionally cannot be compared.
            if object_type != "url" || !valid_hash(&id, 64) {
                return Err(ErrorCode::InvalidResponse);
            }
        }
        IndicatorKind::Hash => {
            if object_type != "file" || !valid_hash(&id, 64) {
                return Err(ErrorCode::InvalidResponse);
            }
            let requested_hash = match indicator.hash_algorithm {
                Some(HashAlgorithm::Md5) => attributes.md5.as_deref(),
                Some(HashAlgorithm::Sha1) => attributes.sha1.as_deref(),
                Some(HashAlgorithm::Sha256) => Some(id.as_str()),
                None => None,
            };
            if !requested_hash
                .is_some_and(|hash| hash.eq_ignore_ascii_case(&indicator.lookup_value))
            {
                return Err(ErrorCode::InvalidResponse);
            }
            for (value, len) in [
                (&attributes.md5, 32),
                (&attributes.sha1, 40),
                (&attributes.sha256, 64),
            ] {
                if value
                    .as_deref()
                    .is_some_and(|value| !valid_hash(value, len))
                {
                    return Err(ErrorCode::InvalidResponse);
                }
            }
            if attributes
                .sha256
                .as_deref()
                .is_some_and(|sha256| !sha256.eq_ignore_ascii_case(&id))
            {
                return Err(ErrorCode::InvalidResponse);
            }
        }
    }
    let last_analysis_at = attributes
        .last_analysis_date
        .map(|seconds| {
            DateTime::from_timestamp(seconds, 0)
                .filter(|timestamp| (0..=9999).contains(&timestamp.year()))
                .ok_or(ErrorCode::InvalidResponse)
        })
        .transpose()?;
    let ip = indicator.input.kind == IndicatorKind::Ip;
    let file = indicator.input.kind == IndicatorKind::Hash;
    let summary = VirustotalSummary {
        analysis_stats: attributes.last_analysis_stats.map(|stats| AnalysisStats {
            malicious: stats.malicious,
            suspicious: stats.suspicious,
            harmless: stats.harmless,
            undetected: stats.undetected,
            timeout: stats.timeout,
            confirmed_timeout: stats.confirmed_timeout,
            failure: stats.failure,
            type_unsupported: stats.type_unsupported,
        }),
        reputation: attributes.reputation,
        last_analysis_at,
        country: if ip { attributes.country } else { None },
        asn: if ip { attributes.asn } else { None },
        as_owner: if ip { attributes.as_owner } else { None },
        md5: if file { attributes.md5 } else { None },
        sha1: if file { attributes.sha1 } else { None },
        sha256: if file { attributes.sha256 } else { None },
        file_type: if file {
            attributes.type_description
        } else {
            None
        },
    };
    Ok((Summary::Virustotal(Box::new(summary)), last_analysis_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::validate_indicator;

    const SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";
    const SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    fn adapter(id: ProviderId) -> Adapter {
        Adapter::new(
            id,
            "sanitized-key",
            30,
            Duration::from_secs(2),
            Duration::from_secs(5),
        )
        .unwrap()
    }

    fn decode(
        id: ProviderId,
        kind: IndicatorKind,
        value: &str,
        body: Value,
    ) -> Result<Outcome, ErrorCode> {
        adapter(id).decode(
            200,
            &serde_json::to_vec(&body).unwrap(),
            &validate_indicator(kind, value).unwrap(),
            DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )
    }

    #[test]
    fn requests_have_fixed_origins_encoded_values_and_private_headers() {
        let abuse = adapter(ProviderId::Abuseipdb)
            .request(&validate_indicator(IndicatorKind::Ip, "2001:db8::1").unwrap())
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            abuse.url().origin().ascii_serialization(),
            "https://api.abuseipdb.com"
        );
        assert_eq!(abuse.url().path(), "/api/v2/check");
        assert_eq!(
            abuse.url().query_pairs().collect::<Vec<_>>(),
            [
                ("ipAddress".into(), "2001:db8::1".into()),
                ("maxAgeInDays".into(), "30".into())
            ]
        );
        assert!(!abuse.url().as_str().contains("verbose"));
        assert!(abuse.headers()["Key"].is_sensitive());
        assert_eq!(abuse.headers()[ACCEPT], "application/json");
        assert!(!abuse.headers().contains_key("authorization"));

        let url = "HTTPS://EXAMPLE.COM:443/path?q=%2f&z=á#Frag";
        let vt = adapter(ProviderId::Virustotal)
            .request(&validate_indicator(IndicatorKind::Url, url).unwrap())
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            vt.url().origin().ascii_serialization(),
            "https://www.virustotal.com"
        );
        let url_id = vt.url().path_segments().unwrap().next_back().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(url_id).unwrap(), url.as_bytes());
        assert!(!url_id.contains(['+', '/', '=']));
        assert!(vt.headers()["x-apikey"].is_sensitive());
        assert!(!vt.headers().contains_key("authorization"));
        assert_eq!(vt.headers()[ACCEPT], "application/json");
        let file = adapter(ProviderId::Virustotal)
            .request(&validate_indicator(IndicatorKind::Hash, &MD5.to_uppercase()).unwrap())
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(file.url().path(), format!("/api/v3/files/{MD5}"));
    }

    #[test]
    fn optional_evidence_stays_null_and_unknown_raw_fields_survive() {
        let raw = json!({"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":0,"future_evidence":{"arbitrary":"preserved"}},"meta":{"extra":true}});
        let outcome = decode(
            ProviderId::Abuseipdb,
            IndicatorKind::Ip,
            "8.8.8.8",
            raw.clone(),
        )
        .unwrap();
        assert_eq!(outcome.raw, Some(raw));
        assert_eq!(outcome.status, Status::Ok);
        let summary = serde_json::to_value(outcome.summary).unwrap();
        assert_eq!(summary["abuse_confidence_score"], 0);
        assert!(summary["total_reports"].is_null());
        assert!(summary["is_whitelisted"].is_null());
        assert!(outcome.provider_updated_at.is_none());
    }

    #[test]
    fn sanitized_fixtures_cover_both_providers_and_all_kinds() {
        for (provider, kind, value, fixture) in [
            (
                ProviderId::Abuseipdb,
                IndicatorKind::Ip,
                "8.8.8.8",
                include_str!("../tests/fixtures/abuseipdb-ip.json"),
            ),
            (
                ProviderId::Virustotal,
                IndicatorKind::Ip,
                "2001:db8::1",
                include_str!("../tests/fixtures/virustotal-ip.json"),
            ),
            (
                ProviderId::Virustotal,
                IndicatorKind::Url,
                "https://example.com/",
                include_str!("../tests/fixtures/virustotal-url.json"),
            ),
            (
                ProviderId::Virustotal,
                IndicatorKind::Hash,
                SHA256,
                include_str!("../tests/fixtures/virustotal-file.json"),
            ),
            (
                ProviderId::Virustotal,
                IndicatorKind::Hash,
                MD5,
                include_str!("../tests/fixtures/virustotal-file.json"),
            ),
            (
                ProviderId::Virustotal,
                IndicatorKind::Hash,
                SHA1,
                include_str!("../tests/fixtures/virustotal-file.json"),
            ),
        ] {
            let outcome = decode(
                provider,
                kind,
                value,
                serde_json::from_str(fixture).unwrap(),
            )
            .unwrap();
            assert_eq!(outcome.status, Status::Ok);
            assert!(outcome.provider_updated_at.is_some());
            // Persistence cannot reinterpret VirusTotal's untagged summary as AbuseIPDB.
            let recovered: Outcome =
                serde_json::from_slice(&serde_json::to_vec(&outcome).unwrap()).unwrap();
            assert_eq!(recovered, outcome);
        }
    }

    #[test]
    fn cache_roundtrip_preserves_provider_variant_when_all_evidence_is_null() {
        for (provider, body) in [
            (
                ProviderId::Abuseipdb,
                json!({"data":{"ipAddress":"8.8.8.8"}}),
            ),
            (
                ProviderId::Virustotal,
                json!({"data":{"id":"8.8.8.8","type":"ip_address","attributes":{}}}),
            ),
        ] {
            let original = decode(provider, IndicatorKind::Ip, "8.8.8.8", body).unwrap();
            let recovered: Outcome =
                serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
            assert_eq!(original, recovered);
            match (provider, recovered.summary) {
                (ProviderId::Abuseipdb, Some(Summary::Abuseipdb(_)))
                | (ProviderId::Virustotal, Some(Summary::Virustotal(_))) => {}
                _ => panic!("cached summary changed provider"),
            }
        }
    }

    #[test]
    fn maps_signed_reputation_and_hyphenated_counts_without_inventing_evidence() {
        let outcome = decode(ProviderId::Virustotal, IndicatorKind::Ip, "8.8.8.8", json!({"data":{"id":"8.8.8.8","type":"ip_address","attributes":{"reputation":-15,"last_analysis_stats":{"malicious":0,"confirmed-timeout":2,"type-unsupported":3,"failure":4,"unknown_count":50}}}})).unwrap();
        let summary = serde_json::to_value(outcome.summary).unwrap();
        assert_eq!(summary["reputation"], -15);
        assert_eq!(summary["analysis_stats"]["malicious"], 0);
        assert!(summary["analysis_stats"]["suspicious"].is_null());
        assert_eq!(summary["analysis_stats"]["confirmed_timeout"], 2);
        assert_eq!(summary["analysis_stats"]["type_unsupported"], 3);
        assert_eq!(summary["analysis_stats"]["failure"], 4);
        assert!(summary["md5"].is_null());
    }

    #[test]
    fn enforces_mandatory_provider_identity_even_without_evidence() {
        for body in [
            json!({}),
            json!({"data":null}),
            json!({"data":[]}),
            json!({"data":{}}),
            json!({"data":{"ipAddress":null}}),
            json!({"data":{"ipAddress":"8.8.4.4"}}),
            json!({"data":{"ipAddress":"[8.8.8.8]"}}),
        ] {
            assert_eq!(
                decode(ProviderId::Abuseipdb, IndicatorKind::Ip, "8.8.8.8", body),
                Err(ErrorCode::InvalidResponse)
            );
        }
        for body in [
            json!({"data":{"id":"8.8.8.8","type":"url","attributes":{}}}),
            json!({"data":{"id":"8.8.4.4","type":"ip_address","attributes":{}}}),
            json!({"data":{"id":"8.8.8.8","type":"ip_address"}}),
            json!({"data":{"id":"8.8.8.8","type":"ip_address","attributes":null}}),
        ] {
            assert_eq!(
                decode(ProviderId::Virustotal, IndicatorKind::Ip, "8.8.8.8", body),
                Err(ErrorCode::InvalidResponse)
            );
        }
        assert!(
            decode(
                ProviderId::Abuseipdb,
                IndicatorKind::Ip,
                "2001:db8::1",
                json!({"data":{"ipAddress":"2001:0db8:0:0:0:0:0:1"}})
            )
            .is_ok()
        );
        assert_eq!(
            decode(
                ProviderId::Abuseipdb,
                IndicatorKind::Ip,
                "::ffff:192.0.2.1",
                json!({"data":{"ipAddress":"192.0.2.1"}})
            ),
            Err(ErrorCode::InvalidResponse)
        );
    }

    #[test]
    fn url_response_identity_is_canonical_sha256_and_not_outgoing_base64() {
        let body = json!({"data":{"id":"a".repeat(64),"type":"url","attributes":{"url":"http://canonical.example/","country":"US","md5":MD5}}});
        let outcome = decode(
            ProviderId::Virustotal,
            IndicatorKind::Url,
            "https://EXAMPLE.com:443/#frag",
            body,
        )
        .unwrap();
        let summary = serde_json::to_value(outcome.summary).unwrap();
        assert!(summary["country"].is_null());
        assert!(summary["md5"].is_null());
        for id in [
            URL_SAFE_NO_PAD.encode(b"https://example.com/"),
            "g".repeat(64),
            "a".repeat(63),
        ] {
            assert_eq!(
                decode(
                    ProviderId::Virustotal,
                    IndicatorKind::Url,
                    "https://example.com/",
                    json!({"data":{"id":id,"type":"url","attributes":{}}})
                ),
                Err(ErrorCode::InvalidResponse)
            );
        }
    }

    #[test]
    fn hash_lookup_checks_corresponding_algorithm_and_canonical_file_id() {
        for (requested, attrs, id) in [
            (MD5, json!({}), SHA256.to_owned()),
            (MD5, json!({"md5":"a".repeat(32)}), SHA256.to_owned()),
            (SHA1, json!({"sha1":null}), SHA256.to_owned()),
            (SHA256, json!({}), "a".repeat(64)),
            (MD5, json!({"md5":MD5}), MD5.to_owned()),
            (SHA256, json!({"sha256":"b".repeat(64)}), SHA256.to_owned()),
        ] {
            assert_eq!(
                decode(
                    ProviderId::Virustotal,
                    IndicatorKind::Hash,
                    requested,
                    json!({"data":{"id":id,"type":"file","attributes":attrs}})
                ),
                Err(ErrorCode::InvalidResponse)
            );
        }
        assert!(
            decode(
                ProviderId::Virustotal,
                IndicatorKind::Hash,
                MD5,
                json!({"data":{"id":SHA256,"type":"file","attributes":{"md5":MD5.to_uppercase()}}})
            )
            .is_ok()
        );
    }

    #[test]
    fn incorrectly_typed_evidence_invalid_timestamps_and_negative_counts_fail() {
        for (key, value) in [
            ("abuseConfidenceScore", json!(101)),
            ("totalReports", json!(-1)),
            ("numDistinctUsers", json!(1.5)),
            ("isPublic", json!("true")),
            ("countryCode", json!(2)),
            ("lastReportedAt", json!("not-a-date")),
        ] {
            let mut body = json!({"data":{"ipAddress":"8.8.8.8"}});
            body["data"][key] = value;
            assert_eq!(
                decode(ProviderId::Abuseipdb, IndicatorKind::Ip, "8.8.8.8", body),
                Err(ErrorCode::InvalidResponse)
            );
        }
        for attrs in [
            json!({"last_analysis_stats":{"malicious":-1}}),
            json!({"last_analysis_stats":{"failure":false}}),
            json!({"last_analysis_stats":0}),
            json!({"reputation":1.5}),
            json!({"last_analysis_date":"1800000000"}),
            json!({"last_analysis_date":i64::MAX}),
            json!({"asn":-1}),
            json!({"as_owner":[]}),
            json!({"md5":true}),
        ] {
            assert_eq!(
                decode(
                    ProviderId::Virustotal,
                    IndicatorKind::Ip,
                    "8.8.8.8",
                    json!({"data":{"id":"8.8.8.8","type":"ip_address","attributes":attrs}})
                ),
                Err(ErrorCode::InvalidResponse)
            );
        }
    }

    #[test]
    fn summaries_enforce_size_limit_without_silently_truncating() {
        assert_eq!(
            decode(
                ProviderId::Abuseipdb,
                IndicatorKind::Ip,
                "8.8.8.8",
                json!({"data":{"ipAddress":"8.8.8.8","isp":"a".repeat(SUMMARY_BYTE_LIMIT)}})
            ),
            Err(ErrorCode::ResponseTooLarge)
        );
    }

    #[test]
    fn status_mapping_never_leaks_upstream_error_text() {
        let indicator = validate_indicator(IndicatorKind::Ip, "8.8.8.8").unwrap();
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let vt = adapter(ProviderId::Virustotal);
        for (status, code) in [
            (401, ErrorCode::ProviderAuthenticationFailed),
            (403, ErrorCode::ProviderAccessDenied),
            (429, ErrorCode::QuotaExhausted),
            (500, ErrorCode::ProviderUnavailable),
            (502, ErrorCode::ProviderUnavailable),
            (301, ErrorCode::ProviderRequestRejected),
            (400, ErrorCode::ProviderRequestRejected),
        ] {
            assert_eq!(
                vt.decode(
                    status,
                    b"sensitive upstream error with key",
                    &indicator,
                    now
                ),
                Err(code)
            );
        }
        let not_found = vt
            .decode(
                404,
                br#"{"error":{"code":"NotFoundError","message":"private upstream data"}}"#,
                &indicator,
                now,
            )
            .unwrap();
        assert_eq!(not_found, Outcome::not_found(now));
        assert_eq!(
            vt.decode(
                404,
                br#"{"error":{"code":"UnknownError"}}"#,
                &indicator,
                now
            ),
            Err(ErrorCode::ProviderRequestRejected)
        );
        assert_eq!(
            adapter(ProviderId::Abuseipdb).decode(
                404,
                br#"{"error":{"code":"NotFoundError"}}"#,
                &indicator,
                now
            ),
            Err(ErrorCode::ProviderRequestRejected)
        );
        for body in [b"not json".as_slice(), br#"{"data": "#, b"null", b"[]"] {
            assert_eq!(
                vt.decode(200, body, &indicator, now),
                Err(ErrorCode::InvalidResponse)
            );
        }
    }

    #[tokio::test]
    async fn client_does_not_follow_redirects() {
        use axum::{Router, response::Redirect, routing::get};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/v2/check",
            get(|| async { Redirect::temporary("http://127.0.0.1:1/should-never-be-fetched") }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let adapter = Adapter::for_test(ProviderId::Abuseipdb, &format!("http://{address}"));
        let response = adapter
            .request(&validate_indicator(IndicatorKind::Ip, "8.8.8.8").unwrap())
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 307);
        server.abort();
        let _ = server.await;
    }
}

use super::*;
use crate::domain::{IndicatorKind, Outcome, validate_indicator};
use serde_json::{Value, json};

fn setup(raw: Option<Value>, count: usize) -> (ValidatedRequest, Vec<LookupResult>) {
    let indicator = validate_indicator(IndicatorKind::Ip, "8.8.8.8").unwrap();
    let mut outcome = Outcome::empty(Status::Ok);
    outcome.raw = raw;
    outcome.fetched_at = Some(Utc::now());
    let outcome = Arc::new(outcome);
    let request = ValidatedRequest {
        indicators: vec![indicator; count],
        providers: vec![ProviderId::Abuseipdb],
        include_raw: true,
    };
    let outcomes = vec![
        LookupResult {
            outcome,
            cache_hit: false,
            expires_at: None
        };
        count
    ];
    (request, outcomes)
}

#[test]
fn raw_budget_counts_duplicate_slots_and_full_objects() {
    let (request, outcomes) = setup(Some(json!({"data":"x".repeat(900_000)})), 20);
    let bytes = project("id", &request, &outcomes, 8 * 1024 * 1024).unwrap();
    assert!(bytes.len() <= 9 * 1024 * 1024);
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    for (index, result) in response["results"].as_array().unwrap().iter().enumerate() {
        let provider = &result["providers"][0];
        assert_eq!(provider["status"], "ok");
        if index < 9 {
            assert_eq!(provider["raw"]["data"].as_str().unwrap().len(), 900_000);
            assert!(provider.get("raw_omitted_reason").is_none());
        } else {
            assert_eq!(provider["raw_omitted_reason"], "response_size_limit");
            assert!(provider.get("raw").is_none());
        }
    }
}

#[test]
fn raw_budget_continues_to_consider_smaller_later_reports() {
    let (request, mut outcomes) = setup(Some(json!({"data":"large report"})), 3);
    let mut small = (*outcomes[1].outcome).clone();
    small.raw = Some(json!({"a":1}));
    outcomes[1].outcome = Arc::new(small);
    let value: Value =
        serde_json::from_slice(&project("id", &request, &outcomes, 7).unwrap()).unwrap();
    assert_eq!(
        value["results"][0]["providers"][0]["raw_omitted_reason"],
        "response_size_limit"
    );
    assert_eq!(value["results"][1]["providers"][0]["raw"], json!({"a":1}));
    assert_eq!(
        value["results"][2]["providers"][0]["raw_omitted_reason"],
        "response_size_limit"
    );
}

#[test]
fn raw_presentation_does_not_remove_required_nullable_fields() {
    let (mut request, outcomes) = setup(None, 1);
    for include_raw in [true, false] {
        request.include_raw = include_raw;
        let value: Value =
            serde_json::from_slice(&project("id", &request, &outcomes, 100).unwrap()).unwrap();
        let provider = &value["results"][0]["providers"][0];
        for field in ["summary", "provider_updated_at", "error"] {
            assert_eq!(provider.get(field), Some(&Value::Null));
        }
        assert_eq!(provider["cache"]["expires_at"], Value::Null);
        assert_eq!(provider.get("raw_omitted_reason").is_some(), include_raw);
        assert!(provider.get("raw").is_none());
    }
}

#[test]
fn non_raw_envelope_overflow_returns_small_safe_500() {
    let (mut request, outcomes) = setup(None, 1);
    request.indicators[0].input.value = "x".repeat(ENVELOPE_LIMIT);
    assert_eq!(
        project("id", &request, &outcomes, 100),
        Err(ErrorCode::ResponseTooLarge)
    );
    let response = error_response(
        "id",
        StatusCode::INTERNAL_SERVER_ERROR,
        ErrorCode::ResponseTooLarge,
        None,
    );
    assert_eq!(response.status(), 500);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
}

#[test]
fn retry_after_dates_round_up_and_reject_bad_values() {
    let now = DateTime::parse_from_rfc3339("2026-09-12T00:00:00.001Z")
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!(
        crate::enrichment::parse_retry_after(Some("Sat, 12 Sep 2026 00:00:02 GMT"), now),
        Some(Duration::from_secs(2))
    );
    assert_eq!(
        crate::enrichment::parse_retry_after(Some("12"), now),
        Some(Duration::from_secs(12))
    );
    assert_eq!(crate::enrichment::parse_retry_after(Some("-1"), now), None);
    assert_eq!(
        crate::enrichment::parse_retry_after(Some("provider secret text"), now),
        None
    );
}

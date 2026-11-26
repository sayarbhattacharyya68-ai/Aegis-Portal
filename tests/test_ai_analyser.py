import json

import ai_analyser as ai


def test_oracle_local_scoring_does_not_call_gemini(monkeypatch):
    monkeypatch.setattr(ai, "_generate_content", lambda **kwargs: (_ for _ in ()).throw(AssertionError("Gemini called")))
    result = ai.get_oracle_analysis("aVeryLong!DistinctivePhrase_482920", allow_ai=False)
    assert result.startswith("[FORTIFIED]") or result.startswith("[COMPROMISED]") or result.startswith("[CRITICAL]")
    assert "password" not in result.casefold()


def test_oracle_opt_in_sends_only_derived_features(monkeypatch):
    secret = "TopSecret-Password-Do-Not-Send-764920!"
    observed = {}

    def fake_generate(**kwargs):
        observed.update(kwargs)
        return "▸ Strong length band\n▸ Several character classes\n▸ No common sequence\n⚡ Keep it unique.", None

    monkeypatch.setattr(ai, "_generate_content", fake_generate)
    result = ai.get_oracle_analysis(secret, allow_ai=True)
    assert secret not in json.dumps(observed, default=str)
    assert result.startswith("[")


def test_sentinel_validates_output_and_local_recipient_match(monkeypatch):
    monkeypatch.setenv("PAYMENT_RECIPIENT_NAME", "Example Recipient")
    monkeypatch.setenv("PAYMENT_RECIPIENT_VPA", "example@bank")
    monkeypatch.setattr(ai, "_get_gemini_client", lambda: object())
    monkeypatch.setattr(ai, "_build_image_part", lambda image_bytes: {"test_image_part": True})
    raw = {
        "verdict": "VERIFIED",
        "confidence": 0.98,
        "amount_detected": "INR 50.00",
        "recipient_text": "Example Recipient example@bank",
        "upi_ref": "1234567890",
        "findings": ["Payment status text appears successful"],
    }
    monkeypatch.setattr(ai, "_generate_content", lambda **kwargs: (json.dumps(raw), None))
    result = ai.verify_payment_screenshot(b"synthetic-jpeg-bytes", 50)
    assert result["verdict"] == "VERIFIED"
    assert result["recipient_match"] is True
    assert result["confidence"] <= 1.0


def test_sentinel_downgrades_when_recipient_not_configured(monkeypatch):
    monkeypatch.delenv("PAYMENT_RECIPIENT_NAME", raising=False)
    monkeypatch.delenv("PAYMENT_RECIPIENT_VPA", raising=False)
    monkeypatch.setattr(ai, "_get_gemini_client", lambda: object())
    monkeypatch.setattr(ai, "_build_image_part", lambda image_bytes: {"test_image_part": True})
    raw = {
        "verdict": "VERIFIED",
        "confidence": 0.99,
        "amount_detected": "50",
        "recipient_text": "Example Recipient",
        "upi_ref": "99887766",
        "findings": [],
    }
    monkeypatch.setattr(ai, "_generate_content", lambda **kwargs: (json.dumps(raw), None))
    result = ai.verify_payment_screenshot(b"synthetic-jpeg-bytes", 50)
    assert result["verdict"] == "PENDING_ADMIN_REVIEW"
    assert result["recipient_match"] is False


def test_warden_uses_structured_ai_and_sends_only_sanitized_event_data(monkeypatch):
    observed = {}

    def fake_generate(**kwargs):
        observed.update(kwargs)
        return json.dumps({
            "threat_level": "ELEVATED",
            "risk_score": 5.5,
            "assessment": "Repeated authentication failures warrant administrator review.",
            "recommended_action": "WARN",
            "indicators": ["Repeated failed authentication events"],
        }), None

    monkeypatch.setattr(ai, "_generate_content", fake_generate)
    events = [
        (1, "2026-11-17 20:00:00", "AUTH_FAILURE", "private@example.test", "IP 10.1.2.3 secret text", "WARNING"),
        (2, "2026-11-17 20:01:00", "AUTH_THROTTLED", "private@example.test", "Private details", "WARNING"),
    ]
    result = ai.warden_assess_identity("private@example.test", events)
    payload = json.loads(observed["contents"])
    assert "private@example.test" not in observed["contents"]
    assert "10.1.2.3" not in observed["contents"]
    assert "secret text" not in observed["contents"]
    assert payload["events_reviewed"] == 2
    assert payload["event_counts"]["AUTH_FAILURE"] == 1
    assert payload["event_counts"]["AUTH_THROTTLED"] == 1
    assert observed["response_mime_type"] == "application/json"
    assert observed["response_schema"] == ai.WARDEN_RESPONSE_SCHEMA
    assert observed["max_output_tokens"] == 2048
    assert result["assessment_status"] == "complete"
    assert result["threat_level"] == "ELEVATED"
    assert result["risk_score"] == 5.5
    assert result["recommended_action"] == "WARN"


def test_warden_rejects_invalid_ai_output_without_fabricating_nominal_score(monkeypatch):
    raw = {
        "threat_level": "CRITICAL",
        "risk_score": 999,
        "assessment": "x" * 2000,
        "recommended_action": "PURGE_DATABASE",
        "indicators": ["a" * 300],
    }
    monkeypatch.setattr(ai, "_generate_content", lambda **kwargs: (json.dumps(raw), None))
    result = ai.warden_assess_identity("private@example.test", [])
    assert result["assessment_status"] == "unavailable"
    assert result["threat_level"] == "UNAVAILABLE"
    assert result["risk_score"] is None
    assert result["recommended_action"] == "MANUAL_REVIEW"


def test_gemini_missing_key_uses_safe_sentinel_fallback(monkeypatch):
    monkeypatch.setattr(ai, "_get_gemini_client", lambda: None)
    result = ai.verify_payment_screenshot(b"fake", 50)
    assert result["verdict"] == "PENDING_ADMIN_REVIEW"


def test_warden_api_failure_is_not_displayed_as_nominal(monkeypatch):
    monkeypatch.setattr(ai, "_generate_content", lambda **kwargs: (None, "authentication"))
    result = ai.warden_assess_identity("private@example.test", [])
    assert result["assessment_status"] == "unavailable"
    assert result["threat_level"] == "UNAVAILABLE"
    assert result["risk_score"] is None
    assert result["recommended_action"] == "MANUAL_REVIEW"
    assert "authentication failed" in result["assessment"].casefold()


def test_warden_rejects_score_threat_label_mismatch(monkeypatch):
    raw = {
        "threat_level": "NOMINAL",
        "risk_score": 8.2,
        "assessment": "The supplied recent events show repeated high-risk signals.",
        "recommended_action": "LOCKDOWN",
        "indicators": ["Repeated critical events"],
    }
    monkeypatch.setattr(ai, "_generate_content", lambda **kwargs: (json.dumps(raw), None))
    result = ai.warden_assess_identity("private@example.test", [])
    assert result["assessment_status"] == "unavailable"
    assert result["error_code"] == "inconsistent_score"
    assert result["risk_score"] is None


def test_recipient_match_rejects_short_ocr_substring(monkeypatch):
    monkeypatch.setenv("PAYMENT_RECIPIENT_NAME", "Example Recipient")
    monkeypatch.delenv("PAYMENT_RECIPIENT_VPA", raising=False)
    assert ai._recipient_matches("a") is False
    assert ai._recipient_matches("Example Recipient") is True


def test_model_output_with_unexpected_container_types_uses_safe_defaults(monkeypatch):
    sentinel_raw = {"verdict": ["VERIFIED"], "confidence": 1.0, "amount_detected": "50"}
    monkeypatch.setattr(ai, "_get_gemini_client", lambda: object())
    monkeypatch.setattr(ai, "_build_image_part", lambda image_bytes: {"test_image_part": True})
    monkeypatch.setattr(ai, "_generate_content", lambda **kwargs: (json.dumps(sentinel_raw), None))
    sentinel = ai.verify_payment_screenshot(b"synthetic-jpeg-bytes", 50)
    assert sentinel["verdict"] == "PENDING_ADMIN_REVIEW"

    warden_raw = {
        "threat_level": ["CRITICAL"],
        "risk_score": 4.0,
        "assessment": "A malformed model response was safely handled.",
        "recommended_action": {"action": "BAN"},
        "indicators": [],
    }
    monkeypatch.setattr(ai, "_generate_content", lambda **kwargs: (json.dumps(warden_raw), None))
    warden = ai.warden_assess_identity("nobody@example.test", [])
    assert warden["assessment_status"] == "unavailable"
    assert warden["threat_level"] == "UNAVAILABLE"
    assert warden["risk_score"] is None
    assert warden["recommended_action"] == "MANUAL_REVIEW"
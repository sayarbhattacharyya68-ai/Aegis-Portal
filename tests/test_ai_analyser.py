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


def test_warden_does_not_send_identity_or_event_details(monkeypatch):
    observed = {}

    def fake_generate(**kwargs):
        observed.update(kwargs)
        return json.dumps({
            "threat_level": "ELEVATED",
            "risk_score": 5.5,
            "assessment": "Repeated authentication failures were observed.",
            "recommended_action": "WARN",
            "indicators": ["Repeated failures"],
        }), None

    monkeypatch.setattr(ai, "_generate_content", fake_generate)
    events = [(1, "2026-11-17 20:00:00", "AUTH_FAILURE", "private@example.test", "IP 10.1.2.3 secret text", "WARNING")]
    result = ai.warden_assess_identity("private@example.test", events)
    payload = str(observed.get("contents", ""))
    assert "private@example.test" not in payload
    assert "10.1.2.3" not in payload
    assert "secret text" not in payload
    assert result["recommended_action"] == "WARN"


def test_warden_rejects_invalid_enums_and_ranges(monkeypatch):
    raw = {
        "threat_level": "EXECUTE_ADMIN",
        "risk_score": 999,
        "assessment": "x" * 2000,
        "recommended_action": "PURGE_DATABASE",
        "indicators": ["a" * 300],
    }
    monkeypatch.setattr(ai, "_generate_content", lambda **kwargs: (json.dumps(raw), None))
    result = ai.warden_assess_identity("private@example.test", [])
    assert result["threat_level"] == "NOMINAL"
    assert result["risk_score"] == 10.0
    assert result["recommended_action"] == "MONITOR"
    assert len(result["assessment"]) <= 800
    assert len(result["indicators"][0]) <= 160


def test_gemini_missing_key_uses_safe_sentinel_fallback(monkeypatch):
    monkeypatch.setattr(ai, "_get_gemini_client", lambda: None)
    result = ai.verify_payment_screenshot(b"fake", 50)
    assert result["verdict"] == "PENDING_ADMIN_REVIEW"


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
    assert warden["threat_level"] == "NOMINAL"
    assert warden["recommended_action"] == "MONITOR"

def test_oracle_intermediate_heuristic_uses_moderate_label():
    # A deliberately mid-range 12-character value: the heuristic band is not
    # a breach lookup and must not be labelled as a confirmed compromise.
    features = ai._derive_password_features("Abc123def456")
    assert features["local_grade"] == "MODERATE"
    report = ai.get_oracle_analysis("Abc123def456", allow_ai=False)
    assert report.startswith("[MODERATE]")

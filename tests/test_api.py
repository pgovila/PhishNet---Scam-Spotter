"""PhishNet API test suite."""

from __future__ import annotations

# pyrefly: ignore[missing-import]
from fastapi.testclient import TestClient

from api import app

client = TestClient(app)


def test_health_endpoint():
    """Test health check returns status ok."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "phishnet"}


def test_analyze_endpoint_success():
    """Test message analysis endpoint with standard scam message."""
    payload = {
        "text": "SBI ALERT: Your KYC is incomplete. Visit http://sbi-kyc.example and share OTP.",
        "mode": "default",
    }
    response = client.post("/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "score" in data
    assert "tier" in data
    assert "findings" in data
    assert data["tier"] in ("low", "medium", "high")
    assert len(data["findings"]) > 0


def test_analyze_endpoint_too_short():
    """Test that messages under 10 characters are rejected with 422."""
    response = client.post("/v1/analyze", json={"text": "Short"})
    assert response.status_code == 422


def test_api_key_auth(monkeypatch):
    """Test API key authentication enforcement when keys are configured."""
    monkeypatch.setenv("PHISHNET_API_KEYS", "secret-test-key,other-key")
    payload = {
        "text": "SBI ALERT: Your KYC is incomplete. Visit http://sbi-kyc.example and share OTP.",
    }

    # Without key -> 401
    resp_unauth = client.post("/v1/analyze", json=payload)
    assert resp_unauth.status_code == 401

    # With invalid key -> 401
    resp_bad = client.post("/v1/analyze", json=payload, headers={"X-API-Key": "wrong-key"})
    assert resp_bad.status_code == 401

    # With valid key -> 200
    resp_ok = client.post("/v1/analyze", json=payload, headers={"X-API-Key": "secret-test-key"})
    assert resp_ok.status_code == 200

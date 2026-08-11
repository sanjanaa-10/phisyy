"""
Minimal API test suite for the Phisyy backend.

Run from the backend/ directory (with requirements installed):
    pytest

These tests deliberately mock URLFeatureExtractor for the
/predict_url cases so CI never depends on a live network call
to a real website.
"""

from unittest.mock import patch

from fastapi.testclient import TestClient

from app import app

client = TestClient(app)

# A feature vector matching the model's expected 22 columns.
VALID_FEATURES = {
    "URLLength": 23,
    "DomainLength": 10,
    "TLDLength": 3,
    "NoOfImage": 5,
    "NoOfJS": 4,
    "NoOfCSS": 2,
    "NoOfSelfRef": 12,
    "NoOfExternalRef": 3,
    "IsHTTPS": 1,
    "HasObfuscation": 0,
    "HasTitle": 1,
    "HasDescription": 1,
    "HasSubmitButton": 0,
    "HasSocialNet": 1,
    "HasFavicon": 1,
    "HasCopyrightInfo": 1,
    "popUpWindow": 0,
    "Iframe": 0,
    "Abnormal_URL": 0,
    "LetterToDigitRatio": 4.5,
    "Redirect_0": 1,
    "Redirect_1": 0,
}


def test_root_health_check():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "online"


def test_predict_with_valid_features_returns_full_result():
    response = client.post("/predict", json=VALID_FEATURES)
    assert response.status_code == 200

    body = response.json()
    assert body["result"] in ("Legitimate", "Phishing")
    assert 0 <= body["threat_score"] <= 100
    assert body["risk_level"] in ("LOW", "MEDIUM", "HIGH")
    assert len(body["explanations"]) <= 7


def test_predict_with_missing_field_returns_422():
    incomplete = VALID_FEATURES.copy()
    del incomplete["URLLength"]

    response = client.post("/predict", json=incomplete)
    assert response.status_code == 422


def test_predict_url_with_empty_url_returns_422():
    response = client.post("/predict_url", json={"url": "   "})
    assert response.status_code == 422


def test_predict_url_when_page_fetch_fails_returns_502():
    """
    Regression test for the fixed bug: a failed page fetch must
    short-circuit with a clear error, not silently fall through to
    feature extraction with empty/zero defaults and a confident-
    looking prediction for a page that was never actually analyzed.
    """
    with patch("app.URLFeatureExtractor") as mock_extractor_cls:
        mock_instance = mock_extractor_cls.return_value
        mock_instance.page_fetch_failed = True
        mock_instance.page_fetch_error = "Website response timed out."

        response = client.post(
            "/predict_url",
            json={"url": "https://example-unreachable-site.test"},
        )

    assert response.status_code == 502
    assert "timed out" in response.json()["detail"].lower()


def test_predict_url_success_with_mocked_extractor():
    with patch("app.URLFeatureExtractor") as mock_extractor_cls:
        mock_instance = mock_extractor_cls.return_value
        mock_instance.page_fetch_failed = False
        mock_instance.extract_model_features.return_value = VALID_FEATURES

        response = client.post(
            "/predict_url",
            json={"url": "https://example.com"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["url"] == "https://example.com"
    assert body["result"] in ("Legitimate", "Phishing")

"""
API test suite for the Phisyy backend.

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

# A feature vector matching the model's expected 25 columns
# (URLLength is now a length BUCKET: 1=short, 2=medium, 3=long,
# 4=very long).
VALID_FEATURES = {
    "URLLength": 1,
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
    "FetchFailed": 0,
    "DomainAgeDays": 3650,
    "DomainAgeUnknown": 0,
}

# A fully-empty feature vector (all zeros / neutral values).
EMPTY_FEATURES = {
    "URLLength": 1,
    "DomainLength": 1,
    "TLDLength": 3,
    "NoOfImage": 0,
    "NoOfJS": 0,
    "NoOfCSS": 0,
    "NoOfSelfRef": 0,
    "NoOfExternalRef": 0,
    "IsHTTPS": 0,
    "HasObfuscation": 0,
    "HasTitle": 0,
    "HasDescription": 0,
    "HasSubmitButton": 0,
    "HasSocialNet": 0,
    "HasFavicon": 0,
    "HasCopyrightInfo": 0,
    "popUpWindow": 0,
    "Iframe": 0,
    "Abnormal_URL": 0,
    "LetterToDigitRatio": 1.0,
    "Redirect_0": 1,
    "Redirect_1": 0,
    "FetchFailed": 0,
    "DomainAgeDays": 0,
    "DomainAgeUnknown": 1,
}


def test_root_health_check():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "online"


def test_model_info_reports_25_features():
    response = client.get("/model-info")
    assert response.status_code == 200
    body = response.json()
    assert body["features"] == 25
    assert body["feature_names"] == list(VALID_FEATURES.keys())


def test_predict_with_valid_features_returns_full_result():
    response = client.post("/predict", json=VALID_FEATURES)
    assert response.status_code == 200

    body = response.json()
    assert body["result"] in ("Legitimate", "Phishing")
    assert 0 <= body["threat_score"] <= 100
    assert body["risk_level"] in ("LOW", "MEDIUM", "HIGH")
    assert len(body["explanations"]) <= 7


def test_predict_with_empty_features_does_not_crash():
    # Regression: the 3 domain-age / fetch features must always be
    # present, otherwise NaN sneaks into the model output and the
    # JSON response fails to serialize.
    response = client.post("/predict", json=EMPTY_FEATURES)
    assert response.status_code == 200


def test_predict_with_missing_field_returns_422():
    incomplete = VALID_FEATURES.copy()
    del incomplete["URLLength"]

    response = client.post("/predict", json=incomplete)
    assert response.status_code == 422


def test_predict_url_with_empty_url_returns_422():
    response = client.post("/predict_url", json={"url": "   "})
    assert response.status_code == 422


def test_predict_url_when_page_fetch_fails_still_returns_prediction():
    """
    A failed page fetch is a first-class feature (FetchFailed=1), not
    an error: the model was trained with it. The endpoint must return
    a coherent prediction with fetch_status surfacing the failure.
    """
    with patch("app.URLFeatureExtractor") as mock_extractor_cls:
        mock_instance = mock_extractor_cls.return_value
        mock_instance.page_fetch_failed = True
        mock_instance.page_fetch_error = "Website response timed out."
        mock_instance.extract_model_features.return_value = {
            **VALID_FEATURES,
            "FetchFailed": 1,
        }
        mock_instance.get_fetch_status.return_value = {
            "page_analyzed": False,
            "page_fetch_failed": True,
            "page_fetch_error": "Website response timed out.",
        }

        response = client.post(
            "/predict_url",
            json={"url": "https://example-unreachable-site.test"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["fetch_status"]["page_fetch_failed"] is True
    assert body["result"] in ("Legitimate", "Phishing")
    assert 0 <= body["threat_score"] <= 100


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
    assert body["features"] == VALID_FEATURES
    # explanations must reference only real model features
    for expl in body["explanations"]:
        assert expl["feature"] in VALID_FEATURES
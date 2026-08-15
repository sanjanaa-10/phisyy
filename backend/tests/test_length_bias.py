"""
Length-bias regression tests for the Phisyy phishing detector.

The core bug being guarded: the old model fed raw, unbounded URL
length into an XGBoost trained on a dataset where legitimate URLs
almost never exceeded ~58 characters. Result: a legitimate URL's
phishing risk climbed purely as the URL grew longer (the PhiUSIIL
distribution had "long URL => phishing" baked in).

The fix has three parts, all asserted here:

  1. URLLength is a categorical BUCKET (1..4), not a raw length.
  2. Trusted allowlisted domains are capped at bucket 2 so a long
     Google/Amazon/... URL is never penalized for length alone.
  3. The model output must not move when only the length bucket
     changes on an otherwise-clean legitimate vector.

These tests run against the saved model/scaler artifacts and never
touch the network. Run from backend/:  pytest tests/test_length_bias.py
"""

import joblib
import pandas as pd
import xgboost as xgb

from url_feature_extractor import (
    url_length_bucket,
    is_trusted_domain,
    get_registered_domain,
)

import json
import os

BACKEND = os.path.dirname(os.path.abspath(__file__))

scaler = joblib.load(os.path.join(BACKEND, "..", "scaler.pkl"))
booster = xgb.Booster()
booster.load_model(os.path.join(BACKEND, "..", "xgb_model.json"))

with open(
    os.path.join(BACKEND, "..", "feature_names.json"),
    encoding="utf-8",
) as f:
    FEATURE_COLUMNS = json.load(f)


# A clean, plausible legitimate vector (long-ish article page).
def _base_vector():
    return {
        "URLLength": 2,
        "DomainLength": 15,
        "TLDLength": 3,
        "NoOfImage": 1,
        "NoOfJS": 2,
        "NoOfCSS": 1,
        "NoOfSelfRef": 3,
        "NoOfExternalRef": 1,
        "IsHTTPS": 1,
        "HasObfuscation": 0,
        "HasTitle": 1,
        "HasDescription": 0,
        "HasSubmitButton": 0,
        "HasSocialNet": 0,
        "HasFavicon": 0,
        "HasCopyrightInfo": 0,
        "popUpWindow": 0,
        "Iframe": 0,
        "Abnormal_URL": 0,
        "LetterToDigitRatio": 5.0,
        "Redirect_0": 1,
        "Redirect_1": 0,
        "FetchFailed": 0,
        "DomainAgeDays": 3650,
        "DomainAgeUnknown": 0,
    }


def _score(vector):
    df = pd.DataFrame([vector], columns=FEATURE_COLUMNS)
    scaled = scaler.transform(df)
    dmatrix = xgb.DMatrix(scaled, feature_names=FEATURE_COLUMNS)
    legit_prob = float(booster.predict(dmatrix)[0])
    threat = round((1 - legit_prob) * 100, 1)
    return legit_prob, threat


# ============================================================
# 1. Bucketing
# ============================================================

def test_urllength_is_bucketed_not_raw():
    assert url_length_bucket("https://example.com", 19) == 1
    assert url_length_bucket("https://example.com", 45) == 1
    assert url_length_bucket("https://example.com", 46) == 2
    assert url_length_bucket("https://example.com", 90) == 2
    assert url_length_bucket("https://example.com", 91) == 3
    assert url_length_bucket("https://example.com", 140) == 3
    assert url_length_bucket("https://example.com", 141) == 4
    assert url_length_bucket("https://example.com", 500) == 4


def test_bucket_values_stay_in_small_range():
    for length in [0, 1, 20, 100, 200, 1000, 6000]:
        bucket = url_length_bucket("https://example.com", length)
        assert 1 <= bucket <= 4


# ============================================================
# 2. Trusted-domain dampening
# ============================================================

def test_trusted_domain_detection():
    assert is_trusted_domain("https://accounts.google.com/login?x=1")
    assert is_trusted_domain("https://www.amazon.com/s?k=headphones")
    assert is_trusted_domain("https://en.wikipedia.org/wiki/Phishing")
    assert is_trusted_domain("https://www.nytimes.com/2026/01/15/x.html")


def test_trusted_domain_is_not_typosquat():
    # A subdomain of a trusted brand is NOT trusted.
    assert not is_trusted_domain("https://paypal.com.attacker.net/login")
    assert not is_trusted_domain("https://accounts-g00gle.com/login")
    assert not is_trusted_domain("https://www.amazonn-security.com/ap")


def test_trusted_domain_caps_length_bucket_at_2():
    # Even a 400-char Google login redirect stays bucket 2.
    google = "https://accounts.google.com/ServiceLogin?x=" + "a" * 380
    assert url_length_bucket(google, len(google)) == 2

    # A non-trusted domain of the same length is bucket 4.
    evil = "https://accounts-g00gle.com/login?x=" + "a" * 380
    assert url_length_bucket(evil, len(evil)) == 4


# ============================================================
# 3. Model output must not move with length alone
# ============================================================

def test_score_unchanged_across_length_buckets():
    baseline = _score(_base_vector())
    for bucket in [1, 2, 3, 4]:
        v = _base_vector()
        v["URLLength"] = bucket
        legit_prob, threat = _score(v)
        # Length alone must not flip the prediction.
        assert abs(legit_prob - baseline[0]) < 0.05, (
            f"bucket={bucket} changed legit_prob "
            f"{baseline[0]:.4f} -> {legit_prob:.4f}"
        )


def test_legit_long_url_vector_scores_low():
    # Simulates a legitimate long article/product URL.
    v = _base_vector()
    v["URLLength"] = 2  # 46-90 chars, typical article permalink
    legit_prob, threat = _score(v)
    assert threat < 30, f"legit long URL scored threat={threat}"


def test_suspicious_young_domain_still_scores_high():
    # A young phishing-like domain must still be flagged even when
    # the URL is short and the page looks clean.
    v = _base_vector()
    v["DomainAgeDays"] = 5
    v["DomainAgeUnknown"] = 0
    legit_prob, threat = _score(v)
    assert threat >= 70, f"young-domain URL threat={threat}"


def test_registered_domain_helper():
    assert get_registered_domain("https://www.amazon.com/s") == "amazon.com"
    assert get_registered_domain("https://accounts.google.co.in/login") == "google.co.in"
    assert get_registered_domain("https://en.wikipedia.org/x") == "wikipedia.org"
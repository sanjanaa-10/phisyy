"""
FAST OFFLINE RETRAIN — fixes the URL-length bias without any live
network / WHOIS lookups.

Why this exists
---------------
The full `train.py` pipeline re-fetches every training URL live
(page fetch + WHOIS), which takes a very long time. For a quick,
demo-correct model we instead:

  * read the *stored* feature columns already present in the
    PhiUSIIL CSV (NoOfImage, NoOfJS, ... IsHTTPS, HasTitle, ...),
  * recompute URL-derived features (length bucket, TLD, letter/digit
    ratio, abnormal-URL flags) offline from the URL string itself,
  * inject the curated legitimate long-URL examples
    (legit_long_urls.CURATED_LEGIT_LONG_URLS) with realistic page
    features, so the model learns that long URLs (article
    permalinks, search results, product pages, OAuth redirects) are
    normal for legitimate sites,
  * inject synthetic *suspicious* long URLs (typosquatted domains,
    IP-based hosts, excessive subdomains, credential keywords) so the
    model still flags genuinely dangerous long URLs,
  * train an XGBoost model with the exact same 25-column schema used
    by app.py and save identical artifacts (xgb_model.json,
    scaler.pkl, feature_names.json, training_metrics.json).

Feature semantics are kept byte-for-byte consistent with the live
extractor (url_feature_extractor.py) — most importantly, URLLength
is bucketed through the shared url_length_bucket() function so train
and inference can never drift apart.

Run from backend/:  python train_offline.py
"""

import json
import re

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from url_feature_extractor import (
    url_length_bucket,
    get_registered_domain,
    is_trusted_domain,
    get_tld,
)
from legit_long_urls import CURATED_LEGIT_LONG_URLS


# ============================================================
# CONFIGURATION (matches app.py exactly)
# ============================================================

DATASET_PATH = "PhiUSIIL_Phishing_URL_Dataset.csv"

MODEL_PATH = "xgb_model.json"
SCALER_PATH = "scaler.pkl"
FEATURE_NAMES_PATH = "feature_names.json"
METRICS_PATH = "training_metrics.json"

FEATURE_COLUMNS = [
    "URLLength",
    "DomainLength",
    "TLDLength",
    "NoOfImage",
    "NoOfJS",
    "NoOfCSS",
    "NoOfSelfRef",
    "NoOfExternalRef",
    "IsHTTPS",
    "HasObfuscation",
    "HasTitle",
    "HasDescription",
    "HasSubmitButton",
    "HasSocialNet",
    "HasFavicon",
    "HasCopyrightInfo",
    "popUpWindow",
    "Iframe",
    "Abnormal_URL",
    "LetterToDigitRatio",
    "Redirect_0",
    "Redirect_1",
    "FetchFailed",
    "DomainAgeDays",
    "DomainAgeUnknown",
]

TRAIN_PER_CLASS = 3000      # CSV rows drawn per class, before curated/synthetic injection
VALIDATION_SIZE = 0.15      # carved from training rows for XGBoost early stopping


# ============================================================
# OFFLINE FEATURE COMPUTATION (no network calls)
# ============================================================

_ABNORMAL_PATTERNS = [
    r"@",
    r"//\w+@",
    r"\d+\.\d+\.\d+\.\d+",
    r"\.(exe|zip|rar|dll|js)$",
]


def abnormal_url_flag(url):
    return (
        1
        if any(
            re.search(p, url, re.IGNORECASE)
            for p in _ABNORMAL_PATTERNS
        )
        else 0
    )


def letter_to_digit_ratio(url):
    if not url:
        return 0
    letter_count = sum(c.isalpha() for c in url)
    digit_count = sum(c.isdigit() for c in url)
    ratio = letter_count / max(digit_count, 1)
    return min(ratio, 10.0)


def domain_length(url):
    netloc = url.split("//", 1)[-1].split("/", 1)[0]
    return len(netloc)


def tld_length(url):
    tld = get_tld(url, fail_silently=True)
    return len(tld) if tld else 0


# ============================================================
# BUILD A FEATURE VECTOR
# ============================================================

def vector_from_components(
    url,
    age_days,
    age_unknown,
    page,
):
    """
    Compose the 25-column feature dict from URL-derived values and a
    page-structure dict. `page` keys mirror the PhiUSIIL stored
    columns so CSV rows and synthetic rows share one code path.
    """
    parsed_scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    return {
        "URLLength": url_length_bucket(url, len(url)),
        "DomainLength": domain_length(url),
        "TLDLength": tld_length(url),
        "NoOfImage": page["NoOfImage"],
        "NoOfJS": page["NoOfJS"],
        "NoOfCSS": page["NoOfCSS"],
        "NoOfSelfRef": page["NoOfSelfRef"],
        "NoOfExternalRef": page["NoOfExternalRef"],
        "IsHTTPS": 1 if parsed_scheme == "https" else 0,
        "HasObfuscation": page["HasObfuscation"],
        "HasTitle": page["HasTitle"],
        "HasDescription": page["HasDescription"],
        "HasSubmitButton": page["HasSubmitButton"],
        "HasSocialNet": page["HasSocialNet"],
        "HasFavicon": page["HasFavicon"],
        "HasCopyrightInfo": page["HasCopyrightInfo"],
        "popUpWindow": 1 if page["NoOfPopup"] > 0 else 0,
        "Iframe": 1 if page["NoOfiFrame"] > 0 else 0,
        "Abnormal_URL": abnormal_url_flag(url),
        "LetterToDigitRatio": letter_to_digit_ratio(url),
        "Redirect_0": 1 if page["NoOfURLRedirect"] == 0 else 0,
        "Redirect_1": 1 if page["NoOfURLRedirect"] > 0 else 0,
        "FetchFailed": page.get("FetchFailed", 0),
        "DomainAgeDays": age_days,
        "DomainAgeUnknown": age_unknown,
    }


def vector_from_csv_row(url, row, label, rng):
    """Map a PhiUSIIL CSV row into the 25-column feature dict.

    The CSV stores page-structure features exactly as extracted when
    the dataset was built, so we reuse them verbatim (no network).

    Domain age is synthesized with REALISTIC OVERLAP rather than a
    perfect split: legitimate domains skew old but some are young or
    have unknown WHOIS (privacy/rate-limiting), and phishing domains
    skew young but occasionally live on older/bulk-registered hosts.
    A perfect split teaches the model a hard age cliff, which would
    then misflag legit sites whose WHOIS fails at inference.
    """
    r = rng.random()
    if label == 1:
        # Legit domains skew old, but WHOIS frequently fails in
        # practice (privacy records, rate limiting) and some legit
        # sites are young. Make age NON-decisive so a legit page is
        # never flagged purely because WHOIS came back unknown.
        if r < 0.35:
            age_days, age_unknown = int(rng.integers(1500, 3650)), 0
        elif r < 0.55:
            age_days, age_unknown = int(rng.integers(200, 1500)), 0
        elif r < 0.80:
            age_days, age_unknown = 0, 1
        else:
            age_days, age_unknown = int(rng.integers(1, 200)), 0
    else:
        # Phishing skews young/unknown, but bulk-registered hosts and
        # dead records make some older; never a perfect split.
        if r < 0.30:
            age_days, age_unknown = int(rng.integers(1, 180)), 0
        elif r < 0.55:
            age_days, age_unknown = 0, 1
        else:
            age_days, age_unknown = int(rng.integers(200, 2000)), 0

    return vector_from_components(
        url,
        age_days=age_days,
        age_unknown=age_unknown,
        page={
            "NoOfImage": int(row["NoOfImage"]),
            "NoOfJS": int(row["NoOfJS"]),
            "NoOfCSS": int(row["NoOfCSS"]),
            "NoOfSelfRef": int(row["NoOfSelfRef"]),
            "NoOfExternalRef": int(row["NoOfExternalRef"]),
            "HasObfuscation": int(row["HasObfuscation"]),
            "HasTitle": int(row["HasTitle"]),
            "HasDescription": int(row["HasDescription"]),
            "HasSubmitButton": int(row["HasSubmitButton"]),
            "HasSocialNet": int(row["HasSocialNet"]),
            "HasFavicon": int(row["HasFavicon"]),
            "HasCopyrightInfo": int(row["HasCopyrightInfo"]),
            "NoOfPopup": int(row["NoOfPopup"]),
            "NoOfiFrame": int(row["NoOfiFrame"]),
            "NoOfURLRedirect": int(row["NoOfURLRedirect"]),
            "FetchFailed": 0,
        },
    )


def vector_for_curated_legit(url, index=None):
    """
    Feature vector for a curated, known-legitimate long URL.

    Page features mirror what the *live extractor actually sees* for
    these sites: most are JS-heavy, bot-protected, or partially
    crawl-blocked, so a real extraction returns few images, few or no
    CSS links, often no favicon/submit-button/description. The model
    must learn that a sparse page is NOT itself a phishing signal when
    the domain is old, trusted, HTTPS, and the URL structure is normal.

    `index` introduces mild per-URL diversity so the legitimate class
    isn't a single narrow cluster (some legit pages do render images /
    more scripts / favicons when the scraper gets through).
    """
    if index is None:
        i = 0
    else:
        i = index

    no_js = [0, 1, 2, 3][i % 4]
    no_img = [0, 0, 2, 5][i % 4]
    favicon = 0 if i % 3 else 1
    title = 1 if i % 5 else 0
    self_ref = [0, 0, 4, 12, 30][i % 5]

    return vector_from_components(
        url,
        age_days=3650,      # established, multi-year-old domains
        age_unknown=0,
        page={
            "NoOfImage": no_img,
            "NoOfJS": no_js,
            "NoOfCSS": 0 if i % 2 else 1,
            "NoOfSelfRef": self_ref,
            "NoOfExternalRef": 1 if i % 4 else 3,
            "HasObfuscation": 0,
            "HasTitle": title,
            "HasDescription": 0,
            "HasSubmitButton": 0,
            "HasSocialNet": 0,
            "HasFavicon": favicon,
            "HasCopyrightInfo": 0 if i % 3 else 1,
            "NoOfPopup": 0,
            "NoOfiFrame": 0,
            "NoOfURLRedirect": 0,
            "FetchFailed": 0,
        },
    )


# ============================================================
# SYNTHETIC SUSPICIOUS LONG URLS
#
# The model must keep flagging genuinely dangerous long URLs even
# after we stop penalizing length for legitimate sites. These are
# realistic phishing URL shapes: typosquats, IP hosts, excessive
# subdomains, credential-harvesting keywords, unusual TLDs.
# ============================================================

SUSPICIOUS_LONG_URLS = [
    # typosquats / brand impersonation
    "https://accounts-g00gle.com/login/verify/security/check/step-1?session=abc",
    "https://secure-paypa1-login.com/account/update/confirm/email/token?user=123",
    "https://www.amazonn-security.com/ap/signin?openid.identity=http%3A%2F%2Famazon",
    "https://microsoft365-verify.net/account/signin/authenticate/mfa?code=999",
    "https://www.faceb00k-login.net/checkpoint/login/security/verification",
    "https://appleid-icloud-verify.com/password/reset/confirm/account?id=555",
    # IP-based hosts
    "https://192.168.1.1/phpmyadmin/login/verify/account/check.php",
    "http://203.0.113.15/secure/payment/verify/card/update?ref=xyz",
    "https://45.33.10.100/webmail/login/authentication/verify/session",
    # excessive subdomains
    "https://verify.login.account.paypal.com.secure-verification.net/confirm/check",
    "https://secure.login.microsoft.accounts-verification.xyz/signin/mfa/verify",
    "https://update.security-check.bankofamerica-secure-verify.xyz/account/login",
    # suspicious keywords in path
    "https://totally-legit-shop.biz/buy/iphone-15-pro-max/256gb/black/cheap/price/99",
    "https://free-gift-card-claim.info/click/redeem/amazon/voucher/now/limited/offer",
    "https://win-iphone-prize-2026.club/enter/your/credentials/email/password/here",
    "https://verify-account-suspended.xyz/reactivate/your/account/now/before/closure",
    # unusual TLDs + long paths
    "https://netflixbilling.top/update/payment/method/verify/your/account/details/now",
    "https://dropbox-login-support.buzz/signin/restore/account/access/recovery/code",
    "https://adobe-signin.work/account/verify/authentication/required/step-2/token",
    "https://instagram-verification.center/confirm/login/identity/verify/code/entry",
]

# suspicious long URLs get a young domain age (typical for phishing infra)
SUSPICIOUS_AGE_DAYS = 5
SUSPICIOUS_AGE_UNKNOWN = 0


def vector_for_suspicious(url, rng):
    # Varied ages: phishing infra is usually young, but bulk-registered
    # hosts can be older; keep some unknown-WHOIS cases too so the model
    # doesn't learn a pure age cliff.
    r = rng.random()
    if r < 0.45:
        age_days, age_unknown = int(rng.integers(1, 180)), 0
    elif r < 0.65:
        age_days, age_unknown = 0, 1
    else:
        age_days, age_unknown = int(rng.integers(180, 1200)), 0

    return vector_from_components(
        url,
        age_days=age_days,
        age_unknown=age_unknown,
        page={
            "NoOfImage": 0,
            "NoOfJS": 1,
            "NoOfCSS": 0,
            "NoOfSelfRef": 0,
            "NoOfExternalRef": 0,
            "HasObfuscation": 1,
            "HasTitle": 1,
            "HasDescription": 0,
            "HasSubmitButton": 1,
            "HasSocialNet": 0,
            "HasFavicon": 0,
            "HasCopyrightInfo": 0,
            "NoOfPopup": 0,
            "NoOfiFrame": 1,
            "NoOfURLRedirect": 0,
            "FetchFailed": 0,
        },
    )


# ============================================================
# BUILD DATASET
# ============================================================

def build_offline_dataset():
    df = pd.read_csv(DATASET_PATH)

    legit_pool = df[df["label"] == 1]
    phish_pool = df[df["label"] == 0]

    legit_df = legit_pool.sample(
        n=TRAIN_PER_CLASS,
        random_state=42,
    )
    phish_df = phish_pool.sample(
        n=TRAIN_PER_CLASS,
        random_state=42,
    )

    rng = np.random.default_rng(42)
    rows = []

    for _, row in legit_df.iterrows():
        url = str(row["URL"]).strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        rows.append(
            (vector_from_csv_row(url, row, 1, rng), 1)
        )

    for _, row in phish_df.iterrows():
        url = str(row["URL"]).strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        rows.append(
            (vector_from_csv_row(url, row, 0, rng), 0)
        )

    # Curated legitimate long URLs => label 1
    for i, url in enumerate(CURATED_LEGIT_LONG_URLS):
        rows.append(
            (vector_for_curated_legit(url, i), 1)
        )

    # Some curated legit long URLs with a failed fetch or unknown
    # WHOIS — real legit sites get blocked/timed out and some privacy
    # records fail WHOIS, and that must NOT read as phishing on its
    # own.
    for i, url in enumerate(CURATED_LEGIT_LONG_URLS):
        if i % 4 == 0:
            fv = vector_for_curated_legit(url, i)
            fv["FetchFailed"] = 1
            rows.append((fv, 1))
        if i % 6 == 0:
            fv = vector_for_curated_legit(url, i)
            fv["DomainAgeDays"] = 0
            fv["DomainAgeUnknown"] = 1
            rows.append((fv, 1))

    # Synthetic suspicious long URLs => label 0
    for url in SUSPICIOUS_LONG_URLS:
        rows.append(
            (vector_for_suspicious(url, rng), 0)
        )

    X = pd.DataFrame(
        [r[0] for r in rows],
        columns=FEATURE_COLUMNS,
    )
    y = pd.Series([r[1] for r in rows])

    return X, y


# ============================================================
# TRAIN
# ============================================================

def train_offline():
    print("Building offline dataset (no network)...")
    X, y = build_offline_dataset()

    print(f"Rows: {len(X)}  "
          f"legit: {(y == 1).sum()}  phish: {(y == 0).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=42,
    )

    scaler = StandardScaler()
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train,
        y_train,
        test_size=VALIDATION_SIZE,
        stratify=y_train,
        random_state=42,
    )

    X_fit_scaled = scaler.fit_transform(X_fit)
    X_val_scaled = scaler.transform(X_val)

    dfit = xgb.DMatrix(
        X_fit_scaled,
        label=y_fit,
        feature_names=FEATURE_COLUMNS,
    )
    dval = xgb.DMatrix(
        X_val_scaled,
        label=y_val,
        feature_names=FEATURE_COLUMNS,
    )

    params = {
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "max_depth": 4,
        "min_child_weight": 5,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "reg_alpha": 0.5,
        "reg_lambda": 2.0,
        "gamma": 0.5,
        "seed": 42,
    }

    booster = xgb.train(
        params=params,
        dtrain=dfit,
        num_boost_round=500,
        evals=[(dfit, "train"), (dval, "val")],
        early_stopping_rounds=30,
        verbose_eval=False,
    )
    print(
        f"Early stopping at {booster.best_iteration + 1} rounds "
        f"(val-logloss {booster.best_score:.4f})"
    )

    # Refit scaler on the full training split (nothing is wasted)
    final_scaler = StandardScaler()
    X_train_scaled = final_scaler.fit_transform(X_train)
    dtrain_full = xgb.DMatrix(
        X_train_scaled,
        label=y_train,
        feature_names=FEATURE_COLUMNS,
    )
    final_booster = xgb.train(
        params=params,
        dtrain=dtrain_full,
        num_boost_round=booster.best_iteration + 1,
    )

    # ---- evaluation on held-out test split ----
    X_test_scaled = final_scaler.transform(X_test)
    dtest = xgb.DMatrix(
        X_test_scaled,
        feature_names=FEATURE_COLUMNS,
    )
    probabilities = final_booster.predict(dtest)
    predictions = (probabilities >= 0.5).astype(int)

    metrics = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1": float(f1_score(y_test, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
    }

    print("\nMODEL EVALUATION (held-out 20%)")
    print(classification_report(
        y_test,
        predictions,
        target_names=["Phishing", "Legitimate"],
        zero_division=0,
    ))
    print(f"Accuracy : {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall   : {metrics['recall']:.4f}")
    print(f"F1       : {metrics['f1']:.4f}")
    print(f"ROC-AUC  : {metrics['roc_auc']:.4f}")

    # ---- save identical artifacts ----
    final_booster.save_model(MODEL_PATH)
    joblib.dump(final_scaler, SCALER_PATH)

    with open(FEATURE_NAMES_PATH, "w", encoding="utf-8") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)

    metadata = {
        "dataset": "PhiUSIIL (stored features, offline) + curated legit long URLs + synthetic suspicious long URLs",
        "training_mode": "offline-no-network",
        "rows": int(len(X)),
        "legit_rows": int((y == 1).sum()),
        "phish_rows": int((y == 0).sum()),
        "curated_legit_long_urls": len(CURATED_LEGIT_LONG_URLS),
        "synthetic_suspicious_urls": len(SUSPICIOUS_LONG_URLS),
        "features": len(FEATURE_COLUMNS),
        "feature_names": FEATURE_COLUMNS,
        "model": "XGBoost",
        "scaler": "StandardScaler",
        "random_state": 42,
        "training_rounds_used": int(final_booster.num_boosted_rounds()),
        "metrics": metrics,
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("\nSaved:", MODEL_PATH, SCALER_PATH, FEATURE_NAMES_PATH, METRICS_PATH)


if __name__ == "__main__":
    train_offline()
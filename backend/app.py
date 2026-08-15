import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import xgboost as xgb
import shap

from url_feature_extractor import URLFeatureExtractor


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="Phisyy Security API",
    description="ML-powered phishing URL detection API using XGBoost and SHAP",
    version="1.0.0",
)


# ============================================================
# CORS
#
# The extension calls this API directly (no cookies/session
# auth involved), so credentials are not needed and origins
# are restricted instead of wildcarded. Set PHISYY_ALLOWED_ORIGINS
# to your loaded extension's origin, e.g.:
#   chrome-extension://<your-extension-id>
# after loading the unpacked extension in chrome://extensions.
# ============================================================

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "PHISYY_ALLOWED_ORIGINS",
        "http://127.0.0.1:8000,http://localhost:8000",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ============================================================
# LOAD ML ARTIFACTS
# ============================================================

scaler = joblib.load("scaler.pkl")

booster = xgb.Booster()
booster.load_model("xgb_model.json")

# SHAP explainer for the trained XGBoost model
explainer = shap.TreeExplainer(
    booster,
    model_output="raw",
)


# ============================================================
# MODEL FEATURE ORDER
# ============================================================

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


# ============================================================
# REQUEST MODELS
# ============================================================

class URLFeatures(BaseModel):
    URLLength: int
    DomainLength: int
    TLDLength: int
    NoOfImage: int
    NoOfJS: int
    NoOfCSS: int
    NoOfSelfRef: int
    NoOfExternalRef: int
    IsHTTPS: int
    HasObfuscation: int
    HasTitle: int
    HasDescription: int
    HasSubmitButton: int
    HasSocialNet: int
    HasFavicon: int
    HasCopyrightInfo: int
    popUpWindow: int
    Iframe: int
    Abnormal_URL: int
    LetterToDigitRatio: float
    Redirect_0: int
    Redirect_1: int
    FetchFailed: int
    DomainAgeDays: int
    DomainAgeUnknown: int


class URLInput(BaseModel):
    url: str


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_prediction(prediction: float):
    """
    XGBoost binary:logistic model.

    Existing model convention:
        1 = Legitimate
        0 = Phishing

    Therefore:
        prediction = legitimate probability
        1 - prediction = phishing probability
    """

    legitimate_probability = prediction
    phishing_probability = 1.0 - prediction

    # Convert phishing probability into 0-100 threat score
    threat_score = round(
        phishing_probability * 100,
        1,
    )

    # Risk classification
    if threat_score >= 70:
        risk_level = "HIGH"
    elif threat_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Existing model threshold
    label = int(round(prediction))

    return {
        "prediction": label,
        "result": (
            "Legitimate"
            if label == 1
            else "Phishing"
        ),
        "legitimate_probability": round(
            legitimate_probability,
            4,
        ),
        "phishing_probability": round(
            phishing_probability,
            4,
        ),
        "threat_score": threat_score,
        "risk_level": risk_level,
    }


# ============================================================
# MODEL INFERENCE
# ============================================================

def run_model(features):
    """
    Convert extracted features into the exact representation
    expected by the original scaler and XGBoost model.
    """

    # Create dataframe in exact training feature order
    input_df = pd.DataFrame(
        [features],
        columns=FEATURE_COLUMNS,
    )

    # Apply original scaler
    scaled_input = scaler.transform(
        input_df,
    )

    # Create XGBoost DMatrix
    dmatrix = xgb.DMatrix(
        scaled_input,
        feature_names=FEATURE_COLUMNS,
    )

    # Generate model prediction
    prediction = float(
        booster.predict(dmatrix)[0]
    )

    return classify_prediction(
        prediction,
    )


# ============================================================
# SHAP EXPLAINABILITY
# ============================================================

def explain_prediction(features):
    """
    Generate SHAP feature contributions for the trained
    XGBoost model.

    Positive SHAP values push the model toward
    class 1 (Legitimate).

    Negative SHAP values push the model toward
    class 0 (Phishing).

    These explanations come from the trained model.
    They are not manually generated rules.
    """

    # Create dataframe in exact feature order
    input_df = pd.DataFrame(
        [features],
        columns=FEATURE_COLUMNS,
    )

    # Apply the same scaler used during inference
    scaled_input = scaler.transform(
        input_df,
    )

    # Calculate SHAP values
    shap_values = explainer.shap_values(
        scaled_input,
    )

    # Compatibility with different SHAP versions
    if isinstance(shap_values, list):
        shap_values = shap_values[0]

    values = shap_values[0]

    explanations = []

    # Create explanation for every feature
    for feature_name, feature_value, shap_value in zip(
        FEATURE_COLUMNS,
        input_df.iloc[0].values,
        values,
    ):
        impact = float(shap_value)

        # Model class convention:
        #
        # Positive = class 1 = Legitimate
        # Negative = class 0 = Phishing

        if impact < 0:
            direction = "phishing"
        else:
            direction = "legitimate"

        explanations.append(
            {
                "feature": feature_name,
                "value": float(feature_value),
                "impact": round(
                    impact,
                    6,
                ),
                "absolute_impact": round(
                    abs(impact),
                    6,
                ),
                "direction": direction,
            }
        )

    # Most influential features first
    explanations.sort(
        key=lambda item: item["absolute_impact"],
        reverse=True,
    )

    # Return top 7 model contributors
    return explanations[:7]


# ============================================================
# DIRECT FEATURE PREDICTION
# ============================================================

@app.post("/predict")
def predict(features: URLFeatures):

    try:

        # Convert Pydantic object to dictionary
        feature_dict = features.model_dump()

        # Run trained model
        model_result = run_model(
            feature_dict,
        )

        # Generate SHAP explanation
        explanations = explain_prediction(
            feature_dict,
        )

        # Return complete response
        return {
            "features": feature_dict,
            "explanations": explanations,
            **model_result,
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Model inference failed: {e}",
        )


# ============================================================
# RAW URL PREDICTION
# ============================================================

@app.post("/predict_url")
def predict_from_url(
    input_data: URLInput,
):

    try:

        # ----------------------------------------------------
        # Validate URL
        # ----------------------------------------------------

        url = input_data.url.strip()

        if not url:
            raise HTTPException(
                status_code=422,
                detail="URL cannot be empty.",
            )

        # Add HTTPS if protocol is missing
        if not url.startswith(
            ("http://", "https://")
        ):
            url = "https://" + url

        # ----------------------------------------------------
        # Extract webpage + URL features
        # ----------------------------------------------------

        extractor = URLFeatureExtractor(
            url,
        )

        # A failed page fetch is no longer treated as "can't score
        # this" - the retrained model was trained with FetchFailed
        # as an explicit feature, since a dead/blocked/timed-out
        # page is itself a meaningful signal (phishing infrastructure
        # fails to load far more often than legitimate sites). We
        # still surface the fetch status in the response so the user
        # knows the page didn't actually load.
        features = (
            extractor.extract_model_features()
        )

        fetch_status = extractor.get_fetch_status()

        # ----------------------------------------------------
        # Run trained XGBoost model
        # ----------------------------------------------------

        model_result = run_model(
            features,
        )

        # ----------------------------------------------------
        # Generate SHAP explanations
        # ----------------------------------------------------

        explanations = explain_prediction(
            features,
        )

        # ----------------------------------------------------
        # API response
        # ----------------------------------------------------

        return {
            "url": url,
            "features": features,
            "explanations": explanations,
            "fetch_status": fetch_status,
            **model_result,
        }

    except HTTPException:
        # Already has the right status code (422 above) — just re-raise.
        raise

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Model inference failed: {e}",
        )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def read_root():

    return {
        "message": "Phisyy Security API is running",
        "model": "XGBoost",
        "features": len(FEATURE_COLUMNS),
        "explainability": "SHAP",
        "status": "online",
    }


# ============================================================
# MODEL INFORMATION
# ============================================================

@app.get("/model-info")
def model_info():

    return {
        "model": "XGBoost",
        "objective": "binary:logistic",
        "trees": 200,
        "features": len(FEATURE_COLUMNS),
        "feature_names": FEATURE_COLUMNS,
        "scaler": "StandardScaler",
        "explainability": "SHAP TreeExplainer",
        "status": "loaded",
    }
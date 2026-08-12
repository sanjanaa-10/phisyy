import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import joblib
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

from url_feature_extractor import URLFeatureExtractor


# ============================================================
# CONFIGURATION
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
]


# ============================================================
# EXTRACT FEATURES FROM ONE URL
# ============================================================

def extract_features(row):

    url = str(row["URL"]).strip()
    label = int(row["label"])

    if not url:
        return {
            "success": False,
            "label": label,
            "reason": "empty_url",
        }

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:

        extractor = URLFeatureExtractor(url)

        if extractor.page_fetch_failed:
            return {
                "success": False,
                "label": label,
                "url": url,
                "reason": extractor.page_fetch_error,
            }

        features = extractor.extract_model_features()

        return {
            "success": True,
            "label": label,
            "url": url,
            "features": features,
        }

    except Exception as exc:

        return {
            "success": False,
            "label": label,
            "url": url,
            "reason": str(exc),
        }


# ============================================================
# EXTRACT FEATURES FROM DATASET
# ============================================================

def build_feature_dataset(df, workers=8):

    results = []

    print(
        f"\nExtracting features from "
        f"{len(df)} URLs..."
    )

    print(f"Workers: {workers}\n")

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = [
            executor.submit(
                extract_features,
                row
            )
            for _, row in df.iterrows()
        ]

        for index, future in enumerate(
            as_completed(futures),
            start=1
        ):

            result = future.result()

            results.append(result)

            successful_count = sum(
                result["success"]
                for result in results
            )

            if index % 50 == 0:

                print(
                    f"Processed "
                    f"{index}/{len(futures)} | "
                    f"Successful: "
                    f"{successful_count}"
                )

    # --------------------------------------------------------
    # SUCCESS / FAILURE STATISTICS
    # --------------------------------------------------------

    successful = [
        result
        for result in results
        if result["success"]
    ]

    failed = [
        result
        for result in results
        if not result["success"]
    ]

    attempted_by_label = (
        df["label"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    successful_by_label = (
        pd.Series(
            [
                result["label"]
                for result in successful
            ]
        )
        .value_counts()
        .sort_index()
        .to_dict()
    )

    failed_by_label = (
        pd.Series(
            [
                result["label"]
                for result in failed
            ]
        )
        .value_counts()
        .sort_index()
        .to_dict()
    )

    for label in [0, 1]:

        attempted_by_label.setdefault(
            label,
            0
        )

        successful_by_label.setdefault(
            label,
            0
        )

        failed_by_label.setdefault(
            label,
            0
        )

    print("\n==============================")
    print("FETCH STATISTICS")
    print("==============================")

    print(
        "\n                 "
        "Attempted   Successful   Failed"
    )

    print(
        f"Legitimate       "
        f"{attempted_by_label[1]:9d}   "
        f"{successful_by_label[1]:10d}   "
        f"{failed_by_label[1]:6d}"
    )

    print(
        f"Phishing         "
        f"{attempted_by_label[0]:9d}   "
        f"{successful_by_label[0]:10d}   "
        f"{failed_by_label[0]:6d}"
    )

    print(
        f"Total            "
        f"{len(df):9d}   "
        f"{len(successful):10d}   "
        f"{len(failed):6d}"
    )

    if not successful:

        raise RuntimeError(
            "No URLs were successfully processed."
        )

    return successful, {
        "attempted": len(df),
        "successful": len(successful),
        "failed": len(failed),
        "attempted_by_label": {
            "phishing": attempted_by_label[0],
            "legitimate": attempted_by_label[1],
        },
        "successful_by_label": {
            "phishing": successful_by_label[0],
            "legitimate": successful_by_label[1],
        },
        "failed_by_label": {
            "phishing": failed_by_label[0],
            "legitimate": failed_by_label[1],
        },
    }


# ============================================================
# BALANCE SUCCESSFUL DATA
# ============================================================

def balance_successful_results(results):

    phishing = [
        result
        for result in results
        if result["label"] == 0
    ]

    legitimate = [
        result
        for result in results
        if result["label"] == 1
    ]

    print("\n==============================")
    print("BEFORE BALANCING")
    print("==============================")

    print(
        f"Phishing successful:   "
        f"{len(phishing)}"
    )

    print(
        f"Legitimate successful: "
        f"{len(legitimate)}"
    )

    target_count = min(
        len(phishing),
        len(legitimate)
    )

    if target_count == 0:

        raise RuntimeError(
            "Only one class was successfully "
            "extracted. Cannot train a binary model."
        )

    # Deterministic selection.
    phishing = phishing[:target_count]
    legitimate = legitimate[:target_count]

    balanced = phishing + legitimate

    balanced_df = pd.DataFrame(
        [
            {
                "features": result["features"],
                "label": result["label"],
            }
            for result in balanced
        ]
    )

    balanced_df = balanced_df.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    print("\n==============================")
    print("AFTER BALANCING")
    print("==============================")

    print(
        f"Phishing:   {target_count}"
    )

    print(
        f"Legitimate: {target_count}"
    )

    print(
        f"Total:      {len(balanced_df)}"
    )

    X = pd.DataFrame(
        balanced_df["features"].tolist(),
        columns=FEATURE_COLUMNS
    )

    y = balanced_df["label"]

    return X, y


# ============================================================
# TRAIN XGBOOST
# ============================================================

def train_model(X_train, y_train):

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    dtrain = xgb.DMatrix(
        X_train_scaled,
        label=y_train,
        feature_names=FEATURE_COLUMNS,
    )

    params = {
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "max_depth": 6,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "seed": 42,
    }

    booster = xgb.train(
        params=params,
        dtrain=dtrain,
        num_boost_round=200,
    )

    return booster, scaler


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(
    booster,
    scaler,
    X_test,
    y_test
):

    X_test_scaled = scaler.transform(
        X_test
    )

    dtest = xgb.DMatrix(
        X_test_scaled,
        feature_names=FEATURE_COLUMNS,
    )

    probabilities = booster.predict(
        dtest
    )

    predictions = (
        probabilities >= 0.5
    ).astype(int)

    metrics = {

        "accuracy": float(
            accuracy_score(
                y_test,
                predictions
            )
        ),

        "precision": float(
            precision_score(
                y_test,
                predictions,
                zero_division=0
            )
        ),

        "recall": float(
            recall_score(
                y_test,
                predictions,
                zero_division=0
            )
        ),

        "f1": float(
            f1_score(
                y_test,
                predictions,
                zero_division=0
            )
        ),

        "roc_auc": float(
            roc_auc_score(
                y_test,
                probabilities
            )
        ),

        "confusion_matrix":
            confusion_matrix(
                y_test,
                predictions
            ).tolist()
    }

    print("\n==============================")
    print("MODEL EVALUATION")
    print("==============================")

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Phishing",
                "Legitimate"
            ],
            zero_division=0
        )
    )

    print(
        "Accuracy :",
        metrics["accuracy"]
    )

    print(
        "Precision:",
        metrics["precision"]
    )

    print(
        "Recall   :",
        metrics["recall"]
    )

    print(
        "F1       :",
        metrics["f1"]
    )

    print(
        "ROC-AUC  :",
        metrics["roc_auc"]
    )

    print(
        "\nConfusion Matrix:"
    )

    print(
        metrics["confusion_matrix"]
    )

    return metrics


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--sample-size",
        type=int,
        default=500,
        help=(
            "Number of candidate URLs to "
            "process."
        ),
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help=(
            "Number of concurrent URL "
            "fetch workers."
        ),
    )

    args = parser.parse_args()

    print("==============================")
    print("PHISYY MODEL TRAINING")
    print("==============================")

    # --------------------------------------------------------
    # LOAD DATASET
    # --------------------------------------------------------

    print(
        "\nLoading PhiUSIIL dataset..."
    )

    df = pd.read_csv(
        DATASET_PATH
    )

    print(
        f"Total dataset rows: "
        f"{len(df)}"
    )

    required_columns = {
        "URL",
        "label"
    }

    missing = (
        required_columns
        - set(df.columns)
    )

    if missing:

        raise ValueError(
            f"Missing required columns: "
            f"{missing}"
        )

    # --------------------------------------------------------
    # BALANCED CANDIDATE SAMPLE
    # --------------------------------------------------------

    per_class = args.sample_size // 2

    legitimate_df = df[
        df["label"] == 1
    ].sample(
        n=per_class,
        random_state=42
    )

    phishing_df = df[
        df["label"] == 0
    ].sample(
        n=per_class,
        random_state=42
    )

    sample_df = pd.concat(
        [
            legitimate_df,
            phishing_df
        ]
    )

    sample_df = sample_df.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    print(
        f"URLs selected for "
        f"feature extraction: "
        f"{len(sample_df)}"
    )

    print(
        "\nCandidate label distribution:"
    )

    print(
        sample_df["label"]
        .value_counts()
    )

    # --------------------------------------------------------
    # FEATURE EXTRACTION
    # --------------------------------------------------------

    successful_results, fetch_stats = (
        build_feature_dataset(
            sample_df,
            workers=args.workers
        )
    )

    # --------------------------------------------------------
    # BALANCE SUCCESSFUL DATA
    # --------------------------------------------------------

    X, y = balance_successful_results(
        successful_results
    )

    print(
        "\nSuccessfully extracted:"
    )

    print(
        f"Features: {X.shape}"
    )

    print(
        f"Labels:   {y.shape}"
    )

    print(
        "\nFeature columns:"
    )

    print(
        X.columns.tolist()
    )

    # --------------------------------------------------------
    # TRAIN / TEST SPLIT
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.2,
            stratify=y,
            random_state=42
        )
    )

    print(
        "\nTrain size:",
        len(X_train)
    )

    print(
        "Test size :",
        len(X_test)
    )

    # --------------------------------------------------------
    # TRAIN
    # --------------------------------------------------------

    print(
        "\nTraining XGBoost..."
    )

    booster, scaler = train_model(
        X_train,
        y_train
    )

    # --------------------------------------------------------
    # EVALUATE
    # --------------------------------------------------------

    metrics = evaluate_model(
        booster,
        scaler,
        X_test,
        y_test
    )

    # --------------------------------------------------------
    # SAVE MODEL
    # --------------------------------------------------------

    booster.save_model(
        MODEL_PATH
    )

    joblib.dump(
        scaler,
        SCALER_PATH
    )

    with open(
        FEATURE_NAMES_PATH,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            FEATURE_COLUMNS,
            file,
            indent=2
        )

    # --------------------------------------------------------
    # SAVE METADATA
    # --------------------------------------------------------

    training_metadata = {

        "dataset": "PhiUSIIL",

        "candidate_sample_size":
            len(sample_df),

        "successful_samples":
            fetch_stats["successful"],

        "failed_samples":
            fetch_stats["failed"],

        "balanced_training_samples":
            len(X),

        "features":
            len(FEATURE_COLUMNS),

        "feature_names":
            FEATURE_COLUMNS,

        "model":
            "XGBoost",

        "scaler":
            "StandardScaler",

        "random_state":
            42,

        "fetch_statistics":
            fetch_stats,

        "metrics":
            metrics
    }

    with open(
        METRICS_PATH,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            training_metadata,
            file,
            indent=2
        )

    print(
        "\n=============================="
    )

    print(
        "TRAINING COMPLETE"
    )

    print(
        "=============================="
    )

    print(
        f"Saved: {MODEL_PATH}"
    )

    print(
        f"Saved: {SCALER_PATH}"
    )

    print(
        f"Saved: {FEATURE_NAMES_PATH}"
    )

    print(
        f"Saved: {METRICS_PATH}"
    )


if __name__ == "__main__":
    main()
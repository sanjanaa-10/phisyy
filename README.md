# Phisyy

**ML-Powered Browser Phishing Detection Extension**

Phisyy is a Chrome extension that analyzes websites and uses machine learning to identify potentially phishing or suspicious pages. It combines custom URL/webpage feature extraction, an XGBoost classifier, FastAPI inference, and SHAP explainability.

## Highlights

- Real-time website risk analysis from a Chrome extension
- XGBoost phishing classification
- Custom 22-feature extraction pipeline
- Same `URLFeatureExtractor` used for training and inference
- Threat score with LOW / MEDIUM / HIGH risk levels
- SHAP-based prediction explanations
- FastAPI backend for model inference
- Automated backend tests with Pytest
- Reproducible training using the PhiUSIIL Phishing URL Dataset

## Architecture

```text
Chrome Extension
       |
       v
Website / URL Feature Extraction
       |
       v
22 Production Features
       |
       v
FastAPI Backend
       |
       v
StandardScaler
       |
       v
XGBoost Model
       |
       +------------------+
       |                  |
       v                  v
Phishing Probability   Legitimate Probability
       |
       v
Threat Score
       |
       v
Risk Classification
       |
       v
SHAP Explanation
       |
       v
Browser Dashboard
```

## Machine Learning

The project uses the **PhiUSIIL Phishing URL Dataset** as the source of labeled URLs.

Rather than directly training on the dataset's precomputed feature columns, Phisyy re-extracts features from raw URLs using its own `URLFeatureExtractor`.

This keeps the training pipeline aligned with the feature extraction logic used by the application and reduces train/serve feature skew.

### Production Feature Set

The model uses 22 features:

- URLLength
- DomainLength
- TLDLength
- NoOfImage
- NoOfJS
- NoOfCSS
- NoOfSelfRef
- NoOfExternalRef
- IsHTTPS
- HasObfuscation
- HasTitle
- HasDescription
- HasSubmitButton
- HasSocialNet
- HasFavicon
- HasCopyrightInfo
- popUpWindow
- Iframe
- Abnormal_URL
- LetterToDigitRatio
- Redirect_0
- Redirect_1

## Training Experiment

A balanced 5,000-URL candidate sample was used.

| Class | Attempted | Successfully Extracted |
|---|---:|---:|
| Legitimate | 2,500 | 2,254 |
| Phishing | 2,500 | 1,317 |

After successful feature extraction, the classes were balanced:

```text
1,317 phishing
1,317 legitimate
2,634 usable samples
```

The data was split using an 80/20 stratified train/test split:

```text
Training: 2,107
Testing:    527
```

### Evaluation

| Metric | Result |
|---|---:|
| Accuracy | 98.48% |
| Precision | 97.75% |
| Recall | 99.24% |
| F1 Score | 98.49% |
| ROC-AUC | 99.85% |

These results describe this specific training experiment and are not a guarantee of real-world phishing detection performance.

### Important Limitation

Some historical URLs in the dataset are no longer reachable during live feature extraction.

In the 5,000-URL experiment:

```text
Legitimate extraction success: 90.2%
Phishing extraction success:   52.7%
```

The final evaluation therefore applies to the successfully extracted and class-balanced subset.

## Explainable AI

Phisyy uses **SHAP** to provide feature-level explanations for individual predictions.

Instead of returning only a phishing/legitimate classification, the system can expose the security signals that contributed to the prediction.

## Risk Scoring

The phishing probability is converted into a user-facing threat score:

| Score | Risk |
|---:|---|
| 0–29 | LOW |
| 30–69 | MEDIUM |
| 70–100 | HIGH |

The score is a model-based security signal, not a definitive security verdict.

## Tech Stack

**Frontend**
- JavaScript
- HTML
- CSS
- Chrome Extension Manifest V3

**Backend**
- Python
- FastAPI
- Uvicorn
- Pydantic

**Machine Learning**
- XGBoost
- Scikit-learn
- SHAP
- Pandas
- Joblib

**Testing**
- Pytest

## Project Structure

```text
Phisyy/
├── backend/
│   ├── app.py
│   ├── train.py
│   ├── url_feature_extractor.py
│   ├── xgb_model.json
│   ├── scaler.pkl
│   ├── feature_names.json
│   ├── training_metrics.json
│   ├── requirements.txt
│   └── tests/
│       └── test_app.py
│
├── frontend/
│   ├── manifest.json
│   ├── background.js
│   ├── popup.html
│   ├── popup.js
│   ├── styles.css
│   └── icons/
│
├── docs/
│   └── demo.png
│
└── README.md
```

## Run Locally

### 1. Install backend dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Start FastAPI

```bash
python -m uvicorn app:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

### 3. Load the Chrome Extension

Open:

```text
chrome://extensions/
```

Enable **Developer mode** → **Load unpacked** → select:

```text
Phisyy/frontend
```

### 4. Test the Extension

1. Open a website in Chrome.
2. Click the Phisyy extension.
3. Run the analysis.
4. Review the risk score and classification.
5. Inspect the security signals and SHAP explanation.

## Train the Model

The training script is:

```text
backend/train.py
```

Place the PhiUSIIL dataset at:

```text
backend/PhiUSIIL_Phishing_URL_Dataset.csv
```

Small test:

```bash
python train.py --sample-size 500
```

Main experiment:

```bash
python train.py --sample-size 5000
```

Generated model artifacts:

```text
xgb_model.json
scaler.pkl
feature_names.json
training_metrics.json
```

## Testing

Run:

```bash
cd backend
python -m pytest
```

Current result:

```text
6 passed
```

## Security Note

Phisyy is a machine-learning-assisted security tool. A LOW-risk result does not guarantee that a website is safe, and a HIGH-risk result does not independently prove malicious intent.

The project is intended for educational, research, and demonstration purposes.

## Future Improvements

- Cloud-hosted FastAPI inference
- Continuous model retraining
- Larger and newer phishing datasets
- Threat-intelligence integration
- Production monitoring
- Model performance monitoring
- Additional domain and webpage features
- Chrome Web Store deployment
- API authentication and rate limiting

## Author

**Sanjana V Hathwar**

GitHub: https://github.com/sanjanaa-10

Repository: https://github.com/sanjanaa-10/phisyy

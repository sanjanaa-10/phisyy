# Phisyy

## ML-Powered Browser Phishing Detection Extension

[![Backend CI](https://github.com/sanjanaa-10/phisyy/actions/workflows/ci.yml/badge.svg)](https://github.com/sanjanaa-10/phisyy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Phisyy is a Chrome browser security extension that analyzes websites in real time and identifies potentially suspicious or phishing pages using machine learning.

The system combines an XGBoost classification model, URL and webpage-derived security features, a FastAPI inference backend, and SHAP-based explainability to provide an interpretable website risk assessment directly inside the browser.

---

## Demo

<!--
  Add a screenshot or short GIF of the popup dashboard here, e.g.:
  ![Phisyy popup showing risk level, threat score, and security signals](docs/demo.png)

  Quick way to capture one:
  1. Load the extension (see "Chrome Extension Setup" below) and run the backend.
  2. Open any site, click the Phisyy icon, and screenshot the popup once results load.
  3. Save the image as docs/demo.png (or demo.gif for a short click-through) and
     replace this comment with the markdown image line above.
-->

---

## Overview

Phishing websites are designed to appear similar to legitimate websites and can be difficult for users to identify through visual inspection alone.

Phisyy approaches phishing detection as a machine-learning classification problem. It extracts security-related characteristics from the current website, processes them through a trained XGBoost model, and converts the prediction into a risk assessment.

The extension provides:

- Website risk classification
- Phishing probability
- Legitimate probability
- Threat score
- Security signals
- SHAP-based explainability
- Recent scan history
- Browser security notifications

---

## Problem Statement

Users frequently encounter websites that may look legitimate while containing characteristics associated with phishing or suspicious behavior.

A practical phishing detection system should be able to:

1. Analyze characteristics of the current website.
2. Identify potentially suspicious patterns.
3. Produce an understandable risk assessment.
4. Provide supporting security signals.
5. Present the result directly inside the browser.

Phisyy addresses these requirements through a Chrome extension connected to a machine-learning inference backend.

---

## Solution

Phisyy consists of two primary components.

### Browser Extension

The Chrome extension is responsible for:

- Identifying the active website.
- Collecting relevant URL and webpage information.
- Communicating with the backend API.
- Displaying the prediction.
- Displaying security signals.
- Maintaining recent scan information.
- Providing browser security notifications.

### Machine Learning Backend

The FastAPI backend is responsible for:

- Receiving website security features.
- Processing the feature vector.
- Applying the trained feature scaler.
- Performing XGBoost inference.
- Calculating prediction probabilities.
- Generating a threat score.
- Producing SHAP-based explanation information.

---

# Key Features

## Real-Time Website Analysis

Phisyy analyzes the currently opened website and generates a phishing risk assessment through the browser extension.

## Machine Learning Classification

The backend uses an XGBoost binary classification model to distinguish between legitimate and potentially phishing websites.

## 22 Security Features

The system uses URL and webpage-derived security characteristics including:

- URL length
- Domain length
- TLD length
- Number of images
- Number of JavaScript files
- Number of CSS files
- Self references
- External references
- HTTPS usage
- URL obfuscation
- Page title
- Page description
- Submit buttons
- Social network indicators
- Favicon
- Copyright information
- Popup windows
- Iframes
- Abnormal URL indicators
- Letter-to-digit ratio
- Redirect indicators

These features are extracted and arranged according to the model's expected feature order before inference.

## Threat Scoring

The phishing probability is converted into a threat score between 0 and 100.

| Threat Score | Risk Level |
|---:|---|
| 0–29 | LOW |
| 30–69 | MEDIUM |
| 70–100 | HIGH |

The score is intended to provide an easy-to-understand indication of the model's phishing prediction.

## Explainable AI

Phisyy integrates SHAP-based explainability to provide information about the security signals influencing individual predictions.

This makes the system more interpretable than presenting only a phishing or legitimate label.

## Security Dashboard

The browser popup displays:

- Current website
- Risk level
- Threat score
- Legitimate probability
- Phishing probability
- Security signals
- Recent scans

## Browser Security Notifications

The extension can display browser notifications when a suspicious website is detected, allowing the user to review the assessment.

---

# System Architecture

```text
                    Chrome Browser
                          |
                          v
              +-----------------------+
              |   Phisyy Extension    |
              |                       |
              | Popup + Background    |
              | Security Monitoring   |
              +-----------+-----------+
                          |
                          v
              +-----------------------+
              | Feature Extraction    |
              |                       |
              | URL + Webpage Data    |
              +-----------+-----------+
                          |
                          v
              +-----------------------+
              |     FastAPI API       |
              |                       |
              |  Model Inference      |
              +-----------+-----------+
                          |
                          v
              +-----------------------+
              |    XGBoost Model      |
              |                       |
              | Phishing Prediction   |
              +-----------+-----------+
                          |
                          v
              +-----------------------+
              |  SHAP Explainability  |
              |                       |
              | Security Signals      |
              +-----------+-----------+
                          |
                          v
              +-----------------------+
              |   Risk Assessment     |
              |                       |
              | LOW / MEDIUM / HIGH   |
              +-----------------------+
```

---

# Machine Learning Pipeline

```text
Website
   |
   v
Feature Extraction
   |
   v
22 Security Features
   |
   v
Feature Scaling
   |
   v
XGBoost Classification
   |
   +-------------------+
   |                   |
   v                   v
Legitimate          Phishing
Probability         Probability
   |                   |
   +---------+---------+
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

---

# How the System Works

## Step 1: Website Identification

The browser extension identifies the currently active website.

## Step 2: Feature Extraction

URL and webpage-derived security characteristics are collected from the current website.

## Step 3: Feature Processing

The extracted values are arranged according to the model's expected feature order.

The stored scaler is then applied to prepare the feature vector for model inference.

## Step 4: Model Inference

The processed feature vector is passed to the trained XGBoost classifier.

## Step 5: Probability Calculation

The model generates class probabilities representing the predicted likelihood of the website belonging to each class.

## Step 6: Threat Score

The phishing probability is converted into a threat score between 0 and 100.

## Step 7: Risk Classification

The threat score is mapped to one of three risk levels:

```text
0–29     LOW
30–69    MEDIUM
70–100   HIGH
```

## Step 8: Explainability

SHAP is used to provide information about the security signals influencing the prediction.

## Step 9: Browser Presentation

The final assessment is returned to the browser extension and displayed through the Phisyy interface.

---

# Technology Stack

## Browser Extension

- JavaScript
- HTML
- CSS
- Chrome Extension API
- Manifest V3

## Backend

- Python
- FastAPI
- Pydantic

## Machine Learning

- XGBoost
- Scikit-learn
- SHAP
- Joblib
- Pandas

## Development Tools

- Git
- GitHub
- Chrome Developer Tools

---

# Project Structure

```text
Phisyy/
|
+-- backend/
|   +-- app.py
|   +-- url_feature_extractor.py
|   +-- xgb_model.json
|   +-- scaler.pkl
|   +-- requirements.txt
|
+-- Frontend/
|   +-- manifest.json
|   +-- background.js
|   +-- popup.html
|   +-- popup.js
|   +-- styles.css
|
+-- README.md
+-- .gitignore
```

---

# Installation

## Prerequisites

Make sure the following are installed:

- Google Chrome
- Python 3.x
- Git

---

## 1. Clone the Repository

Open PowerShell or Terminal:

```bash
git clone https://github.com/sanjanaa-10/phisyy.git
cd phisyy
```

---

## 2. Install Backend Dependencies

Navigate to the backend directory:

```bash
cd backend
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

---

## 3. Start the Backend

Run the FastAPI application:

```bash
python -m uvicorn app:app --port 8000
```

The backend should start at:

```text
http://127.0.0.1:8000
```

You should see a message similar to:

```text
Uvicorn running on http://127.0.0.1:8000
```

Keep this terminal running while using the extension.

---

# Chrome Extension Setup

## 1. Open Chrome Extensions

Open Google Chrome and navigate to:

```text
chrome://extensions
```

## 2. Enable Developer Mode

Turn on:

```text
Developer mode
```

## 3. Load the Extension

Select:

```text
Load unpacked
```

Navigate to the cloned Phisyy project and select:

```text
Phisyy/Frontend
```

Important:

Select the `Frontend` directory, not the main `Phisyy` directory.

The project should contain:

```text
Phisyy/
|
+-- backend/
|
+-- Frontend/
```

## 4. Pin Phisyy

Open the Chrome Extensions menu and pin Phisyy to the browser toolbar.

---

# Usage

## 1. Start the Backend

Make sure the FastAPI backend is running:

```text
http://127.0.0.1:8000
```

## 2. Open a Website

Navigate to a website in Chrome.

## 3. Open Phisyy

Click the Phisyy extension icon from the Chrome toolbar.

## 4. Wait for Analysis

Phisyy analyzes the website and sends the extracted information to the local ML backend.

## 5. Review the Result

The popup displays:

- Risk level
- Threat score
- Legitimate probability
- Phishing probability
- Security signals
- Recent scan information

---

# Quick Test

The basic workflow is:

```text
Start FastAPI Backend
        |
        v
Open Chrome
        |
        v
Load Phisyy Extension
        |
        v
Open a Website
        |
        v
Click Phisyy
        |
        v
Website Analysis
        |
        v
Risk Assessment
        |
        v
Review Security Signals
```

---

# Example Output

```text
PHISYY

Current Website
https://example.com

MEDIUM RISK

Threat Score
50.2 / 100

Legitimate Probability
49.8%

Phishing Probability
50.2%

Security Signals
HTTPS connection
Long URL
External references
```

The values shown above are an example of the interface format and are not claimed model performance metrics.

---

# Backend API

The backend is implemented using FastAPI and provides the inference layer used by the browser extension.

The local API runs at:

```text
http://127.0.0.1:8000
```

The backend accepts processed website security information and returns the model's prediction and associated risk information.

The inference pipeline includes:

```text
Input Features
      |
      v
Feature Validation
      |
      v
Feature Scaling
      |
      v
XGBoost Prediction
      |
      v
Prediction Probabilities
      |
      v
Threat Score
      |
      v
Risk Classification
      |
      v
Explainability
```

---

# Risk Assessment

Phisyy uses the phishing probability to calculate a threat score.

The current risk mapping is:

| Score Range | Classification |
|---:|---|
| 0–29 | LOW |
| 30–69 | MEDIUM |
| 70–100 | HIGH |

The risk classification is designed as a user-facing interpretation of the model output.

It should not be interpreted as a guarantee that a website is safe or malicious.

---

# Explainability

A key component of Phisyy is the use of SHAP-based explainability.

Instead of returning only:

```text
PHISHING
```

the system can provide information about the security signals associated with the prediction.

This allows the system to communicate not only the classification but also supporting information about the model decision.

The explainability layer is intended to make the machine-learning output easier for users and developers to interpret.

---

# Security Approach

Phisyy combines multiple website characteristics rather than relying on a single indicator.

The project demonstrates the integration of:

- Machine Learning
- Cybersecurity
- Feature Engineering
- Explainable AI
- Browser Extension Development
- REST API Development
- Real-Time Threat Analysis
- Model Inference
- Risk Scoring

---

# Limitations

Phisyy has several limitations that should be considered.

### Model Dependency

The quality of predictions depends on the trained model and the characteristics represented by its training data.

### False Positives and False Negatives

Machine-learning classification can produce incorrect predictions.

### Local Backend

The current implementation requires the FastAPI backend to be running locally.

### No Guaranteed Detection

A low-risk result does not guarantee that a website is safe, and a high-risk result does not by itself prove malicious intent.

### Dataset Availability

The current repository contains the trained model and inference pipeline but does not provide a complete training/evaluation dataset or verified benchmark metrics.

For this reason, no accuracy percentage is claimed in this repository.

---

# Future Improvements

Potential improvements include:

- Cloud-hosted inference
- Automated threat-intelligence integration
- Larger and continuously updated datasets
- Additional domain and webpage features
- Model performance monitoring
- Improved webpage content analysis
- Automated model retraining
- Chrome Web Store distribution
- Improved phishing URL intelligence
- Historical analytics
- Centralized security reporting

---

# Security Considerations

Phisyy is intended as a machine-learning-assisted security tool.

The output should be treated as an additional security signal rather than a definitive security verdict.

Users should avoid entering credentials, payment information, or other sensitive information into suspicious websites.

---

# Disclaimer

Phisyy is an educational and research-oriented cybersecurity project.

Machine-learning predictions should not be treated as a guarantee that a website is safe or malicious.

Users should independently verify suspicious websites before entering sensitive information.

---

# Author

**Sanjana V Hathwar**

Computer Science and Engineering

GitHub:

https://github.com/sanjanaa-10

---

# Repository

GitHub:

https://github.com/sanjanaa-10/phisyy

---

# Project Summary

Phisyy demonstrates a complete machine-learning-assisted browser security workflow:

```text
Chrome Extension
       |
       v
Website Feature Extraction
       |
       v
22 Security Features
       |
       v
Feature Scaling
       |
       v
XGBoost Classification
       |
       v
Prediction Probabilities
       |
       v
Threat Score
       |
       v
Risk Classification
       |
       v
SHAP Explainability
       |
       v
Browser Security Dashboard
```

The project combines **cybersecurity, machine learning, explainable AI, backend API development, and browser extension development** into a single working application.
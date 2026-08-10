# 🐟 Phisyy

### ML-Powered Browser Phishing Detection Extension

Phisyy is a Chrome browser security extension that analyzes websites in real time and identifies potentially suspicious or phishing pages using machine learning.

It combines **XGBoost-based classification**, **URL/webpage security features**, and **SHAP explainability** to provide an interpretable risk assessment directly inside the browser.

---

## 🚨 Why Phisyy?

Phishing websites can look almost identical to legitimate websites.

Instead of relying only on blacklists, Phisyy analyzes multiple characteristics of a website and produces a risk assessment:

- 🟢 LOW RISK
- 🟡 MEDIUM RISK
- 🔴 HIGH RISK

The extension also explains the security signals contributing to the prediction.

---

## ✨ Features

### 🔍 Real-Time Website Analysis
Analyzes the currently opened website and generates a phishing risk assessment.

### 🤖 Machine Learning Detection
Uses an **XGBoost binary classification model** for phishing/legitimate website prediction.

### 📊 22 Security Features
The model uses URL and webpage-derived security characteristics including:

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

### 🧠 Explainable AI

Phisyy integrates **SHAP** to provide explanations for model predictions and identify important security signals.

### ⚠️ Risk Scoring

The phishing probability is converted into a threat score from **0–100**.

| Threat Score | Risk |
|---|---|
| 0–29 | 🟢 LOW |
| 30–69 | 🟡 MEDIUM |
| 70–100 | 🔴 HIGH |

### 📋 Security Dashboard

The browser popup displays:

- Current website
- Risk level
- Threat score
- Legitimate probability
- Phishing probability
- Security signals
- Recent scan history

### 🔔 Browser Security Alerts

Suspicious websites can trigger an in-page Phisyy security notification with options to review the result or close the suspicious tab.

---

## 🏗️ Architecture

```text
                 ┌──────────────────────┐
                 │      Web Browser     │
                 │       Chrome         │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │   Phisyy Extension   │
                 │                      │
                 │ Popup + Background   │
                 │ Security Monitoring  │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │  Feature Extraction  │
                 │                      │
                 │ URL + Webpage Data  │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │     FastAPI API      │
                 │                      │
                 │  Model Inference     │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │   XGBoost Model      │
                 │                      │
                 │ Phishing Prediction  │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │   SHAP Explainability│
                 │                      │
                 │ Security Signals     │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │   Risk Assessment    │
                 │                      │
                 │ LOW / MEDIUM / HIGH  │
                 └──────────────────────┘
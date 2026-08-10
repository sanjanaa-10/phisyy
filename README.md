# 🐟 Phisyy

### ML-Powered Browser Phishing Detection Extension

Phisyy is a Chrome browser security extension that analyzes websites in real time and identifies potentially suspicious or phishing pages using machine learning.

It combines **XGBoost-based classification**, **URL/webpage security features**, and **SHAP explainability** to provide an interpretable risk assessment directly inside the browser.

---

## 🚨 Why Phisyy?

Phishing websites can look almost identical to legitimate websites.

Instead of relying only on blacklists, Phisyy analyzes multiple characteristics of a website and produces a risk assessment:

- 🟢 **LOW RISK**
- 🟡 **MEDIUM RISK**
- 🔴 **HIGH RISK**

The extension also provides security signals that help explain why a website received a particular risk assessment.

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
|---:|---|
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
                 │ URL + Webpage Data   │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │     FastAPI API      │
                 │                      │
                 │   Model Inference    │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │    XGBoost Model     │
                 │                      │
                 │ Phishing Prediction  │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ SHAP Explainability  │
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
```

---

## 🛠️ Technology Stack

### Browser Extension

- JavaScript
- HTML
- CSS
- Chrome Extension API
- Manifest V3

### Backend

- Python
- FastAPI
- Pydantic

### Machine Learning

- XGBoost
- Scikit-learn
- SHAP
- Joblib
- Pandas

### Development

- Git
- GitHub
- Chrome Developer Tools

---

## 📁 Project Structure

```text
Phisyy/
│
├── backend/
│   ├── app.py
│   ├── url_feature_extractor.py
│   ├── xgb_model.json
│   ├── scaler.pkl
│   └── requirements.txt
│
├── Frontend/
│   ├── manifest.json
│   ├── background.js
│   ├── popup.html
│   ├── popup.js
│   └── styles.css
│
├── README.md
└── .gitignore
```

---

# 🚀 Installation & Usage

## Prerequisites

Make sure you have:

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

Navigate to the backend folder:

```bash
cd backend
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

---

## 3. Start the Phisyy Backend

Run:

```bash
python -m uvicorn app:app --port 8000
```

You should see:

```text
Uvicorn running on http://127.0.0.1:8000
```

**Keep this terminal running while using Phisyy.**

---

## 4. Install the Chrome Extension

Open Google Chrome and go to:

```text
chrome://extensions
```

Then:

1. Enable **Developer mode**.
2. Click **Load unpacked**.
3. Open the cloned `phisyy` project folder.
4. Select the **`Frontend`** folder.

Your project should look like:

```text
phisyy/
├── backend/
└── Frontend/
```

⚠️ **Select `Frontend`, not the main `phisyy` folder.**

---

## 5. Pin Phisyy

Click the **Extensions 🧩** button in Chrome.

Find **Phisyy** and click the **Pin 📌** button.

---

## 6. Scan a Website

Open a website in Chrome.

Click the **Phisyy** extension icon.

Phisyy will analyze the website and display:

- 🟢 LOW RISK
- 🟡 MEDIUM RISK
- 🔴 HIGH RISK
- Threat score
- Legitimate probability
- Phishing probability
- Security signals
- Recent scan history

---

## 7. View Security Signals

The popup provides security signals associated with the website analysis.

These signals help the user understand characteristics that may contribute to the risk assessment.

---

## 8. Keep the Backend Running

The backend at:

```text
http://127.0.0.1:8000
```

must remain running while using the extension.

If the backend is stopped, Phisyy cannot perform the ML analysis.

---

# 🧪 Quick Test

After installation:

```text
Start FastAPI Backend
        ↓
Open Chrome
        ↓
Load Phisyy Extension
        ↓
Open a Website
        ↓
Click Phisyy
        ↓
View Risk Assessment
```

---

## 📊 Example Result

```text
PHISYY

Current Website
https://example.com

🟡 MEDIUM RISK

Threat Score
50.2 / 100

Legitimate Probability
49.8%

Phishing Probability
50.2%

Security Signals
✓ HTTPS connection
⚠ Long URL
⚠ External references
```

> The values above are an example of the interface format and are not a claimed model accuracy or benchmark.

---

# 🔄 How Phisyy Works

### 1. Website Detection

Phisyy identifies the currently opened website in Chrome.

### 2. Feature Extraction

URL and webpage-derived security characteristics are collected.

### 3. Feature Processing

The extracted features are arranged according to the model's expected feature order and processed for inference.

### 4. Machine Learning Prediction

The processed features are passed to the XGBoost model.

### 5. Probability Estimation

The model output is used to determine:

- Legitimate probability
- Phishing probability
- Threat score

### 6. Risk Classification

The threat score is mapped to:

```text
0–29     → LOW
30–69    → MEDIUM
70–100   → HIGH
```

### 7. Explainability

SHAP is used to provide interpretable information about the model prediction.

### 8. Browser Result

The final assessment is displayed through the Phisyy browser interface and security alerts.

---

# 🔐 Security Approach

Phisyy uses multiple website characteristics rather than relying on a single signal.

The project demonstrates the integration of:

- Machine Learning
- Cybersecurity
- Feature Engineering
- Explainable AI
- Browser Extension Development
- API Development
- Real-Time Threat Analysis

---

# ⚠️ Disclaimer

Phisyy is an educational and research-oriented cybersecurity project.

Machine-learning predictions should not be treated as a guarantee that a website is safe or malicious.

Users should always verify suspicious websites independently.

---

# 👩‍💻 Author

**Sanjana**

Computer Science & Engineering

GitHub:

https://github.com/sanjanaa-10

---

## ⭐ Project Highlights

```text
✓ Chrome Browser Extension
✓ XGBoost Machine Learning
✓ 22 Security Features
✓ FastAPI Backend
✓ SHAP Explainable AI
✓ Real-Time Risk Scoring
✓ LOW / MEDIUM / HIGH Classification
✓ Security Signals
✓ Scan History
✓ Automated Browser Alerts
```

---

## 📌 Repository

GitHub:

https://github.com/sanjanaa-10/phisyy
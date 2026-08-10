document.addEventListener("DOMContentLoaded", () => {
  const resultDiv = document.getElementById("result");
  const loadingDiv = document.getElementById("loading");
  const historyDiv = document.getElementById("history");
  const currentUrlDiv = document.getElementById("currentUrl");
  const signalsDiv = document.getElementById("signals");
  const signalList = document.getElementById("signalList");

  function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value ?? "";
    return div.innerHTML;
  }

  function formatFeatureName(name) {
    const names = {
      URLLength: "URL Length",
      DomainLength: "Domain Length",
      TLDLength: "TLD Length",
      NoOfImage: "Images",
      NoOfJS: "JavaScript Files",
      NoOfCSS: "CSS Files",
      NoOfSelfRef: "Internal References",
      NoOfExternalRef: "External References",
      IsHTTPS: "HTTPS",
      HasObfuscation: "Obfuscation",
      HasTitle: "Page Title",
      HasDescription: "Meta Description",
      HasSubmitButton: "Submit Button",
      HasSocialNet: "Social Network",
      HasFavicon: "Favicon",
      HasCopyrightInfo: "Copyright Information",
      popUpWindow: "Popup Window",
      Iframe: "Iframe",
      Abnormal_URL: "Abnormal URL",
      LetterToDigitRatio: "Letter-to-Digit Ratio",
      Redirect_0: "Redirect Status",
      Redirect_1: "Redirect Detected"
    };
    return names[name] || name;
  }

  function formatValue(value) {
    if (typeof value !== "number") return String(value ?? "");
    if (Math.abs(value) >= 1000) {
      return value.toLocaleString(undefined, { maximumFractionDigits: 2 });
    }
    return Number.isInteger(value) ? String(value) : value.toFixed(3);
  }

  function formatImpact(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return "0";
    return number >= 0 ? `+${number.toFixed(3)}` : number.toFixed(3);
  }

  function analyzeUrl(url) {
    try {
      const parsed = new URL(url);
      const parts = parsed.hostname.split(".").filter(Boolean);
      return {
        isHttps: parsed.protocol === "https:",
        urlLength: url.length,
        subdomainCount: Math.max(parts.length - 2, 0)
      };
    } catch {
      return { isHttps: false, urlLength: url.length, subdomainCount: 0 };
    }
  }

  function renderSignals(response) {
    const analysis = analyzeUrl(response.url || "");
    const result = String(response.result || "").toLowerCase();
    const risk = String(response.riskLevel || response.risk_level || "LOW").toUpperCase();

    const signals = [
      {
        icon: analysis.isHttps ? "✓" : "!",
        className: analysis.isHttps ? "signal-good" : "signal-warning",
        text: analysis.isHttps ? "HTTPS connection detected" : "Connection is not using HTTPS"
      },
      {
        icon: analysis.urlLength > 100 ? "!" : "✓",
        className: analysis.urlLength > 100 ? "signal-warning" : "signal-good",
        text: analysis.urlLength > 100
          ? `Long URL detected (${analysis.urlLength} characters)`
          : `URL length is ${analysis.urlLength} characters`
      },
      {
        icon: analysis.subdomainCount > 2 ? "!" : "✓",
        className: analysis.subdomainCount > 2 ? "signal-warning" : "signal-good",
        text: analysis.subdomainCount > 2
          ? `${analysis.subdomainCount} subdomain levels detected`
          : "No excessive subdomain pattern detected"
      },
      {
        icon: result === "phishing" ? "!" : "✓",
        className: result === "phishing" ? "signal-danger" : "signal-good",
        text: result === "phishing"
          ? "XGBoost classified this URL as phishing"
          : "XGBoost classified this URL as legitimate"
      },
      {
        icon: risk === "HIGH" ? "!" : risk === "MEDIUM" ? "!" : "✓",
        className: risk === "HIGH" ? "signal-danger" : risk === "MEDIUM" ? "signal-warning" : "signal-good",
        text: risk === "HIGH"
          ? "Overall model risk is high"
          : risk === "MEDIUM"
            ? "Some model signals require caution"
            : "Overall model risk is low"
      }
    ];

    signalList.innerHTML = signals.map(signal => `
      <div class="signal">
        <div class="signal-icon ${signal.className}">${signal.icon}</div>
        <span>${escapeHtml(signal.text)}</span>
      </div>
    `).join("");
  }

  function renderShapExplanations(response) {
    const explanations = Array.isArray(response.explanations) ? response.explanations : [];
    if (!explanations.length) return;

    signalList.innerHTML += explanations.slice(0, 7).map(item => {
      const direction = item.direction || (Number(item.impact) >= 0 ? "legitimate" : "phishing");
      const phishing = direction === "phishing";
      return `
        <div class="signal">
          <div class="signal-icon ${phishing ? "signal-danger" : "signal-good"}">${phishing ? "!" : "✓"}</div>
          <div class="signal-content">
            <strong>${escapeHtml(formatFeatureName(item.feature))}</strong>
            <span>Value: ${escapeHtml(formatValue(item.value))}</span>
            <small>Impact: ${escapeHtml(formatImpact(item.impact))} • ${phishing ? "phishing influence" : "legitimate influence"}</small>
          </div>
        </div>
      `;
    }).join("");
  }

  function renderResult(response) {
    if (!response) {
      resultDiv.innerHTML = `<div class="error-result"><div class="result-icon">⚠️</div><h2 class="result-title">No response</h2><p class="result-description">Phisyy could not receive a response from the security engine.</p></div>`;
      signalsDiv.style.display = "none";
      return;
    }

    if (response.error) {
      resultDiv.innerHTML = `<div class="error-result"><div class="result-icon">⚠️</div><h2 class="result-title">Analysis unavailable</h2><p class="result-description">${escapeHtml(response.error)}</p></div>`;
      signalsDiv.style.display = "none";
      return;
    }

    const url = response.url || "Unknown URL";
    const result = String(response.result || "Unknown");
    const threatScore = Number(response.threatScore ?? response.threat_score ?? 0);
    const legitimateProbability = Number(response.legitimateProbability ?? response.legitimate_probability ?? 0) * 100;
    const phishingProbability = Number(response.phishingProbability ?? response.phishing_probability ?? 0) * 100;
    const riskLevel = String(response.riskLevel ?? response.risk_level ?? "LOW").toUpperCase();

    currentUrlDiv.textContent = url;

    const resultClass = riskLevel === "HIGH"
      ? "phishing-result"
      : riskLevel === "MEDIUM"
        ? "warning-result"
        : "safe-result";

    const icon = riskLevel === "HIGH" ? "🔴" : riskLevel === "MEDIUM" ? "🟡" : "🟢";
    const title = riskLevel === "MEDIUM" ? "MEDIUM RISK" : `${riskLevel} RISK`;
    const description = riskLevel === "HIGH"
      ? "Phisyy's XGBoost model detected a high-risk security profile for this website."
      : riskLevel === "MEDIUM"
        ? "Phisyy detected signals that deserve additional caution. This is a model assessment, not a guarantee of safety."
        : "The XGBoost model classified this URL as low risk. This is a model assessment, not a guarantee of safety.";

    resultDiv.innerHTML = `
      <div class="${resultClass}">
        <div class="result-icon">${icon}</div>
        <h2 class="result-title">${escapeHtml(title)}</h2>
        <p class="result-description">${escapeHtml(description)}</p>
        <div class="score">Threat Score:<strong>${threatScore.toFixed(1)} / 100</strong></div>
        <div class="probabilities">
          <div class="probability-row"><span>Legitimate probability</span><strong>${legitimateProbability.toFixed(2)}%</strong></div>
          <div class="probability-row"><span>Phishing probability</span><strong>${phishingProbability.toFixed(2)}%</strong></div>
        </div>
      </div>
    `;

    signalsDiv.style.display = "block";
    signalList.innerHTML = "";
    renderSignals(response);
    renderShapExplanations(response);
  }

  function loadCurrentStatus() {
    loadingDiv.style.display = "flex";
    currentUrlDiv.textContent = "Getting current website...";

    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (chrome.runtime.lastError) {
        loadingDiv.style.display = "none";
        renderResult({ error: chrome.runtime.lastError.message });
        return;
      }

      const tab = tabs?.[0];
      if (!tab?.url) {
        loadingDiv.style.display = "none";
        renderResult({ error: "Unable to determine the current website." });
        return;
      }

      currentUrlDiv.textContent = tab.url;

      chrome.runtime.sendMessage(
        { action: "getCurrentStatusForUrl", url: tab.url },
        response => {
          loadingDiv.style.display = "none";

          if (chrome.runtime.lastError) {
            renderResult({ error: chrome.runtime.lastError.message });
            return;
          }

          renderResult(response);
        }
      );
    });
  }

  function loadHistory() {
    chrome.runtime.sendMessage({ action: "getHistory" }, history => {
      if (chrome.runtime.lastError) {
        historyDiv.innerHTML = `<div class="empty-history">Unable to load scan history.</div>`;
        return;
      }

      if (!Array.isArray(history) || history.length === 0) {
        historyDiv.innerHTML = `<div class="empty-history">No previous scans yet.</div>`;
        return;
      }

      historyDiv.innerHTML = "";
      history.slice(0, 5).forEach(entry => {
        const risk = String(entry.riskLevel || "LOW").toUpperCase();
        const riskClass = risk === "HIGH" ? "phishing" : risk === "MEDIUM" ? "warning" : "safe";
        const label = risk === "HIGH" ? "🔴 High Risk" : risk === "MEDIUM" ? "🟡 Medium Risk" : "🟢 Low Risk";

        const el = document.createElement("div");
        el.className = "history-entry";
        el.innerHTML = `
          <div class="history-main">
            <span class="history-status ${riskClass}">${label}</span>
            <a href="https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(entry.url || "")}" target="_blank" class="report-link">Report</a>
          </div>
          <div class="history-url">${escapeHtml(entry.url || "Unknown URL")}</div>
          <div class="history-time">${escapeHtml(entry.timestamp || "")}</div>
        `;
        historyDiv.appendChild(el);
      });
    });
  }

  loadCurrentStatus();
  loadHistory();
});

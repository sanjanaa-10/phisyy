// ============================================================
// PHISYY - Browser Security Background Service
// ============================================================

const API_BASE_URL = "http://127.0.0.1:8000";
const MAX_HISTORY_ITEMS = 10;
const tabStates = new Map();
const inFlightScans = new Map();

function getDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "unknown";
  }
}

function isUnsupportedUrl(url) {
  if (!url) return true;

  return /^(chrome|chrome-extension|edge|about|devtools|view-source):/i.test(url)
    || url.startsWith("file:");
}

function normaliseRiskLevel(value, threatScore) {
  const risk = String(value || "").toUpperCase();
  if (risk === "HIGH" || risk === "MEDIUM" || risk === "LOW") return risk;

  if (Number(threatScore) >= 70) return "HIGH";
  if (Number(threatScore) >= 30) return "MEDIUM";
  return "LOW";
}

function storeScanHistory(result) {
  chrome.storage.local.get(["scanHistory"], stored => {
    const history = Array.isArray(stored.scanHistory) ? stored.scanHistory : [];

    // Replace an older entry for the same URL instead of endlessly duplicating it.
    const filtered = history.filter(item => item?.url !== result.url);

    filtered.unshift({
      url: result.url,
      isPhishing: result.isPhishing,
      prediction: result.prediction,
      result: result.result,
      threatScore: result.threatScore,
      riskLevel: result.riskLevel,
      legitimateProbability: result.legitimateProbability,
      phishingProbability: result.phishingProbability,
      features: result.features || {},
      explanations: result.explanations || [],
      timestamp: result.timestamp,
      reported: false
    });

    chrome.storage.local.set({
      scanHistory: filtered.slice(0, MAX_HISTORY_ITEMS)
    });
  });
}

function removePageIndicators(tabId) {
  return chrome.scripting.executeScript({
    target: { tabId },
    func: () => {
      [
        "phisyy-security-popup",
        "phisyy-safe-indicator"
      ].forEach(id => document.getElementById(id)?.remove());
    }
  }).catch(() => {});
}

function injectSecurityPopup(tabId, result) {
  const risk = result.riskLevel;
  const isHigh = risk === "HIGH";
  const isMedium = risk === "MEDIUM";

  const popupHTML = `
    <div id="phisyy-security-popup" style="
      position:fixed;
      top:20px;
      right:20px;
      width:430px;
      max-width:calc(100vw - 40px);
      background:#151b2b;
      color:#fff;
      padding:18px;
      border-radius:16px;
      box-shadow:0 12px 40px rgba(0,0,0,.30);
      z-index:2147483647;
      font-family:Arial,sans-serif;
      border:1px solid rgba(255,255,255,.10);
    ">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;">
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-size:24px">🛡️</span>
          <div>
            <div style="font-size:16px;font-weight:800">Phisyy</div>
            <div style="font-size:10px;color:#9ca3af">Browser Security Engine</div>
          </div>
        </div>
        <button id="phisyy-dismiss" style="background:none;border:0;color:#fff;font-size:20px;cursor:pointer">×</button>
      </div>

      <div style="
        background:${isHigh ? "#3b1116" : isMedium ? "#3b2b0b" : "#102b1d"};
        border:1px solid ${isHigh ? "#7f1d1d" : isMedium ? "#7c5a10" : "#166534"};
        border-radius:12px;
        padding:15px;
      ">
        <div style="color:${isHigh ? "#f87171" : isMedium ? "#fbbf24" : "#4ade80"};font-size:12px;font-weight:800;letter-spacing:1px">
          ${isHigh ? "HIGH RISK" : isMedium ? "MEDIUM RISK" : "LOW RISK"}
        </div>
        <div style="font-size:29px;font-weight:800;margin-top:5px">
          ${Number(result.threatScore ?? 0).toFixed(1)}
          <span style="font-size:12px;color:#94a3b8">/ 100</span>
        </div>
        <div style="font-size:9px;color:#94a3b8;letter-spacing:1px;margin-top:2px">THREAT SCORE</div>
      </div>

      <p style="font-size:12px;line-height:1.5;color:#d1d5db;margin:14px 0 6px">
        Phisyy's XGBoost model classified <strong>${escapeHtmlForInline(getDomain(result.url))}</strong>
        as ${isHigh ? "high risk" : isMedium ? "requiring additional caution" : "low risk"}.
      </p>

      <div style="font-size:11px;color:#9ca3af;margin-top:8px">
        Risk level: <strong>${risk}</strong>
      </div>

      <div style="display:flex;gap:8px;margin-top:14px">
        ${isHigh || isMedium ? `
          <button id="phisyy-close-tab" style="flex:1;background:#ef4444;color:#fff;border:0;padding:10px;border-radius:8px;cursor:pointer;font-weight:700">Close Tab</button>
        ` : ""}
        <button id="phisyy-report" style="flex:1;background:#293246;color:#fff;border:1px solid #46516a;padding:10px;border-radius:8px;cursor:pointer;font-weight:700">Report</button>
      </div>
    </div>
  `;

  removePageIndicators(tabId).finally(() => {
    chrome.scripting.executeScript({
      target: { tabId },
      func: (html, currentTabId) => {
        document.getElementById("phisyy-security-popup")?.remove();
        const wrapper = document.createElement("div");
        wrapper.innerHTML = html;
        const popup = wrapper.firstElementChild;
        if (!popup) return;
        document.documentElement.appendChild(popup);

        popup.querySelector("#phisyy-dismiss")?.addEventListener("click", () => popup.remove());

        popup.querySelector("#phisyy-close-tab")?.addEventListener("click", () => {
          chrome.runtime.sendMessage({ action: "closeCurrentTab", tabId: currentTabId });
        });

        popup.querySelector("#phisyy-report")?.addEventListener("click", () => {
          window.open(
            "https://safebrowsing.google.com/safebrowsing/report_phish/?url=" + encodeURIComponent(window.location.href),
            "_blank"
          );
        });
      },
      args: [popupHTML, tabId]
    }).catch(error => {
      console.debug("Phisyy could not inject the page notification:", error?.message || error);
    });
  });
}

function escapeHtmlForInline(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

async function checkForPhishing(url, tabId) {
  if (isUnsupportedUrl(url)) {
    return {
      url,
      isPhishing: false,
      prediction: null,
      result: "Not Scanned",
      legitimateProbability: 0,
      phishingProbability: 0,
      threatScore: null,
      riskLevel: "N/A",
      features: {},
      explanations: [],
      timestamp: new Date().toLocaleString()
    };
  }

  const key = `${tabId}:${url}`;
  if (inFlightScans.has(key)) return inFlightScans.get(key);

  const scanPromise = (async () => {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 20000);

      let response;
      try {
        response = await fetch(`${API_BASE_URL}/predict_url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
          signal: controller.signal
        });
      } finally {
        clearTimeout(timeout);
      }

      if (!response.ok) {
        throw new Error(`Analysis API returned HTTP ${response.status}`);
      }

      const data = await response.json();
      if (data.error) throw new Error(data.error);

      const threatScore = Number(data.threat_score ?? 0);
      const riskLevel = normaliseRiskLevel(data.risk_level, threatScore);
      const prediction = data.prediction;
      const isPhishing = prediction === 0 || String(data.result).toLowerCase() === "phishing";

      const result = {
        url,
        isPhishing,
        prediction,
        result: data.result,
        legitimateProbability: Number(data.legitimate_probability ?? 0),
        phishingProbability: Number(data.phishing_probability ?? 0),
        threatScore,
        riskLevel,
        features: data.features || {},
        explanations: Array.isArray(data.explanations) ? data.explanations : [],
        timestamp: new Date().toLocaleString()
      };

      tabStates.set(tabId, {
        domain: getDomain(url),
        previousUrl: url,
        result
      });

      storeScanHistory(result);
      injectSecurityPopup(tabId, result);

      return result;
    } catch (error) {
      const message = error?.name === "AbortError"
        ? "The security analysis timed out. Make sure the FastAPI backend is running."
        : error?.message || "Unable to analyze this website.";

      const result = { url, error: message };
      tabStates.set(tabId, { domain: getDomain(url), previousUrl: url, result });
      return result;
    } finally {
      inFlightScans.delete(key);
    }
  })();

  inFlightScans.set(key, scanPromise);
  return scanPromise;
}

function debounce(func, wait) {
  let timeout;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

const debouncedCheck = debounce((url, tabId) => {
  checkForPhishing(url, tabId).catch(() => {});
}, 500);

chrome.webNavigation.onCommitted.addListener(details => {
  if (details.frameId !== 0 || isUnsupportedUrl(details.url)) return;
  debouncedCheck(details.url, details.tabId);
});

chrome.tabs.onActivated.addListener(activeInfo => {
  chrome.tabs.get(activeInfo.tabId, tab => {
    if (tab?.url && !isUnsupportedUrl(tab.url)) {
      debouncedCheck(tab.url, activeInfo.tabId);
    }
  });
});

chrome.tabs.onRemoved.addListener(tabId => {
  tabStates.delete(tabId);
  for (const key of inFlightScans.keys()) {
    if (key.startsWith(`${tabId}:`)) inFlightScans.delete(key);
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getCurrentStatusForUrl") {
    const url = request.url;

    chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
      try {
        const tab = tabs?.[0];
        if (!tab?.id || !url) {
          sendResponse({ error: "Unable to determine the current website." });
          return;
        }

        const state = tabStates.get(tab.id);
        if (state?.previousUrl === url && state.result && !state.result.error) {
          sendResponse(state.result);
          return;
        }

        const result = await checkForPhishing(url, tab.id);
        sendResponse(result);
      } catch (error) {
        sendResponse({ error: error?.message || "Unable to analyze this website." });
      }
    });

    return true;
  }

  if (request.action === "getCurrentStatus") {
    chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
      const tab = tabs?.[0];
      if (!tab?.id || !tab.url) {
        sendResponse({ error: "Unable to determine the current website." });
        return;
      }

      const state = tabStates.get(tab.id);
      if (state?.previousUrl === tab.url && state.result) {
        sendResponse(state.result);
        return;
      }

      sendResponse(await checkForPhishing(tab.url, tab.id));
    });
    return true;
  }

  if (request.action === "getHistory") {
    chrome.storage.local.get(["scanHistory"], stored => {
      sendResponse(Array.isArray(stored.scanHistory) ? stored.scanHistory : []);
    });
    return true;
  }

  if (request.action === "clearHistory") {
    chrome.storage.local.remove(["scanHistory"], () => sendResponse({ ok: true }));
    return true;
  }

  if (request.action === "closeCurrentTab") {
    if (request.tabId) chrome.tabs.remove(request.tabId);
    return false;
  }

  return false;
});

console.log("Phisyy Security Engine started");

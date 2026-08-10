# Phisyy - Fixed Version

This version synchronizes the Chrome extension popup, background service worker, and FastAPI response format.

## What was fixed
- Removed the broken duplicate popup-status flow.
- Fixed the `popup.js` duplicate `const` declarations that caused a JavaScript syntax error.
- Popup now gets the active URL immediately and receives the current scan result from the service worker.
- Added a single in-flight scan per tab/URL to prevent repeated backend requests.
- Popup no longer reuses an old history entry as the current result.
- History entries are updated per URL instead of duplicated endlessly.
- Backend risk levels are preserved: LOW, MEDIUM, HIGH.
- In-page notification now displays MEDIUM RISK when the backend says MEDIUM, instead of incorrectly showing LOW RISK.
- DevTools/internal browser URLs are ignored quietly.
- Close Tab and Report actions remain available for medium/high results.
- Normalized `requirements.txt` to UTF-8.
- Extension version bumped to 1.0.1.

## Run backend
From the `backend` folder:

```powershell
python -m uvicorn app:app --reload --port 8000
```

Keep that terminal running.

## Reload extension
1. Open `chrome://extensions`.
2. Enable Developer mode.
3. Click Reload on Phisyy.
4. Refresh the website being tested.
5. Open the Phisyy toolbar icon.

The extension expects the API at:

`http://127.0.0.1:8000`

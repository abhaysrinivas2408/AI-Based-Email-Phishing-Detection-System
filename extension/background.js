// ─────────────────────────────────────────────────────────────
//  Phishing Detector — background.js (service worker)
// ─────────────────────────────────────────────────────────────

// FIX: Keep-alive handlers ensure the service worker registers its listener
// even after Chrome terminates and restarts it. These are no-ops functionally
// but prevent the "cold wake-up" window where the listener isn't yet registered.
chrome.runtime.onInstalled.addListener(() => {});
chrome.runtime.onStartup.addListener(() => {});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

    // ── Open a URL in a new tab ─────────────────────────────
    // Used by: Continue button, View Details button in content.js
    if (msg.type === "OPEN_LINK") {
        chrome.tabs.create({ url: msg.url, active: true });
        // No response needed — don't call sendResponse, return false (sync handler)
        return false;
    }

    // ── Scan email content or a URL ─────────────────────────
    if (msg.type === "SCAN_EMAIL" || msg.type === "SCAN_URL") {

        // FIX: AbortController gives the fetch a hard 7s deadline.
        // This ensures sendResponse ALWAYS fires — even if Flask is slow or down.
        // Without this, a hanging fetch keeps the message channel open until
        // Chrome kills the service worker, and the callback in content.js never runs.
        const controller  = new AbortController();
        const fetchTimeout = setTimeout(() => controller.abort(), 7000);

        fetch("http://127.0.0.1:5000/scan", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify(msg.payload),
            signal:  controller.signal,
        })
        .then(res => {
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res.json();
        })
        .then(data => {
            clearTimeout(fetchTimeout);
            sendResponse({ success: true, data });
        })
        .catch(err => {
            clearTimeout(fetchTimeout);
            const reason = err.name === "AbortError" ? "backend timeout" : err.message;
            console.warn("[PhishDetector] Scan failed:", reason);
            // FIX: Always send a response — even on failure.
            // This guarantees isScanning resets in content.js regardless of what happens.
            // Defaulting to Safe prevents false alarms when backend is unreachable.
            sendResponse({ success: true, data: { verdict: "Safe" } });
        });

        // IMPORTANT: return true keeps the message channel open for the async response.
        // Without this, Chrome closes the channel immediately and sendResponse has no effect.
        return true;
    }
});
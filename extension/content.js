// ─────────────────────────────────────────────────────────────
//  Phishing Detector — content.js
//  Runs inside Gmail (https://mail.google.com)
// ─────────────────────────────────────────────────────────────

let lastEmailHash = null;
let isScanning    = false;
let scanTimeoutId = null;

// Max characters sent to the backend — ML needs key phrases, not full emails
const MAX_CONTENT_CHARS = 8000;

// ── Runtime validity guard ──────────────────────────────────
// Gmail navigates rapidly as an SPA. If the content-script context becomes
// invalidated, chrome.runtime.* throws "Extension context invalidated" —
// an uncaught exception that silently kills the entire script.
// This wrapper catches it and resets state cleanly.
function runtimeSend(message, callback) {
    try {
        if (!chrome.runtime?.id) {
            isScanning = false;
            return;
        }
        chrome.runtime.sendMessage(message, (response) => {
            if (chrome.runtime.lastError) {
                // Suppress "Unchecked runtime.lastError" console noise
                isScanning = false;
                return;
            }
            if (callback) callback(response);
        });
    } catch (e) {
        isScanning = false;
    }
}

// ── Scan timeout safety valve ───────────────────────────────
// If the service worker is terminated mid-request the callback never fires.
// After 10s we reset so the extension doesn't freeze permanently.
function startScanTimeout() {
    if (scanTimeoutId) clearTimeout(scanTimeoutId);
    scanTimeoutId = setTimeout(() => {
        isScanning    = false;
        scanTimeoutId = null;
    }, 10000);
}

function clearScanTimeout() {
    if (scanTimeoutId) {
        clearTimeout(scanTimeoutId);
        scanTimeoutId = null;
    }
}

// ── Popups ──────────────────────────────────────────────────
function showEmailPopup(result) {
    const old = document.getElementById("phish-popup");
    if (old) old.remove();

    const verdictMap = {
        "Phishing":   { color: "#f8d7da", label: "NOT SAFE"  },
        "Suspicious": { color: "#fff3cd", label: "SUSPICIOUS" },
        "Safe":       { color: "#d4edda", label: "SAFE"       },
    };
    const { color, label } = verdictMap[result.verdict] || verdictMap["Safe"];

    const popup = document.createElement("div");
    popup.id = "phish-popup";
    popup.style.cssText = `
        position:fixed; top:20px; right:20px; padding:10px 16px;
        background:${color}; border:2px solid #333; font-weight:bold;
        z-index:2147483647; border-radius:6px;
        font-family:Arial,sans-serif; font-size:14px;
        box-shadow:0 2px 8px rgba(0,0,0,0.25);
    `;
    popup.innerText = label;
    document.body.appendChild(popup);
    setTimeout(() => { if (popup.parentNode) popup.remove(); }, 3500);
}

function showLinkPopup(result, link) {
    const old = document.getElementById("phish-popup");
    if (old) old.remove();

    const verdictMap = {
        "Phishing":   { color: "#f8d7da", label: "NOT SAFE"  },
        "Suspicious": { color: "#fff3cd", label: "SUSPICIOUS" },
        "Safe":       { color: "#d4edda", label: "SAFE"       },
    };
    const { color, label } = verdictMap[result.verdict] || verdictMap["Safe"];

    const popup = document.createElement("div");
    popup.id = "phish-popup";
    popup.style.cssText = `
        position:fixed; top:20px; right:20px; padding:12px 16px;
        background:${color}; border:2px solid #333; z-index:2147483647;
        border-radius:6px; font-family:Arial,sans-serif; font-size:14px;
        box-shadow:0 2px 8px rgba(0,0,0,0.25); min-width:180px;
    `;
    popup.innerHTML = `
        <b>${label}</b><br><br>
        <button id="phish-cont"   style="margin-right:6px;padding:4px 10px;cursor:pointer;">Continue</button>
        <button id="phish-cancel" style="padding:4px 10px;cursor:pointer;">Cancel</button><br><br>
        <a href="#" id="phish-details" style="font-size:13px;">View Details</a>
    `;
    document.body.appendChild(popup);

    document.getElementById("phish-cont").onclick = () => {
        runtimeSend({ type: "OPEN_LINK", url: link });
        popup.remove();
    };

    document.getElementById("phish-cancel").onclick = () => popup.remove();

    document.getElementById("phish-details").onclick = (e) => {
        e.preventDefault();
        // FIX: close popup after opening details tab
        popup.remove();
        runtimeSend({ type: "OPEN_LINK", url: `http://127.0.0.1:5000/report?url=${encodeURIComponent(link)}` });
    };
}

// ── Fast non-blocking text extraction ──────────────────────
// Uses TreeWalker (reads raw text nodes) instead of .innerText (which forces
// a full synchronous layout reflow — can take 2-4s on large image emails).
function extractTextFast(element) {
    const walker = document.createTreeWalker(
        element,
        NodeFilter.SHOW_TEXT,
        {
            acceptNode(node) {
                const tag = node.parentElement?.tagName?.toUpperCase();
                if (tag === "SCRIPT" || tag === "STYLE" || tag === "NOSCRIPT") {
                    return NodeFilter.FILTER_REJECT;
                }
                const text = node.nodeValue.trim();
                return text.length > 0 ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
            }
        }
    );

    const parts  = [];
    let totalLen = 0;
    let node;
    while ((node = walker.nextNode()) && totalLen < MAX_CONTENT_CHARS) {
        const t = node.nodeValue.trim();
        parts.push(t);
        totalLen += t.length;
    }
    return parts.join(" ");
}

// ── Email content extractor ─────────────────────────────────
function extractEmailContent() {
    const emailEl = document.querySelector("div[role='main'] .ii.gt");
    if (!emailEl) return null;

    // 1. Fast text extraction (TreeWalker — no layout reflow)
    const textContent = extractTextFast(emailEl);

    // 2. Alt text from images (catches image-only emails)
    const altTexts = [];
    emailEl.querySelectorAll("img[alt]").forEach(img => {
        const a = img.alt.trim();
        if (a.length > 2) altTexts.push(a);
    });

    // 3. Title attributes — but ONLY on non-interactive elements.
    //    Gmail UI buttons inside .ii.gt have titles like "Reply", "More options"
    //    which pollute content. Skip buttons, toolbars, and small elements.
    const titleTexts = [];
    emailEl.querySelectorAll("[title]").forEach(el => {
        const tag = el.tagName.toUpperCase();
        if (tag === "BUTTON" || tag === "INPUT" || tag === "SELECT") return;
        if (el.getAttribute("role") === "button") return;
        const t = el.getAttribute("title").trim();
        if (t.length > 3) titleTexts.push(t);
    });

    // 4. Aria labels (same guard — skip interactive elements)
    const ariaTexts = [];
    emailEl.querySelectorAll("[aria-label]").forEach(el => {
        const tag = el.tagName.toUpperCase();
        if (tag === "BUTTON" || tag === "INPUT") return;
        if (el.getAttribute("role") === "button") return;
        const a = (el.getAttribute("aria-label") || "").trim();
        if (a.length > 3) ariaTexts.push(a);
    });

    // Combine and cap
    const combined = [textContent, altTexts.join(" "), titleTexts.join(" "), ariaTexts.join(" ")]
        .filter(s => s.trim().length > 0)
        .join(" ")
        .trim()
        .slice(0, MAX_CONTENT_CHARS);

    // 5. Real navigation links only — filter out images, trackers, and gmail internals
    const imageExt = /\.(jpg|jpeg|png|gif|webp|bmp|svg|ico)(\?.*)?$/i;
    // FIX: removed /\/open\// — too broad, blocks legitimate links like /open-orders
    const trackingPatterns = [
        /mail\.google\.com/,
        /open\?messagePartId/,
        /googleusercontent\.com/,
        /\/track\//,
        /\/pixel\//,
        /\/unsubscribe\//,
    ];

    const links = [];
    const seen  = new Set();
    emailEl.querySelectorAll("a[href]").forEach(a => {
        const href = a.href;
        if (!href || !href.startsWith("http")) return;
        if (imageExt.test(href)) return;
        if (trackingPatterns.some(p => p.test(href))) return;
        if (seen.has(href)) return;
        seen.add(href);
        links.push(href);
    });

    return { combined, links };
}

// ── Gmail SPA navigation watcher ───────────────────────────
// Gmail changes the URL hash when opening emails (#inbox/threadId).
// Reset lastEmailHash so each newly opened email gets scanned fresh.
let lastGmailUrl = location.href;
setInterval(() => {
    if (location.href !== lastGmailUrl) {
        lastGmailUrl  = location.href;
        lastEmailHash = null;   // force re-scan on next poll
    }
}, 500);

// ── Email scan (polls every 4s) ─────────────────────────────
function scanEmail() {
    // FIX: isScanning guard BEFORE requestIdleCallback was a race condition.
    // Now we set isScanning=true synchronously here, then do the async work.
    // This ensures no second scan can start while one is in progress.
    if (isScanning) return;

    const extracted = extractEmailContent();
    if (!extracted) return;

    const { combined, links } = extracted;
    if (combined.length < 20 && links.length === 0) return;

    const hash = combined.slice(0, 200) + (links[0] || "");
    if (hash === lastEmailHash) return;

    // Lock BEFORE the async call — prevents double-fire
    lastEmailHash = hash;
    isScanning    = true;
    startScanTimeout();

    runtimeSend(
        { type: "SCAN_EMAIL", payload: { content: combined || " ", links } },
        (res) => {
            clearScanTimeout();
            isScanning = false;
            if (res?.success) showEmailPopup(res.data);
        }
    );
}

// FIX: Removed requestIdleCallback wrapper — it caused race conditions and
// froze on backgrounded tabs. extractEmailContent() is already fast (TreeWalker),
// so calling it directly is safe and reliable.
setInterval(scanEmail, 4000);

// ── Link click interceptor ──────────────────────────────────
document.addEventListener("click", function(e) {
    if (e.target.closest("#phish-popup")) return;

    let t = e.target;
    while (t && t.tagName !== "A") t = t.parentElement;
    if (!t || !t.href || !t.href.startsWith("http")) return;

    const link = t.href;

    // Skip image/asset URLs
    const imageExt = /\.(jpg|jpeg|png|gif|webp|bmp|svg|ico)(\?.*)?$/i;
    if (imageExt.test(link)) return;

    // Skip Gmail-internal navigation
    if (link.includes("mail.google.com")) return;

    e.preventDefault();
    e.stopPropagation();

    // Use email container text only — NOT document.body.innerText.
    // body.innerText on Gmail is 100,000+ chars and crashes the message bridge.
    const emailEl   = document.querySelector("div[role='main'] .ii.gt");
    const emailText = emailEl ? extractTextFast(emailEl).slice(0, MAX_CONTENT_CHARS) : "";

    runtimeSend(
        { type: "SCAN_URL", payload: { content: emailText, links: [link] } },
        (res) => {
            if (res?.success) showLinkPopup(res.data, link);
        }
    );

}, true);
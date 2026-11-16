from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re
import socket
import ssl
import requests as req_lib
from urllib.parse import urlparse
from datetime import datetime, timezone
from markupsafe import escape

app = Flask(__name__)
CORS(app)

model      = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


# ── Trusted domains (exact suffix match) ────────────────────
TRUSTED_DOMAINS = [
    # Indian Banks
    "hdfcbank.com", "icicibank.com", "sbi.co.in",
    "axisbank.com", "kotak.com", "indusind.com",
    "yesbank.in", "bankofbaroda.in", "pnbindia.in",
    "canarabank.com", "unionbankofindia.co.in",
    "idbibank.in", "federalbank.co.in", "idfcfirstbank.com",
    "rblbank.com", "bandhanbank.com",

    # International Banks
    "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citibank.com", "hsbc.com", "barclays.co.uk",
    "standardchartered.com", "deutschebank.com",

    # Payment & Fintech
    "paypal.com", "paytm.com", "phonepe.com",
    "razorpay.com", "stripe.com", "billdesk.com",
    "mobikwik.com", "freecharge.in", "gpay.app",
    "cred.club",

    # Indian E-commerce & Food
    "zomato.com", "swiggy.com", "blinkit.com",
    "ajio.com", "myntra.com", "nykaa.com",
    "meesho.com", "snapdeal.com", "tatacliq.com",
    "bigbasket.com", "zepto.com", "dunzo.com",
    "amazon.in", "amazon.com", "flipkart.com",
    "jiomart.com", "reliancedigital.com",

    # Travel & Booking
    "makemytrip.com", "goibibo.com", "yatra.com",
    "irctc.co.in", "bookmyshow.com", "cleartrip.com",
    "airbnb.com", "booking.com", "oyo.com",
    "indigo.in", "airindia.in", "spicejet.com",

    # Utilities & Services
    "cleartax.in", "policybazaar.com", "coverfox.com",
    "ola.com", "uber.com", "rapido.bike",

    # Global Tech & Services
    "google.com", "apple.com", "microsoft.com",
    "linkedin.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "github.com",
    "netflix.com", "adobe.com", "zoom.us",
    "dropbox.com", "salesforce.com", "notion.so",
    "slack.com", "atlassian.com", "shopify.com",

    # Property & Real Estate
    "magicbricks.com", "99acres.com", "housing.com",
    "nobroker.in", "commonfloor.com", "proptiger.com",

    # News & Media
    "timesofindia.com", "hindustantimes.com", "ndtv.com",
    "thehindu.com", "moneycontrol.com", "economictimes.com",
    "livemint.com", "businessstandard.com",

    # Telecom & Utilities
    "jio.com", "airtel.in", "bsnl.co.in", "vodafone.in",
    "tatapower.com", "bescom.org",

    # Ed-tech & misc Indian services
    "byju.com", "unacademy.com", "upstox.com", "zerodha.com",
    "groww.in", "angelone.in", "icicidirect.com",
]

# Safe transactional phrases — clear signals of legitimate emails
SAFE_PATTERNS = [
    # Property / real-estate alerts (MagicBricks, 99acres, Housing.com, NoBroker)
    "bhk", "sq ft", "sqft", "sq.ft", "rental property", "property for rent",
    "property for sale", "similar properties", "new properties",
    "view property", "schedule a visit", "property alert",
    "floor plan", "possession date", "rera",
    "transaction successful", "transaction of rs", "transaction of inr",
    "payment confirmed", "payment of rs", "payment of inr",
    "your order has been", "order has been placed", "order has been confirmed",
    "order has been shipped", "order has been delivered",
    "booking confirmed", "booking id",
    "successfully logged in",
    "otp for", "one time password", "your otp is",
    "statement for", "account statement",
    "we have received your",
    "thank you for your purchase", "thank you for your order",
    "your ticket", "invoice attached", "receipt for",
    "successfully transferred",
    "amount credited", "amount debited", "has been credited", "has been debited",
    "minimum due", "due date",
    "your delivery", "out for delivery", "delivered successfully",
    "your subscription",
    # Property / recommendation emails
    "properties for you", "property for you", "properties in your",
    "rental property", "properties matching", "new properties",
    "property alert", "similar properties", "based on your search",
    "recommended for you", "new listing", "price drop",
    "we found", "properties near",
]

# Hard phishing phrases — override safe patterns if present
HARD_PHISHING_PATTERNS = [
    "verify your account immediately",
    "your account will be suspended",
    "click here to avoid suspension",
    "update your payment details now",
    "confirm your identity to restore",
    "account has been temporarily suspended",
    "restore access to your account",
    "you have won", "claim your prize", "claim your reward",
    "wire transfer required",
    "provide your ssn", "provide your aadhaar",
    "provide your cvv", "provide your pin",
    "act now or lose",
    "your account has been compromised",
    "unauthorized transaction detected",
    "verify within 24 hours",
    "failure to comply",
]

# Legitimate promotional/marketing words
PROMOTIONAL_WORDS = [
    "% off", "% discount", "sale", "deal", "offer", "offers",
    "discount", "shop now", "hurry", "limited time", "ends tonight",
    "ends today", "flash sale", "cashback", "coupon", "promo code",
    "voucher", "exclusive", "buy now", "free delivery", "free shipping",
    "use code", "extra off", "upto", "up to",
]

# Words that only appear in phishing, not in legitimate promos
PHISHING_CONTEXT_WORDS = [
    "verify your account", "account suspended", "account locked",
    "confirm your identity", "update your details", "login to confirm",
    "restore access", "unauthorized access", "security alert",
    "unusual activity", "click here to verify", "verify immediately",
    "account will be closed",
]

# Banking notification vocabulary
BANKING_NOTIFICATION_WORDS = [
    "statement", "transaction", "credited", "debited",
    "balance", "passbook", "otp", "receipt", "invoice",
    "emi", "minimum due", "due date", "credit card",
]

# Image/asset URL pattern — don't run website analysis on these
IMAGE_EXT_RE = re.compile(
    r'\.(jpg|jpeg|png|gif|webp|bmp|svg|ico|pdf|zip|mp4|mp3)(\?.*)?$',
    re.IGNORECASE
)


def strip_www(domain: str) -> str:
    """FIX: Use proper prefix removal, not lstrip() which strips characters not strings."""
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def is_trusted_domain(domain: str) -> bool:
    """Exact suffix match — prevents evil-hdfcbank.com matching hdfcbank.com."""
    domain = strip_www(domain)
    for td in TRUSTED_DOMAINS:
        if domain == td or domain.endswith("." + td):
            return True
    return False


# Real-estate notification vocabulary
PROPERTY_WORDS = [
    "bhk", "sq ft", "sqft", "sq.ft", "property", "flat", "apartment",
    "villa", "plot", "rent", "lease", "possession", "floor plan",
    "builder", "locality", "rera", "carpet area", "builtup",
    "similar properties", "view property", "schedule a visit",
    "property alert", "new listing", "price drop",
]


def is_promotional_email(content_lower: str) -> bool:
    """True if email has promo language but zero phishing-context language."""
    has_promo    = sum(1 for w in PROMOTIONAL_WORDS if w in content_lower) >= 2
    has_phishing = any(w in content_lower for w in PHISHING_CONTEXT_WORDS)
    return has_promo and not has_phishing


def is_property_alert_email(content_lower: str) -> bool:
    """True if email looks like a real-estate property notification.
    These contain property vocabulary but zero phishing-context language."""
    has_property = sum(1 for w in PROPERTY_WORDS if w in content_lower) >= 2
    has_phishing = any(w in content_lower for w in PHISHING_CONTEXT_WORDS)
    return has_property and not has_phishing


# ── Website analysis ────────────────────────────────────────
def analyze_website(url: str) -> dict:
    """
    Score how safe this URL is for the user to visit.
    Starts at 50 (neutral). Safe signals → higher. Risk signals → lower.
    Safe ≥ 65 | Suspicious 38–64 | Phishing < 38
    """
    score   = 50
    issuer  = "Unknown"
    days_left = 0
    reasons = []

    # Don't analyse image/asset URLs — they are not web pages
    if IMAGE_EXT_RE.search(url):
        return {
            "risk": "Safe", "score": 70, "issuer": "N/A",
            "days_left": 0, "reasons": ["URL points to a media file, not a web page"]
        }

    try:
        parsed = urlparse(url)
        host   = parsed.hostname
        path   = (parsed.path  or "").lower()
        query  = (parsed.query or "").lower()

        if not host:
            return {
                "risk": "Phishing", "score": 0, "issuer": issuer,
                "days_left": days_left, "reasons": ["Invalid or empty URL"]
            }

        domain = strip_www(host)

        # Trusted domain check
        trusted = is_trusted_domain(domain)
        if trusted:
            score += 30
            reasons.append("Domain belongs to a known trusted service")

        # Suspicious URL structure checks — SKIP for trusted domains.
        # A tracking link from magicbricks.com may be long, have subdomains,
        # or redirect to a CDN — none of that makes it dangerous.
        # Structural penalties only matter for unknown/untrusted domains.
        if not trusted:
            if "@" in url:
                score -= 30
                reasons.append("URL contains @ symbol (credential harvesting pattern)")

            if len(url) > 120:
                score -= 10
                reasons.append("Unusually long URL")

            dash_count = host.count("-")
            if dash_count > 4:
                score -= 15
                reasons.append(f"Excessive hyphens in domain ({dash_count})")
            elif dash_count > 2:
                score -= 5

            subdomain_count = host.count(".")
            if subdomain_count > 4:
                score -= 20
                reasons.append("Excessive subdomains — common spoofing pattern")
            elif subdomain_count > 3:
                score -= 8

            # Raw IP address as hostname
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                score -= 35
                reasons.append("URL uses a raw IP address instead of a domain name")

            # Brand spoofing
            brand_spoofs = {
                "paypal": "paypal.com",   "hdfc":    "hdfcbank.com",
                "sbi":    "sbi.co.in",    "icici":   "icicibank.com",
                "amazon": "amazon.com",   "google":  "google.com",
                "apple":  "apple.com",    "microsoft": "microsoft.com",
                "zomato": "zomato.com",   "swiggy":  "swiggy.com",
                "ajio":   "ajio.com",     "myntra":  "myntra.com",
            }
            for brand, real_domain in brand_spoofs.items():
                if brand in domain:
                    score -= 30
                    reasons.append(f"Brand '{brand}' used in domain that is not {real_domain}")
                    break

            # High-risk TLDs
            suspicious_tlds = [
                ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
                ".top", ".work", ".click", ".link", ".online"
            ]
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    score -= 20
                    reasons.append(f"High-risk top-level domain: {tld}")
                    break

            # Phishing keywords in path/query
            phishing_url_words = [
                "verify", "update-account", "confirm-identity",
                "account-suspended", "recover-account"
            ]
            if any(w in path or w in query for w in phishing_url_words):
                score -= 15
                reasons.append("Suspicious action keywords in URL path")

        # ── HTTPS + redirect check ────────────────────────
        # FIX: Don't penalise on generic network exceptions (timeout, DNS, etc.)
        # — these are neutral signals, not risk signals.
        # Only penalise on explicit security failures (SSLError).
        https_checked = False
        try:
            resp      = req_lib.get(url, timeout=4, allow_redirects=True)
            final_url = resp.url
            https_checked = True

            if final_url.startswith("https://"):
                score += 15
                reasons.append("Site uses HTTPS encryption")
            else:
                score -= 20
                reasons.append("Site does not use HTTPS — connection is unencrypted")

            # Redirect to a different domain check.
            # Skip redirect penalty if original domain is already trusted —
            # trusted senders routinely use CDNs and email-tracking redirects.
            final_host   = urlparse(final_url).hostname or ""
            final_domain = strip_www(final_host)
            if final_host and final_host != host:
                if is_trusted_domain(final_domain):
                    reasons.append(f"Redirects to trusted domain: {final_host}")
                elif trusted:
                    reasons.append(f"Redirects via trusted sender's tracking infrastructure")
                else:
                    score -= 20
                    reasons.append(f"Redirects to a different unknown domain: {final_host}")

        except req_lib.exceptions.SSLError:
            score -= 25
            reasons.append("SSL certificate error during connection")
        except Exception:
            # Timeout, DNS failure, connection refused — don't penalise,
            # just note we couldn't verify
            if not https_checked:
                reasons.append("Could not reach site to verify HTTPS status")

        # ── SSL certificate check ─────────────────────────
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=4) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    issuer_data = dict(x[0] for x in cert["issuer"])
                    issuer      = issuer_data.get("organizationName", "Unknown")

                    # FIX: use timezone-aware UTC comparison
                    expiry    = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    now_utc   = datetime.now(timezone.utc).replace(tzinfo=None)
                    days_left = (expiry - now_utc).days

                    if days_left > 30:
                        score += 15
                        reasons.append(f"Valid SSL certificate — expires in {days_left} days")
                    elif days_left > 0:
                        score += 5
                        reasons.append(f"SSL certificate expiring soon ({days_left} days left)")
                    else:
                        score -= 30
                        reasons.append("SSL certificate has expired")

                    # Self-signed check
                    subject_data = dict(x[0] for x in cert["subject"])
                    subject_cn   = subject_data.get("commonName", "")
                    if issuer == subject_cn or issuer == "Unknown":
                        score -= 10
                        reasons.append("Certificate appears to be self-signed or issuer unknown")

        except ssl.SSLCertVerificationError:
            score -= 30
            reasons.append("SSL certificate verification failed — possible impersonation")
        except Exception:
            pass

        score = max(0, min(100, score))
        risk  = "Safe" if score >= 65 else "Suspicious" if score >= 38 else "Phishing"

        return {
            "risk":     risk,
            "score":    score,
            "issuer":   issuer,
            "days_left": days_left,
            "reasons":  reasons if reasons else ["No specific risk signals detected"]
        }

    except Exception as e:
        return {
            "risk":     "Phishing",
            "score":    0,
            "issuer":   issuer,
            "days_left": days_left,
            "reasons":  [f"Analysis could not be completed: {str(e)}"]
        }


# ── /scan route ─────────────────────────────────────────────
@app.route("/scan", methods=["POST"])
def scan():
    # FIX: Use get_json(silent=True) to handle missing/wrong Content-Type
    # gracefully instead of crashing with AttributeError on None.
    data    = request.get_json(silent=True) or {}
    content = data.get("content", "").strip()
    links   = data.get("links",   [])

    # Guard against empty content (e.g. image-only email with no alt text)
    if not content:
        content = " "

    content_lower = content.lower()

    # Step 1: Hard safe override — clear transactional/confirmation signals
    if any(p in content_lower for p in SAFE_PATTERNS):
        if not any(p in content_lower for p in HARD_PHISHING_PATTERNS):
            return jsonify({"verdict": "Safe"})

    # Step 2a: Promotional email — legitimate marketing with no phishing language
    if is_promotional_email(content_lower):
        url = links[0] if links else None
        if url:
            parsed_domain = strip_www(urlparse(url).netloc)
            if is_trusted_domain(parsed_domain):
                return jsonify({"verdict": "Safe"})
        else:
            return jsonify({"verdict": "Safe"})

    # Step 2b: Property alert email — real-estate notifications (MagicBricks etc.)
    # These have NO safe patterns and NO promo words, so they fall through to ML
    # which over-flags them because of words like "important", "contact", "update".
    # Detect them by property vocabulary + no phishing context.
    if is_property_alert_email(content_lower):
        url = links[0] if links else None
        if url:
            parsed_domain = strip_www(urlparse(url).netloc)
            if is_trusted_domain(parsed_domain):
                return jsonify({"verdict": "Safe"})
        else:
            # No link — safe (property notifications without links are benign)
            return jsonify({"verdict": "Safe"})

    # Step 3: ML scoring
    vec           = vectorizer.transform([content])
    prob          = model.predict_proba(vec)[0]
    phishing_prob = prob[1] * 100

    if phishing_prob > 88:
        verdict = "Phishing"
    elif phishing_prob > 60:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    url = links[0] if links else None

    if url:
        parsed_domain = strip_www(urlparse(url).netloc)
        rep           = analyze_website(url)

        if is_trusted_domain(parsed_domain):
            # Trusted domain: only escalate if ML is overwhelmingly confident.
            # Raise thresholds — property/recommendation emails from real senders
            # can score 86-92% from the model (trained on Western spam, not Indian
            # real-estate/notification emails). We trust the domain, so we need
            # extreme confidence before overriding.
            if phishing_prob > 95 and rep["risk"] == "Phishing":
                verdict = "Phishing"
            elif phishing_prob > 93:
                verdict = "Suspicious"
            else:
                verdict = "Safe"
        else:
            # Unknown domain: fuse ML probability + URL risk analysis
            if rep["risk"] == "Phishing" and phishing_prob > 35:
                verdict = "Phishing"
            elif rep["risk"] == "Phishing" or (rep["risk"] == "Suspicious" and phishing_prob > 50):
                verdict = "Suspicious"
            elif phishing_prob > 60:
                verdict = "Suspicious"
            elif rep["risk"] == "Safe" and phishing_prob < 70:
                verdict = "Safe"

        return jsonify({"verdict": verdict, "url": url})

    # Step 4: No URL — banking notification check
    # (model over-flags these due to "account", "transaction", "bank" vocabulary)
    notification_count = sum(1 for w in BANKING_NOTIFICATION_WORDS if w in content_lower)
    if notification_count >= 2 and phishing_prob < 80:
        verdict = "Safe"

    return jsonify({"verdict": verdict})


# ── /report route ────────────────────────────────────────────
@app.route("/report")
def report():
    url = request.args.get("url", "").strip()
    if not url:
        return "No URL provided", 400

    rep      = analyze_website(url)
    safe_url = escape(url)

    # FIX: Apply the same trusted-domain override that /scan applies.
    # /scan uses ML fusion + trusted domain logic to determine the final verdict.
    # /report was previously only showing the raw analyze_website() score,
    # which caused popup="Safe" but report="Suspicious" for trusted domains
    # whose raw URL score happened to fall in the Suspicious band.
    #
    # Priority: explicit ?verdict= param (passed by content.js) > trusted domain > raw score
    popup_verdict = request.args.get("verdict", "").strip()
    if popup_verdict in ("Safe", "Suspicious", "Phishing"):
        # Use the verdict the popup already showed — keeps report consistent
        display_verdict = popup_verdict
    else:
        # Recalculate with the same trusted-domain logic
        parsed_host = urlparse(url).hostname or ""
        domain      = strip_www(parsed_host)
        if is_trusted_domain(domain) and rep["risk"] != "Phishing":
            display_verdict = "Safe"
        else:
            display_verdict = rep["risk"]

    # Use display_verdict for the badge color and label
    risk_color = {
        "Safe":       "#28a745",
        "Suspicious": "#ffc107",
        "Phishing":   "#dc3545"
    }.get(display_verdict, "#666")

    reasons_html = "".join(f"<li>{escape(r)}</li>" for r in rep.get("reasons", []))

    days_badge = (
        f"<span class='ssl-ok'>{rep['days_left']} days remaining</span>"
        if rep["days_left"] > 30 else
        f"<span class='ssl-warn'>Expiring soon ({rep['days_left']} days)</span>"
        if rep["days_left"] > 0 else
        "<span class='ssl-bad'>Expired or could not be verified</span>"
    )

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Website Security Report</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family:Arial,sans-serif; max-width:640px; margin:40px auto; padding:0 20px; color:#222; }}
        h2   {{ color:#333; border-bottom:2px solid #eee; padding-bottom:8px; }}
        .verdict    {{ display:inline-block; padding:6px 18px; border-radius:20px;
                       background:{risk_color}; color:#fff; font-weight:bold; font-size:16px; }}
        .score-bar  {{ background:#eee; border-radius:8px; height:14px; width:100%; margin:8px 0; }}
        .score-fill {{ background:{risk_color}; height:14px; border-radius:8px; width:{rep['score']}%; }}
        .field {{ margin:14px 0; }}
        .label {{ font-weight:bold; color:#555; font-size:12px; text-transform:uppercase; letter-spacing:0.5px; }}
        .value {{ font-size:15px; margin-top:3px; word-break:break-all; }}
        ul  {{ margin:6px 0; padding-left:20px; }}
        li  {{ margin:5px 0; font-size:14px; }}
        .ssl-ok   {{ color:#28a745; font-weight:bold; }}
        .ssl-warn {{ color:#e67e00; font-weight:bold; }}
        .ssl-bad  {{ color:#dc3545; font-weight:bold; }}
    </style>
</head>
<body>
    <h2>Website Security Report</h2>
    <div class="field">
        <div class="label">URL assessed</div>
        <div class="value">{safe_url}</div>
    </div>
    <div class="field">
        <div class="label">Safety verdict</div>
        <div class="value"><span class="verdict">{display_verdict}</span></div>
    </div>
    <div class="field">
        <div class="label">Safety score</div>
        <div class="score-bar"><div class="score-fill"></div></div>
        <div class="value">{rep['score']} / 100</div>
    </div>
    <div class="field">
        <div class="label">SSL certificate issuer</div>
        <div class="value">{escape(rep['issuer'])}</div>
    </div>
    <div class="field">
        <div class="label">Certificate validity</div>
        <div class="value">{days_badge}</div>
    </div>
    <div class="field">
        <div class="label">Analysis details</div>
        <ul>{reasons_html}</ul>
    </div>
</body>
</html>"""


# ── Run ──────────────────────────────────────────────────────
if __name__ == "__main__":
    # FIX: threaded=True so each request gets its own thread.
    # Without this, analyze_website()'s two blocking network calls (requests.get
    # + ssl.create_connection, up to 8s combined) block ALL other requests.
    # With threaded=True, email scan and link scan can run simultaneously.
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
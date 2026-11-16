import joblib
import os
import platform
from urllib.parse import urlparse

import pytesseract
from PIL import Image
import requests
from io import BytesIO

# Cross-platform Tesseract path
if platform.system() == "Windows":
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
# On Linux/Mac, tesseract is expected to be in PATH (brew install tesseract / apt install tesseract-ocr)

current_dir = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(os.path.join(current_dir, "model.pkl"))
vectorizer = joblib.load(os.path.join(current_dir, "vectorizer.pkl"))

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".link"]

SAFE_PATTERNS = [
    "transaction successful", "payment confirmed", "booking confirmed",
    "otp for", "one time password", "your account statement",
    "thank you for your purchase", "receipt for", "successfully transferred",
]

HARD_PHISHING_PATTERNS = [
    "verify your account immediately", "your account will be suspended",
    "update your payment details now", "confirm your identity to restore",
    "you have won", "claim your prize", "wire transfer required",
]


def extract_text_from_image_url(url):
    """Download an image by URL and extract text via OCR."""
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        img = Image.open(BytesIO(response.content)).convert("RGB")
        text = pytesseract.image_to_string(img, config="--psm 6")
        return text.strip()
    except Exception:
        return ""


def analyze_email(content, links):
    """
    Analyze email content + any image links.
    links may include external image URLs (sent from content.js when email is image-heavy).
    """
    reasons = []

    # OCR: attempt on image links (both embedded image URLs and attachment-style links)
    image_text_parts = []
    non_image_links = []

    for link in links:
        lower_link = link.lower()
        if any(lower_link.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".webp"]):
            ocr_text = extract_text_from_image_url(link)
            if ocr_text:
                image_text_parts.append(ocr_text)
        else:
            non_image_links.append(link)

    image_text = " ".join(image_text_parts)
    final_content = (content + " " + image_text).strip().lower()

    # Hard safe check
    if any(p in final_content for p in SAFE_PATTERNS):
        if not any(p in final_content for p in HARD_PHISHING_PATTERNS):
            return {
                "verdict": "Safe",
                "confidence": "99.00%",
                "reasons": ["Matches known safe transactional email pattern"]
            }

    # Rule-based feature injection (mirrors train_model.py feature engineering)
    if "urgent" in final_content:
        final_content += " urgent_flag"
        reasons.append("Urgency keyword detected")
    if "verify" in final_content:
        final_content += " verify_flag"
        reasons.append("Verification request detected")
    if "click here" in final_content:
        final_content += " click_flag"
        reasons.append("Suspicious call-to-action detected")
    if "password" in final_content:
        final_content += " password_flag"
        reasons.append("Password-related content found")
    if image_text:
        reasons.append("Text extracted from image content via OCR")

    # ML classification
    email_vector = vectorizer.transform([final_content])
    prediction = model.predict(email_vector)[0]
    probability = model.predict_proba(email_vector)[0]
    phishing_prob = probability[1] * 100
    confidence = max(probability) * 100

    # Domain TLD check
    for link in non_image_links:
        domain = urlparse(link).netloc.lower()
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                reasons.append(f"Suspicious TLD in link: {tld}")

    # Verdict
    if phishing_prob > 88:
        verdict = "Phishing"
        reasons.append("ML model strongly detected phishing signals")
    elif phishing_prob > 60:
        verdict = "Suspicious"
        reasons.append("ML model detected possible phishing signals")
    else:
        verdict = "Safe"

    return {
        "verdict": verdict,
        "confidence": f"{confidence:.2f}%",
        "reasons": reasons if reasons else ["ML model classified as safe"]
    }
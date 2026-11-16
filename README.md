# AI-Based Email Phishing Detection System

A Chrome extension and Flask backend that scan Gmail emails in real time and label each one **Safe**, **Suspicious** or **Phishing**. A link in an email is checked when you click it, before you're taken to the site.

The system is a **hybrid**. A machine-learning model reads the wording of the email, and a website analyser checks the links in it (URL structure, HTTPS, SSL certificate and redirects). A layer of rules sits in front of both to cut false alarms on genuine bank, shopping and property emails.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-REST%20API-000000?logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-Logistic%20Regression-F7931E?logo=scikitlearn&logoColor=white)
![Chrome](https://img.shields.io/badge/Chrome-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white)

---

## Features

- **Real-time Gmail scanning.** Open an email and a popup shows its verdict within seconds.
- **Link protection.** Clicking a link in an email is paused while the link is scanned. You can then continue, cancel, or open a full security report.
- **ML text classifier.** Logistic Regression on TF-IDF features, with **85% accuracy** on a held-out test set.
- **Website risk score (0–100).** Combines 10+ signals: raw-IP hosts, `@` in the URL, excessive hyphens and subdomains, brand spoofing, high-risk TLDs, suspicious path keywords, HTTPS, redirects, SSL certificate validity and expiry, and self-signed certificates.
- **Trusted-domain allowlist.** 114 Indian and global domains (banks, payments, e-commerce, travel, tech). Exact suffix matching means a look-alike such as `evil-hdfcbank.com` does **not** match `hdfcbank.com`.
- **False-positive reduction.** Rules recognise genuine transactional emails (OTPs, order confirmations, statements), marketing emails and property alerts before the ML model runs.
- **Security report page.** Shows the verdict, safety score, SSL issuer, days until the certificate expires, and every reason behind the score. All output is HTML-escaped to prevent XSS.

---

## How it works

```
Gmail email
    │  content.js extracts the email text (+ image alt text) and real links
    ▼
Chrome extension (Manifest V3)
    │  background.js → POST /scan  (7 s timeout)
    ▼
Flask API  /scan
    ├─ 1. Safe transactional patterns   → Safe (unless hard phishing phrases appear)
    ├─ 2. Promotional / property-alert   → Safe if the link is trusted
    ├─ 3. ML classifier                  → phishing probability
    ├─ 4. Website analysis (if a link)   → 0–100 risk score
    └─ 5. Fusion of 3 + 4                → Safe / Suspicious / Phishing
    ▼
Verdict popup in Gmail  ──►  /report?url=…  (full security report)
```

### Verdict thresholds

| Stage | Safe | Suspicious | Phishing |
|---|---|---|---|
| ML phishing probability | ≤ 60% | 60–88% | > 88% |
| Website safety score | ≥ 65 | 38–64 | < 38 |

For links on trusted domains, the ML thresholds are raised (93% for Suspicious, 95% plus a failed website check for Phishing). This is because the model was trained mostly on Western spam, so it tends to over-flag Indian notification emails.

---

## Model

| | |
|---|---|
| Algorithm | Logistic Regression (`C=3.0`, `class_weight="balanced"`) |
| Features | TF-IDF, 12,000 features, unigrams + bigrams |
| Extra signals | Hand-built flags: urgency, verify, click, password, bank/account, links, all-caps words, generic greetings, short messages |
| Class imbalance | Minority class upsampled to match the majority |
| Evaluation | 80/20 train/test split, **85.2% accuracy** |

---

## Tech stack

**Backend:** Python, Flask, Flask-CORS, scikit-learn, pandas, joblib, requests, `ssl`/`socket`
**Extension:** JavaScript, Chrome Extensions Manifest V3 (content script + service worker)
**Additional modules:** Tesseract OCR (`pytesseract`, Pillow), SQLite

---

## Project structure

```
AI-Based-Email-Phishing-Detection-System/
├── backend/
│   ├── app.py              # Flask API: /scan and /report, rules, website analysis, fusion logic
│   ├── train_model.py      # Training pipeline (cleaning, feature flags, balancing, TF-IDF, LR)
│   ├── model.pkl           # Trained classifier
│   ├── vectorizer.pkl      # Fitted TF-IDF vectorizer
│   ├── scanner.py          # OCR module: extracts text from email images with Tesseract
│   ├── database.py         # SQLite scan-log helpers (phishing.db)
│   ├── rules.py            # Keyword, domain and TLD lists
│   ├── templates/          # Scan-log dashboard page
│   └── requirements.txt
└── extension/
    ├── manifest.json       # Manifest V3 config
    ├── content.js          # Runs in Gmail: extracts email content, intercepts link clicks, shows popups
    ├── background.js       # Service worker: calls the Flask API
    └── style.css
```

---

## Getting started

### 1. Run the backend

```bash
cd backend
pip install -r requirements.txt
python app.py
```

The API starts at `http://127.0.0.1:5000`.

> **OCR (optional):** to use `scanner.py`, install Tesseract. On Windows the default path is `C:\Program Files\Tesseract-OCR\tesseract.exe`; on Linux run `sudo apt install tesseract-ocr`; on macOS run `brew install tesseract`.

### 2. Load the extension

1. Open `chrome://extensions` in Chrome.
2. Turn on **Developer mode**.
3. Click **Load unpacked** and select the `extension/` folder.
4. Open [Gmail](https://mail.google.com) and open any email.

### 3. (Optional) Retrain the model

Put your labelled CSV datasets in `backend/`. Each file needs the email text in its first column and the label in its last column (`spam`/`phishing` = 1, `ham`/`legitimate` = 0). Then run:

```bash
python train_model.py
```

This overwrites `model.pkl` and `vectorizer.pkl`.

---

## API

### `POST /scan`

```json
// Request
{ "content": "Your account will be suspended. Verify now…", "links": ["http://paypal-verify.xyz/login"] }

// Response
{ "verdict": "Phishing", "url": "http://paypal-verify.xyz/login" }
```

### `GET /report?url=<url>&verdict=<optional>`

Returns an HTML security report for the URL: verdict, 0–100 score, SSL issuer, certificate days remaining, and the reasons behind the score.

---

## Limitations and next steps

- The backend runs locally (`127.0.0.1`), so the extension only works on the machine running `app.py`.
- The model is trained mostly on English-language spam datasets. More Indian phishing samples would improve accuracy on local emails.
- Planned: connect the OCR (`scanner.py`) and scan-logging (`database.py`) modules to the main `/scan` route, add a `/logs` endpoint for the dashboard, and test transformer-based classifiers.

---

## Author

**Abhay Srinivas**, B.E. Computer Science and Engineering, BNM Institute of Technology
[Portfolio](https://p-coral-tau.vercel.app/) · [LinkedIn](https://www.linkedin.com/in/abhay-srinivas-7b46103b3/)

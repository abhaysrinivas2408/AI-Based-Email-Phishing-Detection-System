import pandas as pd
import glob
import os
import joblib
import re

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.utils import resample

print("RUNNING FINAL MODEL")

# ---------------- CLEAN TEXT ----------------
def clean_text(text):
    text = str(text).lower()

    # preserve info before cleaning
    has_url = " url_flag" if "http" in text else ""

    text = re.sub(r"http\S+", "", text)
    text = re.sub(r"\d+", " number ", text)
    text = re.sub(r"[^a-zA-Z ]", " ", text)

    return text + has_url


# ---------------- FEATURE ENGINEERING ----------------
def add_features(text):
    features = ""

    # 🔹 phishing indicators
    if "urgent" in text:
        features += " urgent_flag"
    if "verify" in text:
        features += " verify_flag"
    if "click" in text:
        features += " click_flag"
    if "password" in text:
        features += " password_flag"

    # bank handling 
    if "bank" in text:
        features += " bank_flag"
    if "account" in text:
        features += " account_flag"

    # 🔹 NEW SMART FEATURES
    if "http" in text:
        features += " has_link"
    if "@" in text:
        features += " email_symbol"

    # uppercase words
    if any(word.isupper() for word in text.split()):
        features += " caps_flag"

    # short suspicious messages
    if len(text) < 50:
        features += " short_msg"

    # 🔹 CONTEXT FEATURES (VERY IMPORTANT)
    if "dear customer" in text:
        features += " generic_greeting"

    if "dear " in text and "bank" not in text:
        features += " generic_mail"

    return text + features


# ---------------- LOAD DATA ----------------
current_dir = os.path.dirname(os.path.abspath(__file__))
csv_files = glob.glob(os.path.join(current_dir, "*.csv"))

dataframes = []

for file in csv_files:
    print("Loading:", file)
    df = pd.read_csv(file)

    df = df.iloc[:, [0, -1]]
    df.columns = ["text", "label"]

    dataframes.append(df)

if not dataframes:
    print("❌ No CSV files found!")
    exit()

data = pd.concat(dataframes, ignore_index=True)

# ---------------- CLEAN LABELS ----------------
data["label"] = data["label"].astype(str).str.lower()

data["label"] = data["label"].replace({
    "spam": 1,
    "phishing": 1,
    "ham": 0,
    "legitimate": 0
})

data["label"] = pd.to_numeric(data["label"], errors="coerce")
data.dropna(inplace=True)

# ---------------- TEXT PROCESSING ----------------
data["text"] = data["text"].apply(clean_text)
data["text"] = data["text"].apply(add_features)

print("\nClass distribution BEFORE balancing:")
print(data["label"].value_counts())

# ---------------- BALANCE DATA ----------------
majority = data[data.label == 0]
minority = data[data.label == 1]

if len(minority) > 0:
    minority_upsampled = resample(
        minority,
        replace=True,
        n_samples=len(majority),
        random_state=42
    )
    data = pd.concat([majority, minority_upsampled])

print("\nClass distribution AFTER balancing:")
print(data["label"].value_counts())

# ---------------- FEATURES ----------------
X = data["text"]
y = data["label"]

vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=12000,   # 🔥 increased
    ngram_range=(1, 2),   # 🔥 bigrams
    min_df=2,
    max_df=0.85
)

X_vectorized = vectorizer.fit_transform(X)

# ---------------- SPLIT ----------------
X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized,
    y,
    test_size=0.2,
    random_state=42
)

print("\nTraining samples:", X_train.shape[0])
print("Testing samples:", X_test.shape[0])

# ---------------- MODEL ----------------
model = LogisticRegression(
    max_iter=3000,
    C=3.0,
    class_weight="balanced"   
)

model.fit(X_train, y_train)

# ---------------- EVALUATION ----------------
accuracy = model.score(X_test, y_test)

print("\nAccuracy:", accuracy)
print("\nClassification Report:\n")
print(classification_report(y_test, model.predict(X_test)))

# ---------------- SAVE ----------------
joblib.dump(model, os.path.join(current_dir, "model.pkl"))
joblib.dump(vectorizer, os.path.join(current_dir, "vectorizer.pkl"))

print("\n✅ FINAL MODEL TRAINED & SAVED")

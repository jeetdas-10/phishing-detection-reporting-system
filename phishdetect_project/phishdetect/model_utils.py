# phishdetect/model_utils.py
import os
import joblib
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from phishdetect.config import MODEL_PATH

def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))

def build_model(name: str):
    if name == "logreg":
        clf = LogisticRegression(max_iter=1000, solver="liblinear", class_weight="balanced", random_state=42)
    elif name == "rf":
        clf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1)
    else:
        raise SystemExit(f"Unknown --clf '{name}'. Use 'logreg' or 'rf'.")
    return Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=50_000)),
        ("clf", clf)
    ])

def load_model(path: str = MODEL_PATH):
    if not os.path.exists(path):
        raise SystemExit(f"❌ Model not found at {path}")
    return joblib.load(path)

def get_probabilities(model, X):
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        if proba.shape[1] != 2:
            raise SystemExit("❌ Expected binary classifier with 2 probability columns.")
        return proba[:, 1]
    elif hasattr(model, "decision_function"):
        return _sigmoid(model.decision_function(X))
    else:
        raise SystemExit("❌ Model provides neither predict_proba nor decision_function.")

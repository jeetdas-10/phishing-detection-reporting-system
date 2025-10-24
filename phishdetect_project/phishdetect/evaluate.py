# phishdetect/evaluate.py
import argparse
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report, confusion_matrix
from phishdetect.model_utils import load_model, get_probabilities
from phishdetect.config import MODEL_PATH, DATA_DIR

def to_num_label(series):
    mapping = {"phish":1,"phishing":1,"malicious":1,"spam":1,"benign":0,"legit":0,"legitimate":0,"good":0,"safe":0,"0":0,"1":1}
    return series.astype(str).str.lower().map(lambda x: mapping.get(x, None))

def basic_eval(model_path, data_path):
    model = load_model(model_path)
    df = pd.read_csv(data_path).dropna(subset=["url","label"])
    X, y = df["url"].astype(str), to_num_label(df["label"])
    preds = model.predict(X)
    print("Accuracy:", accuracy_score(y, preds))
    if hasattr(model, "predict_proba"):
        print("ROC AUC:", roc_auc_score(y, get_probabilities(model, X)))
    print("Confusion matrix:\n", confusion_matrix(y, preds))
    print("Report:\n", classification_report(y, preds, digits=3, zero_division=0))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=MODEL_PATH)
    ap.add_argument("--data", default=f"{DATA_DIR}/test.csv")
    args = ap.parse_args()
    basic_eval(args.model, args.data)

if __name__ == "__main__":
    main()

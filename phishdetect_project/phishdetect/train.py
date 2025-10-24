# phishdetect/train.py
import os
import argparse
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, classification_report
from phishdetect.config import DATA_DIR, MODEL_PATH
from phishdetect.model_utils import build_model

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clf", default="logreg", choices=["logreg", "rf"],
                        help="Classifier to use: logreg or rf (default: logreg)")
    args = parser.parse_args()

    train = pd.read_csv(os.path.join(DATA_DIR, "train.csv")).dropna(subset=["url","label"])
    val   = pd.read_csv(os.path.join(DATA_DIR, "val.csv")).dropna(subset=["url","label"])

    X_train, y_train = train["url"].astype(str), train["label"]
    X_val,   y_val   = val["url"].astype(str),   val["label"]

    model = build_model(args.clf)
    print(f"🔨 Training with {args.clf} ...")
    model.fit(X_train, y_train)

    preds = model.predict(X_val)
    acc = accuracy_score(y_val, preds)
    print(f"\n✅ Validation Accuracy: {acc:.4f}")
    print("\nClassification Report:\n", classification_report(y_val, preds, digits=3, zero_division=0))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\n🎉 Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()

# phishdetect/predict.py
import argparse
import pandas as pd
import numpy as np
from phishdetect.config import MODEL_PATH, DEFAULT_THRESHOLD
from phishdetect.model_utils import load_model, get_probabilities
from phishdetect.domain_utils import registered_domain, load_allowlist

def predict_single(url, model, threshold, allowlist):
    dom = registered_domain(url)
    if dom in allowlist:
        print(f"Prediction: Benign (allowlist: {dom})")
        return
    p = float(get_probabilities(model, [url])[0])
    label = "Phishing" if p >= threshold else "Benign"
    print(f"Prediction: {label} (prob={p:.4f}, threshold={threshold:.2f})")

def predict_csv(path, model, threshold, out_path, allowlist):
    df = pd.read_csv(path)
    if "url" not in df.columns:
        raise SystemExit("❌ CSV must contain a 'url' column.")
    X = df["url"].astype(str)
    domains = X.map(registered_domain)
    probs = get_probabilities(model, X)
    preds = (probs >= threshold).astype(int)
    preds[domains.isin(allowlist)] = 0

    out = df.copy()
    out["domain"] = domains
    out["prob_phish"] = probs
    out["pred"] = preds
    out["pred_label"] = np.where(preds == 1, "phish", "benign")
    if out_path:
        out.to_csv(out_path, index=False)
        print(f"💾 Saved predictions to {out_path}")
    else:
        print(out.head(10))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?")
    ap.add_argument("--csv")
    ap.add_argument("--out")
    ap.add_argument("--model", default=MODEL_PATH)
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--allowlist")
    args = ap.parse_args()

    model = load_model(args.model)
    allow = load_allowlist(args.allowlist)

    if args.csv:
        predict_csv(args.csv, model, args.threshold, args.out, allow)
    elif args.url:
        predict_single(args.url, model, args.threshold, allow)
    else:
        ap.print_help()

if __name__ == "__main__":
    main()

"""
Train the XGBoost triage classifier.

    python scripts/train_triage.py

The training data is generated from the labelled attack / false-positive
patterns validated in the FYP1 prototype (six detection rules from the lab
environment). Each sample is the same 5-feature vector that
TriageAgent._extract_features produces at inference time:

    [rule_encoded, risk_score, severity_num, has_keyword, request_count]

The model is a binary classifier (1 = true positive) trained with
binary:logistic, so Booster.predict() returns the TP probability directly --
that probability is the `confidence` the pipeline routes on.

Saves:
    XGBOOST_MODEL_PATH  (data/models/triage_xgb.json)  -- the booster
    RULE_MAP_PATH       (data/models/rule_map.json)    -- rule-name encoding
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings

try:
    import pandas as pd
    import xgboost as xgb
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
except ImportError:
    print("Install xgboost, scikit-learn and pandas first.")
    sys.exit(1)

RULE_MAP = {
    "SQL Injection Detected": 1,
    "XSS Attack Detected": 2,
    "Command Injection Detected": 3,
    "File Inclusion Detected": 4,
    "Port Scan Detected": 5,
    "SSH Brute Force Detected": 6,
}

FEATURES = ["rule_encoded", "risk_score", "severity_num", "has_keyword", "request_count"]


def generate_training_data() -> pd.DataFrame:
    """Labelled dataset from the attack patterns observed in the lab.
    label 1 = true positive (real attack), 0 = false positive."""
    attack_patterns = [
        {"rule": "SQL Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 1, "request_count": 10, "label": 1},
        {"rule": "SQL Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 1, "request_count": 50, "label": 1},
        {"rule": "SQL Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 1, "request_count": 100, "label": 1},
        {"rule": "SQL Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 1, "request_count": 200, "label": 1},
        {"rule": "XSS Attack Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 1, "request_count": 5, "label": 1},
        {"rule": "XSS Attack Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 1, "request_count": 20, "label": 1},
        {"rule": "XSS Attack Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 1, "request_count": 8, "label": 1},
        {"rule": "Command Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 1, "request_count": 10, "label": 1},
        {"rule": "Command Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 1, "request_count": 30, "label": 1},
        {"rule": "Command Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 1, "request_count": 15, "label": 1},
        {"rule": "Command Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 1, "request_count": 25, "label": 1},
        {"rule": "File Inclusion Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 1, "request_count": 5, "label": 1},
        {"rule": "File Inclusion Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 1, "request_count": 12, "label": 1},
        {"rule": "File Inclusion Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 1, "request_count": 8, "label": 1},
        {"rule": "Port Scan Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 1, "request_count": 1000, "label": 1},
        {"rule": "Port Scan Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 1, "request_count": 500, "label": 1},
        {"rule": "SSH Brute Force Detected", "risk_score": 90, "severity_num": 4, "has_keyword": 1, "request_count": 100, "label": 1},
        {"rule": "SSH Brute Force Detected", "risk_score": 90, "severity_num": 4, "has_keyword": 1, "request_count": 500, "label": 1},
        {"rule": "SSH Brute Force Detected", "risk_score": 90, "severity_num": 4, "has_keyword": 1, "request_count": 50, "label": 1},
        {"rule": "SSH Brute Force Detected", "risk_score": 90, "severity_num": 4, "has_keyword": 1, "request_count": 1000, "label": 1},
    ]
    normal_patterns = [
        {"rule": "SQL Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 0, "request_count": 1, "label": 0},
        {"rule": "SQL Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 0, "request_count": 2, "label": 0},
        {"rule": "SQL Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 0, "request_count": 1, "label": 0},
        {"rule": "SQL Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 0, "request_count": 3, "label": 0},
        {"rule": "XSS Attack Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 0, "request_count": 1, "label": 0},
        {"rule": "XSS Attack Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 0, "request_count": 1, "label": 0},
        {"rule": "XSS Attack Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 0, "request_count": 2, "label": 0},
        {"rule": "XSS Attack Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 0, "request_count": 1, "label": 0},
        {"rule": "Command Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 0, "request_count": 1, "label": 0},
        {"rule": "Command Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 0, "request_count": 2, "label": 0},
        {"rule": "Command Injection Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 0, "request_count": 1, "label": 0},
        {"rule": "File Inclusion Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 0, "request_count": 1, "label": 0},
        {"rule": "File Inclusion Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 0, "request_count": 1, "label": 0},
        {"rule": "File Inclusion Detected", "risk_score": 73, "severity_num": 3, "has_keyword": 0, "request_count": 2, "label": 0},
        {"rule": "Port Scan Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 0, "request_count": 3, "label": 0},
        {"rule": "Port Scan Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 0, "request_count": 5, "label": 0},
        {"rule": "Port Scan Detected", "risk_score": 50, "severity_num": 2, "has_keyword": 0, "request_count": 2, "label": 0},
        {"rule": "SSH Brute Force Detected", "risk_score": 90, "severity_num": 4, "has_keyword": 0, "request_count": 2, "label": 0},
        {"rule": "SSH Brute Force Detected", "risk_score": 90, "severity_num": 4, "has_keyword": 0, "request_count": 3, "label": 0},
        {"rule": "SSH Brute Force Detected", "risk_score": 90, "severity_num": 4, "has_keyword": 1, "request_count": 3, "label": 0},
    ]

    rows = []
    for p in attack_patterns + normal_patterns:
        rows.append({
            "rule_encoded": RULE_MAP.get(p["rule"], 0),
            "risk_score": p["risk_score"],
            "severity_num": p["severity_num"],
            "has_keyword": p["has_keyword"],
            "request_count": p["request_count"],
            "label": p["label"],
        })
    return pd.DataFrame(rows)


def load_csv(path: str) -> "pd.DataFrame":
    """Load a labelled CSV exported by scripts/export_training_set.py.
    Only the model FEATURES + label are used; any extra columns (behavioural
    features, etc.) are ignored, and source_ip is intentionally not present."""
    df = pd.read_csv(path)
    missing = [c for c in FEATURES + ["label"] if c not in df.columns]
    if missing:
        raise SystemExit(f"CSV is missing required columns: {missing}")
    return df[FEATURES + ["label"]]


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", help="labelled CSV (from export_training_set.py); "
                                    "default uses the built-in synthetic patterns")
    args = ap.parse_args()

    if args.data:
        print(f"Loading training data from {args.data} ...")
        df = load_csv(args.data)
    else:
        print("Generating training data from labelled attack patterns...")
        df = generate_training_data()
    X, y = df[FEATURES], df["label"]

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    print(f"Training samples: {len(X_tr)}  |  Testing samples: {len(X_te)}")

    model = xgb.XGBClassifier(
        n_estimators=100, max_depth=4, learning_rate=0.1,
        objective="binary:logistic", eval_metric="logloss", random_state=42,
    )
    model.fit(X_tr, y_tr)

    y_pred = model.predict(X_te)
    print(f"\nAccuracy: {accuracy_score(y_te, y_pred):.3f}")
    print("\nClassification report:")
    print(classification_report(y_te, y_pred, target_names=["False Positive", "True Positive"]))
    print("Confusion matrix:")
    print(confusion_matrix(y_te, y_pred))

    print("\nFeature importance:")
    for feat, imp in sorted(zip(FEATURES, model.feature_importances_),
                            key=lambda x: x[1], reverse=True):
        print(f"  {feat}: {imp:.4f}")

    os.makedirs(os.path.dirname(settings.XGBOOST_MODEL_PATH), exist_ok=True)
    model.get_booster().save_model(settings.XGBOOST_MODEL_PATH)
    with open(settings.RULE_MAP_PATH, "w") as fh:
        json.dump(RULE_MAP, fh, indent=2)
    print(f"\nSaved model to {settings.XGBOOST_MODEL_PATH}")
    print(f"Saved rule map to {settings.RULE_MAP_PATH}")


if __name__ == "__main__":
    main()

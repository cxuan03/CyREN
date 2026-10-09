# -*- coding: utf-8 -*-
"""Measure CyREN's evaluation metrics for the FYP report, in one place:

  * MTTD  Mean Time To Detect   = when CyREN created the event  -  the attack's
          own log time (Event.ingested_at - Event.first_seen). How long after
          the malicious activity CyREN raised it as an event.
  * MTTR  Mean Time To Respond  = when the firewall block was applied  -  when
          the event was detected (BlockedIP.created_at - Event.ingested_at).
          How long from detection to automatic containment.
  * Classification accuracy of the XGBoost triage model on a held-out test set
          (same 70/30 stratified split as objective3_classifier_comparison).

MTTD and MTTR read CyREN's own database, so they work with filebeat-direct
ingest (no Kibana alert engine needed). Run a fresh attack, then:

    venv\\Scripts\\python.exe scripts\\measure_metrics.py
    ... --hours 24        # only events ingested in the last N hours
    ... --no-accuracy     # skip the model evaluation (DB metrics only)
"""
import argparse
import os
import sys
import statistics as st
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fmt(seconds):
    if seconds < 90:
        return f"{seconds:.1f}s"
    if seconds < 5400:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} h"


def _summary(name, vals, unit_fmt=_fmt):
    if not vals:
        print(f"  {name}: no data")
        return
    vals = sorted(vals)
    p95 = vals[max(0, int(0.95 * len(vals)) - 1)]
    print(f"  {name}: n={len(vals)}  mean={unit_fmt(st.mean(vals))}  "
          f"median={unit_fmt(st.median(vals))}  min={unit_fmt(vals[0])}  "
          f"max={unit_fmt(vals[-1])}  p95={unit_fmt(p95)}")


def measure_db(hours):
    from app import create_app
    from app.models.db import Event, BlockedIP
    app = create_app()
    with app.app_context():
        since = datetime.utcnow() - timedelta(hours=hours) if hours else None

        evq = Event.query
        if since:
            evq = evq.filter(Event.ingested_at >= since)
        events = evq.all()
        by_id = {e.id: e for e in events}

        # ---- MTTD ----
        print("\n=== MTTD  (Mean Time To Detect: attack time -> event created) ===")
        mttd = []
        for e in events:
            if e.first_seen and e.ingested_at:
                d = (e.ingested_at - e.first_seen).total_seconds()
                if 0 <= d < 7 * 86400:          # ignore clock-skew negatives / stale
                    mttd.append(d)
        _summary("MTTD", mttd)

        # ---- MTTR ----
        print("\n=== MTTR  (Mean Time To Respond: detection -> firewall block) ===")
        blq = BlockedIP.query
        if since:
            blq = blq.filter(BlockedIP.created_at >= since)
        mttr = []
        for b in blq.all():
            e = by_id.get(b.event_id) or (Event.query.get(b.event_id) if b.event_id else None)
            if e and e.ingested_at and b.created_at:
                d = (b.created_at - e.ingested_at).total_seconds()
                if 0 <= d < 7 * 86400:
                    mttr.append(d)
        _summary("MTTR", mttr)
        # end-to-end: attack time -> block
        e2e = []
        for b in blq.all():
            e = by_id.get(b.event_id) or (Event.query.get(b.event_id) if b.event_id else None)
            if e and e.first_seen and b.created_at:
                d = (b.created_at - e.first_seen).total_seconds()
                if 0 <= d < 7 * 86400:
                    e2e.append(d)
        _summary("End-to-end (attack -> contained)", e2e)


def measure_accuracy():
    print("\n=== Classification accuracy  (XGBoost triage, held-out test set) ===")
    try:
        import pandas as pd
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                      f1_score, roc_auc_score, confusion_matrix)
        from xgboost import XGBClassifier
    except ImportError as exc:
        print(f"  skipped (missing library: {exc}).")
        return

    csv = None
    for p in ("data/training_set.csv", "../data/training_set.csv"):
        if os.path.exists(p):
            csv = p; break
    if csv is None:
        print("  skipped (data/training_set.csv not found; run scripts/export_training_set.py).")
        return

    df = pd.read_csv(csv)
    FEATURES = ["rule_encoded", "risk_score", "severity_num", "has_keyword",
                "request_count", "duration_seconds", "request_rate_per_min"]
    FEATURES = [f for f in FEATURES if f in df.columns]
    X, y = df[FEATURES], df["label"]
    print(f"  dataset: {len(df)} rows  ({int((y == 1).sum())} attack / {int((y == 0).sum())} benign)")

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.30, stratify=y, random_state=42)
    clf = XGBClassifier(n_estimators=200, max_depth=3, learning_rate=0.1,
                        subsample=0.9, eval_metric="logloss", random_state=42)
    clf.fit(Xtr, ytr)
    yp = clf.predict(Xte)
    proba = clf.predict_proba(Xte)[:, 1]
    print(f"  test set: {len(Xte)} rows")
    print(f"  accuracy  = {accuracy_score(yte, yp):.3f}")
    print(f"  precision = {precision_score(yte, yp, zero_division=0):.3f}")
    print(f"  recall    = {recall_score(yte, yp, zero_division=0):.3f}")
    print(f"  F1        = {f1_score(yte, yp, zero_division=0):.3f}")
    try:
        print(f"  ROC-AUC   = {roc_auc_score(yte, proba):.3f}")
    except ValueError:
        pass
    tn, fp, fn, tp = confusion_matrix(yte, yp, labels=[0, 1]).ravel()
    print(f"  confusion : TP={tp} FP={fp} FN={fn} TN={tn}")
    print("  (full comparison vs RandomForest/etc: notebooks/objective3_classifier_comparison.ipynb)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=None, help="only events/blocks in the last N hours")
    ap.add_argument("--no-accuracy", action="store_true", help="skip the model evaluation")
    args = ap.parse_args()
    measure_db(args.hours)
    if not args.no_accuracy:
        measure_accuracy()
    print()


if __name__ == "__main__":
    main()

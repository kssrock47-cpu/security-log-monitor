"""Step 4-5: two detectors, one explanation helper.

* Isolation Forest: unsupervised, needs no labels.
* Random Forest: supervised, needs labelled blocks (Normal / Anomaly).
"""
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score


def time_split(n: int, train_frac: float = 0.7):
    """Blocks are already sorted oldest -> newest. First part trains, last part tests."""
    cut = max(1, min(n - 1, int(n * train_frac)))
    return np.arange(0, cut), np.arange(cut, n)


def run_isolation_forest(X, train_idx, contamination=0.03, seed=42):
    """Fit on the older blocks only (no labels used). Returns score (higher = more unusual)."""
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    model.fit(X[train_idx])
    score = -model.score_samples(X)           # higher = more anomalous
    thr = np.quantile(-model.score_samples(X[train_idx]), 1 - contamination)
    flagged = score > thr
    return score, flagged, model, float(thr)


def run_random_forest(X, y, train_idx, seed=42):
    """Fit on labelled older blocks. Returns probability of 'Anomaly' and flagged mask."""
    model = RandomForestClassifier(
        n_estimators=200, class_weight="balanced", random_state=seed, n_jobs=-1
    )
    model.fit(X[train_idx], y[train_idx])
    proba = model.predict_proba(X)[:, list(model.classes_).index(1)] if 1 in model.classes_ else np.zeros(len(X))
    return proba, proba >= 0.5, model


def scores(y_true, flagged):
    return (
        precision_score(y_true, flagged, zero_division=0),
        recall_score(y_true, flagged, zero_division=0),
        f1_score(y_true, flagged, zero_division=0),
    )


def severity(score, flagged, high_q):
    if not flagged:
        return "Normal"
    return "High" if score >= high_q else "Medium"


def explain_block(block_id, counts_row: pd.Series, templates: dict, normal_presence: pd.Series,
                  rare_below=0.05, usual_above=0.95, n_show=3):
    """Plain-language reason built only from the data.

    normal_presence[tid] = share of normal (training) blocks that contain that event type.
    Reason 1: the block has event types that are rare in normal blocks.
    Reason 2: the block lacks event types that almost every normal block has.
    """
    def short(tid):
        t = templates.get(tid, "?")
        return t if len(t) <= 90 else t[:87] + "..."

    present = counts_row[counts_row > 0].index
    rare = sorted(((normal_presence.get(t, 0.0), t) for t in present if normal_presence.get(t, 0.0) < rare_below))
    missing = [t for t in normal_presence.index if normal_presence[t] >= usual_above and counts_row.get(t, 0) == 0]
    parts = []
    if rare:
        items = "; ".join(
            f'"{short(t)}" ({"never seen in normal blocks" if sh == 0 else f"in only {sh * 100:.1f}% of normal blocks"})'
            for sh, t in rare[:n_show])
        parts.append("Rare events: " + items + ".")
    if missing:
        items = "; ".join(f'"{short(t)}"' for t in missing[:n_show])
        parts.append("Missing events that normal blocks almost always have: " + items + ".")
    if not parts:
        parts.append("The mix of event counts is unusual compared with normal blocks.")
    return " ".join(parts)


def now_iso():
    return datetime.now().isoformat(timespec="seconds")

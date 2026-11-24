"""Compare existing machine-learning techniques for log anomaly detection on the same data.

The eight methods are the standard set from the log-analysis benchmark of He et al. (2016),
"Experience Report: System Log Analysis for Anomaly Detection" (ISSRE), run here with scikit-learn:

  learn from labelled examples (supervised)   Logistic Regression, Decision Tree, linear SVM, Random Forest
  learn only what normal looks like (unsupervised)   Isolation Forest, PCA, One-Class SVM, Local Outlier Factor

All use the same input (how often each message type appears in each storage task, log-scaled),
the same time-ordered split (train on the older 70%, test on the newer 30%), and the unsupervised ones
the same alert line (the 97th percentile of their score on the training tasks, as in the main pipeline).

    python -m seclog.compare                 # uses data/seclog.db from the full HDFS_v1 run
"""
import argparse
import json
import os
import sqlite3
import time
from contextlib import closing

import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import LinearSVC, OneClassSVM
from sklearn.tree import DecisionTreeClassifier

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(HERE, "data", "seclog.db")
CONTAMINATION = 0.03
SUBSAMPLE = 20000  # One-Class SVM and LOF scale badly with size; they learn from a random sample of the older tasks

PLAIN = {
    "Logistic Regression": "Weighs each message type and adds them up",
    "Decision Tree": "A chain of yes/no questions about the counts",
    "Linear SVM": "Draws the widest possible line between normal and problem tasks",
    "Random Forest": "200 decision trees vote",
    "Isolation Forest": "Unusual tasks are easier to separate from the rest",
    "PCA": "Normal tasks follow a few main patterns; problems don't fit them",
    "One-Class SVM": "Draws a boundary around normal tasks",
    "Local Outlier Factor": "Problem tasks sit in sparse areas, far from their neighbours",
}


def load(db=DB, progress=print):
    """Rebuild the task x message-type count matrix from the results database (same order as the pipeline)."""
    t0 = time.time()
    with closing(sqlite3.connect(db)) as con:
        blocks = con.execute("select block_id, split, label from blocks order by rowid").fetchall()  # stored oldest first, as sorted
        tids = [r[0] for r in con.execute("select template_id from templates order by template_id")]
        progress(f"  {len(blocks):,} tasks, {len(tids)} message types; counting messages per task…")
        row = {b: i for i, (b, _, _) in enumerate(blocks)}
        col = {t: j for j, t in enumerate(tids)}
        counts = np.zeros((len(blocks), len(tids)), dtype=np.float32)
        cur = con.execute("select block_id, template_id, count(*) from log_events group by block_id, template_id")
        while True:
            chunk = cur.fetchmany(200000)
            if not chunk:
                break
            for b, t, n in chunk:
                i = row.get(b)
                if i is not None and t in col:
                    counts[i, col[t]] = n
    split = np.array([s for _, s, _ in blocks])
    y = np.array([1 if l == "Anomaly" else 0 for _, _, l in blocks])
    progress(f"  loaded in {time.time() - t0:.0f} s")
    return np.log1p(counts), y, np.where(split == "train")[0], np.where(split == "test")[0]


def _unsup_flags(score_train, score_all):
    thr = np.quantile(score_train, 1 - CONTAMINATION)
    return score_all > thr


def run(db=DB, seed=42, progress=print, out_json=None):
    X, y, tr, te = load(db, progress)
    rng = np.random.default_rng(seed)
    sub = rng.choice(tr, size=min(SUBSAMPLE, len(tr)), replace=False)
    results = []

    def record(name, kind, flags_test, score_test, t_fit, t_pred, note=""):
        yt = y[te]
        p, r = precision_score(yt, flags_test, zero_division=0), recall_score(yt, flags_test, zero_division=0)
        results.append({
            "model": name, "kind": kind, "plain": PLAIN[name],
            "precision": round(float(p), 4), "recall": round(float(r), 4),
            "f1": round(float(f1_score(yt, flags_test, zero_division=0)), 4),
            "pr_auc": round(float(average_precision_score(yt, score_test)), 4),
            "caught": int((flags_test & (yt == 1)).sum()), "real": int(yt.sum()),
            "false_alarms": int((flags_test & (yt == 0)).sum()), "n_train": int(len(tr)), "n_test": int(len(te)),
            "train_seconds": round(t_fit, 1), "check_seconds": round(t_pred, 1), "note": note})
        x = results[-1]
        progress(f"  {name:22s} P {x['precision']:.3f}  R {x['recall']:.3f}  F1 {x['f1']:.3f}  "
                 f"false alarms {x['false_alarms']:,}  ({t_fit:.0f} s to learn)")

    # ---- supervised: learn from labelled older tasks
    sup = [("Logistic Regression", LogisticRegression(class_weight="balanced", max_iter=2000)),
           ("Decision Tree", DecisionTreeClassifier(class_weight="balanced", random_state=seed)),
           ("Linear SVM", LinearSVC(class_weight="balanced", random_state=seed, max_iter=5000)),
           ("Random Forest", RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=seed, n_jobs=-1))]
    for name, m in sup:
        t0 = time.time()
        m.fit(X[tr], y[tr])
        t1 = time.time()
        if hasattr(m, "decision_function"):
            score = m.decision_function(X[te])
            flags = score > 0
        else:  # same rule as the main pipeline: alert when the chance of a problem is at least 50%
            score = m.predict_proba(X[te])[:, list(m.classes_).index(1)]
            flags = score >= 0.5
        record(name, "supervised", flags, score, t1 - t0, time.time() - t1)

    # ---- unsupervised: learn only what the older tasks look like (labels never used)
    t0 = time.time()
    m = IsolationForest(n_estimators=200, contamination=CONTAMINATION, random_state=seed).fit(X[tr])
    t1 = time.time()
    s_tr, s_te = -m.score_samples(X[tr]), -m.score_samples(X[te])
    record("Isolation Forest", "unsupervised", _unsup_flags(s_tr, s_te), s_te, t1 - t0, time.time() - t1)

    t0 = time.time()
    mu = X[tr].mean(axis=0)
    pca = PCA(n_components=0.95, svd_solver="full", random_state=seed).fit(X[tr] - mu)
    t1 = time.time()
    def spe(A):  # squared prediction error: what the main patterns can't explain
        Z = A - mu
        return ((Z - pca.inverse_transform(pca.transform(Z))) ** 2).sum(axis=1)
    s_tr, s_te = spe(X[tr]), spe(X[te])
    record("PCA", "unsupervised", _unsup_flags(s_tr, s_te), s_te, t1 - t0, time.time() - t1,
           f"{pca.n_components_} main patterns keep 95% of the variation")

    t0 = time.time()
    m = OneClassSVM(nu=CONTAMINATION, kernel="rbf", gamma="scale").fit(X[sub])
    t1 = time.time()
    s_tr, s_te = -m.decision_function(X[sub]), -m.decision_function(X[te])
    record("One-Class SVM", "unsupervised", _unsup_flags(s_tr, s_te), s_te, t1 - t0, time.time() - t1,
           f"learned from a random {len(sub):,} of the older tasks")

    t0 = time.time()
    m = LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=CONTAMINATION).fit(X[sub])
    t1 = time.time()
    s_tr, s_te = -m.negative_outlier_factor_, -m.score_samples(X[te])  # training scores without counting itself
    record("Local Outlier Factor", "unsupervised", _unsup_flags(s_tr, s_te), s_te, t1 - t0, time.time() - t1,
           f"learned from a random {len(sub):,} of the older tasks")

    out = {"dataset": "HDFS_v1", "split": "older 70% to learn, newer 30% to test", "contamination": CONTAMINATION,
           "run_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "results": results}
    with closing(sqlite3.connect(db)) as con:
        con.execute("drop table if exists comparison")
        con.execute("create table comparison (run_at TEXT, data TEXT)")
        con.execute("insert into comparison values (?, ?)", (out["run_at"], json.dumps(out)))
        con.commit()
    out_json = out_json or os.path.join(HERE, "data", "eval", "compare.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    with open(out_json, "w") as f:
        json.dump(out, f, indent=2)
    return out


def main():
    ap = argparse.ArgumentParser(description="Compare 8 machine-learning techniques on the HDFS_v1 results.")
    ap.add_argument("--db", default=DB)
    a = ap.parse_args()
    print(f"Comparing 8 techniques on {a.db}")
    run(a.db)
    print("Saved data/eval/compare.json and the 'comparison' table")


if __name__ == "__main__":
    main()

"""Run the whole offline flow: parse -> store -> features -> two models -> alerts."""
import argparse
import os
import sqlite3
from contextlib import closing

import joblib
import numpy as np
import pandas as pd

from . import features, models, store
from .parse import parse_file


def load_labels(path: str | None):
    """HDFS_v1 label file: BlockId,Label with Normal / Anomaly."""
    if not path:
        return None
    df = pd.read_csv(path)
    cols = {c.lower(): c for c in df.columns}
    b, l = cols.get("blockid"), cols.get("label")
    if not b or not l:
        raise ValueError("Label file needs columns BlockId and Label")
    return dict(zip(df[b], df[l]))


def model_path(db_path: str) -> str:
    return os.path.splitext(db_path)[0] + ".models.joblib"


def run(log_path: str, db_path: str, labels_path: str | None = None,
        max_lines: int | None = None, contamination: float = 0.03, train_frac: float = 0.7,
        demo: bool = False) -> dict:
    labels = load_labels(labels_path)
    events, templates, miner = parse_file(log_path, max_lines, return_miner=True)
    if not events:
        raise ValueError("No HDFS-format log lines with a block id were found.")

    blocks = features.build_blocks(events, labels)
    tids = sorted(templates)
    counts = features.count_matrix(events, blocks, tids)
    X = features.to_model_input(counts)
    train_idx, test_idx = models.time_split(len(blocks), train_frac)
    blocks["split"] = ["train" if i in set(train_idx.tolist()) else "test" for i in range(len(blocks))]

    labelled = labels is not None and blocks["label"].notna().all() and blocks["label"].nunique() > 1
    y = (blocks["label"] == "Anomaly").astype(int).values if labelled else None

    results = {}
    if_score, if_flag, if_model, if_thr = models.run_isolation_forest(X, train_idx, contamination)
    results["Isolation Forest"] = (if_score, if_flag)
    rf_model = None
    if labelled and len(set(y[train_idx])) > 1:
        rf_score, rf_flag, rf_model = models.run_random_forest(X, y, train_idx)
        results["Random Forest"] = (rf_score, rf_flag)

    # "Normal" profile for explanations: which event types normal training blocks contain.
    normal_mask = np.zeros(len(blocks), dtype=bool)
    normal_mask[train_idx] = True
    if labelled:
        normal_mask &= (y == 0)
    normal_presence = (counts[normal_mask] > 0).mean() if normal_mask.any() else pd.Series(dtype=float)

    # Profile of a normal block, used to tell the story of each alert in plain words.
    normal_counts = counts[normal_mask] if normal_mask.any() else counts
    normal_median = normal_counts.median()
    ev = pd.DataFrame([(e.block_id, e.line_no, e.template_id) for e in events],
                      columns=["block_id", "line_no", "template_id"]).sort_values(["block_id", "line_no"])
    ev["pos"] = ev.groupby("block_id").cumcount()
    first = ev.groupby(["block_id", "template_id"])["pos"].min().reset_index()
    normal_ids = set(blocks.loc[normal_mask, "block_id"])
    typical_pos = first[first["block_id"].isin(normal_ids)].groupby("template_id")["pos"].median()
    stats_rows = [(int(t), float(normal_presence.get(t, 0.0)), float(normal_median.get(t, 0.0)),
                   float(typical_pos[t]) if t in typical_pos.index else None) for t in tids]

    stamp = models.now_iso()
    alerts, runs = [], []
    for name, (score, flag) in results.items():
        high_q = np.quantile(score[flag], 0.75) if flag.any() else np.inf
        for i, bid in enumerate(blocks["block_id"]):
            sev = models.severity(score[i], bool(flag[i]), high_q)
            reason = models.explain_block(bid, counts.iloc[i], templates, normal_presence) if flag[i] else ""
            alerts.append((bid, name, float(score[i]), int(flag[i]), sev, reason))
        if labelled:
            p, r, f = models.scores(y[test_idx], flag[test_idx])
            runs.append((name, 1, len(train_idx), len(test_idx), p, r, f, stamp))
        else:
            runs.append((name, 0, len(train_idx), len(test_idx), None, None, None, stamp))

    store.reset(db_path)
    with closing(store.connect(db_path)) as con:
        store.insert_many(con, "log_events",
            ((e.line_no, e.block_id, e.ts, e.level, e.component, e.template_id, e.content) for e in events), 7)
        store.insert_many(con, "templates", templates.items(), 2)
        store.insert_many(con, "blocks",
            ((r.block_id, r.first_ts, int(r.n_events), r.label if isinstance(r.label, str) else None, r.split)
             for r in blocks.itertuples()), 5)
        store.insert_many(con, "alerts", alerts, 6)
        store.insert_many(con, "model_runs", runs, 8)
        store.insert_many(con, "template_stats", stats_rows, 4)
        store.insert_many(con, "meta", [("source", os.path.basename(log_path)), ("demo", "1" if demo else "0"),
                                          ("run_at", stamp), ("contamination", str(contamination)),
                                          ("log_path", os.path.abspath(log_path)), ("if_threshold", str(if_thr)),
                                          ("rf_threshold", "0.5"), ("labelled", "1" if labelled else "0"),
                                          ("test_start", str(blocks.loc[test_idx[0], "first_ts"]))], 2)
        con.commit()

    # Save the trained parts so live mode can parse and score new lines the same way.
    joblib.dump({"tids": tids, "templates": templates, "miner": miner, "if_model": if_model, "if_thr": if_thr,
                 "rf_model": rf_model, "stats_rows": stats_rows, "run_at": stamp},
                model_path(db_path))

    return {"lines_used": len(events), "blocks": len(blocks), "templates": len(templates),
            "labelled": bool(labelled), "flagged": {k: int(v[1].sum()) for k, v in results.items()}}


def main():
    ap = argparse.ArgumentParser(description="Offline log analysis: parse, detect, store alerts.")
    ap.add_argument("--log", required=True, help="HDFS log file (e.g. HDFS.log or HDFS_2k.log)")
    ap.add_argument("--labels", help="Optional anomaly_label.csv (BlockId,Label) from HDFS_v1")
    ap.add_argument("--db", default="data/seclog.db")
    ap.add_argument("--max-lines", type=int)
    ap.add_argument("--contamination", type=float, default=0.03)
    ap.add_argument("--demo", action="store_true", help="Mark the data as synthetic demo data")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.db) or ".", exist_ok=True)
    print(run(a.log, a.db, a.labels, a.max_lines, a.contamination, demo=a.demo))


if __name__ == "__main__":
    main()

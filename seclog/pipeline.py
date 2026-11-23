"""Run the whole offline flow: parse -> store -> features -> two models -> alerts.

Memory-lean: raw lines are written to SQLite while reading, and only integer arrays stay
in memory, so the full HDFS_v1 file (about 11 million lines) fits on a normal laptop.
"""
import argparse
import json
import os
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

from . import models, store
from .parse import parse_to_db


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


def _say(progress, msg):
    if progress:
        progress(msg)


def run(log_path: str, db_path: str, labels_path: str | None = None,
        max_lines: int | None = None, contamination: float = 0.03, train_frac: float = 0.7,
        demo: bool = False, progress=None) -> dict:
    t0 = time.time()
    labels = load_labels(labels_path)
    tmp_db = db_path + ".building"
    if os.path.exists(tmp_db):
        os.remove(tmp_db)
    store.reset(tmp_db)  # build into a new file, so the dashboard keeps working until we're done
    con = store.connect(tmp_db)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")

    _say(progress, "Reading the log and sorting lines into message types…")
    P = parse_to_db(log_path, con, max_lines)
    if len(P["block"]) == 0:
        con.close()
        raise ValueError("No HDFS-format log lines with a block id were found.")
    templates, tids = P["templates"], sorted(P["templates"])
    nb, nt = len(P["block_ids"]), len(tids)
    col = np.zeros(max(tids) + 1, dtype=np.int64)
    col[tids] = np.arange(nt)

    _say(progress, "Counting messages per storage task…")
    first_unix = np.full(nb, np.iinfo(np.int64).max, dtype=np.int64)
    np.minimum.at(first_unix, P["block"], P["ts"])
    n_events = np.bincount(P["block"], minlength=nb)
    counts_np = np.bincount(P["block"].astype(np.int64) * nt + col[P["tid"]], minlength=nb * nt).reshape(nb, nt)

    # oldest first: train on older blocks, test on newer ones
    order = np.lexsort((np.arange(nb), first_unix))
    block_ids = np.asarray(P["block_ids"], dtype=object)[order]
    first_unix, n_events, counts_np = first_unix[order], n_events[order], counts_np[order]
    counts = pd.DataFrame(counts_np, columns=tids)
    X = np.log1p(counts_np.astype(np.float32))
    train_idx, test_idx = models.time_split(nb, train_frac)
    split = np.where(np.arange(nb) < len(train_idx), "train", "test")

    lab = np.array([labels.get(b) if labels else None for b in block_ids], dtype=object)
    labelled = labels is not None and all(l is not None for l in lab) and len(set(lab)) > 1
    y = (lab == "Anomaly").astype(int) if labelled else None

    _say(progress, "Training Detector A (Isolation Forest)…")
    results = {}
    if_score, if_flag, if_model, if_thr = models.run_isolation_forest(X, train_idx, contamination)
    results["Isolation Forest"] = (if_score, if_flag)
    rf_model = None
    if labelled and len(set(y[train_idx])) > 1:
        _say(progress, "Training Detector B (Random Forest)…")
        rf_score, rf_flag, rf_model = models.run_random_forest(X, y, train_idx)
        results["Random Forest"] = (rf_score, rf_flag)

    _say(progress, "Learning the usual routine and writing alerts…")
    normal_mask = np.zeros(nb, dtype=bool)
    normal_mask[train_idx] = True
    if labelled:
        normal_mask &= (y == 0)
    if not normal_mask.any():
        normal_mask[:] = True
    normal_presence = pd.Series((counts_np[normal_mask] > 0).mean(axis=0), index=tids)
    normal_median = pd.Series(np.median(counts_np[normal_mask], axis=0), index=tids)

    # typical position of each message type inside a normal task (orders the routine on screen)
    rank_of = np.empty(nb, dtype=np.int64)
    rank_of[order] = np.arange(nb)
    ev = pd.DataFrame({"b": rank_of[P["block"]], "t": P["tid"], "l": P["line"]})
    ev = ev[normal_mask[ev["b"].values]]
    keep = pd.Series(ev["b"].unique()).sample(min(20000, ev["b"].nunique()), random_state=0)
    sample = ev[ev["b"].isin(set(keep))].sort_values(["b", "l"])
    sample["pos"] = sample.groupby("b").cumcount()
    typical_pos = sample.groupby(["b", "t"])["pos"].min().groupby("t").median()
    stats_rows = [(int(t), float(normal_presence[t]), float(normal_median[t]),
                   float(typical_pos[t]) if t in typical_pos.index else None) for t in tids]
    del ev, sample

    stamp = models.now_iso()
    alerts, runs = [], []
    for name, (score, flag) in results.items():
        high_q = np.quantile(score[flag], 0.75) if flag.any() else np.inf
        for i in range(nb):
            f = bool(flag[i])
            sev = models.severity(score[i], f, high_q)
            reason = models.explain_block(block_ids[i], counts.iloc[i], templates, normal_presence) if f else ""
            alerts.append((block_ids[i], name, float(score[i]), int(f), sev, reason))
        if labelled:
            p, r, f1 = models.scores(y[test_idx], flag[test_idx])
            runs.append((name, 1, len(train_idx), len(test_idx), p, r, f1, stamp))
        else:
            runs.append((name, 0, len(train_idx), len(test_idx), None, None, None, stamp))

    def iso(u):
        return datetime.fromtimestamp(int(u)).isoformat()

    test_start_unix = int(first_unix[test_idx[0]])
    # where live replay starts reading: the last checkpoint before the test period
    cp = [c for c in P["checkpoints"] if datetime.fromisoformat(c[2]).timestamp() <= test_start_unix]
    test_offset = cp[-1][1] if cp else 0

    store.insert_many(con, "templates", templates.items(), 2)
    store.insert_many(con, "blocks", ((block_ids[i], iso(first_unix[i]), int(n_events[i]), lab[i], split[i])
                                      for i in range(nb)), 5)
    store.insert_many(con, "alerts", alerts, 6)
    store.insert_many(con, "model_runs", runs, 8)
    store.insert_many(con, "template_stats", stats_rows, 4)
    store.insert_many(con, "meta", [
        ("source", os.path.basename(log_path)), ("demo", "1" if demo else "0"), ("run_at", stamp),
        ("contamination", str(contamination)), ("log_path", os.path.abspath(log_path)),
        ("if_threshold", str(if_thr)), ("rf_threshold", "0.5"), ("labelled", "1" if labelled else "0"),
        ("test_start", iso(test_start_unix)), ("test_offset", str(test_offset)),
        ("n_lines", str(int(len(np.unique(P["line"]))))), ("n_blocks", str(nb)),
        ("max_lines", str(max_lines or "")), ("seconds", str(round(time.time() - t0, 1)))], 2)
    con.commit()
    con.close()

    joblib.dump({"tids": tids, "templates": templates, "miner": P["miner"], "if_model": if_model, "if_thr": if_thr,
                 "rf_model": rf_model, "stats_rows": stats_rows, "run_at": stamp}, model_path(db_path))
    os.replace(tmp_db, db_path)  # swap in the finished database in one step

    return {"lines_used": int(len(P["block"])), "blocks": nb, "templates": nt, "labelled": bool(labelled),
            "flagged": {k: int(v[1].sum()) for k, v in results.items()}, "seconds": round(time.time() - t0, 1)}


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
    print(json.dumps(run(a.log, a.db, a.labels, a.max_lines, a.contamination, demo=a.demo, progress=print)))


if __name__ == "__main__":
    main()

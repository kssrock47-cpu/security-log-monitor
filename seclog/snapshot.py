"""A small, portable copy of the HDFS_v1 research results, so any PC shows the real results.

The full results database is about 3 GB, because it keeps all 11 million log lines. The research
screens only need the results for every task, the log lines of the tasks that were flagged,
the trained models, and a slice of the newer log for the replay. That fits in a few megabytes.

Make it (on the PC that ran HDFS_v1):
    python -m seclog.snapshot export
Any PC then unpacks it automatically on first start (server.py), or with:
    python -m seclog.snapshot install
"""
import argparse
import lzma
import os
import re
import shutil
import sqlite3
import time
from contextlib import closing

import pandas as pd

from . import store
from .pipeline import model_path

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP_DIR = os.path.join(HERE, "data", "research")
DB_XZ = "results.db.xz"
MODELS_XZ = "models.joblib.xz"
REPLAY_XZ = "replay.log.xz"
REPLAY_LOG = os.path.join("data", "research_replay.log")  # where the replay slice is unpacked (relative)
BLOCK_RE = re.compile(r"blk_-?\d+")


def available(snap_dir=SNAP_DIR):
    return all(os.path.exists(os.path.join(snap_dir, f)) for f in (DB_XZ, MODELS_XZ))


def _xz(src, dst):
    with open(src, "rb") as fi, lzma.open(dst, "wb", preset=9 | lzma.PRESET_EXTREME) as fo:
        shutil.copyfileobj(fi, fo, 1 << 20)


def _unxz(src, dst):
    tmp = dst + ".building"
    with lzma.open(src, "rb") as fi, open(tmp, "wb") as fo:
        shutil.copyfileobj(fi, fo, 1 << 20)
    os.replace(tmp, dst)


def _first_alert_and_normal(con):
    """The same two tasks the dashboard shows first (top alert, and a normal example), so their lines are kept."""
    al = pd.read_sql_query("select a.block_id, a.model, a.score, a.flagged, b.first_ts, b.split from alerts a "
                           "join blocks b using (block_id)", con)
    models = al["model"].unique()
    fl = al[al.flagged == 1]
    by = fl.groupby("block_id").agg(n_det=("model", "nunique"), score=("score", "max"), first_ts=("first_ts", "first"))
    by["rank"] = (by.n_det < 2).astype(int) if len(models) == 2 else 0
    by = by.reset_index().sort_values(["rank", "score", "first_ts"], ascending=[True, False, True])
    first = by.iloc[0]["block_id"] if len(by) else None
    ok = al[al.split == "test"].groupby("block_id")["flagged"].max()
    ok = ok[ok == 0]
    normal = ok.index[len(ok) // 2] if len(ok) else None
    return first, normal


def export(src_db, out_dir=SNAP_DIR, replay_lines=400_000, log_path=None, allow_demo=False):
    t0 = time.time()
    os.makedirs(out_dir, exist_ok=True)
    src = sqlite3.connect(src_db)
    meta = dict(src.execute("select key, value from meta").fetchall())
    if meta.get("demo") == "1" and not allow_demo:
        raise SystemExit("The results in this database are the made-up demo. Run HDFS_v1 first.")
    first, normal = _first_alert_and_normal(src)
    hero = src.execute("select min(line_no) from log_events where block_id=?", (first,)).fetchone()[0] if first else None
    n_train = src.execute("select count(*) from blocks where split='train'").fetchone()[0]
    t_min, t_max = src.execute("select min(first_ts), max(first_ts) from blocks").fetchone()
    src.close()

    # 1. the replay slice: the newer part of the log, from where the replay starts
    log_path = log_path or meta["log_path"]
    replay_tmp = os.path.join(out_dir, "replay.log")
    seen = set()
    with open(log_path, "rb") as fi, open(replay_tmp, "wb") as fo:
        fi.seek(int(meta.get("test_offset") or 0))
        for i, line in enumerate(fi):
            if i >= replay_lines:
                break
            fo.write(line)
            seen.update(BLOCK_RE.findall(line.decode("utf-8", "replace")))

    # 2. the slim database
    tmp = os.path.join(out_dir, "results.db")
    if os.path.exists(tmp):
        os.remove(tmp)
    store.reset(tmp)
    with closing(sqlite3.connect(tmp)) as con:
        con.execute("attach database ? as s", (src_db,))
        for t in ("templates", "template_stats", "model_runs", "feedback"):
            con.execute(f"insert into {t} select * from s.{t}")
        # every newer task (for the accuracy check), plus every older task that a detector flagged (alert list)
        con.execute("create temp table keep (block_id text primary key)")
        con.execute("insert or ignore into keep select block_id from s.blocks where split='test'")
        con.execute("insert or ignore into keep select distinct block_id from s.alerts where flagged=1")
        con.execute("insert into blocks select b.* from s.blocks b join keep using (block_id)")
        con.execute("insert into alerts select a.* from s.alerts a join keep using (block_id)")
        # tasks from the older part that are still writing when the replay starts: the replay must skip them
        con.execute("create temp table seen (block_id text primary key)")
        con.executemany("insert or ignore into seen values (?)", ((b,) for b in seen))
        con.execute("insert or ignore into blocks select b.* from s.blocks b join seen using (block_id) where b.split='train'")
        # log lines: every flagged task, the normal example, and the lines around the top alert
        con.execute("create temp table want (block_id text primary key)")
        con.execute("insert or ignore into want select distinct block_id from s.alerts where flagged=1")
        if normal:
            con.execute("insert or ignore into want values (?)", (normal,))
        sql = "insert into log_events select * from s.log_events where block_id in (select block_id from want)"
        params = ()
        if hero is not None:
            sql += " union select * from s.log_events where line_no between ? and ?"
            params = (hero - 4, hero + 60)
        con.execute(sql, params)
        meta.update(log_path=REPLAY_LOG.replace(os.sep, "/"), test_offset="0", n_train=str(n_train),
                    t_min=t_min, t_max=t_max, snapshot="1", replay_lines=str(replay_lines))
        con.executemany("insert or replace into meta values (?,?)", meta.items())
        con.commit()
        con.execute("detach database s")
        con.execute("vacuum")
    # 3. compress everything
    _xz(tmp, os.path.join(out_dir, DB_XZ))
    _xz(model_path(src_db), os.path.join(out_dir, MODELS_XZ))
    _xz(replay_tmp, os.path.join(out_dir, REPLAY_XZ))
    os.remove(tmp)
    os.remove(replay_tmp)
    sizes = {f: round(os.path.getsize(os.path.join(out_dir, f)) / 1e6, 1) for f in (DB_XZ, MODELS_XZ, REPLAY_XZ)}
    print(f"Snapshot written to {out_dir} in {time.time() - t0:.0f} s: {sizes} MB")
    return sizes


def install(db_path, snap_dir=SNAP_DIR, replay_to=None):
    """Unpack the snapshot as the research results (replaces whatever results are there)."""
    if not available(snap_dir):
        raise FileNotFoundError("No saved HDFS_v1 results in this copy of the project.")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    _unxz(os.path.join(snap_dir, MODELS_XZ), model_path(db_path))
    rp = os.path.join(snap_dir, REPLAY_XZ)
    if os.path.exists(rp):
        _unxz(rp, replay_to or os.path.join(HERE, REPLAY_LOG))
    _unxz(os.path.join(snap_dir, DB_XZ), db_path)


def main():
    ap = argparse.ArgumentParser(description="Make or unpack the portable HDFS_v1 research results.")
    ap.add_argument("action", choices=["export", "install"])
    ap.add_argument("--db", default=os.path.join(HERE, "data", "seclog.db"))
    ap.add_argument("--log", default=None, help="HDFS.log, if it has moved since the run")
    ap.add_argument("--lines", type=int, default=400_000, help="lines of the newer log kept for the replay")
    a = ap.parse_args()
    if a.action == "export":
        export(a.db, replay_lines=a.lines, log_path=a.log)
    else:
        install(a.db)
        print("Saved HDFS_v1 results unpacked.")


if __name__ == "__main__":
    main()

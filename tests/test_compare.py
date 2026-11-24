"""The eight-technique comparison runs end to end on a small made-up results database."""
import json
import sqlite3
from contextlib import closing

import numpy as np

from seclog import compare


def _db(path, n=600, seed=0):
    rng = np.random.default_rng(seed)
    with closing(sqlite3.connect(path)) as con:
        con.execute("create table blocks (block_id TEXT PRIMARY KEY, first_ts TEXT, n_events INTEGER, label TEXT, split TEXT)")
        con.execute("create table templates (template_id INTEGER PRIMARY KEY, template TEXT)")
        con.execute("create table log_events (line_no INTEGER, block_id TEXT, ts TEXT, level TEXT, component TEXT, template_id INTEGER, content TEXT)")
        con.executemany("insert into templates values (?, ?)", [(t, f"type {t}") for t in range(1, 6)])
        line = 0
        for i in range(n):
            bad = rng.random() < 0.05
            con.execute("insert into blocks values (?,?,?,?,?)",
                        (f"b{i}", f"t{i:05d}", 0, "Anomaly" if bad else "Normal", "train" if i < n * 0.7 else "test"))
            types = [1, 1, 2, 3] + ([5, 5, 5] if bad else [4])
            for t in types:
                line += 1
                con.execute("insert into log_events values (?,?,?,?,?,?,?)", (line, f"b{i}", "", "INFO", "x", t, ""))
        con.commit()


def test_compare_runs_all_eight(tmp_path, monkeypatch):
    db = str(tmp_path / "r.db")
    _db(db)
    monkeypatch.setattr(compare, "SUBSAMPLE", 200)
    out = compare.run(db, progress=lambda *_: None, out_json=str(tmp_path / "c.json"))
    names = [r["model"] for r in out["results"]]
    assert len(names) == 8 and set(names) == set(compare.PLAIN)
    rf = next(r for r in out["results"] if r["model"] == "Random Forest")
    assert rf["f1"] > 0.9  # the problem tasks have a message type normal ones never have
    assert all(r["n_test"] == 180 for r in out["results"])
    with closing(sqlite3.connect(db)) as con:
        saved = json.loads(con.execute("select data from comparison").fetchone()[0])
    assert saved["results"] == out["results"]

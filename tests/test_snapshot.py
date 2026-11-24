"""The portable research results: export a slim copy, unpack it, and check it matches the original."""
import os
import sqlite3

from seclog import pipeline, snapshot

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "data", "sample", "demo_hdfs_style.log")
LABELS = os.path.join(ROOT, "data", "sample", "demo_labels.csv")


def test_snapshot_round_trip(tmp_path):
    src = str(tmp_path / "full.db")
    pipeline.run(LOG, src, LABELS, None, 0.03, demo=True)
    out = tmp_path / "snap"
    sizes = snapshot.export(src, str(out), replay_lines=5000, allow_demo=True)
    assert all(v >= 0 for v in sizes.values())
    dst = str(tmp_path / "copy" / "seclog.db")
    snapshot.install(dst, str(out), replay_to=str(tmp_path / "replay.log"))
    a, b = sqlite3.connect(src), sqlite3.connect(dst)
    one = lambda c, q: c.execute(q).fetchall()
    # the accuracy numbers come out the same
    assert one(a, "select * from model_runs") == one(b, "select * from model_runs")
    q = ("select a.model, sum(b.label='Anomaly' and a.flagged=1), sum(a.flagged) from alerts a join blocks b "
         "using (block_id) where b.split='test' group by a.model")
    assert one(a, q) == one(b, q)
    # every flagged task keeps all its log lines
    q = "select count(*) from log_events where block_id in (select block_id from alerts where flagged=1)"
    assert one(a, q) == one(b, q)
    m = dict(one(b, "select key, value from meta"))
    assert m["snapshot"] == "1" and m["test_offset"] == "0" and int(m["n_train"]) > 0
    assert os.path.getsize(pipeline.model_path(dst)) > 0 and os.path.getsize(tmp_path / "replay.log") > 0

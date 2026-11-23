import os
import sqlite3
import subprocess
import sys

import pytest

from seclog import models, pipeline
from seclog.parse import parse_file, parse_line

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REAL_SAMPLE = os.path.join(ROOT, "data", "sample", "HDFS_2k.log")  # real loghub lines


def test_parse_line_real_format():
    ts, lvl, comp, content = parse_line(
        "081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating")
    assert ts == "2008-11-09T20:36:15" and lvl == "INFO"
    assert comp == "dfs.DataNode$PacketResponder" and "blk_38865049064139660" in content


def test_parse_line_rejects_garbage():
    assert parse_line("not a log line") is None


@pytest.mark.skipif(not os.path.exists(REAL_SAMPLE), reason="real sample not present")
def test_drain3_groups_real_lines():
    events, templates = parse_file(REAL_SAMPLE)
    assert len(events) > 1500
    assert 5 <= len(templates) <= 40          # thousands of lines collapse to a few event types
    assert all("blk_" not in t for t in templates.values())  # block ids are masked


def _make_demo(tmp_path, blocks=800):
    log, lab = tmp_path / "d.log", tmp_path / "l.csv"
    subprocess.run([sys.executable, "-m", "seclog.make_demo", "--blocks", str(blocks),
                    "--out", str(log), "--labels", str(lab)], cwd=ROOT, check=True, capture_output=True)
    return str(log), str(lab)


def test_end_to_end_labelled(tmp_path):
    log, lab = _make_demo(tmp_path)
    db = str(tmp_path / "t.db")
    info = pipeline.run(log, db, lab, demo=True)
    assert info["labelled"] and set(info["flagged"]) == {"Isolation Forest", "Random Forest"}
    con = sqlite3.connect(db)
    runs = {r[0]: r for r in con.execute("select model, f1 from model_runs")}
    assert runs["Random Forest"][1] > 0.8
    # every flagged alert has a reason and supporting log lines
    n_bad = con.execute("select count(*) from alerts where flagged=1 and (reason is null or reason='')").fetchone()[0]
    assert n_bad == 0
    bid = con.execute("select block_id from alerts where flagged=1 limit 1").fetchone()[0]
    assert con.execute("select count(*) from log_events where block_id=?", (bid,)).fetchone()[0] > 0


def test_time_split_is_older_then_newer():
    tr, te = models.time_split(10, 0.7)
    assert tr.max() < te.min() and len(tr) == 7 and len(te) == 3


def test_unlabelled_run_has_no_scores(tmp_path):
    log, _ = _make_demo(tmp_path, 500)
    info = pipeline.run(log, str(tmp_path / "u.db"), None)
    assert not info["labelled"] and list(info["flagged"]) == ["Isolation Forest"]
    row = sqlite3.connect(str(tmp_path / "u.db")).execute("select precision, f1 from model_runs").fetchone()
    assert row == (None, None)

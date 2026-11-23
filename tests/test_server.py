import json
import os
import shutil

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    import server
    from seclog import pipeline
    d = tmp_path_factory.mktemp("srv")
    server.DB = str(d / "t.db")
    server._cache.clear()
    pipeline.run(server.DEMO_LOG, server.DB, server.DEMO_LABELS, None, 0.03, demo=True)
    return TestClient(server.app)


def test_overview_and_alerts(client):
    o = client.get("/api/overview").json()
    assert o["n_alerts"] > 0 and o["n_first"] + o["n_check"] == o["n_alerts"]
    assert len(o["normal_track"]) > 0 and o["hero"]
    alerts = client.get("/api/alerts").json()
    assert alerts[0]["priority"] == "first"  # most urgent first
    d = client.get(f"/api/alerts/{alerts[0]['id']}").json()
    assert d["headline"] and d["lines"] and any(l["unusual"] for l in d["lines"])


def test_feedback_roundtrip(client):
    bid = client.get("/api/alerts").json()[0]["id"]
    assert client.post("/api/feedback", json={"block_id": bid, "verdict": "false"}).json()["ok"]
    assert client.get(f"/api/alerts/{bid}").json()["review"] == "false"
    client.post("/api/feedback", json={"block_id": bid, "verdict": None})
    assert client.get(f"/api/alerts/{bid}").json()["review"] is None
    assert client.post("/api/feedback", json={"block_id": bid, "verdict": "maybe"}).status_code == 400


def test_accuracy_counts_add_up(client):
    a = client.get("/api/accuracy").json()
    for d in a["detectors"]:
        assert d["caught"] <= d["real"] and d["caught"] + d["false_alarms"] == d["raised"]


def test_walkthrough_normal_task(client):
    o = client.get("/api/overview").json()
    w = client.get(f"/api/walkthrough/{o['normal_example']}").json()
    assert not w["flagged"] and w["track"] == w["normal_track"]


def test_live_stream_checks_new_tasks(client):
    sid = client.post("/api/live/start?speed=100000").json()["sid"]
    done, flagged = None, 0
    with client.stream("GET", f"/api/live/stream?sid={sid}") as r:
        ev = None
        for line in r.iter_lines():
            if line.startswith("event:"):
                ev = line[7:]
            elif line.startswith("data:") and ev == "batch":
                flagged += sum(1 for e in json.loads(line[5:])["events"] if e["type"] == "task" and e["flagged"])
            elif line.startswith("data:") and ev == "done":
                done = json.loads(line[5:])
    assert done and done["tasks"] > 100 and done["alerts"] == flagged > 0

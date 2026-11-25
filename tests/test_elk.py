"""The ELK connector: ECS documents, index templates, bulk sending, and staying calm when Elasticsearch is down."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from seclog import elk


class FakeES(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def _reply(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self._reply({"version": {"number": "8.19.26"}})

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        FakeES.seen.append(("PUT", self.path, self.rfile.read(n).decode()))
        self._reply({"acknowledged": True})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        FakeES.seen.append(("POST", self.path, body))
        lines = [json.loads(x) for x in body.strip().split("\n")]
        self._reply({"errors": False, "items": [{"index": {"status": 201}} for _ in lines[::2]]})


def _server():
    FakeES.seen = []
    srv = HTTPServer(("127.0.0.1", 0), FakeES)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


ALERT = {"id": 7, "created": "2026-11-25T10:00:05", "first_ts": "2026-11-25T10:00:00", "last_ts": "2026-11-25T10:00:04",
         "source_id": 1, "entity": "45.155.205.233", "kind": "pattern", "rule": "brute_force", "severity": "high",
         "title": "Someone is guessing passwords", "detail": "40 failed logins in 60 seconds", "status": "new",
         "mitre": "T1110.001 Brute Force: Password Guessing", "features": "[]", "count": 3}
EVENT = (12, "2026-11-25T10:00:01", 1, "auth", "web01", "sshd", "45.155.205.233", "45.155.205.233", "root", "fail",
         None, 4, "Failed password for root from 45.155.205.233 port 4242 ssh2")


def test_documents_use_ecs_fields():
    e = elk.event_doc(*EVENT)
    assert e["source"]["ip"] == "45.155.205.233" and e["user"]["name"] == "root"
    assert e["event"]["outcome"] == "failure" and e["event"]["dataset"] == "seclog.auth"
    assert e["@timestamp"].startswith("2026-11-25T10:00:01") and len(e["@timestamp"]) > 19  # has a time zone
    a = elk.alert_doc(ALERT)
    assert a["event"]["kind"] == "alert" and a["event"]["severity"] == 73
    assert a["threat"]["technique"]["id"] == "T1110.001" and a["threat"]["tactic"]["name"] == "Credential Access"
    assert a["rule"]["category"] == "Known attack pattern" and a["labels"]["count"] == 3
    bad = elk.event_doc(1, "2026-11-25T10:00:01", 1, "hdfs", None, None, "blk_1", "not-an-ip", None, None, None, 1, "x")
    assert "source" not in bad and "user" not in bad  # empty and invalid values are left out


def test_sends_templates_and_bulk_batches():
    srv, url = _server()
    try:
        s = elk.Shipper(url, api_key="")
        s.event(EVENT)
        s.alert(ALERT)
        s.wake.set()
        for _ in range(50):
            if s.sent["alerts"] and s.sent["events"]:
                break
            time.sleep(0.1)
        st = s.status()
        assert st["connected"] and st["version"] == "8.19.26" and st["sent_events"] == 1 and st["sent_alerts"] == 1
        puts = {p for m, p, _ in FakeES.seen if m == "PUT"}
        assert puts == {"/_index_template/seclog-events", "/_index_template/seclog-alerts"}
        bulk = next(b for m, p, b in FakeES.seen if p == "/_bulk").strip().split("\n")
        actions = [json.loads(x)["index"] for x in bulk[::2]]
        assert {"_index": "seclog-alerts", "_id": "7"} in actions  # alerts are updated in place, by id
    finally:
        srv.shutdown()


def test_unreachable_elasticsearch_keeps_documents_and_reports_why():
    s = elk.Shipper("http://127.0.0.1:9", api_key="")  # nothing listens on port 9
    s.event(EVENT)
    s.wake.set()
    for _ in range(50):
        if s.last_error:
            break
        time.sleep(0.1)
    st = s.status()
    assert not st["connected"] and "reach" in st["error"] and st["waiting"] == 1
    s.configure(None)  # switching off empties the queue
    assert s.status()["waiting"] == 0 and not s.status()["on"]


def test_rejects_a_bad_address():
    s = elk.Shipper(None)
    try:
        s.configure("ftp://somewhere")
        assert False
    except ValueError:
        pass

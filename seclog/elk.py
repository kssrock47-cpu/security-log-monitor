"""Send the monitor's log events and alerts to Elasticsearch, so they can be searched and charted in Kibana
(the ELK Stack), or picked up by a SOC's own SIEM that runs on Elasticsearch.

* Off until a person switches it on (or SECLOG_ELASTIC is set, for example http://127.0.0.1:9200).
* Field names follow the Elastic Common Schema (ECS): @timestamp, source.ip, user.name, event.outcome,
  rule.name, threat.technique.id, ... so Kibana, Elastic Security and other ECS tools understand them as-is.
* Two indices: seclog-events (every log line) and seclog-alerts (one document per alert, updated in place
  when its count or status changes).
* Sending happens on its own thread in batches, so a slow or missing Elasticsearch never slows the monitor.
  If it is unreachable the monitor keeps working; up to MAX_QUEUE documents wait and the oldest are dropped
  beyond that (the count is shown).
* For a secured cluster set SECLOG_ELASTIC_API_KEY (an Elasticsearch API key, sent as "ApiKey <key>").
* Optionally through Logstash (the L of ELK): documents go to Logstash's HTTP input instead, and the pipeline
  in elk/logstash/seclog.conf adds map locations (city, coordinates) from its GeoIP database before storing
  them in Elasticsearch. The monitor still talks to Elasticsearch itself for the index templates and status.
"""
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime

from seclog import insight

EVENTS, ALERTS = "seclog-events", "seclog-alerts"
MAX_QUEUE = 200000
BATCH = 2000
SEV_NUM = {"low": 21, "medium": 47, "high": 73, "critical": 99}  # the 0-100 scale Elastic Security uses
OUTCOME = {"fail": "failure", "success": "success"}
KIND = {"ai": "AI (Isolation Forest)", "pattern": "Known attack pattern"}

GEO = {"properties": {"country_iso_code": {"type": "keyword"}, "country_name": {"type": "keyword"},
                      "city_name": {"type": "keyword"}, "region_name": {"type": "keyword"},
                      "continent_name": {"type": "keyword"}, "location": {"type": "geo_point"}}}
KW = {"type": "keyword"}
TEMPLATES = {
    EVENTS: {"index_patterns": [EVENTS + "*"], "priority": 200, "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {"dynamic": False, "properties": {
            "@timestamp": {"type": "date"}, "message": {"type": "match_only_text"},
            "event": {"properties": {"kind": KW, "dataset": KW, "outcome": KW, "id": KW, "module": KW}},
            "source": {"properties": {"ip": {"type": "ip", "ignore_malformed": True}, "geo": GEO}},
            "user": {"properties": {"name": KW}}, "host": {"properties": {"name": KW}},
            "process": {"properties": {"name": KW}}, "log": {"properties": {"level": KW}},
            "observer": {"properties": {"name": KW, "product": KW}},
            "labels": {"properties": {"connection": KW, "entity": KW, "message_type": KW}}}}}},
    ALERTS: {"index_patterns": [ALERTS + "*"], "priority": 200, "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {"dynamic": False, "properties": {
            "@timestamp": {"type": "date"}, "message": {"type": "match_only_text"},
            "event": {"properties": {"kind": KW, "id": KW, "severity": {"type": "integer"}, "created": {"type": "date"},
                                     "start": {"type": "date"}, "end": {"type": "date"}, "module": KW}},
            "rule": {"properties": {"name": KW, "id": KW, "category": KW}},
            "threat": {"properties": {"framework": KW, "tactic": {"properties": {"id": KW, "name": KW}},
                                      "technique": {"properties": {"id": KW, "name": KW}}}},
            "source": {"properties": {"ip": {"type": "ip", "ignore_malformed": True}, "geo": GEO}},
            "user": {"properties": {"name": KW}},
            "observer": {"properties": {"name": KW, "product": KW}},
            "labels": {"properties": {"severity": KW, "status": KW, "attack_step": KW, "entity": KW,
                                      "connection": KW, "count": {"type": "integer"}}}}}}},
}


def _iso(ts):
    """Log times are local time without a zone; Elasticsearch needs the zone or Kibana shifts them."""
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
        return (d if d.tzinfo else d.astimezone()).isoformat(timespec="seconds")
    except (ValueError, OSError, OverflowError):
        return None


def _ip(s):
    try:
        return str(ipaddress.ip_address(s)) if s else None
    except ValueError:
        return None


def _geo(ip):
    if not ip:
        return None
    g = insight.locate(ip)
    if not g["cc"] or g["internal"]:
        return None
    return {"country_iso_code": g["cc"], "country_name": g["country"]}


def _clean(d):
    """Drop empty values so documents stay small and Kibana shows no blank fields."""
    if isinstance(d, dict):
        out = {k: _clean(v) for k, v in d.items()}
        return {k: v for k, v in out.items() if v not in (None, {}, "", [])}
    return d


def event_doc(eid, ts, sid, fmt, host, app, ent, src_ip, user, outcome, level, tid, raw):
    ip = _ip(src_ip)
    return _clean({
        "@timestamp": _iso(ts), "message": raw,
        "event": {"kind": "event", "dataset": f"seclog.{fmt}", "outcome": OUTCOME.get(outcome, "unknown" if outcome else None),
                  "id": str(eid), "module": "security-log-monitor"},
        "source": {"ip": ip, "geo": _geo(ip)}, "user": {"name": user}, "host": {"name": host},
        "process": {"name": app}, "log": {"level": level},
        "observer": {"name": "Security Log Monitor", "product": "security-log-monitor"},
        "labels": {"connection": str(sid), "entity": ent, "message_type": str(tid)}})


def alert_doc(a):
    """a: a row of the alerts table as a dict."""
    ent = a["entity"] or ""
    ip = _ip(ent)
    user = ent.split(":", 1)[1] if ent.startswith("user:") else None
    tech = (a.get("mitre") or "").split(" ", 1)
    if not re.fullmatch(r"T\d{4}(\.\d{3})?", tech[0]):  # AI alerts describe unusual behaviour, not a MITRE technique
        tech = [None]
    stage = insight.STAGES[insight.STAGE_IX[insight.stage_of(a["kind"], a["rule"], json.loads(a.get("features") or "[]"))]]
    return _clean({
        "@timestamp": _iso(a["first_ts"]) or _iso(a["created"]), "message": a.get("detail"),
        "event": {"kind": "alert", "id": str(a["id"]), "severity": SEV_NUM.get(a["severity"], 21),
                  "created": _iso(a["created"]), "start": _iso(a["first_ts"]), "end": _iso(a["last_ts"]),
                  "module": "security-log-monitor"},
        "rule": {"name": a["title"], "id": a["rule"], "category": KIND.get(a["kind"], a["kind"])},
        "threat": {"framework": "MITRE ATT&CK", "tactic": {"id": stage[4], "name": stage[3]},
                   "technique": {"id": tech[0], "name": tech[1] if len(tech) > 1 else None}},
        "source": {"ip": ip, "geo": _geo(ip)}, "user": {"name": user},
        "observer": {"name": "Security Log Monitor", "product": "security-log-monitor"},
        "labels": {"severity": a["severity"], "status": a.get("status"), "attack_step": stage[1], "entity": ent,
                   "connection": str(a.get("source_id")), "count": a.get("count")}})


class LogstashDown(Exception):
    pass


class Shipper:
    def __init__(self, url=None, api_key=None, via=None):
        self.url = None
        self.via = None  # Logstash HTTP input, or None to send straight to Elasticsearch
        self.api_key = api_key if api_key is not None else os.environ.get("SECLOG_ELASTIC_API_KEY") or None
        self.q = deque()
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.sent = {"events": 0, "alerts": 0}
        self.dropped = 0
        self.ready = False  # index templates are in place
        self.version = None
        self.last_error = None
        self.last_ok = None
        self.configure(url, via)
        threading.Thread(target=self._loop, daemon=True).start()

    # ------------------------------------------------------------ settings
    def configure(self, url, via=None):
        url = (url or "").strip().rstrip("/") or None
        via = (via or "").strip().rstrip("/") or None
        for u, eg in ((url, "http://127.0.0.1:9200"), (via, "http://127.0.0.1:5080")):
            if u:
                p = urllib.parse.urlparse(u)
                if p.scheme not in ("http", "https") or not p.netloc:
                    raise ValueError(f"Use a web address such as {eg}")
        with self.lock:
            if url != self.url or via != self.via:
                self.ready, self.version, self.last_error = False, None, None
            self.url, self.via = url, (via if url else None)
            if not url:
                self.q.clear()
        self.wake.set()

    @property
    def on(self):
        return bool(self.url)

    def status(self):
        return {"on": self.on, "url": self.url, "via": self.via, "connected": self.ready and self.last_error is None,
                "version": self.version, "sent_events": self.sent["events"], "sent_alerts": self.sent["alerts"],
                "waiting": len(self.q), "dropped": self.dropped, "error": self.last_error,
                "last_ok": self.last_ok, "indices": [EVENTS, ALERTS], "api_key": bool(self.api_key)}

    # ------------------------------------------------------------ queueing
    def _put(self, index, doc, _id=None):
        if not self.url:
            return
        with self.lock:
            if len(self.q) >= MAX_QUEUE:
                self.q.popleft()
                self.dropped += 1
            self.q.append((index, _id, doc))
        if len(self.q) >= BATCH:
            self.wake.set()

    def event(self, row):
        """row: the tuple saved in the events table."""
        if self.url:
            self._put(EVENTS, event_doc(*row), _id=f"{row[0]}")

    def alert(self, a):
        if self.url:
            self._put(ALERTS, alert_doc(a), _id=str(a["id"]))

    # ------------------------------------------------------------ HTTP
    def _req(self, method, path, body=None, ctype="application/json", timeout=15, base=None):
        url = (base or self.url) + path
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": ctype})
        if self.api_key:
            req.add_header("Authorization", "ApiKey " + self.api_key)
        host = urllib.parse.urlparse(url).hostname or ""
        handlers = [urllib.request.ProxyHandler({})] if host in ("127.0.0.1", "localhost", "::1") else []
        with urllib.request.build_opener(*handlers).open(req, timeout=timeout) as r:
            raw = r.read() or b"{}"
            try:
                return json.loads(raw)
            except ValueError:  # Logstash answers "ok"
                return {"text": raw.decode("utf-8", "replace")[:200]}

    @staticmethod
    def _why(e):
        if isinstance(e, urllib.error.HTTPError):
            try:
                detail = json.loads(e.read()).get("error", {})
                detail = detail.get("reason") if isinstance(detail, dict) else detail
            except Exception:
                detail = ""
            if e.code in (401, 403):
                return f"Elasticsearch refused the login ({e.code}). Set SECLOG_ELASTIC_API_KEY to an API key."
            return f"Elasticsearch answered {e.code}{': ' + str(detail)[:160] if detail else ''}"
        if isinstance(e, urllib.error.URLError):
            return "Can't reach Elasticsearch at this address. Is it running? (elk\\start-windows.ps1 starts it.)"
        if isinstance(e, LogstashDown):
            return str(e)
        return str(e)[:200]

    def check(self):
        """Connect, make sure the index templates exist, and report the version. Raises on failure."""
        info = self._req("GET", "/")
        for name, body in TEMPLATES.items():
            self._req("PUT", f"/_index_template/{name}", json.dumps(body))
            try:  # indices made by an older version get the new fields (such as map locations) too
                self._req("PUT", f"/{name}/_mapping", json.dumps({"properties": body["template"]["mappings"]["properties"]}))
            except urllib.error.HTTPError:
                pass  # the index doesn't exist yet
        self.version = (info.get("version") or {}).get("number")
        if self.via:
            try:
                self._req("POST", "", "[]", base=self.via)  # an empty batch: checks the pipeline is listening
            except Exception:
                raise LogstashDown(f"Elasticsearch is fine, but Logstash isn't answering at {self.via}. "
                                   "Is it running? (elk\\start-windows.ps1 starts it.)")
        self.ready, self.last_error = True, None
        return self.status()

    def _send(self, batch):
        if self.via:  # Logstash: one JSON array; the pipeline reads where each document goes from these two fields
            docs = [{**doc, "seclog_index": index, "seclog_id": _id} for index, _id, doc in batch]
            try:
                self._req("POST", "", json.dumps(docs, default=str), timeout=60, base=self.via)
            except Exception as e:
                raise LogstashDown(f"Logstash at {self.via} didn't take the documents ({str(e)[:120]}). Is it running?")
            for index, _, _ in batch:
                self.sent["alerts" if index == ALERTS else "events"] += 1
            return 0
        lines = []
        for index, _id, doc in batch:
            lines.append(json.dumps({"index": {"_index": index, **({"_id": _id} if _id else {})}}))
            lines.append(json.dumps(doc, default=str))
        res = self._req("POST", "/_bulk", "\n".join(lines) + "\n", ctype="application/x-ndjson", timeout=60)
        items = res.get("items") or [{}] * len(batch)
        failed = 0
        for (index, _, _), it in zip(batch, items):
            r = it.get("index", {})
            if r.get("status", 200) >= 300:
                failed += 1
                self.last_error = f"Elasticsearch rejected a document: {str(r.get('error', {}).get('reason', ''))[:160]}"
            else:
                self.sent["alerts" if index == ALERTS else "events"] += 1
        return failed

    def _loop(self):
        while True:
            self.wake.wait(2.0)
            self.wake.clear()
            if not self.url:
                continue
            try:
                if not self.ready:
                    self.check()
                while self.q and self.url:
                    with self.lock:
                        batch = [self.q.popleft() for _ in range(min(BATCH, len(self.q)))]
                    try:
                        failed = self._send(batch)
                    except Exception:
                        with self.lock:  # put them back in order and try again later
                            self.q.extendleft(reversed(batch))
                        raise
                    if not failed:
                        self.last_error = None
                    self.last_ok = time.time()
            except Exception as e:
                self.ready = False
                self.last_error = self._why(e)
                self.wake.wait(8.0)  # wait before trying again
                self.wake.clear()

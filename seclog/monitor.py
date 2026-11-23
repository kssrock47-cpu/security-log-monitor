"""The live monitor engine.

Lines from every connection go into one queue. A single worker reads them, turns each into an
event (formats.py), sorts it into a message type (Drain3), checks known attack patterns (rules.py),
feeds the AI (ai.py), and stores everything in SQLite. The dashboard follows along through `feed`.
"""
import json
import os
import queue
import re
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from . import formats
from .ai import WindowAI
from .parse import make_miner
from .rules import RuleEngine
from .sources import KINDS

SEV_W = {"critical": 10, "high": 5, "medium": 2, "low": 1}
LEVELS = [(0, "Calm"), (1, "Watchful"), (6, "Elevated"), (15, "Under attack")]

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (id INTEGER PRIMARY KEY, kind TEXT, name TEXT, config TEXT, enabled INTEGER, created TEXT);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts TEXT, source_id INTEGER, fmt TEXT, host TEXT, app TEXT,
    entity TEXT, src_ip TEXT, user TEXT, outcome TEXT, level TEXT, template_id INTEGER, raw TEXT);
CREATE INDEX IF NOT EXISTS ev_entity ON events(source_id, entity, ts);
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, created TEXT, first_ts TEXT, last_ts TEXT, source_id INTEGER,
    entity TEXT, kind TEXT, rule TEXT, severity TEXT, title TEXT, detail TEXT, why TEXT, advice TEXT, mitre TEXT,
    score REAL, threshold REAL, count INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS templates (id INTEGER PRIMARY KEY, template TEXT);
"""

PLAIN = [
    (r"Failed password for invalid user", "Wrong password for a username that doesn't exist"),
    (r"Failed (?:password|publickey)", "Wrong password"),
    (r"[Ii]nvalid user", "Login attempt with a username that doesn't exist"),
    (r"Accepted (?:password|publickey|keyboard)", "Successful login"),
    (r"session opened", "A login session started"),
    (r"session closed", "A login session ended"),
    (r"BREAK-IN ATTEMPT", "The server noticed a suspicious address"),
    (r"authentication failure", "Login failed"),
    (r"check pass; user unknown", "Login attempt with an unknown user"),
    (r"incorrect password attempts|NOT in sudoers", "Wrong password when asking for admin rights"),
    (r"COMMAND=", "Ran a command with admin rights (sudo)"),
    (r"UFW BLOCK|\bDROP\b|\bBLOCK\b", "The firewall blocked a connection"),
    (r"new user: name=|useradd", "A new user account was created"),
    (r"to group|usermod", "A user's groups were changed"),
    (r"Received disconnect|Disconnected from|Connection closed|connection closed", "The connection ended"),
    (r"Too many authentication failures|maximum authentication attempts", "Too many wrong passwords: disconnected"),
]


def plain_line(fmt, msg, status=None):
    if fmt == "web" and status:
        return {200: "Page served", 301: "Redirected", 302: "Redirected", 304: "Page served from cache",
                400: "Bad request", 401: "Login required", 403: "Access denied", 404: "Page not found",
                500: "Server error", 502: "Server error", 503: "Server busy"}.get(status, f"Web answer {status}")
    if fmt == "windows":
        m = re.match(r"Event \d+: ([^=]+?)(?:\s+\w+=|$)", msg)
        return m.group(1) if m else msg[:80]
    for pat, text in PLAIN:
        if re.search(pat, msg):
            return text
    return None


class Monitor:
    def __init__(self, db_path, upload_dir):
        self.db_path, self.upload_dir = db_path, upload_dir
        os.makedirs(upload_dir, exist_ok=True)
        self.con = sqlite3.connect(db_path, check_same_thread=False)
        self.con.executescript(SCHEMA)
        self.dbl = threading.Lock()
        self.q: queue.Queue = queue.Queue(maxsize=20000)
        self.sources: dict = {}
        self.ai: dict = {}
        self.rules: dict = {}
        self.watermark: dict = {}
        self.pending = defaultdict(int)
        self.flushed: set = set()
        self.miner = make_miner()
        self.templates: dict = {}
        self.feed = deque(maxlen=4000)
        self.seq = 0
        self.flock = threading.Lock()
        self.next_event = (self._one("select max(id) from events") or 0) + 1
        self.ev_buf = []
        self.entities: dict = {}
        self.buckets = deque(maxlen=360)  # 10-second buckets of activity for the last hour
        self.recent_rate = deque(maxlen=50)
        self.total = 0
        self.started = time.time()
        threading.Thread(target=self._worker, daemon=True).start()
        threading.Thread(target=self._ticker, daemon=True).start()
        for r in self._rows("select id, kind, name, config from sources where enabled=1 and kind!='upload'"):
            self._start(r[0], r[1], r[2], json.loads(r[3]))

    # ---------------------------------------------------------------- db helpers
    def _rows(self, sql, params=()):
        with self.dbl:
            return self.con.execute(sql, params).fetchall()

    def _one(self, sql, params=()):
        r = self._rows(sql, params)
        return r[0][0] if r else None

    def _exec(self, sql, params=()):
        with self.dbl:
            cur = self.con.execute(sql, params)
            self.con.commit()
            return cur.lastrowid

    def _push(self, kind, payload):
        with self.flock:
            self.seq += 1
            self.feed.append((self.seq, kind, payload))

    def since(self, seq):
        with self.flock:
            return [x for x in self.feed if x[0] > seq], self.seq

    # ---------------------------------------------------------------- sources
    def add_source(self, kind, name, config):
        if kind not in KINDS:
            raise ValueError("Unknown connection type")
        if kind == "simulator":
            for s in self.sources.values():
                if s.kind == "simulator" and s.is_alive():
                    return s.sid
        sid = self._exec("insert into sources(kind,name,config,enabled,created) values (?,?,?,?,?)",
                         (kind, name, json.dumps(config), 1, datetime.now().isoformat(timespec="seconds")))
        self._start(sid, kind, name, config)
        return sid

    def _start(self, sid, kind, name, config):
        src = KINDS[kind](sid, name, config, self._sink)
        self.sources[sid] = src
        self.ai[sid] = WindowAI(window_secs=30, learn_windows=60 if kind == "upload" else 120)
        self.rules[sid] = RuleEngine()
        self.flushed.discard(sid)
        src.start()
        return src

    def stop_source(self, sid):
        s = self.sources.get(sid)
        if s:
            s.stop()
        self._exec("update sources set enabled=0 where id=?", (sid,))

    def start_source(self, sid):
        r = self._rows("select kind, name, config from sources where id=?", (sid,))
        if not r:
            raise KeyError(sid)
        old = self.sources.get(sid)
        if old and old.is_alive():
            return
        self._exec("update sources set enabled=1 where id=?", (sid,))
        self._start(sid, r[0][0], r[0][1], json.loads(r[0][2]))

    def remove_source(self, sid):
        self.stop_source(sid)
        self.sources.pop(sid, None)
        self._exec("delete from sources where id=?", (sid,))

    def simulator(self):
        for s in self.sources.values():
            if s.kind == "simulator" and s.is_alive():
                return s
        return None

    def _sink(self, sid, line, host):
        self.pending[sid] += 1
        self.q.put((sid, line, host))

    # ---------------------------------------------------------------- the worker
    def _worker(self):
        while True:
            try:
                sid, line, host = self.q.get(timeout=0.3)
            except queue.Empty:
                continue
            try:
                self._handle(sid, line, host)
            except Exception as e:  # one bad line must never stop the monitor
                self._push("error", {"source": sid, "text": str(e)[:200]})
            finally:
                self.pending[sid] -= 1

    def _handle(self, sid, line, host):
        now = datetime.now()
        ev = formats.parse(line, now, host)
        if not ev:
            return
        ev["ts"] = ev["ts"] or now  # lines without a time get the time they arrived
        ent = formats.entity(ev)
        res = self.miner.add_log_message(ev["msg"][:2000])
        tid = res["cluster_id"]
        if res["change_type"] != "none" or tid not in self.templates:
            self.templates[tid] = res["template_mined"]
        eid = self.next_event
        self.next_event += 1
        ts_iso = ev["ts"].isoformat(timespec="seconds")
        self.ev_buf.append((eid, ts_iso, sid, ev["fmt"], ev["host"], ev["app"], ent, ev["src_ip"], ev["user"],
                            ev["outcome"], ev["level"], tid, ev["raw"][:2000]))
        self.total += 1
        wm = self.watermark.get(sid)
        if wm is None or ev["ts"] > wm:
            self.watermark[sid] = ev["ts"]
        # entity activity for the "who's active" view
        e = self.entities.get(ent)
        if e is None:
            e = self.entities[ent] = {"events": 0, "fails": 0, "alerts": 0, "sev": None, "source": sid, "last": 0,
                                      "kind": "ip" if ev["src_ip"] and ent == ev["src_ip"] else ent.split(":")[0]}
        e["events"] += 1
        e["fails"] += ev["outcome"] == "fail"
        e["last"] = time.time()
        self._bucket()["events"] += 1
        self._push("event", {"id": eid, "source": sid, "ts": ts_iso, "entity": ent, "outcome": ev["outcome"],
                             "level": ev["level"], "raw": ev["raw"][:220],
                             "plain": plain_line(ev["fmt"], ev["msg"], ev["status"])})
        for hit in self.rules[sid].check(ev, ent):
            self._rule_alert(sid, hit, ev)
        self.ai[sid].add(ev, ent, tid, eid)

    def _bucket(self):
        k = int(time.time()) // 10 * 10
        if not self.buckets or self.buckets[-1]["t"] != k:
            self.buckets.append({"t": k, "events": 0, "alerts": 0})
        return self.buckets[-1]

    # ---------------------------------------------------------------- alerts
    def _rule_alert(self, sid, hit, ev):
        ts = ev["ts"].isoformat(timespec="seconds")
        if hit["update"]:
            row = self._rows("select id from alerts where source_id=? and entity=? and rule=? order by id desc limit 1",
                             (sid, hit["entity"], hit["rule"]))
            if row:
                self._exec("update alerts set count=count+1, last_ts=?, detail=? where id=?", (ts, hit["detail"], row[0][0]))
                self._push("alert_update", {"id": row[0][0]})
            return
        self._new_alert(sid, hit["entity"], "pattern", hit["rule"], hit["severity"], hit["title"], hit["detail"], [],
                        hit["advice"], hit["mitre"], None, None, ts, ts)

    def _ai_alerts(self, sid, results):
        for r in results:
            ent = r["entity"]
            start = r["start"].isoformat(timespec="seconds")
            end = (r["start"] + timedelta(seconds=30)).isoformat(timespec="seconds")
            recent = self._rows("select id from alerts where source_id=? and entity=? and kind='ai' and last_ts>=?",
                                (sid, ent, (r["start"] - timedelta(minutes=5)).isoformat(timespec="seconds")))
            if recent:
                self._exec("update alerts set count=count+1, last_ts=?, score=max(score,?) where id=?",
                           (end, r["score"], recent[0][0]))
                self._push("alert_update", {"id": recent[0][0]})
                continue
            sev = "high" if r["strength"] >= 5 or r["score"] > r["threshold"] + 0.08 else "medium"
            why = r["why"] or ["its overall mix of activity is very different from normal"]
            who = "This address" if formats.RE_IP.fullmatch(ent) else ("This user" if ent.startswith("user:") else "This machine")
            detail = f"{who}, in 30 seconds, " + "; ".join(why) + "."
            self._new_alert(sid, ent, "ai", "unusual", sev, "Unusual behaviour the AI hasn't seen before", detail, why,
                            "Look at what this address or user did. If it isn't expected, block it and check the affected accounts.",
                            "Anomaly detection (Isolation Forest)", r["score"], r["threshold"], start, end)

    def _new_alert(self, sid, ent, kind, rule, sev, title, detail, why, advice, mitre, score, thr, first_ts, last_ts):
        aid = self._exec("insert into alerts(created,first_ts,last_ts,source_id,entity,kind,rule,severity,title,detail,why,"
                         "advice,mitre,score,threshold,count,status) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'new')",
                         (datetime.now().isoformat(timespec="seconds"), first_ts, last_ts, sid, ent, kind, rule, sev,
                          title, detail, json.dumps(why), advice, mitre, score, thr))
        e = self.entities.get(ent)
        if e:
            e["alerts"] += 1
            if e["sev"] is None or SEV_W[sev] > SEV_W[e["sev"]]:
                e["sev"] = sev
        self._bucket()["alerts"] += 1
        src = self.sources.get(sid)
        if src and src.kind == "simulator":
            src.sim.mark_detected(ent, aid, "AI" if kind == "ai" else "known pattern")
        self._push("alert", self.alert_brief(aid))
        return aid

    # ---------------------------------------------------------------- background ticks
    def _ticker(self):
        last = 0
        while True:
            time.sleep(0.5)
            try:
                self._flush_events()
                for sid, src in list(self.sources.items()):
                    ai = self.ai.get(sid)
                    if not ai:
                        continue
                    caught_up = self.pending[sid] <= 0 and (src.kind != "simulator" or src.sim.ready)
                    if src.live and caught_up and src.is_alive():
                        # live sources: time moves on even when nothing is logged
                        now = datetime.now()
                        wm = self.watermark.get(sid)
                        self.watermark[sid] = max(wm, now) if wm else now
                    wm = self.watermark.get(sid)
                    if wm:
                        was_learning = ai.learning
                        self._ai_alerts(sid, ai.close(wm))
                        if was_learning and not ai.learning:
                            self._push("learned", {"source": sid})
                    if not src.live and src.done and self.pending[sid] <= 0 and sid not in self.flushed:
                        self.flushed.add(sid)
                        self._flush_events()
                        self._ai_alerts(sid, ai.flush())
                        self._push("source_done", {"source": sid})
                n = self.total
                self.recent_rate.append((time.time(), n))
                if time.time() - last > 1:
                    last = time.time()
                    self._push("stats", self.stats())
            except Exception as e:
                self._push("error", {"text": str(e)[:200]})

    def _flush_events(self):
        if not self.ev_buf:
            return
        buf, self.ev_buf = self.ev_buf, []
        with self.dbl:
            self.con.executemany("insert into events values (?,?,?,?,?,?,?,?,?,?,?,?,?)", buf)
            self.con.executemany("insert or replace into templates values (?,?)", list(self.templates.items()))
            self.con.commit()

    # ---------------------------------------------------------------- read side
    def rate(self):
        if len(self.recent_rate) < 2:
            return 0.0
        (t0, n0), (t1, n1) = self.recent_rate[0], self.recent_rate[-1]
        return (n1 - n0) / max(t1 - t0, 0.5)

    def threat(self):
        since = (datetime.now() - timedelta(minutes=10)).isoformat(timespec="seconds")
        rows = self._rows("select severity, count(*) from alerts where created>=? and status not in ('false','resolved') "
                          "group by severity", (since,))
        score = sum(SEV_W.get(s, 1) * n for s, n in rows)
        crit = any(s == "critical" for s, _ in rows)
        level = [name for lim, name in LEVELS if score >= lim][-1]
        if crit:
            level = "Under attack"
        return {"score": score, "level": level, "counts": dict(rows)}

    def stats(self):
        srcs = []
        for sid, s in self.sources.items():
            ai = self.ai.get(sid)
            d = s.info()
            d.update(learning=ai.learning if ai else None, progress=round(ai.progress, 2) if ai else None,
                     alive=s.is_alive(), pending=max(self.pending[sid], 0))
            srcs.append(d)
        open_alerts = self._one("select count(*) from alerts where status='new'") or 0
        return {"total": self.total, "rate": round(self.rate(), 1), "sources": srcs, "threat": self.threat(),
                "open_alerts": open_alerts, "queue": self.q.qsize(),
                "buckets": list(self.buckets)[-60:]}

    def known_sources(self):
        live = {sid: s for sid, s in self.sources.items()}
        out = []
        for sid, kind, name, cfg, enabled, created in self._rows("select * from sources order by id desc"):
            s = live.get(sid)
            ai = self.ai.get(sid)
            d = s.info() if s else {"id": sid, "kind": kind, "name": name, "config": json.loads(cfg),
                                    "status": "finished" if kind == "upload" else "stopped",
                                    "lines": self._one("select count(*) from events where source_id=?", (sid,)) or 0,
                                    "error": None, "last_line": None, "done": kind == "upload", "live": kind != "upload"}
            d.update(enabled=bool(enabled), created=created, alive=bool(s and s.is_alive()),
                     learning=ai.learning if ai else None, progress=round(ai.progress, 2) if ai else None,
                     alerts=self._one("select count(*) from alerts where source_id=?", (sid,)) or 0)
            out.append(d)
        return out

    def alert_brief(self, aid):
        r = self._rows("select id, created, first_ts, last_ts, source_id, entity, kind, rule, severity, title, detail, "
                       "count, status, mitre from alerts where id=?", (aid,))
        if not r:
            return None
        k = ["id", "created", "first_ts", "last_ts", "source", "entity", "kind", "rule", "severity", "title", "detail",
             "count", "status", "mitre"]
        d = dict(zip(k, r[0]))
        s = self.sources.get(d["source"])
        d["source_name"] = s.name if s else self._one("select name from sources where id=?", (d["source"],))
        return d

    def alerts(self, limit=500, status=None):
        sql = "select id from alerts"
        params = ()
        if status:
            sql += " where status=?"
            params = (status,)
        ids = [r[0] for r in self._rows(sql + " order by id desc limit ?", params + (limit,))]
        return [self.alert_brief(i) for i in ids]

    def alert_detail(self, aid):
        d = self.alert_brief(aid)
        if not d:
            return None
        r = self._rows("select why, advice, score, threshold from alerts where id=?", (aid,))[0]
        d.update(why=json.loads(r[0] or "[]"), advice=r[1], score=r[2], threshold=r[3])
        t0 = (datetime.fromisoformat(d["first_ts"]) - timedelta(minutes=2 if d["kind"] == "pattern" else 0)).isoformat(timespec="seconds")
        t1 = (datetime.fromisoformat(d["last_ts"]) + timedelta(seconds=2)).isoformat(timespec="seconds")
        self._flush_events()
        rows = self._rows("select id, ts, fmt, outcome, level, raw from events where source_id=? and entity=? "
                          "and ts between ? and ? order by id limit 300", (d["source"], d["entity"], t0, t1))
        lines = []
        for i, ts, fmt, outcome, level, raw in rows:
            ev = formats.parse(raw) or {"msg": raw, "status": None}
            lines.append({"id": i, "time": ts[11:], "raw": raw, "outcome": outcome,
                          "plain": plain_line(fmt, ev["msg"], ev.get("status")) or ev["msg"][:120],
                          "bad": outcome == "fail" or (level or "") in ("warning", "error", "crit", "critical")})
        d["lines"] = lines
        d["entity_total"] = self._one("select count(*) from events where source_id=? and entity=?", (d["source"], d["entity"]))
        return d

    def set_status(self, aid, status):
        if status not in ("new", "real", "false", "resolved"):
            raise ValueError("status must be new, real, false or resolved")
        self._exec("update alerts set status=? where id=?", (status, aid))

    def entity_list(self, minutes=15, top=60):
        cut = time.time() - minutes * 60
        items = [(k, v) for k, v in self.entities.items() if v["last"] >= cut]
        items.sort(key=lambda kv: (-(SEV_W.get(kv[1]["sev"], 0)), -kv[1]["events"]))
        return [{"entity": k, **v} for k, v in items[:top]]

    def save_upload(self, name, stream_iter):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(name or "upload.log"))[:80] or "upload.log"
        path = os.path.join(self.upload_dir, f"{int(time.time())}_{safe}")
        size = 0
        with open(path, "wb") as f:
            for chunk in stream_iter:
                f.write(chunk)
                size += len(chunk)
        return path, size

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

from . import elk, firewall, formats, insight
from .ai import WindowAI
from .learning import Learner
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
    score REAL, threshold REAL, count INTEGER, status TEXT, features TEXT, learned INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS lessons (id INTEGER PRIMARY KEY, created TEXT, alert_id INTEGER, label TEXT, text TEXT);
CREATE TABLE IF NOT EXISTS memory (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS templates (id INTEGER PRIMARY KEY, template TEXT);
CREATE TABLE IF NOT EXISTS blocks (entity TEXT PRIMARY KEY, created REAL, until REAL, alert_id INTEGER, mode TEXT);
CREATE INDEX IF NOT EXISTS ev_entity2 ON events(entity, ts);
CREATE INDEX IF NOT EXISTS al_entity ON alerts(entity);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
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
        self.con = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        # WAL + normal sync: safe, and much faster on Windows where every commit otherwise waits for the disk
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=NORMAL")
        self.con.executescript(SCHEMA)
        for col in ("features TEXT", "learned INTEGER DEFAULT 0"):  # older databases
            try:
                self.con.execute(f"alter table alerts add column {col}")
            except sqlite3.OperationalError:
                pass
        row = self.con.execute("select value from memory where key='learner'").fetchone()
        self.learner = Learner(json.loads(row[0]) if row else None)
        self._learner_saved = self.learner.dump()
        self.dbl = threading.Lock()
        self.q: queue.Queue = queue.Queue(maxsize=20000)
        self.sources: dict = {}
        self.ai: dict = {}
        self.rules: dict = {}
        self.watermark: dict = {}
        self.pending = defaultdict(int)
        self.flushed: set = set()
        self.miner = make_miner(live=True)
        self.templates: dict = {}
        self.feed = deque(maxlen=4000)
        self.seq = 0
        self.flock = threading.Lock()
        self.next_event = (self._one("select max(id) from events") or 0) + 1
        self.ev_buf = []
        self.upd: dict = {}  # alert id -> [extra count, last time, latest detail], saved in batches
        self.rule_open: dict = {}  # (source, who, rule) -> [alert id, last time]: the open alert an attack keeps updating
        self.ulock = threading.Lock()
        self.entities: dict = {}
        self.buckets = deque(maxlen=360)  # 10-second buckets of activity for the last hour
        self.recent_rate = deque(maxlen=50)
        self.total = 0
        self.started = time.time()
        self.blocks = {r[0]: r[1] for r in self._rows("select entity, until from blocks where until>?", (time.time(),))}
        self._restore_recent()
        row = self.con.execute("select value from memory where key='settings'").fetchone()
        self.settings = {"real_firewall": False, **(json.loads(row[0]) if row else {})}
        # ELK Stack: send events and alerts to Elasticsearch when switched on (or SECLOG_ELASTIC is set)
        self.elastic = elk.Shipper(self.settings.get("elastic_url") or os.environ.get("SECLOG_ELASTIC"),
                                   via=self.settings.get("logstash_url") or os.environ.get("SECLOG_LOGSTASH"))
        self._last_expiry = 0
        threading.Thread(target=self._firewall_tidy, daemon=True).start()
        threading.Thread(target=self._worker, daemon=True).start()
        threading.Thread(target=self._ticker, daemon=True).start()
        for r in self._rows("select id, kind, name, config from sources where enabled=1 and kind!='upload'"):
            self._start(r[0], r[1], r[2], json.loads(r[3]))

    def _restore_recent(self, minutes=60):
        """After a restart, rebuild 'who's active' and the activity chart from the last hour in the database."""
        now = time.time()
        cut = (datetime.now() - timedelta(minutes=minutes)).isoformat(timespec="seconds")
        try:
            rows = self._rows("select entity, count(*), coalesce(sum(outcome='fail'),0), max(ts), min(source_id), "
                              "max(src_ip=entity) from events where ts>=? group by entity", (cut,))
            sev = {}
            for ent, n, s in self._rows("select entity, count(*), max(case severity when 'critical' then 4 when 'high' then 3 "
                                        "when 'medium' then 2 else 1 end) from alerts where created>=? group by entity", (cut,)):
                sev[ent] = (n, {4: "critical", 3: "high", 2: "medium", 1: "low"}[s])
            for ent, n, fails, last, sid, is_ip in rows:
                n_al, sv = sev.get(ent, (0, None))
                self.entities[ent] = {"events": n, "fails": fails, "alerts": n_al, "sev": sv, "source": sid,
                                      "last": min(now, self._epoch(last)), "kind": "ip" if is_ip else ent.split(":")[0]}
            # the activity chart: 10-second buckets of the last 10 minutes
            cut10 = (datetime.now() - timedelta(minutes=10)).isoformat(timespec="seconds")
            b = defaultdict(lambda: {"events": 0, "alerts": 0})
            for ts, in self._rows("select ts from events where ts>=?", (cut10,)):
                b[int(self._epoch(ts)) // 10 * 10]["events"] += 1
            for c, in self._rows("select created from alerts where created>=?", (cut10,)):
                b[int(self._epoch(c)) // 10 * 10]["alerts"] += 1
            for t in sorted(b):
                if t <= now:
                    self.buckets.append({"t": t, **b[t]})
        except Exception:  # never stop the monitor from starting
            pass

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
        self.ai[sid] = WindowAI(window_secs=30, learn_windows=60 if kind == "upload" else 120, learner=self.learner,
                                offline=kind == "upload")
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
    def is_blocked(self, ent):
        until = self.blocks.get(ent)
        if until and until <= time.time():
            self.blocks.pop(ent, None)
            return False
        return bool(until)

    def _queue_update(self, aid, ts, detail):
        """A repeat of an open alert: count it in memory, save in one batch (saving each one is slow on Windows)."""
        with self.ulock:
            u = self.upd.get(aid)
            if u:
                u[0] += 1
                u[1] = max(u[1], ts)
                u[2] = detail
            else:
                self.upd[aid] = [1, ts, detail]

    def _rule_alert(self, sid, hit, ev):
        ts = ev["ts"].isoformat(timespec="seconds")
        if self.is_blocked(hit["entity"]):
            return  # already blocked: its traffic is being dropped, no need to raise it again
        if self.learner.muted(hit["rule"], hit["entity"]):
            if not hit["update"]:
                self.learner.count("avoided")  # a person said this one was a false alarm before
            return
        key = (sid, hit["entity"], hit["rule"])
        o = self.rule_open.get(key)
        if hit["update"]:
            if o:
                o[1] = max(o[1], ts)
                self._queue_update(o[0], ts, hit["detail"])
            else:
                row = self._rows("select id from alerts where source_id=? and entity=? and rule=? order by id desc limit 1", key)
                if row:
                    self._queue_update(row[0][0], ts, hit["detail"])
            return
        # one attack, one alert: while the same attack carries on (within 30 minutes), update the open alert
        since = (ev["ts"] - timedelta(minutes=30)).isoformat(timespec="seconds")
        if o is None:  # e.g. after a restart: look in the database
            row = self._rows("select id, last_ts from alerts where source_id=? and entity=? and rule=? and status='new' "
                             "order by id desc limit 1", key)
            o = self.rule_open[key] = [row[0][0], row[0][1]] if row else None
        if o and o[1] >= since:
            o[1] = max(o[1], ts)
            self._queue_update(o[0], ts, hit["detail"])
            return
        self.rule_open[key] = [None, ts]
        self.rule_open[key][0] = self._new_alert(sid, hit["entity"], "pattern", hit["rule"], hit["severity"], hit["title"], hit["detail"], [],
                        hit["advice"], hit["mitre"], None, None, ts, ts,
                        features=self.ai[sid].current_features(hit["entity"]))

    def _ai_alerts(self, sid, results):
        for r in results:
            ent = r["entity"]
            if self.is_blocked(ent):
                continue
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
            title = "Unusual behaviour the AI hasn't seen before"
            if r.get("learned"):
                title = "Looks like a threat you taught the AI about"
                detail += " The AI only caught this because you confirmed a similar threat before."
            self._new_alert(sid, ent, "ai", "learned" if r.get("learned") else "unusual", sev, title, detail, why,
                            "Look at what this address or user did. If it isn't expected, block it and check the affected accounts.",
                            "Anomaly detection (Isolation Forest) + learning from feedback" if r.get("learned")
                            else "Anomaly detection (Isolation Forest)", r["score"], r["threshold"], start, end,
                            features=r.get("features"), learned=bool(r.get("learned")))

    def _new_alert(self, sid, ent, kind, rule, sev, title, detail, why, advice, mitre, score, thr, first_ts, last_ts,
                   features=None, learned=False):
        aid = self._exec("insert into alerts(created,first_ts,last_ts,source_id,entity,kind,rule,severity,title,detail,why,"
                         "advice,mitre,score,threshold,count,status,features,learned) "
                         "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'new',?,?)",
                         (datetime.now().isoformat(timespec="seconds"), first_ts, last_ts, sid, ent, kind, rule, sev,
                          title, detail, json.dumps(why), advice, mitre, score, thr, json.dumps(features or []), int(learned)))
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
        self._ship_alert(aid)
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
                        self._flush_events()
                        try:
                            self._ai_alerts(sid, ai.flush())
                        finally:
                            self.flushed.add(sid)  # only "finished" once the AI has judged the whole file
                        self._push("source_done", {"source": sid})
                n = self.total
                self.recent_rate.append((time.time(), n))
                if time.time() - last > 1:
                    last = time.time()
                    self._push("stats", self.stats())
                    self._save_learner()
                if time.time() - self._last_expiry > 15:
                    self._last_expiry = time.time()
                    self._expire_blocks()
            except Exception as e:
                self._push("error", {"text": str(e)[:200]})

    def _flush_events(self):
        if self.upd:
            with self.ulock:
                upd, self.upd = self.upd, {}
            with self.dbl:
                self.con.executemany("update alerts set count=count+?, last_ts=max(last_ts, ?), detail=? where id=?",
                                     [(n, ts, d, aid) for aid, (n, ts, d) in upd.items()])
                self.con.commit()
            for aid in upd:
                self._push("alert_update", {"id": aid})
                self._ship_alert(aid)
        if not self.ev_buf:
            return
        buf, self.ev_buf = self.ev_buf, []
        with self.dbl:
            self.con.executemany("insert into events values (?,?,?,?,?,?,?,?,?,?,?,?,?)", buf)
            self.con.executemany("insert or replace into templates values (?,?)", list(self.templates.items()))
            self.con.commit()
        if self.elastic.on:
            for row in buf:
                self.elastic.event(row)

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
                       "count, status, mitre, learned from alerts where id=?", (aid,))
        if not r:
            return None
        k = ["id", "created", "first_ts", "last_ts", "source", "entity", "kind", "rule", "severity", "title", "detail",
             "count", "status", "mitre", "learned"]
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
        """Save a person's answer. 'real' and 'false' also teach the AI (learning.py)."""
        if status not in ("new", "real", "false", "resolved"):
            raise ValueError("status must be new, real, false or resolved")
        r = self._rows("select status, kind, rule, entity, features, title from alerts where id=?", (aid,))
        if not r:
            raise KeyError(aid)
        old, kind, rule, ent, feats, title = r[0]
        self._exec("update alerts set status=? where id=?", (status, aid))
        self._ship_alert(aid)
        if status != "new":  # a person has dealt with it: the next attack gets a fresh alert
            for k in [k for k, v in self.rule_open.items() if v and v[0] == aid]:
                del self.rule_open[k]
        lessons = []
        if status in ("real", "false") and status != old:
            lessons = self.learner.learn(status, kind, rule, ent, json.loads(feats or "[]"), title)
            now = datetime.now().isoformat(timespec="seconds")
            for t in lessons:
                self._exec("insert into lessons(created, alert_id, label, text) values (?,?,?,?)", (now, aid, status, t))
            self._save_learner(force=True)
            if lessons:
                self._push("lesson", {"alert": aid, "label": status, "lessons": lessons})
        return lessons

    def _save_learner(self, force=False):
        d = self.learner.dump()
        if force or d != self._learner_saved:
            self._exec("insert or replace into memory values ('learner', ?)", (d,))
            self._learner_saved = d

    def ai_view(self):
        """Everything the 'AI learning' page shows."""
        conns = []
        for sid, s in self.sources.items():
            ai = self.ai.get(sid)
            if not ai:
                continue
            conns.append({"id": sid, "name": s.name, "kind": s.kind, "alive": s.is_alive(), "learning": ai.learning,
                          "progress": round(ai.progress, 2), "trained_on": ai.trained_on, "retrains": ai.retrains,
                          "threshold": round(ai.threshold, 3) if ai.threshold else None,
                          "windows_ok": len(ai.recent_ok)})
        lessons = [dict(zip(["created", "alert_id", "label", "text"], r)) for r in
                   self._rows("select created, alert_id, label, text from lessons order by id desc limit 60")]
        learned = [self.alert_brief(r[0]) for r in self._rows("select id from alerts where learned=1 order by id desc limit 10")]
        # before and after teaching: the lab's sneaky thefts, split by the first time a person said "real"
        first_real = self._one("select min(created) from lessons where label='real'")
        t_real = self._epoch(first_real) if first_real else None
        sim = self.simulator()
        runs = []
        for a in reversed(sim.sim.attacks if sim else []):
            if a["kind"] != "sneaky_theft":
                continue
            missed = not a["detected"] and time.time() > (a["ends"] or 0) + 45
            runs.append({"launched": a["launched"], "detected": a["detected"], "by": a["by"], "alert_id": a["alert_id"],
                         "caught_in": round(a["detected"] - a["launched"], 1) if a["detected"] else None,
                         "missed": missed, "running": not a["detected"] and not missed,
                         "after": bool(t_real and a["launched"] > t_real)})
        return {**self.learner.view(), "connections": conns, "lessons": lessons, "learned_alerts": learned,
                "taught_at": t_real, "sneaky_runs": runs}

    def reset_learning(self):
        self.learner.reset()
        for ai in self.ai.values():
            ai.learner = self.learner
        self._exec("delete from lessons")
        self._save_learner(force=True)


    def entity_list(self, minutes=15, top=60):
        cut = time.time() - minutes * 60
        items = [(k, v) for k, v in self.entities.items() if v["last"] >= cut]
        items.sort(key=lambda kv: (-(SEV_W.get(kv[1]["sev"], 0)), -kv[1]["events"]))
        alerts = self._alert_times()
        now = time.time()
        out = []
        for k, v in items[:top]:
            r = insight.risk(alerts.get(k, []), v["fails"], now)
            out.append({"entity": k, **v, "risk": r, "band": insight.band(r)[0], "blocked": self.is_blocked(k)})
        return out

    @staticmethod
    def _epoch(iso):
        return datetime.fromisoformat(iso).timestamp()

    def _alert_times(self, entity=None, hours=12):
        cut = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
        sql, params = "select entity, created, severity, status from alerts where created>=?", (cut,)
        if entity:
            sql, params = sql + " and entity=?", (cut, entity)
        out = defaultdict(list)
        for e, c, sev, st in self._rows(sql, params):
            out[e].append((self._epoch(c), sev, st))
        return out

    # ---------------------------------------------------------------- map, profiles, attack stories
    def map_data(self, minutes=60):
        pts, countries = [], {}
        for e in self.entity_list(minutes, top=600):
            if not insight.is_ip(e["entity"]):
                continue
            g = insight.locate(e["entity"])
            p = {"entity": e["entity"], "cc": g["cc"], "country": g["country"], "internal": g["internal"],
                 "events": e["events"], "fails": e["fails"], "alerts": e["alerts"], "sev": e["sev"],
                 "risk": e["risk"], "band": e["band"], "blocked": e["blocked"]}
            pts.append(p)
            c = countries.setdefault(g["country"] or "Unknown", {"country": g["country"] or "Unknown", "cc": g["cc"],
                                                                  "addresses": 0, "events": 0, "threats": 0, "risk": 0})
            c["addresses"] += 1
            c["events"] += e["events"]
            c["threats"] += e["alerts"]
            c["risk"] = max(c["risk"], e["risk"])
        cl = sorted(countries.values(), key=lambda c: (-c["threats"], -c["risk"], -c["events"]))
        return {"home": insight.HOME, "points": pts, "countries": cl}

    def story(self, ent, alert_id=None):
        """The attack story: which steps of an attack this address or user (and the accounts it used) reached."""
        self._flush_events()
        related = {ent}
        if insight.is_ip(ent):
            related |= {f"user:{u}" for (u,) in self._rows(
                "select distinct user from events where src_ip=? and outcome='success' and user is not null", (ent,))}
        elif ent.startswith("user:"):
            related |= {ip for (ip,) in self._rows(
                "select distinct src_ip from events where user=? and outcome='success' and src_ip is not null", (ent[5:],))}
        cols = "id, created, first_ts, kind, rule, severity, title, features, status, entity"
        if alert_id:
            c = self._one("select created from alerts where id=?", (alert_id,))
            centre = [self._epoch(c)] if c else []
        else:
            centre = [self._epoch(c) for (c,) in self._rows(
                "select created from alerts where entity=? and status!='false'", (ent,))]
        if not centre:
            return {"stages": [dict(zip(("key", "name", "desc", "tactic", "code"), s), alerts=[]) for s in insight.STAGES],
                    "reached": 0, "summary": None, "verdict": None, "entities": []}
        lo = datetime.fromtimestamp(min(centre) - 1800).isoformat(timespec="seconds")
        hi = datetime.fromtimestamp(max(centre) + 1800).isoformat(timespec="seconds")
        qs = ",".join("?" * len(related))
        rows = self._rows(f"select {cols} from alerts where entity in ({qs}) and created between ? and ? "
                          "and status!='false' order by first_ts", (*related, lo, hi))
        stages = [dict(zip(("key", "name", "desc", "tactic", "code"), s), alerts=[]) for s in insight.STAGES]
        times = []
        for aid, created, first_ts, kind, rule, sev, title, feats, status, e in rows:
            st = insight.stage_of(kind, rule, json.loads(feats or "[]"))
            stages[insight.STAGE_IX[st]]["alerts"].append({"id": aid, "title": title, "entity": e, "severity": sev,
                                                          "time": first_ts, "current": aid == alert_id, "rule": rule})
            times.append(self._epoch(first_ts))
        reached = [s for s in stages if s["alerts"]]
        if not reached:
            return {"stages": stages, "reached": 0, "summary": None, "verdict": None, "entities": []}
        span = max(times) - min(times)
        summary = f"{len(reached)} of {len(stages)} attack steps seen: " + ", then ".join(s["name"].lower() for s in reached)
        summary += f", over {insight.secs_text(span)}." if span >= 1 else "."
        far = max(insight.STAGE_IX[s["key"]] for s in reached)
        got_in = any(a["rule"] == "break_in" for s in reached for a in s["alerts"])
        verdict = {0: "So far it is only looking around.", 1: "It is trying to get in. No sign it got in yet.",
                   2: "It got in." if got_in else "It tried to break in.",
                   3: "It got in and became an administrator.", 4: "It got in and set up a way to come back.",
                   5: "It got in and tried to hide its tracks.",
                   6: "No break-in steps came before it, so it probably used ordinary access, such as the public website."
                   if len(reached) == 1 else "It got as far as taking data or doing harm."}[far]
        ents = sorted({a["entity"] for s in stages for a in s["alerts"]})
        return {"stages": stages, "reached": len(reached), "summary": summary, "verdict": verdict, "entities": ents,
                "furthest": stages[far]["name"]}

    def entity_profile(self, ent):
        self._flush_events()
        n, fails, first, last = self._rows("select count(*), coalesce(sum(outcome='fail'),0), min(ts), max(ts) "
                                           "from events where entity=?", (ent,))[0]
        ids = [r[0] for r in self._rows("select id from alerts where entity=? order by id desc limit 200", (ent,))]
        if not n and not ids:
            return None
        now = time.time()
        times = self._alert_times(ent, hours=48).get(ent, [])
        mem = self.entities.get(ent)
        score = insight.risk(times, mem["fails"] if mem else min(fails, 25), now)
        trend = [insight.risk(times, 0, now - (12 - i) * 300) for i in range(12)] + [score]
        srcs = [r[0] for r in self._rows("select distinct s.name from events e join sources s on s.id=e.source_id "
                                         "where e.entity=? limit 6", (ent,))]
        used = []
        if insight.is_ip(ent):
            used = [f"user:{r[0]}" for r in self._rows("select user, count(*) n from events where src_ip=? and user is not null "
                                                       "group by user order by n desc limit 8", (ent,))]
        elif ent.startswith("user:"):
            used = [r[0] for r in self._rows("select src_ip, count(*) n from events where user=? and src_ip is not null "
                                               "group by src_ip order by n desc limit 8", (ent[5:],))]
        act = []
        if last:
            t_last = datetime.fromisoformat(last)
            t0 = t_last - timedelta(minutes=29, seconds=t_last.second)
            buckets = [{"events": 0, "fails": 0} for _ in range(30)]
            for ts, outcome in self._rows("select ts, outcome from events where entity=? and ts>=?",
                                          (ent, t0.isoformat(timespec="seconds"))):
                i = int((datetime.fromisoformat(ts) - t0).total_seconds() // 60)
                if 0 <= i < 30:
                    buckets[i]["events"] += 1
                    buckets[i]["fails"] += outcome == "fail"
            act = {"start": t0.isoformat(timespec="seconds"), "minutes": buckets}
        lines = []
        for i, ts, fmt, outcome, level, raw in self._rows("select id, ts, fmt, outcome, level, raw from events where entity=? "
                                                          "order by id desc limit 25", (ent,)):
            ev = formats.parse(raw) or {"msg": raw, "status": None}
            lines.append({"id": i, "time": ts, "raw": raw, "bad": outcome == "fail" or (level or "") in ("warning", "error", "crit", "critical"),
                          "plain": plain_line(fmt, ev["msg"], ev.get("status")) or ev["msg"][:120]})
        geo = insight.locate(ent) if insight.is_ip(ent) else None
        blk = self._rows("select created, until, mode from blocks where entity=? and until>?", (ent, now))
        return {"entity": ent, "kind": "ip" if insight.is_ip(ent) else ent.split(":")[0], "geo": geo,
                "risk": score, "band": insight.band(score)[0], "band_text": insight.band(score)[1], "trend": trend,
                "events": n, "fails": fails, "first_seen": first, "last_seen": last, "sources": srcs, "used": used,
                "activity": act, "alerts": [self.alert_brief(i) for i in ids], "story": self.story(ent), "lines": lines[::-1],
                "blocked": {"created": blk[0][0], "until": blk[0][1], "mode": blk[0][2]} if blk else None,
                "can_block": insight.is_ip(ent) and not insight.allowlisted(ent)}

    # ---------------------------------------------------------------- responding: block an address
    def block(self, ent, minutes=30, alert_id=None):
        if not insight.is_ip(ent):
            raise ValueError("Only an address can be blocked. For a user account, lock the account on the server.")
        if insight.allowlisted(ent):
            raise PermissionError(f"{ent} is inside your own network, so it is on the allowlist and isn't blocked. "
                                  "This stops the monitor from locking out your own machines.")
        until = time.time() + minutes * 60
        sim = self.simulator()
        in_lab = bool(sim and sim.sim.block(ent))
        mode, problem = ("lab" if in_lab else "simulated"), None
        if not in_lab and self.settings.get("real_firewall"):
            if firewall.status()["available"]:
                ok, out = firewall.add(ent)
                if ok:
                    mode = "firewall"
                else:
                    problem = out[:200] or "the firewall refused the rule"
            else:
                problem = firewall.status()["why"]
        self._exec("insert or replace into blocks values (?,?,?,?,?)", (ent, time.time(), until, alert_id, mode))
        self.blocks[ent] = until
        e = self.entities.get(ent)
        if e:
            e["last"] = time.time()
        if mode == "lab":
            text = f"Blocked in the attack lab for {minutes} minutes. The lab firewall now drops everything from {ent}."
        elif mode == "firewall":
            text = (f"Blocked with the Windows Firewall for {minutes} minutes. A rule named \"{firewall.rule_name(ent)}\" "
                    "now drops all incoming traffic from it, and is removed automatically when the block ends.")
        elif problem:
            text = f"Marked as blocked for {minutes} minutes, but the real firewall rule could not be added: {problem}"
        else:
            text = (f"Marked as blocked for {minutes} minutes. This block is simulated. To really block it, switch on "
                    "\"Block with the Windows Firewall\" on the Connect logs page (needs administrator).")
        self._push("block", {"entity": ent, "until": until, "mode": mode, "text": text})
        return {"entity": ent, "until": until, "mode": mode, "text": text}

    def unblock(self, ent):
        mode = self._one("select mode from blocks where entity=?", (ent,))
        if mode == "firewall":
            firewall.remove(ent)
        self._exec("delete from blocks where entity=?", (ent,))
        self.blocks.pop(ent, None)
        sim = self.simulator()
        if sim:
            sim.sim.unblock(ent)
        self._push("unblock", {"entity": ent})

    # ---------------------------------------------------------------- the real firewall (optional)
    def _expire_blocks(self):
        """Remove firewall rules for blocks that have ended, and forget ended blocks."""
        now = time.time()
        for (ent,) in self._rows("select entity from blocks where until<=? and mode='firewall'", (now,)):
            firewall.remove(ent)
        if self._one("select count(*) from blocks where until<=?", (now,)):
            self._exec("delete from blocks where until<=?", (now,))

    def _firewall_tidy(self):
        """At start-up: remove any of our rules left behind (for example after a crash) that no longer match a block."""
        try:
            self._expire_blocks()
            if firewall.status()["available"]:
                active = {r[0] for r in self._rows("select entity from blocks where mode='firewall' and until>?", (time.time(),))}
                for ip in firewall.ours():
                    if ip not in active:
                        firewall.remove(ip)
        except Exception:
            pass

    def response_view(self):
        return {"firewall": firewall.status(), "real_firewall": bool(self.settings.get("real_firewall")),
                "blocks": self.block_list(), "rule_prefix": firewall.PREFIX.strip(), "minutes": 30}

    def set_real_firewall(self, on):
        on = bool(on)
        if on and not firewall.status()["available"]:
            raise PermissionError(firewall.status()["why"])
        self.settings["real_firewall"] = on
        self._exec("insert or replace into memory values ('settings', ?)", (json.dumps(self.settings),))
        if not on:  # switching off removes every rule we added; the blocks carry on as simulated
            for (ent,) in self._rows("select entity from blocks where mode='firewall'"):
                firewall.remove(ent)
            self._exec("update blocks set mode='simulated' where mode='firewall'")
        return self.response_view()

    def firewall_test(self, ip="203.0.113.50"):
        """Prove it works without touching real traffic: add a rule for a documentation-only address, check, remove."""
        st = firewall.status()
        if not st["available"]:
            raise PermissionError(st["why"])
        steps = []
        ok, out = firewall.add(ip)
        steps.append({"step": f"Add a rule blocking {ip} (an address reserved for examples, never used on the internet)",
                      "ok": ok, "detail": "" if ok else out[:200]})
        found = firewall.exists(ip)
        steps.append({"step": f"Windows Firewall now lists the rule \"{firewall.rule_name(ip)}\"", "ok": found, "detail": ""})
        firewall.remove(ip)
        gone = not firewall.exists(ip)
        steps.append({"step": "Remove the rule again", "ok": gone, "detail": ""})
        return {"ok": ok and found and gone, "steps": steps}

    # ---------------------------------------------------------------- ELK Stack (Elasticsearch + Kibana)
    def _alert_row(self, aid):
        with self.dbl:
            cur = self.con.execute("select * from alerts where id=?", (aid,))
            row = cur.fetchone()
            return dict(zip([c[0] for c in cur.description], row)) if row else None

    def _ship_alert(self, aid):
        if self.elastic.on:
            a = self._alert_row(aid)
            if a:
                self.elastic.alert(a)

    def elastic_view(self):
        return {**self.elastic.status(), "kibana": os.environ.get("SECLOG_KIBANA", "http://127.0.0.1:5601"),
                "dashboard": "/app/dashboards#/view/seclog-overview"}

    def set_elastic(self, url, via=None, backfill_events=20000):
        """Switch sending on (url) or off (None), straight to Elasticsearch or through Logstash (via).
        On: also sends every alert so far and the latest log lines."""
        self.elastic.configure(url, via)
        self.settings["elastic_url"], self.settings["logstash_url"] = self.elastic.url, self.elastic.via
        self._exec("insert or replace into memory values ('settings', ?)", (json.dumps(self.settings),))
        if self.elastic.on:
            self._flush_events()
            rows = self._rows("select * from (select * from events order by id desc limit ?) order by id", (backfill_events,))
            for r in rows:
                self.elastic.event(r)
            with self.dbl:
                cur = self.con.execute("select * from alerts order by id")
                cols = [c[0] for c in cur.description]
                alerts = [dict(zip(cols, r)) for r in cur.fetchall()]
            for a in alerts:
                self.elastic.alert(a)
        return self.elastic_view()

    def elastic_test(self):
        if not self.elastic.on:
            raise ValueError("Switch sending on first.")
        try:
            self.elastic.check()
        except Exception as e:
            self.elastic.last_error = self.elastic._why(e)
            raise ConnectionError(self.elastic.last_error)
        return self.elastic_view()

    def block_list(self):
        now = time.time()
        return [dict(zip(("entity", "created", "until", "alert_id", "mode"), r)) for r in
                self._rows("select entity, created, until, alert_id, mode from blocks where until>? order by created desc", (now,))]

    # ---------------------------------------------------------------- clear the slate (keeps what the AI learned)
    def clear(self):
        self._flush_events()
        for (ent,) in self._rows("select entity from blocks where mode='firewall'"):
            firewall.remove(ent)
        with self.dbl:
            self.con.execute("delete from alerts")
            self.con.execute("delete from events")
            self.con.execute("delete from blocks")
            self.con.execute("update lessons set alert_id=NULL")
            self.con.commit()
        self.entities.clear()
        self.rule_open.clear()
        with self.ulock:
            self.upd.clear()
        self.buckets.clear()
        self.blocks.clear()
        for sid in list(self.rules):
            self.rules[sid] = RuleEngine()
        sim = self.simulator()
        if sim:
            sim.sim.reset_history()
        self._push("cleared", {})

    def save_upload(self, name, stream_iter):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(name or "upload.log"))[:80] or "upload.log"
        path = os.path.join(self.upload_dir, f"{int(time.time())}_{safe}")
        size = 0
        with open(path, "wb") as f:
            for chunk in stream_iter:
                f.write(chunk)
                size += len(chunk)
        return path, size

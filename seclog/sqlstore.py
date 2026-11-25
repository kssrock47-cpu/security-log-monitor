"""Keep a copy of the monitor's log events and alerts in a MySQL database, for SQL reporting and for other
tools that read MySQL.

* Off until a person switches it on (or SECLOG_MYSQL is set, for example mysql://root@127.0.0.1:3306/seclog).
* The monitor's own working store stays SQLite (one file, nothing to install). MySQL gets a normalised copy:
  sources, events and alerts tables with keys and indexes, plus views that answer the usual questions
  (top attackers, threats per hour, accounts under attack, threats by MITRE ATT&CK tactic).
* Rows are written in batches on their own thread with INSERT ... ON DUPLICATE KEY UPDATE, so alerts are
  updated in place when their count or status changes, and resending is harmless. If MySQL is down the
  monitor keeps working; up to MAX_QUEUE rows wait and the oldest are dropped beyond that.
"""
import ipaddress
import threading
import time
import urllib.parse
from collections import deque
from datetime import datetime
from decimal import Decimal

from seclog import insight

MAX_QUEUE = 200000
BATCH = 1000

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS sources (
        id INT PRIMARY KEY,
        name VARCHAR(200) NOT NULL DEFAULT ''
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS events (
        id BIGINT PRIMARY KEY,
        ts DATETIME(3) NULL,
        source_id INT NULL,
        log_format VARCHAR(30) NULL,
        host VARCHAR(255) NULL,
        app VARCHAR(255) NULL,
        entity VARCHAR(255) NULL,
        src_ip VARCHAR(45) NULL,
        country CHAR(2) NULL,
        user_name VARCHAR(255) NULL,
        outcome ENUM('fail', 'success') NULL,
        level VARCHAR(20) NULL,
        message_type INT NULL,
        message TEXT NULL,
        KEY ix_events_ts (ts),
        KEY ix_events_ip_ts (src_ip, ts),
        KEY ix_events_user_outcome (user_name, outcome),
        CONSTRAINT fk_events_source FOREIGN KEY (source_id) REFERENCES sources (id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS alerts (
        id BIGINT PRIMARY KEY,
        created DATETIME(3) NULL,
        first_ts DATETIME(3) NULL,
        last_ts DATETIME(3) NULL,
        source_id INT NULL,
        entity VARCHAR(255) NULL,
        src_ip VARCHAR(45) NULL,
        country CHAR(2) NULL,
        caught_by ENUM('ai', 'pattern') NOT NULL,
        rule_id VARCHAR(60) NULL,
        severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
        title VARCHAR(255) NOT NULL,
        detail TEXT NULL,
        status VARCHAR(20) NULL,
        mitre_technique VARCHAR(20) NULL,
        mitre_tactic VARCHAR(40) NULL,
        attack_step VARCHAR(60) NULL,
        times_seen INT NOT NULL DEFAULT 1,
        KEY ix_alerts_first_ts (first_ts),
        KEY ix_alerts_entity (entity),
        KEY ix_alerts_severity (severity),
        CONSTRAINT fk_alerts_source FOREIGN KEY (source_id) REFERENCES sources (id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE OR REPLACE VIEW v_top_attackers AS
        SELECT src_ip, MAX(country) AS country, COUNT(*) AS threats,
               SUM(severity IN ('high', 'critical')) AS serious, MIN(first_ts) AS first_seen, MAX(last_ts) AS last_seen
        FROM alerts WHERE src_ip IS NOT NULL GROUP BY src_ip""",
    """CREATE OR REPLACE VIEW v_threats_per_hour AS
        SELECT DATE_FORMAT(first_ts, '%Y-%m-%d %H:00') AS hour, severity, COUNT(*) AS threats
        FROM alerts GROUP BY hour, severity""",
    """CREATE OR REPLACE VIEW v_accounts_under_attack AS
        SELECT user_name, COUNT(*) AS failed_logins, COUNT(DISTINCT src_ip) AS from_addresses,
               MIN(ts) AS first_try, MAX(ts) AS last_try
        FROM events WHERE outcome = 'fail' AND user_name IS NOT NULL GROUP BY user_name""",
    """CREATE OR REPLACE VIEW v_threats_by_tactic AS
        SELECT mitre_tactic, caught_by, COUNT(*) AS threats
        FROM alerts GROUP BY mitre_tactic, caught_by""",
]

REPORTS = {  # shown on the Connect logs page, straight from MySQL
    "Top attackers": "SELECT src_ip, country, threats, serious, last_seen FROM v_top_attackers "
                     "ORDER BY threats DESC, last_seen DESC LIMIT 5",
    "Accounts under attack": "SELECT user_name, failed_logins, from_addresses, last_try FROM v_accounts_under_attack "
                             "ORDER BY failed_logins DESC LIMIT 5",
    "Threats by MITRE ATT&CK tactic": "SELECT mitre_tactic, caught_by, threats FROM v_threats_by_tactic "
                                      "ORDER BY threats DESC LIMIT 8",
}

EVENT_SQL = ("INSERT INTO events (id, ts, source_id, log_format, host, app, entity, src_ip, country, user_name, "
             "outcome, level, message_type, message) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
             "ON DUPLICATE KEY UPDATE id = id")
ALERT_SQL = ("INSERT INTO alerts (id, created, first_ts, last_ts, source_id, entity, src_ip, country, caught_by, "
             "rule_id, severity, title, detail, status, mitre_technique, mitre_tactic, attack_step, times_seen) "
             "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
             "ON DUPLICATE KEY UPDATE last_ts = VALUES(last_ts), status = VALUES(status), "
             "times_seen = VALUES(times_seen), detail = VALUES(detail), severity = VALUES(severity)")
SOURCE_SQL = "INSERT INTO sources (id, name) VALUES (%s, %s) ON DUPLICATE KEY UPDATE name = VALUES(name)"


def parse_url(url):
    """mysql://user[:password]@host[:port]/database -> connection settings."""
    p = urllib.parse.urlparse(url)
    if p.scheme != "mysql" or not p.hostname or not p.path.strip("/"):
        raise ValueError("Use an address such as mysql://root@127.0.0.1:3306/seclog")
    db = p.path.strip("/")
    if not db.replace("_", "").isalnum():
        raise ValueError("The database name can only have letters, digits and _")
    return {"host": p.hostname, "port": p.port or 3306, "user": urllib.parse.unquote(p.username or "root"),
            "password": urllib.parse.unquote(p.password or ""), "database": db}


def safe_url(url):
    """The address without any password, for showing on screen."""
    if not url:
        return None
    p = urllib.parse.urlparse(url)
    netloc = (p.username + "@" if p.username else "") + (p.hostname or "") + (f":{p.port}" if p.port else "")
    return urllib.parse.urlunparse(p._replace(netloc=netloc))


def _dt(ts):
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
        return d.replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def _ip(s):
    try:
        return str(ipaddress.ip_address(s)) if s else None
    except ValueError:
        return None


def _cut(s, n):
    return s[:n] if isinstance(s, str) else s


def _cc(ip):
    if not ip:
        return None
    g = insight.locate(ip)
    return g["cc"] if g["cc"] and not g["internal"] else None


def event_row(eid, ts, sid, fmt, host, app, ent, src_ip, user, outcome, level, tid, raw):
    ip = _ip(src_ip)
    return (eid, _dt(ts), sid, _cut(fmt, 30), _cut(host, 255), _cut(app, 255), _cut(ent, 255), ip, _cc(ip),
            _cut(user, 255), outcome if outcome in ("fail", "success") else None, _cut(level, 20), tid,
            _cut(raw, 60000))


def alert_row(a):
    import json
    ent = a.get("entity") or ""
    ip = _ip(ent)
    tech = (a.get("mitre") or "").split(" ", 1)[0]
    stage = insight.STAGES[insight.STAGE_IX[insight.stage_of(a["kind"], a["rule"], json.loads(a.get("features") or "[]"))]]
    return (a["id"], _dt(a.get("created")), _dt(a.get("first_ts")), _dt(a.get("last_ts")), a.get("source_id"),
            _cut(ent, 255), ip, _cc(ip), "ai" if a["kind"] == "ai" else "pattern", _cut(a.get("rule"), 60),
            a["severity"] if a["severity"] in ("low", "medium", "high", "critical") else "low",
            _cut(a.get("title") or "", 255), a.get("detail"), _cut(a.get("status"), 20),
            tech if tech.startswith("T") and tech[1:5].isdigit() else None, stage[3], stage[1], a.get("count") or 1)


class Store:
    def __init__(self, url=None, connect=None):
        self._connect = connect  # tests can swap the driver
        self.url = None
        self.q = deque()
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.sent = {"events": 0, "alerts": 0}
        self.dropped = 0
        self.ready = False
        self.version = None
        self.last_error = None
        self.last_ok = None
        self.sources = {}
        self.con = None
        self.configure(url)
        threading.Thread(target=self._loop, daemon=True).start()

    def configure(self, url):
        url = (url or "").strip() or None
        if url:
            parse_url(url)  # raises ValueError for a bad address
        with self.lock:
            if url != self.url:
                self._close()
                self.ready, self.version, self.last_error = False, None, None
            self.url = url
            if not url:
                self.q.clear()
        self.wake.set()

    @property
    def on(self):
        return bool(self.url)

    def status(self):
        cfg = parse_url(self.url) if self.url else {}
        return {"on": self.on, "url": safe_url(self.url), "database": cfg.get("database"),
                "connected": self.ready and self.last_error is None, "version": self.version,
                "sent_events": self.sent["events"], "sent_alerts": self.sent["alerts"], "waiting": len(self.q),
                "dropped": self.dropped, "error": self.last_error, "last_ok": self.last_ok}

    # ------------------------------------------------------------ queueing
    def _put(self, kind, row, source=None):
        if not self.url:
            return
        with self.lock:
            if len(self.q) >= MAX_QUEUE:
                self.q.popleft()
                self.dropped += 1
            self.q.append((kind, row, source))
        if len(self.q) >= BATCH:
            self.wake.set()

    def event(self, row, source_name=None):
        if self.url:
            self._put("events", event_row(*row), (row[2], source_name))

    def alert(self, a, source_name=None):
        if self.url:
            self._put("alerts", alert_row(a), (a.get("source_id"), source_name))

    # ------------------------------------------------------------ database
    def _open(self):
        cfg = parse_url(self.url)
        if self._connect:
            return self._connect(cfg)
        import pymysql
        base = dict(host=cfg["host"], port=cfg["port"], user=cfg["user"], password=cfg["password"],
                    charset="utf8mb4", connect_timeout=5, autocommit=False)
        con = pymysql.connect(**base)
        with con.cursor() as c:
            c.execute(f"CREATE DATABASE IF NOT EXISTS `{cfg['database']}` CHARACTER SET utf8mb4")
            c.execute(f"USE `{cfg['database']}`")
        return con

    def _close(self):
        try:
            if self.con:
                self.con.close()
        except Exception:
            pass
        self.con = None

    @staticmethod
    def _why(e):
        code = e.args[0] if getattr(e, "args", None) and isinstance(e.args[0], int) else None
        if code in (2003, 2002, 2013):
            return "Can't reach MySQL at this address. Is it running? (mysql\\start-windows.ps1 starts it.)"
        if code in (1045, 1044):
            return "MySQL refused the login. Check the user name and password in the address."
        if isinstance(e, ModuleNotFoundError):
            return "The MySQL driver is missing. Run: pip install PyMySQL"
        return f"MySQL: {str(e)[:200]}"

    def check(self):
        """Connect, create the tables and views if needed, and report the version. Raises on failure."""
        self._close()
        self.con = self._open()
        with self.con.cursor() as c:
            for stmt in SCHEMA:
                c.execute(stmt)
            c.execute("SELECT VERSION()")
            self.version = c.fetchone()[0]
        self.con.commit()
        self.sources = {}
        self.ready, self.last_error = True, None
        return self.status()

    def _send(self, batch):
        with self.con.cursor() as c:
            for sid, name in {s for _, _, s in batch if s and s[0] is not None}:
                if self.sources.get(sid) != name:
                    c.execute(SOURCE_SQL, (sid, _cut(name or f"Connection {sid}", 200)))
                    self.sources[sid] = name
            for kind, sql in (("events", EVENT_SQL), ("alerts", ALERT_SQL)):
                rows = [r for k, r, _ in batch if k == kind]
                if rows:
                    c.executemany(sql, rows)
        self.con.commit()
        for kind, _, _ in batch:
            self.sent[kind] += 1

    def report(self):
        """The REPORTS queries, run on MySQL: {title: {"columns": [...], "rows": [[...]]}}."""
        if not (self.url and self.ready):
            return {}
        con = self._open()
        try:
            out = {}
            with con.cursor() as c:
                for title, sql in REPORTS.items():
                    c.execute(sql)
                    out[title] = {"columns": [d[0] for d in c.description],
                                  "rows": [[v.strftime("%d %b %H:%M") if isinstance(v, datetime) else
                                            int(v) if isinstance(v, Decimal) else v
                                            for v in r] for r in c.fetchall()],
                                  "sql": sql}
            return out
        finally:
            con.close()

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
                        self._send(batch)
                    except Exception:
                        try:
                            self.con.rollback()
                        except Exception:
                            pass
                        with self.lock:  # put them back in order and try again later
                            self.q.extendleft(reversed(batch))
                        raise
                    self.last_ok = time.time()
                    self.last_error = None
            except Exception as e:
                self.ready = False
                self.last_error = self._why(e)
                self._close()
                self.wake.wait(8.0)
                self.wake.clear()

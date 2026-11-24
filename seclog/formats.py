"""Read many kinds of security logs and pull out the parts that matter.

Supported, detected automatically line by line:
  * Linux syslog / auth.log (sshd, sudo, su, useradd, kernel firewall), with or without <PRI>
  * ISO-timestamped syslog (systemd, rsyslog high-precision)
  * Web server access logs (Apache / Nginx common and combined)
  * Apache error logs
  * Windows events (from this PC, from .evtx files, or as JSON lines)
  * JSON lines with common field names
  * HDFS logs (the research dataset)
  * Anything else: kept as plain text, time taken from the line if possible
Every event gets the same fields, so the detectors work the same way on all of them.
"""
import json
import re
from datetime import datetime, timedelta, timezone

MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

RE_PRI = re.compile(r"^<\d{1,3}>(?:1 )?")
RE_SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d) (?P<host>[^\s\[\]]*[^\s\[\]:]) "
                       r"(?P<app>[^\s:\[]+(?:\([^)]*\))?)(?:\[(?P<pid>\d+)\])?:? (?P<msg>.*)$")
# syslog written straight to a file by a program, without the machine name (dnsmasq, openvpn, ...)
RE_SYSLOG_NOHOST = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d) "
                              r"(?P<app>[\w./-]+)\[(?P<pid>\d+)\]: (?P<msg>.*)$")
# Linux audit log (auditd): type=USER_AUTH msg=audit(1642723741.072:375): ... acct="root" ... res=failed
RE_AUDIT = re.compile(r"^type=(?P<type>\S+) msg=audit\((?P<ts>\d+(?:\.\d+)?):\d+\):\s*(?P<rest>.*)$")
RE_AUDIT_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
# OpenVPN client lines: "2022-01-21 00:09:11 jhall/192.168.230.165:46011 TLS: ..."
RE_VPN_PEER = re.compile(r"^(?P<user>[\w.@-]+)/(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d+ ")
RE_ISOSYS = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?) (?P<host>\S+) "
                       r"(?P<app>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:? (?P<msg>.*)$")
RE_ACCESS = re.compile(r'^(?P<ip>[\da-fA-F.:]+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)'
                       r'(?: [^"]*)?" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
RE_APERR = re.compile(r"^\[(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2} \d\d [\d:.]+ \d{4})\] \[(?P<level>[\w:]+)\]"
                      r"(?: \[pid \d+(?::tid \d+)?\])?(?: \[client (?P<ip>[\d.]+)(?::\d+)?\])? (?P<msg>.*)$")
RE_HDFS = re.compile(r"^(\d{6}) (\d{6}) (\d+) (\w+) ([\w.$]+): (.*)$")
RE_ISOLINE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[.,]\d+)?)[,\s]+(?:(?P<level>INFO|Info|WARN|Warning|WARNING|ERROR|Error|DEBUG|CRITICAL|FATAL)\b\s*)?(?P<msg>.*)$")

RE_IP = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
RE_IP_HINT = re.compile(r"(?:from|rhost=|SRC=|Source Network Address:\s*|client |ip=|addr=)\s*\[?([\d.]+)")
RE_USER = [
    re.compile(r"\[([\w.@-]+)\] Peer Connection Initiated"),  # OpenVPN
    re.compile(r"[Ff]ailed (?:password|publickey|none) for (?:invalid user )?(\S+)"),
    re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+)"),
    re.compile(r"[Ii]nvalid user (\S+)"),
    re.compile(r"session (?:opened|closed) for user (\S+?)(?:\(|\s|$)"),
    re.compile(r"\buser[= ]([A-Za-z0-9._\-$]+)"),
    re.compile(r"Account Name:\s+([^\s]+)"),
    re.compile(r"^\s*(\S+) : .*COMMAND="),  # sudo
    re.compile(r"new user: name=([^,\s]+)"),
    re.compile(r"add '([^']+)' to group"),
]
FAIL = re.compile(r"[Ff]ailed password|authentication failure|(?i:log(?:in|on) (?:failed|failure)|failed (?:log(?:in|on)|sign[- ]?in))|[Ii]nvalid user|FAILED|[Ff]ailed to log ?on|"
                  r"account failed to log on|incorrect password|NOT in sudoers|Connection closed by authenticating user|"
                  r"maximum authentication attempts|Disconnecting: Too many authentication failures|BREAK-IN ATTEMPT")
SUCCESS = re.compile(r"Accepted (?:password|publickey|keyboard)|session opened for user|successfully logged on|"
                     r"An account was successfully logged on|Successful su|Peer Connection Initiated")
LEVEL_BAD = re.compile(r"\b(?:error|err|crit|critical|alert|emerg|fatal|fail(?:ed|ure)?|denied|refused|warn(?:ing)?)\b", re.I)

# Windows event ids that matter for security, in plain words
WIN_EVENTS = {
    4624: ("An account logged on", "success"), 4625: ("An account failed to log on", "fail"),
    4634: ("An account logged off", None), 4648: ("A logon was attempted with someone else's password", None),
    4672: ("Admin rights were given to a new logon", None), 4688: ("A new program was started", None),
    4720: ("A user account was created", None), 4722: ("A user account was enabled", None),
    4724: ("Someone tried to reset an account password", None), 4728: ("A user was added to a security group", None),
    4732: ("A user was added to a local group", None), 4740: ("A user account was locked out", "fail"),
    4756: ("A user was added to a universal group", None), 4771: ("Kerberos pre-authentication failed", "fail"),
    4776: ("The computer tried to validate an account's password", None), 1102: ("The security log was cleared", None),
    104: ("An event log was cleared", None), 7045: ("A new service was installed", None),
    4697: ("A new service was installed", None), 4698: ("A scheduled task was created", None),
    5156: ("A network connection was allowed", None), 5157: ("A network connection was blocked", "fail"),
    1116: ("Windows Defender found malware", None), 1117: ("Windows Defender acted on malware", None),
}


def _year_fix(dt: datetime, now: datetime) -> datetime:
    # syslog lines have no year: assume the most recent past date
    if dt > now + timedelta(days=2):
        dt = dt.replace(year=dt.year - 1)
    return dt


def _parse_access_ts(s):
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").astimezone().replace(tzinfo=None)
    except ValueError:
        return None


def _iso(s):
    try:
        s = s.replace(",", ".").replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt
    except ValueError:
        return None


def _enrich(ev: dict) -> dict:
    msg = ev["msg"]
    if not ev.get("src_ip"):
        m = RE_IP_HINT.search(msg)
        if not m:  # a bare address counts only if it doesn't look like a version number
            m = next((x for x in RE_IP.finditer(msg) if not x.group(1).startswith("0.")
                      and not re.search(r"(?:version|v)\s*$", msg[:x.start()], re.I)), None)
        if m and RE_IP.fullmatch(m.group(1)):
            ev["src_ip"] = m.group(1)
    if not ev.get("user"):
        for r in RE_USER:
            m = r.search(msg)
            if m and m.group(1) not in ("-", "unknown", "N/A"):
                ev["user"] = m.group(1).strip(":;,")
                break
    if ev.get("outcome") is None:
        if FAIL.search(msg):
            ev["outcome"] = "fail"
        elif SUCCESS.search(msg):
            ev["outcome"] = "success"
    if not ev.get("level"):
        ev["level"] = "warning" if LEVEL_BAD.search(msg) else "info"
    m = re.search(r"DPT=(\d+)", msg)
    if m:
        ev["port"] = int(m.group(1))
    return ev


def parse(line: str, now: datetime | None = None, hint_host: str | None = None) -> dict | None:
    """One raw line -> one event dict (or None for blank lines)."""
    raw = line.rstrip("\r\n")
    if not raw.strip():
        return None
    now = now or datetime.now()
    ev = {"raw": raw, "ts": None, "host": hint_host, "app": None, "msg": raw, "fmt": "text", "src_ip": None,
          "user": None, "outcome": None, "level": None, "status": None, "method": None, "path": None, "ua": None,
          "port": None, "event_id": None}
    s = RE_PRI.sub("", raw)

    if s.startswith("{"):
        try:
            j = json.loads(s)
        except ValueError:
            j = None
        if isinstance(j, dict):
            return _from_json(j, ev, now)

    m = RE_SYSLOG.match(s)
    if m:
        try:
            dt = datetime(now.year, MONTHS[m["mon"]], int(m["day"]), *map(int, m["time"].split(":")))
            ev.update(ts=_year_fix(dt, now), host=m["host"], app=m["app"], msg=m["msg"], fmt="syslog")
            if m["app"].startswith("kernel") and "SRC=" in m["msg"]:
                ev["fmt"] = "firewall"
            return _enrich(ev)
        except (KeyError, ValueError):
            pass
    m = RE_SYSLOG_NOHOST.match(s)
    if m:
        try:
            dt = datetime(now.year, MONTHS[m["mon"]], int(m["day"]), *map(int, m["time"].split(":")))
            ev.update(ts=_year_fix(dt, now), app=m["app"], msg=m["msg"], fmt="syslog")
            ev = _enrich(ev)
            if m["app"] == "dnsmasq" and not m["msg"].startswith("query["):
                ev["src_ip"] = None  # replies name the address looked up, not the computer that asked
            return ev
        except (KeyError, ValueError):
            pass
    m = RE_AUDIT.match(s)
    if m:
        kv = {k: v.strip("\"'") for k, v in RE_AUDIT_KV.findall(m["rest"])}
        typ, res = m["type"], kv.get("res", "")
        user = kv.get("acct") or kv.get("UID") or kv.get("AUID")
        exe = (kv.get("exe") or kv.get("comm") or "").rsplit("/", 1)[-1] or None
        ev.update(ts=datetime.fromtimestamp(float(m["ts"])), app=exe or "audit", fmt="audit",
                  user=None if user in (None, "?", "unset", "(unknown)") else user,
                  msg=" ".join(x for x in (typ, f"user {user}" if user else "", exe or "", kv.get("op", ""), res) if x),
                  level="warning" if res in ("failed", "no") else "info")
        addr = kv.get("addr")
        if addr and RE_IP.fullmatch(addr):
            ev["src_ip"] = addr
        if typ in ("USER_AUTH", "USER_LOGIN", "USER_ERR"):
            ev["outcome"] = "fail" if res in ("failed", "no") else "success" if res in ("success", "yes") else None
        return ev
    m = RE_ISOSYS.match(s)
    if m:
        ev.update(ts=_iso(m["ts"]), host=m["host"], app=m["app"], msg=m["msg"], fmt="syslog")
        return _enrich(ev)
    m = RE_ACCESS.match(s)
    if m:
        st = int(m["status"])
        ev.update(ts=_parse_access_ts(m["ts"]), src_ip=m["ip"], user=None if m["user"] == "-" else m["user"],
                  method=m["method"], path=m["path"], status=st, ua=m["ua"], fmt="web", app="web",
                  level="warning" if st >= 400 else "info",
                  msg=f'{m["method"]} {m["path"].split("?")[0]} {st}')
        if st in (401, 403):
            ev["outcome"] = "fail"
        return ev
    m = RE_APERR.match(s)
    if m:
        try:  # "Mon Jan 24 03:57:26.696483 2022": drop the fraction of a second, keep the year
            ts = datetime.strptime(re.sub(r"\.\d+", "", m["ts"]), "%a %b %d %H:%M:%S %Y")
        except ValueError:
            ts = None
        ev.update(ts=ts, level=m["level"].split(":")[-1], src_ip=m["ip"], msg=m["msg"], fmt="web-error", app="web")
        return _enrich(ev)
    m = RE_HDFS.match(s)
    if m:
        d, t, _pid, lvl, comp, content = m.groups()
        try:
            ts = datetime.strptime(d + t, "%y%m%d%H%M%S")
        except ValueError:
            ts = None
        ev.update(ts=ts, level=lvl.lower(), app=comp, msg=content, fmt="hdfs")
        return ev
    m = RE_ISOLINE.match(s)
    if m:
        ev.update(ts=_iso(m["ts"]), level=(m["level"] or "").lower() or None, msg=m["msg"] or s, fmt="text")
        v = RE_VPN_PEER.match(ev["msg"])
        if v:
            ev.update(user=v["user"], src_ip=v["ip"], app="openvpn")
        return _enrich(ev)
    ev["msg"] = s
    return _enrich(ev)


def _from_json(j: dict, ev: dict, now: datetime) -> dict:
    if j.get("_win"):  # produced by the Windows sources in this project
        eid = int(j.get("id") or 0)
        name, outcome = WIN_EVENTS.get(eid, (None, None))
        detail = " ".join(f"{k}={v}" for k, v in (j.get("fields") or {}).items() if v not in (None, "", "-"))
        ev.update(ts=_iso(j.get("time", "")) or now, host=j.get("host"), app=j.get("channel", "Windows"),
                  event_id=eid, fmt="windows", level=(j.get("level") or "info").lower(),
                  msg=f"Event {eid}: {name or j.get('text', '')[:120]} {detail}".strip())
        f = j.get("fields") or {}
        ev["user"] = f.get("TargetUserName") or f.get("SubjectUserName") or None
        ip = f.get("IpAddress") or f.get("SourceNetworkAddress")
        ev["src_ip"] = ip if ip and RE_IP.fullmatch(ip) else None
        ev["outcome"] = outcome
        return _enrich(ev)
    pick = lambda *ks: next((j[k] for k in ks if k in j and j[k] not in (None, "")), None)
    ts = pick("timestamp", "@timestamp", "time", "ts", "date", "datetime")
    ev.update(ts=_iso(str(ts)) if ts else None, fmt="json",
              msg=str(pick("message", "msg", "log", "event", "text") or json.dumps(j)[:300]),
              host=pick("host", "hostname", "computer"), app=pick("app", "program", "service", "source"),
              level=(str(pick("level", "severity", "loglevel") or "") or None),
              src_ip=pick("src_ip", "client_ip", "remote_addr", "ip", "source_ip"), user=pick("user", "username", "account"))
    if isinstance(ev["level"], str):
        ev["level"] = ev["level"].lower()
    return _enrich(ev)


def entity(ev: dict) -> str:
    """Who did it: the outside address if there is one, else the user, else the machine."""
    if ev.get("src_ip") and ev["src_ip"] not in ("127.0.0.1", "::1", "0.0.0.0"):
        return ev["src_ip"]
    if ev.get("user"):
        return "user:" + ev["user"]
    return "host:" + (ev.get("host") or ev.get("app") or "unknown")

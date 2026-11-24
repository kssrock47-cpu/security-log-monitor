"""Known attack patterns, checked as each event arrives.

Each rule watches a short sliding window per attacker and fires once per cooldown,
so a long attack becomes one alert with a growing count, not hundreds of alerts.
MITRE ATT&CK ids are shown when "technical terms" is switched on.
"""
import ipaddress
import os
import re
from collections import Counter, defaultdict, deque
from datetime import timedelta
from functools import lru_cache


@lru_cache(maxsize=100000)
def _outside_v4(ip):
    """True for a public IPv4 address (cached: it is asked for every failed login)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and not (a.is_private or a.is_loopback)

# accounts that only websites run as; they never log in as people (Debian uid 33, Red Hat uid 48)
WEB_ACCOUNTS = {"www-data", "apache", "nginx", "httpd", "wwwrun", "_www"}
RE_SU = re.compile(r"Successful su for (\S+) by (\S+)|session opened for user (\S+) by \(uid=(\d+)\)")
RE_SUDO_CMD = re.compile(r"^\s*(\S+) : .*COMMAND=(.*)$")
RE_AUDIT_CMD = re.compile(r"\bcmd=([0-9A-Fa-f]{6,})")
SECRET_FILES = re.compile(r"/etc/(?:shadow|gshadow|sudoers)\b|/\.ssh/|\bid_(?:rsa|ed25519|ecdsa)\b")
# DNS lookups: dnsmasq "query[A] name from 1.2.3.4", BIND "query: name IN A"
DNS_QUERY = re.compile(r"query\[(\w+)\] (\S+) from |query: (\S+) IN (\w+)")
SQLI = re.compile(r"(?:%27|')\s*(?:or|and|union)\b|union(?:\s|%20|\+)+select|select(?:\s|%20|\+).+from|"
                  r"sleep\(|benchmark\(|information_schema|--(?:\s|%20|$)|/\*.*\*/", re.I)
XSS = re.compile(r"<script|%3cscript|javascript:|onerror=|onload=|alert\(", re.I)
TRAVERSAL = re.compile(r"\.\./|\.\.%2f|%2e%2e|/etc/passwd|win\.ini|boot\.ini", re.I)
CMDI = re.compile(r";\s*(?:cat|ls|id|whoami|wget|curl|nc|bash)\b|\|\s*(?:sh|bash)|\$\(|%7c|`", re.I)
SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|acunetix|hydra|"
                        r"python-requests|curl/|Go-http-client", re.I)
SENSITIVE_PATH = re.compile(r"/(?:\.env|\.git|wp-admin|wp-login|phpmyadmin|admin|xmlrpc\.php|server-status|"
                            r"cgi-bin|actuator|\.aws|config\.php)", re.I)

RULES = {
    "brute_force": ("Someone is guessing passwords", "high", "T1110.001 Brute Force: Password Guessing",
                    "Block this address for now, and make sure the targeted accounts use strong passwords or keys."),
    "spray": ("One address is trying many different usernames", "high", "T1110.003 Brute Force: Password Spraying",
              "Block this address. Check whether any of the tried usernames logged in successfully afterwards."),
    "break_in": ("A login succeeded right after many failed guesses", "critical", "T1078 Valid Accounts",
                 "Treat this account as possibly stolen: lock it, change its password, and check what it did after logging in."),
    "web_attack": ("A web attack was attempted", "high", "T1190 Exploit Public-Facing Application",
                   "Check the response code: 200 means the page answered, so confirm the input is handled safely. Block the address."),
    "scanner": ("An automated attack tool is probing the website", "medium", "T1595 Active Scanning",
                "Usually noise from the internet, but block the address if it keeps going."),
    "web_probe": ("Someone is hunting for hidden pages", "medium", "T1595.003 Wordlist Scanning",
                  "Make sure admin pages and secret files are not reachable from outside. Block the address if it continues."),
    "port_scan": ("Someone is scanning the network for open doors", "high", "T1046 Network Service Discovery",
                  "Check that only the ports you need are open. Block the address at the firewall."),
    "priv_fail": ("Someone failed to get admin rights", "medium", "T1548 Abuse Elevation Control Mechanism",
                  "Ask the user if it was them. Repeated failures can mean someone is using their account."),
    "root_shell": ("Someone opened an admin (root) shell", "high", "T1548.003 Sudo and Sudo Caching",
                   "Confirm this was planned work. An unexpected root shell is a strong sign of an intruder."),
    "new_account": ("A new user account was created", "medium", "T1136 Create Account",
                    "Confirm someone in your team created it. Attackers add accounts to get back in later."),
    "admin_group": ("Someone was given admin rights", "high", "T1098 Account Manipulation",
                    "Confirm this change was approved. If not, remove the rights and lock the account."),
    "log_cleared": ("Security logs were wiped", "critical", "T1070.001 Indicator Removal: Clear Windows Event Logs",
                    "Attackers clear logs to hide their tracks. Investigate this machine straight away."),
    "malware": ("Antivirus found malware", "critical", "T1204 User Execution",
                "Disconnect the machine from the network and run a full scan."),
    "new_service": ("A new background service was installed", "medium", "T1543.003 Create or Modify System Process: Windows Service",
                    "Check the service name and file. Attackers install services to keep running after a restart."),
    "lockout": ("An account was locked after too many wrong passwords", "medium", "T1110 Brute Force",
                "Find out who tried. If it wasn't the account owner, someone may be guessing its password."),
    # found by testing on the real loghub SSH server log: attackers who stay under the fast rule
    # data hidden inside DNS names (MITRE T1048.003 / T1071.004). Thresholds follow common guidance for DNS tunnelling:
    # a name over 100 characters or one part over 50 is very rare for normal sites.
    "dns_tunnel": ("Data may be leaving through DNS lookups", "high",
                   "T1048.003 Exfiltration Over Alternative Protocol (DNS)",
                   "Very long, random-looking names are a known way to smuggle data out. Find the computer that asked "
                   "and what runs on it, and block lookups to that domain at the DNS server or firewall."),
    # added after the first AIT-LDS v2.0 run; each is a standard detection, with general (not tuned) thresholds
    "web_account_switch": ("The website's account switched to another user", "high", "T1078 Valid Accounts / T1548 Abuse Elevation",
                           "Website accounts never log in as people, so this usually means a webshell or a hacked website. "
                           "Check recently uploaded or changed files under the web folder, and the account it switched to."),
    "secret_files": ("Admin rights were used to read password or key files", "high",
                     "T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow",
                     "Reading /etc/shadow or SSH keys with admin rights is how attackers collect passwords. "
                     "Find out who ran it; if it wasn't planned, change the passwords and keys on this machine."),
    "dns_scan": ("Someone is guessing names in your domain (DNS scan)", "medium",
                 "T1590.002 Gather Victim Network Information: DNS",
                 "Trying many made-up names is how attackers map which servers exist. Check the computer that asked."),
    "ptr_sweep": ("Someone is mapping your network with reverse lookups", "medium", "T1018 Remote System Discovery",
                  "Looking up the names of many addresses one after another is a network sweep. Check the computer that asked."),
    "new_place_login": ("An account logged in from a new address", "medium", "T1078 Valid Accounts",
                        "This account always logged in from elsewhere before. If its owner didn't just change device or "
                        "location, its password or certificate may be stolen."),
    "slow_guess": ("Someone is guessing passwords slowly, to stay under the radar", "medium",
                   "T1110.001 Brute Force: Password Guessing",
                   "Block this address. Guessing a few passwords an hour for days is deliberate; check that the "
                   "targeted accounts use strong passwords or keys."),
    "net_guess": ("Many addresses from one network are guessing passwords together", "high", "T1110 Brute Force (distributed)",
                  "Several addresses are sharing the work so each stays below the alarm. Block the network range at "
                  "the firewall if you have no users there, and check the targeted accounts."),
}


class RuleEngine:
    def __init__(self):
        self.fails = defaultdict(deque)        # ip -> times of failed logins
        self.fail_users = defaultdict(deque)   # ip -> (time, user)
        self.http4 = defaultdict(deque)        # ip -> (time, path)
        self.ports = defaultdict(deque)        # ip -> (time, port)
        self.priv = defaultdict(deque)
        self.slow = defaultdict(deque)         # ip -> times of failed logins, last 24 hours
        self.oks = defaultdict(deque)          # ip -> times of successful logins, last 24 hours
        self.nets = defaultdict(deque)         # network (first two numbers) -> (time, ip), last 6 hours
        self.net_ips = defaultdict(Counter)    # network -> failures per address in that window (a running tally)
        self.dns_long = defaultdict(deque)     # computer -> times of very long DNS lookups, last 5 minutes
        self.dns_names = defaultdict(deque)    # (computer, domain) -> (time, name) of lookups, last minute
        self.dns_ptr = defaultdict(deque)      # computer -> (time, name) of reverse lookups, last minute
        self.user_places = defaultdict(Counter)  # user -> address -> successful logins
        self.last_fired = {}                   # (rule, entity) -> time
        # for fair before/after evaluations: SECLOG_DISABLE_RULES=dns_tunnel,dns_scan,...
        self.disabled = {r for r in os.environ.get("SECLOG_DISABLE_RULES", "").split(",") if r}

    @staticmethod
    def _trim(dq, now, secs):
        while dq and (now - (dq[0][0] if isinstance(dq[0], tuple) else dq[0])).total_seconds() > secs:
            dq.popleft()

    def _fire(self, rule, ent, now, detail, cooldown=300):
        key = (rule, ent)
        last = self.last_fired.get(key)
        if last and (now - last).total_seconds() < cooldown:
            return {"rule": rule, "entity": ent, "update": True, "detail": detail}
        self.last_fired[key] = now
        title, sev, mitre, advice = RULES[rule]
        return {"rule": rule, "entity": ent, "update": False, "title": title, "severity": sev, "mitre": mitre,
                "advice": advice, "detail": detail}

    def _slow_and_spread(self, ip, now):
        out = []
        dq, ok = self.slow[ip], self.oks[ip]
        dq.append(now)
        self._trim(dq, now, 86400)
        self._trim(ok, now, 86400)
        fast = self.last_fired.get(("brute_force", ip))
        recently_fast = fast is not None and (now - fast).total_seconds() < 86400
        # 20+ failures in a day, almost never a successful login (a person with typos logs in afterwards)
        if len(dq) >= 20 and len(dq) >= 9 * len(ok) and not recently_fast:
            span = (dq[-1] - dq[0]).total_seconds() / 3600
            out.append(self._fire("slow_guess", ip, now, f"{len(dq)} failed logins over {span:.1f} hours, never "
                                  "enough at once to look like fast guessing", cooldown=6 * 3600))
        if _outside_v4(ip):
            key = ".".join(ip.split(".")[:2])
            dn, tally = self.nets[key], self.net_ips[key]
            dn.append((now, ip))
            tally[ip] += 1
            while dn and (now - dn[0][0]).total_seconds() > 6 * 3600:
                _, old = dn.popleft()
                tally[old] -= 1
                if not tally[old]:
                    del tally[old]
            if len(tally) >= 4 and len(dn) >= 40:
                ent = f"net:{key}.0.0/16"
                detail = f"{len(tally)} addresses from {key}.x.x made {len(dn)} failed logins in 6 hours"
                last = self.last_fired.get(("net_guess", ent))
                if last is None or (now - last).total_seconds() >= 6 * 3600:  # examples only when the alert is new
                    detail += ", for example " + ", ".join(sorted(tally)[:3])
                out.append(self._fire("net_guess", ent, now, detail, cooldown=6 * 3600))
        return out

    def check(self, ev: dict, ent: str) -> list:
        """Return a list of rule hits for this event (usually empty)."""
        now, msg, out = ev["ts"], ev["msg"], []
        ip = ev.get("src_ip")
        eid = ev.get("event_id")

        # --- DNS: data hidden in very long lookups ---------------------------------
        if ip and "query" in msg:
            q = DNS_QUERY.search(msg)
            if q:
                qtype = q.group(1) or q.group(4) or ""
                name = (q.group(2) or q.group(3)).rstrip(".").lower()
                parts = name.split(".")
                parent = (".".join(parts[1:]) if len(parts) > 2 else name) if qtype != "PTR" else "in-addr.arpa"
                for dq_, kind, need, rule in ((self.dns_names[(ip, parent)], "", 50, "dns_scan"),
                                              (self.dns_ptr[ip], "PTR", 20, "ptr_sweep")):
                    if kind and qtype != kind:
                        continue
                    if not kind and qtype == "PTR":
                        continue
                    dq_.append((now, name))
                    while dq_ and (now - dq_[0][0]).total_seconds() > 60:
                        dq_.popleft()
                    if len(dq_) >= need:
                        names = {n for _, n in dq_}
                        if len(names) >= need:
                            out.append(self._fire(rule, ip, now, f"{len(names)} different names looked up in a minute, "
                                                  f"for example {sorted(names)[0][:60]}"))
                if len(name) > 100 or max((len(p) for p in name.split(".")), default=0) > 50:
                    dq = self.dns_long[ip]
                    dq.append(now)
                    self._trim(dq, now, 300)
                    if len(dq) >= 20:
                        out.append(self._fire("dns_tunnel", ip, now, f"{len(dq)} very long DNS lookups in 5 minutes, "
                                              f"for example {name[:60]}…"))

        # --- a website's account becoming someone else (webshell) -------------------------
        app = (ev.get("app") or "").lower()
        if app == "su" or (ev["fmt"] == "audit" and "/su" in ev.get("raw", "")):
            m_ = RE_SU.search(msg)
            by = target = None
            if m_:
                target, by = (m_.group(1), m_.group(2)) if m_.group(1) else (m_.group(3), m_.group(4))
            elif ev["fmt"] == "audit":
                u = re.search(r"\buid=(\d+)", ev["raw"])
                by, target = (u.group(1) if u else None), ev.get("user")
            if by in WEB_ACCOUNTS or by in ("33", "48"):
                out.append(self._fire("web_account_switch", "user:www-data" if by in ("33", "48") else f"user:{by}", now,
                                      f"The website's account switched to the user {target}"))
        # --- admin rights used on password or key files -----------------------------------
        cmd = None
        if app == "sudo":
            m_ = RE_SUDO_CMD.search(msg)
            if m_:
                cmd, sudo_user = m_.group(2), m_.group(1)
        elif ev["fmt"] == "audit" and "USER_CMD" in ev.get("raw", ""):
            m_ = RE_AUDIT_CMD.search(ev["raw"])
            if m_:
                try:
                    cmd = bytes.fromhex(m_.group(1)).decode("utf-8", "replace")
                except ValueError:
                    cmd = None
                u = re.search(r"\bauid=(\d+)|\buid=(\d+)", ev["raw"])
                sudo_user = ev.get("user") or (u and (u.group(1) or u.group(2)))
        if cmd and SECRET_FILES.search(cmd):
            out.append(self._fire("secret_files", f"user:{sudo_user}" if sudo_user else ent, now,
                                  f"Ran with admin rights: {cmd[:120]}"))

        # --- logins ---------------------------------------------------------------
        if ev.get("outcome") == "fail" and ev["fmt"] != "web" and (ip or ev.get("user")):
            k = ip or ent
            dq = self.fails[k]
            dq.append(now)
            self._trim(dq, now, 120)
            if len(dq) >= 8:
                out.append(self._fire("brute_force", k, now, f"{len(dq)} failed logins in the last 2 minutes"))
            if ev.get("user"):
                du = self.fail_users[k]
                du.append((now, ev["user"]))
                self._trim(du, now, 300)
                users = {u for _, u in du}
                if len(users) >= 5:
                    out.append(self._fire("spray", k, now, f"{len(users)} different usernames tried in 5 minutes, "
                                          f"for example {', '.join(sorted(users)[:4])}"))
        if ev.get("outcome") == "fail" and ev["fmt"] != "web" and ip:
            out += self._slow_and_spread(ip, now)
        if ev.get("outcome") == "success" and ip and ev.get("user"):
            places = self.user_places[ev["user"]]
            if ip not in places and sum(places.values()) >= 5:
                out.append(self._fire("new_place_login", f"user:{ev['user']}", now,
                                      f"Logged in from {ip}; before, only from {', '.join(list(places)[:3])}",
                                      cooldown=3600))
            places[ip] += 1
        if ev.get("outcome") == "success" and ip:
            self.oks[ip].append(now)
            self._trim(self.oks[ip], now, 86400)
            dq = self.fails.get(ip)
            if dq:
                recent = [t for t in dq if (now - t).total_seconds() <= 180]
                if len(recent) >= 8:  # a few typos are normal; a run of failures then success is not
                    who = f" as '{ev['user']}'" if ev.get("user") else ""
                    out.append(self._fire("break_in", ip, now, f"Logged in{who} after {len(recent)} failed attempts "
                                          "in the last 3 minutes"))
        if eid == 4740:
            out.append(self._fire("lockout", ent, now, msg[:160]))

        # --- web --------------------------------------------------------------------
        if ev["fmt"] == "web" and ev.get("path"):
            p = ev["path"]
            kind = ("SQL injection" if SQLI.search(p) else "cross-site scripting" if XSS.search(p) else
                    "path traversal" if TRAVERSAL.search(p) else "command injection" if CMDI.search(p) else None)
            if kind:
                out.append(self._fire("web_attack", ip, now, f"{kind} in {ev['method']} {p[:120]} "
                                      f"(answer {ev['status']})"))
            if ev.get("ua") and SCANNER_UA.search(ev["ua"]):
                out.append(self._fire("scanner", ip, now, f"Tool: {ev['ua'][:80]}", cooldown=900))
            if ev.get("status") and 400 <= ev["status"] < 500:
                dq = self.http4[ip]
                dq.append((now, p))
                self._trim(dq, now, 60)
                paths = {x for _, x in dq}
                if len(paths) >= 15 or (len(paths) >= 5 and any(SENSITIVE_PATH.search(x) for x in paths)):
                    out.append(self._fire("web_probe", ip, now, f"{len(paths)} missing or forbidden pages in a minute, "
                                          f"for example {', '.join(sorted(paths)[:3])}"))

        # --- network ----------------------------------------------------------------
        if ev.get("port") and ip and ("BLOCK" in msg or "DROP" in msg or "DENY" in msg.upper() or eid == 5157):
            dq = self.ports[ip]
            dq.append((now, ev["port"]))
            self._trim(dq, now, 60)
            ports = {x for _, x in dq}
            if len(ports) >= 15:
                out.append(self._fire("port_scan", ip, now, f"{len(ports)} different ports knocked on in a minute"))

        # --- admin rights and accounts ----------------------------------------------------
        if re.search(r"NOT in sudoers|incorrect password attempts|su: FAILED|FAILED su|authentication failure.*sudo", msg) \
                or (ev.get("app") or "").startswith("sudo") and ev.get("outcome") == "fail":
            out.append(self._fire("priv_fail", ent, now, msg[:160], cooldown=120))
        if re.search(r"COMMAND=/(?:usr/)?bin/(?:ba|z|da)?sh\b|COMMAND=/(?:usr/)?bin/su\b|sudo -i", msg):
            out.append(self._fire("root_shell", ent, now, msg[:160], cooldown=120))
        if re.search(r"new user: name=|useradd|adduser", msg) or eid == 4720:
            out.append(self._fire("new_account", ent, now, msg[:160], cooldown=60))
        if re.search(r"usermod.*-a?G.*(?:sudo|wheel|admin)|add '?\S+'? to group '?(?:sudo|wheel|admin)", msg) \
                or eid in (4728, 4732, 4756):
            out.append(self._fire("admin_group", ent, now, msg[:160], cooldown=60))
        if eid in (1102, 104) or re.search(r"audit log was cleared|log file .* cleared", msg, re.I):
            out.append(self._fire("log_cleared", ent, now, msg[:160], cooldown=60))
        if eid in (1116, 1117):
            out.append(self._fire("malware", ent, now, msg[:160], cooldown=60))
        if eid in (7045, 4697):
            out.append(self._fire("new_service", ent, now, msg[:160], cooldown=60))
        if self.disabled:
            out = [h for h in out if h and h["rule"] not in self.disabled]
        return out

"""Attack lab: a pretend company network that writes realistic logs.

Normal life: website visitors, staff logging in over SSH, an admin running updates,
cron jobs, and the usual background noise of internet scanners hitting the firewall.
On request it launches an attack, with its own attacker address, so the monitor can
show how fast it catches each one. Everything here is made up and clearly labelled.
"""
import random
import threading
import time
import uuid
from datetime import datetime, timedelta

PAGES = ["/", "/products", "/about", "/contact", "/cart", "/checkout", "/login", "/blog", "/faq",
         *[f"/products/{i}" for i in range(1, 41)], *[f"/blog/post-{i}" for i in range(1, 15)]]
STATIC = ["/static/app.js", "/static/style.css", "/images/logo.png", "/images/hero.jpg", "/favicon.ico"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/18.1 Safari/605.1.15",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
       "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"]
STAFF = {"alice": "10.0.0.11", "bob": "10.0.0.12", "carol": "10.0.0.13", "dave": "10.0.0.14", "farah": "10.0.0.15"}
SPRAY_USERS = ["admin", "test", "oracle", "postgres", "ubuntu", "git", "deploy", "guest", "support", "backup",
               "ftp", "mysql", "user", "pi", "jenkins", "hadoop"]
HIDDEN = ["/.env", "/.git/config", "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/backup.zip", "/admin/",
          "/config.php", "/.aws/credentials", "/server-status", "/actuator/env", "/db.sql", "/old/", "/test.php",
          "/.htpasswd", "/xmlrpc.php", "/cgi-bin/test.cgi", "/api/v1/users", "/debug", "/console"]
SQLI = ["/products?id=1' OR '1'='1", "/login?user=admin'--", "/products?id=1 UNION SELECT username,password FROM users",
        "/search?q=1' AND SLEEP(5)--", "/products?id=1;DROP TABLE orders", "/search?q=<script>alert(1)</script>",
        "/download?file=../../../../etc/passwd", "/ping?host=127.0.0.1;cat /etc/passwd"]

ATTACKS = {
    "brute_force": ("Password guessing", "Tries 40 passwords for the root account, two a second."),
    "break_in": ("Break-in", "Guesses passwords until one works, then becomes admin."),
    "password_spray": ("Password spraying", "Tries common usernames like admin, test and oracle."),
    "sql_injection": ("Website hacking", "Sends SQL injection and script attacks to the website."),
    "web_scan": ("Hidden page hunt", "Looks for secret files like .env, backups and admin panels."),
    "port_scan": ("Port scan", "Knocks on 40 network ports to find open doors."),
    "new_admin": ("Backdoor account", "Creates a new user and gives it admin rights."),
    "data_theft": ("Quiet data theft", "Downloads 150 invoices quickly. No known pattern matches this, so only the AI can catch it."),
    "sneaky_theft": ("Sneaky data theft", "Takes 72 invoices slowly, under the radar. The AI misses it until you teach it: "
                                          "mark a Quiet data theft alert as a real threat, then launch this again."),
}


# attackers come from the usual places on the internet (Germany, Russia, Romania, Netherlands, Lithuania, China, US)
BAD_NETS = ["185.220.101.", "45.155.205.", "193.32.162.", "103.145.13.", "141.98.11.", "218.92.0.", "167.94.138."]
# the company is in Malaysia, so most visitors are local, with some from the region and further away
VISITOR_NETS = [("175.139.", 5), ("60.50.", 4), ("115.133.", 4), ("113.210.", 3), ("121.122.", 3), ("219.92.", 2),
                ("118.200.", 2), ("116.86.", 1), ("36.68.", 2), ("114.124.", 1), ("73.20.", 1), ("24.20.", 1),
                ("86.20.", 1), ("1.120.", 1), ("49.36.", 1)]


def _bad_ip(r):
    return r.choice(BAD_NETS) + str(r.randint(2, 250))


class Simulator:
    def __init__(self, emit, rate=8.0, history_minutes=20, seed=None):
        self.emit = emit                  # function(line: str)
        self.rate = rate
        self.history = history_minutes
        self.r = random.Random(seed)
        self.queue: list = []             # (due_wall_time, line_builder)
        self.attacks: list = []
        self.lock = threading.Lock()
        self.stop_flag = threading.Event()
        self.ready = False  # True once the history has been written
        self.tz = datetime.now().astimezone().strftime("%z")
        nets = [n for n, w in VISITOR_NETS for _ in range(w)]
        self.visitors = [f"{self.r.choice(nets)}{self.r.randint(1, 250)}.{self.r.randint(1, 250)}" for _ in range(40)]
        self.blocked: set = set()
        self.fw_last: dict = {}

    # ---- log line builders -------------------------------------------------------
    def _sys(self, t, host, app, msg, pid=None):
        pid = pid or self.r.randint(1000, 39999)
        return f"{t:%b} {t.day:2d} {t:%H:%M:%S} {host} {app}[{pid}]: {msg}"

    def _web(self, t, ip, path, status, ua, method="GET"):
        size = self.r.randint(300, 40000) if status == 200 else self.r.randint(150, 600)
        return f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} {self.tz}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'

    def _fw(self, t, ip, port):
        return (f"{t:%b} {t.day:2d} {t:%H:%M:%S} firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=203.0.113.10 "
                f"PROTO=TCP SPT={self.r.randint(1024, 65000)} DPT={port}")

    # ---- normal life -------------------------------------------------------------------
    def _normal(self, t):
        r = self.r
        x = r.random()
        if x < 0.78:  # a website visit
            ip = r.choice(self.visitors)
            page = r.choice(PAGES)
            st = 200 if r.random() > 0.015 else 404
            lines = [self._web(t, ip, page, st, r.choice(UAS))]
            if r.random() < 0.5:
                lines.append(self._web(t, ip, r.choice(STATIC), 200 if r.random() > 0.5 else 304, r.choice(UAS)))
            return lines
        if x < 0.88:  # internet background noise at the firewall
            return [self._fw(t, _bad_ip(r), r.choice([23, 445, 3389, 22, 1433, 5900]))]
        if x < 0.92:  # staff using SSH (a few logins a minute, the odd typo)
            u, ip = r.choice(list(STAFF.items()))
            pid = r.randint(2000, 30000)
            if r.random() < 0.05:  # a typo, then success
                return [self._sys(t, "web-server", "sshd", f"Failed password for {u} from {ip} port {r.randint(40000, 60000)} ssh2", pid),
                        self._sys(t, "web-server", "sshd", f"Accepted password for {u} from {ip} port {r.randint(40000, 60000)} ssh2", pid)]
            return [self._sys(t, "web-server", "sshd", f"Accepted publickey for {u} from {ip} port {r.randint(40000, 60000)} ssh2: RSA SHA256:{uuid.uuid4().hex[:20]}", pid),
                    self._sys(t, "web-server", "sshd", f"pam_unix(sshd:session): session opened for user {u}(uid=100{list(STAFF).index(u)}) by (uid=0)", pid)]
        if x < 0.96:
            return [self._sys(t, "web-server", "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")]
        u, ip = r.choice(list(STAFF.items()))
        return [self._sys(t, "web-server", "sshd", f"Received disconnect from {ip} port {r.randint(40000, 60000)}:11: disconnected by user"),
                self._sys(t, "web-server", "sudo", f"    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update")
                if r.random() < 0.3 else self._sys(t, "web-server", "sshd", f"pam_unix(sshd:session): session closed for user {u}")]

    def backfill(self):
        """Write `history` minutes of normal activity first, so the AI can learn what normal looks like."""
        now = datetime.now()
        t = now - timedelta(minutes=self.history)
        while t < now - timedelta(seconds=2) and not self.stop_flag.is_set():
            for ln in self._normal(t):
                self.emit(ln)
            t += timedelta(seconds=self.r.expovariate(self.rate))

    # ---- attacks ---------------------------------------------------------------------
    def launch(self, kind: str) -> dict:
        if kind not in ATTACKS:
            raise ValueError("Unknown attack")
        r = self.r
        ip = _bad_ip(r)
        a = {"id": uuid.uuid4().hex[:8], "kind": kind, "name": ATTACKS[kind][0], "ip": ip,
             "launched": time.time(), "detected": None, "by": None, "alert_id": None, "also": [],
             "ends": None, "blocked_at": None, "dropped": 0, "sent": 0, "total": 0}
        start = time.time()
        steps = []  # (seconds after launch, function(t) -> line)
        pid = r.randint(2000, 30000)
        if kind == "brute_force":
            for i in range(40):
                steps.append((i * 0.5, lambda t, i=i: self._sys(t, "web-server", "sshd", f"Failed password for root from {ip} port {r.randint(30000, 60000)} ssh2", pid)))
        elif kind == "break_in":
            a["also"] = ["user:admin"]
            for i in range(12):
                steps.append((i * 0.6, lambda t: self._sys(t, "web-server", "sshd", f"Failed password for admin from {ip} port {r.randint(30000, 60000)} ssh2", pid)))
            steps.append((8.0, lambda t: self._sys(t, "web-server", "sshd", f"Accepted password for admin from {ip} port {r.randint(30000, 60000)} ssh2", pid)))
            steps.append((8.1, lambda t: self._sys(t, "web-server", "sshd", "pam_unix(sshd:session): session opened for user admin(uid=1005) by (uid=0)", pid)))
            steps.append((14.0, lambda t: self._sys(t, "web-server", "sudo", "   admin : TTY=pts/3 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash")))
        elif kind == "password_spray":
            for i, u in enumerate(SPRAY_USERS):
                steps.append((i * 0.8, lambda t, u=u: self._sys(t, "web-server", "sshd", f"Invalid user {u} from {ip} port {r.randint(30000, 60000)}", pid)))
                steps.append((i * 0.8 + 0.1, lambda t, u=u: self._sys(t, "web-server", "sshd", f"Failed password for invalid user {u} from {ip} port {r.randint(30000, 60000)} ssh2", pid)))
        elif kind == "sql_injection":
            for i, p in enumerate(SQLI):
                steps.append((i * 1.0, lambda t, p=p: self._web(t, ip, p.replace(" ", "%20"), r.choice([200, 403, 500]), "sqlmap/1.8.11#stable (https://sqlmap.org)")))
        elif kind == "web_scan":
            for i, p in enumerate(HIDDEN * 2):
                steps.append((i * 0.25, lambda t, p=p: self._web(t, ip, p, 404 if r.random() > 0.1 else 403, "gobuster/3.6")))
        elif kind == "port_scan":
            ports = r.sample(range(1, 10000), 40)
            for i, pt in enumerate(ports):
                steps.append((i * 0.2, lambda t, pt=pt: self._fw(t, ip, pt)))
        elif kind == "new_admin":
            a["also"] = ["user:sysupdate"]
            steps += [(0.0, lambda t: self._sys(t, "web-server", "useradd", "new user: name=sysupdate, UID=1010, GID=1010, home=/home/sysupdate, shell=/bin/bash")),
                      (1.5, lambda t: self._sys(t, "web-server", "usermod", "add 'sysupdate' to group 'sudo'")),
                      (2.0, lambda t: self._sys(t, "web-server", "sshd", f"Accepted password for sysupdate from {ip} port {r.randint(30000, 60000)} ssh2", pid))]
        elif kind == "sneaky_theft":
            ua = r.choice(UAS)
            for i in range(72):  # about 25 invoices every 30 seconds, for 85 seconds
                steps.append((i * 1.2, lambda t, i=i: self._web(t, ip, f"/invoices/INV-{31000 + i}.pdf", 200, ua)))
        elif kind == "data_theft":
            ua = r.choice(UAS)
            for i in range(150):
                steps.append((i * 0.12, lambda t, i=i: self._web(t, ip, f"/invoices/INV-{24000 + i}.pdf", 200, ua)))
        a["ends"] = start + max(s for s, _ in steps)
        a["total"] = len(steps)
        with self.lock:
            self.attacks.insert(0, a)
            self.queue.extend((start + s, f, a) for s, f in steps)
            self.queue.sort(key=lambda x: x[0])
        return a

    # ---- responding -------------------------------------------------------------------
    def block(self, ip: str) -> bool:
        """The lab firewall drops everything from this address. True if it was one of the lab's attackers."""
        self.blocked.add(ip)
        hit = False
        for a in self.attacks:
            if a["ip"] == ip:
                hit = True
                if a["blocked_at"] is None:
                    a["blocked_at"] = time.time()
        return hit

    def unblock(self, ip: str):
        self.blocked.discard(ip)

    def reset_history(self):
        with self.lock:
            self.attacks.clear()
            self.queue.clear()
        self.blocked.clear()

    def _dropped(self, a, t):
        """A line from a blocked attacker: the firewall drops it and, now and then, says so."""
        a["dropped"] += 1
        now = time.time()
        if now - self.fw_last.get(a["ip"], 0) >= 5:
            self.fw_last[a["ip"]] = now
            port = 443 if a["kind"] in ("sql_injection", "web_scan", "data_theft", "sneaky_theft") else 22
            self.emit(self._fw(t, a["ip"], port))

    def mark_detected(self, entity: str, alert_id: int, by: str):
        for a in self.attacks:
            if (a["ip"] == entity or entity in a["also"]) and a["detected"] is None:
                a.update(detected=time.time(), by=by, alert_id=alert_id)

    # ---- main loop ---------------------------------------------------------------------------
    def run(self):
        self.backfill()
        self.ready = True
        next_normal = time.time()
        while not self.stop_flag.is_set():
            now = time.time()
            t = datetime.now()
            while next_normal <= now:
                for ln in self._normal(t):
                    self.emit(ln)
                next_normal += self.r.expovariate(self.rate)
            with self.lock:
                due = [(f, a) for d, f, a in self.queue if d <= now]
                self.queue = [x for x in self.queue if x[0] > now]
            for f, a in due:
                if a["ip"] in self.blocked:
                    self._dropped(a, t)
                else:
                    a["sent"] += 1
                    self.emit(f(t))
            time.sleep(0.05)

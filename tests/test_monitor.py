import os
import socket
import time
from datetime import datetime, timedelta

import pytest

from seclog import formats
from seclog.ai import WindowAI
from seclog.monitor import Monitor
from seclog.rules import RuleEngine

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SSH = os.path.join(ROOT, "data", "sample", "OpenSSH_2k.log")  # real log from loghub


def test_reads_many_formats():
    cases = {
        "<34>Nov 23 21:50:01 web1 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2": ("syslog", "1.2.3.4", "fail"),
        '203.0.113.9 - - [23/Nov/2026:21:50:01 +0800] "GET /x?id=1%27 HTTP/1.1" 403 5 "-" "sqlmap/1.7"': ("web", "203.0.113.9", "fail"),
        "Nov 23 21:50:02 fw kernel: [UFW BLOCK] IN=eth0 SRC=45.9.1.2 DST=10.0.0.5 PROTO=TCP DPT=3389": ("firewall", "45.9.1.2", None),
        '{"_win":1,"id":4625,"time":"2026-11-23T21:50:05","fields":{"TargetUserName":"admin","IpAddress":"10.1.1.9"}}': ("windows", "10.1.1.9", "fail"),
        '{"time":"2026-11-23T21:50:06Z","message":"login failed for bob","ip":"8.8.4.4"}': ("json", "8.8.4.4", "fail"),
    }
    for line, (fmt, ip, outcome) in cases.items():
        ev = formats.parse(line)
        assert (ev["fmt"], ev["src_ip"], ev["outcome"]) == (fmt, ip, outcome), line


def test_version_numbers_are_not_ip_addresses():
    ev = formats.parse("2016-09-28 04:30:31, Info CSI WcpInitialize (wcp.dll version 0.0.0.6) called")
    assert ev["src_ip"] is None


def test_rules_find_real_brute_force():
    r = RuleEngine()
    hits = [h for line in open(SSH) for ev in [formats.parse(line)] for h in r.check(ev, formats.entity(ev)) if not h["update"]]
    rules = {h["rule"] for h in hits}
    assert "brute_force" in rules and "spray" in rules


def test_a_few_typos_are_not_a_break_in():
    r, t = RuleEngine(), datetime(2026, 11, 23, 9, 0)
    out = []
    for i in range(6):  # six typos spread over ten minutes, then a normal login
        ev = formats.parse(f"Nov 23 09:{i:02d}:00 h sshd[1]: Failed password for alice from 10.0.0.11 port 1 ssh2")
        out += r.check(ev, "10.0.0.11")
    ev = formats.parse("Nov 23 09:09:00 h sshd[1]: Accepted password for alice from 10.0.0.11 port 1 ssh2")
    out += r.check(ev, "10.0.0.11")
    assert not [h for h in out if h["rule"] == "break_in"]


def test_ai_learns_normal_and_flags_far_outlier():
    ai = WindowAI(window_secs=30, learn_windows=60)
    t0 = datetime(2026, 11, 23, 10, 0)
    for w in range(80):  # normal: each visitor reads a few pages per window
        for v in range(3):
            for p in range(3):
                ev = {"ts": t0 + timedelta(seconds=w * 30 + p), "outcome": None, "user": None, "path": f"/p{p}",
                      "port": None, "status": 200, "level": "info"}
                ai.add(ev, f"10.0.{v}.1", 1, 0)
        ai.close(t0 + timedelta(seconds=(w + 1) * 30 + 10))
    assert not ai.learning
    start = t0 + timedelta(seconds=81 * 30)
    for p in range(150):  # one address grabs 150 different pages
        ai.add({"ts": start + timedelta(seconds=p * 0.1), "outcome": None, "user": None, "path": f"/invoice/{p}",
                "port": None, "status": 200, "level": "info"}, "6.6.6.6", 1, 0)
    res = ai.close(start + timedelta(seconds=60))
    assert [r["entity"] for r in res] == ["6.6.6.6"]
    assert any("150 different web pages" in w for w in res[0]["why"])


def _wait(cond, secs=60):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.2)
    return False


@pytest.fixture
def mon(tmp_path):
    return Monitor(str(tmp_path / "m.db"), str(tmp_path / "up"))


def test_upload_real_ssh_log_finds_threats(mon):
    sid = mon.add_source("upload", "ssh", {"path": SSH})
    assert _wait(lambda: sid in mon.flushed)
    alerts = mon.alerts()
    assert len(alerts) >= 10 and alerts[0]["title"]
    d = mon.alert_detail(alerts[-1]["id"])
    assert d["lines"] and d["advice"]


def test_syslog_from_another_device(mon):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    mon.add_source("syslog", "net", {"port": port})
    time.sleep(0.5)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(10):
        u.sendto(f"<38>Nov 23 22:31:{i:02d} r sshd[9]: Failed password for admin from 192.0.2.99 port {i} ssh2".encode(),
                 ("127.0.0.1", port))
    assert _wait(lambda: any(a["entity"] == "192.0.2.99" for a in mon.alerts()))


def test_learning_from_answers():
    from seclog.learning import Learner
    L = Learner()
    assert not L.far("pages", 25, 12)  # 25 pages is not "far" by default (needs 3x and +5)
    lessons = L.learn("real", "ai", "unusual", "6.6.6.6", ["pages"], "Unusual behaviour")
    assert lessons and L.far("pages", 25, 12)  # after one confirmed threat it is
    L2 = Learner()
    assert L2.far("failures", 8, 1)
    L2.learn("false", "ai", "unusual", "10.0.0.15", ["failures"], "Unusual behaviour")
    L2.learn("false", "ai", "unusual", "10.0.0.15", ["failures"], "Unusual behaviour")
    assert not L2.far("failures", 8, 1)  # calmer after two false alarms
    L2.learn("false", "pattern", "brute_force", "10.0.0.15", [], "Someone is guessing passwords")
    assert L2.muted("brute_force", "10.0.0.15") and not L2.muted("brute_force", "6.6.6.6")


def test_learning_is_saved(tmp_path):
    m = Monitor(str(tmp_path / "m.db"), str(tmp_path / "up"))
    sid = m.add_source("upload", "ssh", {"path": SSH})
    assert _wait(lambda: sid in m.flushed)
    a = m.alerts()[0]
    lessons = m.set_status(a["id"], "false")
    assert lessons
    m2 = Monitor(str(tmp_path / "m.db"), str(tmp_path / "up2"))
    assert m2.learner.view()["stats"]["false"] == 1 and m2.ai_view()["lessons"]


def test_slow_and_distributed_guessing():
    """Found on the real loghub SSH log: attackers who stay under the fast rule, alone or as a group."""
    from datetime import datetime, timedelta
    r, t0 = RuleEngine(), datetime(2026, 11, 20, 0, 0)
    hits = []
    for i in range(30):  # one address, 3 failures an hour: never fast enough for the 8-in-2-minutes rule
        ev = formats.parse(f"Nov 20 {i // 3:02d}:{(i % 3) * 20:02d}:00 h sshd[1]: Failed password for root from 203.0.113.250 port 1 ssh2")
        hits += r.check(ev, "203.0.113.250")
    assert {h["rule"] for h in hits if not h["update"]} == {"slow_guess"}
    r2, hits2 = RuleEngine(), []
    for i in range(48):  # six addresses in one network, taking turns
        ip = f"183.136.{170 + i % 6}.{20 + i % 6}"
        ev = formats.parse(f"Nov 20 01:{i:02d}:00 h sshd[1]: Failed password for admin from {ip} port 1 ssh2")
        hits2 += r2.check(ev, ip)
    assert any(h["rule"] == "net_guess" and h["entity"] == "net:183.136.0.0/16" for h in hits2)
    r3, hits3 = RuleEngine(), []
    for i in range(40):  # a member of staff with many typos who always logs in afterwards is not an attacker
        for line in (f"Nov 20 {i // 4:02d}:{(i % 4) * 15:02d}:00 h sshd[1]: Failed password for bob from 10.0.0.12 port 1 ssh2",
                     f"Nov 20 {i // 4:02d}:{(i % 4) * 15:02d}:05 h sshd[1]: Accepted password for bob from 10.0.0.12 port 1 ssh2"):
            hits3 += r3.check(formats.parse(line), "10.0.0.12")
    assert not hits3


def test_reads_formats_found_in_ait_lds():
    """Formats from the AIT-LDS v2.0 testbed that the monitor misread before."""
    ev = formats.parse("Jan 21 00:00:09 dnsmasq[3468]: query[A] www.example.org from 10.143.0.103")
    assert (ev["app"], ev["src_ip"], ev["ts"].hour) == ("dnsmasq", "10.143.0.103", 0)
    ev = formats.parse("Jan 21 00:00:31 dnsmasq[3468]: reply www.example.org is 195.128.194.168")
    assert ev["src_ip"] is None  # the looked-up address is not the computer that asked
    ev = formats.parse("[Mon Jan 24 03:57:26.696483 2022] [authz_core:error] [pid 25711] [client 172.19.131.174:36072] "
                       "AH01630: client denied by server configuration: /var/www/x/.hta")
    assert ev["ts"].year == 2022 and ev["src_ip"] == "172.19.131.174"
    ev = formats.parse("type=USER_AUTH msg=audit(1642995460.540:997): pid=1 uid=0 auid=1001 ses=3 "
                       "msg='op=PAM:authentication acct=\"jhall\" exe=\"/usr/bin/su\" hostname=? addr=? terminal=pts/0 res=failed'")
    assert (ev["fmt"], ev["user"], ev["outcome"], ev["app"]) == ("audit", "jhall", "fail", "su")
    ev = formats.parse("2022-01-21 00:09:11 jhall/192.168.230.165:46011 TLS: soft reset sec=3308/3308")
    assert (ev["user"], ev["src_ip"]) == ("jhall", "192.168.230.165")


def test_dns_tunnel_rule():
    r, hits = RuleEngine(), []
    for i in range(25):
        ev = formats.parse(f"Jan 24 04:00:{i:02d} dnsmasq[3468]: query[A] {'a' * 55}{i}.data.{'b' * 40}.example.com from 10.1.2.3")
        hits += r.check(ev, "10.1.2.3")
    assert [h["rule"] for h in hits if not h["update"]] == ["dns_tunnel"]
    r2 = RuleEngine()
    for i in range(50):  # ordinary lookups never trigger it
        ev = formats.parse(f"Jan 24 04:00:{i:02d} dnsmasq[3468]: query[AAAA] www.site{i}.com from 10.1.2.3")
        assert not r2.check(ev, "10.1.2.3")


def test_rules_added_after_ait_lds():
    """Standard detections added after the first AIT-LDS run (general thresholds, not tuned to it)."""
    from datetime import datetime
    def run(lines):
        r, hits = RuleEngine(), []
        for l in lines:
            ev = formats.parse(l)
            hits += r.check(ev, formats.entity(ev))
        return {h["rule"] for h in hits if not h["update"]}
    assert "web_account_switch" in run(["Jan 24 04:37:40 web su[27950]: Successful su for jhall by www-data"])
    assert "secret_files" in run(["Jan 24 04:38:06 web sudo:    jhall : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow"])
    assert not run(["Jan 24 04:38:06 web sudo:    bob : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/apt update"])
    assert "dns_scan" in run([f"Jan 24 03:01:{i % 60:02d} dnsmasq[1]: query[A] {i:04x}guess.example.com from 10.9.0.10" for i in range(55)])
    assert "ptr_sweep" in run([f"Jan 24 03:02:{i:02d} dnsmasq[1]: query[PTR] {i}.0.143.10.in-addr.arpa from 10.9.0.10" for i in range(25)])
    vpn = [f"2022-01-2{d} 0{d}:00:00 192.168.230.165:4600{d} [jhall] Peer Connection Initiated with [AF_INET]192.168.230.165:4600{d}" for d in range(6)]
    assert "new_place_login" in run(vpn + ["2022-01-24 03:01:00 192.168.230.122:53581 [jhall] Peer Connection Initiated with [AF_INET]192.168.230.122:53581"])
    assert not run(vpn)


def test_huge_web_scan_stays_fast():
    """A scan of tens of thousands of different pages from one address (as in AIT-LDS fox) must not slow down:
    the hidden-page rule keeps a running tally, and live message sorting masks every page path."""
    import time
    from datetime import datetime, timedelta
    from seclog.parse import make_miner
    from seclog.rules import RuleEngine
    r, miner, t0 = RuleEngine(), make_miner(live=True), datetime(2022, 1, 18, 12)
    start, new_alerts = time.time(), 0
    for i in range(60000):
        p = f"/w{i}" if i % 2 else f"/wp-content/d{i}/f"
        ev = {"ts": t0 + timedelta(milliseconds=3 * i), "msg": f"GET {p} 404", "fmt": "web", "path": p,
              "status": 404, "method": "GET", "ua": "Mozilla", "src_ip": "172.17.130.196"}
        new_alerts += sum(1 for o in r.check(ev, "172.17.130.196") if not o["update"])
        miner.add_log_message(ev["msg"])
    assert new_alerts >= 1 and len(miner.drain.clusters) < 10
    assert time.time() - start < 30

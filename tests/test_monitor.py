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


def _wait(cond, secs=15):
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

"""The MySQL copy: row building, safe addresses, and (when a test server is given) the real round trip.

    SECLOG_TEST_MYSQL=mysql://root@127.0.0.1:3306/seclog_test python -m pytest tests/test_sqlstore.py
"""
import os
import time

import pytest

from seclog import sqlstore

ALERT = {"id": 7, "created": "2026-11-25T10:00:05", "first_ts": "2026-11-25T10:00:00", "last_ts": "2026-11-25T10:00:04",
         "source_id": 1, "entity": "45.155.205.233", "kind": "pattern", "rule": "brute_force", "severity": "high",
         "title": "Someone is guessing passwords", "detail": "40 failed logins in 60 seconds", "status": "new",
         "mitre": "T1110.001 Brute Force: Password Guessing", "features": "[]", "count": 3}
EVENT = (12, "2026-11-25T10:00:01", 1, "auth", "web01", "sshd", "45.155.205.233", "45.155.205.233", "root", "fail",
         None, 4, "Failed password for root from 45.155.205.233 port 4242 ssh2")


def test_rows_and_addresses():
    e = sqlstore.event_row(*EVENT)
    assert e[0] == 12 and e[1].year == 2026 and e[7] == "45.155.205.233" and e[9] == "root" and e[10] == "fail"
    a = sqlstore.alert_row(ALERT)
    assert a[8] == "pattern" and a[10] == "high" and a[14] == "T1110.001" and a[15] == "Credential Access" and a[17] == 3
    ai = sqlstore.alert_row({**ALERT, "kind": "ai", "rule": None, "mitre": "Anomaly", "features": '["pages"]'})
    assert ai[8] == "ai" and ai[14] is None
    assert sqlstore.parse_url("mysql://bob:s3cret@db.local:3307/logs") == {
        "host": "db.local", "port": 3307, "user": "bob", "password": "s3cret", "database": "logs"}
    assert sqlstore.safe_url("mysql://bob:s3cret@db.local:3307/logs") == "mysql://bob@db.local:3307/logs"
    for bad in ("http://x/db", "mysql://host", "mysql://host/bad;name"):
        with pytest.raises(ValueError):
            sqlstore.parse_url(bad)


def test_unreachable_mysql_keeps_rows_and_reports_why():
    s = sqlstore.Store("mysql://root@127.0.0.1:9/seclog")  # nothing listens on port 9
    s.event(EVENT, "Auth log")
    s.wake.set()
    for _ in range(80):
        if s.last_error:
            break
        time.sleep(0.1)
    st = s.status()
    assert not st["connected"] and st["waiting"] == 1 and st["error"]
    s.configure(None)
    assert s.status()["waiting"] == 0


URL = os.environ.get("SECLOG_TEST_MYSQL")


@pytest.mark.skipif(not URL, reason="set SECLOG_TEST_MYSQL to test against a real MySQL server")
def test_round_trip_with_views():
    import pymysql
    cfg = sqlstore.parse_url(URL)
    con = pymysql.connect(host=cfg["host"], port=cfg["port"], user=cfg["user"], password=cfg["password"])
    with con.cursor() as c:
        c.execute(f"DROP DATABASE IF EXISTS `{cfg['database']}`")
    con.close()
    s = sqlstore.Store(URL)
    s.event(EVENT, "Auth log")
    s.alert(ALERT, "Auth log")
    s.alert({**ALERT, "count": 9, "status": "real"}, "Auth log")  # an update to the same alert
    s.wake.set()
    for _ in range(100):
        if s.sent["alerts"] == 2 and s.sent["events"] == 1:
            break
        time.sleep(0.1)
    assert s.status()["connected"], s.status()
    rep = s.report()
    top = rep["Top attackers"]
    assert top["rows"][0][0] == "45.155.205.233" and top["rows"][0][2] == 1  # one alert, updated in place
    assert rep["Accounts under attack"]["rows"][0][:3] == ["root", 1, 1]
    con = pymysql.connect(host=cfg["host"], port=cfg["port"], user=cfg["user"], password=cfg["password"], database=cfg["database"])
    with con.cursor() as c:
        c.execute("SELECT times_seen, status FROM alerts WHERE id = 7")
        assert c.fetchone() == (9, "real")
        c.execute("SELECT name FROM sources WHERE id = 1")
        assert c.fetchone() == ("Auth log",)
    con.close()

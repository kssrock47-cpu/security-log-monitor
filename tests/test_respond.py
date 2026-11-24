"""Attack story, risk score, location, blocking, clearing and the PDF report."""
import time

from seclog import insight, report
from seclog.monitor import Monitor
from tests.test_monitor import SSH, _wait


def test_location_is_offline_and_your_network_is_home():
    assert insight.locate("10.0.0.11")["internal"]
    assert insight.locate("185.220.101.5")["cc"] == "DE"
    assert insight.locate("user:admin")["cc"] is None


def test_risk_fades_and_false_alarms_count_nothing():
    now = time.time()
    fresh = insight.risk([(now, "critical", "new")], 0, now)
    old = insight.risk([(now - 3600, "critical", "new")], 0, now)
    assert fresh > old > 0
    assert insight.risk([(now, "critical", "false")], 0, now) == 0
    assert insight.risk([(now, "high", "real")], 0, now) > insight.risk([(now, "high", "new")], 0, now)
    assert 0 <= insight.risk([(now, "critical", "new")] * 20, 50, now) <= 100


def test_alerts_map_to_attack_steps():
    assert insight.stage_of("pattern", "port_scan", []) == "recon"
    assert insight.stage_of("pattern", "break_in", []) == "access"
    assert insight.stage_of("pattern", "root_shell", []) == "admin"
    assert insight.stage_of("ai", "unusual", ["pages", "lines"]) == "harm"
    assert insight.stage_of("ai", "unusual", ["failures"]) == "creds"


def test_lab_break_in_story_block_report_and_clear(tmp_path):
    m = Monitor(str(tmp_path / "m.db"), str(tmp_path / "up"))
    m.add_source("simulator", "Attack lab", {})
    assert _wait(lambda: m.simulator() and m.simulator().sim.ready, 30)
    sim = m.simulator().sim
    time.sleep(2)
    a = sim.launch("break_in")
    assert _wait(lambda: a["detected"], 30)
    time.sleep(16)  # the attacker becomes admin 14 seconds in
    st = m.story(a["ip"])
    keys = [s["key"] for s in st["stages"] if s["alerts"]]
    assert keys[:3] == ["creds", "access", "admin"] and "user:admin" in st["entities"]
    p = m.entity_profile(a["ip"])
    assert p["risk"] >= 50 and p["geo"]["cc"] and "user:admin" in p["used"] and p["can_block"]
    # never block your own network
    try:
        m.block("10.0.0.11")
        assert False, "should refuse"
    except PermissionError:
        pass
    # block a running attack: the lab firewall drops the rest
    t = sim.launch("data_theft")
    time.sleep(3)
    r = m.block(t["ip"])
    assert r["mode"] == "lab"
    time.sleep(4)
    assert t["dropped"] > 0 and t["sent"] < t["total"]
    aid = m.alerts()[-1]["id"]
    pdf = report.build(m.alert_detail(aid), m.story(a["ip"], aid), p)
    assert pdf[:5] == b"%PDF-" and len(pdf) > 5000
    m.clear()
    assert not m.alerts() and not m.block_list() and not sim.attacks


def test_map_groups_by_country(tmp_path):
    m = Monitor(str(tmp_path / "m.db"), str(tmp_path / "up"))
    sid = m.add_source("upload", "ssh", {"path": SSH})
    assert _wait(lambda: sid in m.flushed)
    # the upload is old log time, but entities are counted by when they were seen
    d = m.map_data(60)
    assert d["points"] and d["countries"] and all("risk" in p for p in d["points"])

"""Real firewall blocking, tested with a pretend firewall (no real rules are touched)."""
import time

import pytest

from seclog import firewall
from seclog.monitor import Monitor


class FakeNetsh:
    def __init__(self):
        self.rules, self.calls = set(), []

    def __call__(self, args):
        self.calls.append(args)
        assert args[0] == "netsh"  # never a shell, never anything else
        name = next((a[5:] for a in args if a.startswith("name=")), "")
        if args[3] == "add":
            self.rules.add(name)
            return True, "Ok."
        if args[3] == "delete":
            ok = name in self.rules
            self.rules.discard(name)
            return ok, "Ok." if ok else "No rules match the specified criteria."
        if args[3] == "show":
            if name == "all":
                return True, "\n".join(f"Rule Name: {r}" for r in self.rules)
            return (name in self.rules), (f"Rule Name: {name}\nRemoteIP: {name.split()[-1]}/32" if name in self.rules else "")
        return False, "?"


@pytest.fixture
def fw(monkeypatch):
    fake = FakeNetsh()
    monkeypatch.setattr(firewall, "RUN", fake)
    monkeypatch.setattr(firewall, "status", lambda: {"available": True, "admin": True, "why": None})
    return fake


def test_only_real_addresses_reach_the_command(fw):
    with pytest.raises(ValueError):
        firewall.add("1.2.3.4 & del C:\\")
    with pytest.raises(ValueError):
        firewall.add("user:root")
    ok, _ = firewall.add("185.220.101.5")
    assert ok and "SecurityLogMonitor block 185.220.101.5" in fw.rules
    assert firewall.ours() == ["185.220.101.5"]


def test_block_unblock_switch_off_and_safe_test(fw, tmp_path):
    m = Monitor(str(tmp_path / "m.db"), str(tmp_path / "up"))
    r = m.block("185.220.101.9")
    assert r["mode"] == "simulated" and not fw.rules  # off by default
    m.set_real_firewall(True)
    r = m.block("45.155.205.7")
    assert r["mode"] == "firewall" and "SecurityLogMonitor block 45.155.205.7" in fw.rules
    with pytest.raises(PermissionError):
        m.block("192.168.1.10")  # your own network is never blocked
    m.unblock("45.155.205.7")
    assert not fw.rules
    m.block("45.155.205.8")
    m.set_real_firewall(False)  # switching off removes every rule we added
    assert not fw.rules and m.block_list()[0]["mode"] == "simulated"
    m.set_real_firewall(True)
    res = m.firewall_test()
    assert res["ok"] and not fw.rules  # the test adds a rule, finds it, removes it


def test_rules_are_removed_when_the_block_ends(fw, tmp_path):
    m = Monitor(str(tmp_path / "m.db"), str(tmp_path / "up"))
    m.set_real_firewall(True)
    m.block("141.98.11.4", minutes=1)
    assert fw.rules
    m._exec("update blocks set until=?", (time.time() - 1,))
    m._expire_blocks()
    assert not fw.rules and not m.block_list()


def test_leftover_rules_are_tidied_at_start(fw, tmp_path):
    fw.rules.add("SecurityLogMonitor block 103.99.0.122")  # e.g. left behind by a crash
    fw.rules.add("Some other program's rule")
    Monitor(str(tmp_path / "m.db"), str(tmp_path / "up"))
    time.sleep(1)
    assert fw.rules == {"Some other program's rule"}

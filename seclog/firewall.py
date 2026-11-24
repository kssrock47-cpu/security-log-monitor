"""Real blocking with the Windows Firewall (optional, off by default).

Safety rules:
* Only when a person switches it on, and only when the monitor runs as administrator.
* Never for addresses inside your own network (the allowlist in insight.py is checked first).
* Every rule is named "SecurityLogMonitor block <address>", blocks incoming traffic only,
  and is removed when the block expires (30 minutes by default), when it is unblocked,
  when the switch is turned off, and at start-up if one was left behind.
Addresses are checked to be real IP addresses before any command runs, and commands run
without a shell, so nothing from a log line can sneak into the command.
"""
import ctypes
import ipaddress
import platform
import subprocess

PREFIX = "SecurityLogMonitor block "


def _run(args):
    """Run a command without a shell. Returns (ok, output)."""
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        p = subprocess.run(args, capture_output=True, text=True, timeout=20, creationflags=flags)
        return p.returncode == 0, (p.stdout + p.stderr).strip()
    except Exception as e:  # netsh missing, timeout, ...
        return False, str(e)


RUN = _run  # tests swap this for a fake


def is_admin():
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def status():
    if platform.system() != "Windows":
        return {"available": False, "admin": False,
                "why": "The real firewall option works on Windows. On this computer blocking stays simulated."}
    if not is_admin():
        return {"available": False, "admin": False,
                "why": "Windows only lets administrators change the firewall. Close the monitor, then right-click "
                       "run.bat and choose \"Run as administrator\"."}
    return {"available": True, "admin": True, "why": None}


def _ip(ip):
    return str(ipaddress.ip_address(ip))  # raises ValueError for anything that isn't an address


def rule_name(ip):
    return PREFIX + _ip(ip)


def add(ip):
    ip = _ip(ip)
    remove(ip)  # never two rules for one address
    return RUN(["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name(ip)}", "dir=in",
                "action=block", f"remoteip={ip}", "enable=yes", "profile=any",
                "description=Added by the Security Log Monitor. Removed automatically when the block ends."])


def remove(ip):
    return RUN(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name(ip)}"])


def exists(ip):
    ok, out = RUN(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name(ip)}"])
    return ok and _ip(ip) in out


def ours():
    """Addresses that currently have one of our rules (to clean up anything left behind)."""
    ok, out = RUN(["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in"])
    if not ok:
        return []
    found = []
    for line in out.splitlines():
        if PREFIX in line:
            try:
                found.append(_ip(line.split(PREFIX, 1)[1].strip()))
            except ValueError:
                pass
    return sorted(set(found))

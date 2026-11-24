"""Turning alerts into a picture a person can act on: where an address is, how risky it is right now,
and the attack story (which steps of an attack it reached).

* Location: an offline country lookup (geoip2fast, built from MaxMind GeoLite2 data), so it works without internet.
* Risk score 0-100: recent threats count most and fade with a 30-minute half-life. Threats a person marked
  real count more; false alarms count nothing.
* Attack story: each alert is placed on one step of an attack, using the MITRE ATT&CK tactics
  (Reconnaissance, Credential Access, Initial Access, Privilege Escalation, Persistence, Defense Evasion,
  Exfiltration/Impact).
"""
import ipaddress
import math
import os
import warnings
from functools import lru_cache

HOME = os.environ.get("SECLOG_HOME", "MY")  # where "your systems" are drawn on the map
ALLOW = {x.strip() for x in os.environ.get("SECLOG_ALLOW", "").split(",") if x.strip()}

try:
    with warnings.catch_warnings():  # the package has old-style regex strings that warn on Python 3.12+
        warnings.simplefilter("ignore")
        from geoip2fast import GeoIP2Fast
        _GEO = GeoIP2Fast(verbose=False)
except Exception:  # still works without it, just without countries
    _GEO = None

COUNTRY_FIX = {"The Netherlands": "Netherlands"}


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local


@lru_cache(maxsize=20000)
def locate(ip):
    """{'cc': 'DE', 'country': 'Germany', 'internal': False}, or cc None when unknown."""
    if not is_ip(ip):
        return {"cc": None, "country": None, "internal": False}
    if is_internal(ip):
        return {"cc": HOME, "country": "Your own network", "internal": True}
    if _GEO is None:
        return {"cc": None, "country": "Unknown", "internal": False}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            r = _GEO.lookup(ip)
        cc = r.country_code if r.country_code and r.country_code != "--" else None
        name = COUNTRY_FIX.get(r.country_name, r.country_name) if cc else "Unknown"
        return {"cc": cc, "country": name, "internal": False}
    except Exception:
        return {"cc": None, "country": "Unknown", "internal": False}


def allowlisted(entity):
    """Addresses that must never be blocked: your own network, and anything in SECLOG_ALLOW."""
    return entity in ALLOW or is_internal(entity)


# ---------------------------------------------------------------- risk score
SEV_PTS = {"critical": 40, "high": 25, "medium": 12, "low": 5}
HALF_LIFE = 1800.0


def risk(alerts, fails=0, now=None):
    """alerts: iterable of (epoch_seconds, severity, status). Returns 0-100."""
    raw = 0.0
    for t, sev, status in alerts:
        if status == "false" or (now is not None and t > now):
            continue
        age = max(0.0, (now - t) if now is not None else 0.0)
        w = {"real": 1.3, "resolved": 0.4}.get(status, 1.0)
        raw += SEV_PTS.get(sev, 5) * w * 0.5 ** (age / HALF_LIFE)
    raw += min(10.0, fails * 0.4)
    return int(round(100 * (1 - math.exp(-raw / 45))))


def band(score):
    if score >= 80:
        return "critical", "Critical"
    if score >= 50:
        return "high", "High"
    if score >= 20:
        return "medium", "Worth checking"
    return "low", "Low"


# ---------------------------------------------------------------- attack story
STAGES = [
    ("recon", "Looking around", "Scanning for open doors and hidden pages", "Reconnaissance", "TA0043"),
    ("creds", "Guessing passwords", "Trying usernames and passwords", "Credential Access", "TA0006"),
    ("access", "Getting in", "Breaking in through a login or the website", "Initial Access", "TA0001"),
    ("admin", "Becoming admin", "Getting administrator (root) rights", "Privilege Escalation", "TA0004"),
    ("stay", "Staying in", "New accounts or services to come back later", "Persistence", "TA0003"),
    ("hide", "Hiding tracks", "Wiping logs", "Defense Evasion", "TA0005"),
    ("harm", "Taking data or doing harm", "Copying data, malware, unusual activity", "Exfiltration / Impact", "TA0010"),
]
STAGE_IX = {s[0]: i for i, s in enumerate(STAGES)}
RULE_STAGE = {
    "scanner": "recon", "web_probe": "recon", "port_scan": "recon",
    "brute_force": "creds", "spray": "creds", "lockout": "creds", "slow_guess": "creds", "net_guess": "creds",
    "web_attack": "access", "break_in": "access",
    "priv_fail": "admin", "root_shell": "admin", "admin_group": "admin",
    "new_account": "stay", "new_service": "stay",
    "log_cleared": "hide",
    "malware": "harm", "dns_tunnel": "harm",
}
AI_FEATURE_STAGE = {"failures": "creds", "users": "creds", "ports": "recon", "not_found": "recon"}


def stage_of(kind, rule, features):
    if kind == "pattern":
        return RULE_STAGE.get(rule, "harm")
    for f in features or []:
        if f in AI_FEATURE_STAGE:
            return AI_FEATURE_STAGE[f]
    return "harm"  # lots of pages, lines or logins: someone taking something


def secs_text(s):
    s = max(0, int(round(s)))
    if s < 90:
        return f"{s} second{'s' if s != 1 else ''}"
    if s < 5400:
        return f"{round(s / 60)} minutes"
    return f"{s / 3600:.1f} hours"

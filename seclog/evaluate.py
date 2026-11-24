"""Evaluate the monitor on real and labelled datasets.

    python -m seclog.evaluate ssh  C:\\path\\SSH.log            real SSH server, no labels: what it finds
    python -m seclog.evaluate ait  C:\\path\\russellmitchell     AIT-LDS v2.0: recall per attack step, false alarms
    python -m seclog.evaluate lanl C:\\path\\auth.txt.gz C:\\path\\redteam.txt.gz   LANL: real red-team logins

Each run uses its own throwaway monitor database (data/eval/), so the dashboard is not touched,
and writes a summary to data/eval/<name>.json.
"""
import argparse
import json
import os
import shutil
import sys
import time
from collections import Counter, defaultdict, deque

from . import insight
from .monitor import Monitor

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "data", "eval")


def fresh_monitor(name):
    d = os.path.join(OUT, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=True)
    return Monitor(os.path.join(d, "monitor.db"), os.path.join(d, "uploads"))


def run_file(m, path, label, timeout=7200):
    """Feed one file through the monitor exactly as if it were dropped on the page; wait until fully judged."""
    t0 = time.time()
    sid = m.add_source("upload", label, {"path": path, "size": os.path.getsize(path)})
    last = -1
    while sid not in m.flushed:
        if time.time() - t0 > timeout:
            raise TimeoutError("took too long")
        src = m.sources[sid]
        if src.error:
            raise RuntimeError(src.error)
        if src.lines // 100000 != last:
            last = src.lines // 100000
            print(f"  {src.lines:,} lines read, {len(m.alerts(100000))} alerts so far", flush=True)
        time.sleep(1)
    m._flush_events()
    return sid, time.time() - t0


def save(name, data):
    os.makedirs(OUT, exist_ok=True)
    p = os.path.join(OUT, f"{name}.json")
    with open(p, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\nSaved {p}")


# ---------------------------------------------------------------- 1. real SSH server (loghub), no labels
def ssh(path):
    m = fresh_monitor("ssh")
    print(f"Real SSH log: {path}")
    sid, secs = run_file(m, path, "Loghub SSH (real server)")
    lines = m.sources[sid].lines
    alerts = m.alerts(100000)
    by_rule = Counter(a["title"] for a in alerts)
    by_kind = Counter(a["kind"] for a in alerts)
    ents = {a["entity"] for a in alerts}
    ips = {e for e in ents if insight.is_ip(e)}
    seen_ips = {r[0] for r in m._rows("select distinct src_ip from events where src_ip is not null")}
    fail_ips = {r[0] for r in m._rows("select distinct src_ip from events where outcome='fail' and src_ip is not null")}
    # logins that worked from an address that was flagged: the ones a person must check first
    succ = m._rows("select src_ip, user, count(*) from events where outcome='success' and src_ip is not null "
                   "group by src_ip, user")
    risky_success = [{"ip": ip, "user": u, "logins": n} for ip, u, n in succ if ip in ips]
    countries = Counter(insight.locate(ip)["country"] or "Unknown" for ip in ips)
    breakins = [a for a in alerts if a["rule"] == "break_in"]
    data = {
        "dataset": "Loghub OpenSSH (real server on the internet, unlabelled)", "file": path,
        "lines": lines, "seconds": round(secs, 1), "lines_per_second": round(lines / max(secs, 1)),
        "addresses_seen": len(seen_ips), "addresses_with_failed_logins": len(fail_ips),
        "alerts": len(alerts), "alerts_per_1000_lines": round(1000 * len(alerts) / max(lines, 1), 2),
        "alerts_by_kind": dict(by_kind), "alerts_by_type": dict(by_rule.most_common()),
        "addresses_flagged": len(ips), "share_of_failing_addresses_flagged": round(len(ips & fail_ips) / max(len(fail_ips), 1), 3),
        "flagged_by_country": dict(countries.most_common(12)),
        "break_in_alerts": [{"ip": a["entity"], "detail": a["detail"], "time": a["first_ts"]} for a in breakins],
        "successful_logins_from_flagged_addresses": risky_success[:50],
    }
    print(json.dumps({k: v for k, v in data.items() if k not in ("successful_logins_from_flagged_addresses",)}, indent=2))
    save("ssh", data)
    return data


# ---------------------------------------------------------------- 3. LANL: real enterprise logins, real red-team labels
def lanl(auth_path, red_path, train_hours=40, settings=(1, 2, 3, 5), stop_after_days=1.0):
    """Lateral movement: an account logging in to computers it has never logged in to before.

    The first `train_hours` hours teach the detector which account logs in where. After that, every successful
    login to a new destination for that account counts as "new". An alert is raised for an account when it reaches
    k new destinations within 24 hours (k = 1, 2, 3, 5 are compared). Red-team events come from redteam.txt.
    """
    import gzip
    op = lambda p: gzip.open(p, "rt") if p.endswith(".gz") else open(p)
    red = set()
    with op(red_path) as f:
        for line in f:
            if line.count(",") == 3:
                t, u, s_, d = line.strip().split(",")
                red.add((int(t), u, s_, d))
    red_users = {u for _, u, _, _ in red}
    t_train, t_end = train_hours * 3600, max(t for t, *_ in red) + int(stop_after_days * 86400)
    print(f"LANL: {len(red)} red-team events by {len(red_users)} accounts; learning for {train_hours} h, "
          f"reading until day {t_end / 86400:.1f}")
    seen = set()                                  # (account, destination) seen before
    recent = defaultdict(deque)                   # account -> times of new destinations, last 24 h
    alerted = {k: {} for k in settings}           # k -> account -> time of last alert
    alerts = {k: 0 for k in settings}             # number of alerts (one per account per 24 h)
    caught = {k: set() for k in settings}         # red events covered by an alert for that account within 24 h
    red_seen, n_ok, n_lines, t0 = set(), 0, 0, time.time()
    with op(auth_path) as f:
        for line in f:
            n_lines += 1
            if n_lines % 20_000_000 == 0:
                print(f"  {n_lines:,} lines, day {int(line.split(',', 1)[0]) / 86400:.1f}, "
                      f"{time.time() - t0:.0f} s", flush=True)
            p = line.rstrip("\n").split(",")
            if len(p) < 9 or p[8] != "Success":
                continue
            t, user, src, dst = int(p[0]), p[1], p[3], p[4]
            if t > t_end:
                break
            if user.startswith(("ANONYMOUS", "SYSTEM", "LOCAL")) or "$@" in user:
                continue  # computer and system accounts, not people
            n_ok += 1
            key = (user, dst)
            if t < t_train:
                seen.add(key)
                continue
            is_red = (t, user, src, dst) in red
            if is_red:
                red_seen.add((t, user, src, dst))
            if key not in seen:
                seen.add(key)
                dq = recent[user]
                dq.append(t)
                while dq and t - dq[0] > 86400:
                    dq.popleft()
                for k in settings:
                    last = alerted[k].get(user)
                    if len(dq) >= k and (last is None or t - last > 86400):
                        alerted[k][user] = t
                        alerts[k] += 1
            if is_red:
                for k in settings:
                    last = alerted[k].get(user)
                    if last is not None and 0 <= t - last <= 86400:
                        caught[k].add((t, user, src, dst))
    days = max((t_end - t_train) / 86400, 1)
    results = []
    for k in settings:
        hit_users = {u for _, u, _, _ in caught[k]}
        results.append({"new_destinations_in_24h": k, "alerts": alerts[k], "alerts_per_day": round(alerts[k] / days, 1),
                        "red_events_caught": len(caught[k]), "red_events": len(red_seen),
                        "recall": round(len(caught[k]) / max(len(red_seen), 1), 3),
                        "red_accounts_caught": len(hit_users), "red_accounts": len(red_users)})
        print(f"  k={k}: recall {results[-1]['recall']:.3f} ({len(caught[k])}/{len(red_seen)} red events, "
              f"{len(hit_users)}/{len(red_users)} accounts), {alerts[k]} alerts = {results[-1]['alerts_per_day']}/day")
    data = {"dataset": "LANL Comprehensive Multi-Source Cyber-Security Events (real enterprise, red-team labels)",
            "auth": auth_path, "lines_read": n_lines, "people_logins": n_ok, "learning_hours": train_hours,
            "days_checked": round(days, 1), "seconds": round(time.time() - t0, 1), "results": results}
    save("lanl", data)
    return data


def main():
    ap = argparse.ArgumentParser(description="Evaluate the monitor on real and labelled datasets.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("ssh")
    s.add_argument("path")
    s = sub.add_parser("lanl")
    s.add_argument("auth")
    s.add_argument("redteam")
    s.add_argument("--train-hours", type=int, default=40)
    a = ap.parse_args()
    if a.cmd == "ssh":
        ssh(a.path)
    elif a.cmd == "lanl":
        lanl(a.auth, a.redteam, a.train_hours)


if __name__ == "__main__":
    sys.exit(main())

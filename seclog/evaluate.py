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


# ---------------------------------------------------------------- 2. AIT-LDS v2.0: labelled attack steps
# Generic tags are skipped so each line is counted under the attack step it belongs to.
AIT_STEPS = ["dirb", "wpscan", "webshell_upload", "webshell_cmd", "service_scan", "dns_scan", "network_scan",
             "attacker_vpn", "attacker_change_user", "escalated_sudo_command", "escalated_command", "dnsteal"]
AIT_NAMES = {"dirb": "Hidden-page scan (dirb)", "wpscan": "WordPress scan (WPScan)", "webshell_upload": "Webshell upload",
             "webshell_cmd": "Commands through the webshell", "service_scan": "Service scan (nmap)",
             "dns_scan": "DNS brute-force scan", "network_scan": "Network scan", "attacker_vpn": "Attacker's VPN login",
             "attacker_change_user": "Switching to another user", "escalated_sudo_command": "Admin commands with sudo",
             "escalated_command": "Admin commands", "dnsteal": "Data theft over DNS (DNSteal)",
             "foothold": "Other attacker activity"}


def _ait_step(labels):
    for s_ in AIT_STEPS:
        if s_ in labels:
            return s_
    return sorted(labels)[0]


def _siblings(path):
    """A log and its rotated older copies, oldest first: x.log.4, x.log.3, ..., x.log.1, x.log."""
    import glob
    import re as _re
    base = _re.sub(r"\.\d+$", "", path)
    files = [f for f in glob.glob(glob.escape(base) + "*") if f == base or _re.fullmatch(_re.escape(base) + r"\.\d+", f)]
    num = lambda f: int(f.rsplit(".", 1)[1]) if f != base else 0
    return sorted(files, key=num, reverse=True)


AIT_NEW_RULES = "dns_tunnel,web_account_switch,secret_files,dns_scan,ptr_sweep,new_place_login"


def ait(root, slack=60, baseline=False):
    """root: the folder with gather/ and labels/ from one AIT-LDS v2.0 scenario (e.g. russellmitchell)."""
    import glob
    from datetime import timedelta
    from . import formats
    scenario = os.path.basename(os.path.normpath(root)).replace("ait_", "")
    # russellmitchell keeps its original result names; other scenarios get their own
    name = ("ait" if scenario == "russellmitchell" else f"ait_{scenario}") + ("_baseline" if baseline else "")
    if baseline:  # the rules added after looking at the first run are switched off
        os.environ["SECLOG_DISABLE_RULES"] = AIT_NEW_RULES
    m = fresh_monitor(name)
    feeds = os.path.join(OUT, name, "feeds")
    os.makedirs(feeds, exist_ok=True)
    labelled = [f for f in glob.glob(os.path.join(root, "labels", "**", "*"), recursive=True)
                if os.path.isfile(f) and "monitoring" not in f]
    per_file, steps = [], defaultdict(lambda: {"lines": 0, "covered": 0, "files": set()})
    t_start = time.time()
    for lab in sorted(labelled):
        rel = os.path.relpath(lab, os.path.join(root, "labels"))
        target = os.path.join(root, "gather", rel)
        if not os.path.exists(target):
            continue
        # feed the rotated older days first, so the AI sees normal days before the attack day
        parts = _siblings(target)
        feed = os.path.join(feeds, rel.replace(os.sep, "__"))
        offset, lines = 0, []
        for f in parts:
            with open(f, errors="replace") as fh:
                chunk = fh.read().splitlines()
            if f == target:
                offset = len(lines)
            lines += chunk
        with open(feed, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        labels = {}
        with open(lab) as fh:
            for row in fh:
                d = json.loads(row)
                labels[offset + d["line"] - 1] = set(d["labels"])
        print(f"{rel}: {len(lines):,} lines ({len(parts)} file{'s' if len(parts) > 1 else ''}), {len(labels):,} attack lines")
        sid, secs = run_file(m, feed, rel)
        alerts = [a for a in m.alerts(100000) if a["source"] == sid]
        windows = defaultdict(list)
        for a in alerts:
            windows[a["entity"]].append([datetime_(a["first_ts"]) - timedelta(seconds=slack),
                                         datetime_(a["last_ts"]) + timedelta(seconds=slack), a, False])
        all_windows = [w for ws in windows.values() for w in ws]
        host_windows = [w for e, ws in windows.items() if not _named(e) for w in ws]
        # which lines did an alert cover? (same address or user, inside the alert's time span)
        now = datetime_now()
        normal_lines = 0
        for i, line in enumerate(lines):
            ev = formats.parse(line, now)
            if ev is None:
                continue
            ent, ts = formats.entity(ev), ev["ts"]
            hits = []
            if ts is not None:
                # a line that names an address or user is matched to alerts about that address or user;
                # a line that names neither (e.g. a DNS reply) is matched by time, to any alert in this log
                pool = windows.get(ent, []) + host_windows if _named(ent) else all_windows
                hits = [w for w in pool if w[0] <= ts <= w[1]]
            if i in labels:
                st = steps[_ait_step(labels[i])]
                st["lines"] += 1
                st["files"].add(rel)
                if hits:
                    st["covered"] += 1
                    for w in hits:  # every alert that overlaps the attack counts as a true alert
                        w[3] = True
            else:
                normal_lines += 1
        true_alerts = sum(1 for ws in windows.values() for w in ws if w[3])
        false = [w[2] for ws in windows.values() for w in ws if not w[3]]
        per_file.append({"file": rel, "lines": len(lines), "attack_lines": len(labels), "normal_lines": normal_lines,
                         "alerts": len(alerts), "alerts_on_attacks": true_alerts, "false_alarms": len(false),
                         "false_alarms_per_1000_normal_lines": round(1000 * len(false) / max(normal_lines, 1), 2),
                         "false_alarm_examples": [f"{a['title']} ({a['entity']})" for a in false[:5]],
                         "seconds": round(secs, 1)})
        print(f"  alerts {len(alerts)}: {true_alerts} on the attack, {len(false)} false alarms")
    table = []
    for k in sorted(steps, key=lambda s_: AIT_STEPS.index(s_) if s_ in AIT_STEPS else 99):
        v = steps[k]
        table.append({"step": AIT_NAMES.get(k, k), "label": k, "lines": v["lines"], "lines_covered": v["covered"],
                      "line_recall": round(v["covered"] / max(v["lines"], 1), 3), "detected": v["covered"] > 0,
                      "files": sorted(v["files"])})
    normal = sum(f["normal_lines"] for f in per_file)
    false = sum(f["false_alarms"] for f in per_file)
    data = {"dataset": "AIT Log Data Set V2.0, scenario " + scenario,
            "rules": "without the rules added after the first run" if baseline else "all rules",
            "steps_detected": sum(t["detected"] for t in table), "steps": len(table),
            "attack_lines": sum(t["lines"] for t in table), "attack_lines_covered": sum(t["lines_covered"] for t in table),
            "normal_lines": normal, "false_alarms": false,
            "false_alarms_per_1000_normal_lines": round(1000 * false / max(normal, 1), 3),
            "per_step": table, "per_file": per_file, "seconds": round(time.time() - t_start, 1)}
    print("\nAttack step                          detected   lines covered")
    for t in table:
        print(f"  {t['step'][:34]:34s} {'yes' if t['detected'] else 'NO ':3s}       {t['lines_covered']:,} of {t['lines']:,} ({t['line_recall']:.0%})")
    print(f"False alarms: {false} over {normal:,} normal lines = {data['false_alarms_per_1000_normal_lines']} per 1,000")
    save(name, data)
    return data


def ait_extract(zip_path, dest):
    """Unpack only what the AIT evaluation reads from a scenario zip: the label files, and for each one the
    log it labels plus that log's rotated older copies (x.log.1, x.log.2, ...). Saves unpacking the rest."""
    import re as _re
    import shutil
    import zipfile
    with zipfile.ZipFile(zip_path) as z:
        names = [n for n in z.namelist() if not n.endswith("/")]
        labels = [n for n in names if _re.search(r"(^|/)labels/", n)]
        if not labels:
            raise SystemExit("No labels/ folder in this zip; is it an AIT-LDS v2.0 scenario?")
        prefix = labels[0][:_re.search(r"(^|/)labels/", labels[0]).start() + (1 if "/labels/" in labels[0] else 0)]
        wanted = set(labels)
        gather = prefix + "gather/"
        for lab in labels:
            rel = lab[len(prefix) + len("labels/"):]
            base = _re.sub(r"\.\d+$", "", gather + rel)  # the log's own name, without a rotation number
            wanted |= {n for n in names if n == base or _re.fullmatch(_re.escape(base) + r"\.\d+", n)}
        size = sum(z.getinfo(n).file_size for n in wanted)
        print(f"Unpacking {len(wanted)} of {len(names)} files ({size / 1e9:.2f} GB) into {dest}")
        for n in sorted(wanted):
            out = os.path.join(dest, *n[len(prefix):].split("/"))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with z.open(n) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
    return dest


def _named(ent):
    return insight.is_ip(ent) or ent.startswith("user:")


def datetime_(iso):
    from datetime import datetime
    return datetime.fromisoformat(iso)


def datetime_now():
    from datetime import datetime
    return datetime.now()


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
    s = sub.add_parser("ait")
    s.add_argument("root")
    s.add_argument("--baseline", action="store_true", help="switch off the rules added after the first run")
    s = sub.add_parser("ait-extract", help="unpack only the files the AIT evaluation needs from a scenario zip")
    s.add_argument("zip")
    s.add_argument("dest")
    s = sub.add_parser("lanl")
    s.add_argument("auth")
    s.add_argument("redteam")
    s.add_argument("--train-hours", type=int, default=40)
    a = ap.parse_args()
    if a.cmd == "ssh":
        ssh(a.path)
    elif a.cmd == "ait":
        ait(a.root, baseline=a.baseline)
    elif a.cmd == "ait-extract":
        ait_extract(a.zip, a.dest)
    elif a.cmd == "lanl":
        lanl(a.auth, a.redteam, a.train_hours)


if __name__ == "__main__":
    sys.exit(main())

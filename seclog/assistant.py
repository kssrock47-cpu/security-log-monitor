"""The AI assistant: a large language model (LLM) that runs on this PC and answers questions about the monitor's data.

It uses Ollama (https://ollama.com), which runs open models locally, so log lines never leave the computer and it
works without internet once the model is downloaded. The assistant is grounded: every question is sent together
with the relevant facts from the monitor (threats, evidence lines, address profiles, attack stories, the
algorithm arena and the HDFS_v1 results), and the model is told to answer only from them. This is the
retrieval-augmented generation (RAG) pattern from the literature review.

    Install Ollama, then:   ollama pull qwen2.5:7b      (about 4.7 GB; qwen2.5:3b is 1.9 GB for slower PCs)
"""
import json
import os
import re
from datetime import datetime

import httpx

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS = os.path.join(HERE, "data", "assistant.json")
OLLAMA = os.environ.get("SECLOG_OLLAMA", "http://127.0.0.1:11434").rstrip("/")
RECOMMENDED = [
    {"name": "qwen2.5:7b", "size": "4.7 GB", "note": "Best answers. Needs about 8 GB of free memory; fast with a graphics card."},
    {"name": "qwen2.5:3b", "size": "1.9 GB", "note": "Smaller and quicker, for PCs without a graphics card."},
    {"name": "llama3.2:3b", "size": "2.0 GB", "note": "Meta's small model, a good alternative."},
]
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ALERT_RE = re.compile(r"(?:#|threat\s*|alert\s*)(\d{1,7})\b", re.I)
MAX_CONTEXT = 9000  # characters of facts sent with each question

SYSTEM = """You are the AI assistant inside Security Log Monitor, a security log analysis and threat monitoring \
system built as a university final-year project. You help a security analyst understand threats, log activity \
and the machine-learning results.

Rules:
- Answer ONLY from the FACTS section below and the conversation. If the facts don't contain the answer, say what \
is missing and which page of the dashboard would show it. Never invent addresses, numbers, log lines or alerts.
- Refer to threats as "threat #<id>" and quote short evidence lines when they help.
- Be short and plain: a direct answer first, then at most a few bullet points. Explain technical terms in a few words.
- When asked what to do, give concrete next steps (check, block, reset a password, mark as false alarm), and \
remind that a person decides.
- For the algorithm results: precision = share of alerts that were real, recall = share of real problems caught, \
F1 = their balance. Compare algorithms with the numbers given."""


# ---------------------------------------------------------------- settings and status
def settings():
    try:
        with open(SETTINGS, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_settings(**kw):
    s = {**settings(), **kw}
    os.makedirs(os.path.dirname(SETTINGS), exist_ok=True)
    with open(SETTINGS, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=1)
    return s


def status():
    """Is Ollama running, which models are on this PC, and which one the assistant uses."""
    out = {"url": OLLAMA, "running": False, "models": [], "model": None, "recommended": RECOMMENDED}
    try:
        r = httpx.get(f"{OLLAMA}/api/tags", timeout=2.5)
        r.raise_for_status()
        out["running"] = True
        out["models"] = [{"name": m["name"], "size_gb": round(m.get("size", 0) / 1e9, 1)}
                         for m in r.json().get("models", [])]
    except Exception:
        return out
    names = [m["name"] for m in out["models"]]
    want = settings().get("model")
    if want in names:
        out["model"] = want
    else:
        out["model"] = next((r["name"] for r in RECOMMENDED if r["name"] in names), names[0] if names else None)
    return out


def pull(model):
    """Download a model through Ollama, yielding progress dicts."""
    with httpx.stream("POST", f"{OLLAMA}/api/pull", json={"model": model, "stream": True}, timeout=None) as r:
        r.raise_for_status()
        for line in r.iter_lines():
            if line:
                d = json.loads(line)
                if d.get("error"):
                    raise RuntimeError(d["error"])
                yield d


# ---------------------------------------------------------------- facts (retrieval)
def _clip(s, n):
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def _alert_line(a):
    return (f"threat #{a['id']} [{a['severity']}] {a['title']} | from {a['entity']} | {a['kind']}"
            f"{' rule ' + a['rule'] if a.get('rule') else ''} | seen {a['count']}x {a['first_ts']} to {a['last_ts']}"
            f" | status {a['status']}{' | MITRE ' + a['mitre'] if a.get('mitre') else ''}")


def facts_monitor(mon, question, page):
    """Facts from the live monitor that this question and page need."""
    out = []
    st = mon.stats()
    th = st["threat"]
    out.append(f"Live monitor now: {st['total']:,} log lines read, {st['rate']} lines/s, threat level {th['level']}, "
               f"{st['open_alerts']} threats not yet answered. Connections: " +
               "; ".join(f"{s.get('name')} ({s.get('kind')}, {s.get('status')}, {s.get('lines', 0):,} lines)"
                         for s in st["sources"][:8]) if st["sources"] else "Live monitor now: no log connections running.")
    alerts = mon.alerts(400)
    if alerts:
        sev = {}
        for a in alerts:
            sev[a["severity"]] = sev.get(a["severity"], 0) + 1
        out.append(f"Threats so far (latest 400): {len(alerts)}; by severity " + ", ".join(f"{k} {v}" for k, v in sev.items()) +
                   "; answered real " + str(sum(a["status"] == "real" for a in alerts)) +
                   ", false alarm " + str(sum(a["status"] == "false" for a in alerts)) + ".")
        top = {}
        for a in alerts:
            top[a["entity"]] = top.get(a["entity"], 0) + 1
        out.append("Most threats by address/user: " + ", ".join(f"{e} ({n})" for e, n in sorted(top.items(), key=lambda x: -x[1])[:8]))
        out.append("Latest threats:\n" + "\n".join(_alert_line(a) for a in alerts[:12]))

    # the threats and addresses the question or the page is about
    ids = {int(x) for x in ALERT_RE.findall(question or "")}
    if page.get("alert"):
        ids.add(int(page["alert"]))
    for aid in list(ids)[:3]:
        d = mon.alert_detail(aid)
        if not d:
            out.append(f"threat #{aid}: does not exist.")
            continue
        story = mon.story(d["entity"], aid)
        out.append(f"DETAIL of {_alert_line(d)}\nWhy: " + " | ".join(_clip(w if isinstance(w, str) else w.get('text', w), 200) for w in d.get("why", [])[:6]) +
                   f"\nAdvice: {_clip(d.get('advice'), 400)}\nAttack story: {story.get('summary')} {story.get('verdict') or ''}\n"
                   f"Evidence lines ({len(d['lines'])} of {d.get('entity_total')} from this address/user):\n" +
                   "\n".join(_clip(l["raw"], 220) for l in d["lines"][:18]))
    ents = set(IP_RE.findall(question or ""))
    for w in re.findall(r"\b[a-z_][a-z0-9_.-]{2,31}\b", (question or "").lower()):
        if mon._one("select 1 from events where user=? limit 1", (w,)):
            ents.add(f"user:{w}")
    if page.get("entity"):
        ents.add(page["entity"])
    for e in list(ents)[:3]:
        p = mon.entity_profile(e)
        if not p:
            out.append(f"{e}: nothing seen from this address or user.")
            continue
        geo = p.get("geo") or {}
        out.append(f"PROFILE {e}: country {geo.get('country') or 'unknown'}, risk {p['risk']}/100 ({p['band']}), "
                   f"{p['events']:,} log lines, {p['fails']:,} failed, first {p['first_seen']}, last {p['last_seen']}, "
                   f"related {', '.join(p['used']) or 'none'}, blocked {'yes' if p.get('blocked') else 'no'}.\n"
                   f"Attack story: {p['story'].get('summary')} {p['story'].get('verdict') or ''}\n"
                   f"Its threats: " + "; ".join(f"#{a['id']} {a['title']} ({a['status']})" for a in p["alerts"][:10]) +
                   "\nIts latest lines:\n" + "\n".join(_clip(l["raw"], 200) for l in p["lines"][-10:]))
    return out


def facts_arena(view):
    if not view or not view.get("contenders"):
        return []
    rows = [c for c in view["contenders"] if c.get("result")]
    if not rows:
        return ["Algorithm arena: no fights run yet on this dataset."]
    rows.sort(key=lambda c: -c["result"]["f1"])
    lines = []
    for c in rows:
        r = c["result"]
        changed = {k: c["params"][k] for k in c.get("defaults_changed", [])}
        lines.append(f"{c['name']} ({c['algo_name']}, {c['learns']}{', AI-tuned' if c.get('tuned') else ''}): F1 {r['f1']:.3f}, "
                     f"precision {r['precision']:.3f}, recall {r['recall']:.3f}, caught {r['caught']:,} of {r['real']:,}, "
                     f"false alarms {r['false_alarms']:,}, learned in {r['train_seconds']:.1f}s"
                     f"{', PR-AUC ' + format(r['pr_auc'], '.3f') if r.get('pr_auc') is not None else ''}"
                     f"{', results outdated (settings changed)' if r.get('outdated') else ''}; settings " +
                     ", ".join(f"{k}={v}" for k, v in c["params"].items()) +
                     (f"; changed from default: {changed}" if changed else ""))
    return [f"Algorithm arena on dataset '{view.get('dataset')}' (train on older tasks, test on newer; "
            f"{rows[0]['result']['n_train']:,} train / {rows[0]['result']['n_test']:,} test tasks), best first:\n" + "\n".join(lines)]


def facts_research(acc):
    if not acc or not acc.get("labelled"):
        return []
    out = ["HDFS_v1 research detectors: " + "; ".join(
        f"{d['model']}: caught {d['caught']} of {d['real']}, {d['false_alarms']} false alarms, F1 {d['f1']:.3f}"
        for d in acc.get("detectors", []))]
    c = acc.get("comparison")
    if c and c.get("results"):
        out.append("Eight-technique comparison on HDFS_v1: " + "; ".join(
            f"{r['model']} F1 {r['f1']:.3f} (P {r['precision']:.3f}, R {r['recall']:.3f})" for r in c["results"]))
    return out


def build_facts(parts):
    text, used = [], 0
    for p in parts:
        if not p:
            continue
        if used + len(p) > MAX_CONTEXT:
            p = p[: max(0, MAX_CONTEXT - used)]
        text.append(p)
        used += len(p)
        if used >= MAX_CONTEXT:
            break
    return "\n\n".join(text)


# ---------------------------------------------------------------- chat
def messages_for(question, history, facts):
    msgs = [{"role": "system", "content": SYSTEM + f"\n\nToday is {datetime.now():%d %b %Y %H:%M}.\n\nFACTS:\n" + (facts or "(none)")}]
    for m in (history or [])[-8:]:
        if m.get("role") in ("user", "assistant") and m.get("content"):
            msgs.append({"role": m["role"], "content": _clip(m["content"], 2000)})
    msgs.append({"role": "user", "content": question})
    return msgs


def chat(model, msgs):
    """Stream the answer from the local model, one piece of text at a time."""
    body = {"model": model, "messages": msgs, "stream": True, "options": {"temperature": 0.2, "num_ctx": 8192}}
    with httpx.stream("POST", f"{OLLAMA}/api/chat", json=body, timeout=httpx.Timeout(300, connect=5)) as r:
        if r.status_code == 404:
            raise RuntimeError(f"The model {model} isn't on this PC. Download it from the assistant's settings.")
        r.raise_for_status()
        for line in r.iter_lines():
            if not line:
                continue
            d = json.loads(line)
            if d.get("error"):
                raise RuntimeError(d["error"])
            piece = (d.get("message") or {}).get("content")
            if piece:
                yield piece
            if d.get("done"):
                break

"""Web server for the Security Log Monitor.

Run:  python server.py        (then open http://localhost:8600)
"""
import asyncio
import json
import os
import sqlite3
import threading
import time
import uuid
import webbrowser
from contextlib import closing
from datetime import datetime

import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from seclog import insight, pipeline, plain, report, snapshot
from seclog.live import LiveEngine
from seclog.monitor import Monitor
from seclog.simulator import ATTACKS
from seclog.sources import lan_ip

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "data", "seclog.db")
DEMO_LOG = os.path.join(HERE, "data", "sample", "demo_hdfs_style.log")
DEMO_LABELS = os.path.join(HERE, "data", "sample", "demo_labels.csv")
PORT = int(os.environ.get("SECLOG_PORT", "8600"))

app = FastAPI(title="Security Log Monitor")
app.mount("/static", StaticFiles(directory=os.path.join(HERE, "web")), name="static")


@app.middleware("http")
async def always_fresh(request, call_next):
    """Browsers re-check the page and its scripts each time, so an update shows up without clearing the cache."""
    resp = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-cache"
    return resp

RUN = {"state": "idle", "message": "", "started": None}
MON = Monitor(os.path.join(HERE, "data", "monitor.db"), os.path.join(HERE, "data", "uploads"))
_cache: dict = {}
_lock = threading.Lock()


# ---------------------------------------------------------------- helpers
def q(sql, params=()):
    with closing(sqlite3.connect(DB)) as con:
        return pd.read_sql_query(sql, con, params=params)


def execute(sql, params=()):
    with closing(sqlite3.connect(DB)) as con:
        con.execute(sql, params)
        con.commit()


def has_data():
    try:
        return os.path.exists(DB) and q("select count(*) n from template_stats")["n"][0] > 0
    except Exception:
        return False


def meta():
    return dict(q("select key, value from meta").values)


def bundle():
    """Everything that depends only on the current run, computed once (and shared safely)."""
    m = meta()
    key = m.get("run_at")
    if _cache.get("key") == key:
        return _cache
    with _lock:
        if _cache.get("key") == key:
            return _cache
        return _build(m, key)


def _build(m, key):
    _cache.clear()
    templates = {int(k): v for k, v in q("select template_id, template from templates").values}
    stats = q("select * from template_stats").set_index("template_id")
    alerts = q("select a.block_id, a.model, a.score, a.flagged, b.first_ts, b.n_events, b.label, b.split "
               "from alerts a join blocks b using (block_id)")
    models = sorted(alerts["model"].unique())
    fl = alerts[alerts.flagged == 1]
    by = (fl.groupby("block_id").agg(detectors=("model", lambda s: sorted(set(s))), score=("score", "max"),
                                     first_ts=("first_ts", "first"), n=("n_events", "first"),
                                     label=("label", "first")).reset_index())
    two = len(models) == 2
    by["priority"] = by["detectors"].map(lambda d: "first" if (len(d) == 2 or not two) else "check")
    # counts for all flagged blocks in one query -> stories
    cnt = q("select e.block_id, e.template_id, count(*) n from log_events e join "
            "(select distinct block_id from alerts where flagged=1) f using (block_id) "
            "group by e.block_id, e.template_id")
    stories = {}
    for bid, g in cnt.groupby("block_id"):
        stories[bid] = plain.story(g.set_index("template_id")["n"], stats, templates)
    by["headline"] = by["block_id"].map(lambda b: stories[b]["headline"])
    by["kind"] = by["block_id"].map(lambda b: kind_of(stories[b]))
    by["rank"] = by["priority"].map({"first": 0, "check": 1})
    by = by.sort_values(["rank", "score", "first_ts"], ascending=[True, False, True]).reset_index(drop=True)
    _cache.update(key=key, meta=m, templates=templates, stats=stats, alerts=alerts, models=models,
                  by=by, stories=stories)
    return _cache


def beads(story, cap_extra=4):
    """Routine track: one bead per expected step. o=ok, m=missing, d=extra repeat, x=unusual event."""
    out = []
    for st in story["steps"]:
        n, h = st["normal"], st["here"]
        out += ["o"] * min(h, n) + ["m"] * max(n - h, 0) + ["d"] * max(h - n, 0)
    for u in story["unusual"]:
        out += ["x"] * min(u["times"], cap_extra)
    return "".join(out)


def kind_of(story):
    if story["unusual"]:
        return story["unusual"][0]["text"]
    if any(s["status"] == "missing" for s in story["steps"]):
        return "The task stopped before it finished"
    return "Usual steps, unusual amounts"


def nice(ts):
    return datetime.fromisoformat(ts).strftime("%d %b %Y, %H:%M")


# ---------------------------------------------------------------- pages
@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "web", "index.html"))


# ---------------------------------------------------------------- run
class RunReq(BaseModel):
    mode: str = "demo"
    log: str | None = None
    labels: str | None = None
    max_lines: int | None = None
    contamination: float = 0.03


def _progress(msg):
    RUN["message"] = msg


def _do_run(req: RunReq):
    try:
        if req.mode == "snapshot":
            _progress("Unpacking the saved HDFS_v1 results…")
            snapshot.install(DB)
        elif req.mode == "demo":
            pipeline.run(DEMO_LOG, DB, DEMO_LABELS, None, req.contamination, demo=True, progress=_progress)
        else:
            if not req.log or not os.path.exists(req.log):
                raise ValueError(f"Can't find the log file at {req.log!r}. Check the path.")
            lab = req.labels if req.labels and os.path.exists(req.labels) else None
            if req.labels and not lab:
                raise ValueError(f"Can't find the labels file at {req.labels!r}.")
            pipeline.run(req.log, DB, lab, req.max_lines or None, req.contamination, demo=False, progress=_progress)
        _cache.clear()
        RUN.update(state="done", message="Check finished.")
    except Exception as e:  # report in plain words
        RUN.update(state="error", message=str(e))


@app.post("/api/run")
def start_run(req: RunReq):
    if RUN["state"] == "running":
        raise HTTPException(409, "A check is already running.")
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    RUN.update(state="running", message="Reading the logs and training the detectors…", started=time.time())
    threading.Thread(target=_do_run, args=(req,), daemon=True).start()
    return RUN


@app.get("/api/run/status")
def run_status():
    return {**RUN, "elapsed": round(time.time() - RUN["started"], 1) if RUN["started"] else 0}


# ---------------------------------------------------------------- data
@app.get("/api/state")
def state():
    if not has_data():
        return {"has_data": False, "run": RUN}
    m = meta()
    return {"has_data": True, "run": RUN, "demo": m.get("demo") == "1", "source": m.get("source"),
            "run_at": m.get("run_at"), "labelled": m.get("labelled") == "1", "snapshot": m.get("snapshot") == "1",
            "snapshot_available": snapshot.available()}


@app.get("/api/overview")
def overview():
    b = bundle()
    by = b["by"]
    n_lines = int(b["meta"].get("n_lines") or q("select count(*) n from log_events")["n"][0])
    n_blocks = int(b["meta"].get("n_blocks") or q("select count(*) n from blocks")["n"][0])
    # timeline: at most ~40 bars
    t0 = pd.to_datetime(b["meta"].get("t_min") or q("select min(first_ts) t from blocks")["t"][0])
    t1 = pd.to_datetime(b["meta"].get("t_max") or q("select max(first_ts) t from blocks")["t"][0])
    span_min = max((t1 - t0).total_seconds() / 60, 1)
    step = next(s for s in [5, 10, 15, 30, 60, 120, 240, 480, 1440, 10_000] if span_min / s <= 40)
    t = by.copy()
    t["bin"] = pd.to_datetime(t["first_ts"]).dt.floor(f"{step}min")
    bins = pd.date_range(t0.floor(f"{step}min"), t1.floor(f"{step}min"), freq=f"{step}min")
    piv = t.pivot_table(index="bin", columns="priority", values="block_id", aggfunc="count").reindex(bins).fillna(0)
    timeline = [{"t": i.isoformat(), "first": int(r.get("first", 0)), "check": int(r.get("check", 0))}
                for i, r in piv.iterrows()]
    kinds = by.groupby("kind").size().sort_values(ascending=False)
    fb = q("select verdict, count(*) n from feedback group by verdict")
    # a slice of real log lines for the hero, with one alert inside it
    hero = []
    if len(by):
        bid = by.iloc[0]["block_id"]
        ln = int(q("select min(line_no) n from log_events where block_id=?", (bid,))["n"][0])
        rows = q("select line_no, block_id, template_id, content from log_events "
                 "where line_no between ? and ? order by line_no limit 60", (ln - 4, ln + 56))
        hero = [{"raw": r.content[:200], "alert": r.block_id == bid,
                 "plain": plain.friendly(b["templates"][int(r.template_id)])} for r in rows.itertuples()]
    return {"n_lines": n_lines, "n_blocks": n_blocks, "n_alerts": int(len(by)),
            "n_first": int((by.priority == "first").sum()), "n_check": int((by.priority == "check").sum()),
            "n_kinds": len(b["templates"]), "detectors": b["models"], "bin_minutes": step,
            "timeline": timeline, "kinds": [{"kind": k, "n": int(v)} for k, v in kinds.items()],
            "reviewed": {r.verdict: int(r.n) for r in fb.itertuples()}, "hero": hero,
            "first_alert": by.iloc[0]["block_id"] if len(by) else None,
            "first_headline": by.iloc[0]["headline"] if len(by) else None,
            "normal_example": normal_example(b),
            "normal_track": "".join("o" * int(round(r.normal_median)) for _, r in
                                    b["stats"][b["stats"].normal_share >= 0.95].sort_values("typical_pos").iterrows()),
            "test_start": b["meta"].get("test_start"),
            "n_train": int(b["meta"].get("n_train") or q("select count(*) n from blocks where split='train'")["n"][0]),
            "demo": b["meta"].get("demo") == "1", "max_lines": b["meta"].get("max_lines") or None,
            "live_wait_min": live_wait(b["meta"]) // 60}


def normal_example(b):
    """A newer task that no detector flagged, to show what normal looks like."""
    ok = b["alerts"][(b["alerts"].split == "test")].groupby("block_id")["flagged"].max()
    ok = ok[ok == 0]
    return ok.index[len(ok) // 2] if len(ok) else None


@app.get("/api/alerts")
def alert_list():
    b = bundle()
    fb = dict(q("select block_id, verdict from feedback").values)
    st = b["stories"]
    return [{"id": r.block_id, "headline": r.headline, "kind": r.kind, "priority": r.priority,
             "track": beads(st[r.block_id]),
             "detectors": r.detectors, "time": r.first_ts, "when": nice(r.first_ts), "lines": int(r.n),
             "review": fb.get(r.block_id)} for r in b["by"].head(3000).itertuples()]


@app.get("/api/alerts/{bid}")
def alert_detail(bid: str):
    b = bundle()
    row = b["by"][b["by"].block_id == bid]
    if row.empty:
        raise HTTPException(404, "No alert with that id.")
    r = row.iloc[0]
    s = b["stories"][bid]
    ev = q("select line_no, ts, level, template_id, content from log_events where block_id=? order by line_no",
           (bid,))
    m = b["meta"]
    det = []
    for _, a in b["alerts"][b["alerts"].block_id == bid].iterrows():
        thr = float(m["if_threshold"]) if a.model == "Isolation Forest" else 0.5
        det.append({"model": a.model, "score": round(float(a.score), 3), "threshold": round(thr, 3),
                    "flagged": bool(a.flagged)})
    fb = q("select verdict from feedback where block_id=?", (bid,))
    return {"id": bid, "headline": s["headline"], "priority": r.priority, "detectors": r.detectors,
            "when": nice(r.first_ts), "steps": s["steps"], "unusual": s["unusual"], "next": s["next_steps"],
            "lines": [{"time": x.ts[11:], "level": x.level, "raw": x.content,
                       "plain": plain.friendly(b["templates"][int(x.template_id)]),
                       "unusual": int(x.template_id) in s["rare_ids"]} for x in ev.itertuples()],
            "scores": det, "answer": r.label if isinstance(r.label, str) else None,
            "track": beads(s), "normal_track": "".join("o" * st["normal"] for st in s["steps"]),
            "review": fb["verdict"][0] if len(fb) else None}


class Feedback(BaseModel):
    block_id: str
    verdict: str | None  # "real", "false", "unsure" or None to clear


@app.post("/api/feedback")
def feedback(f: Feedback):
    if f.verdict is None:
        execute("delete from feedback where block_id=?", (f.block_id,))
    else:
        if f.verdict not in {"real", "false", "unsure"}:
            raise HTTPException(400, "verdict must be real, false or unsure")
        execute("insert or replace into feedback values (?,?,?)",
                (f.block_id, f.verdict, datetime.now().isoformat(timespec="seconds")))
    return {"ok": True}


@app.get("/api/accuracy")
def accuracy():
    b = bundle()
    m = b["meta"]
    runs = q("select * from model_runs")
    out = {"labelled": m.get("labelled") == "1", "demo": m.get("demo") == "1", "detectors": []}
    if not out["labelled"]:
        return out
    test = b["alerts"][b["alerts"].split == "test"]
    for _, rr in runs.iterrows():
        t = test[test.model == rr.model]
        real = t[t.label == "Anomaly"]
        out["detectors"].append({
            "model": rr.model, "n_train": int(rr.n_train), "n_test": int(rr.n_test),
            "real": int(len(real)), "caught": int(real.flagged.sum()), "raised": int(t.flagged.sum()),
            "false_alarms": int(((t.label != "Anomaly") & (t.flagged == 1)).sum()),
            "precision": rr.precision, "recall": rr.recall, "f1": rr.f1,
            **dots(int(len(real)), int(real.flagged.sum()), int(((t.label != "Anomaly") & (t.flagged == 1)).sum()))})
    return out


def dots(real, caught, false_alarms, most=200):
    """Dot picture for the accuracy page: one dot per problem, or one dot per `unit` problems if many."""
    unit = max(1, -(-real // most))
    return {"unit": unit, "dot_caught": round(caught / unit), "dot_missed": round((real - caught) / unit),
            "dot_false": min(round(false_alarms / unit), most)}


@app.get("/api/walkthrough/{bid}")
def walkthrough(bid: str):
    """The same task followed through every stage of the pipeline."""
    b = bundle()
    m = b["meta"]
    ev = q("select content, template_id from log_events where block_id=? order by line_no", (bid,))
    if ev.empty:
        raise HTTPException(404, "Unknown task.")
    counts = ev.groupby("template_id").size()
    stats = b["stats"]
    vec = [{"id": int(t), "plain": plain.friendly(b["templates"][int(t)]), "here": int(counts.get(t, 0)),
            "normal": round(float(stats.loc[t, "normal_median"]), 1)} for t in stats.index
           if counts.get(t, 0) or stats.loc[t, "normal_median"] > 0]
    det = []
    for _, a in b["alerts"][b["alerts"].block_id == bid].iterrows():
        thr = float(m["if_threshold"]) if a.model == "Isolation Forest" else 0.5
        det.append({"model": a.model, "score": round(float(a.score), 3), "threshold": round(thr, 3),
                    "flagged": bool(a.flagged)})
    s = b["stories"].get(bid) or plain.story(counts, stats, b["templates"])
    flagged = bid in b["stories"]
    return {"id": bid, "flagged": flagged, "track": beads(s),
            "normal_track": "".join("o" * st["normal"] for st in s["steps"]),
            "raw": ev["content"].str.slice(0, 200).tolist()[:10],
            "templates": [{"template": b["templates"][int(t)], "plain": plain.friendly(b["templates"][int(t)]),
                           "n": int(n)} for t, n in counts.items()],
            "vector": vec, "detectors": det,
            "headline": s["headline"] if flagged else "Nothing unusual. This task followed the usual routine."}


# ---------------------------------------------------------------- live mode
def live_wait(m):
    """How long a task must be quiet before it is checked.

    Measured on HDFS_v1 (20,000 newer tasks): 1 minute gave 715 false alarms, 10 minutes gave 1,
    30 minutes gave 0 and caught 91% of real problems. The made-up demo tasks finish within a minute.
    """
    return 60 if m.get("demo") == "1" else 1800

LIVE: dict = {}


def replay_log(m):
    p = m.get("log_path") or ""
    return p if os.path.isabs(p) else os.path.join(HERE, p)


@app.post("/api/live/start")
def live_start(speed: float = 60):
    m = meta()
    if not os.path.exists(replay_log(m)):
        raise HTTPException(409, f"The replay needs the original log file, which isn't on this computer ({m.get('log_path')}). "
                                 "Use \"Re-run the HDFS check\" to point at it, or restore the saved HDFS_v1 results.")
    sid = uuid.uuid4().hex[:8]
    LIVE[sid] = {"speed": speed, "paused": False, "stop": False}
    return {"sid": sid, "start": m.get("test_start")}


class LiveCtl(BaseModel):
    sid: str
    speed: float | None = None
    paused: bool | None = None
    stop: bool | None = None


@app.post("/api/live/control")
def live_control(c: LiveCtl):
    s = LIVE.get(c.sid)
    if not s:
        raise HTTPException(404, "No live session.")
    for k in ("speed", "paused", "stop"):
        v = getattr(c, k)
        if v is not None:
            s[k] = v
    return s


@app.get("/api/live/stream")
async def live_stream(sid: str):
    s = LIVE.get(sid)
    if not s:
        raise HTTPException(404, "No live session.")
    m = meta()
    skip = set(q("select block_id from blocks where split='train'")["block_id"])
    eng = LiveEngine(pipeline.model_path(DB), replay_log(m), m["test_start"], idle_secs=live_wait(m),
                     offset=int(m.get("test_offset") or 0), skip_blocks=skip)

    async def gen():
        it = eng.events()
        sim_prev = None
        batch, last_flush = [], time.monotonic()
        stats = {"lines": 0, "tasks": 0, "alerts": 0}
        yield f"event: hello\ndata: {json.dumps({'start': m['test_start']})}\n\n"
        for ev in it:
            if s["stop"]:
                break
            while s["paused"] and not s["stop"]:
                await asyncio.sleep(0.2)
            ts = datetime.fromisoformat(ev["time"])
            if ev["type"] == "line":
                if sim_prev is not None and ts > sim_prev:
                    wait = (ts - sim_prev).total_seconds() / max(s["speed"], 0.1)
                    if batch and (time.monotonic() - last_flush > 0.12 or wait > 0.12):
                        yield f"event: batch\ndata: {json.dumps({'events': batch, 'stats': stats, 'clock': ev['time']})}\n\n"
                        batch, last_flush = [], time.monotonic()
                    await asyncio.sleep(min(wait, 2.0))
                sim_prev = ts if sim_prev is None or ts > sim_prev else sim_prev
                stats["lines"] += 1
            else:
                stats["tasks"] += 1
                stats["alerts"] += int(ev["flagged"])
            batch.append(ev)
            if len(batch) > 400:
                yield f"event: batch\ndata: {json.dumps({'events': batch, 'stats': stats, 'clock': ev['time']})}\n\n"
                batch, last_flush = [], time.monotonic()
                await asyncio.sleep(0)
        if batch:
            yield f"event: batch\ndata: {json.dumps({'events': batch, 'stats': stats})}\n\n"
        yield f"event: done\ndata: {json.dumps(stats)}\n\n"
        LIVE.pop(sid, None)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ================================================================ live security monitor
@app.get("/api/m/state")
def m_state():
    import platform
    st = MON.stats()
    st["connections"] = MON.known_sources()
    st["platform"] = platform.system()
    st["lan_ip"] = lan_ip()
    sim = MON.simulator()
    st["lab"] = {"running": bool(sim), "ready": bool(sim and sim.sim.ready)}
    return st


class SourceReq(BaseModel):
    kind: str
    name: str | None = None
    config: dict = {}


NAMES = {"watch": "Watched file", "url": "Web address", "syslog": "Devices on the network",
         "windows": "This PC's Windows events", "simulator": "Attack lab"}


@app.post("/api/m/sources")
def m_add(r: SourceReq):
    if r.kind == "upload":
        raise HTTPException(400, "Upload files with /api/m/upload.")
    if r.kind == "watch" and not os.path.exists(os.path.expanduser(r.config.get("path", ""))):
        raise HTTPException(400, f"Can't find {r.config.get('path')!r} on this computer. Check the path.")
    if r.kind == "url" and not str(r.config.get("url", "")).startswith(("http://", "https://")):
        raise HTTPException(400, "The web address must start with http:// or https://")
    try:
        sid = MON.add_source(r.kind, r.name or NAMES.get(r.kind, r.kind), r.config)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"id": sid}


@app.post("/api/m/sources/{sid}/{action}")
def m_source_action(sid: int, action: str):
    if action == "stop":
        MON.stop_source(sid)
    elif action == "start":
        MON.start_source(sid)
    elif action == "remove":
        MON.remove_source(sid)
    else:
        raise HTTPException(400, "action must be stop, start or remove")
    return {"ok": True}


@app.post("/api/m/upload")
async def m_upload(request: Request, name: str = "upload.log"):
    async def chunks():
        async for c in request.stream():
            yield c
    data = []
    async for c in chunks():
        data.append(c)
    path, size = MON.save_upload(name, iter(data))
    if size == 0:
        raise HTTPException(400, "The file is empty.")
    sid = MON.add_source("upload", name, {"path": path, "size": size})
    return {"id": sid, "size": size}


SAMPLES = {
    "ssh": ("OpenSSH_2k.log", "Real SSH server under attack (loghub)"),
    "linux": ("Linux_2k.log", "Real Linux system log (loghub)"),
    "apache": ("Apache_2k.log", "Real Apache web server errors (loghub)"),
}


@app.post("/api/m/sample/{key}")
def m_sample(key: str):
    if key not in SAMPLES:
        raise HTTPException(404, "No such sample.")
    fn, name = SAMPLES[key]
    path = os.path.join(HERE, "data", "sample", fn)
    return {"id": MON.add_source("upload", name, {"path": path, "size": os.path.getsize(path), "sample": True})}


@app.get("/api/m/alerts")
def m_alerts(status: str | None = None, limit: int = 500):
    return MON.alerts(limit, status)


@app.get("/api/m/alerts/{aid}")
def m_alert(aid: int):
    d = MON.alert_detail(aid)
    if not d:
        raise HTTPException(404, "No such alert.")
    ent = d["entity"]
    d["story"] = MON.story(ent, aid)
    d["geo"] = insight.locate(ent) if insight.is_ip(ent) else None
    d["blocked"] = next((b for b in MON.block_list() if b["entity"] == ent), None)
    d["can_block"] = insight.is_ip(ent) and not insight.allowlisted(ent)
    d["allowlisted"] = insight.is_ip(ent) and insight.allowlisted(ent)
    d["risk"] = insight.risk(MON._alert_times(ent).get(ent, []), 0, time.time())
    return d


@app.get("/api/m/alerts/{aid}/report.pdf")
def m_alert_report(aid: int):
    d = MON.alert_detail(aid)
    if not d:
        raise HTTPException(404, "No such alert.")
    blocked = next((b for b in MON.block_list() if b["entity"] == d["entity"]), None)
    pdf = report.build(d, MON.story(d["entity"], aid), MON.entity_profile(d["entity"]), blocked)
    name = f"threat-{aid}-report-{datetime.now():%Y%m%d-%H%M}.pdf"
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/m/entity")
def m_entity(e: str):
    d = MON.entity_profile(e)
    if not d:
        raise HTTPException(404, "Nothing has been seen from this address or user.")
    return d


@app.get("/api/m/map")
def m_map(minutes: int = 60):
    return MON.map_data(minutes)


class BlockReq(BaseModel):
    entity: str
    minutes: int = 30
    alert_id: int | None = None


@app.post("/api/m/block")
def m_block(b: BlockReq):
    try:
        return MON.block(b.entity, max(1, min(b.minutes, 1440)), b.alert_id)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/m/unblock")
def m_unblock(b: BlockReq):
    MON.unblock(b.entity)
    return {"ok": True}


@app.get("/api/m/blocks")
def m_blocks():
    return MON.block_list()


@app.get("/api/m/response")
def m_response():
    return MON.response_view()


class FirewallReq(BaseModel):
    real_firewall: bool


@app.post("/api/m/response")
def m_response_set(r: FirewallReq):
    try:
        return MON.set_real_firewall(r.real_firewall)
    except PermissionError as e:
        raise HTTPException(403, str(e))


@app.post("/api/m/response/test")
def m_response_test():
    try:
        return MON.firewall_test()
    except PermissionError as e:
        raise HTTPException(403, str(e))


@app.post("/api/m/clear")
def m_clear():
    MON.clear()
    return {"ok": True}


class Status(BaseModel):
    status: str


@app.post("/api/m/alerts/{aid}/status")
def m_alert_status(aid: int, s: Status):
    try:
        lessons = MON.set_status(aid, s.status)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except KeyError:
        raise HTTPException(404, "No such alert.")
    return {"ok": True, "lessons": lessons}


@app.get("/api/m/ai")
def m_ai():
    return MON.ai_view()


@app.post("/api/m/ai/reset")
def m_ai_reset():
    MON.reset_learning()
    return {"ok": True}


@app.get("/api/m/entities")
def m_entities(minutes: int = 15):
    return MON.entity_list(minutes)


@app.get("/api/m/stream")
async def m_stream(request: Request, since: int = 0):
    async def gen():
        seq = since or MON.seq
        while True:
            if await request.is_disconnected():
                break
            items, seq_now = MON.since(seq)
            seq = seq_now
            if items:
                evs = [p for _, k, p in items if k == "event"][-40:]
                alerts = [p for _, k, p in items if k == "alert"]
                other = [{"kind": k, **p} for _, k, p in items if k not in ("event", "alert", "stats")]
                stats = [p for _, k, p in items if k == "stats"]
                payload = {"events": evs, "alerts": alerts, "notes": other[-20:], "seq": seq}
                if stats:
                    payload["stats"] = stats[-1]
                yield f"data: {json.dumps(payload, default=str)}\n\n"
            await asyncio.sleep(0.4)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/m/lab")
def m_lab():
    sim = MON.simulator()
    return {"running": bool(sim), "ready": bool(sim and sim.sim.ready),
            "catalog": [{"kind": k, "name": v[0], "text": v[1]} for k, v in ATTACKS.items()],
            "attacks": [{**a, "now": time.time(), "missed": not a["detected"] and time.time() > (a["ends"] or 0) + 45,
                         "blocked": a["ip"] in sim.sim.blocked,
                         "stopped": a["total"] - a["sent"] if a["blocked_at"] else 0}
                        for a in (sim.sim.attacks if sim else [])][:50]}


@app.post("/api/m/lab/start")
def m_lab_start():
    return {"id": MON.add_source("simulator", "Attack lab", {})}


@app.post("/api/m/lab/stop")
def m_lab_stop():
    sim = MON.simulator()
    if sim:
        MON.stop_source(sim.sid)
    return {"ok": True}


class Attack(BaseModel):
    kind: str


@app.post("/api/m/lab/attack")
def m_lab_attack(a: Attack):
    sim = MON.simulator()
    if not sim or not sim.sim.ready:
        raise HTTPException(409, "Start the attack lab first, and wait a moment while it learns.")
    try:
        return sim.sim.launch(a.kind)
    except ValueError as e:
        raise HTTPException(400, str(e))


def main():
    import uvicorn
    if not has_data():
        if snapshot.available():
            print("First start: unpacking the saved HDFS_v1 research results…")
            snapshot.install(DB)
        else:
            print("First start: running the demo check once…")
            pipeline.run(DEMO_LOG, DB, DEMO_LABELS, None, 0.03, demo=True)
    # prepare the dashboard data in the background, so the first page opens quickly
    threading.Thread(target=lambda: has_data() and bundle(), daemon=True).start()
    url = f"http://localhost:{PORT}"
    print(f"\n  Security Log Monitor is running at {url}\n  Close this window to stop it.\n")
    if not os.environ.get("SECLOG_NO_BROWSER"):
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()

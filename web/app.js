/* Security Log Monitor — front end. Plain JavaScript, no build step, works offline. */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (n) => Number(n).toLocaleString("en-GB");
const api = async (path, opts) => {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r.json();
};
const post = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
const when = (iso) => new Date(iso).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
const clockTime = (iso) => new Date(iso).toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });

const DET = {
  "Isolation Forest": { name: "Detector A", plain: "learns what normal looks like, then spots anything different" },
  "Random Forest": { name: "Detector B", plain: "learns from past examples marked normal or problem" },
  "New message type": { name: "New message", plain: "a kind of message the monitor has never seen" },
};
const detName = (m) => (DET[m] ? DET[m].name : m);
const techChip = (t) => `<span class="chip tech tech-only">${esc(t)}</span>`;

const S = { state: null, overview: null, alerts: null, filter: { pri: "all", q: "", kind: null, from: null, to: null, todo: false }, cur: null, live: null };

/* ---------- routine track ---------- */
function track(code, mini = false, label = "") {
  const cls = { o: "", m: "miss", d: "diff", x: "extra" };
  const title = { o: "Usual step", m: "Missing step", d: "Repeated more than usual", x: "Unusual event" };
  const beads = [...(code || "")].map((c) => `<span class="bead ${cls[c]}" title="${title[c]}"></span>`).join("");
  return `<div class="track${mini ? " mini" : ""}" role="img" aria-label="${esc(label || "routine track")}">${beads}</div>`;
}

/* ---------- shell ---------- */
async function loadState() {
  S.state = await api("/api/state");
  const st = S.state;
  const src = $("#source");
  if (!st.has_data) { src.textContent = "No logs checked yet."; return; }
  src.innerHTML = `Showing <b>${esc(st.source)}</b>, checked ${esc(when(st.run_at))} ` +
    (st.demo ? `<span class="chip demo">Made-up demo logs</span>` : `<span class="chip ok">Real logs</span>`);
}

function setTech(on) {
  document.body.classList.toggle("tech", on);
  $("#techToggle").checked = on;
  try { localStorage.setItem("tech", on ? "1" : "0"); } catch (e) { /* storage may be blocked */ }
}

function demoNote() {
  return S.state && S.state.demo
    ? `<div class="demo-note">These are made-up logs, built to look like a real storage system's. They show how the monitor works. The numbers are not research results.</div>`
    : "";
}

const routes = { research: viewOverview, alerts: viewAlerts, replay: viewLive, accuracy: viewAccuracy, how: viewHow };
const RESEARCH = new Set(Object.keys(routes));
window.APP = { routes, api, post, esc, fmt, when, clockTime, techChip, $, $$, track, showTip, hideTip, S };
async function route() {
  stopLive();
  if (window.MON && window.MON.leave) window.MON.leave();
  const [, name = "monitor", arg] = location.hash.split("/");
  const area = RESEARCH.has(name) ? "research" : "monitor";
  document.body.dataset.area = area;
  $$("[data-nav]").forEach((a) => a.setAttribute("aria-current", a.dataset.nav === name ? "page" : "false"));
  const view = $("#view");
  view.innerHTML = `<p class="muted"><span class="spinner"></span>Loading…</p>`;
  try {
    if (area === "monitor") { await (routes[name] || routes.monitor)(view, arg && decodeURIComponent(arg)); view.focus({ preventScroll: true }); return; }
    if (!S.state) await loadState();
    if (!S.state.has_data) { view.innerHTML = emptyState(); return; }
    await (routes[name] || viewOverview)(view, arg && decodeURIComponent(arg));
  } catch (e) {
    view.innerHTML = `<div class="empty">Something went wrong: ${esc(e.message)}. Try reloading the page.</div>`;
  }
  view.focus({ preventScroll: true });
}

function emptyState() {
  return `<div class="empty"><h2>No logs checked yet</h2><p>Run the check on the demo logs to see what the monitor does.</p>
  <button class="btn primary" onclick="openRun()">Check a log file</button></div>`;
}

/* ---------- 1. overview ---------- */
async function viewOverview(view) {
  const o = (S.overview = await api("/api/overview"));
  const reviewed = Object.values(o.reviewed).reduce((a, b) => a + b, 0);
  view.innerHTML = `
  ${demoNote()}
  <section class="hero">
    <div class="hero-text">
      <h1><span class="num">${fmt(o.n_alerts)}</span> of ${fmt(o.n_blocks)} storage tasks need a second look.</h1>
      <p class="lead">The monitor read ${fmt(o.n_lines)} log lines, learned the usual routine, and picked out the tasks that broke it. Each one comes with a reason in plain words and the lines that prove it.</p>
      <div class="figures">
        <div><b>${fmt(o.n_lines)}</b>log lines read</div>
        <div><b>${fmt(o.n_kinds)}</b>kinds of message</div>
        <div><b style="color:var(--flare)">${fmt(o.n_first)}</b>look at first</div>
        <div><b style="color:#9a7a0a">${fmt(o.n_check)}</b>worth checking</div>
      </div>
      <div class="actions">
        <a class="btn primary" href="#/alerts">Review the alerts</a>
        <a class="btn" href="#/replay">Replay it live</a>
      </div>
      <div>${techChip("Drain3 log parsing")} ${techChip("Isolation Forest")} ${techChip("Random Forest")} ${techChip("SQLite")}</div>
    </div>
    <div class="river" id="river" aria-label="A slice of the log with one flagged task">
      <div class="river-head"><span>The raw log</span><span>${fmt(o.n_lines)} lines</span></div>
      <div class="river-lines">${o.hero.map((l) => `<div class="ln${l.alert ? " hot" : ""}">${esc(l.raw)}</div>`).join("")}</div>
      <div class="river-fade"></div>
      ${o.first_alert ? `<a class="river-callout" href="#/alerts/${encodeURIComponent(o.first_alert)}" style="text-decoration:none">
        <span class="small muted">The red lines belong to one task that broke the routine</span>
        <b>${esc(o.first_headline)}</b>
        <span class="small" style="color:var(--harbor);font-weight:600">Open this alert</span></a>` : ""}
    </div>
  </section>

  <section class="panel" style="margin-bottom:22px">
    <div class="grid2 howread" style="align-items:center">
      <div>
        <h3>How to read a storage task</h3>
        <p class="muted" style="margin:6px 0 0">The system saves each file in pieces, and copies every piece to three computers. Each piece follows the same short routine of ${o.normal_track.length} steps, drawn here as beads. The monitor checks every piece against that routine.</p>
      </div>
      <div class="tracks">
        <span class="lbl">Normal</span>${track(o.normal_track, false, "a normal routine")}
        <span class="lbl">Missing step</span>${track(o.normal_track.slice(0, 5) + "mmmm" + o.normal_track.slice(9), false, "a routine with missing steps")}
        <span class="lbl">Odd event</span>${track(o.normal_track + "xx", false, "a routine with unusual events")}
      </div>
    </div>
  </section>

  <section class="grid2">
    <div class="panel">
      <h3>When things went wrong</h3>
      <p class="muted small" style="margin:4px 0 10px">Unusual tasks per ${o.bin_minutes} minutes. Click a bar to see those alerts.</p>
      <div id="tl"></div>
      <div class="legend"><span><i style="background:var(--flare)"></i>Look at this first (both detectors agree)</span><span><i style="background:var(--brass)"></i>Worth checking (one detector)</span></div>
    </div>
    <div class="panel">
      <h3>What kind of problems</h3>
      <p class="muted small" style="margin:4px 0 0">Grouped by the oddest thing in each task. Click one to filter.</p>
      <ul class="kinds">${o.kinds.slice(0, 8).map((k) => `<li><button data-kind="${esc(k.kind)}"><span class="row"><span>${esc(k.kind)}</span><b>${k.n}</b></span>
        <span class="bar"><span style="width:${(k.n / o.kinds[0].n) * 100}%"></span></span></button></li>`).join("")}</ul>
    </div>
  </section>

  <section class="panel" style="margin-top:22px">
    <div class="review-meter">
      <div><h3>Your review</h3><p class="muted small" style="margin:2px 0 0">You've marked ${reviewed} of ${o.n_alerts} alerts. Your answers are saved, so they can later be used to retrain the detectors.</p></div>
      <div class="bar"><span style="width:${(reviewed / Math.max(o.n_alerts, 1)) * 100}%;background:var(--moss)"></span></div>
      <a class="btn small" href="#/alerts">${reviewed ? "Continue reviewing" : "Start reviewing"}</a>
    </div>
  </section>`;

  drawTimeline($("#tl"), o.timeline, o.bin_minutes);
  $$(".kinds button").forEach((b) => b.addEventListener("click", () => { resetFilter(); S.filter.kind = b.dataset.kind; location.hash = "#/alerts"; }));
  requestAnimationFrame(() => $("#river").classList.add("play"));
}

function drawTimeline(box, data, bin) {
  const W = Math.max(box.clientWidth, 300), H = 200, pad = { l: 40, r: 6, t: 8, b: 30 };
  const max = Math.max(1, ...data.map((d) => d.first + d.check));
  const bw = (W - pad.l - pad.r) / data.length;
  const y = (v) => pad.t + (H - pad.t - pad.b) * (1 - v / max);
  const ticks = [0, Math.ceil(max / 2), max];
  let svg = `<svg class="tl" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Unusual tasks over time">`;
  ticks.forEach((t) => { svg += `<line x1="${pad.l}" x2="${W - pad.r}" y1="${y(t)}" y2="${y(t)}" stroke="#e4e9ef"/><text x="${pad.l - 8}" y="${y(t) + 4}" font-size="11" fill="#5b6b7f" text-anchor="end">${t}</text>`; });
  const every = Math.ceil(data.length / 7);
  data.forEach((d, i) => {
    const x = pad.l + i * bw + 1.5, w = Math.max(bw - 3, 2);
    const tip = `${when(d.t)}: ${d.first} to look at first, ${d.check} worth checking`;
    if (d.first) svg += `<rect data-i="${i}" x="${x}" y="${y(d.first)}" width="${w}" height="${y(0) - y(d.first)}" rx="2" fill="#c43d2b" data-tip="${esc(tip)}"/>`;
    if (d.check) svg += `<rect data-i="${i}" x="${x}" y="${y(d.first + d.check)}" width="${w}" height="${y(d.first) - y(d.first + d.check)}" rx="2" fill="#c9a227" data-tip="${esc(tip)}"/>`;
    if (!d.first && !d.check) svg += `<rect data-i="${i}" x="${x}" y="${pad.t}" width="${w}" height="${y(0) - pad.t}" fill="transparent" data-tip="${esc(tip)}"/>`;
    if (i % every === 0) {
      const t = new Date(d.t);
      svg += `<text x="${x + w / 2}" y="${H - 10}" font-size="11" fill="#5b6b7f" text-anchor="middle">${t.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}</text>`;
    }
  });
  box.innerHTML = svg + "</svg>";
  $$("rect", box).forEach((r) => {
    r.addEventListener("mousemove", (e) => showTip(e, r.dataset.tip));
    r.addEventListener("mouseleave", hideTip);
    r.addEventListener("click", () => {
      const d = data[+r.dataset.i];
      resetFilter();
      S.filter.from = d.t;
      S.filter.to = new Date(new Date(d.t).getTime() + bin * 60000).toISOString().slice(0, 19);
      location.hash = "#/alerts";
    });
  });
}
function showTip(e, text) { const t = $("#tip"); t.textContent = text; t.style.display = "block"; t.style.left = e.clientX + 14 + "px"; t.style.top = e.clientY + 14 + "px"; }
function hideTip() { $("#tip").style.display = "none"; }

/* ---------- 2. alerts ---------- */
function resetFilter() { S.filter = { pri: "all", q: "", kind: null, from: null, to: null, todo: false }; }

function filtered() {
  const f = S.filter, q = f.q.toLowerCase();
  return S.alerts.filter((a) =>
    (f.pri === "all" || a.priority === f.pri) && (!f.todo || !a.review) && (!f.kind || a.kind === f.kind) &&
    (!f.from || (a.time >= f.from && a.time < f.to)) && (!q || a.headline.toLowerCase().includes(q) || a.id.includes(q)));
}

async function viewAlerts(view, id) {
  S.alerts = await api("/api/alerts");
  if (!S.overview) S.overview = await api("/api/overview");
  if (!S.alerts.length) { view.innerHTML = `${demoNote()}<div class="empty"><h2>Nothing unusual found</h2><p>Every task followed the usual routine.</p></div>`; return; }
  view.innerHTML = `${demoNote()}
  <div class="inbox">
    <aside class="inbox-list" aria-label="Alerts">
      <div class="filters">
        <input type="search" id="q" placeholder="Search alerts" aria-label="Search alerts" value="${esc(S.filter.q)}">
        <div class="fchips" role="group" aria-label="Filter">
          <button data-pri="all">All</button><button data-pri="first">Look at first</button><button data-pri="check">Worth checking</button>
          <button data-todo="1">Not reviewed</button>
        </div>
        <div class="kind-filter" id="kf" hidden></div>
      </div>
      <div class="count-line" id="countLine"></div>
      <div class="items" id="items"></div>
    </aside>
    <section class="detail" id="detail" aria-live="polite"></section>
  </div>`;
  $("#q").addEventListener("input", (e) => { S.filter.q = e.target.value; renderList(); });
  $$(".fchips [data-pri]").forEach((b) => b.addEventListener("click", () => { S.filter.pri = b.dataset.pri; renderList(); }));
  $(".fchips [data-todo]").addEventListener("click", () => { S.filter.todo = !S.filter.todo; renderList(); });
  renderList();
  const list = filtered();
  openAlert(id && S.alerts.some((a) => a.id === id) ? id : (list[0] || S.alerts[0]).id, false);
}

function renderList() {
  const f = S.filter, list = filtered();
  $$(".fchips [data-pri]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.pri === f.pri));
  $(".fchips [data-todo]").setAttribute("aria-pressed", f.todo);
  const kf = $("#kf");
  const tags = [];
  if (f.kind) tags.push(`Showing: ${esc(f.kind)}`);
  if (f.from) tags.push(`Showing: ${esc(when(f.from))} to ${esc(new Date(f.to).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }))}`);
  kf.hidden = !tags.length;
  kf.innerHTML = tags.join(" ") + ` <button id="clearKf">Clear</button>`;
  if (tags.length) $("#clearKf").addEventListener("click", () => { f.kind = null; f.from = f.to = null; renderList(); });
  const done = S.alerts.filter((a) => a.review).length;
  const total = S.overview ? S.overview.n_alerts : S.alerts.length;
  $("#countLine").textContent = (total > S.alerts.length
    ? `The ${fmt(S.alerts.length)} most urgent of ${fmt(total)} alerts. `
    : "") + `${fmt(list.length)} shown, ${fmt(done)} reviewed`;
  const lab = { real: "Real problem", false: "False alarm", unsure: "Not sure" };
  $("#items").innerHTML = list.slice(0, 600).map((a) => `
    <button class="item ${a.priority}" data-id="${esc(a.id)}" aria-current="${a.id === S.cur}">
      <b>${esc(a.headline)}</b>
      ${track(a.track, true, "routine of this task")}
      <span class="meta"><span>${esc(a.when)}</span>${a.review ? `<span class="done">${lab[a.review]}</span>` : `<span>${a.priority === "first" ? "Look at first" : "Worth checking"}</span>`}</span>
    </button>`).join("") || `<div class="empty" style="margin:14px">No alerts match. Clear a filter to see more.</div>`;
  $$("#items .item").forEach((b) => b.addEventListener("click", () => openAlert(b.dataset.id)));
}

async function openAlert(id, scroll = true) {
  S.cur = id;
  history.replaceState(null, "", `#/alerts/${encodeURIComponent(id)}`);
  $$("#items .item").forEach((b) => b.setAttribute("aria-current", b.dataset.id === id));
  const d = await api(`/api/alerts/${encodeURIComponent(id)}`);
  const both = d.detectors.length === 2;
  const lab = { real: "Real problem", false: "False alarm", unsure: "Not sure" };
  const steps = d.steps.map((s) => {
    if (s.status === "ok") return `<li class="ok"><span class="mk">✓</span><span>${esc(s.text)}</span><span class="cnt">${s.here}×</span></li>`;
    if (s.status === "missing") return `<li class="missing"><span class="mk">✗</span><span>Never happened: ${esc(s.text.toLowerCase())}</span><span class="cnt">0 of ${s.normal}</span></li>`;
    return `<li class="different"><span class="mk">!</span><span>${esc(s.text)}</span><span class="cnt">${s.here}×, usually ${s.normal}×</span></li>`;
  }).join("") + d.unusual.map((u) => `<li class="extra"><span class="mk">!</span><span>${esc(u.text)} <span class="muted">(${u.share === 0 ? "never seen in normal tasks" : `in ${(u.share * 100).toFixed(1)}% of normal tasks`})</span></span><span class="cnt">${u.times}×</span></li>`).join("");

  $("#detail").innerHTML = `
    <div class="detail-head">
      <div class="verdict" style="gap:8px">
        <span class="chip ${d.priority}">${d.priority === "first" ? "Look at this first" : "Worth checking"}</span>
        <span class="muted small">${both ? "Both detectors flagged it" : `Flagged by ${esc(detName(d.detectors[0]))} only`}</span>
        ${d.detectors.map((m) => techChip(m)).join(" ")}
      </div>
      <h2>${esc(d.headline)}</h2>
      <span class="muted small">Started ${esc(d.when)}, ${d.lines.length} log lines</span>
    </div>

    <div class="panel">
      <h3>The usual routine against this task</h3>
      <div class="tracks" style="margin-top:14px">
        <span class="lbl">Usually</span>${track(d.normal_track, false, "the usual routine")}
        <span class="lbl">This task</span>${track(d.track, false, "this task's routine")}
      </div>
      <ul class="steps-list">${steps}</ul>
    </div>

    <div class="panel">
      <h3>Is it a real problem?</h3>
      <p class="muted small" style="margin:4px 0 12px">Your answer is saved on this computer. Keys: <span class="kbd">1</span> <span class="kbd">2</span> <span class="kbd">3</span> to answer, <span class="kbd">J</span> <span class="kbd">K</span> for next and previous.</p>
      <div class="verdict">
        ${["real", "false", "unsure"].map((v) => `<button data-v="${v}" aria-pressed="${d.review === v}">${lab[v]}</button>`).join("")}
        <button class="btn small ghost" id="nextBtn" type="button" style="margin-left:auto">Next alert</button>
      </div>
      ${d.answer ? `<p class="small muted" style="margin:12px 0 0">Answer key in the demo data: <b>${d.answer === "Anomaly" ? "a real problem" : "normal"}</b></p>` : ""}
    </div>

    <div class="panel">
      <h3>What a person could check next</h3>
      <ul class="next-list">${d.next.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>
      <p class="muted small" style="margin:8px 0 0">Suggestions to start with. The monitor points at the problem; it does not know the cause for sure.</p>
    </div>

    <div class="logview">
      <div class="logview-head"><h3>The evidence: this task's log lines</h3>
        <div class="seg" role="group" aria-label="Show lines as"><button data-show="plain" aria-pressed="true">Plain words</button><button data-show="raw" aria-pressed="false">Original lines</button></div></div>
      <div class="logrows" id="logrows"></div>
    </div>

    <details class="tech-box">
      <summary>How sure were the detectors?</summary>
      <div class="gauges">${d.scores.map((s) => gauge(s)).join("")}</div>
    </details>`;

  const showLines = (mode) => {
    $$("[data-show]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.show === mode));
    $("#logrows").innerHTML = d.lines.map((l) => `<div class="logrow ${mode === "raw" ? "raw" : ""} ${l.unusual ? "hot" : ""}">
      <time>${esc(l.time)}</time><span>${l.unusual && mode !== "raw" ? "! " : ""}${esc(mode === "raw" ? l.raw : l.plain)}</span></div>`).join("");
  };
  showLines("plain");
  $$("[data-show]").forEach((b) => b.addEventListener("click", () => showLines(b.dataset.show)));
  $$(".verdict [data-v]").forEach((b) => b.addEventListener("click", () => review(d.id, b.dataset.v === d.review ? null : b.dataset.v)));
  $("#nextBtn").addEventListener("click", () => step(1));
  if (scroll && window.innerWidth < 860) $("#detail").scrollIntoView({ behavior: "smooth" });
}

function gauge(s) {
  const max = Math.max(1, s.score, s.threshold) * 1.1;
  const over = s.score >= s.threshold;
  return `<div class="gauge">
    <div class="row"><span><b>${esc(detName(s.model))}</b> ${techChip(s.model)}</span><span>${over ? "Flagged" : "Not flagged"}</span></div>
    <div class="g"><span class="${over ? "over" : ""}" style="width:${(s.score / max) * 100}%"></span><i style="left:${(s.threshold / max) * 100}%" title="alert line"></i></div>
    <span class="muted small">Score ${s.score.toFixed(2)}. It raises an alert at ${s.threshold.toFixed(2)} or more (the black line).</span>
  </div>`;
}

async function review(id, verdict) {
  await post("/api/feedback", { block_id: id, verdict });
  const a = S.alerts.find((x) => x.id === id);
  if (a) a.review = verdict;
  renderList();
  await openAlert(id, false);
}

function step(dir) {
  const list = filtered();
  const i = list.findIndex((a) => a.id === S.cur);
  const next = list[Math.min(Math.max(i + dir, 0), list.length - 1)];
  if (next) { openAlert(next.id, false); const el = $(`#items [data-id="${CSS.escape(next.id)}"]`); if (el) el.scrollIntoView({ block: "nearest" }); }
}

document.addEventListener("keydown", (e) => {
  if (!location.hash.startsWith("#/alerts") || e.target.matches("input, textarea") || e.metaKey || e.ctrlKey || e.altKey) return;
  const k = e.key.toLowerCase();
  if (k === "j") step(1);
  else if (k === "k") step(-1);
  else if (["1", "2", "3"].includes(k) && S.cur) review(S.cur, ["real", "false", "unsure"][+k - 1]);
});

/* ---------- 3. live ---------- */
async function viewLive(view) {
  const o = S.overview || (S.overview = await api("/api/overview"));
  view.innerHTML = `${demoNote()}
  <h1 style="font-size:36px">Replay the research log live</h1>
  <p class="lead" style="margin-top:10px">This replays the newer part of the log as if the lines were arriving right now. The detectors learned only from the older part, the ${fmt(o.n_train)} tasks before ${esc(when(o.test_start))}, so everything you see here is new to them.</p>
  <p class="muted small">Each line is sorted the moment it arrives. When a task has been quiet for ${o.live_wait_min === 1 ? "a minute" : `${o.live_wait_min} minutes`} of log time, the detectors check it and either let it pass or raise an alert.${o.live_wait_min > 1 ? " Real storage tasks can send their last messages several minutes late, so the monitor waits before judging." : ""} ${techChip("Server-sent events")} ${techChip("Drain3 match")} ${techChip("saved scikit-learn models")}</p>
  <div class="live-bar">
    <button class="btn primary" id="liveGo">Start</button>
    <button class="btn" id="livePause" disabled>Pause</button>
    <div class="seg" role="group" aria-label="Replay speed">
      <button data-speed="10">10× speed</button><button data-speed="60" aria-pressed="true">60×</button><button data-speed="300">300×</button>
    </div>
    <span class="clock" id="clock" aria-live="off">Log time: not started</span>
  </div>
  <div class="live-grid">
    <div class="river live-river" aria-label="Incoming log lines">
      <div class="river-head"><span>Incoming lines</span><span id="rate"></span></div>
      <div class="river-lines" id="liveLines"></div>
    </div>
    <div>
      <div class="counters">
        <div class="counter"><b id="cLines">0</b><span>lines read</span></div>
        <div class="counter"><b id="cTasks">0</b><span>tasks checked</span></div>
        <div class="counter"><b id="cAlerts" style="color:var(--flare)">0</b><span>alerts raised</span></div>
      </div>
      <div class="feed" id="feed"><div class="empty">Alerts will appear here as the detectors raise them.</div></div>
    </div>
  </div>`;
  let speed = 60;
  $$("[data-speed]").forEach((b) => b.addEventListener("click", async () => {
    speed = +b.dataset.speed;
    $$("[data-speed]").forEach((x) => x.setAttribute("aria-pressed", x === b));
    if (S.live) await post("/api/live/control", { sid: S.live.sid, speed });
  }));
  $("#liveGo").addEventListener("click", () => (S.live ? stopLive(true) : startLive(speed)));
  $("#livePause").addEventListener("click", async () => {
    if (!S.live) return;
    S.live.paused = !S.live.paused;
    await post("/api/live/control", { sid: S.live.sid, paused: S.live.paused });
    $("#livePause").textContent = S.live.paused ? "Resume" : "Pause";
  });
}

async function startLive(speed) {
  const { sid } = await post(`/api/live/start?speed=${speed}`);
  const es = new EventSource(`/api/live/stream?sid=${sid}`);
  S.live = { sid, es, paused: false, shown: 0 };
  $("#liveGo").textContent = "Stop";
  $("#livePause").disabled = false;
  $("#liveLines").innerHTML = "";
  $("#feed").innerHTML = "";
  let last = performance.now(), lastLines = 0;
  es.addEventListener("batch", (msg) => {
    const { events, stats, clock } = JSON.parse(msg.data);
    const box = $("#liveLines");
    if (!box) return;
    const frag = document.createDocumentFragment();
    const shown = events.filter((e) => e.type === "line").slice(-40);
    for (const ev of events) {
      if (ev.type === "line" && !shown.includes(ev)) continue;
      const div = document.createElement("div");
      if (ev.type === "line") {
        div.className = "ln" + (ev.problem ? " problem" : "");
        div.textContent = ev.raw;
      } else if (ev.flagged) {
        div.className = "ln problem";
        div.textContent = `⚑ Task finished and flagged: ${ev.headline}`;
        addFeed(ev);
      } else {
        continue;
      }
      frag.appendChild(div);
    }
    box.appendChild(frag);
    while (box.children.length > 70) box.firstChild.remove();
    $("#cLines").textContent = fmt(stats.lines);
    $("#cTasks").textContent = fmt(stats.tasks);
    $("#cAlerts").textContent = fmt(stats.alerts);
    if (clock) $("#clock").textContent = "Log time: " + clockTime(clock);
    const now = performance.now();
    if (now - last > 1000) { $("#rate").textContent = `${fmt(Math.round(((stats.lines - lastLines) * 1000) / (now - last)))} lines a second`; last = now; lastLines = stats.lines; }
  });
  es.addEventListener("done", (msg) => {
    const s = JSON.parse(msg.data);
    $("#clock").textContent = `Finished: ${fmt(s.tasks)} tasks checked, ${fmt(s.alerts)} alerts`;
    stopLive(false);
  });
  es.onerror = () => { if (S.live && S.live.es === es) stopLive(false); };
}

function addFeed(ev) {
  const feed = $("#feed");
  const pri = ev.priority === "first";
  const card = document.createElement("a");
  card.className = `card new ${pri ? "first" : ""}`;
  card.href = `#/alerts/${encodeURIComponent(ev.block)}`;
  card.style.textDecoration = "none";
  card.innerHTML = `<span class="chip ${pri ? "first" : "check"}" style="justify-self:start">${pri ? "Look at this first" : "Worth checking"}</span>
    <b>${esc(ev.headline)}</b><small>${esc(clockTime(ev.time))}, flagged by ${esc(ev.detectors.map(detName).join(" and "))}</small>`;
  feed.prepend(card);
  while (feed.children.length > 40) feed.lastChild.remove();
}

function stopLive(userStopped) {
  if (!S.live) return;
  const { sid, es } = S.live;
  S.live = null;
  es.close();
  post("/api/live/control", { sid, stop: true }).catch(() => {});
  const go = $("#liveGo");
  if (go) { go.textContent = "Start again"; $("#livePause").disabled = true; $("#livePause").textContent = "Pause"; }
  if (userStopped && $("#clock")) $("#clock").textContent = "Stopped";
}

/* ---------- 4. accuracy ---------- */
async function viewAccuracy(view) {
  const a = await api("/api/accuracy");
  if (!a.labelled) {
    view.innerHTML = `<h1 style="font-size:36px">How often it's right</h1><div class="empty" style="margin-top:20px">
      <h3>This needs an answer key</h3><p>An answer key is a file that says which tasks really were problems. This check ran without one, so the monitor can raise alerts but can't measure itself. HDFS_v1 comes with one: anomaly_label.csv.</p>
      <button class="btn primary" onclick="openRun()">Check a log file with an answer key</button></div>`;
    return;
  }
  const d0 = a.detectors[0];
  view.innerHTML = `${demoNote()}
  <h1 style="font-size:36px">How often it's right</h1>
  <p class="lead" style="margin-top:10px">To be fair, the detectors learned from the older ${fmt(d0.n_train)} tasks and were then tested on the newer ${fmt(d0.n_test)}, the way a real monitor learns from yesterday and faces tomorrow. ${a.demo ? "On these easy made-up logs the numbers are high; real logs will be harder." : "These are real results on the HDFS_v1 dataset, checked against its official answer key."}</p>
  <div class="acc" style="margin-top:24px">
    ${a.detectors.map((d) => `
      <div class="panel">
        <div><h2>${esc(detName(d.model))}</h2><p class="muted small" style="margin:4px 0 0">${esc(DET[d.model] ? DET[d.model].plain : "")} ${techChip(d.model)}</p></div>
        <div><div class="big">${d.caught} of ${d.real}</div><span class="muted">real problems caught</span></div>
        <div class="dots" role="img" aria-label="${d.caught} caught, ${d.real - d.caught} missed, ${d.false_alarms} false alarms">
          ${"<i></i>".repeat(d.dot_caught)}${"<i class='missed'></i>".repeat(d.dot_missed)}${"<i class='fa'></i>".repeat(d.dot_false)}
        </div>
        <div class="legend" style="margin:0"><span><i style="background:var(--moss);border-radius:50%"></i>caught</span><span><i style="border:2px solid var(--flare);border-radius:50%"></i>missed</span><span><i style="background:var(--brass);width:3px"></i>false alarm</span>${d.unit > 1 ? `<span>Each mark stands for about ${d.unit} tasks.</span>` : ""}</div>
        <p style="margin:0">It raised <b>${d.raised}</b> alerts in this period, and <b>${d.false_alarms}</b> ${d.false_alarms === 1 ? "was a false alarm" : "were false alarms"}.</p>
        <table class="tech-table tech-only">
          <tr><td>Precision (alerts that were real)</td><td>${(d.precision ?? 0).toFixed(3)}</td></tr>
          <tr><td>Recall (real problems caught)</td><td>${(d.recall ?? 0).toFixed(3)}</td></tr>
          <tr><td>F1 (balance of the two)</td><td>${(d.f1 ?? 0).toFixed(3)}</td></tr>
          <tr><td>Train tasks (older) / test tasks (newer)</td><td>${fmt(d.n_train)} / ${fmt(d.n_test)}</td></tr>
        </table>
      </div>`).join("")}
  </div>
  <p class="muted small" style="margin-top:18px">Catching more problems usually means more false alarms. That is why each alert shows its evidence: a person can rule out a false alarm in seconds.</p>`;
}

/* ---------- 5. how it works ---------- */
const STAGES = [
  { t: "Read", s: "The raw log lines", tech: "Python" },
  { t: "Sort", s: "Lines become message types", tech: "Drain3" },
  { t: "Count", s: "The task becomes numbers", tech: "pandas" },
  { t: "Check", s: "Two detectors score it", tech: "Isolation Forest, Random Forest" },
  { t: "Explain", s: "A person gets a reason", tech: "SQLite, this dashboard" },
];

async function viewHow(view) {
  const o = S.overview || (S.overview = await api("/api/overview"));
  let which = "flagged", stage = 0;
  view.innerHTML = `
  <h1 style="font-size:36px">How it works</h1>
  <p class="lead" style="margin-top:10px">Follow one storage task through the five stages, from raw text to an alert a person can act on.</p>
  <div class="live-bar" style="margin-bottom:0">
    <span class="muted small">Example:</span>
    <div class="seg" role="group" aria-label="Example task"><button data-ex="flagged" aria-pressed="true">A flagged task</button><button data-ex="normal" aria-pressed="false">A normal task</button></div>
  </div>
  <div class="stages" role="group" aria-label="Stages">${STAGES.map((s, i) => `<button class="stage" data-st="${i}"><span class="n">Stage ${i + 1}</span><b>${s.t}</b><span>${s.s}</span></button>`).join("")}</div>
  <div class="panel stage-body" id="stageBody"></div>
  <div class="actions" style="margin-top:16px"><button class="btn" id="prevSt">Back</button><button class="btn primary" id="nextSt">Next stage</button></div>
  <section class="grid2" style="margin-top:30px">
    <div class="panel"><h3>Built with</h3><p class="muted" style="margin:6px 0 0">Python for the pipeline, Drain3 to sort log lines, scikit-learn for the two detectors, SQLite to store results, and FastAPI with plain HTML, CSS and JavaScript for this dashboard. Everything runs on one laptop, offline.</p></div>
    <div class="panel"><h3>Not built yet</h3><p class="muted" style="margin:6px 0 0">Planned for FYP2: a second research dataset (BGL), a deep sequence model, deeper per-alert explanations (SHAP), and learning from your reviews to improve over time.</p></div>
  </section>`;
  const cache = {};
  const load = async () => {
    const id = which === "flagged" ? o.first_alert : o.normal_example;
    if (!cache[id]) cache[id] = await api(`/api/walkthrough/${encodeURIComponent(id)}`);
    return cache[id];
  };
  const render = async () => {
    $$("[data-st]").forEach((b) => b.setAttribute("aria-pressed", +b.dataset.st === stage));
    $$("[data-ex]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.ex === which));
    $("#prevSt").disabled = stage === 0;
    $("#nextSt").textContent = stage === 4 ? "Start over" : "Next stage";
    const w = await load();
    $("#stageBody").innerHTML = stageHtml(stage, w);
  };
  $$("[data-st]").forEach((b) => b.addEventListener("click", () => { stage = +b.dataset.st; render(); }));
  $$("[data-ex]").forEach((b) => b.addEventListener("click", () => { which = b.dataset.ex; render(); }));
  $("#prevSt").addEventListener("click", () => { stage = Math.max(0, stage - 1); render(); });
  $("#nextSt").addEventListener("click", () => { stage = stage === 4 ? 0 : stage + 1; render(); });
  render();
}

function highlightTemplate(t) {
  return esc(t).replace(/&lt;(BLK|IP|NUM|\*)&gt;/g, (m, k) => `<mark title="${{ BLK: "task id", IP: "computer address", NUM: "number", "*": "anything" }[k]}">${{ BLK: "task id", IP: "address", NUM: "number", "*": "…" }[k]}</mark>`);
}

function stageHtml(i, w) {
  const head = (title, text) => `<div><h3>${title} ${techChip(STAGES[i].tech)}</h3><p class="muted" style="margin:6px 0 0">${text}</p></div>`;
  if (i === 0) return head("The computer writes plain text", `This task produced ${w.raw.length}${w.raw.length === 10 ? "+" : ""} lines. Each has a date, time, importance level, the part of the system that wrote it, and a message. Hard for a person to scan at scale.`) +
    `<div class="rawbox">${w.raw.map(esc).join("\n")}</div>`;
  if (i === 1) return head("Similar lines are grouped into message types", "The parts that change from line to line, like the task id, computer addresses and sizes, are swapped for placeholders. Lines that then look the same are one message type. Thousands of lines become about a dozen types.") +
    `<div class="stack" style="gap:12px">${w.templates.map((t) => `<div><div class="tmpl">${highlightTemplate(t.template)}</div><p class="small" style="margin:6px 0 0"><b>${esc(t.plain)}</b> <span class="muted">appears ${t.n}× in this task</span></p></div>`).join("")}</div>`;
  if (i === 2) {
    const max = Math.max(1, ...w.vector.map((v) => Math.max(v.here, v.normal)));
    return head("The task becomes a row of numbers", "For each message type, count how many times it appears in this task. The grey bar is what a normal task has. The detectors only ever see these numbers.") +
      `<div class="vec">${w.vector.map((v) => `<div class="row"><span>${esc(v.plain)}</span><div class="pair">
        <div class="bar normal"><span style="width:${(v.normal / max) * 100}%"></span></div>
        <div class="bar here ${v.here !== Math.round(v.normal) ? "off" : ""}"><span style="width:${(v.here / max) * 100}%"></span></div>
        <span class="muted small">this task ${v.here}, usually ${v.normal}</span></div></div>`).join("")}</div>`;
  }
  if (i === 3) return head("Two detectors each give a score", "Detector A learned what normal looks like and scores how different this task is. Detector B learned from examples marked normal or problem and scores how likely it is a problem. Past the black line, it raises an alert.") +
    `<div class="gauges">${w.detectors.map(gauge).join("")}</div>`;
  return head("A person gets a reason, not just a score", "The monitor compares the task with the usual routine and writes what is different in plain words, with the lines that prove it.") +
    `<div class="tracks"><span class="lbl">Usually</span>${track(w.normal_track)}<span class="lbl">This task</span>${track(w.track)}</div>
     <div class="panel" style="background:var(--mist);border:0"><b style="color:var(--ink);font-size:20px">${esc(w.headline)}</b>
     ${w.flagged ? `<p style="margin:8px 0 0"><a href="#/alerts/${encodeURIComponent(w.id)}">Open this alert</a></p>` : ""}</div>`;
}

/* ---------- run dialog ---------- */
let runMode = "demo";
function openRun() { $("#runStatus").hidden = true; $("#runDialog").showModal(); }
window.openRun = openRun;
$("#runBtn").addEventListener("click", openRun);
$$("#runForm [data-mode]").forEach((b) => b.addEventListener("click", () => {
  runMode = b.dataset.mode;
  $$("#runForm [data-mode]").forEach((x) => x.setAttribute("aria-pressed", x === b));
  $("#modeDemo").hidden = runMode !== "demo";
  $("#modeSnap").hidden = runMode !== "snapshot";
  $("#modeFile").hidden = runMode !== "file";
}));
$("#runGo").addEventListener("click", async () => {
  const f = $("#runForm"), st = $("#runStatus");
  const body = { mode: runMode };
  if (runMode === "file") {
    body.log = f.log.value.trim().replace(/^"|"$/g, "");
    body.labels = f.labels.value.trim().replace(/^"|"$/g, "") || null;
    body.max_lines = f.max_lines.value ? +f.max_lines.value : null;
    if (!body.log) { st.hidden = false; st.className = "status err"; st.textContent = "Enter the path to the log file."; return; }
  }
  $("#runGo").disabled = true;
  st.hidden = false; st.className = "status"; st.innerHTML = `<span class="spinner"></span>Starting…`;
  try {
    await post("/api/run", body);
    const poll = async () => {
      const r = await api("/api/run/status");
      if (r.state === "running") { st.innerHTML = `<span class="spinner"></span>${esc(r.message)} ${r.elapsed}s`; setTimeout(poll, 1000); return; }
      $("#runGo").disabled = false;
      if (r.state === "error") { st.className = "status err"; st.textContent = r.message; return; }
      st.textContent = "Done. Showing the new results.";
      S.overview = S.alerts = null; S.state = null; resetFilter();
      await loadState();
      setTimeout(() => { $("#runDialog").close(); location.hash = "#/research"; route(); }, 700);
    };
    poll();
  } catch (e) {
    $("#runGo").disabled = false; st.className = "status err"; st.textContent = e.message;
  }
});

/* ---------- start ---------- */
$("#techToggle").addEventListener("change", (e) => setTech(e.target.checked));
try { setTech(localStorage.getItem("tech") === "1"); } catch (e) { setTech(false); }
window.addEventListener("hashchange", route);
let rt; window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => { if (S.overview && $("#tl")) drawTimeline($("#tl"), S.overview.timeline, S.overview.bin_minutes); }, 200); });
window.addEventListener("load", () => { if (window.MON && window.MON.boot) window.MON.boot(); route(); });
window.APP.route = route;
window.APP_GAUGE = gauge;

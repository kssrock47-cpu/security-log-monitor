/* Live monitor screens: radar home, threats inbox, connections, attack lab. Plain JavaScript. */
"use strict";
(() => {
  const { routes, api, post, esc, fmt, techChip, $, $$, showTip, hideTip } = window.APP;
  const M = { state: null, seq: 0, es: null, page: null, timers: [], river: [], riverMode: "plain", alerts: [],
              filter: { sev: "all", status: "open", kind: "all", q: "", entity: null, source: null }, cur: null };
  window.MON = M;

  const SEV = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  const who = (e) => !e ? "" : e.startsWith("user:") ? `user ${e.slice(5)}` : e.startsWith("host:") ? `machine ${e.slice(5)}` : e;
  const clock = (iso) => (iso || "").slice(11, 19);
  const day = (iso) => new Date(iso).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  const every = (fn, ms) => { fn(); M.timers.push(setInterval(fn, ms)); };
  const KIND = {
    upload: ["A file you dropped", "Checked once, as fast as possible"],
    watch: ["A file or folder on this PC", "Followed as new lines are written"],
    url: ["A web address", "Fetched again every few seconds"],
    syslog: ["Devices on your network", "Routers, servers and PCs send logs here"],
    windows: ["This PC's Windows events", "Logons, new accounts, cleared logs"],
    simulator: ["The attack lab", "A pretend network with attacks on request"],
  };
  const ICON = {
    upload: '<svg viewBox="0 0 30 30"><path d="M15 20V6M9 12l6-6 6 6"/><path d="M5 20v4h20v-4"/></svg>',
    watch: '<svg viewBox="0 0 30 30"><path d="M4 9h8l2 3h12v12H4z"/><path d="M11 18l3 3 5-6"/></svg>',
    url: '<svg viewBox="0 0 30 30"><circle cx="15" cy="15" r="10"/><path d="M5 15h20M15 5c3 3 4 6.5 4 10s-1 7-4 10c-3-3-4-6.5-4-10s1-7 4-10z"/></svg>',
    syslog: '<svg viewBox="0 0 30 30"><rect x="11" y="4" width="8" height="6" rx="1"/><rect x="3" y="20" width="8" height="6" rx="1"/><rect x="19" y="20" width="8" height="6" rx="1"/><path d="M15 10v5M7 20v-5h16v5"/></svg>',
    windows: '<svg viewBox="0 0 30 30"><path d="M4 7l9-1.5v8.5H4zM15 5.2L26 3.5V14H15zM4 16h9v8.5L4 23zM15 16h11v10.5L15 24.8z"/></svg>',
    simulator: '<svg viewBox="0 0 30 30"><path d="M11 4h8M12 4v8L5 23a2 2 0 0 0 1.7 3h16.6A2 2 0 0 0 25 23l-7-11V4"/><path d="M8 18h14"/></svg>',
  };

  /* ---------------------------------------------------------------- live stream */
  M.boot = () => {
    const open = () => {
      M.es = new EventSource(`/api/m/stream?since=${M.seq}`);
      M.es.onmessage = (m) => onFeed(JSON.parse(m.data));
      M.es.onopen = () => { if (M.down) { M.down = false; api("/api/m/state").then(applyStats).catch(() => {}); } };
      M.es.onerror = () => {
        M.es.close();
        M.down = true;
        $("#monSource").innerHTML = `<b style="color:var(--flare)">The monitor has stopped.</b> Start it again with run.bat. This page reconnects by itself.`;
        setTimeout(open, 2000);
      };
    };
    open();
    api("/api/m/state").then(applyStats).catch(() => {});
    setupDrop();
    // browsers only allow sound after a click, so the switch itself starts the audio
    $("#soundBtn").addEventListener("click", () => setSound(!SOUND.on, true));
    if (SOUND.on) {
      setSound(true, false);
      const wake = () => { if (SOUND.ctx && SOUND.ctx.state === "suspended") SOUND.ctx.resume(); };
      window.addEventListener("pointerdown", wake, { once: true });
      window.addEventListener("keydown", wake, { once: true });
    }
  };
  M.leave = () => { M.timers.forEach(clearInterval); M.timers = []; M.page = null; hideTip(); };

  function onFeed(d) {
    M.seq = d.seq || M.seq;
    if (d.stats) applyStats(d.stats);
    d.events.forEach((e) => M.river.push(e));
    if (M.river.length > 60) M.river.splice(0, M.river.length - 60);
    if (M.page === "monitor") drawRiver();
    if (d.alerts.length) {
      const top = d.alerts.reduce((m, a) => (RANK[a.severity] > RANK[m] ? a.severity : m), "low");
      playAlert(top);
    }
    d.alerts.forEach((a) => {
      toast(a);
      M.alerts.unshift(a);
      if (M.page === "threats") { M.list = [a, ...(M.list || [])]; renderThreatList(); }
      if (M.page === "monitor") drawThreatCards();
      if (M.page === "lab") pollLab();
    });
    d.notes.forEach((n) => {
      if (n.kind === "source_done") {
        const s = (M.state?.connections || []).find((c) => c.id === n.source);
        note(`Finished checking ${s ? s.name : "the file"}`, "Open Threats to see what was found.", "#/threats");
      } else if (n.kind === "lesson") {
        note(n.label === "real" ? "The AI learned from your answer" : "The AI will be calmer about this",
             n.lessons.join(" "), "#/ai");
        if (M.page === "ai") routes.ai($("#view"));
      } else if (n.kind === "learned") {
        note("The AI has learned what normal looks like", "From now on it flags anything unusual.");
      }
    });
  }

  function applyStats(s) {
    M.state = { ...(M.state || {}), ...s };
    const lv = s.threat.level;
    const pill = $("#railLevel");
    pill.dataset.level = lv; $("span", pill).textContent = lv;
    const badge = $("#threatBadge");
    badge.hidden = !s.open_alerts; badge.textContent = s.open_alerts > 99 ? "99+" : s.open_alerts;
    const live = (s.sources || []).filter((x) => x.alive && x.live).length;
    $("#monSource").innerHTML = `Watching <b>${live}</b> live connection${live === 1 ? "" : "s"}, ${fmt(s.rate)} lines a second`;
    const bar = $("#reviewBar");
    bar.hidden = !s.open_alerts || M.page === "threats";
    $("#reviewText").textContent = `${fmt(s.open_alerts)} threat${s.open_alerts === 1 ? "" : "s"} waiting for you to review`;
    if (M.page === "monitor") updateHome();
  }

  /* ---------------------------------------------------------------- alert sounds (made in the browser, no files) */
  const SOUND = { on: false, ctx: null, last: 0 };
  const RANK = { low: 1, medium: 2, high: 3, critical: 4 };
  try { SOUND.on = localStorage.getItem("sound") === "1"; } catch (e) { /* storage may be blocked */ }

  function tone(freq, start, dur, type = "sine", vol = 0.18, endFreq = null) {
    const c = SOUND.ctx, o = c.createOscillator(), g = c.createGain();
    o.type = type;
    o.frequency.setValueAtTime(freq, c.currentTime + start);
    if (endFreq) o.frequency.linearRampToValueAtTime(endFreq, c.currentTime + start + dur);
    g.gain.setValueAtTime(0.0001, c.currentTime + start);
    g.gain.exponentialRampToValueAtTime(vol, c.currentTime + start + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, c.currentTime + start + dur);
    o.connect(g).connect(c.destination);
    o.start(c.currentTime + start);
    o.stop(c.currentTime + start + dur + 0.05);
  }

  function playAlert(sev) {
    if (!SOUND.on || !SOUND.ctx) return;
    const now = Date.now();
    if (now - SOUND.last < 1500) return;  // a burst of alerts makes one sound, not fifty
    SOUND.last = now;
    if (SOUND.ctx.state === "suspended") SOUND.ctx.resume();
    if (sev === "critical") {          // short alarm: three rising sweeps
      [0, 0.3, 0.6].forEach((t) => tone(600, t, 0.26, "sawtooth", 0.12, 950));
    } else if (sev === "high") {       // double beep
      tone(740, 0, 0.13, "triangle", 0.22); tone(740, 0.2, 0.13, "triangle", 0.22);
    } else {                           // soft chime
      tone(880, 0, 0.5, "sine", 0.16); tone(1320, 0.08, 0.45, "sine", 0.08);
    }
  }

  function setSound(on, announce) {
    SOUND.on = on;
    try { localStorage.setItem("sound", on ? "1" : "0"); } catch (e) { /* ignore */ }
    if (on && !SOUND.ctx) SOUND.ctx = new (window.AudioContext || window.webkitAudioContext)();
    const b = $("#soundBtn");
    b.setAttribute("aria-pressed", on);
    $("span", b).textContent = on ? "Sound on" : "Sound off";
    if (on && announce) { SOUND.last = 0; playAlert("medium"); }
  }
  M.setSound = setSound;

  /* ---------------------------------------------------------------- toasts */
  function toast(a) {
    const t = document.createElement("a");
    t.className = `toast ${a.severity}`;
    t.href = `#/threats/${a.id}`;
    t.innerHTML = `<span class="sev ${a.severity}" style="margin-top:4px"></span><div><b>${esc(a.title)}</b><small>${esc(who(a.entity))}, ${esc(a.source_name || "")}${a.kind === "ai" ? ", spotted by the AI" : ""}</small></div>`;
    pushToast(t);
  }
  function note(title, text, href) {
    const t = document.createElement(href ? "a" : "div");
    t.className = "toast"; t.style.borderLeftColor = "var(--moss)";
    if (href) t.href = href;
    t.innerHTML = `<span class="sev" style="background:var(--moss);margin-top:4px"></span><div><b>${esc(title)}</b><small>${esc(text)}</small></div>`;
    pushToast(t);
  }
  function pushToast(t) {
    const box = $("#toasts");
    box.appendChild(t);
    while (box.children.length > 4) box.firstChild.remove();
    setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 320); }, 6500);
  }

  /* ---------------------------------------------------------------- drag and drop / file pick */
  function setupDrop() {
    const dz = $("#dropzone");
    let depth = 0;
    window.addEventListener("dragenter", (e) => { if ([...e.dataTransfer.types].includes("Files")) { depth++; dz.hidden = false; } });
    window.addEventListener("dragleave", () => { depth = Math.max(0, depth - 1); if (!depth) dz.hidden = true; });
    window.addEventListener("dragover", (e) => e.preventDefault());
    window.addEventListener("drop", (e) => { e.preventDefault(); depth = 0; dz.hidden = true; uploadFiles([...e.dataTransfer.files]); });
    $("#filePick").addEventListener("change", (e) => { uploadFiles([...e.target.files]); e.target.value = ""; });
  }
  async function uploadFiles(files) {
    for (const f of files) {
      note(`Checking ${f.name}`, `${fmt(Math.round(f.size / 1024))} KB. Threats will pop up here as they're found.`);
      try {
        const r = await fetch(`/api/m/upload?name=${encodeURIComponent(f.name)}`, { method: "POST", body: f });
        if (!r.ok) throw new Error((await r.json()).detail);
      } catch (err) { note(`Couldn't check ${f.name}`, err.message); }
    }
    if (M.page === "connect") renderConns();
  }
  M.uploadFiles = uploadFiles;

  /* ================================================================ 1. live monitor (home) */
  routes.monitor = async (view) => {
    M.page = "monitor";
    const s = await api("/api/m/state");
    applyStats(s); M.state = s;
    const first = !s.total && !s.connections.length;
    view.innerHTML = `
    <section class="mon-hero">
      <div class="radar-card">
        <div class="rhead"><span>Who's active, last 15 minutes</span><span id="blipCount"></span></div>
        <svg class="radar" id="radar" viewBox="0 0 400 400" role="img" aria-label="Radar of active addresses and users"></svg>
        <div class="radar-legend"><span><i style="background:#8fd3b4"></i>normal</span><span><i style="background:var(--brass)"></i>worth checking</span><span><i style="background:#ff6b57"></i>threat</span><span>Closer to the middle means more dangerous.</span></div>
      </div>
      <div class="mon-text">
        <span class="muted">Threat level right now</span>
        <div class="level-word" id="levelWord">${esc(s.threat.level)}</div>
        <p class="lead" id="levelText" style="margin:0"></p>
        <div class="livecount">
          <div><b id="cRate">0</b>lines a second</div>
          <div><b id="cTotal">0</b>lines checked</div>
          <div><b id="cOpen" style="color:var(--flare)">0</b>threats to review</div>
          <div><b id="cConn">0</b>live connections</div>
        </div>
        <div class="actions">
          <a class="btn primary" href="#/connect">Connect logs</a>
          <a class="btn" href="#/lab">Try the attack lab</a>
          <a class="btn ghost" href="#/threats">Review threats</a>
        </div>
        <div>${techChip("Drain3 message types")} ${techChip("Isolation Forest per 30-second window")} ${techChip("15 attack patterns, MITRE ATT&CK")}</div>
      </div>
    </section>
    ${first ? `<section class="panel" style="margin-bottom:22px"><h3>Start by connecting some logs</h3>
      <p class="muted" style="margin:6px 0 16px">Drop a log file anywhere on this page, or pick a way to connect. Not sure? Open the attack lab: it makes a pretend network you can attack.</p>
      ${tilesHtml()}</section>` : ""}
    <section class="mon-grid">
      <div class="stack">
        <div class="panel"><h3>Activity, last 10 minutes</h3><p class="muted small" style="margin:2px 0 8px">Grey bars are log lines every 10 seconds. Red marks are threats.</p><div id="act"></div></div>
        <div class="mini-river"><div class="head"><span>Incoming lines</span><span class="mode-switch"><button data-rm="plain">Plain words</button><button data-rm="raw">Original</button></span></div><div class="lines" id="river"></div></div>
      </div>
      <div class="panel"><h3>Latest threats</h3><div class="threat-cards" id="tcards" style="margin-top:12px"></div></div>
    </section>`;
    wireTiles(view);
    $$("[data-rm]").forEach((b) => b.addEventListener("click", () => { M.riverMode = b.dataset.rm; drawRiver(); }));
    M.alerts = await api("/api/m/alerts?limit=8");
    drawThreatCards(); drawRiver(); updateHome();
    every(drawRadar, 3000);
  };

  function updateHome() {
    const s = M.state; if (!s || !$("#levelWord")) return;
    const w = $("#levelWord");
    if (w.textContent !== s.threat.level) { w.textContent = s.threat.level; w.classList.remove("pulse"); void w.offsetWidth; w.classList.add("pulse"); }
    w.dataset.level = s.threat.level;
    const c = s.threat.counts || {};
    const n = Object.values(c).reduce((a, b) => a + b, 0);
    $("#levelText").textContent = n
      ? `${n} threat${n === 1 ? "" : "s"} in the last 10 minutes${c.critical ? `, ${c.critical} critical` : ""}. Open them to see what happened and what to do.`
      : (s.total ? "Nothing worrying in the last 10 minutes. The monitor keeps watching." : "Connect some logs to start watching.");
    $("#cRate").textContent = fmt(s.rate);
    $("#cTotal").textContent = fmt(s.total);
    $("#cOpen").textContent = fmt(s.open_alerts);
    $("#cConn").textContent = (s.sources || []).filter((x) => x.alive && x.live).length;
    drawActivity(s.buckets || []);
  }

  function drawActivity(b) {
    const box = $("#act"); if (!box) return;
    const W = Math.max(box.clientWidth, 280), H = 150, n = 60;
    const now = Math.floor(Date.now() / 10000) * 10;
    const map = Object.fromEntries(b.map((x) => [x.t, x]));
    const data = Array.from({ length: n }, (_, i) => map[now - (n - 1 - i) * 10] || { events: 0, alerts: 0 });
    // scale to typical activity, so one burst (like a dropped file) doesn't flatten everything else
    const nz = data.map((d) => d.events).filter((v) => v > 0).sort((a, b) => a - b);
    const typical = nz.length ? nz[Math.floor(nz.length * 0.5)] : 5;
    const max = Math.max(5, Math.min(nz[nz.length - 1] || 5, typical * 3));
    const bw = W / n;
    let svg = `<svg class="act" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}">`;
    data.forEach((d, i) => {
      const h = (Math.min(d.events, max) / max) * (H - 26);
      svg += `<rect x="${i * bw + 1}" y="${H - 18 - h}" width="${Math.max(bw - 2, 1)}" height="${h}" rx="1.5" fill="#c3cfdc"/>`;
      if (d.alerts) svg += `<circle cx="${i * bw + bw / 2}" cy="${Math.max(H - 26 - h, 8)}" r="${Math.min(3 + d.alerts, 8)}" fill="#c43d2b"/>`;
    });
    svg += `<text x="0" y="${H - 3}" font-size="11" fill="#5b6b7f">10 minutes ago</text><text x="${W}" y="${H - 3}" font-size="11" fill="#5b6b7f" text-anchor="end">now</text></svg>`;
    box.innerHTML = svg;
  }

  function drawRiver() {
    const box = $("#river"); if (!box) return;
    $$("[data-rm]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.rm === M.riverMode));
    box.innerHTML = M.river.slice(-16).map((e) => {
      const cls = e.outcome === "fail" ? "fail" : e.outcome === "success" ? "success" : /warn|err|crit/.test(e.level || "") ? "warn" : "";
      const text = M.riverMode === "plain" && e.plain ? `${clock(e.ts)}  ${who(e.entity)}: ${e.plain}` : e.raw;
      return `<div class="${cls}">${esc(text)}</div>`;
    }).join("") || `<div>Waiting for log lines…</div>`;
  }

  function drawThreatCards() {
    const box = $("#tcards"); if (!box) return;
    box.innerHTML = M.alerts.slice(0, 7).map((a) => `
      <a class="tcard" href="#/threats/${a.id}"><span class="sev ${a.severity}"></span>
        <span><b>${esc(a.title)}</b><small>${esc(who(a.entity))}, ${esc(a.source_name || "")}</small></span>
        <small>${a.kind === "ai" ? '<span class="chip ai">AI</span>' : ""} ${esc(clock(a.created))}</small></a>`).join("")
      || `<div class="empty">No threats yet. When something suspicious happens it shows up here, and pops up in the corner.</div>`;
  }

  function hashAngle(s) { let h = 2166136261; for (const c of s) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return ((h >>> 0) % 3600) / 10; }

  async function drawRadar() {
    const svg = $("#radar"); if (!svg) return;
    const ents = await api("/api/m/entities?minutes=15").catch(() => []);
    if (!$("#radar")) return;
    $("#blipCount").textContent = `${ents.length} active`;
    let g = `<defs><linearGradient id="sw" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#2e8b62" stop-opacity="0"/><stop offset="1" stop-color="#2e8b62" stop-opacity=".45"/></linearGradient></defs>`;
    [50, 100, 150, 190].forEach((r) => (g += `<circle class="ring" cx="200" cy="200" r="${r}"/>`));
    g += `<line class="axis" x1="10" y1="200" x2="390" y2="200"/><line class="axis" x1="200" y1="10" x2="200" y2="390"/>`;
    g += `<g class="sweep"><path d="M200 200 L390 200 A190 190 0 0 0 334.4 65.6 Z" fill="url(#sw)"/></g>`;
    const maxE = Math.max(1, ...ents.map((e) => e.events));
    const labels = [[200, 200]];
    ents.forEach((e, i) => {
      const ang = (hashAngle(e.entity) * Math.PI) / 180;
      const base = { critical: 40, high: 70, medium: 110 }[e.sev] || 140 + 45 * (1 - Math.min(e.events / maxE, 1));
      const r = base + (hashAngle(e.entity + "r") % 20) - 10;
      const x = 200 + r * Math.cos(ang), y = 200 + r * Math.sin(ang);
      const size = 3 + Math.min(6, Math.log2(1 + e.events));
      const cls = e.sev === "critical" || e.sev === "high" ? e.sev : e.sev ? "medium" : "ok";
      if (cls === "high" || cls === "critical") g += `<circle class="halo" cx="${x}" cy="${y}" r="${size + 2}"/>`;
      g += `<circle class="blip ${cls}" cx="${x}" cy="${y}" r="${size}" data-e="${esc(e.entity)}" data-tip="${esc(`${who(e.entity)}: ${fmt(e.events)} lines, ${e.fails} failures, ${e.alerts} threat${e.alerts === 1 ? "" : "s"}`)}"/>`;
      if (e.sev && labels.length < 4 && labels.every(([lx, ly]) => Math.abs(lx - x) > 90 || Math.abs(ly - y) > 16)) {
        labels.push([x, y]);
        g += `<text x="${x + size + 4}" y="${y + 4}">${esc(who(e.entity))}</text>`;
      }
    });
    g += `<circle cx="200" cy="200" r="5" fill="#c9a227"/><text x="208" y="196">your systems</text>`;
    svg.innerHTML = g;
    $$(".blip", svg).forEach((b) => {
      b.addEventListener("mousemove", (ev) => showTip(ev, b.dataset.tip));
      b.addEventListener("mouseleave", hideTip);
      b.addEventListener("click", () => { M.filter = { ...M.filter, entity: b.dataset.e, status: "all", sev: "all" }; location.hash = "#/threats"; });
    });
  }

  /* ================================================================ 2. threats */
  routes.threats = async (view, arg) => {
    M.page = "threats";
    if (arg && arg.startsWith("s:")) { M.filter = { ...M.filter, source: +arg.slice(2), status: "all", entity: null }; arg = null; }
    M.list = await api("/api/m/alerts?limit=1000");
    view.innerHTML = `
    <div class="inbox">
      <aside class="inbox-list" aria-label="Threats">
        <div class="filters">
          <input type="search" id="tq" placeholder="Search threats, addresses, users" value="${esc(M.filter.q)}">
          <div class="fchips" role="group" aria-label="Status">
            <button data-st="open">To review</button><button data-st="all">All</button><button data-st="real">Marked real</button><button data-st="false">False alarms</button>
          </div>
          <div class="fchips" role="group" aria-label="How it was found">
            <button data-k="all">Any way</button><button data-k="pattern">Known attack</button><button data-k="ai">Spotted by AI</button>
          </div>
          <div class="kind-filter" id="tkf" hidden></div>
        </div>
        <div class="count-line" id="tcount"></div>
        <div class="items" id="titems"></div>
      </aside>
      <section class="detail" id="tdetail"></section>
    </div>`;
    $("#tq").addEventListener("input", (e) => { M.filter.q = e.target.value; renderThreatList(); });
    $$("[data-st]").forEach((b) => b.addEventListener("click", () => { M.filter.status = b.dataset.st; renderThreatList(); }));
    $$("[data-k]").forEach((b) => b.addEventListener("click", () => { M.filter.kind = b.dataset.k; renderThreatList(); }));
    renderThreatList();
    const list = threatFiltered();
    const id = arg ? +arg : (list[0] || M.list[0] || {}).id;
    if (id) openThreat(id); else $("#tdetail").innerHTML = `<div class="empty"><h2>No threats</h2><p>Nothing suspicious so far. Try the attack lab to see what a threat looks like.</p><a class="btn primary" href="#/lab">Open the attack lab</a></div>`;
  };

  function threatFiltered() {
    const f = M.filter, q = f.q.toLowerCase();
    return (M.list || []).filter((a) =>
      (f.status === "all" || (f.status === "open" ? a.status === "new" : a.status === f.status)) &&
      (f.kind === "all" || a.kind === f.kind) && (!f.entity || a.entity === f.entity) && (!f.source || a.source === f.source) &&
      (!q || `${a.title} ${a.entity} ${a.detail} ${a.source_name}`.toLowerCase().includes(q)));
  }

  function renderThreatList() {
    const box = $("#titems"); if (!box) return;
    const f = M.filter, list = threatFiltered();
    $$("[data-st]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.st === f.status));
    $$("[data-k]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.k === f.kind));
    const tags = [];
    if (f.entity) tags.push(`Only ${esc(who(f.entity))}`);
    if (f.source) tags.push(`Only connection ${f.source}`);
    $("#tkf").hidden = !tags.length;
    $("#tkf").innerHTML = tags.join(", ") + ` <button id="tclr">Clear</button>`;
    if (tags.length) $("#tclr").addEventListener("click", () => { f.entity = f.source = null; renderThreatList(); });
    $("#tcount").textContent = `${fmt(list.length)} shown of ${fmt((M.list || []).length)}`;
    const lab = { real: "Marked real", false: "False alarm", resolved: "Resolved" };
    box.innerHTML = list.slice(0, 400).map((a) => `
      <button class="item ${a.severity === "critical" || a.severity === "high" ? "first" : ""}" data-id="${a.id}" aria-current="${a.id === M.cur}">
        <b>${esc(a.title)}</b>
        <span class="meta"><span>${esc(who(a.entity))}</span><span>${a.learned ? "Learned, " : a.kind === "ai" ? "AI, " : ""}${SEV[a.severity]}</span></span>
        <span class="meta"><span>${esc(a.source_name || "")}, ${esc(clock(a.created))}${a.count > 1 ? `, ${a.count}×` : ""}</span>${a.status !== "new" ? `<span class="done">${lab[a.status]}</span>` : ""}</span>
      </button>`).join("") || `<div class="empty" style="margin:14px">No threats match. Clear a filter to see more.</div>`;
    $$("#titems .item").forEach((b) => b.addEventListener("click", () => openThreat(+b.dataset.id)));
  }

  async function openThreat(id) {
    M.cur = id;
    history.replaceState(null, "", `#/threats/${id}`);
    $$("#titems .item").forEach((b) => b.setAttribute("aria-current", +b.dataset.id === id));
    const d = await api(`/api/m/alerts/${id}`);
    const ai = d.kind === "ai";
    $("#tdetail").innerHTML = `
      <div class="detail-head">
        <div class="verdict" style="gap:8px">
          <span class="chip sev-${d.severity}">${SEV[d.severity]}</span>
          <span class="chip ${ai ? "ai" : "pattern"}">${ai ? "Spotted by the AI" : "Known attack pattern"}</span>
          ${d.learned ? '<span class="chip learned">Learned from you</span>' : ""}
          ${techChip(d.mitre || "")}
        </div>
        <h2>${esc(d.title)}</h2>
        <div class="facts">
          <div><b>${esc(who(d.entity))}</b>who</div>
          <div><b>${esc(d.source_name || "")}</b>from</div>
          <div><b>${esc(day(d.first_ts))}</b>when, in the log</div>
          <div><b>${d.count}×</b>${d.count > 1 ? "it kept happening" : "seen once"}</div>
        </div>
      </div>
      <div class="panel">
        <h3>What happened</h3>
        <p style="margin:8px 0 0">${esc(d.detail)}</p>
        ${ai ? `<h3 style="margin-top:16px">Why the AI flagged it</h3>
          <p class="muted small" style="margin:4px 0 0">It learned what normal looks like for this connection, then compared this ${d.entity.startsWith("user:") ? "user" : "address"}'s last 30 seconds with that.</p>
          <ul class="why-list">${(d.why || []).map((w) => `<li>${esc(w)}</li>`).join("") || "<li>The overall mix of activity was very different from normal.</li>"}</ul>
          ${d.score != null && d.score >= d.threshold ? `<div class="gauges">${window.APP_GAUGE({ model: "Isolation Forest", score: d.score, threshold: d.threshold })}</div>`
            : `<p class="muted small" style="margin:8px 0 0">Some of these numbers were far beyond anything it saw while learning, which is enough on its own to raise an alert.</p>`}` : ""}
      </div>
      <div class="panel">
        <h3>What to do now</h3>
        <p style="margin:8px 0 0">${esc(d.advice || "")}</p>
        <h3 style="margin-top:18px">Is it a real threat?</h3>
        <p class="muted small" style="margin:4px 0 0">Your answer teaches the AI. Real threats make it more watchful of this kind of behaviour; false alarms make it calmer.</p>
        <div class="actbar" style="margin-top:12px">
          <button data-s="real" aria-pressed="${d.status === "real"}">Real threat</button>
          <button data-s="false" aria-pressed="${d.status === "false"}">False alarm</button>
          <button data-s="resolved" aria-pressed="${d.status === "resolved"}">Dealt with</button>
        </div>
        <div id="learnedBox"></div>
      </div>
      <div class="logview">
        <div class="logview-head"><h3>The evidence: ${d.lines.length} log line${d.lines.length === 1 ? "" : "s"} from ${esc(who(d.entity))}</h3>
          <div class="seg" role="group"><button data-show="plain" aria-pressed="true">Plain words</button><button data-show="raw" aria-pressed="false">Original lines</button></div></div>
        <div class="logrows" id="tlog"></div>
      </div>`;
    const show = (mode) => {
      $$("#tdetail [data-show]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.show === mode));
      $("#tlog").innerHTML = d.lines.map((l) => `<div class="logrow ${mode === "raw" ? "raw" : ""} ${l.bad ? "fail" : ""}"><time>${esc(l.time)}</time><span>${esc(mode === "raw" ? l.raw : l.plain)}</span></div>`).join("")
        || `<div class="logrow"><span>No lines kept for this one.</span></div>`;
    };
    show("plain");
    $$("#tdetail [data-show]").forEach((b) => b.addEventListener("click", () => show(b.dataset.show)));
    $$("#tdetail [data-s]").forEach((b) => b.addEventListener("click", async () => {
      const s = b.dataset.s === d.status ? "new" : b.dataset.s;
      const r = await post(`/api/m/alerts/${id}/status`, { status: s });
      const a = M.list.find((x) => x.id === id); if (a) a.status = s;
      renderThreatList();
      await openThreat(id);
      if (r.lessons && r.lessons.length) {
        $("#learnedBox").innerHTML = `<div class="learned-box"><b>The AI learned from this</b><ul>${r.lessons.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>
          <a href="#/ai" class="small">See everything it has learned</a></div>`;
      }
    }));
  }

  /* ================================================================ 3. connect logs */
  function tilesHtml() {
    const win = M.state && M.state.platform === "Windows";
    return `<div class="tiles">${Object.entries(KIND).map(([k, [t, s]]) => `
      <button class="tile" data-tile="${k}" ${k === "windows" && !win ? 'title="Only on a Windows PC"' : ""}>${ICON[k]}<b>${t}</b><span>${s}</span>
      <span class="when ${k === "upload" ? "off" : ""}">${k === "upload" ? "Offline" : "Online, live"}</span></button>`).join("")}</div>`;
  }
  function wireTiles(root) {
    $$("[data-tile]", root).forEach((b) => b.addEventListener("click", () => {
      const k = b.dataset.tile;
      if (k === "upload") return $("#filePick").click();
      if (k === "simulator") return (location.hash = "#/lab");
      openConn(k);
    }));
  }

  routes.connect = async (view) => {
    M.page = "connect";
    M.state = await api("/api/m/state");
    view.innerHTML = `
    <h1 style="font-size:36px">Connect logs</h1>
    <p class="lead" style="margin-top:10px">Bring in logs from this PC, other machines, websites or files. Offline files are checked once. Online connections are watched live and checked as each line arrives.</p>
    <p class="muted small">Works with Linux and SSH logins, web server logs, firewall logs, Windows events, JSON lines and plain text. Drop a file anywhere on the page.</p>
    <section style="margin:20px 0 14px">${tilesHtml()}</section>
    <p class="small" style="margin:0 0 30px">No logs to hand? Try real ones from the loghub research collection:
      <button class="btn small ghost" data-sample="ssh">SSH server under attack</button>
      <button class="btn small ghost" data-sample="linux">Linux system log</button>
      <button class="btn small ghost" data-sample="apache">Apache web server</button></p>
    <h2>Your connections</h2>
    <div class="conns" id="conns" style="margin-top:14px"></div>`;
    wireTiles(view);
    $$("[data-sample]").forEach((b) => b.addEventListener("click", async () => {
      b.disabled = true;
      await post(`/api/m/sample/${b.dataset.sample}`);
      note(`Checking ${b.textContent.trim()}`, "Threats will pop up as they're found.");
      renderConns();
    }));
    every(renderConns, 2000);
  };

  async function renderConns() {
    const box = $("#conns"); if (!box) return;
    const s = await api("/api/m/state");
    M.state = s;
    if (!$("#conns")) return;
    box.innerHTML = s.connections.map((c) => {
      const st = c.alive ? (c.error ? "error" : "running") : c.done ? "finished" : c.status === "error" ? "error" : "stopped";
      const word = { running: c.live ? "Watching live" : "Checking…", finished: "Finished", error: "Problem", stopped: "Stopped" }[st];
      const where = c.kind === "watch" ? c.config.path : c.kind === "url" ? c.config.url : c.kind === "syslog" ? `port ${c.config.port || 5140}` :
        c.kind === "windows" ? (c.config.channels || ["Security", "System", "Application"]).join(", ") : c.kind === "upload" ? `${fmt(Math.round((c.config.size || 0) / 1024))} KB` : "";
      const learn = c.learning === null ? "" : c.learning ? `<span>AI learning normal <span class="learnbar"><span style="width:${Math.round((c.progress || 0) * 100)}%"></span></span></span>` : "<span>AI trained</span>";
      return `<div class="conn">
        <span class="dot ${st}"></span>
        <div style="min-width:0;display:grid;gap:4px">
          <b>${esc(c.name)}</b>
          <div class="meta"><span>${esc(KIND[c.kind] ? KIND[c.kind][0] : c.kind)}</span><span>${esc(where || "")}</span><span>${word}</span><span>${fmt(c.lines)} lines</span>
            <a href="#/threats/s:${c.id}">${c.alerts} threat${c.alerts === 1 ? "" : "s"}</a>${learn}</div>
          ${c.error ? `<div class="err">${esc(c.error)}</div>` : ""}
          ${c.last_line ? `<div class="last">${esc(c.last_line)}</div>` : ""}
        </div>
        <div class="actions">
          ${c.kind !== "upload" ? (c.alive ? `<button class="btn small" data-act="stop" data-id="${c.id}">Stop</button>` : `<button class="btn small" data-act="start" data-id="${c.id}">Start</button>`) : ""}
          <button class="btn small ghost" data-act="remove" data-id="${c.id}">Remove</button>
        </div></div>`;
    }).join("") || `<div class="empty">No connections yet. Pick one above, or drop a log file on the page.</div>`;
    $$("[data-act]", box).forEach((b) => b.addEventListener("click", async () => {
      await post(`/api/m/sources/${b.dataset.id}/${b.dataset.act}`);
      renderConns();
    }));
  }

  function openConn(kind) {
    const d = $("#connDialog"), f = $("#connForm");
    const ip = (M.state && M.state.lan_ip) || "this-pc";
    const forms = {
      watch: `<h2>Watch a file or folder</h2>
        <p class="muted" style="margin:0">The monitor follows it like a live feed. Point it at a log file, or a folder of .log files.</p>
        <label>Path on this computer<input type="text" name="path" required placeholder="C:\\inetpub\\logs\\LogFiles\\W3SVC1   or   /var/log/auth.log"></label>
        <label>File pattern inside a folder<input type="text" name="pattern" value="*.log"></label>
        <label class="check"><input type="checkbox" name="from_start"> Also read what's already in the file, not just new lines</label>`,
      url: `<h2>Link a web address</h2>
        <p class="muted" style="margin:0">For logs a server publishes over HTTP. New lines are picked up each time it is checked.</p>
        <label>Web address<input type="text" name="url" required placeholder="https://example.com/logs/access.log"></label>
        <label>Check every (seconds)<input type="number" name="every" value="10" min="2"></label>`,
      syslog: `<h2>Receive logs from other devices</h2>
        <p class="muted" style="margin:0">Routers, firewalls, Linux servers and many apps can send their logs over the network (syslog). The monitor listens on this port.</p>
        <label>Port<input type="number" name="port" value="5140" min="1024" max="65535"></label>
        <p class="small" style="margin:0">Then point devices at <b>${esc(ip)}</b> on that port, UDP or TCP. For a Linux server, add this line to <code>/etc/rsyslog.conf</code> and restart rsyslog:</p>
        <div class="codebox">*.* @@${esc(ip)}:5140</div>
        <p class="small" style="margin:0">To send a test message from Linux or WSL:</p>
        <div class="codebox">logger -n ${esc(ip)} -P 5140 -T "Failed password for root from 203.0.113.7 port 22 ssh2"</div>
        <p class="muted small" style="margin:0">If nothing arrives, allow the port in Windows Firewall.</p>`,
      windows: `<h2>This PC's Windows events</h2>
        <p class="muted" style="margin:0">Reads the Windows Event Log every few seconds: logons, failed passwords, new accounts, new services, cleared logs, malware found.</p>
        ${["Security", "System", "Application", "Windows PowerShell", "Microsoft-Windows-Windows Defender/Operational"].map((c, i) =>
          `<label class="check"><input type="checkbox" name="ch" value="${c}" ${i < 3 ? "checked" : ""}> ${c}</label>`).join("")}
        <label>Also read the last (minutes)<input type="number" name="history_minutes" value="60" min="0"></label>
        <p class="muted small" style="margin:0">The Security channel only works when the monitor runs as administrator. Right-click run.bat and choose "Run as administrator".</p>`,
    };
    f.innerHTML = `${forms[kind]}<div class="status err" id="connErr" hidden></div>
      <div class="actions" style="justify-content:flex-end"><button class="btn ghost" value="cancel" formnovalidate>Cancel</button><button class="btn primary" type="button" id="connGo">Connect</button></div>`;
    d.showModal();
    $("#connGo").addEventListener("click", async () => {
      const cfg = {};
      if (kind === "watch") Object.assign(cfg, { path: f.path.value.trim().replace(/^"|"$/g, ""), pattern: f.pattern.value.trim() || "*.log", from_start: f.from_start.checked });
      if (kind === "url") Object.assign(cfg, { url: f.url.value.trim(), every: +f.every.value || 10 });
      if (kind === "syslog") cfg.port = +f.port.value || 5140;
      if (kind === "windows") Object.assign(cfg, { channels: $$('input[name="ch"]:checked', f).map((x) => x.value), history_minutes: +f.history_minutes.value });
      try {
        await post("/api/m/sources", { kind, config: cfg });
        d.close();
        note("Connected", `${KIND[kind][0]} is now being watched.`);
        if (M.page === "connect") renderConns(); else location.hash = "#/connect";
      } catch (e) { const er = $("#connErr"); er.hidden = false; er.textContent = e.message; }
    });
  }

  /* ================================================================ AI learning */
  const WAYS = [
    ["When a connection starts", "Learns what normal looks like", "It watches the first few minutes, or the first part of a file, and learns the usual amounts of logins, pages, errors and message types for each address or user."],
    ["Every few minutes", "Keeps up as things change", "It re-learns normal from recent activity it judged safe, so a busier day or a new app doesn't turn into a flood of alerts."],
    ["Every time you answer", "Learns from you", "Marking a threat real makes it more watchful of that behaviour. Marking a false alarm makes it calmer, and stops that exact alert coming back. Your answers are its reward signal."],
  ];

  routes.ai = async (view) => {
    M.page = "ai";
    const v = await api("/api/m/ai");
    if (M.page !== "ai") return;
    const st = v.stats;
    const label = { real: "Real threat", false: "False alarm" };
    view.innerHTML = `
    <h1 style="font-size:36px">How the AI is learning</h1>
    <p class="lead" style="margin-top:10px">The AI isn't fixed. It learns normal behaviour by itself, keeps re-learning as things change, and gets better from your answers on the Threats page.</p>
    <div class="ways">${WAYS.map(([w, t, d]) => `<div class="panel"><span class="when">${w}</span><h3>${t}</h3><p class="muted small" style="margin:0">${d}</p></div>`).join("")}</div>
    <div class="impact">
      <div><b>${st.real + st.false}</b><span>answers you've given</span></div>
      <div><b>${st.lessons}</b><span>lessons learned</span></div>
      <div><b style="color:var(--moss)">${st.caught}</b><span>times it caught something only because you taught it</span></div>
      <div><b>${st.avoided}</b><span>false alarms it avoided thanks to you</span></div>
      <div><b>${v.connections.reduce((n, c) => n + c.retrains, 0)}</b><span>times it re-learned normal</span></div>
    </div>
    <section class="grid2">
      <div class="panel">
        <h3>How watchful it is right now</h3>
        <p class="muted small" style="margin:4px 0 0">The grey tick is where it started. Your answers move the dot.</p>
        <div class="dials">${v.features.map((f) => {
          const moved = f.watch - f.default;
          return `<div class="dial"><span>${esc(f.name[0].toUpperCase() + f.name.slice(1))}
            ${Math.abs(moved) > 0.01 ? `<br><span class="moved ${moved > 0 ? "up" : "down"}">${moved > 0 ? "More watchful" : "Calmer"}</span>` : ""}
            <span class="tech-only small muted" style="display:block">alert at ${f.ratio}× normal and +${f.margin}</span></span>
            <div><div class="track2"><u style="left:${f.default * 100}%"></u><i style="left:${Math.max(0, Math.min(1, f.watch)) * 100}%"></i></div>
            <div class="ends"><span>Calmer</span><span>More watchful</span></div></div></div>`;
        }).join("")}</div>
        <p class="tech-only small muted" style="margin-top:12px">Overall alert line shift: ${v.thr_shift > 0 ? "+" : ""}${v.thr_shift} (Isolation Forest score)</p>
      </div>
      <div class="stack">
        <div class="panel">
          <h3>What it learned from you</h3>
          <div class="lessons">${v.lessons.map((l) => `<div class="lesson"><span class="chip ${l.label === "real" ? "first" : "ok"}">${label[l.label]}</span>
            <span>${esc(l.text)}</span><a class="small" href="#/threats/${l.alert_id}">the alert</a></div>`).join("")
            || `<div class="empty">Nothing yet. Open a threat and tell it whether it was real. <a href="#/threats">Go to threats</a></div>`}</div>
        </div>
        <div class="panel">
          <h3>Caught because you taught it</h3>
          <div class="threat-cards" style="margin-top:12px">${v.learned_alerts.map((a) => `<a class="tcard" href="#/threats/${a.id}"><span class="sev ${a.severity}"></span>
            <span><b>${esc(a.title)}</b><small>${esc(who(a.entity))}, ${esc(a.source_name || "")}</small></span><small>${esc(clock(a.created))}</small></a>`).join("")
            || `<div class="empty">Try it in the attack lab: launch Sneaky data theft (it gets through), mark a Quiet data theft alert as real, then launch Sneaky data theft again.</div>`}</div>
        </div>
      </div>
    </section>
    <section class="panel" style="margin-top:22px">
      <h3>The AI on each connection</h3>
      <div class="lessons">${v.connections.map((c) => `<div class="lesson"><span class="dot ${c.alive ? "running" : ""}" style="width:10px;height:10px;border-radius:50%;background:${c.alive ? "var(--moss)" : "#b9c6d4"}"></span>
        <span><b>${esc(c.name)}</b>: ${c.learning ? `learning normal, ${Math.round(c.progress * 100)}% done` : `learned from ${fmt(c.trained_on)} windows of activity, re-learned ${c.retrains} time${c.retrains === 1 ? "" : "s"}`}
        <span class="tech-only small muted">alert line ${c.threshold ?? "–"}</span></span><span></span></div>`).join("") || `<div class="empty">No connections yet.</div>`}</div>
      ${v.muted.length ? `<h3 style="margin-top:18px">Alerts you said were false alarms</h3><p class="muted small" style="margin:4px 0 0">These won't be raised again for the same address.</p>
        <ul class="next-list">${v.muted.map(([r, e]) => `<li>${esc(r.replace("_", " "))} from ${esc(who(e))}</li>`).join("")}</ul>` : ""}
      <div class="actions" style="margin-top:18px"><button class="btn small ghost" id="forget">Make it forget everything it learned from you</button></div>
    </section>`;
    const f = $("#forget");
    f.addEventListener("click", async () => {
      if (f.dataset.sure !== "1") { f.dataset.sure = "1"; f.textContent = "Click again to forget all lessons"; return; }
      await post("/api/m/ai/reset");
      note("The AI forgot its lessons", "It's back to how it started. What it learned about normal activity stays.");
      routes.ai(view);
    });
  };

  /* ================================================================ 4. attack lab */
  const ATK_ICON = { brute_force: "🔑", break_in: "🚪", password_spray: "🌧️", sql_injection: "💉", web_scan: "🔦", port_scan: "📡", new_admin: "👤", data_theft: "📦" };

  routes.lab = async (view) => {
    M.page = "lab";
    const lab = await api("/api/m/lab");
    if (!lab.running) {
      view.innerHTML = `
      <h1 style="font-size:36px">Attack lab</h1>
      <p class="lead" style="margin-top:10px">A pretend company network: a website with visitors, staff logging in, a firewall. Launch real-looking attacks against it and watch how fast the monitor catches each one.</p>
      <p class="muted">Everything here is made up and stays on this computer. The lab first writes 20 minutes of normal activity so the AI can learn what normal looks like.</p>
      <button class="btn primary" id="labGo" style="margin-top:10px">Start the attack lab</button>`;
      $("#labGo").addEventListener("click", async () => {
        $("#labGo").disabled = true; $("#labGo").innerHTML = `<span class="spinner"></span>Building the network and teaching the AI…`;
        await post("/api/m/lab/start");
        for (let i = 0; i < 60; i++) { await new Promise((r) => setTimeout(r, 700)); const l = await api("/api/m/lab"); if (l.ready) break; }
        routes.lab(view);
      });
      return;
    }
    view.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:end;gap:16px;flex-wrap:wrap">
      <div><h1 style="font-size:36px">Attack lab</h1>
      <p class="lead" style="margin:10px 0 0">Pick an attack and launch it. The monitor doesn't know it's coming.</p></div>
      <button class="btn ghost small" id="labStop">Stop the lab</button>
    </div>
    <div class="score" id="score"></div>
    <div class="attacks">${lab.catalog.map((c) => `
      <div class="attack" data-kind="${c.kind}">
        ${c.kind === "data_theft" ? '<span class="chip ai ai-tag">Only the AI can catch this</span>' : ""}
        ${c.kind === "sneaky_theft" ? '<span class="chip learned ai-tag">Teach the AI first</span>' : ""}
        <span style="font-size:28px" aria-hidden="true">${ATK_ICON[c.kind] || "⚡"}</span>
        <h3>${esc(c.name)}</h3><p>${esc(c.text)}</p>
        <div class="state" data-state="${c.kind}"></div>
        <button class="btn primary small" data-launch="${c.kind}">Launch</button>
      </div>`).join("")}</div>
    <h2 style="margin-top:30px">What happened</h2>
    <div class="history" id="hist"></div>`;
    $("#labStop").addEventListener("click", async () => { await post("/api/m/lab/stop"); routes.lab(view); });
    $$("[data-launch]").forEach((b) => b.addEventListener("click", async () => {
      b.disabled = true;
      try { await post("/api/m/lab/attack", { kind: b.dataset.launch }); } catch (e) { note("Couldn't launch", e.message); }
      setTimeout(() => (b.disabled = false), 1500);
      pollLab();
    }));
    M.flashed = new Set();
    every(pollLab, 500);
  };

  async function pollLab() {
    if (!$("#score")) return;
    const lab = await api("/api/m/lab");
    if (!$("#score")) return;
    const a = lab.attacks, caught = a.filter((x) => x.detected);
    const avg = caught.length ? caught.reduce((s, x) => s + (x.detected - x.launched), 0) / caught.length : 0;
    $("#score").innerHTML = `<div><b>${a.length}</b><span>attacks launched</span></div><div><b style="color:var(--moss)">${caught.length}</b><span>caught</span></div>
      <div><b>${caught.length ? avg.toFixed(1) + " s" : "–"}</b><span>average time to catch</span></div><div><b>${caught.filter((x) => x.by === "AI").length}</b><span>caught by the AI</span></div>`;
    const latest = {};
    a.forEach((x) => { if (!latest[x.kind]) latest[x.kind] = x; });
    $$("[data-state]").forEach((el) => {
      const x = latest[el.dataset.state];
      if (!x) { el.textContent = ""; el.className = "state"; return; }
      if (x.detected) {
        el.className = "state caught";
        el.textContent = `Caught in ${(x.detected - x.launched).toFixed(1)} s by ${x.by === "AI" ? "the AI" : "a known pattern"}`;
        if (!M.flashed.has(x.id)) { M.flashed.add(x.id); const card = el.closest(".attack"); card.classList.remove("caught-flash"); void card.offsetWidth; card.classList.add("caught-flash"); }
      } else {
        el.className = "state wait";
        el.textContent = `Running from ${x.ip}… ${(x.now - x.launched).toFixed(0)} s`;
      }
    });
    $("#hist").innerHTML = a.map((x) => `<div><span><b>${esc(x.name)}</b> from ${esc(x.ip)}, ${new Date(x.launched * 1000).toLocaleTimeString("en-GB")}</span>
      ${x.detected ? `<a class="ok" href="#/threats/${x.alert_id}">Caught in ${(x.detected - x.launched).toFixed(1)} s by ${x.by === "AI" ? "the AI" : "a known pattern"}</a>` : `<span class="no">Not caught yet</span>`}</div>`).join("")
      || `<div><span class="muted">No attacks yet. Launch one above.</span></div>`;
  }
})();

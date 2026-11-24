/* Attack story, risk scores, responding (block, report), the attack map, address profiles,
   the before/after teaching chart and presentation mode. Plain JavaScript, no libraries. */
"use strict";
(() => {
  const { routes, api, post, esc, fmt, $, $$, showTip, hideTip } = window.APP;
  const M = window.MON;
  const X = {};
  window.INSIGHT = X;

  const BAND = { low: "Low", medium: "Worth checking", high: "High", critical: "Critical" };
  const bandOf = (r) => (r >= 80 ? "critical" : r >= 50 ? "high" : r >= 20 ? "medium" : "low");
  const hhmm = (t) => new Date(t * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  const timeOnly = (iso) => (iso || "").slice(11, 19);
  const enc = encodeURIComponent;
  const hash = (s) => { let h = 2166136261; for (const c of s) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; };
  const tipOn = (root) => $$("[data-tip]", root).forEach((el) => {
    el.addEventListener("mousemove", (ev) => showTip(ev, el.dataset.tip));
    el.addEventListener("mouseleave", hideTip);
  });

  /* ================================================================ risk */
  X.riskHtml = (r) => `<span class="risk ${bandOf(r)}" title="Risk score ${r} of 100"><b>${r}</b><span>${BAND[bandOf(r)]}</span></span>`;
  function ring(r) {
    const C = 2 * Math.PI * 52, b = bandOf(r);
    return `<svg class="ring-gauge ${b}" viewBox="0 0 120 120" role="img" aria-label="Risk score ${r} of 100">
      <circle cx="60" cy="60" r="52" class="track"/><circle cx="60" cy="60" r="52" class="val" stroke-dasharray="${(C * r) / 100} ${C}"/>
      <text x="60" y="63" class="num">${r}</text><text x="60" y="83" class="of">of 100</text></svg>`;
  }
  function spark(vals, w = 220, h = 46) {
    const max = Math.max(100, ...vals), n = vals.length;
    const pts = vals.map((v, i) => `${((i / (n - 1)) * (w - 4) + 2).toFixed(1)},${(h - 4 - (v / max) * (h - 8)).toFixed(1)}`).join(" ");
    return `<svg class="spark" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" aria-hidden="true"><polyline points="${pts}"/>
      <circle cx="${w - 2}" cy="${(h - 4 - (vals[n - 1] / max) * (h - 8)).toFixed(1)}" r="3.5"/></svg>`;
  }

  /* ================================================================ attack story */
  X.storyHtml = (st, currentId) => {
    if (!st || !st.reached) return `<p class="muted small" style="margin:10px 0 0">No attack steps linked to this yet.</p>`;
    const idx = st.stages.map((s, i) => (s.alerts.length ? i : -1)).filter((i) => i >= 0);
    const first = idx[0], far = idx[idx.length - 1];
    const others = st.entities;
    return `<div class="chain" role="list">${st.stages.map((s, i) => {
      const on = s.alerts.length > 0, cur = s.alerts.some((a) => a.id === currentId);
      const cls = [on && "on", cur && "cur", i === far && "far", i >= first && i < far && "lit"].filter(Boolean).join(" ");
      return `<div class="step ${cls}" role="listitem">
        <span class="node">${on ? s.alerts.length : ""}</span>
        <b>${esc(s.name)}</b>
        <span class="tech-only small">${esc(s.tactic)}</span>
        <span class="when">${on ? esc(timeOnly(s.alerts[0].time)) : "not seen"}</span>
        ${on ? `<span class="links">${s.alerts.slice(0, 2).map((a) => `<a href="#/threats/${a.id}" title="${esc(a.title)}">${esc(a.title)}</a>`).join("")}${s.alerts.length > 2 ? `<small>and ${s.alerts.length - 2} more</small>` : ""}</span>` : ""}
      </div>`;
    }).join("")}</div>
    <p class="chain-sum"><b>${esc(st.summary)}</b> ${esc(st.verdict)}</p>
    ${others.length > 1 ? `<p class="muted small" style="margin:4px 0 0">Joined up from ${others.map((e) => M.entLink(e)).join(" and ")}, because the address logged in as that user.</p>` : ""}`;
  };
  X.storyPanel = (st, id) => `<div class="panel story-panel"><h3>The attack story</h3>
    <p class="muted small" style="margin:2px 0 0">How far this attacker got, one step at a time. The steps follow the MITRE ATT&CK tactics.</p>
    ${X.storyHtml(st, id)}</div>`;

  /* ================================================================ responding: block + report */
  function blockHtml(d) {
    if (d.blocked) {
      return `<span class="blocked-chip">Blocked until ${hhmm(d.blocked.until)}${{ lab: ", by the attack lab firewall", firewall: ", by the Windows Firewall" }[d.blocked.mode] || ", simulated"}</span>
        <button class="btn small ghost" data-unblock type="button">Unblock</button>`;
    }
    if (d.can_block) return `<button class="btn small danger" data-blockit type="button">Block this address for 30 minutes</button>`;
    if (d.allowlisted) return `<span class="muted small">Inside your own network, so it is on the allowlist and can't be blocked.</span>`;
    return "";
  }
  X.respondHtml = (d) => `
    <div class="respond-row">
      ${blockHtml(d)}
      <a class="btn small" href="/api/m/alerts/${d.id}/report.pdf" download data-report>Download report (PDF)</a>
      <a class="btn small ghost" href="#/entity/${enc(d.entity)}">Everything from ${esc(M.who(d.entity))}</a>
    </div>
    <div class="block-msg" data-blockmsg hidden></div>`;
  X.wireRespond = (root, d, refresh) => {
    const msg = $("[data-blockmsg]", root);
    const say = (t, bad) => { if (!msg) return; msg.hidden = false; msg.className = `block-msg ${bad ? "bad" : ""}`; msg.textContent = t; };
    const b = $("[data-blockit]", root);
    if (b) b.addEventListener("click", async () => {
      b.disabled = true;
      try {
        const r = await post("/api/m/block", { entity: d.entity, minutes: 30, alert_id: d.id });
        await refresh(); const m2 = $("[data-blockmsg]", $("#view")); if (m2) { m2.hidden = false; m2.textContent = r.text; }
      } catch (e) { say(e.message, true); b.disabled = false; }
    });
    const u = $("[data-unblock]", root);
    if (u) u.addEventListener("click", async () => { await post("/api/m/unblock", { entity: d.entity }); refresh(); });
    const rep = $("[data-report]", root);
    if (rep) rep.addEventListener("click", () => M.note("Making the report", "The PDF downloads in a moment. Open it from your Downloads folder."));
  };

  /* ================================================================ before and after teaching (AI learning page) */
  X.teachPanel = (v) => {
    const runs = v.sneaky_runs || [];
    const moved = v.features.filter((f) => Math.abs(f.watch - f.default) > 0.01);
    const AX = 120;
    const runRows = runs.map((r) => {
      const label = r.after ? "After teaching" : "Before teaching";
      const at = new Date(r.launched * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
      let bar;
      if (r.caught_in != null) bar = `<span class="bar caught" style="width:${Math.max(4, Math.min(100, (r.caught_in / AX) * 100))}%"></span><em>Caught in ${r.caught_in} s</em>`;
      else if (r.missed) bar = `<span class="bar missed" style="width:100%"></span><em>Got through</em>`;
      else bar = `<span class="bar running"></span><em>Running…</em>`;
      return `<div class="ba-row ${r.after ? "after" : "before"}"><span class="ba-label"><b>${label}</b><small>launched ${at}</small></span><span class="ba-track">${bar}</span></div>`;
    }).join("");
    const featRows = moved.map((f) => {
      const now = f.ratio, before = 3.0, max = 8;
      return `<div class="ba-feat"><b>${esc(f.name[0].toUpperCase() + f.name.slice(1))}</b>
        <div class="ba-row"><span class="ba-label"><small>Before</small></span><span class="ba-track"><span class="bar base" style="width:${(before / max) * 100}%"></span><em>alerts at ${before}× normal</em></span></div>
        <div class="ba-row"><span class="ba-label"><small>Now</small></span><span class="ba-track"><span class="bar ${now < before ? "caught" : "calm"}" style="width:${(now / max) * 100}%"></span><em>alerts at ${now}× normal</em></span></div></div>`;
    }).join("");
    return `<section class="panel teach">
      <h3>Before and after your lessons</h3>
      <p class="muted small" style="margin:2px 0 0">Proof that the AI learns: the same sneaky attack, before and after a person taught it.</p>
      <div class="teach-grid">
        <div><h4>Sneaky data theft in the attack lab</h4>
          ${runRows || `<div class="empty small">Not run yet. In the attack lab, launch <b>Sneaky data theft</b> (it gets through), mark a <b>Quiet data theft</b> alert as a real threat, then launch it again.</div>`}
          ${runRows ? `<div class="ba-axis"><span>0 s</span><span>${AX} s</span></div>` : ""}</div>
        <div><h4>What changed inside the AI</h4>
          ${featRows ? `${featRows}<p class="muted small" style="margin:8px 0 0">A shorter bar means it reacts sooner.</p>` : `<div class="empty small">Nothing yet. Mark an AI threat as real and the line it uses moves here.</div>`}</div>
      </div></section>`;
  };

  /* ================================================================ the world map */
  const W = window.WORLD;
  let LAND = null;
  function land() {
    if (!LAND) LAND = `<g class="land">${W.shapes.map((s) => `<path d="${s.d}" data-c="${s.c || ""}"><title>${esc(s.n)}</title></path>`).join("")}</g>`;
    return LAND;
  }
  const isThreat = (p) => p.alerts > 0 || p.risk >= 20 || p.blocked;

  X.drawMap = (svg, data, opts = {}) => {
    if (!svg || !W) return;
    if (!svg.dataset.base) {
      svg.setAttribute("viewBox", `0 0 ${W.w} ${W.h}`);
      svg.innerHTML = `${land()}<g class="arcs"></g><g class="ov"></g>`;
      svg.dataset.base = "1";
    }
    const home = W.centers[data.home] || [752, 261];
    const by = {};
    data.points.forEach((p) => { if (!p.internal && p.cc) (by[p.cc] = by[p.cc] || []).push(p); });
    $$(".land path", svg).forEach((el) => {
      const ps = by[el.dataset.c];
      el.setAttribute("class", !ps ? "" : ps.some((p) => p.alerts > 0 && !p.blocked) ? "hot" : "act");
    });
    let arcs = "", ov = "";
    // country bubbles: how many addresses wrote logs from each country
    Object.entries(by).forEach(([cc, ps]) => {
      const c = W.centers[cc]; if (!c) return;
      const worst = Math.max(...ps.map((p) => p.risk)), threats = ps.filter((p) => p.alerts > 0).length;
      const r = Math.min(26, 4 + 2.4 * Math.sqrt(ps.length));
      const country = ps[0].country || cc;
      ov += `<circle class="bubble ${bandOf(worst)}" cx="${c[0]}" cy="${c[1]}" r="${r.toFixed(1)}"
        data-tip="${esc(`${country}: ${ps.length} address${ps.length === 1 ? "" : "es"}, ${fmt(ps.reduce((n, p) => n + p.events, 0))} lines${threats ? `, ${threats} with threats` : ""}`)}"/>`;
    });
    // attackers: their own dot, with a line to your systems
    data.points.filter((p) => !p.internal && p.cc && isThreat(p) && W.centers[p.cc]).slice(0, opts.max || 60).forEach((p) => {
      const c = W.centers[p.cc], h = hash(p.entity), ang = ((h % 360) * Math.PI) / 180, rad = 7 + (h % 9);
      const x = c[0] + rad * Math.cos(ang), y = c[1] + rad * Math.sin(ang);
      const dx = home[0] - x, dy = home[1] - y, dist = Math.hypot(dx, dy);
      const cx = (x + home[0]) / 2 - dy * 0.18, cy = (y + home[1]) / 2 - Math.min(140, dist * 0.32);
      const b = p.blocked ? "blocked" : bandOf(p.risk);
      if (dist > 12) arcs += `<path class="arc ${b}" d="M${x.toFixed(1)} ${y.toFixed(1)} Q${cx.toFixed(1)} ${cy.toFixed(1)} ${home[0]} ${home[1]}"/>`;
      if (!p.blocked && (b === "high" || b === "critical")) ov += `<circle class="halo" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="5"/>`;
      ov += `<g class="pt ${b}" data-e="${esc(p.entity)}" data-tip="${esc(`${p.entity}, ${p.country}: risk ${p.risk} of 100, ${p.alerts} threat${p.alerts === 1 ? "" : "s"}${p.blocked ? ", blocked" : ""}. Click for details.`)}">
        <circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${p.blocked ? 4.5 : 5.5}"/>
        ${p.blocked ? `<path d="M${(x - 3).toFixed(1)} ${(y - 3).toFixed(1)}l6 6m0 -6l-6 6"/>` : ""}</g>`;
    });
    ov += `<circle class="home-pulse" cx="${home[0]}" cy="${home[1]}" r="7"/><circle class="home" cx="${home[0]}" cy="${home[1]}" r="6"/>
      <text class="home-label" x="${home[0] + 10}" y="${home[1] + 18}">your systems</text>`;
    $(".arcs", svg).innerHTML = arcs;
    $(".ov", svg).innerHTML = ov;
    tipOn(svg);
    $$(".pt", svg).forEach((g) => g.addEventListener("click", () => { hideTip(); location.hash = `#/entity/${enc(g.dataset.e)}`; }));
  };

  const MAPLEGEND = `<div class="map-legend">
    <span><i class="lg bubble"></i>addresses in a country (bigger means more)</span>
    <span><i class="lg attacker"></i>attacker, line to your systems</span>
    <span><i class="lg blocked"></i>blocked</span>
    <span><i class="lg home"></i>your systems</span></div>`;

  routes.map = async (view) => {
    M.page = "map";
    let minutes = +(sessionStorage.getItem("mapMin") || 60);
    view.innerHTML = `
    <div class="pagehead"><div><h1 style="font-size:36px">Attack map</h1>
      <p class="lead" style="margin:10px 0 0">Where the activity comes from. Red lines are attackers heading for your systems. Click an attacker to see everything it did.</p></div>
      <div class="seg" role="group" aria-label="Time range"><button data-min="15" type="button">Last 15 minutes</button><button data-min="60" type="button">Last hour</button></div></div>
    <div class="mapcard"><svg class="worldmap" id="wmap" role="img" aria-label="World map of where log activity comes from"></svg>${MAPLEGEND}</div>
    <section class="grid2" style="margin-top:22px">
      <div class="panel"><h3>Attackers</h3><p class="muted small" style="margin:2px 0 10px">Addresses with threats or a raised risk score.</p><div id="mapAttackers" class="rows"></div></div>
      <div class="panel"><h3>Countries</h3><p class="muted small" style="margin:2px 0 10px">Found with an offline lookup, so it works without internet.</p><div id="mapCountries"></div></div>
    </section>`;
    const seg = () => $$("[data-min]").forEach((b) => b.setAttribute("aria-pressed", +b.dataset.min === minutes));
    $$("[data-min]").forEach((b) => b.addEventListener("click", () => { minutes = +b.dataset.min; try { sessionStorage.setItem("mapMin", minutes); } catch (e) { /* ignore */ } seg(); load(); }));
    seg();
    async function load() {
      const d = await api(`/api/m/map?minutes=${minutes}`).catch(() => null);
      if (!d || !$("#wmap")) return;
      X.drawMap($("#wmap"), d);
      const att = d.points.filter(isThreat).sort((a, b) => b.risk - a.risk).slice(0, 12);
      $("#mapAttackers").innerHTML = att.map((p) => `<div class="arow">${X.riskHtml(p.risk)}
          <span>${M.entLink(p.entity, p.entity)}<small>${esc(p.country || "Unknown")}, ${p.alerts} threat${p.alerts === 1 ? "" : "s"}, ${fmt(p.events)} lines</small></span>
          ${p.blocked ? `<span class="blocked-chip">Blocked</span>` : p.internal ? `<span class="muted small">your network</span>` : `<button class="btn small danger" data-blk="${esc(p.entity)}" type="button">Block</button>`}</div>`).join("")
        || `<div class="empty">No attackers in this time range. Launch one in the <a href="#/lab">attack lab</a>.</div>`;
      $$("[data-blk]").forEach((b) => b.addEventListener("click", async () => {
        b.disabled = true;
        try { await post("/api/m/block", { entity: b.dataset.blk }); } catch (e) { M.note("Couldn't block", e.message); }
        load();
      }));
      const cs = d.countries.slice(0, 12), maxE = Math.max(1, ...cs.map((c) => c.events));
      $("#mapCountries").innerHTML = cs.length ? `<table class="ctable"><thead><tr><th>Country</th><th>Addresses</th><th>Lines</th><th>Threats</th></tr></thead><tbody>
        ${cs.map((c) => `<tr><td>${esc(c.country)}</td><td>${fmt(c.addresses)}</td>
          <td><span class="cbar"><span style="width:${(c.events / maxE) * 100}%"></span></span>${fmt(c.events)}</td>
          <td>${c.threats ? `<b class="tcount">${c.threats}</b>` : "0"}</td></tr>`).join("")}</tbody></table>`
        : `<div class="empty">No addresses yet.</div>`;
    }
    M.every(load, 3000);
  };

  /* ================================================================ address / user profile */
  routes.entity = async (view, ent) => {
    M.page = "entity";
    if (!ent) { location.hash = "#/map"; return; }
    let d;
    try { d = await api(`/api/m/entity?e=${enc(ent)}`); } catch (e) {
      view.innerHTML = `<div class="empty"><h2>Nothing seen from ${esc(M.who(ent))}</h2><p>It may have been cleared. <a href="#/monitor">Back to the monitor</a></p></div>`;
      return;
    }
    const kind = { ip: "Address", user: "User account", host: "Machine" }[d.kind] || "Source";
    const act = d.activity && d.activity.minutes ? d.activity.minutes : [];
    const maxA = Math.max(1, ...act.map((a) => a.events));
    const actSvg = act.length ? (() => {
      const Wd = 600, H = 120, bw = Wd / act.length;
      return `<svg class="act" viewBox="0 0 ${Wd} ${H}" preserveAspectRatio="none" style="height:120px" aria-label="Log lines per minute">${act.map((a, i) => {
        const h = (a.events / maxA) * (H - 20), hf = (a.fails / maxA) * (H - 20);
        return `<rect x="${i * bw + 1}" y="${H - 16 - h}" width="${bw - 2}" height="${h}" rx="1.5" fill="#c3cfdc"/>${a.fails ? `<rect x="${i * bw + 1}" y="${H - 16 - hf}" width="${bw - 2}" height="${hf}" rx="1.5" fill="#c43d2b"/>` : ""}`;
      }).join("")}</svg><div class="axis-row"><span>${esc(timeOnly(d.activity.start).slice(0, 5))}</span><span>30 minutes, log time</span><span>${esc(timeOnly(d.last_seen).slice(0, 5))}</span></div>`;
    })() : `<div class="empty small">No activity kept.</div>`;
    view.innerHTML = `
    <a class="back" href="javascript:history.back()">Back</a>
    <section class="prof-head">
      <div class="prof-id">
        <span class="muted">${kind}${d.geo ? `, ${esc(d.geo.country || "unknown country")}` : ""}</span>
        <h1>${esc(M.who(d.entity))}</h1>
        <div class="facts" style="margin-top:12px">
          <div><b>${fmt(d.events)}</b>log lines</div>
          <div><b>${fmt(d.fails)}</b>failures</div>
          <div><b>${d.alerts.length}</b>threat${d.alerts.length === 1 ? "" : "s"}</div>
          <div><b>${esc(timeOnly(d.first_seen) || "–")}</b>first seen</div>
          <div><b>${esc(timeOnly(d.last_seen) || "–")}</b>last seen</div>
        </div>
        ${d.used.length ? `<p class="small" style="margin:12px 0 0">${d.kind === "ip" ? "Accounts it used" : "Addresses it came from"}: ${d.used.map((u) => M.entLink(u, d.kind === "ip" ? u.slice(5) : u)).join(", ")}</p>` : ""}
        ${d.sources.length ? `<p class="muted small" style="margin:4px 0 0">Seen in: ${d.sources.map(esc).join(", ")}</p>` : ""}
        <div class="respond" id="presp"></div>
      </div>
      <div class="risk-card ${d.band}">
        <span class="muted small">Risk score right now</span>
        ${ring(d.risk)}
        <b class="band-word">${esc(d.band_text)}</b>
        <div class="trend">${spark(d.trend)}<span class="muted small">last hour</span></div>
        <p class="muted small" style="margin:0">Recent threats count most and fade over 30 minutes. Threats marked real count more; false alarms count nothing.</p>
      </div>
    </section>
    <div class="panel story-panel"><h3>The attack story</h3>${X.storyHtml(d.story)}</div>
    <section class="grid2" style="margin-top:22px">
      <div class="panel"><h3>Activity per minute</h3><p class="muted small" style="margin:2px 0 8px">Grey is all lines, red is failures.</p>${actSvg}</div>
      <div class="panel"><h3>Threats</h3><div class="threat-cards" style="margin-top:12px">${d.alerts.slice(0, 8).map((a) => `<a class="tcard" href="#/threats/${a.id}"><span class="sev ${a.severity}"></span>
        <span><b>${esc(a.title)}</b><small>${esc(a.source_name || "")}${a.kind === "ai" ? ", spotted by the AI" : ""}</small></span><small>${esc(M.clock(a.created))}</small></a>`).join("")
        || `<div class="empty">No threats from ${esc(M.who(d.entity))}.</div>`}</div></div>
    </section>
    <div class="logview" style="margin-top:22px">
      <div class="logview-head"><h3>Latest log lines</h3></div>
      <div class="logrows">${d.lines.map((l) => `<div class="logrow ${l.bad ? "fail" : ""}"><time>${esc(timeOnly(l.time))}</time><span>${esc(l.plain)}</span></div>`).join("") || `<div class="logrow"><span>None kept.</span></div>`}</div>
    </div>`;
    const resp = { id: d.alerts[0] ? d.alerts[0].id : null, entity: d.entity, blocked: d.blocked, can_block: d.can_block, allowlisted: d.kind === "ip" && !d.can_block };
    $("#presp").innerHTML = `<div class="respond-row">${blockHtml(resp)}${resp.id ? `<a class="btn small" href="/api/m/alerts/${resp.id}/report.pdf" download data-report>Report on the latest threat (PDF)</a>` : ""}</div><div class="block-msg" data-blockmsg hidden></div>`;
    X.wireRespond($("#presp"), resp, () => routes.entity(view, ent));
  };

  /* ================================================================ presentation mode */
  const P = { view: "map", manual: false, rotate: 0 };
  X.present = () => {
    const el = document.documentElement;
    if (el.requestFullscreen && !document.fullscreenElement) el.requestFullscreen().catch(() => {});
    location.hash = "#/present";
  };
  document.addEventListener("fullscreenchange", () => {
    if (!document.fullscreenElement && M.page === "present") location.hash = "#/monitor";
  });
  addEventListener("keydown", (e) => {
    if (M.page !== "present") return;
    if (e.key === "Escape") location.hash = "#/monitor";
    if (e.key === "m" || e.key === "M") { P.manual = true; setPView(P.view === "map" ? "radar" : "map"); }
  });
  function setPView(v) {
    P.view = v;
    $$("[data-pv]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.pv === v));
    if ($("#pMap")) $("#pMap").style.display = v === "map" ? "" : "none";
    if ($("#pRadarBox")) $("#pRadarBox").style.display = v === "radar" ? "" : "none";
    refreshPView();
  }
  async function refreshPView() {
    if (P.view === "map") { const d = await api("/api/m/map?minutes=60").catch(() => null); if (d) X.drawMap($("#pMap"), d, { max: 40 }); }
    else M.drawRadarInto("#pRadar");
  }

  routes.present = async (view) => {
    M.page = "present";
    document.body.classList.add("present");
    P.manual = false; P.rotate = 0;
    view.innerHTML = `
    <div class="pres">
      <header class="pres-head">
        <div class="pres-brand"><i></i>Security Log Monitor<span>live</span></div>
        <div class="pres-level" id="pLevel"></div>
        <div class="pres-clock" id="pClock"></div>
        <button class="pres-x" id="pExit" type="button">Leave (Esc)</button>
      </header>
      <div class="pres-grid">
        <div class="pres-main">
          <div class="pres-tabs" role="group"><button data-pv="map" type="button">Attack map</button><button data-pv="radar" type="button">Radar</button><span>Press M to switch</span></div>
          <svg class="worldmap" id="pMap" role="img" aria-label="World map of activity"></svg>
          <div id="pRadarBox" class="pres-radar" style="display:none"><svg class="radar" id="pRadar" viewBox="0 0 400 400" role="img" aria-label="Radar"></svg></div>
        </div>
        <aside class="pres-side">
          <div class="pres-counts">
            <div><b id="pRate">0</b>lines a second</div><div><b id="pTotal">0</b>lines checked</div>
            <div><b id="pOpen">0</b>threats to review</div><div><b id="pBlocked">0</b>addresses blocked</div>
          </div>
          <h3>Latest threats</h3><div id="pThreats" class="pres-threats"></div>
          <h3>Riskiest right now</h3><div id="pRisk" class="pres-risk"></div>
        </aside>
      </div>
      <div class="pres-river" id="pRiver"></div>
    </div>`;
    $("#pExit").addEventListener("click", () => { if (document.fullscreenElement) document.exitFullscreen().catch(() => {}); location.hash = "#/monitor"; });
    $$("[data-pv]").forEach((b) => b.addEventListener("click", () => { P.manual = true; setPView(b.dataset.pv); }));
    const threats = await api("/api/m/alerts?limit=6").catch(() => []);
    const drawThreats = (list, fresh) => {
      $("#pThreats").innerHTML = list.slice(0, 6).map((a, i) => `<a class="pthreat ${a.severity} ${fresh && i < fresh ? "new" : ""}" href="#/threats/${a.id}">
        <span class="sev ${a.severity}"></span><span><b>${esc(a.title)}</b><small>${esc(M.who(a.entity))}${a.kind === "ai" ? ", spotted by the AI" : ""}</small></span><time>${esc(M.clock(a.created))}</time></a>`).join("")
        || `<div class="pempty">No threats yet. All quiet.</div>`;
    };
    P.threats = threats; drawThreats(threats);
    M.presentStats = (s) => {
      if (!$("#pLevel")) return;
      $("#pLevel").textContent = s.threat.level; $("#pLevel").dataset.level = s.threat.level;
      $("#pRate").textContent = fmt(s.rate); $("#pTotal").textContent = fmt(s.total); $("#pOpen").textContent = fmt(s.open_alerts);
    };
    M.presentFeed = (d) => {
      if (!$("#pRiver")) return;
      if (d.alerts.length) { P.threats = [...d.alerts.slice().reverse(), ...P.threats].slice(0, 6); drawThreats(P.threats, d.alerts.length); }
      $("#pRiver").innerHTML = M.river.slice(-4).map((e) => `<div class="${e.outcome === "fail" ? "fail" : ""}">${esc(M.clock(e.ts))}  ${esc(M.who(e.entity))}: ${esc(e.plain || e.raw)}</div>`).join("");
    };
    if (M.state) M.presentStats(M.state);
    setPView("map");
    M.every(() => { $("#pClock").textContent = new Date().toLocaleTimeString("en-GB"); }, 1000);
    M.every(async () => {
      if (!$("#pRisk")) return;
      const [ents, blocks] = await Promise.all([api("/api/m/entities?minutes=15").catch(() => []), api("/api/m/blocks").catch(() => [])]);
      if (!$("#pRisk")) return;
      $("#pBlocked").textContent = blocks.length;
      const top = ents.filter((e) => e.risk > 0).sort((a, b) => b.risk - a.risk).slice(0, 5);
      $("#pRisk").innerHTML = top.map((e) => `<div class="prisk ${bandOf(e.risk)}"><span>${esc(M.who(e.entity))}${e.blocked ? " (blocked)" : ""}</span>
        <span class="pbar"><span style="width:${e.risk}%"></span></span><b>${e.risk}</b></div>`).join("") || `<div class="pempty">Nobody risky right now.</div>`;
      P.rotate += 3;
      if (!P.manual && P.rotate % 21 === 0) setPView(P.view === "map" ? "radar" : "map"); else refreshPView();
    }, 3000);
  };
})();

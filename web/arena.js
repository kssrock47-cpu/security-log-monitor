/* Algorithm arena: algorithms fight on the same data; see how each performs, its settings, and compare them. */
"use strict";
(() => {
  const { routes, api, post, esc, fmt, $, $$, techChip } = window.APP;
  const A = { ds: null, data: null, pick: new Set(), filter: "all", poll: null, curveIds: null };
  const FAM = { supervised: "Learns from examples", unsupervised: "Learns normal only", deep: "Deep learning" };
  const COLORS = ["#1f4e8c", "#c9a227", "#2e8b62", "#c43d2b", "#6a4c93", "#0b1f3a", "#d17a22", "#3a8fb7"];
  const f3 = (v) => (v == null ? "–" : Number(v).toFixed(3));
  const secs = (s) => (s == null ? "–" : s < 1 ? "under 1 s" : s < 90 ? `${Math.round(s)} s` : `${(s / 60).toFixed(1)} min`);
  const famChip = (c) => `<span class="chip fam-${c.family}">${esc(c.family === "deep" ? `Deep learning, ${c.learns === "supervised" ? "from examples" : "normal only"}` : FAM[c.family])}</span>`;
  const param = (k, v) => `<span class="pv"><i>${esc(k)}</i> ${esc(v === "" ? "–" : v)}</span>`;

  async function load(ds) {
    A.data = await api(`/api/arena${ds ? `?dataset=${encodeURIComponent(ds)}` : ""}`);
    A.ds = A.data.dataset;
    window.ARENA_DS = A.ds;
    const ids = new Set(A.data.contenders.map((c) => c.id));
    A.pick = new Set([...A.pick].filter((i) => ids.has(i)));
    if (!A.pick.size) A.data.contenders.forEach((c) => A.pick.add(c.id));
    return A.data;
  }

  routes.arena = async (view) => {
    await load(A.ds);
    render(view);
    if (A.data.job.state === "running") startPoll();
  };

  /* ------------------------------------------------------------ page */
  function render(view) {
    const d = A.data;
    if (!d.datasets.length) {
      view.innerHTML = `<h1 style="font-size:36px">Algorithm arena</h1><div class="empty" style="margin-top:20px"><h3>No data to fight on yet</h3>
        <p>The arena needs every task's message counts and an answer key. For HDFS_v1, run <code>python -m seclog.arena build-features</code> once after a full HDFS_v1 check (or add <code>--log HDFS.log --labels anomaly_label.csv</code>). To try it now, run the demo check.</p>
        <button class="btn primary" onclick="openRun()">Re-run the HDFS check</button></div>`;
      return;
    }
    const dsInfo = d.datasets.find((x) => x.id === A.ds);
    const ran = d.contenders.filter((c) => c.result);
    view.innerHTML = `
    ${dsInfo.demo ? `<div class="demo-note">These are made-up demo logs, so every algorithm finds them easy. Pick HDFS_v1 for real results.</div>` : ""}
    <div class="arena-head">
      <div>
        <h1 style="font-size:36px">Algorithm arena</h1>
        <p class="lead" style="margin-top:8px">Every algorithm learns from the same older ${dsInfo ? fmt(Math.round(dsInfo.tasks * 0.7)) : ""} tasks and is tested on the same newer ones, so the results are a fair fight. Add any algorithm, change its settings, and let the AI search for better ones.</p>
      </div>
      ${d.datasets.length > 1 ? `<label class="dspick">Data<select id="dsSel">${d.datasets.map((x) => `<option value="${x.id}" ${x.id === A.ds ? "selected" : ""}>${esc(x.name)}</option>`).join("")}</select></label>`
        : `<div class="dspick"><span>Data</span><b>${esc(dsInfo.name)}</b></div>`}
    </div>
    <div class="arena-actions">
      <button class="btn primary" id="goFight">Start the fight <span class="cnt" id="pickCount"></span></button>
      <button class="btn" id="goAdd">Add an algorithm</button>
      <button class="btn" id="goTune"><svg viewBox="0 0 20 20" aria-hidden="true" class="ico"><path d="M10 2.5l1.8 4.2 4.2 1.8-4.2 1.8L10 14.5l-1.8-4.2L4 8.5l4.2-1.8z"/><path d="M15.5 13.5l.8 1.7 1.7.8-1.7.8-.8 1.7-.8-1.7-1.7-.8 1.7-.8z"/></svg>AI: find the best settings</button>
      <button class="btn ghost" id="goAsk" data-ai-ask="Which algorithm is best here and why? Compare their precision, recall, false alarms and speed.">Ask the AI about these results</button>
      <button class="linkbtn" id="goReset" type="button">Restore the starting line-up</button>
    </div>
    <div id="fightBox"></div>
    ${recHtml(d.recommendation)}
    <section class="panel arena-board">
      <div class="board-head">
        <div><h2>How each algorithm performs</h2>
        <p class="muted small" style="margin:4px 0 0">Ranked by F1, which balances catching problems (recall) against false alarms (precision); 1.0 is perfect. Tick the ones to fight or to draw below.</p></div>
        <div class="seg" role="group" aria-label="Show">${[["all", "All"], ["supervised", "From examples"], ["unsupervised", "Normal only"], ["deep", "Deep learning"]]
          .map(([k, t]) => `<button data-fam="${k}" aria-pressed="${A.filter === k}">${t}</button>`).join("")}</div>
      </div>
      <div class="board" id="board"></div>
    </section>
    <section class="arena-charts" id="charts"></section>
    <p class="muted small" style="margin-top:18px">Each fight is saved, so results stay after a restart. Changed a setting? The old result is marked <i>out of date</i> until it fights again. Command line: <code>python -m seclog.arena fight</code>.</p>`;
    renderBoard();
    renderCharts();
    renderJob(d.job);
    $("#dsSel") && $("#dsSel").addEventListener("change", async (e) => { await load(e.target.value); render(view); });
    $$("[data-fam]").forEach((b) => b.addEventListener("click", () => { A.filter = b.dataset.fam; $$("[data-fam]").forEach((x) => x.setAttribute("aria-pressed", x === b)); renderBoard(); }));
    $("#goFight").addEventListener("click", () => fight([...A.pick]));
    $("#goAdd").addEventListener("click", () => editDialog(null));
    $("#goTune").addEventListener("click", () => tuneDialog(null));
    const rs = $("#goReset");
    rs.addEventListener("click", async () => {
      if (rs.dataset.sure !== "1") { rs.dataset.sure = "1"; rs.textContent = "Click again: removes added algorithms and all results"; rs.classList.add("warn"); return; }
      try { await post("/api/arena/reset"); A.pick.clear(); await load(A.ds); render(view); } catch (e) { alert(e.message); }
    });
  }

  function recHtml(r) {
    if (!r) return "";
    const lines = [`<li><b>Best overall: ${esc(r.best.name)}</b>, F1 ${f3(r.best.f1)}. It caught ${fmt(r.best.caught)} of ${fmt(r.best.real)} problems with ${fmt(r.best.false_alarms)} false alarm${r.best.false_alarms === 1 ? "" : "s"}.</li>`];
    if (r.best_unsupervised) lines.push(`<li><b>Best without an answer key: ${esc(r.best_unsupervised.name)}</b>, F1 ${f3(r.best_unsupervised.f1)}. Use this kind on logs nobody has labelled, which is most real security logs.</li>`);
    if (r.fastest_good.id !== r.best.id) lines.push(`<li><b>Fastest of the near-best: ${esc(r.fastest_good.name)}</b>, F1 ${f3(r.fastest_good.f1)} in ${secs(r.fastest_good.seconds)}.</li>`);
    return `<section class="panel arena-rec"><div class="rec-mark" aria-hidden="true">AI</div><div><h3>The AI's pick, from ${r.n} finished fights</h3><ul>${lines.join("")}</ul></div></section>`;
  }

  /* ------------------------------------------------------------ leaderboard */
  function renderBoard() {
    const box = $("#board"); if (!box) return;
    const rows = A.data.contenders.filter((c) => A.filter === "all" || c.family === A.filter)
      .sort((x, y) => ((y.result && !y.result.outdated ? y.result.f1 : -1) - (x.result && !x.result.outdated ? x.result.f1 : -1)) || x.name.localeCompare(y.name));
    let rank = 0;
    box.innerHTML = `<div class="brow bhead" role="row"><span></span><span>#</span><span>Algorithm and its settings</span><span>F1</span><span>Caught</span><span>False alarms</span><span class="tech-only">Precision / recall</span><span>Learned in</span><span></span></div>` +
      rows.map((c) => {
        const r = c.result, live = r && !r.outdated;
        if (live) rank++;
        const ps = Object.entries(c.params).map(([k, v]) => (c.defaults_changed.includes(k) ? `<b>${param(k, v)}</b>` : param(k, v))).join("");
        return `<div class="brow ${live && rank === 1 ? "first" : ""}" data-id="${c.id}">
          <label class="pick"><input type="checkbox" data-pick="${c.id}" ${A.pick.has(c.id) ? "checked" : ""} aria-label="Pick ${esc(c.name)}"></label>
          <span class="rank">${live ? (rank === 1 ? `<span class="crown" title="Winner">1</span>` : rank) : ""}</span>
          <div class="bname">
            <button class="namebtn" data-detail="${c.id}">${esc(c.name)}</button>
            <span class="tags">${famChip(c)}${c.detector ? `<span class="chip ok">${c.detector} in this monitor</span>` : ""}${c.tuned ? `<span class="chip ai">Tuned by the AI</span>` : ""}${c.defaults_changed.length && !c.tuned ? `<span class="chip check">Settings changed</span>` : ""}</span>
            <span class="params">${ps}</span>
          </div>
          ${r ? `<div class="cmp-bar ${r.outdated ? "stale" : ""}" role="img" aria-label="F1 ${f3(r.f1)}"><div class="track"><span style="width:${Math.max(1, r.f1 * 100)}%"></span></div><em>${f3(r.f1)}</em>${r.outdated ? `<small>out of date</small>` : ""}</div>
            <span><b>${fmt(r.caught)}</b> <span class="muted small">of ${fmt(r.real)}</span></span>
            <span><b>${fmt(r.false_alarms)}</b></span>
            <span class="tech-only small">${f3(r.precision)} / ${f3(r.recall)}</span>
            <span class="small">${secs(r.train_seconds)}</span>`
          : `<span class="muted small notyet">Not fought yet</span><span></span><span></span><span class="tech-only"></span><span></span>`}
          <span class="bact"><button class="btn small ghost" data-edit="${c.id}">Change settings</button><button class="iconbtn" data-more="${c.id}" aria-label="More for ${esc(c.name)}" title="More">⋯</button></span>
        </div>`;
      }).join("") + (rows.length ? "" : `<div class="empty" style="margin-top:12px">Nothing in this group. Add an algorithm.</div>`);
    $("#pickCount").textContent = `(${A.pick.size})`;
    $$("[data-pick]").forEach((b) => b.addEventListener("change", () => {
      b.checked ? A.pick.add(b.dataset.pick) : A.pick.delete(b.dataset.pick);
      $("#pickCount").textContent = `(${A.pick.size})`;
      renderCharts();
    }));
    $$("[data-detail]").forEach((b) => b.addEventListener("click", () => detailDialog(b.dataset.detail)));
    $$("[data-edit]").forEach((b) => b.addEventListener("click", () => editDialog(b.dataset.edit)));
    $$("[data-more]").forEach((b) => b.addEventListener("click", () => moreMenu(b)));
  }

  function moreMenu(btn) {
    $$(".moremenu").forEach((m) => m.remove());
    const id = btn.dataset.more;
    const m = document.createElement("div");
    m.className = "moremenu";
    m.innerHTML = `<button data-a="detail">See how it performs</button><button data-a="fight">Fight this one again</button><button data-a="tune">Let the AI tune it</button><button data-a="copy">Make a copy</button><button data-a="del" class="warn">Delete</button>`;
    btn.parentElement.appendChild(m);
    const close = (e) => { if (!m.contains(e.target) && e.target !== btn) { m.remove(); document.removeEventListener("click", close); } };
    setTimeout(() => document.addEventListener("click", close), 0);
    m.addEventListener("click", async (e) => {
      const a = e.target.dataset.a; if (!a) return;
      m.remove();
      try {
        if (a === "detail") detailDialog(id);
        if (a === "fight") fight([id]);
        if (a === "tune") tuneDialog(id);
        if (a === "copy") { const c = await post(`/api/arena/contenders/${id}/duplicate`); A.pick.add(c.id); await refresh(); editDialog(c.id); }
        if (a === "del") { await api(`/api/arena/contenders/${id}`, { method: "DELETE" }); A.pick.delete(id); await refresh(); }
      } catch (err) { alert(err.message); }
    });
  }

  async function refresh() { await load(A.ds); const v = $("#view"); if (location.hash.startsWith("#/arena")) render(v); }

  /* ------------------------------------------------------------ charts */
  function renderCharts() {
    const box = $("#charts"); if (!box) return;
    const done = A.data.contenders.filter((c) => c.result && !c.result.outdated);
    if (done.length < 1) { box.innerHTML = ""; return; }
    const picked = done.filter((c) => A.pick.has(c.id)).sort((a, b) => b.result.f1 - a.result.f1);
    const show = (picked.length ? picked : done).slice(0, 12);
    box.innerHTML = `
      <div class="panel"><h3>Precision, recall and F1, side by side</h3>
        <p class="muted small" style="margin:4px 0 10px">Precision: how many alerts were real. Recall: how many real problems were caught. A good detector is high on both.</p>
        ${metricBars(show)}</div>
      <div class="panel"><h3>Quality against speed</h3>
        <p class="muted small" style="margin:4px 0 10px">Up is better, left is faster. Time to learn is on a log scale.</p>
        ${speedPlot(show)}</div>
      <div class="panel wide"><h3>Precision–recall curves</h3>
        <p class="muted small" style="margin:4px 0 10px">Each curve shows what happens if the alert line moves: catching more problems (right) usually costs precision (down). The dot is where each one stands now. ${show.length > 8 ? "Showing the top 8 ticked." : ""}</p>
        <div id="curves"><p class="muted small"><span class="spinner"></span>Drawing…</p></div></div>`;
    drawCurves(show.slice(0, 8));
  }

  function metricBars(rows) {
    const W = 560, rowH = 46, L = 170, H = rows.length * rowH + 30, bw = W - L - 50;
    const ms = [["precision", "#1f4e8c"], ["recall", "#c9a227"], ["f1", "#2e8b62"]];
    const g = rows.map((c, i) => {
      const y = 22 + i * rowH;
      return `<text x="${L - 10}" y="${y + 17}" text-anchor="end" class="lbl">${esc(c.name.length > 24 ? c.name.slice(0, 23) + "…" : c.name)}</text>` +
        ms.map(([k, col], j) => `<rect x="${L}" y="${y + j * 12}" width="${Math.max(1, c.result[k] * bw)}" height="10" rx="2" fill="${col}"><title>${esc(c.name)}: ${k} ${f3(c.result[k])}</title></rect>
          <text x="${L + Math.max(1, c.result[k] * bw) + 5}" y="${y + j * 12 + 9}" class="val">${f3(c.result[k])}</text>`).join("");
    }).join("");
    const grid = [0, 0.25, 0.5, 0.75, 1].map((t) => `<line x1="${L + t * bw}" x2="${L + t * bw}" y1="16" y2="${H - 8}" class="grid"/><text x="${L + t * bw}" y="12" text-anchor="middle" class="tick">${t}</text>`).join("");
    return `<div class="legend" style="margin:0 0 6px">${ms.map(([k, c]) => `<span><i style="background:${c}"></i>${k === "f1" ? "F1" : k[0].toUpperCase() + k.slice(1)}</span>`).join("")}</div>
      <svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Precision, recall and F1 for each algorithm">${grid}${g}</svg>`;
  }

  function speedPlot(rows) {
    const W = 520, H = 300, L = 50, B = 40, T = 14, R = 16;
    const t = rows.map((c) => Math.max(0.05, c.result.train_seconds + c.result.check_seconds));
    const lo = Math.log10(Math.min(...t) / 1.5), hi = Math.log10(Math.max(...t) * 1.5);
    const x = (s) => L + ((Math.log10(Math.max(0.05, s)) - lo) / Math.max(0.3, hi - lo)) * (W - L - R);
    const y = (f) => T + (1 - f) * (H - T - B);
    const ticks = [0.1, 1, 10, 60, 600].filter((s) => Math.log10(s) >= lo && Math.log10(s) <= hi);
    const pts = rows.map((c, i) => {
      const px = x(t[i]), py = y(c.result.f1);
      return `<circle cx="${px}" cy="${py}" r="6" fill="${famColor(c)}" stroke="#fff" stroke-width="1.5"><title>${esc(c.name)}: F1 ${f3(c.result.f1)}, ${secs(t[i])}</title></circle>
        <text x="${px + 9}" y="${py + 4}" class="val">${esc(c.name.length > 18 ? c.name.slice(0, 17) + "…" : c.name)}</text>`;
    }).join("");
    return `<div class="legend" style="margin:0 0 6px">${Object.entries(FAM).map(([k, v]) => `<span><i style="background:${famColor({ family: k })};border-radius:50%"></i>${v}</span>`).join("")}</div>
    <svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="F1 against time for each algorithm">
      ${[0, 0.25, 0.5, 0.75, 1].map((f) => `<line x1="${L}" x2="${W - R}" y1="${y(f)}" y2="${y(f)}" class="grid"/><text x="${L - 8}" y="${y(f) + 4}" text-anchor="end" class="tick">${f}</text>`).join("")}
      ${ticks.map((s) => `<text x="${x(s)}" y="${H - B + 18}" text-anchor="middle" class="tick">${secs(s)}</text>`).join("")}
      <text x="${(W + L) / 2}" y="${H - 6}" text-anchor="middle" class="axis">time to learn and test</text>
      <text x="14" y="${(H - B) / 2}" text-anchor="middle" class="axis" transform="rotate(-90 14 ${(H - B) / 2})">F1</text>
      ${pts}</svg>`;
  }

  function famColor(c) { return { supervised: "#1f4e8c", unsupervised: "#c9a227", deep: "#6a4c93" }[c.family] || "#5b6b7f"; }

  async function drawCurves(rows) {
    const det = await Promise.all(rows.map((c) => api(`/api/arena/contenders/${c.id}?dataset=${A.ds}`).catch(() => null)));
    const box = $("#curves"); if (!box) return;
    const W = 860, H = 340, L = 50, B = 40, T = 12, R = 200;
    const x = (r) => L + r * (W - L - R), y = (p) => T + (1 - p) * (H - T - B);
    const lines = det.map((d, i) => {
      if (!d || !d.result || !d.result.curve || !d.result.curve.length) return "";
      const col = COLORS[i % COLORS.length];
      const path = d.result.curve.map(([r, p], k) => `${k ? "L" : "M"}${x(r).toFixed(1)},${y(p).toFixed(1)}`).join("");
      return `<path d="${path}" fill="none" stroke="${col}" stroke-width="2.2"><title>${esc(rows[i].name)}</title></path>
        <circle cx="${x(d.result.recall)}" cy="${y(d.result.precision)}" r="5.5" fill="${col}" stroke="#fff" stroke-width="1.5"><title>${esc(rows[i].name)} now: precision ${f3(d.result.precision)}, recall ${f3(d.result.recall)}</title></circle>
        <rect x="${W - R + 16}" y="${T + 6 + i * 22}" width="14" height="4" fill="${col}"/><text x="${W - R + 36}" y="${T + 11 + i * 22}" class="val">${esc(rows[i].name.length > 22 ? rows[i].name.slice(0, 21) + "…" : rows[i].name)}</text>`;
    }).join("");
    box.innerHTML = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Precision-recall curves">
      ${[0, 0.25, 0.5, 0.75, 1].map((v) => `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" class="grid"/><text x="${L - 8}" y="${y(v) + 4}" text-anchor="end" class="tick">${v}</text>
        <text x="${x(v)}" y="${H - B + 18}" text-anchor="middle" class="tick">${v}</text>`).join("")}
      <text x="${(L + W - R) / 2}" y="${H - 6}" text-anchor="middle" class="axis">recall: share of real problems caught</text>
      <text x="14" y="${(H - B) / 2}" text-anchor="middle" class="axis" transform="rotate(-90 14 ${(H - B) / 2})">precision</text>
      ${lines}</svg>`;
  }

  /* ------------------------------------------------------------ fights and AI tuning */
  async function fight(ids) {
    if (!ids.length) return alert("Tick at least one algorithm to fight.");
    try { renderJob(await post("/api/arena/fight", { ids, dataset: A.ds })); startPoll(); }
    catch (e) { alert(e.message); }
  }

  function startPoll() {
    clearInterval(A.poll);
    A.poll = setInterval(async () => {
      if (!location.hash.startsWith("#/arena")) { clearInterval(A.poll); return; }
      const j = await api("/api/arena/job").catch(() => null);
      if (!j) return;
      renderJob(j);
      if (j.state !== "running") {
        clearInterval(A.poll);
        await refresh();
        if (j.kind === "tune" && j.new_id) { A.pick.add(j.new_id); detailDialog(j.new_id); }
      }
    }, 700);
  }

  function renderJob(j) {
    const box = $("#fightBox"); if (!box) return;
    if (!j || j.state === "idle") { box.innerHTML = ""; return; }
    const running = j.state === "running";
    const el = (s) => (s ? `${Math.round((Date.now() / 1000 - s))} s` : "");
    if (j.kind === "fight") {
      const best = Math.max(0, ...j.lanes.filter((l) => l.state === "done").map((l) => l.f1));
      box.innerHTML = `<section class="panel fight ${running ? "on" : ""}">
        <div class="board-head"><h2>${running ? "The fight is on" : "Fight results"}</h2>
          ${running ? `<button class="btn small" id="stopJob">Stop after this one</button>` : `<button class="linkbtn" id="hideJob">Hide</button>`}</div>
        <p class="muted small" style="margin:2px 0 12px">${esc(j.message || "")}</p>
        <div class="lanes">${j.lanes.map((l) => `
          <div class="lane ${l.state} ${l.state === "done" && l.f1 === best && !running ? "win" : ""}">
            <b>${esc(l.name)}</b>
            <div class="cmp-bar"><div class="track">${l.state === "running" ? `<span class="pulse"></span>` : l.state === "done" ? `<span style="width:${Math.max(1, l.f1 * 100)}%"></span>` : ""}</div>
              <em>${l.state === "done" ? f3(l.f1) : ""}</em></div>
            <span class="small muted">${{ waiting: "waiting", running: `learning… ${el(l.started)}`, done: `${fmt(l.caught)} of ${fmt(l.real)} caught, ${fmt(l.false_alarms)} false alarms, ${secs(l.seconds)}`, failed: `failed: ${esc(l.error || "")}`, skipped: "stopped" }[l.state]}</span>
          </div>`).join("")}</div></section>`;
    } else {
      const t = j.target || {};
      const tr = j.trials || [];
      const okv = tr.filter((r) => r.val_f1 != null).map((r) => r.val_f1);
      const bestv = okv.length ? Math.max(...okv) : null;
      box.innerHTML = `<section class="panel fight ${running ? "on" : ""}">
        <div class="board-head"><h2>${running ? `The AI is tuning ${esc(t.name || "")}` : "AI tuning finished"}</h2>
          ${running ? `<button class="btn small" id="stopJob">Stop and keep the best so far</button>` : `<button class="linkbtn" id="hideJob">Hide</button>`}</div>
        <p class="muted small" style="margin:2px 0 10px">${esc(j.message || "")}</p>
        <p class="small" style="margin:0 0 10px">It tries different settings on the older tasks only (learning on 80% of them, checking on the newest 20%), keeps the best, and then tests that once on the newer tasks. The test tasks are never used to choose.</p>
        <div class="trials">${tr.map((r) => `<span class="trial ${r.val_f1 === bestv ? "best" : ""}" title="${esc(Object.entries(r.params).map(([k, v]) => `${k}=${v}`).join(", "))}">
          <i style="height:${Math.max(3, (r.val_f1 || 0) * 46)}px"></i><small>${r.val_f1 == null ? "×" : f3(r.val_f1)}</small></span>`).join("")}
          ${running ? `<span class="trial ghost"><i class="pulse"></i><small>…</small></span>` : ""}</div>
        ${j.summary ? `<p style="margin:12px 0 0"><b>Result on the newer tasks:</b> F1 ${f3(j.summary.test_f1)}${j.summary.before_test_f1 != null ? `, was ${f3(j.summary.before_test_f1)} with the old settings` : ""}. ${Object.keys(j.summary.changed).length ? `Changed: ${Object.entries(j.summary.changed).map(([k, [a, b]]) => `${esc(k)} ${esc(a)} → ${esc(b)}`).join(", ")}.` : "The old settings were already the best it found."}</p>` : ""}
      </section>`;
    }
    $("#stopJob") && $("#stopJob").addEventListener("click", () => post("/api/arena/stop"));
    $("#hideJob") && $("#hideJob").addEventListener("click", () => { box.innerHTML = ""; });
  }

  /* ------------------------------------------------------------ dialogs */
  function dlg(cls = "") {
    let d = $("#arenaDialog");
    if (!d) { d = document.createElement("dialog"); d.id = "arenaDialog"; document.body.appendChild(d); }
    d.className = cls;
    return d;
  }

  function fieldHtml(p, v) {
    const id = `p_${p.name}`;
    const range = p.min != null && p.max != null ? `${p.min} to ${p.max}` : "";
    let input;
    if (p.type === "choice") input = `<select id="${id}" name="${p.name}">${p.choices.map((c) => `<option ${String(c) === String(v) ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>`;
    else if (p.type === "layers") input = `<input type="text" id="${id}" name="${p.name}" value="${esc(v)}" pattern="[0-9 ,]+">`;
    else input = `<input type="number" id="${id}" name="${p.name}" value="${esc(v)}" ${p.min != null ? `min="${p.min}"` : ""} ${p.max != null ? `max="${p.max}"` : ""} step="${p.type === "int" ? 1 : "any"}">`;
    return `<label class="pfield"><span>${esc(p.label)} ${techChip(p.name)}</span>${input}
      <small class="muted">${esc(p.help || "")}${p.help && range ? " " : ""}${range ? `Range ${range}.` : ""} Default ${esc(p.default)}.</small></label>`;
  }

  async function editDialog(id) {
    const cat = A.data.algorithms;
    const c = id ? A.data.contenders.find((x) => x.id === id) : null;
    let algo = c ? c.algo : null;
    const d = dlg("wide");
    const draw = () => {
      const a = cat.find((x) => x.id === algo);
      d.innerHTML = `<form class="modal" method="dialog" id="edForm">
        <h2>${c ? `Change the settings of ${esc(c.name)}` : "Add an algorithm"}</h2>
        ${c ? "" : `<div class="algo-pick">${["supervised", "unsupervised", "deep"].map((f) => `<div><h3>${esc(A.data.families[f].title)}</h3><p class="muted small" style="margin:2px 0 8px">${esc(A.data.families[f].text)}</p>
          ${cat.filter((x) => x.family === f).map((x) => `<button type="button" class="algo ${x.id === algo ? "on" : ""}" data-algo="${x.id}"><b>${esc(x.name)}</b><span>${esc(x.plain)}</span></button>`).join("")}</div>`).join("")}</div>`}
        ${a ? `<div class="algo-form">
          ${c ? `<p class="muted" style="margin:0">${esc(a.plain)}</p>` : ""}
          <label class="pfield"><span>Name in the arena</span><input type="text" name="__name" value="${esc(c ? c.name : a.name)}" maxlength="60"></label>
          <div class="pgrid">${a.params.map((p) => fieldHtml(p, c ? c.params[p.name] : p.default)).join("")}</div>
          <div class="status" id="edErr" hidden></div>
        </div>` : `<p class="muted">Pick an algorithm to see its settings.</p>`}
        <div class="actions" style="justify-content:space-between">
          <button type="button" class="linkbtn" id="edDefaults" ${a ? "" : "hidden"}>Back to default settings</button>
          <span style="display:flex;gap:10px"><button class="btn ghost" value="cancel" formnovalidate>Cancel</button>
          <button type="button" class="btn" id="edSave" ${a ? "" : "disabled"}>Save</button>
          <button type="button" class="btn primary" id="edRun" ${a ? "" : "disabled"}>Save and fight</button></span>
        </div></form>`;
      $$("[data-algo]", d).forEach((b) => b.addEventListener("click", () => { algo = b.dataset.algo; draw(); }));
      if (!a) return;
      $("#edDefaults", d).addEventListener("click", () => { a.params.forEach((p) => { const el = d.querySelector(`[name="${p.name}"]`); if (el) el.value = p.default; }); });
      const save = async (andRun) => {
        const params = {};
        a.params.forEach((p) => { params[p.name] = d.querySelector(`[name="${p.name}"]`).value; });
        const name = d.querySelector('[name="__name"]').value;
        try {
          const r = c ? await post(`/api/arena/contenders/${c.id}`, { name, params }) : await post("/api/arena/contenders", { algo, name, params });
          A.pick.add(r.id);
          d.close();
          await refresh();
          if (andRun) fight([r.id]);
        } catch (e) { const er = $("#edErr", d); er.hidden = false; er.textContent = e.message; }
      };
      $("#edSave", d).addEventListener("click", () => save(false));
      $("#edRun", d).addEventListener("click", () => save(true));
    };
    draw();
    d.showModal();
  }

  async function tuneDialog(id) {
    const d = dlg("");
    const cs = A.data.contenders;
    d.innerHTML = `<form class="modal" method="dialog">
      <h2>AI: find the best settings</h2>
      <p class="muted" style="margin:0">The AI tries different settings for one algorithm (a random search), keeps the one that scores best on a validation slice of the older tasks, then saves it as a new contender and tests it once on the newer tasks.</p>
      <label>Algorithm to tune<select id="tuWho">${cs.map((c) => `<option value="${c.id}" ${c.id === id ? "selected" : ""}>${esc(c.name)}</option>`).join("")}</select></label>
      <label>How many settings to try<input type="number" id="tuN" value="12" min="3" max="60"></label>
      <p class="muted small" style="margin:0">More tries can find better settings but take longer: about as long as one fight of that algorithm, times the number of tries.</p>
      <div class="actions" style="justify-content:flex-end"><button class="btn ghost" value="cancel" formnovalidate>Cancel</button><button type="button" class="btn primary" id="tuGo">Start tuning</button></div>
    </form>`;
    d.showModal();
    $("#tuGo", d).addEventListener("click", async () => {
      try { const j = await post(`/api/arena/contenders/${$("#tuWho", d).value}/tune`, { dataset: A.ds, trials: +$("#tuN", d).value }); d.close(); renderJob(j); startPoll(); window.scrollTo({ top: 0, behavior: "smooth" }); }
      catch (e) { alert(e.message); }
    });
  }

  async function detailDialog(id) {
    const x = await api(`/api/arena/contenders/${id}?dataset=${A.ds}`);
    const { contender: c, algo: a, result: r, tuning: t } = x;
    const d = dlg("wide");
    const unit = r ? Math.max(1, Math.ceil(r.real / 200)) : 1;
    d.innerHTML = `<div class="modal adetail">
      <div class="board-head"><div><h2>${esc(c.name)}</h2>
        <p class="muted" style="margin:4px 0 0">${esc(a.name)}: ${esc(a.plain)}</p>
        <p class="small" style="margin:6px 0 0">${famChip({ family: a.family, learns: a.learns })} <span class="muted">${esc(a.family_text)}</span></p></div>
        <button class="btn ghost small" id="dClose">Close</button></div>
      ${r ? `${x.outdated ? `<div class="demo-note">These results are from older settings. Fight again to see the new ones.</div>` : ""}
      <div class="dgrid">
        <div class="panel"><h3>How it performed</h3>
          <div class="kpis"><div><div class="big">${f3(r.f1)}</div><span class="muted small">F1</span></div>
            <div><div class="big">${fmt(r.caught)}<small> of ${fmt(r.real)}</small></div><span class="muted small">real problems caught</span></div>
            <div><div class="big">${fmt(r.false_alarms)}</div><span class="muted small">false alarms</span></div></div>
          <div class="dots" role="img" aria-label="${r.caught} caught, ${r.missed} missed, ${r.false_alarms} false alarms">${"<i></i>".repeat(Math.round(r.caught / unit))}${"<i class='missed'></i>".repeat(Math.round(r.missed / unit))}${"<i class='fa'></i>".repeat(Math.min(200, Math.round(r.false_alarms / unit)))}</div>
          <div class="legend" style="margin:0"><span><i style="background:var(--moss);border-radius:50%"></i>caught</span><span><i style="border:2px solid var(--flare);border-radius:50%"></i>missed</span><span><i style="background:var(--brass);width:3px"></i>false alarm</span>${unit > 1 ? `<span>Each mark is about ${unit} tasks.</span>` : ""}</div>
          <table class="cm" aria-label="Confusion matrix"><tr><th></th><th>Alert raised</th><th>No alert</th></tr>
            <tr><th>Real problem</th><td class="good">${fmt(r.caught)}<small>caught</small></td><td class="bad">${fmt(r.missed)}<small>missed</small></td></tr>
            <tr><th>Normal task</th><td class="warn">${fmt(r.false_alarms)}<small>false alarms</small></td><td>${fmt(r.quiet)}<small>rightly quiet</small></td></tr></table>
          <table class="tech-table">
            <tr><td>Precision (alerts that were real)</td><td>${f3(r.precision)}</td></tr>
            <tr><td>Recall (real problems caught)</td><td>${f3(r.recall)}</td></tr>
            <tr><td>F1 (balance of the two)</td><td>${f3(r.f1)}</td></tr>
            ${r.pr_auc != null ? `<tr><td>PR-AUC (quality at every alert line)</td><td>${f3(r.pr_auc)}</td></tr><tr><td>ROC-AUC</td><td>${f3(r.roc_auc)}</td></tr>` : ""}
            <tr><td>Learned from / tested on</td><td>${fmt(r.info && r.info.n_fit ? r.info.n_fit : r.n_train)} / ${fmt(r.n_test)} tasks</td></tr>
            <tr><td>Time to learn / to check</td><td>${secs(r.train_seconds)} / ${secs(r.check_seconds)}</td></tr>
            ${r.info && r.info.epochs ? `<tr><td>Training passes (epochs) used</td><td>${r.info.epochs}</td></tr>` : ""}
            ${r.info && r.info.main_patterns ? `<tr><td>Main patterns kept</td><td>${r.info.main_patterns}</td></tr>` : ""}
            <tr><td>Fought on</td><td>${esc((r.run_at || "").replace("T", " "))}</td></tr>
          </table></div>
        <div class="panel"><h3>Precision–recall curve</h3><p class="muted small" style="margin:4px 0 8px">The dot is the current alert line.</p>${miniCurve(r)}</div>
      </div>` : `<div class="empty">Not fought yet. Start a fight to see how it performs.</div>`}
      <div class="panel"><h3>Its settings (parameters)</h3>
        <table class="ptable"><tr><th>Setting</th><th>Value</th><th>Default</th><th>What it does</th></tr>
        ${x.params.map((p) => `<tr class="${String(p.value) !== String(p.default) ? "chg" : ""}"><td>${esc(p.label)} ${techChip(p.name)}</td><td><b>${esc(p.value)}</b></td><td>${esc(p.default)}</td><td class="muted small">${esc(p.help || "")}</td></tr>`).join("")}</table></div>
      ${t ? `<div class="panel"><h3>How the AI tuned it</h3>
        <p class="small" style="margin:4px 0 8px">Started from ${esc(t.summary.from)}. Tried ${t.trials.length} settings: learned on ${fmt(t.validation.fit_tasks)} older tasks and checked on the next ${fmt(t.validation.val_tasks)} (${fmt(t.validation.val_problems)} problems). Best validation F1 ${f3(t.best_val_f1)}; on the newer test tasks it scored ${f3(t.summary.test_f1)}${t.summary.before_test_f1 != null ? ` (the starting settings scored ${f3(t.summary.before_test_f1)})` : ""}.</p>
        <table class="ptable"><tr><th>Try</th><th>Validation F1</th><th>Settings tried</th></tr>
        ${t.trials.slice().sort((p, q) => (q.val_f1 ?? -1) - (p.val_f1 ?? -1)).map((tr) => `<tr class="${tr.val_f1 === t.best_val_f1 ? "chg" : ""}"><td>${tr.trial}</td><td>${tr.val_f1 == null ? "failed" : f3(tr.val_f1)}</td><td class="small">${esc(Object.entries(tr.params).map(([k, v]) => `${k}=${v}`).join(", "))}</td></tr>`).join("")}</table></div>` : ""}
      <div class="actions"><button class="btn primary" id="dFight">Fight it again</button><button class="btn" id="dEdit">Change settings</button><button class="btn" id="dTune">Let the AI tune it</button>
        <button class="btn ghost" data-ai-ask="Explain how ${esc(c.name)} performed and what its settings mean. What would you change?">Ask the AI about it</button></div>
    </div>`;
    if (!d.open) d.showModal();
    $("#dClose", d).addEventListener("click", () => d.close());
    $("#dFight", d).addEventListener("click", () => { d.close(); fight([c.id]); });
    $("#dEdit", d).addEventListener("click", () => { d.close(); editDialog(c.id); });
    $("#dTune", d).addEventListener("click", () => { d.close(); tuneDialog(c.id); });
  }

  function miniCurve(r) {
    if (!r.curve || !r.curve.length) return `<p class="muted small">No curve for this one.</p>`;
    const W = 360, H = 260, L = 40, B = 34, T = 8, R = 10;
    const x = (v) => L + v * (W - L - R), y = (v) => T + (1 - v) * (H - T - B);
    return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Precision-recall curve">
      ${[0, 0.5, 1].map((v) => `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" class="grid"/><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end" class="tick">${v}</text><text x="${x(v)}" y="${H - B + 16}" text-anchor="middle" class="tick">${v}</text>`).join("")}
      <path d="${r.curve.map(([a, b], k) => `${k ? "L" : "M"}${x(a).toFixed(1)},${y(b).toFixed(1)}`).join("")}" fill="none" stroke="#1f4e8c" stroke-width="2.4"/>
      <circle cx="${x(r.recall)}" cy="${y(r.precision)}" r="6" fill="#c9a227" stroke="#fff" stroke-width="1.5"/>
      <text x="${(L + W - R) / 2}" y="${H - 4}" text-anchor="middle" class="axis">recall</text>
      <text x="12" y="${(H - B) / 2}" text-anchor="middle" class="axis" transform="rotate(-90 12 ${(H - B) / 2})">precision</text></svg>`;
  }
})();

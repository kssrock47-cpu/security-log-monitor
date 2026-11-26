/* AI assistant panel: a local large language model (through Ollama) that answers from the monitor's own data. */
"use strict";
(() => {
  const { api, esc, $ } = window.APP;
  const AI = { status: null, history: [], busy: false };

  document.body.insertAdjacentHTML("beforeend", `
    <button class="ai-fab" id="aiFab" type="button" aria-controls="aiPanel"><span class="orb" aria-hidden="true"></span>Ask the AI</button>
    <aside class="ai-panel" id="aiPanel" aria-label="AI assistant" aria-hidden="true">
      <div class="ai-top">
        <div class="row"><h2><span class="orb" aria-hidden="true"></span>AI assistant</h2>
          <span><button class="linkbtn" id="aiNew" type="button">New chat</button>&nbsp;&nbsp;<button class="btn small ghost" id="aiClose" type="button">Close</button></span></div>
        <div class="ai-sub" id="aiSub">Checking…</div>
      </div>
      <div class="ai-body" id="aiBody"></div>
      <form class="ai-form" id="aiForm">
        <div class="row"><textarea id="aiQ" rows="1" placeholder="Ask about threats, addresses or the algorithms" aria-label="Your question"></textarea>
          <button class="btn primary" id="aiSend" type="submit">Ask</button></div>
        <div class="ai-note">Runs on this PC: logs never leave it. It answers only from the monitor's data, and a person still decides.</div>
      </form>
    </aside>`);

  const open = async () => {
    document.body.classList.add("ai-open");
    $("#aiPanel").setAttribute("aria-hidden", "false");
    await refresh();
    setTimeout(() => $("#aiQ") && $("#aiQ").focus(), 50);
  };
  const close = () => { document.body.classList.remove("ai-open"); $("#aiPanel").setAttribute("aria-hidden", "true"); };
  $("#aiFab").addEventListener("click", open);
  $("#aiClose").addEventListener("click", close);
  $("#aiNew").addEventListener("click", () => { AI.history = []; refresh(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && document.body.classList.contains("ai-open") && !document.querySelector("dialog[open]")) close(); });
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-ai-ask]");
    if (!b) return;
    e.preventDefault();
    const d = b.closest("dialog"); if (d) d.close();
    open().then(() => ask(b.dataset.aiAsk));
  });
  const q = $("#aiQ");
  q.addEventListener("input", () => { q.style.height = "auto"; q.style.height = Math.min(140, q.scrollHeight) + "px"; });
  q.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("#aiForm").requestSubmit(); } });
  $("#aiForm").addEventListener("submit", (e) => { e.preventDefault(); const t = q.value.trim(); if (t) { q.value = ""; q.style.height = "auto"; ask(t); } });

  function page() {
    const [, name = "monitor", arg] = location.hash.split("/");
    const p = { page: name };
    if (name === "threats" && arg && /^\d+$/.test(arg)) p.alert = +arg;
    if (name === "entity" && arg) p.entity = decodeURIComponent(arg);
    if (name === "arena" && window.ARENA_DS) p.dataset = window.ARENA_DS;
    return p;
  }

  function suggestions() {
    const p = page();
    if (p.alert) return [`Explain threat #${p.alert} in plain words.`, `How serious is threat #${p.alert}, and what should I do now?`, `Could threat #${p.alert} be a false alarm?`];
    if (p.entity) return [`What has ${p.entity} been doing?`, `Is ${p.entity} dangerous? Should I block it?`];
    if (p.page === "arena") return ["Which algorithm is best here and why?", "Why do the algorithms that learn normal only score lower?", "Which settings should I change to cut false alarms?", "Is the neural network worth it compared with Random Forest?"];
    if (["research", "accuracy", "alerts", "replay", "how"].includes(p.page)) return ["Summarise the HDFS_v1 results.", "Why does Random Forest beat Isolation Forest?", "What does F1 mean here?"];
    return ["What is happening right now?", "Which address is the most dangerous, and why?", "Summarise the threats so far.", "Which threats should I review first?"];
  }

  async function refresh() {
    const sub = $("#aiSub"), body = $("#aiBody");
    try { AI.status = await api("/api/assistant/status"); } catch (e) { AI.status = { running: false, recommended: [] }; }
    const s = AI.status;
    $("#aiSend").disabled = !(s.running && s.model);
    q.disabled = !(s.running && s.model);
    if (!s.running) {
      sub.innerHTML = `<span class="dot off"></span>The AI model isn't running on this PC.`;
      body.innerHTML = `<div class="ai-setup"><p style="margin:0">The assistant runs a language model on this computer with <b>Ollama</b>, so no log line is sent to the internet. One-time setup:</p>
        <ol><li>Download and install Ollama from <a href="https://ollama.com/download" target="_blank" rel="noopener">ollama.com/download</a> (no administrator rights needed).</li>
        <li>Open it once; it keeps running in the background.</li><li>Come back here and click <b>Check again</b>, then download a model.</li></ol>
        <button class="btn primary" type="button" id="aiRetry">Check again</button></div>`;
      $("#aiRetry").addEventListener("click", refresh);
      return;
    }
    if (!s.model) {
      sub.innerHTML = `<span class="dot off"></span>Ollama is running, but no model is downloaded yet.`;
      body.innerHTML = `<div class="ai-setup"><p style="margin:0">Pick a model to download. It is saved on this PC and works offline afterwards.</p>
        <div class="ai-models">${s.recommended.map((m) => `<button type="button" data-pull="${esc(m.name)}"><b>${esc(m.name)}, ${esc(m.size)}</b><span>${esc(m.note)}</span></button>`).join("")}</div>
        <div id="aiPull"></div></div>`;
      body.querySelectorAll("[data-pull]").forEach((b) => b.addEventListener("click", () => pull(b.dataset.pull)));
      return;
    }
    sub.innerHTML = `<span class="dot"></span>Running on this PC with <b>${esc(s.model)}</b>` +
      (s.models.length > 1 ? ` <select id="aiModel" aria-label="Model">${s.models.map((m) => `<option ${m.name === s.model ? "selected" : ""}>${esc(m.name)}</option>`).join("")}</select>` : "");
    $("#aiModel") && $("#aiModel").addEventListener("change", async (e) => { AI.status = await window.APP.post("/api/assistant/model", { model: e.target.value }); refresh(); });
    if (!AI.history.length) {
      body.innerHTML = `<div class="ai-msg bot">Hi. I can explain threats, describe what an address did, and compare the algorithms in the arena, using only this monitor's data. Try one of these:</div>
        <div class="ai-suggest">${suggestions().map((t) => `<button type="button">${esc(t)}</button>`).join("")}</div>`;
      body.querySelectorAll(".ai-suggest button").forEach((b) => b.addEventListener("click", () => ask(b.textContent)));
    }
  }

  async function pull(model) {
    const box = $("#aiPull");
    box.innerHTML = `<p class="small" style="margin:8px 0 4px" id="aiPullT">Starting the download of ${esc(model)}…</p><div class="ai-bar"><span id="aiPullB"></span></div>`;
    document.querySelectorAll("[data-pull]").forEach((b) => (b.disabled = true));
    try {
      await stream("/api/assistant/pull", { model }, (d) => {
        if (d.error) throw new Error(d.error);
        if (d.total && d.completed) {
          $("#aiPullB").style.width = `${Math.round((d.completed / d.total) * 100)}%`;
          $("#aiPullT").textContent = `${d.status}: ${(d.completed / 1e9).toFixed(2)} of ${(d.total / 1e9).toFixed(2)} GB`;
        } else if (d.status) $("#aiPullT").textContent = d.status;
      });
      await refresh();
    } catch (e) {
      box.innerHTML = `<div class="status err">${esc(e.message)}</div>`;
      document.querySelectorAll("[data-pull]").forEach((b) => (b.disabled = false));
    }
  }

  async function stream(url, body, onData) {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
    const rd = r.body.getReader(), dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await rd.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, i); buf = buf.slice(i + 2);
        const line = chunk.split("\n").find((l) => l.startsWith("data: "));
        if (line) onData(JSON.parse(line.slice(6)));
      }
    }
  }

  const md = (t) => esc(t).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>").replace(/^#{1,4} (.*)$/gm, "<b>$1</b>");

  async function ask(question) {
    if (AI.busy) return;
    if (!AI.status || !AI.status.running || !AI.status.model) { await refresh(); if (!AI.status.running || !AI.status.model) return; }
    const body = $("#aiBody");
    if (!AI.history.length) body.innerHTML = "";
    AI.busy = true; $("#aiSend").disabled = true;
    body.insertAdjacentHTML("beforeend", `<div class="ai-msg user">${esc(question)}</div>`);
    const el = document.createElement("div");
    el.className = "ai-msg bot";
    el.innerHTML = `<span class="muted small">Reading the monitor's data…</span>`;
    body.appendChild(el);
    body.scrollTop = body.scrollHeight;
    let text = "", facts = "";
    try {
      await stream("/api/assistant/chat", { question, history: AI.history, page: page() }, (d) => {
        if (d.error) throw new Error(d.error);
        if (d.facts !== undefined) { facts = d.facts; el.innerHTML = `<span class="cursor"></span>`; }
        if (d.t) { text += d.t; el.innerHTML = md(text) + `<span class="cursor"></span>`; body.scrollTop = body.scrollHeight; }
      });
      el.innerHTML = md(text) + (facts ? `<button class="linkbtn facts-toggle" type="button">Show what the AI was given</button>` : "");
      const ft = el.querySelector(".facts-toggle");
      if (ft) ft.addEventListener("click", () => {
        const pre = el.querySelector("pre.facts");
        if (pre) { pre.remove(); ft.textContent = "Show what the AI was given"; return; }
        ft.insertAdjacentHTML("afterend", `<pre class="facts">${esc(facts)}</pre>`); ft.textContent = "Hide what the AI was given";
      });
      AI.history.push({ role: "user", content: question }, { role: "assistant", content: text });
    } catch (e) {
      el.classList.add("err");
      el.textContent = e.message || "The AI stopped answering.";
    }
    AI.busy = false; $("#aiSend").disabled = false;
    body.scrollTop = body.scrollHeight;
  }

  window.ASSISTANT = { open, ask };
})();

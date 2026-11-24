/* Guided demo: a step-by-step tour that explains each part and runs the real thing. */
"use strict";
(() => {
  const { api, post, esc, $ } = window.APP;
  const T = { i: 0, on: false, busy: false, data: {}, fresh: false };

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  async function until(fn, secs, tick) {
    const end = Date.now() + secs * 1000;
    while (Date.now() < end && T.on) {
      const v = await fn().catch(() => null);
      if (v) return v;
      if (tick) tick(Math.ceil((end - Date.now()) / 1000));
      await wait(800);
    }
    return null;
  }
  async function go(hash, selector) {
    if (location.hash !== hash) location.hash = hash;
    if (!selector) { await wait(500); return null; }
    const el = await until(async () => document.querySelector(selector), 8);
    await wait(300);
    return el;
  }
  const lab = () => api("/api/m/lab");
  async function ensureLab(say) {
    let l = await lab();
    if (!l.running) { say("Building a pretend company network and teaching the AI what normal looks like…"); await post("/api/m/lab/start"); }
    return until(async () => ((l = await lab()).ready ? l : null), 90, () => say("Building a pretend company network and teaching the AI what normal looks like…"));
  }
  async function launchAndWait(kind, say, secs = 90) {
    const a = await post("/api/m/lab/attack", { kind });
    const t0 = Date.now();
    const done = await until(async () => {
      const x = (await lab()).attacks.find((z) => z.id === a.id);
      return x && x.detected ? x : null;
    }, secs, () => say(`Attack running from ${a.ip}… ${Math.round((Date.now() - t0) / 1000)} s`));
    return done || { ...a, detected: null };
  }
  const caught = (x) => x.detected
    ? `<b>Caught in ${(x.detected - x.launched).toFixed(1)} seconds by ${x.by === "AI" ? "the AI" : "a known attack pattern"}.</b>`
    : `<b>Not caught yet.</b> Press Next to carry on.`;

  // ---------------------------------------------------------------- the story
  const STEPS = [
    { title: "Welcome to the Security Log Monitor", page: "#/monitor",
      text: `Computers keep a diary of everything they do, called a <b>log</b>. This monitor reads security logs, uses AI to spot threats, and explains each one in plain words.
             <br><br>This tour takes about 4 minutes. It explains each part and runs a real demo: attacks are launched, caught, and the AI learns from you.
             <label class="tour-check"><input type="checkbox" id="tourFresh"> Start fresh: make the AI forget earlier lessons (best for a demo)</label>` },
    { title: "The radar: who's active", page: "#/monitor", target: ".radar-card",
      text: `Every dot is an <b>IP address or user</b> that wrote to the logs in the last 15 minutes. Green is normal. Gold is worth checking. Red is a threat, and the closer to the middle, the more dangerous. Click any dot to see its threats.` },
    { title: "Threat level and live numbers", page: "#/monitor", target: ".mon-text",
      text: `A one-word summary of the last 10 minutes, from <b>Calm</b> to <b>Under attack</b>, plus how many lines a second are being checked and how many threats are waiting for a person.` },
    { title: "Live activity", page: "#/monitor", target: ".mon-grid",
      text: `The chart shows log activity every 10 seconds, with red marks where threats were found. Below it, log lines stream in as they arrive, in plain words or the original text. On the right are the latest threats.` },
    { title: "Connect logs from anywhere", page: "#/connect", target: ".tiles",
      text: `Six ways to bring logs in. <b>Offline</b>: drop a file. <b>Online, live</b>: watch a file or folder on this PC, link a web address, receive logs from routers and servers (syslog), read this PC's Windows events, or use the attack lab. It reads Linux, SSH, web server, firewall, Windows and JSON logs.` },
    { title: "The attack lab", page: "#/lab", action: "Start the attack lab",
      text: `To show the monitor working, we use a pretend company network: a website with visitors, staff logging in, a firewall. It writes realistic logs. First the AI watches 20 minutes of normal activity to learn what normal looks like.`,
      run: async (say) => { const l = await ensureLab(say); return l ? `<b>Ready.</b> The AI has learned normal behaviour. Now let's attack it.` : `It's taking longer than usual. Press Next to carry on.`; } },
    { title: "Attack 1: a break-in", page: "#/lab", target: '[data-kind="break_in"]', action: "Launch the break-in",
      text: `An attacker guesses passwords until one works, then makes itself an administrator. A <b>known attack pattern</b> should catch this within seconds.`,
      run: async (say) => { await ensureLab(say); const x = await launchAndWait("break_in", say, 40); T.data.breakin = x; return caught(x); } },
    { title: "Attack 2: quiet data theft", page: "#/lab", target: '[data-kind="data_theft"]', action: "Launch the data theft",
      text: `Someone quietly downloads 150 invoices. Every request looks normal on its own, so <b>no known pattern matches</b>. Only the AI can notice that this address is behaving unlike anyone else. The AI checks every 30 seconds, so this takes a little longer.`,
      run: async (say) => { await ensureLab(say); const x = await launchAndWait("data_theft", say, 90); T.data.theft = x; return caught(x); } },
    { title: "Opening a threat", target: "#tdetail .detail-head",
      page: () => (T.data.theft && T.data.theft.alert_id ? `#/threats/${T.data.theft.alert_id}` : "#/threats"),
      text: `Each threat says <b>what happened</b> in plain words, <b>who</b> did it, <b>where</b> it came from and <b>when</b>. Red is high risk, gold is medium.` },
    { title: "Why the AI flagged it", target: "#tdetail .panel",
      text: `The AI explains itself with numbers anyone can read, for example "asked for 150 different web pages (normally at most 13)". It compares this address with the normal behaviour it learned.` },
    { title: "The evidence", target: "#tdetail .logview",
      text: `The actual log lines behind the alert, so a person can check it in seconds. Switch between plain words and the original lines.` },
    { title: "Teach the AI", target: "#tdetail .actbar", action: "Mark it as a real threat",
      text: `This is how the AI <b>learns and adapts</b>. Marking a threat <b>real</b> makes it more watchful of that behaviour; marking a <b>false alarm</b> makes it calmer. Your answers are its reward signal.`,
      run: async () => {
        const id = T.data.theft && T.data.theft.alert_id;
        if (!id) return `There's no data theft alert to teach with. Press Next to carry on.`;
        const r = await post(`/api/m/alerts/${id}/status`, { status: "real" });
        window.APP.route();
        return r.lessons && r.lessons.length ? `<b>The AI learned:</b><br>${r.lessons.map(esc).join("<br>")}` : `Saved. It had already learned this.`;
      } },
    { title: "What the AI has learned", page: "#/ai", target: ".dials",
      text: `Each slider is how watchful the AI is about one kind of behaviour. The grey tick is where it started; your answer moved "grabbing many web pages" towards <b>more watchful</b>. The lessons are saved and shared by every connection.` },
    { title: "Attack 3: sneaky data theft", page: "#/lab", target: '[data-kind="sneaky_theft"]', action: "Launch the sneaky theft",
      text: `A slower theft, designed to stay under the radar. Before your lesson the AI let this through. Now that you've taught it, let's see.`,
      run: async (say) => { await ensureLab(say); const x = await launchAndWait("sneaky_theft", say, 110); T.data.sneaky = x; return caught(x) + (x.detected ? `<br>This was only caught <b>because you taught the AI</b>.` : ""); } },
    { title: "Research results on real data", page: "#/research", target: ".hero",
      text: `The research part of the project. The same methods run on <b>HDFS_v1</b>, a public dataset of 11 million real log lines with an official answer key. This page shows what was found.` },
    { title: "How often it's right", page: "#/accuracy", target: ".acc",
      text: `Checked fairly: the models learned from the older 70% of the logs and were tested on the newer 30%. Each dot is a real problem: filled if caught, hollow if missed.` },
    { title: "That's the tour", page: "#/monitor",
      text: `You've seen it read logs, catch known attacks in seconds, catch an unknown one with AI, explain every alert with evidence, and <b>learn from your answers</b>.
             <br><br>Tip: switch on <b>Show technical terms</b> (top right) to see the algorithm names (Drain3, Isolation Forest, Random Forest) and MITRE ATT&CK codes. <b>The AI does a first check. A person still decides what matters.</b>` },
  ];

  // ---------------------------------------------------------------- overlay
  const ui = document.createElement("div");
  ui.className = "tour";
  ui.hidden = true;
  ui.innerHTML = `<div class="tour-spot" id="tourSpot"></div>
    <div class="tour-card" id="tourCard" role="dialog" aria-live="polite" aria-labelledby="tourTitle">
      <div class="tour-top"><span id="tourCount"></span><button class="tour-x" id="tourExit" aria-label="Exit the tour">Exit tour</button></div>
      <div class="tour-bar"><span id="tourProg"></span></div>
      <h3 id="tourTitle"></h3><div id="tourText"></div><div id="tourResult" class="tour-result" hidden></div>
      <div class="tour-btns"><button class="btn small ghost" id="tourBack">Back</button><button class="btn small primary" id="tourNext">Next</button></div>
    </div>`;
  document.body.appendChild(ui);
  const spot = $("#tourSpot"), card = $("#tourCard");
  let target = null;

  function place() {
    if (!T.on) return;
    const vw = innerWidth, vh = innerHeight, cw = Math.min(400, vw - 24);
    card.style.width = cw + "px";
    if (!target || !document.body.contains(target)) {
      spot.style.cssText = "left:50%;top:50%;width:0;height:0";
      card.style.left = (vw - cw) / 2 + "px"; card.style.top = Math.max(16, (vh - card.offsetHeight) / 2) + "px";
      return;
    }
    const r = target.getBoundingClientRect(), pad = 8;
    spot.style.cssText = `left:${r.left - pad}px;top:${r.top - pad}px;width:${r.width + pad * 2}px;height:${r.height + pad * 2}px`;
    const ch = card.offsetHeight;
    let left = Math.min(Math.max(12, r.left), vw - cw - 12), top;
    if (r.bottom + pad + 14 + ch < vh) top = r.bottom + pad + 14;
    else if (r.top - pad - 14 - ch > 0) top = r.top - pad - 14 - ch;
    else if (r.right + 24 + cw < vw) { left = r.right + 24; top = Math.max(12, Math.min(vh - ch - 12, r.top)); }
    else if (r.left - 24 - cw > 0) { left = r.left - 24 - cw; top = Math.max(12, Math.min(vh - ch - 12, r.top)); }
    else top = vh - ch - 12;
    card.style.left = left + "px"; card.style.top = top + "px";
  }
  addEventListener("resize", place);
  addEventListener("scroll", place, true);

  async function show(i) {
    T.i = i;
    const s = STEPS[i];
    $("#tourCount").textContent = `Step ${i + 1} of ${STEPS.length}`;
    $("#tourProg").style.width = `${((i + 1) / STEPS.length) * 100}%`;
    $("#tourTitle").textContent = s.title;
    $("#tourText").innerHTML = s.text;
    $("#tourResult").hidden = true;
    $("#tourBack").disabled = i === 0;
    $("#tourNext").textContent = s.action || (i === STEPS.length - 1 ? "Finish" : "Next");
    s.done = false;
    target = null; place();
    const page = typeof s.page === "function" ? s.page() : s.page;
    if (page || s.target) {
      target = await go(page || location.hash, s.target);
      if (!T.on || T.i !== i) return;
      if (target) target.scrollIntoView({ block: "center", behavior: "smooth" });
      await wait(450);
      place();
    }
    const fresh = $("#tourFresh");
    if (fresh) fresh.checked = T.fresh, fresh.onchange = (e) => (T.fresh = e.target.checked);
  }

  async function next() {
    if (T.busy) return;
    const s = STEPS[T.i];
    if (T.i === 0 && T.fresh) { await post("/api/m/ai/reset").catch(() => {}); }
    if (s.run && !s.done) {
      T.busy = true;
      const btn = $("#tourNext"), res = $("#tourResult");
      btn.disabled = true; $("#tourBack").disabled = true;
      res.hidden = false;
      const say = (t) => { res.innerHTML = `<span class="spinner"></span>${esc(t)}`; place(); };
      say("Working…");
      try { res.innerHTML = await s.run(say); } catch (e) { res.innerHTML = `Something went wrong: ${esc(e.message)}. Press Next to carry on.`; }
      s.done = true; T.busy = false;
      btn.disabled = false; $("#tourBack").disabled = T.i === 0;
      btn.textContent = T.i === STEPS.length - 1 ? "Finish" : "Next";
      if (s.target) { target = document.querySelector(s.target) || target; }
      place();
      return;
    }
    if (T.i >= STEPS.length - 1) return stop();
    show(T.i + 1);
  }

  function start() {
    T.on = true; T.data = {}; T.fresh = false;
    STEPS.forEach((s) => (s.done = false));
    ui.hidden = false;
    document.body.classList.add("touring");
    show(0);
  }
  function stop() {
    T.on = false; T.busy = false;
    ui.hidden = true;
    document.body.classList.remove("touring");
  }

  $("#tourNext").addEventListener("click", next);
  $("#tourBack").addEventListener("click", () => { if (!T.busy && T.i > 0) show(T.i - 1); });
  $("#tourExit").addEventListener("click", stop);
  addEventListener("keydown", (e) => {
    if (!T.on) return;
    if (e.key === "Escape") stop();
    else if (e.key === "ArrowRight" && !e.target.matches("input")) next();
    else if (e.key === "ArrowLeft" && !e.target.matches("input") && !T.busy && T.i > 0) show(T.i - 1);
  });
  window.TOUR = { start, stop };
  document.addEventListener("click", (e) => { if (e.target.closest("[data-tour]")) { e.preventDefault(); start(); } });
})();

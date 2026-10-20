"use strict";

// Core of the front end: shared helpers, the case form, live scan state fed by
// Server-Sent Events, the details drawer. Rendering of the result views lives in
// views.js and graph.js.
//
// Security: all untrusted text (scraped titles, URLs, snippets) is inserted with
// textContent / setAttribute only, never innerHTML. Links are limited to http(s)
// and get rel="noopener noreferrer".

window.RT = window.RT || {};
const $ = (id) => document.getElementById(id);
RT.$ = $;
const HDR = { "Content-Type": "application/json", "X-Requested-With": "rectool" };

RT.el = function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k === "style") e.style.cssText = v; // CSSOM is allowed by the CSP; a style="" attribute is not
    else e.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) e.append(k);
  return e;
};
const el = RT.el;

RT.api = async function api(path, opts = {}) {
  const r = await fetch(path, { credentials: "same-origin", ...opts, headers: { ...HDR, ...(opts.headers || {}) } });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
};

RT.safeHref = function safeHref(u) {
  try { const x = new URL(u); return x.protocol === "http:" || x.protocol === "https:" ? x.href : null; } catch { return null; }
};
RT.pct = (c) => Math.round((c || 0) * 100);
RT.confClass = (p) => (p >= 80 ? "hi" : p >= 50 ? "mid" : "lo");
RT.clip = (s, n) => (s && s.length > n ? s.slice(0, n) + "…" : s || "");
RT.debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

// ------------------------------------------------------------- hint buttons
RT.infoBtn = function infoBtn(key) {
  const h = RT.HINTS[key];
  if (!h) return null;
  const tip = el("span", { class: "tipbox", role: "tooltip" }, el("span", { class: "en", text: h.en }), el("span", { class: "ar", lang: "ar", dir: "rtl", text: h.ar }));
  const b = el("button", { type: "button", class: "info", "aria-label": "What does this do?" }, "i", tip);
  // The tooltip is position:fixed so it is never clipped by the scrolling side
  // panel; place it next to the button and keep it inside the viewport.
  const place = () => requestAnimationFrame(() => {
    const r = b.getBoundingClientRect();
    const w = Math.min(320, window.innerWidth - 24);
    tip.style.width = w + "px";
    let left = Math.max(12, Math.min(r.left - 8, window.innerWidth - 12 - w));
    let top = r.bottom + 8;
    if (top + tip.offsetHeight > window.innerHeight - 12) top = Math.max(12, r.top - tip.offsetHeight - 8);
    tip.style.left = left + "px";
    tip.style.top = top + "px";
  });
  b.addEventListener("mouseenter", place);
  b.addEventListener("focus", place);
  b.addEventListener("click", (e) => {
    e.preventDefault(); e.stopPropagation();
    const was = b.classList.contains("open");
    document.querySelectorAll(".info.open").forEach((x) => x.classList.remove("open"));
    if (!was) { b.classList.add("open"); place(); }
  });
  return b;
};
document.addEventListener("click", () => document.querySelectorAll(".info.open").forEach((x) => x.classList.remove("open")));
// A fixed tooltip would drift away from its button when the page scrolls.
window.addEventListener("scroll", () => document.querySelectorAll(".info.open").forEach((x) => x.classList.remove("open")), true);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { document.querySelectorAll(".info.open").forEach((x) => x.classList.remove("open")); RT.closeDrawer(); } });

// --------------------------------------------------------------- form build
RT.FIELDS = [
  { group: "Person", items: [
    { name: "full_name", label: "Full name", ph: "John Doe" },
    { name: "username", label: "Username / handle", ph: "johndoe", mono: 1 },
    { name: "alias", label: "Nickname / alias", ph: "Dark Knight" },
    { name: "email", label: "E-mail", ph: "john@example.com", mono: 1 },
    { name: "phone", label: "Phone", ph: "+15551234567", mono: 1 },
  ] },
  { group: "Infrastructure", items: [
    { name: "domain", label: "Domain, website or profile link", ph: "example.com · https://x.com/handle", mono: 1 },
    { name: "ip", label: "IP address", ph: "203.0.113.10", mono: 1 },
    { name: "asn", label: "ASN", ph: "AS13335", mono: 1 },
    { name: "wallet", label: "Crypto wallet", ph: "bc1q… or 0x…", mono: 1 },
  ] },
  { group: "Organisation & place", items: [
    { name: "company", label: "Company / organisation", ph: "Example Inc" },
    { name: "location", label: "Location", ph: "Cairo, Egypt" },
  ] },
];
RT.MODULE_NEEDS = {
  social: "username", profiles: "username", domain: "domain", ip: "IP", asn: "ASN", company: "company", people: "full name", images: "name or username", activity: "username", breach: "e-mail",
  footprint: "e-mail / phone", phone: "phone", crypto: "wallet", dorks: "anything", syswrap: "domain / username",
};
RT.MODULE_ORDER = ["social", "profiles", "footprint", "phone", "domain", "ip", "asn", "company", "people", "images", "activity", "breach", "crypto", "dorks", "syswrap"];

RT.buildForm = function buildForm(info) {
  const fields = $("fields");
  fields.replaceChildren();
  for (const g of RT.FIELDS) {
    fields.append(el("div", { class: "group", text: g.group }));
    for (const f of g.items) {
      const input = el("input", { name: f.name, maxlength: "200", placeholder: f.ph, spellcheck: "false", autocomplete: "off", class: f.mono ? "mono-in" : "" });
      const label = el("label", { for: "f_" + f.name }, el("span", { text: f.label }), RT.infoBtn(f.name));
      input.id = "f_" + f.name;
      fields.append(el("div", { class: "field" }, label, input));
    }
  }

  fields.append(el("div", { class: "group", text: "Evidence you already have" }));
  const notesLabel = el("label", { for: "f_notes" }, el("span", { text: "Paste text (CV, LinkedIn page, bio…)" }), RT.infoBtn("notes"));
  const notes = el("textarea", { name: "notes", id: "f_notes", rows: "3", maxlength: "30000", class: "notes", placeholder: "Optional. Text you copied from a source rectool cannot open." });
  fields.append(el("div", { class: "field" }, notesLabel, notes));

  const check = (name, title, sub, checked) => {
    const cb = el("input", { type: "checkbox", name });
    if (checked) cb.checked = true;
    return el("label", { class: "check" }, cb, el("span", { class: "t" }, el("b", { text: title }), el("small", { text: sub })), RT.infoBtn(name));
  };
  $("intensity").replaceChildren(check("aggressive", "Aggressive", "maximum coverage, slower, many more requests", true));
  $("options").replaceChildren(
    check("verify", "Verify social hits", "canary test removes false positives", false),
    check("derive", "Derive usernames from the name", "jdoe, john.doe, johnd…", false),
    check("no_pivot", "Don't follow discovered leads", "first pass only", false),
    check("browser", "Use local browser for LinkedIn", "headless Chrome/Edge, logged-out view", false),
  );
  $("proxiesInfo").replaceChildren(" ", RT.infoBtn("proxies"));

  const box = $("modules");
  box.replaceChildren();
  const mods = [...info.modules].sort((a, b) => RT.MODULE_ORDER.indexOf(a.name) - RT.MODULE_ORDER.indexOf(b.name));
  const tools = el("div", { class: "mods-tools" },
    el("button", { type: "button", class: "ghost small", text: "All", id: "modAll" }),
    el("button", { type: "button", class: "ghost small", text: "None", id: "modNone" }));
  box.append(tools);
  for (const m of mods) {
    const cb = el("input", { type: "checkbox", name: "mod", value: m.name, checked: "" });
    box.append(el("label", { class: "check mod" }, cb,
      el("span", { class: "t" }, el("b", { text: m.name }), el("span", { class: "need", text: "needs " + (RT.MODULE_NEEDS[m.name] || "input") }), el("small", { text: m.description })),
      RT.infoBtn("mod:" + m.name)));
  }
  $("modAll").addEventListener("click", () => box.querySelectorAll('input[name="mod"]').forEach((c) => (c.checked = true)));
  $("modNone").addEventListener("click", () => box.querySelectorAll('input[name="mod"]').forEach((c) => (c.checked = false)));
};

RT.showFormError = function showFormError(msg) {
  const b = $("formError");
  b.hidden = !msg;
  b.textContent = msg || "";
};

RT.bindForm = function bindForm() {
  $("form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    RT.showFormError("");
    const f = ev.target;
    const mods = [...f.querySelectorAll('input[name="mod"]')];
    const chosen = mods.filter((m) => m.checked).map((m) => m.value);
    if (chosen.length === 0) return RT.showFormError("Select at least one collector.");
    const v = (n) => f.elements[n].value;
    const body = {
      full_name: v("full_name"), username: v("username"), alias: v("alias"), email: v("email"), phone: v("phone"),
      domain: v("domain"), ip: v("ip"), asn: v("asn"), wallet: v("wallet"), company: v("company"), location: v("location"), notes: v("notes"),
      modules: chosen.length === mods.length ? [] : chosen,
      aggressive: f.elements["aggressive"].checked, verify: f.elements["verify"].checked,
      derive: f.elements["derive"].checked, browser: f.elements["browser"].checked, no_pivot: f.elements["no_pivot"].checked,
      proxies: f.elements["proxies"].value.split("\n").map((s) => s.trim()).filter(Boolean),
    };
    $("startBtn").disabled = true;
    try {
      const s = await RT.api("/api/scans", { method: "POST", body: JSON.stringify(body) });
      RT.openScan(s.id);
      RT.refreshHistory();
    } catch (e) {
      RT.showFormError(e.message);
    } finally {
      $("startBtn").disabled = false;
    }
  });
  $("clearBtn").addEventListener("click", () => {
    document.querySelectorAll("#fields input, #fields textarea").forEach((i) => (i.value = ""));
    RT.showFormError("");
  });
};

// ------------------------------------------------------------------ history
RT.refreshHistory = async function refreshHistory() {
  let list;
  try { list = await RT.api("/api/scans"); $("conn").className = "led ok"; } catch { $("conn").className = "led bad"; return; }
  const ul = $("history");
  ul.replaceChildren();
  if (list.length === 0) ul.append(el("li", { class: "muted", text: "No cases yet." }));
  for (const s of list) {
    const t = s.target;
    const label = t.domain || t.username || t.email || t.full_name || t.alias || t.company || t.ip || t.asn || t.wallet || t.phone || s.id;
    const li = el("li", RT.S && RT.S.id === s.id ? { class: "active" } : {});
    const b = el("button", { type: "button" }, el("span", { class: "t", text: label }), el("span", { class: "badge " + s.state, text: s.state }));
    b.addEventListener("click", () => RT.openScan(s.id));
    li.append(b);
    ul.append(li);
  }
};

// -------------------------------------------------------------- scan state
RT.newState = (id) => ({ id, es: null, findings: [], entities: new Map(), target: {}, report: null, progress: {}, state: "running", failuresLive: 0 });

RT.openScan = function openScan(id) {
  if (RT.S && RT.S.es) RT.S.es.close();
  const S = (RT.S = RT.newState(id));
  sessionStorage.setItem("rectool_last", id);
  RT.closeDrawer();

  $("empty").hidden = true;
  $("run").hidden = false;
  $("exports").hidden = true;
  $("bars").replaceChildren();
  $("caseTitle").textContent = "Case " + id;
  $("targetChips").replaceChildren();
  RT.setState("running");
  RT.resetViews();
  RT.selectTab("identity");

  RT.api("/api/scans/" + id).then((s) => { S.target = s.target; RT.renderTargetChips(); RT.scheduleRender(); }).catch(() => {});

  const es = new EventSource("/api/scans/" + id + "/events");
  S.es = es;
  es.addEventListener("finding", (e) => RT.addFinding(JSON.parse(e.data)));
  es.addEventListener("progress", (e) => RT.onProgress(JSON.parse(e.data)));
  es.addEventListener("identities", (e) => RT.onIdentities(JSON.parse(e.data)));
  es.addEventListener("done", (e) => { RT.onDone(JSON.parse(e.data)); es.close(); });
  es.addEventListener("error", (e) => {
    if (e.data) { RT.onFailed(JSON.parse(e.data).error); es.close(); }
    // otherwise a transient network error: EventSource reconnects with Last-Event-ID
  });
  RT.refreshHistory();
};

RT.setState = function setState(s) {
  if (RT.S) RT.S.state = s;
  const b = $("state");
  b.textContent = s;
  b.className = "badge " + s;
  $("cancelBtn").hidden = s !== "running";
};

RT.renderTargetChips = function renderTargetChips() {
  const t = RT.S.target || {};
  const box = $("targetChips");
  box.replaceChildren();
  const labels = { full_name: "name", username: "user", alias: "alias", email: "email", phone: "phone", domain: "domain", ip: "ip", asn: "asn", wallet: "wallet", company: "company", location: "place" };
  for (const [k, lab] of Object.entries(labels)) {
    if (t[k]) box.append(el("span", { class: "chip strong" }, el("span", { class: "k", text: lab }), el("span", { text: t[k] })));
  }
};

RT.addFinding = function addFinding(f) {
  const S = RT.S;
  S.findings.push(f);
  for (const e of f.entities || []) {
    const key = e.type + ":" + e.value.toLowerCase();
    const have = S.entities.get(key);
    if (!have) S.entities.set(key, { ...e, findings: [f] });
    else { have.strong = have.strong || e.strong; have.findings.push(f); }
  }
  RT.scheduleRender();
};

RT.onIdentities = function onIdentities(d) {
  const S = RT.S;
  S.identities = d.identities || [];
  S.ambiguity = d.ambiguity || "";
  S.sameName = d.same_name || 0;
  RT.scheduleRender();
};

RT.onProgress = function onProgress(p) {
  RT.S.progress = p;
  const bars = $("bars");
  let sum = 0, n = 0, finished = 0;
  for (const [mod, [done, total]] of Object.entries(p)) {
    let row = bars.querySelector('[data-mod="' + CSS.escape(mod) + '"]');
    if (!row) {
      row = el("div", { class: "bar", "data-mod": mod }, el("span", { text: mod }), el("div", { class: "track" }, el("div", { class: "fill" })), el("span", { class: "num" }));
      bars.append(row);
    }
    const frac = total > 0 ? Math.min(1, done / total) : 0;
    row.querySelector(".fill").style.width = Math.round(frac * 100) + "%";
    row.querySelector(".num").textContent = done + "/" + total;
    sum += frac; n++;
    if (frac >= 1) finished++;
  }
  const overall = n ? sum / n : 0;
  $("overallFill").style.width = Math.round(overall * 100) + "%";
  $("overallText").textContent = n ? `${finished}/${n} collectors finished · ${RT.S.findings.length} findings · ${RT.S.entities.size} entities` : "starting…";
};

RT.onDone = function onDone(rep) {
  const S = RT.S;
  S.report = rep;
  S.target = rep.target || S.target;
  if (rep.identities) { S.identities = rep.identities; S.ambiguity = rep.ambiguity || ""; }
  RT.setState(rep.interrupted ? "cancelled" : "done");
  RT.renderTargetChips();
  const id = S.id;
  $("expJson").href = `/api/scans/${id}/export?format=json`;
  $("expCsv").href = `/api/scans/${id}/export?format=csv`;
  $("expTxt").href = `/api/scans/${id}/export?format=txt`;
  $("expHtml").href = `/api/scans/${id}/export?format=html`;
  $("expGraphml").href = `/api/scans/${id}/export?format=graphml`;
  $("expStix").href = `/api/scans/${id}/export?format=stix`;
  $("expEntities").href = `/api/scans/${id}/export?format=entities`;
  $("exports").hidden = false;
  if (!rep.interrupted) {
    $("overallFill").style.width = "100%";
    for (const f of $("bars").querySelectorAll(".fill")) f.style.width = "100%";
  }
  $("overallText").textContent = `${rep.interrupted ? "stopped" : "complete"} · ${S.findings.length} findings · ${(rep.entities || []).length || S.entities.size} entities`;
  RT.scheduleRender(true);
  RT.refreshHistory();
};

RT.onFailed = function onFailed(msg) {
  RT.setState("failed");
  $("overallText").textContent = "failed: " + msg;
  RT.refreshHistory();
};

// ------------------------------------------------------------------- tabs
RT.selectTab = function selectTab(name) {
  RT.tab = name;
  document.querySelectorAll(".tab").forEach((t) => {
    const on = t.dataset.tab === name;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", on ? "true" : "false");
  });
  document.querySelectorAll(".tabpanel").forEach((p) => (p.hidden = p.id !== "tab-" + name));
  RT.scheduleRender(true);
};

RT.scheduleRender = (() => {
  let timer = null;
  return function schedule(now) {
    if (now) { clearTimeout(timer); timer = null; RT.render(); return; }
    if (timer) return;
    timer = setTimeout(() => { timer = null; RT.render(); }, 450);
  };
})();

RT.render = function render() {
  if (!RT.S) return;
  $("tabCount").textContent = String(RT.S.findings.length);
  $("photoCount").textContent = String(RT.photoList().length);
  $("idCount").textContent = String((RT.S.identities || []).length);
  const gaps = RT.S.report ? (RT.S.report.failures || []).length : 0;
  const lg = RT.S.report && RT.S.report.geo;
  $("locCount").hidden = !lg;
  if (lg) $("locCount").textContent = String((lg.points || []).length);
  $("gapCount").hidden = gaps === 0;
  $("gapCount").textContent = String(gaps);
  const v = RT.views;
  if (!v) return;
  if (RT.tab === "identity") v.identity();
  else if (RT.tab === "overview") v.overview();
  else if (RT.tab === "tree") v.tree();
  else if (RT.tab === "graph") RT.graph && RT.graph.update();
  else if (RT.tab === "photos") v.photos();
  else if (RT.tab === "location") v.location && v.location();
  else if (RT.tab === "findings") v.findings();
  else if (RT.tab === "coverage") v.coverage();
};

// ------------------------------------------------------------------ drawer
RT.closeDrawer = function closeDrawer() { $("drawer").hidden = true; };

RT.kvTable = function kvTable(obj) {
  const box = el("div", { class: "kv" });
  for (const [k, v] of Object.entries(obj || {})) {
    box.append(el("div", { class: "k", text: k }));
    const href = typeof v === "string" && /^https?:\/\/\S+$/.test(v) ? RT.safeHref(v) : null;
    box.append(href ? el("div", { class: "v" }, el("a", { href, target: "_blank", rel: "noopener noreferrer", text: v })) : el("div", { class: "v", text: String(v) }));
  }
  return box;
};

RT.showFinding = function showFinding(f) {
  $("drawerTitle").textContent = f.source;
  const body = $("drawerBody");
  body.replaceChildren();
  const p = RT.pct(f.confidence);
  const meta = { collector: f.module, category: f.category || "—", status: f.status, confidence: p + "%" };
  if (f.via) meta["found by following"] = f.via;
  if (f.timestamp) meta.collected = f.timestamp;
  if (f.url) meta.url = f.url;
  body.append(el("div", { class: "sec" }, el("h4", { text: "Overview" }), RT.kvTable(meta)));
  if (f.details && Object.keys(f.details).length) body.append(el("div", { class: "sec" }, el("h4", { text: "Evidence" }), RT.kvTable(f.details)));
  if (f.entities && f.entities.length) {
    const chips = el("div", { class: "chips" });
    for (const e of f.entities) chips.append(RT.entityChip(e));
    body.append(el("div", { class: "sec" }, el("h4", { text: "Leads discovered here" }), chips));
  }
  body.append(el("div", { class: "sec" }, el("details", {}, el("summary", { text: "Raw record (JSON)" }), el("pre", { class: "mono", text: JSON.stringify(f, null, 2) }))));
  $("drawer").hidden = false;
};

RT.showEntity = function showEntity(e) {
  $("drawerTitle").textContent = e.value;
  const body = $("drawerBody");
  body.replaceChildren();
  const key = e.type + ":" + e.value.toLowerCase();
  const full = (RT.S && RT.S.entities.get(key)) || e;
  body.append(el("div", { class: "sec" }, el("h4", { text: "Entity" }), RT.kvTable({
    type: e.type, value: e.value, attribution: full.strong ? "strong lead (followed automatically)" : "weak lead (listed, not followed)",
    "first seen in": full.source || "—",
  })));
  const list = el("div", { class: "facts" });
  for (const f of (full.findings || []).slice(0, 40)) {
    const b = el("button", { type: "button", class: "chip", title: f.source }, el("span", { class: "k", text: f.module }), el("span", { text: RT.clip(f.source, 60) }));
    b.addEventListener("click", () => RT.showFinding(f));
    list.append(b);
  }
  body.append(el("div", { class: "sec" }, el("h4", { text: `Mentioned in ${(full.findings || []).length} finding(s)` }), list));
  const via = RT.S ? RT.S.findings.filter((f) => f.via === key.replace(/^(\w+):/, "$1:") || (f.via || "").toLowerCase() === key).slice(0, 40) : [];
  if (via.length) {
    const l2 = el("div", { class: "facts" });
    for (const f of via) {
      const b = el("button", { type: "button", class: "chip" }, el("span", { class: "k", text: f.module }), el("span", { text: RT.clip(f.source, 60) }));
      b.addEventListener("click", () => RT.showFinding(f));
      l2.append(b);
    }
    body.append(el("div", { class: "sec" }, el("h4", { text: "Found by investigating it" }), l2));
  }
  $("drawer").hidden = false;
};

// ------------------------------------------------------------------ photos
RT.imgSrc = (u) => "/api/img?u=" + encodeURIComponent(u);

// Pictures found so far: live from image entities, enriched with size / hash /
// "same picture" group once the final report is in.
RT.photoList = function photoList() {
  const S = RT.S;
  if (!S) return [];
  const rep = new Map(((S.report && S.report.photos) || []).map((p) => [p.url, p]));
  const out = [];
  for (const e of S.entities.values()) {
    if (e.type !== "image") continue;
    const r = rep.get(e.value) || {};
    const sources = (e.findings || []).map((f) => f.source);
    out.push({ url: e.value, sources: r.sources && r.sources.length ? r.sources : sources, group: r.group || 0, width: r.width, height: r.height, bytes: r.bytes, sha256: r.sha256, dhash: r.dhash, error: r.error });
  }
  out.sort((a, b) => (b.group > 0) - (a.group > 0) || a.group - b.group || (a.error ? 1 : 0) - (b.error ? 1 : 0));
  return out;
};

RT.showPhoto = function showPhoto(p) {
  $("drawerTitle").textContent = "Photo";
  const body = $("drawerBody");
  body.replaceChildren();
  const img = el("img", { class: "bigimg", alt: "profile picture", src: RT.imgSrc(p.url) });
  img.addEventListener("error", () => img.replaceWith(el("div", { class: "muted", text: "The image could not be loaded (the host may have removed it or blocked the download)." })));
  body.append(img);
  const meta = { "found at": (p.sources || []).join("  ·  ") || "—" };
  if (p.width) meta.size = p.width + " × " + p.height + " px, " + Math.round((p.bytes || 0) / 1024) + " KB";
  if (p.group) meta["same picture"] = "group " + p.group + " — identical or near-identical picture used by several sources";
  if (p.sha256) meta.sha256 = p.sha256;
  if (p.dhash) meta["perceptual hash"] = p.dhash;
  body.append(el("div", { class: "sec" }, el("h4", { text: "Details" }), RT.kvTable(meta)));
  const u = encodeURIComponent(p.url);
  const links = [
    ["Google Lens", "https://lens.google.com/uploadbyurl?url=" + u],
    ["Yandex Images", "https://yandex.com/images/search?rpt=imageview&url=" + u],
    ["TinEye", "https://tineye.com/search?url=" + u],
    ["Bing Visual Search", "https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:" + u],
  ];
  const row = el("div", { class: "rlinks" });
  for (const [label, href] of links) row.append(el("a", { class: "btn", href, target: "_blank", rel: "noopener noreferrer", text: label }));
  body.append(el("div", { class: "sec" }, el("h4", { text: "Reverse image search (opens an external site)" }), row,
    el("p", { class: "hint-line", text: "Sends this picture's address to that service. Reverse search finds other places the same photo appears: the strongest way to tie accounts together or spot a stolen photo." })));
  const href = RT.safeHref(p.url);
  if (href) body.append(el("div", { class: "sec" }, el("h4", { text: "Original" }), el("a", { href, target: "_blank", rel: "noopener noreferrer", text: p.url })));
  $("drawer").hidden = false;
};

// Fill the case form from a candidate identity and run again: the way to turn
// "several people match" into one confident answer.
RT.refine = function refine(id) {
  const first = (facts) => (facts && facts[0] ? facts[0].value : "");
  const set = (name, value) => { const f = document.getElementById("f_" + name); if (f && value) f.value = value; };
  set("full_name", first(id.names));
  set("location", first(id.locations));
  set("company", first(id.employers));
  set("email", first(id.emails));
  const user = (id.usernames || []).map((u) => u.value.split(":")[1]).find(Boolean);
  set("username", user);
  set("domain", (id.websites || []).map((w) => w.value)[0]);
  document.getElementById("form").scrollIntoView({ behavior: "smooth" });
  RT.showFormError("");
  document.getElementById("startBtn").focus();
};

RT.entityChip = function entityChip(e) {
  const b = el("button", { type: "button", class: "chip " + (e.strong ? "strong" : "weak"), title: e.source || "" },
    el("span", { class: "k", text: e.type }), el("span", { text: e.value }));
  b.addEventListener("click", () => RT.showEntity(e));
  return b;
};

$("drawerClose").addEventListener("click", RT.closeDrawer);
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => RT.selectTab(t.dataset.tab)));
$("cancelBtn").addEventListener("click", async () => {
  if (!RT.S) return;
  try { await RT.api("/api/scans/" + RT.S.id + "/cancel", { method: "POST", body: "{}" }); } catch (e) { alert(e.message); }
});

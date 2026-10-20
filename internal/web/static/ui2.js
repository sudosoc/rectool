"use strict";

// UI layer added on top of the core views: theme switch, first-use notice,
// global search, analyst notes, live collector chips and shared preferences.
(function () {
  const { $, el } = RT;

  // ------------------------------------------------------------ preferences
  const store = {
    get(k, d) { try { const v = localStorage.getItem("rectool_" + k); return v === null ? d : v; } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem("rectool_" + k, v); } catch (e) { /* private mode */ } },
  };
  RT.store = store;
  RT.ui = { full: store.get("full", "0") === "1" };

  // ------------------------------------------------------------------ theme
  const root = document.documentElement;
  const THEMES = ["auto", "light", "dark"];
  let theme = store.get("theme", "auto");
  const themeBtn = el("button", { type: "button", class: "ghost small", id: "themeBtn" });
  function applyTheme() {
    if (theme === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", theme);
    themeBtn.textContent = { auto: "◐ Auto", light: "☀ Light", dark: "☾ Dark" }[theme];
    themeBtn.title = "Colour theme: auto follows your system. Click to change.";
    if (RT.S) { RT.scheduleRender(true); if (RT.graph && RT.tab === "graph") RT.graph.update(); }
  }
  themeBtn.addEventListener("click", () => { theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length]; store.set("theme", theme); applyTheme(); });

  // ----------------------------------------------------------------- search
  const search = el("input", { type: "search", id: "gsearch", placeholder: "Search everything…  ( / )", "aria-label": "Search every result", autocomplete: "off", spellcheck: "false" });
  const tools = el("div", { class: "top-tools" }, search, themeBtn);
  const topRight = document.querySelector(".top-right");
  topRight.prepend(tools);
  applyTheme();

  function marked(text, q) {
    const out = document.createElement("span");
    const low = text.toLowerCase();
    let i = 0;
    for (;;) {
      const j = low.indexOf(q, i);
      if (j < 0) { out.append(document.createTextNode(text.slice(i))); break; }
      out.append(document.createTextNode(text.slice(i, j)), el("mark", { text: text.slice(j, j + q.length) }));
      i = j + q.length;
    }
    return out;
  }
  const snip = (s, q) => {
    const i = s.toLowerCase().indexOf(q);
    if (i < 0) return RT.clip(s, 120);
    const a = Math.max(0, i - 40);
    return (a ? "…" : "") + s.slice(a, i + q.length + 80) + (s.length > i + q.length + 80 ? "…" : "");
  };

  function runSearch() {
    const q = search.value.trim().toLowerCase();
    if (q.length < 2) return;
    const S = RT.S;
    $("drawerTitle").textContent = `Search: ${search.value.trim()}`;
    const body = $("drawerBody");
    body.replaceChildren();
    $("drawer").hidden = false;
    if (!S) { body.append(el("div", { class: "muted", text: "Open or start a case first." })); return; }
    const groups = [];
    const group = (title, items) => {
      if (!items.length) return;
      const g = el("div", { class: "sr-group" }, el("h4", { text: `${title} (${items.length})` }));
      items.slice(0, 25).forEach((x) => g.append(x));
      if (items.length > 25) g.append(el("div", { class: "hint-line", text: `… and ${items.length - 25} more; narrow the search.` }));
      groups.push(g);
    };
    const item = (label, text, onclick) => {
      const b = el("button", { type: "button", class: "ghost sr-item" }, el("b", { text: label + "  " }), marked(snip(text, q), q));
      b.addEventListener("click", onclick);
      return b;
    };

    const fi = [];
    for (const f of S.findings) {
      let hit = "";
      if ((f.source || "").toLowerCase().includes(q)) hit = f.source;
      else if ((f.url || "").toLowerCase().includes(q)) hit = f.url;
      else for (const [k, v] of Object.entries(f.details || {})) { if (String(v).toLowerCase().includes(q) || k.toLowerCase().includes(q)) { hit = k + ": " + v; break; } }
      if (hit) fi.push(item(`${f.module}/${f.source}`, hit, () => RT.showFinding(f)));
    }
    group("Findings", fi);

    const ei = [];
    for (const e of S.entities.values()) if (e.value.toLowerCase().includes(q)) ei.push(item(e.type, e.value, () => RT.showEntity(e)));
    group("Entities", ei);

    const ii = [];
    for (const id of S.identities || []) {
      for (const k of ["names", "headlines", "employers", "locations", "education", "interests", "emails", "phones", "usernames", "websites"]) {
        for (const f of id[k] || []) if (f.value.toLowerCase().includes(q)) ii.push(item(`${id.label} · ${k}`, f.value, () => RT.selectTab("identity")));
      }
    }
    group("People", ii);

    const rep = S.report || {};
    const gi = ((rep.geo && rep.geo.points) || []).filter((p) => (p.label + " " + (p.place || "")).toLowerCase().includes(q)).map((p) => item("location · " + p.kind, p.label + (p.place ? " → " + p.place : ""), () => RT.selectTab("location")));
    group("Locations", gi);
    const ti = (rep.timeline || []).filter((e) => (e.event + " " + e.source).toLowerCase().includes(q)).map((e) => item(e.date, e.event + " · " + e.source, () => RT.selectTab("identity")));
    group("Timeline", ti);
    const ni = Object.entries(rep.notes || {}).filter(([, t]) => t.toLowerCase().includes(q)).map(([k, t]) => item("note", t, () => {}));
    group("Notes", ni);

    if (!groups.length) body.append(el("div", { class: "muted", text: "Nothing matches in this case." }));
    else groups.forEach((g) => body.append(g));
  }
  search.addEventListener("input", RT.debounce(runSearch, 250));
  search.addEventListener("keydown", (e) => { if (e.key === "Enter") runSearch(); if (e.key === "Escape") { search.value = ""; search.blur(); } });
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) { e.preventDefault(); search.focus(); search.select(); }
  });

  // ------------------------------------------------------------------ notes
  const saveTimers = new Map();
  RT.notes = {
    get(key) { const r = RT.S && RT.S.report; return (r && r.notes && r.notes[key]) || ""; },
    ready() { return !!(RT.S && RT.S.report && RT.S.state !== "running"); },
    set(key, text, status) {
      const S = RT.S;
      if (!S || !S.report) return;
      S.report.notes = S.report.notes || {};
      if (text.trim()) S.report.notes[key] = text; else delete S.report.notes[key];
      clearTimeout(saveTimers.get(key));
      const id = S.id;
      saveTimers.set(key, setTimeout(async () => {
        try { await RT.api(`/api/scans/${id}/notes`, { method: "POST", body: JSON.stringify({ key, text }) }); if (status) status.textContent = "saved with the case"; }
        catch (e) { if (status) status.textContent = "could not save: " + e.message; }
      }, 700));
    },
    // a textarea bound to one note key
    box(key, placeholder) {
      const wrap = el("div", {});
      if (!RT.notes.ready()) {
        wrap.append(el("div", { class: "notehint", text: "Notes can be added once the scan has finished." }));
        return wrap;
      }
      const ta = el("textarea", { class: "notebox", maxlength: "4000", placeholder: placeholder || "Your note (saved with the case and included in the reports)…" });
      ta.value = RT.notes.get(key);
      const st = el("span", { class: "notehint" });
      ta.addEventListener("input", () => { st.textContent = "saving…"; RT.notes.set(key, ta.value, st); });
      wrap.append(ta, st);
      return wrap;
    },
  };

  // ------------------------------------------------------ live collector chips
  const overall = document.querySelector(".overall");
  const chips = el("div", { class: "run-chips", id: "runChips" });
  if (overall) overall.append(chips);
  function renderChips() {
    const S = RT.S;
    chips.replaceChildren();
    if (!S) return;
    const mods = Object.entries(S.progress || {}).sort((a, b) => a[0].localeCompare(b[0]));
    for (const [name, p] of mods) {
      const done = p && p.length >= 2 && p[1] > 0 && p[0] >= p[1];
      const on = S.state === "running" && !done;
      chips.append(el("span", { class: "run-chip " + (done ? "done" : on ? "on" : "") }, on ? el("span", { class: "spin" }) : document.createTextNode(done ? "✓" : "·"), document.createTextNode(name + (p && p[1] ? ` ${p[0]}/${p[1]}` : ""))));
    }
  }
  const origProgress = RT.onProgress;
  RT.onProgress = function (p) { origProgress.call(this, p); renderChips(); };
  const origDone = RT.onDone;
  RT.onDone = function (rep) { origDone.call(this, rep); renderChips(); };
  RT.renderChips = renderChips;

  // ---------------------------------------------------------- first-use notice
  if (store.get("consent_v1", "") !== "yes") {
    const bg = el("div", { class: "modal-bg", role: "dialog", "aria-modal": "true", "aria-labelledby": "consentTitle" });
    const cb = el("input", { type: "checkbox", id: "consentCb" });
    const go = el("button", { type: "button", class: "primary", text: "I understand, continue", disabled: true });
    cb.addEventListener("change", () => { go.disabled = !cb.checked; });
    go.addEventListener("click", () => { store.set("consent_v1", "yes"); bg.remove(); });
    bg.append(el("div", { class: "modal" },
      el("h2", { id: "consentTitle", text: "Before you start" }),
      el("p", { text: "rectool gathers information that is already public. It is for lawful, authorised work such as security research, due diligence, journalism, and checking your own exposure." }),
      el("ul", {},
        el("li", { text: "Everything it shows is a lead. A name is not an identity: verify before you act on or share anything." }),
        el("li", { text: "It does not log in anywhere, solve CAPTCHAs, or look for home addresses. Do not use it to stalk, harass or profile private people." }),
        el("li", { text: "You are responsible for following the law and each site's terms where you operate." })),
      el("label", { class: "check" }, cb, el("span", { class: "t" }, el("b", { text: "I will use rectool only for lawful, authorised purposes." }))),
      el("div", { class: "actions-row" }, go)));
    document.body.append(bg);
    setTimeout(() => cb.focus(), 50);
  }
})();

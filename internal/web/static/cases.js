"use strict";

// Saved cases (re-open a finished scan, compare two runs) and side-by-side
// comparison of two candidate people.
(function () {
  const { $, el } = RT;

  const btn = el("button", { type: "button", class: "ghost small", id: "casesBtn", text: "Saved cases" });
  btn.title = "Every finished scan is saved on this machine. Re-open one, or compare two runs to see what changed.";
  document.querySelector(".top-right").prepend(btn);

  function open(title) {
    $("drawerTitle").textContent = title;
    const body = $("drawerBody");
    body.replaceChildren();
    $("drawer").hidden = false;
    return body;
  }

  const picked = new Set();

  async function showCases() {
    const body = open("Saved cases");
    body.append(el("p", { class: "hint-line", text: "Tick two cases and press Compare to see what was added or removed between them. Cases are stored in this machine's user data folder (mode 0600)." }));
    let list;
    try { list = await RT.api("/api/cases"); } catch (e) { body.append(el("div", { class: "muted", text: "Could not list cases: " + e.message })); return; }
    if (!list.length) { body.append(el("div", { class: "muted", text: "No saved cases yet. They appear here after a scan finishes." })); return; }
    const cmp = el("button", { type: "button", class: "ghost small", text: "Compare the two ticked cases", disabled: true });
    const sync = () => { cmp.disabled = picked.size !== 2; };
    cmp.addEventListener("click", () => compareCases([...picked]));
    body.append(cmp);
    for (const c of list) {
      const cb = el("input", { type: "checkbox" });
      cb.checked = picked.has(c.id);
      cb.addEventListener("change", () => { cb.checked ? picked.add(c.id) : picked.delete(c.id); if (picked.size > 2) { picked.delete([...picked][0]); showCases(); return; } sync(); });
      const open1 = el("button", { type: "button", class: "ghost small", text: "Open" });
      open1.addEventListener("click", async () => {
        try { const r = await RT.api("/api/cases/" + c.id + "/open", { method: "POST" }); RT.openScan(r.id); } catch (e) { alert(e.message); }
      });
      const del = el("button", { type: "button", class: "ghost small", text: "Delete" });
      del.addEventListener("click", async () => {
        if (!confirm("Delete this saved case from disk?")) return;
        try { await RT.api("/api/cases/" + c.id, { method: "DELETE" }); picked.delete(c.id); showCases(); } catch (e) { alert(e.message); }
      });
      body.append(el("div", { class: "frow" }, cb, el("div", {},
        el("b", { text: c.title || "(no identifiers)" }),
        el("div", { class: "muted", text: `${new Date(c.at).toLocaleString()} · ${c.findings} findings · ${c.identities} people${c.best ? " · best: " + c.best : ""}` }),
        el("div", { class: "chips" }, open1, del))));
    }
    sync();
  }

  const entKey = (e) => e.type + ": " + e.value;
  const finKey = (f) => (f.module || "") + " / " + f.source + (f.url ? " · " + f.url : "");

  async function compareCases(ids) {
    const body = open("Compare cases");
    body.append(el("div", { class: "muted", text: "loading…" }));
    let a, b;
    try { [a, b] = await Promise.all(ids.map((id) => RT.api("/api/cases/" + id))); } catch (e) { body.replaceChildren(el("div", { class: "muted", text: e.message })); return; }
    if (new Date(a.started_at) > new Date(b.started_at)) [a, b] = [b, a]; // a = older
    body.replaceChildren();
    body.append(el("p", {}, el("b", { text: "Older: " }), document.createTextNode(new Date(a.started_at).toLocaleString()),
      el("br"), el("b", { text: "Newer: " }), document.createTextNode(new Date(b.started_at).toLocaleString())));
    const diff = (xs, ys, key) => {
      const A = new Set(xs.map(key)), B = new Set(ys.map(key));
      return { added: [...B].filter((k) => !A.has(k)), removed: [...A].filter((k) => !B.has(k)) };
    };
    const hits = (r) => (r.findings || []).filter((f) => f.status === "found" || f.status === "uncertain");
    const sections = [
      ["Entities (e-mails, domains, accounts…)", diff(a.entities || [], b.entities || [], entKey)],
      ["Findings", diff(hits(a), hits(b), finKey)],
    ];
    const ga = a.geo && a.geo.consensus, gb = b.geo && b.geo.consensus;
    if (ga !== gb) body.append(el("div", { class: "conflict", text: `Location changed: ${ga || "none"} → ${gb || "none"}` }));
    const la = (a.identities && a.identities[0] || {}).label, lb = (b.identities && b.identities[0] || {}).label;
    if (la !== lb) body.append(el("div", { class: "conflict", text: `Best match changed: ${la || "none"} → ${lb || "none"}` }));
    for (const [title, d] of sections) {
      body.append(el("h4", { class: "sec-title", text: `${title}: +${d.added.length} / −${d.removed.length}` }));
      const ul = el("ul", { class: "reasons" });
      d.added.slice(0, 80).forEach((x) => ul.append(el("li", { class: "ok-line", text: "+ " + x })));
      d.removed.slice(0, 80).forEach((x) => ul.append(el("li", { class: "conflict", text: "− " + x })));
      if (!d.added.length && !d.removed.length) ul.append(el("li", { class: "muted", text: "no change" }));
      body.append(ul);
    }
  }

  // ------------------------------------------------- compare two candidates
  RT.compareIdentities = function compareIdentities(a, b) {
    const body = open("Compare people");
    const rows = [["headlines", "Role"], ["employers", "Employers"], ["locations", "Location"], ["education", "Education"], ["emails", "E-mail"],
      ["phones", "Phone"], ["usernames", "Accounts"], ["websites", "Websites"], ["interests", "Interests"]];
    const tbl = el("table", { class: "tbl" }, el("thead", {}, el("tr", {}, el("th", { text: "" }), el("th", { text: a.label }), el("th", { text: b.label }))));
    const tb = el("tbody");
    const norm = (s) => s.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim();
    const cell = (facts, others) => {
      const td = el("td");
      const set = new Set((others || []).map((f) => norm(f.value)));
      for (const f of (facts || []).slice(0, 6)) {
        const same = set.has(norm(f.value));
        td.append(el("div", { class: same ? "ok-line" : "", text: (same ? "= " : "") + f.value }));
      }
      return td;
    };
    tb.append(el("tr", {}, el("th", { text: "Match score" }), el("td", { text: Math.round(a.score * 100) + "%" }), el("td", { text: Math.round(b.score * 100) + "%" })));
    for (const [k, label] of rows) {
      if (!(a[k] || []).length && !(b[k] || []).length) continue;
      tb.append(el("tr", {}, el("th", { text: label }), cell(a[k], b[k]), cell(b[k], a[k])));
    }
    tb.append(el("tr", {}, el("th", { text: "Sources" }), el("td", { text: (a.records || []).map((r) => r.platform).join(" · ") }), el("td", { text: (b.records || []).map((r) => r.platform).join(" · ") })));
    tbl.append(tb);
    body.append(el("p", { class: "hint-line", text: "Green lines starting with = are stated by both. Values that appear on only one side are what tells the two people apart." }), tbl);
  };

  btn.addEventListener("click", showCases);

  const hb = el("button", { type: "button", class: "ghost small", id: "healthBtn", text: "Source status" });
  hb.title = "Check which of the public services rectool relies on are reachable right now";
  document.querySelector(".top-right").prepend(hb);
  hb.addEventListener("click", async () => {
    const body = open("Source status");
    body.append(el("p", { class: "hint-line", text: "Checking ~23 public services… this takes a few seconds. A source that is down or blocking returns nothing, which is not the same as 'no data exists'." }));
    let rows;
    try { rows = await RT.api("/api/health"); } catch (e) { body.append(el("div", { class: "muted", text: e.message })); return; }
    const down = rows.filter((r) => !r.ok).length;
    body.replaceChildren(el("p", {}, el("b", { text: `${rows.length - down}/${rows.length} reachable` }), down ? el("span", { class: "conflict", text: `  · ${down} not responding` }) : document.createTextNode("")));
    const tbl = el("table", { class: "tbl" }, el("thead", {}, el("tr", {}, ...["", "Service", "Used by", "Time", "Status"].map((h) => el("th", { text: h })))));
    const tb = el("tbody");
    for (const r of rows) {
      const dot = el("span", { class: "ldot" });
      dot.style.background = r.ok ? "#35d08a" : "#ef5b5b";
      tb.append(el("tr", {}, el("td", {}, dot), el("td", { text: r.name }), el("td", { class: "muted", text: r.used_by }), el("td", { text: r.ms + " ms" }), el("td", { text: r.ok ? "OK (" + r.status + ")" : r.error })));
    }
    tbl.append(tb);
    body.append(tbl);
  });
})();

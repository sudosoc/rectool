"use strict";

// Result views: overview dashboard, intelligence tree, findings table,
// coverage & integrity. All DOM is built with textContent (see app.js).
(function () {
  const { $, el, pct, confClass, clip } = RT;

  RT.TYPES = {
    name: { label: "Names", ico: "👤", color: "#e6edf3" },
    username: { label: "Handles", ico: "@", color: "#f472b6" },
    email: { label: "E-mail addresses", ico: "✉", color: "#4cc9f0" },
    phone: { label: "Phone numbers", ico: "☎", color: "#35d08a" },
    domain: { label: "Domains", ico: "◎", color: "#a78bfa" },
    ip: { label: "IP addresses", ico: "▦", color: "#f2b84b" },
    organisation: { label: "Organisations", ico: "▣", color: "#60a5fa" },
    location: { label: "Places", ico: "⌖", color: "#94a3b8" },
    url: { label: "URLs", ico: "⇗", color: "#94a3b8" },
    image: { label: "Pictures", ico: "🖼", color: "#94a3b8" },
  };
  const TYPE_ORDER = ["name", "username", "email", "phone", "domain", "ip", "organisation", "location", "url"];
  const ACCOUNT_CATS = new Set(["social", "profile", "email-account", "social-links"]);

  const filterState = { q: "", mod: "", cat: "", conf: 0, limit: 300 };
  let treeQuery = "";
  const treeOpen = new Set(); // ids of tree nodes the user opened

  const catLabel = (c) => (RT.CATEGORY_LABELS && RT.CATEGORY_LABELS[c]) || c || "other";

  // --------------------------------------------------------------- risk flags
  function flagFor(f) {
    const d = f.details || {};
    // Search-engine hits are leads, not confirmed exposure: never raise a risk flag from them.
    if (f.module === "dorks") return null;
    switch (f.category) {
      case "exposure":
        return { sev: "red", title: f.source, detail: Object.entries(d).filter(([k]) => k !== "note").slice(0, 2).map(([k, v]) => k + ": " + clip(v, 80)).join(" · ") };
      case "takeover":
        return { sev: "red", title: f.source, detail: "CNAME → " + (d["CNAME target"] || "") + " (" + (d.platform || "") + ")" };
      case "reputation":
        if (d["internet noise (mass scanner)"] === "yes") return { sev: "amber", title: "IP is internet background noise / scanner", detail: d.classification || d.message || "" };
        if (d["known benign service (RIOT)"] === "yes") return { sev: "green", title: "IP belongs to a known benign service", detail: d["actor / service"] || "" };
        return null;
      case "email-security":
        if (/missing|permissive/i.test((d.SPF || "") + (d["SPF policy"] || "") + (d.DMARC || ""))) return { sev: "amber", title: "Mail spoofing possible", detail: [d["SPF policy"] || d.SPF, d.DMARC === "missing" ? "DMARC missing" : ""].filter(Boolean).join(" · ") };
        if (d["DMARC policy"] === "none") return { sev: "amber", title: "DMARC in monitor-only mode", detail: "policy p=none does not block spoofed mail" };
        return null;
      case "security":
        if ((d.missing || "").split(",").filter(Boolean).length >= 3) return { sev: "amber", title: "Several security headers missing", detail: d.missing };
        if (d.transport) return { sev: "amber", title: "Site not forced to HTTPS", detail: d.transport };
        return null;
      case "tls":
        if (/^EXPIRED/.test(d.status || "")) return { sev: "red", title: "TLS certificate expired", detail: d.status };
        if (/^expires in/.test(d.status || "")) return { sev: "amber", title: "TLS certificate expires soon", detail: d.status };
        if (d.note) return { sev: "amber", title: "Self-signed TLS certificate", detail: d.subject || "" };
        return null;
      default:
        return null;
    }
  }

  // -------------------------------------------------------------------- overview
  function kpi(label, n, cls, onclick) {
    const b = el("button", { type: "button", class: "kpi " + (cls || "") }, el("span", { class: "n", text: String(n) }), el("span", { class: "l", text: label }));
    b.addEventListener("click", onclick);
    return b;
  }

  function gotoFindings(over) {
    Object.assign(filterState, { q: "", mod: "", cat: "", conf: 0, limit: 300 }, over || {});
    RT.selectTab("findings");
  }

  function overview() {
    const S = RT.S, root = $("tab-overview");
    root.replaceChildren();
    const ents = [...S.entities.values()];
    const byType = (t) => ents.filter((e) => e.type === t);
    const accounts = S.findings.filter((f) => ACCOUNT_CATS.has(f.category) && f.url).length;
    const subs = S.findings.filter((f) => f.category === "subdomain" && f.url).length;
    const flags = S.findings.map((f) => ({ f, flag: flagFor(f) })).filter((x) => x.flag);
    const sevRank = { red: 0, amber: 1, green: 2 };
    flags.sort((a, b) => sevRank[a.flag.sev] - sevRank[b.flag.sev]);
    const risky = flags.filter((x) => x.flag.sev !== "green").length;

    const kp = el("div", { class: "kpis" });
    kp.append(
      kpi("findings", S.findings.length, "accent", () => gotoFindings()),
      kpi("entities", ents.length, "", () => RT.selectTab("tree")),
      kpi("accounts / profiles", accounts, "", () => gotoFindings({ cat: "social" })),
      kpi("e-mail addresses", byType("email").length, "", () => RT.selectTab("tree")),
      kpi("domains · subdomains", byType("domain").length + subs, "", () => gotoFindings({ cat: "subdomain" })),
      kpi("IP addresses", byType("ip").length, "", () => RT.selectTab("tree")),
      kpi("photos", byType("image").length, "", () => RT.selectTab("photos")),
      kpi("risk flags", risky, risky ? "warn" : "", () => { document.getElementById("flagsPanel") && document.getElementById("flagsPanel").scrollIntoView({ behavior: "smooth" }); }),
    );
    if (S.report) {
      const gaps = (S.report.failures || []).length;
      kp.append(kpi("coverage gaps", gaps, gaps ? "warn" : "", () => RT.selectTab("coverage")));
    }
    root.append(kp);

    const grid = el("div", { class: "grid2" });

    // key facts ----------------------------------------------------------
    const facts = el("div", { class: "panel" }, el("h3", { text: "Key facts about the subject" }));
    const rows = el("div", { class: "facts" });
    let any = false;
    for (const t of TYPE_ORDER) {
      const list = byType(t).sort((a, b) => (b.strong - a.strong) || a.value.localeCompare(b.value));
      if (!list.length) continue;
      any = true;
      const chips = el("div", { class: "chips" });
      for (const e of list.slice(0, 10)) chips.append(RT.entityChip(e));
      if (list.length > 10) {
        const more = el("button", { type: "button", class: "chip", text: `+${list.length - 10} more` });
        more.addEventListener("click", () => RT.selectTab("tree"));
        chips.append(more);
      }
      rows.append(el("div", { class: "fact-row" }, el("div", { class: "k", text: (RT.TYPES[t] || {}).label || t }), chips));
    }
    const photos = RT.photoList().filter((p) => !p.error);
    if (photos.length) {
      any = true;
      const th = el("div", { class: "thumbs" });
      for (const p of photos.slice(0, 8)) {
        const b = el("button", { type: "button", title: (p.sources || []).join(" · ") }, el("img", { src: RT.imgSrc(p.url), alt: "", loading: "lazy" }));
        b.addEventListener("click", () => RT.showPhoto(p));
        th.append(b);
      }
      if (photos.length > 8) { const more = el("button", { type: "button", class: "chip", text: "+" + (photos.length - 8) }); more.addEventListener("click", () => RT.selectTab("photos")); th.append(more); }
      rows.prepend(el("div", { class: "fact-row" }, el("div", { class: "k", text: "Photos" }), th));
    }
    if (!any) rows.append(el("div", { class: "muted", text: S.state === "running" ? "Collecting… leads appear here as they are found." : "No new entities were discovered." }));
    facts.append(rows);
    grid.append(facts);

    // risk flags ---------------------------------------------------------
    const fl = el("div", { class: "panel", id: "flagsPanel" }, el("h3", { text: "Notable signals" }));
    if (!flags.length) fl.append(el("div", { class: "muted", text: S.state === "running" ? "Nothing notable yet." : "No risk signals detected in the collected data." }));
    for (const { f, flag } of flags.slice(0, 14)) {
      const row = el("div", { class: "flag" }, el("span", { class: "dot " + (flag.sev === "red" ? "red" : flag.sev === "green" ? "green" : "") }),
        el("div", {}, el("div", { text: flag.title }), el("div", { class: "d", text: clip(flag.detail, 160) })),
        el("span", { class: "tag", text: f.module }));
      row.addEventListener("click", () => RT.showFinding(f));
      fl.append(row);
    }
    grid.append(fl);

    // confidence distribution -------------------------------------------
    const dist = { hi: 0, mid: 0, lo: 0 };
    for (const f of S.findings) dist[confClass(pct(f.confidence))]++;
    const max = Math.max(1, dist.hi, dist.mid, dist.lo);
    const dp = el("div", { class: "panel" }, el("h3", { text: "How reliable is it?" }));
    const dd = el("div", { class: "dist" });
    for (const [k, lab] of [["hi", "High (≥ 80%)"], ["mid", "Medium (50–79%)"], ["lo", "Low (< 50%)"]]) {
      dd.append(el("div", { class: "row" }, el("span", { text: lab }), el("div", { class: "track" }, el("div", { class: "fill", style: `width:${Math.round((dist[k] / max) * 100)}%` })), el("span", { class: "num", text: String(dist[k]) })));
    }
    dp.append(dd, el("p", { class: "hint-line", text: "High = verified by an official source or cross-checked. Low = a name/handle match that may belong to someone else." }));
    grid.append(dp);

    // activity per collector --------------------------------------------
    const per = {};
    for (const f of S.findings) per[f.module] = (per[f.module] || 0) + 1;
    const ap = el("div", { class: "panel" }, el("h3", { text: "Findings per collector" }));
    const ad = el("div", { class: "dist" });
    const pmax = Math.max(1, ...Object.values(per));
    for (const [m, n] of Object.entries(per).sort((a, b) => b[1] - a[1])) {
      const row = el("div", { class: "row" }, el("span", { class: "mono", text: m }), el("div", { class: "track" }, el("div", { class: "fill", style: `width:${Math.round((n / pmax) * 100)}%` })), el("span", { class: "num", text: String(n) }));
      row.style.cursor = "pointer";
      row.addEventListener("click", () => gotoFindings({ mod: m }));
      ad.append(row);
    }
    if (!Object.keys(per).length) ad.append(el("div", { class: "muted", text: "No findings yet." }));
    ap.append(ad);
    grid.append(ap);

    root.append(grid);
  }

  // ------------------------------------------------------------------------ tree
  const SECTIONS = [
    { id: "identity", ico: "👤", label: "Identity", ents: ["name", "username"], cats: [] },
    { id: "contact", ico: "✉", label: "Contact points", ents: ["email", "phone"], cats: ["phone", "contact"] },
    { id: "accounts", ico: "🔗", label: "Online accounts & profiles", ents: [], cats: ["social", "profile", "email-account", "social-links"] },
    { id: "infra", ico: "🌐", label: "Infrastructure", ents: ["domain", "ip"], cats: ["dns", "whois", "subdomain", "tls", "web", "tech", "tracking", "email-security", "security", "archive", "network", "geo", "ip", "email-domain"] },
    { id: "org", ico: "▣", label: "Organisation & places", ents: ["organisation", "location"], cats: ["company", "registry", "reference", "website", "identity"] },
    { id: "exposure", ico: "⚠", label: "Exposure & risk", ents: [], cats: ["exposure", "takeover", "reputation"] },
    { id: "crypto", ico: "₿", label: "Crypto", ents: [], cats: ["crypto"] },
    { id: "other", ico: "🔎", label: "Search leads & mentions", ents: ["url"], cats: null },
  ];

  function hostOf(u) { try { return new URL(u).hostname; } catch { return ""; } }

  function findingLeaf(f) {
    const p = pct(f.confidence);
    const leaf = el("div", { class: "leaf" },
      el("span", { class: "v", text: clip(f.source, 90) }),
      el("span", { class: "pct " + confClass(p), text: p + "%" }),
      el("span", { class: "tag", text: f.module }));
    if (f.via) leaf.append(el("span", { class: "tag via", text: "via " + clip(f.via, 40) }));
    const h = hostOf(f.url);
    if (h) leaf.append(el("span", { class: "m", text: h }));
    leaf.addEventListener("click", () => RT.showFinding(f));
    return leaf;
  }

  function entityLeaf(e) {
    const leaf = el("div", { class: "leaf" }, el("span", { class: "v", text: e.value }),
      el("span", { class: "tag" + (e.strong ? " strong" : ""), text: e.strong ? "strong lead" : "weak lead" }));
    if (e.source) leaf.append(el("span", { class: "m", text: "from " + clip(e.source, 60) }));
    leaf.addEventListener("click", () => RT.showEntity(e));
    return leaf;
  }

  function group(id, ico, label, count, builder, open) {
    const d = el("details", { "data-id": id });
    if (open || treeOpen.has(id)) d.open = true;
    d.append(el("summary", {}, el("span", { class: "ico", text: ico }), el("span", { class: "nm", text: label }), el("span", { class: "cnt", text: String(count) })));
    let built = false;
    const build = () => { if (!built) { built = true; builder(d); } };
    if (d.open) build();
    d.addEventListener("toggle", () => { if (d.open) { treeOpen.add(id); build(); } else treeOpen.delete(id); });
    return d;
  }

  function addLeaves(parent, items, make, cap = 250) {
    for (const it of items.slice(0, cap)) parent.append(make(it));
    if (items.length > cap) {
      const more = el("div", { class: "leaf" }, el("span", { class: "v", text: `… show ${items.length - cap} more` }));
      more.addEventListener("click", () => { more.remove(); for (const it of items.slice(cap)) parent.append(make(it)); });
      parent.append(more);
    }
  }

  function tree() {
    const S = RT.S, root = $("tab-tree");
    const q = treeQuery.toLowerCase();
    root.replaceChildren();

    const bar = el("div", { class: "treebar" });
    const search = el("input", { type: "search", placeholder: "Search the tree…", value: treeQuery, style: "max-width:260px" });
    search.addEventListener("input", RT.debounce(() => { treeQuery = search.value; tree(); search.focus(); }, 250));
    const exp = el("button", { type: "button", class: "ghost small", text: "Expand sections" });
    const col = el("button", { type: "button", class: "ghost small", text: "Collapse all" });
    exp.addEventListener("click", () => { SECTIONS.forEach((s) => treeOpen.add("sec:" + s.id)); tree(); });
    col.addEventListener("click", () => { treeOpen.clear(); tree(); });
    bar.append(search, exp, col, el("span", { class: "hint-line", text: "Click any leaf for the full evidence." }));
    root.append(bar);

    const ents = [...S.entities.values()].filter((e) => !q || (e.value + " " + e.type).toLowerCase().includes(q));
    const finds = S.findings.filter((f) => !q || (f.source + " " + f.url + " " + f.module + " " + JSON.stringify(f.details || {})).toLowerCase().includes(q));
    const known = new Set(SECTIONS.flatMap((s) => s.cats || []));

    const t = S.target || {};
    const subject = [t.full_name, t.username, t.alias, t.email, t.phone, t.domain, t.ip, t.asn, t.wallet, t.company].filter(Boolean)[0] || "Subject";

    const rootBox = el("div", { class: "tree root" });
    const rootNode = group("root", "◉", "Subject · " + clip(subject, 50), finds.length, (d) => {
      for (const s of SECTIONS) {
        const sEnts = ents.filter((e) => s.ents.includes(e.type));
        const sFinds = finds.filter((f) => (s.cats === null ? !known.has(f.category) : s.cats.includes(f.category)));
        const total = sEnts.length + sFinds.length;
        if (!total) continue;
        d.append(group("sec:" + s.id, s.ico, s.label, total, (sd) => {
          for (const type of s.ents) {
            const list = sEnts.filter((e) => e.type === type).sort((a, b) => (b.strong - a.strong) || a.value.localeCompare(b.value));
            if (!list.length) continue;
            const tt = RT.TYPES[type] || { label: type, ico: "•" };
            sd.append(group("ent:" + s.id + ":" + type, tt.ico, tt.label, list.length, (gd) => addLeaves(gd, list, entityLeaf), list.length <= 12));
          }
          const cats = {};
          for (const f of sFinds) (cats[f.category || "other"] = cats[f.category || "other"] || []).push(f);
          for (const c of Object.keys(cats).sort((a, b) => cats[b].length - cats[a].length)) {
            const list = cats[c].sort((a, b) => b.confidence - a.confidence);
            sd.append(group("cat:" + s.id + ":" + c, "•", catLabel(c), list.length, (gd) => addLeaves(gd, list, findingLeaf), list.length <= 6));
          }
        }, true));
      }
      if (!d.children.length > 1 && !finds.length && !ents.length) d.append(el("div", { class: "muted", text: "Nothing collected yet." }));
    }, true);
    rootBox.append(rootNode);
    root.append(rootBox);
  }

  // -------------------------------------------------------------------- findings
  function findings() {
    const S = RT.S;
    const fill = (sel, values, all) => {
      const cur = filterState[sel === "modFilter" ? "mod" : "cat"];
      const node = $(sel);
      const have = [...node.options].map((o) => o.value).slice(1);
      const want = [...values].sort();
      if (have.join("|") !== want.join("|")) {
        node.replaceChildren(el("option", { value: "", text: all }), ...want.map((v) => el("option", { value: v, text: v })));
      }
      node.value = cur;
    };
    fill("modFilter", new Set(S.findings.map((f) => f.module)), "All collectors");
    fill("catFilter", new Set(S.findings.map((f) => f.category || "other")), "All categories");
    $("filter").value = filterState.q;
    $("confFilter").value = String(filterState.conf);

    const q = filterState.q.toLowerCase();
    let list = S.findings.filter((f) => {
      if (filterState.mod && f.module !== filterState.mod) return false;
      if (filterState.cat && (f.category || "other") !== filterState.cat) return false;
      if (f.confidence < filterState.conf) return false;
      if (q && !(f.source + " " + f.url + " " + JSON.stringify(f.details || {}) + " " + JSON.stringify(f.entities || [])).toLowerCase().includes(q)) return false;
      return true;
    });
    list = list.sort((a, b) => b.confidence - a.confidence);

    const body = $("rows");
    body.replaceChildren();
    for (const f of list.slice(0, filterState.limit)) {
      const sub = el("div", { class: "fsub" }, el("span", { class: "pill", text: f.category || "other" }));
      if (f.via) sub.append(el("span", { class: "tag via", text: "via " + clip(f.via, 40) }));
      const info = el("td", { class: "info" });
      const entries = Object.entries(f.details || {}).sort((a, b) => ["note", "md5", "http_status", "avatar", "username", "rank", "engine", "query", "host", "handle"].includes(a[0]) - ["note", "md5", "http_status", "avatar", "username", "rank", "engine", "query", "host", "handle"].includes(b[0]));
      for (const [k, v] of entries.slice(0, 3)) info.append(el("div", { text: k + ": " + clip(v, 160) }));
      const href = RT.safeHref(f.url);
      const title = el("div", { class: "ftitle" });
      title.append(href ? el("a", { href, target: "_blank", rel: "noopener noreferrer", text: clip(f.source, 120) }) : el("span", { text: clip(f.source, 120) }));
      if (href && f.url !== f.source) sub.append(el("span", { class: "furl", text: clip(f.url, 90) }));
      const p = pct(f.confidence);
      const tr = el("tr", {}, el("td", {}, el("span", { class: "pill", text: f.module })), el("td", { class: "src" }, title, sub), info, el("td", { class: "conf " + confClass(p), text: p + "%" }));
      tr.addEventListener("click", (e) => { if (e.target.tagName !== "A") RT.showFinding(f); });
      body.append(tr);
    }
    if (list.length > filterState.limit) {
      const more = el("tr", { class: "more-row" }, el("td", { colspan: "4", text: `Showing ${filterState.limit} of ${list.length} — click to show more` }));
      more.addEventListener("click", () => { filterState.limit += 400; findings(); });
      body.append(more);
    }
    if (!list.length) body.append(el("tr", {}, el("td", { colspan: "4", class: "muted", text: S.findings.length ? "No findings match the filters." : "No findings yet." })));
  }

  for (const [id, key] of [["filter", "q"], ["modFilter", "mod"], ["catFilter", "cat"], ["confFilter", "conf"]]) {
    const node = $(id);
    const apply = () => { filterState[key] = key === "conf" ? parseFloat(node.value) : node.value; filterState.limit = 300; findings(); };
    node.addEventListener(key === "q" ? "input" : "change", key === "q" ? RT.debounce(apply, 200) : apply);
  }

  // -------------------------------------------------------------------- coverage
  function coverage() {
    const S = RT.S, root = $("tab-coverage");
    root.replaceChildren();
    root.append(el("div", { class: "cov-note" },
      el("b", { text: "Read this before relying on the results. " }),
      "Public sources rate-limit, block and go offline. A check that could not run is listed below as a gap — the absence of a result is not evidence that nothing exists. Re-run later, use a proxy, or check manually."));

    const rep = S.report;
    if (!rep) {
      root.append(el("div", { class: "panel" }, el("h3", { text: "Collectors" }), el("div", { class: "muted", text: "The full coverage report is produced when the investigation finishes." })));
      return;
    }

    const mods = el("div", { class: "panel" }, el("h3", { text: "Collectors" }));
    const table = el("table", {}, el("thead", {}, el("tr", {}, ...["Collector", "Followed lead", "Checked", "Found", "Errors", "Time"].map((h) => el("th", { text: h })))));
    const tb = el("tbody");
    for (const m of rep.modules || []) {
      tb.append(el("tr", {}, el("td", { class: "mono", text: m.name }), el("td", { class: "mono", text: m.via || "—" }),
        el("td", { text: String(m.checked) }), el("td", { text: String(m.found) }),
        el("td", { text: String(m.errors) + (m.error ? " · " + clip(m.error, 80) : ""), class: m.errors || m.error ? "conf mid" : "" }),
        el("td", { text: (m.duration_ms / 1000).toFixed(1) + "s" })));
    }
    table.append(tb);
    mods.append(el("div", { class: "tablewrap" }, table));
    if ((rep.skipped || []).length) mods.append(el("p", { class: "hint-line", text: "Not run: " + rep.skipped.join(" · ") }));
    root.append(mods);

    const fails = rep.failures || [];
    const gp = el("div", { class: "panel" }, el("h3", { text: `Coverage gaps (${fails.length})` }));
    if (!fails.length) gp.append(el("div", { class: "muted", text: "Every check that ran completed." }));
    const byMod = {};
    for (const f of fails) (byMod[f.module] = byMod[f.module] || []).push(f);
    for (const [m, list] of Object.entries(byMod).sort((a, b) => b[1].length - a[1].length)) {
      const reasons = {};
      for (const f of list) { const r = clip((f.error || "unknown").replace(/\d+/g, "#"), 70); reasons[r] = (reasons[r] || 0) + 1; }
      const det = el("details", {}, el("summary", {}, el("span", { class: "pill", text: m }), " ", el("b", { text: String(list.length) }), el("span", { class: "muted", text: "  " + Object.entries(reasons).sort((a, b) => b[1] - a[1]).slice(0, 2).map(([r, n]) => `${n}× ${r}`).join(" · ") })));
      const kv = el("div", { class: "kv", style: "margin-top:8px" });
      for (const f of list.slice(0, 40)) { kv.append(el("div", { class: "k", text: clip(f.source, 40) }), el("div", { class: "v", text: clip(f.error, 160) + (f.via ? "  (via " + f.via + ")" : "") })); }
      if (list.length > 40) kv.append(el("div", { class: "k", text: "…" }), el("div", { class: "v", text: `${list.length - 40} more in the JSON report` }));
      det.append(kv);
      gp.append(det);
    }
    root.append(gp);

    const leads = rep.manual_leads || [];
    if (leads.length) {
      const lp = el("div", { class: "panel" }, el("h3", { text: `Manual leads (${leads.length}): worth opening by hand` }),
        el("p", { class: "hint-line", text: "These sources need a login, CAPTCHA or payment, so rectool does not (and will not try to) automate them. The links are pre-filled with what you gave it." }));
      const byGroup = {};
      for (const l of leads) (byGroup[l.group] = byGroup[l.group] || []).push(l);
      for (const [g, list] of Object.entries(byGroup)) {
        const box = el("div", { class: "leadgroup" }, el("h4", { text: g }));
        const grid = el("div", { class: "leadlist" });
        for (const l of list) {
          const href = RT.safeHref(l.url);
          grid.append(el("div", { class: "lead" }, href ? el("a", { href, target: "_blank", rel: "noopener noreferrer", text: l.label }) : el("span", { text: l.label }), el("span", { class: "why", text: l.why })));
        }
        box.append(grid);
        lp.append(box);
      }
      root.append(lp);
    }

    const row = el("div", { class: "grid2" });
    const set = el("div", { class: "panel" }, el("h3", { text: "Run settings (reproducibility)" }), RT.kvTable(Object.assign({ started: rep.started_at, finished: rep.finished_at, "tool version": rep.version }, rep.settings || {})));
    row.append(set);
    const integ = el("div", { class: "panel" }, el("h3", { text: "Integrity" }));
    if (rep.integrity) {
      integ.append(el("div", { class: "kv" }, el("div", { class: "k", text: "algorithm" }), el("div", { class: "v", text: rep.integrity.algorithm }),
        el("div", { class: "k", text: "findings / entities" }), el("div", { class: "v", text: rep.integrity.findings + " / " + rep.integrity.entities })),
        el("p", { class: "hint-line", text: "SHA-256 of the target, entities and findings in the exported JSON. Store it with the report; any later edit changes it." }),
        el("div", { class: "digest", text: rep.integrity.digest }));
    }
    row.append(integ);
    root.append(row);
  }

  // ------------------------------------------------------------------------ photos
  function photos() {
    const root = $("tab-photos");
    root.replaceChildren();
    const list = RT.photoList();
    root.append(el("p", { class: "photo-note", text: "Profile pictures found on the discovered accounts. Pictures are downloaded by rectool (not your browser) and compared: a green border means the same picture is used by more than one source, which is strong evidence the accounts belong together. Always open the picture to confirm it shows a real person; default avatars, logos and stock images also repeat." }));
    if (!list.length) {
      root.append(el("div", { class: "panel muted", text: RT.S.state === "running" ? "No pictures yet…" : "No profile pictures were found. Platforms that need a login (Instagram, Facebook, X, LinkedIn) are listed under Coverage → manual leads." }));
      return;
    }
    const isCand = (p) => (p.sources || []).length > 0 && (p.sources || []).every((x) => /^images:/.test(x));
    const tileFor = (p) => {
      const ph = el("div", { class: "ph", text: "loading…" });
      const img = el("img", { src: RT.imgSrc(p.url), alt: "picture", loading: "lazy" });
      img.addEventListener("load", () => { ph.replaceChildren(img); });
      img.addEventListener("error", () => { ph.textContent = "unavailable"; });
      const cap = el("div", { class: "cap" }, el("div", { class: "src", text: clip((p.sources && p.sources[0]) || "picture", 70).replace(/^[a-z]+: /, "") }));
      if (isCand(p)) cap.append(el("span", { class: "tag cand", text: "unverified" }));
      if (p.group) cap.append(el("span", { class: "tag same", text: "same picture · group " + p.group }));
      if ((p.sources || []).length > 1) cap.append(el("div", { class: "m", text: "also: " + clip(p.sources.slice(1).join(" · ").replace(/[a-z]+: /g, ""), 80) }));
      if (p.width) cap.append(el("div", { class: "m", text: p.width + "×" + p.height }));
      const tile = el("button", { type: "button", class: "tile" + (p.group ? " grouped" : "") + (isCand(p) ? " candidate" : "") }, ph, cap);
      tile.addEventListener("click", () => RT.showPhoto(p));
      return tile;
    };
    const sure = list.filter((p) => !isCand(p)), cand = list.filter(isCand);
    if (sure.length) {
      root.append(el("h3", { class: "sec-title", text: `From profiles and accounts (${sure.length})` }));
      const grid = el("div", { class: "gallery" });
      sure.forEach((p) => grid.append(tileFor(p)));
      root.append(grid);
    }
    if (cand.length) {
      const det = el("details", { class: "cand-photos", open: !sure.length },
        el("summary", { text: `Unverified candidates from handle avatars and web image search (${cand.length})` }),
        el("p", { class: "photo-note", text: "Found by searching the handle on major services or the web for the name. Not proof of identity: the handle may belong to someone else and the name may be shared. Use reverse image search and the surrounding page to confirm." }));
      const grid = el("div", { class: "gallery" });
      cand.forEach((p) => grid.append(tileFor(p)));
      det.append(grid);
      root.append(det);
    }
  }

  // ---------------------------------------------------------------- identity
  const FACT_ROWS = [
    ["headlines", "Role"], ["employers", "Employers"], ["locations", "Location"], ["education", "Education"],
    ["interests", "Interests"], ["emails", "E-mail"], ["phones", "Phone"], ["usernames", "Accounts"], ["websites", "Websites"],
  ];

  function factBadge(f) {
    if (f.confirmed) return el("span", { class: "badge-c confirmed", title: "Stated by independent sources: " + (f.sources || []).join(", "), text: "✔ " + f.sources.length + " sources" });
    if (f.self) return el("span", { class: "badge-c self", title: "Stated in the person's own profile (" + (f.sources || []).join(", ") + ")", text: "self-reported" });
    return el("span", { class: "badge-c single", title: "One third-party source: " + (f.sources || []).join(", "), text: "1 source" });
  }

  function factList(facts, max, mono) {
    const box = el("div", { class: "fvals" });
    for (const f of (facts || []).slice(0, max)) {
      const href = /^https?:\/\//.test(f.value) ? RT.safeHref(f.value) : null;
      const v = href ? el("a", { class: "v", href, target: "_blank", rel: "noopener noreferrer", text: f.value }) : el("span", { class: "v" + (mono ? " mono" : ""), text: f.value });
      box.append(el("div", { class: "fv" }, v, factBadge(f)));
    }
    if ((facts || []).length > max) {
      const more = el("button", { type: "button", class: "ghost small", text: `+${facts.length - max} more` });
      more.addEventListener("click", () => { more.replaceWith(...facts.slice(max).map((f) => el("div", { class: "fv" }, el("span", { class: "v", text: f.value }), factBadge(f)))); });
      box.append(more);
    }
    return box;
  }

  function scoreChip(id) {
    const p = Math.round(id.score * 100);
    return el("span", { class: "score " + (p >= 70 ? "hi" : p >= 40 ? "mid" : "lo"), title: "How well this person matches what you supplied" }, "match " + p + "%");
  }

  function dossier(id, S) {
    const card = el("div", { class: "panel" });
    const photo = (id.photos || [])[0];
    const ph = el("button", { type: "button", class: "d-photo", title: photo ? "Open photo" : "No photo found", text: "👤" });
    if (photo) {
      const img = el("img", { src: RT.imgSrc(photo), alt: "profile picture" });
      img.addEventListener("load", () => ph.replaceChildren(img));
      ph.addEventListener("click", () => RT.showPhoto({ url: photo, sources: id.records.map((r) => r.platform), group: 0 }));
    }
    const head = el("div", { class: "d-head" }, el("h2", { text: (id.names[0] && id.names[0].value) || "Unnamed profile" }),
      el("div", { class: "d-sub", text: [ (id.headlines[0] || {}).value, (id.locations[0] || {}).value ].filter(Boolean).join(" · ") }));
    const chips = el("div", { class: "chips" }, scoreChip(id));
    for (const m of id.matched || []) chips.append(el("span", { class: "chip strong" }, el("span", { class: "k", text: "matches" }), el("span", { text: m })));
    head.append(chips);
    const rows = el("div", {});
    for (const [key, label] of FACT_ROWS) {
      const facts = id[key];
      if (!facts || !facts.length) continue;
      rows.append(el("div", { class: "frow" }, el("div", { class: "k", text: label }), factList(facts, key === "interests" ? 12 : 6, key === "emails" || key === "phones" || key === "usernames")));
    }
    if (id.bio) rows.append(el("div", { class: "frow" }, el("div", { class: "k", text: "About" }), el("div", { text: RT.clip(id.bio, 600) })));
    if ((id.documents || []).length) {
      const box = el("div", { class: "fvals" });
      for (const d of id.documents) box.append(el("a", { href: RT.safeHref(d) || "#", target: "_blank", rel: "noopener noreferrer", text: d }));
      rows.append(el("div", { class: "frow" }, el("div", { class: "k", text: "CV / resume" }), box));
    }
    const right = el("div", {}, head, el("div", { style: "margin-top:10px" }, rows));
    const left = el("div", { class: "d-left" }, ph);
    const extra = el("div", { class: "d-thumbs" });
    for (const u of (id.photos || []).slice(1, 9)) {
      const t = el("button", { type: "button", class: "d-thumb" });
      const im = el("img", { src: RT.imgSrc(u), alt: "", loading: "lazy" });
      im.addEventListener("error", () => t.remove());
      t.append(im);
      t.addEventListener("click", () => RT.showPhoto({ url: u, sources: id.records.map((r) => r.platform), group: 0 }));
      extra.append(t);
    }
    left.append(extra);
    card.append(el("div", { class: "dossier" }, left, right));
    for (const c of id.conflicts || []) card.append(el("div", { class: "conflict", text: "⚠ " + c }));
    if ((id.reasons || []).length) {
      const det = el("details", { style: "margin-top:10px" }, el("summary", { text: "Why these sources are treated as the same person" }));
      const ul = el("ul", { class: "reasons" });
      for (const r of id.reasons) ul.append(el("li", { text: r }));
      det.append(ul);
      card.append(det);
    }
    const recs = el("details", { style: "margin-top:8px" }, el("summary", { text: `Sources (${id.records.length})` }));
    const chips2 = el("div", { class: "chips", style: "margin-top:8px" });
    for (const r of id.records) {
      const href = RT.safeHref(r.url);
      chips2.append(href ? el("a", { class: "chip", href, target: "_blank", rel: "noopener noreferrer", title: r.source }, el("span", { class: "k", text: r.self ? "own" : "record" }), el("span", { text: r.platform })) : el("span", { class: "chip" }, el("span", { text: r.platform })));
    }
    recs.append(chips2);
    card.append(recs);
    const act = el("div", { style: "margin-top:10px" });
    const b = el("button", { type: "button", class: "ghost small", text: "Use these details to search again" });
    b.title = "Fills the form with this person's name, location, employer, e-mail, account and website";
    b.addEventListener("click", () => RT.refine(id));
    act.append(b);
    card.append(act);
    return card;
  }

  function candidate(id, best) {
    const c = el("div", { class: "cand" + (best ? " best" : "") });
    const top = el("div", { class: "cand-top" }, el("div", { class: "t", text: id.label }), scoreChip(id));
    c.append(top);
    const sub = [];
    if ((id.employers[0] || {}).value) sub.push("works at " + id.employers[0].value);
    if ((id.education[0] || {}).value) sub.push("studied at " + id.education[0].value);
    sub.push(id.records.map((r) => r.platform).join(" · "));
    c.append(el("div", { class: "muted", text: sub.join(" — ") }));
    const row = el("div", { class: "chips" });
    const use = el("button", { type: "button", class: "ghost small", text: "This is the person: search again with these details" });
    use.addEventListener("click", () => RT.refine(id));
    const open = el("button", { type: "button", class: "ghost small", text: "Show full profile" });
    open.addEventListener("click", () => { c.replaceWith(dossier(id)); });
    row.append(use, open);
    c.append(row);
    return c;
  }

  // glance: a one-line count of what is known about the best match, and what
  // to add to learn more or to separate it from other people.
  function glance(top, S) {
    const n = (k) => (top[k] || []).length;
    const stats = el("div", { class: "kpis" });
    for (const [k, label] of [["emails", "e-mails"], ["phones", "phones"], ["usernames", "accounts"], ["employers", "employers"], ["education", "schools"], ["websites", "websites"], ["photos", "photos"], ["documents", "CVs"]]) {
      const c = k === "documents" ? (top.documents || []).length : n(k);
      stats.append(el("div", { class: "kpi" + (c ? " accent" : ""), style: "cursor:default" }, el("span", { class: "n", text: String(c) }), el("span", { class: "l", text: label })));
    }
    const wrap = el("div", { class: "panel" }, el("h3", { text: "At a glance — " + (top.label || "best match") }), stats);
    const t = S.target || {};
    const tips = [];
    const ambiguous = !!S.ambiguity || S.sameName > 1 || !top.primary;
    if (ambiguous && !t.location) tips.push("Add a location (city or country): it is the quickest way to separate people who share the name.");
    if (ambiguous && !t.company) tips.push("Add an employer or school: profiles that mention it are ranked first.");
    if (!t.email && n("emails")) tips.push("Candidate e-mail found: " + top.emails[0].value + ". If it is right, enter it in the E-mail field to confirm the match and pull its Gravatar, GitHub and leak data.");
    if (!t.username && n("usernames")) tips.push("Account found: " + top.usernames[0].value + ". Enter it as Username to scan ~690 sites for the same handle.");
    if (!t.domain && n("websites")) tips.push("Website found: " + top.websites[0].value + ". Enter its domain to map DNS, subdomains, technologies and contacts.");
    if (!n("photos")) tips.push("No verified photo. Check Photos → unverified candidates, or use the reverse image links on any picture.");
    if (!(t.notes || "").trim() && !(t.links || []).length) tips.push("Open the person's LinkedIn yourself and paste the page text into the Paste text box (e-mail, CV and full history only appear to logged-in viewers).");
    if (tips.length) {
      const ul = el("ul", { class: "reasons" });
      tips.slice(0, 5).forEach((x) => ul.append(el("li", { text: x })));
      wrap.append(el("h4", { class: "sec-title", text: "To learn more or tighten the match" }), ul);
    }
    return wrap;
  }

  function identityView() {
    const S = RT.S, root = $("tab-identity");
    root.replaceChildren();
    const all = S.identities || [];
    const ids = all.filter((i) => !i.weak);
    const weak = all.filter((i) => i.weak);
    if (!ids.length && weak.length) { ids.push(...weak.splice(0, 1)); }
    if (!ids.length) {
      root.append(el("div", { class: "panel muted", text: S.state === "running"
        ? "No person profile yet… as soon as collectors return profile data (LinkedIn, ORCID, GitHub, Wikidata, personal sites, CVs) the people they describe appear here, kept apart."
        : "No person profiles were found. Give a full name plus a location, employer or e-mail, paste a LinkedIn/CV text, or a username, and run again." }));
      return;
    }
    if (S.ambiguity) {
      root.append(el("div", { class: "id-banner" }, el("b", { text: "Several people match. " }), S.ambiguity,
        " Their facts are shown separately, never merged, and none of their e-mails or accounts is followed until you choose one."));
    } else if (S.sameName > 1) {
      root.append(el("div", { class: "id-banner" }, el("b", { text: `${S.sameName} people share this name. ` }), "The best match is shown first; the others are listed below."));
    }
    const top = ids[0];
    root.append(glance(top, S));
    if (top.primary) {
      root.append(dossier(top, S));
    } else {
      root.append(el("p", { class: "hint-line", text: "No single person is a clear match yet. Candidates, best guess first:" }));
    }
    const rest = top.primary ? ids.slice(1) : ids;
    if (rest.length) {
      const wrap = el("div", { class: "panel" }, el("h3", { text: top.primary ? `Other people matching (${rest.length})` : `Candidates (${rest.length})` }));
      const list = el("div", { class: "cands" });
      rest.forEach((id, i) => list.append(candidate(id, !top.primary && i === 0)));
      wrap.append(list);
      root.append(wrap);
    }
    if (weak.length) {
      const det = el("details", { class: "panel" }, el("summary", { text: `Accounts that only share the handle (${weak.length}) — probably other people` }),
        el("p", { class: "hint-line", text: "These accounts have no name and nothing else tying them to your subject. They are shown for completeness and are never followed." }));
      const chips = el("div", { class: "chips", style: "margin-top:8px" });
      for (const id of weak) {
        const r = id.records[0] || {};
        const href = RT.safeHref(r.url);
        const label = (id.usernames[0] || {}).value || r.platform;
        chips.append(href ? el("a", { class: "chip weak", href, target: "_blank", rel: "noopener noreferrer" }, el("span", { class: "k", text: r.platform }), el("span", { text: label })) : el("span", { class: "chip weak", text: label }));
      }
      det.append(chips);
      root.append(det);
    }
  }

  RT.views = { identity: identityView, overview, tree, photos, findings, coverage };

  RT.resetViews = function resetViews() {
    Object.assign(filterState, { q: "", mod: "", cat: "", conf: 0, limit: 300 });
    treeQuery = "";
    treeOpen.clear();
    treeOpen.add("root");
    SECTIONS.forEach((s) => treeOpen.add("sec:" + s.id));
    ["tab-identity", "tab-overview", "tab-tree", "tab-coverage", "tab-location"].forEach((id) => $(id).replaceChildren());
    $("rows").replaceChildren();
    if (RT.graph) RT.graph.reset();
  };
})();

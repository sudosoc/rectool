"use strict";

// Relationship graph: the subject, the identifiers it was given, and every
// entity discovered, linked by *where each lead came from*. A small
// force-directed layout on <canvas>; no external libraries.
(function () {
  const { $ } = RT;
  const canvas = $("graph");
  const ctx = canvas.getContext("2d");
  const tip = $("graphTip");

  const COLORS = {
    subject: "#35d08a", name: "#dfe7ef", username: "#f472b6", email: "#4cc9f0", phone: "#34d399", domain: "#a78bfa",
    ip: "#f2b84b", organisation: "#60a5fa", location: "#94a3b8", asn: "#fb923c", wallet: "#facc15", url: "#94a3b8",
  };
  const INPUT_TYPE = { full_name: "name", username: "username", alias: "username", email: "email", phone: "phone", domain: "domain", ip: "ip", asn: "asn", wallet: "wallet", company: "organisation", location: "location" };
  const MODULE_INPUT = {
    social: ["username"], profiles: ["username"], footprint: ["email", "phone"], phone: ["phone"], domain: ["domain"], ip: ["ip"],
    asn: ["asn"], company: ["organisation"], people: ["name"], images: ["name", "username"], activity: ["username"], breach: ["email"], crypto: ["wallet"], syswrap: ["domain", "username"], dorks: [],
  };
  const MAX_NODES = 260;

  let nodes = [], edges = [], byId = new Map();
  let view = { x: 0, y: 0, k: 1 };
  let alpha = 1, raf = null, hover = null, selected = null, drag = null, showWeak = true;
  let textColor = "#dfe7ef", lineColor = "#3a4658";

  const key = (type, value) => type + ":" + String(value).toLowerCase();

  function build() {
    const S = RT.S;
    const nm = new Map(), em = [];
    const add = (type, value, extra) => {
      const id = key(type, value);
      let n = nm.get(id);
      if (!n) { n = { id, type, value, strong: false, input: false, deg: 0 }; nm.set(id, n); }
      Object.assign(n, extra && Object.fromEntries(Object.entries(extra).filter(([, v]) => v)));
      return n;
    };
    const t = S.target || {};
    const subjectLabel = [t.full_name, t.username, t.alias, t.email, t.phone, t.domain, t.ip, t.asn, t.wallet, t.company].filter(Boolean)[0] || "subject";
    const subject = add("subject", "subject", { strong: true, input: true });
    subject.label = subjectLabel;
    const inputsByType = {};
    for (const [field, type] of Object.entries(INPUT_TYPE)) {
      if (!t[field]) continue;
      const n = add(type, t[field], { strong: true, input: true });
      (inputsByType[type] = inputsByType[type] || []).push(n);
      if (type !== "location") em.push([subject, n, "input"]);
    }
    for (const e of S.entities.values()) if (e.type !== "image") add(e.type, e.value, { strong: e.strong, source: e.source });

    const parentFor = (f) => {
      if (f.via) { const p = nm.get(String(f.via).toLowerCase()); if (p) return p; }
      for (const type of MODULE_INPUT[f.module] || []) if (inputsByType[type]) return inputsByType[type][0];
      return subject;
    };
    for (const f of S.findings) {
      if (!f.entities || !f.entities.length) continue;
      const parent = parentFor(f);
      for (const e of f.entities) {
        const n = nm.get(key(e.type, e.value));
        if (n && n !== parent) em.push([parent, n, f.module]);
      }
    }

    // unique edges, degree
    const seen = new Set();
    let ed = [];
    for (const [a, b, label] of em) {
      const k = a.id + ">" + b.id;
      if (seen.has(k) || seen.has(b.id + ">" + a.id)) continue;
      seen.add(k);
      ed.push({ a, b, label });
      a.deg++; b.deg++;
    }
    let list = [...nm.values()];
    if (!showWeak) {
      const keep = new Set(list.filter((n) => n.strong || n.input).map((n) => n.id));
      list = list.filter((n) => keep.has(n.id));
      ed = ed.filter((e) => keep.has(e.a.id) && keep.has(e.b.id));
    }
    if (list.length > MAX_NODES) {
      list.sort((x, y) => (y.input - x.input) || (y.strong - x.strong) || (y.deg - x.deg));
      list = list.slice(0, MAX_NODES);
      const ids = new Set(list.map((n) => n.id));
      ed = ed.filter((e) => ids.has(e.a.id) && ids.has(e.b.id));
    }

    // keep previous positions
    const prev = byId;
    const w = canvas.clientWidth || 800, h = canvas.clientHeight || 500;
    list.forEach((n, i) => {
      const p = prev.get(n.id);
      if (p) { n.x = p.x; n.y = p.y; n.vx = p.vx; n.vy = p.vy; n.fixed = p.fixed; }
      else {
        const ang = (i / Math.max(1, list.length)) * Math.PI * 2, r = n.input ? 60 : 160 + Math.random() * 80;
        n.x = w / 2 + Math.cos(ang) * r; n.y = h / 2 + Math.sin(ang) * r; n.vx = 0; n.vy = 0;
      }
      if (n.type === "subject") { n.x = w / 2; n.y = h / 2; n.fixed = true; }
    });
    nodes = list; edges = ed; byId = new Map(list.map((n) => [n.id, n]));
    legend();
  }

  function legend() {
    const box = $("graphLegend");
    box.replaceChildren();
    const present = new Set(nodes.map((n) => n.type));
    for (const [type, color] of Object.entries(COLORS)) {
      if (!present.has(type)) continue;
      const sw = document.createElement("span"); sw.className = "sw"; sw.style.background = color;
      const k = document.createElement("span"); k.className = "k"; k.append(sw, document.createTextNode(type));
      box.append(k);
    }
    const info = document.createElement("span"); info.className = "k";
    info.textContent = `${nodes.length} nodes · ${edges.length} links` + (nodes.length >= MAX_NODES ? " (strongest shown)" : "");
    box.append(info);
  }

  // ---------------------------------------------------------------- physics
  function step() {
    const n = nodes.length;
    for (let i = 0; i < n; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < n; j++) {
        const b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy;
        if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.5; }
        if (d2 > 90000) continue;
        const f = (2600 * alpha) / d2, d = Math.sqrt(d2);
        dx = (dx / d) * f; dy = (dy / d) * f;
        a.vx += dx; a.vy += dy; b.vx -= dx; b.vy -= dy;
      }
    }
    for (const e of edges) {
      const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
      const len = e.a.type === "subject" ? 95 : 70, f = (d - len) * 0.02 * alpha * 4;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      e.a.vx += fx; e.a.vy += fy; e.b.vx -= fx; e.b.vy -= fy;
    }
    const cx = (canvas.clientWidth || 800) / 2, cy = (canvas.clientHeight || 500) / 2;
    for (const a of nodes) {
      a.vx += (cx - a.x) * 0.0016 * alpha * 4; a.vy += (cy - a.y) * 0.0016 * alpha * 4;
      if (a.fixed) { a.vx = a.vy = 0; continue; }
      a.vx *= 0.82; a.vy *= 0.82;
      a.x += Math.max(-30, Math.min(30, a.vx)); a.y += Math.max(-30, Math.min(30, a.vy));
    }
    alpha *= 0.985;
  }

  function loop() {
    raf = null;
    if (alpha > 0.02) { step(); step(); }
    draw();
    if (alpha > 0.02 || drag) raf = requestAnimationFrame(loop);
  }
  const kick = (a) => { alpha = Math.max(alpha, a); if (!raf) raf = requestAnimationFrame(loop); };

  // ---------------------------------------------------------------- drawing
  const radius = (n) => (n.type === "subject" ? 13 : n.input ? 9 : 4.5 + Math.min(7, Math.sqrt(n.deg) * 2));

  function draw() {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) { canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr); }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    ctx.save();
    ctx.translate(view.x, view.y); ctx.scale(view.k, view.k);

    ctx.lineWidth = 1 / view.k;
    for (const e of edges) {
      const hot = hover && (e.a === hover || e.b === hover);
      ctx.strokeStyle = hot ? "#35d08a" : lineColor;
      ctx.globalAlpha = hot ? 0.95 : 0.55;
      ctx.beginPath(); ctx.moveTo(e.a.x, e.a.y); ctx.lineTo(e.b.x, e.b.y); ctx.stroke();
    }
    ctx.globalAlpha = 1;
    for (const n of nodes) {
      const r = radius(n);
      ctx.fillStyle = COLORS[n.type] || "#94a3b8";
      ctx.globalAlpha = n.strong || n.input ? 1 : 0.55;
      ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = 1;
      if (n.strong && !n.input) { ctx.strokeStyle = COLORS[n.type] || "#94a3b8"; ctx.lineWidth = 1.4 / view.k; ctx.beginPath(); ctx.arc(n.x, n.y, r + 3, 0, Math.PI * 2); ctx.stroke(); }
      if (n === selected || n === hover) { ctx.strokeStyle = textColor; ctx.lineWidth = 2 / view.k; ctx.beginPath(); ctx.arc(n.x, n.y, r + 5, 0, Math.PI * 2); ctx.stroke(); }
    }
    ctx.font = `${11 / Math.max(0.7, Math.min(1.4, view.k))}px ui-monospace, Menlo, Consolas, monospace`;
    ctx.fillStyle = textColor; ctx.textBaseline = "middle";
    for (const n of nodes) {
      const show = n.input || n === hover || n === selected || (view.k > 0.9 && (n.strong || n.deg >= 3)) || view.k > 1.6;
      if (!show) continue;
      const label = n.type === "subject" ? n.label : n.value;
      ctx.fillText(label.length > 34 ? label.slice(0, 33) + "…" : label, n.x + radius(n) + 6, n.y);
    }
    ctx.restore();
  }

  // ------------------------------------------------------------ interaction
  const toWorld = (px, py) => [(px - view.x) / view.k, (py - view.y) / view.k];
  function pick(px, py) {
    const [x, y] = toWorld(px, py);
    let best = null, bd = Infinity;
    for (const n of nodes) {
      const d = Math.hypot(n.x - x, n.y - y);
      if (d <= radius(n) + 6 / view.k && d < bd) { best = n; bd = d; }
    }
    return best;
  }
  const local = (ev) => { const r = canvas.getBoundingClientRect(); return [ev.clientX - r.left, ev.clientY - r.top]; };

  canvas.addEventListener("pointerdown", (ev) => {
    const [px, py] = local(ev);
    const n = pick(px, py);
    canvas.setPointerCapture(ev.pointerId);
    drag = { n, sx: px, sy: py, ox: view.x, oy: view.y, moved: false };
    if (!n) canvas.classList.add("drag");
    kick(0.3);
  });
  canvas.addEventListener("pointermove", (ev) => {
    const [px, py] = local(ev);
    if (drag) {
      if (Math.hypot(px - drag.sx, py - drag.sy) > 3) drag.moved = true;
      if (drag.n && drag.moved) { const [x, y] = toWorld(px, py); drag.n.x = x; drag.n.y = y; drag.n.fixed = true; drag.n.vx = drag.n.vy = 0; kick(0.3); }
      else if (!drag.n) { view.x = drag.ox + (px - drag.sx); view.y = drag.oy + (py - drag.sy); draw(); }
      return;
    }
    const n = pick(px, py);
    if (n !== hover) { hover = n; draw(); }
    if (n) {
      tip.hidden = false;
      tip.textContent = n.type === "subject" ? "subject" : `${n.type}: ${n.value}${n.strong ? "  · strong lead" : "  · weak lead"}${n.source ? "\nfrom " + n.source : ""}`;
      tip.style.whiteSpace = "pre-wrap";
      tip.style.left = Math.min(px + 14, canvas.clientWidth - 260) + "px"; tip.style.top = py + 14 + "px";
    } else tip.hidden = true;
  });
  canvas.addEventListener("pointerup", () => {
    if (drag && drag.n && !drag.moved) { selected = drag.n; if (drag.n.type !== "subject") RT.showEntity({ type: drag.n.type, value: drag.n.value, strong: drag.n.strong, source: drag.n.source }); }
    canvas.classList.remove("drag");
    drag = null; draw();
  });
  canvas.addEventListener("pointerleave", () => { tip.hidden = true; if (hover) { hover = null; draw(); } });
  canvas.addEventListener("dblclick", (ev) => { const n = pick(...local(ev)); if (n && n.type !== "subject") { n.fixed = false; kick(0.5); } });
  canvas.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const [px, py] = local(ev);
    const k = Math.max(0.3, Math.min(3.5, view.k * (ev.deltaY < 0 ? 1.12 : 1 / 1.12)));
    view.x = px - ((px - view.x) / view.k) * k; view.y = py - ((py - view.y) / view.k) * k; view.k = k;
    draw();
  }, { passive: false });

  $("graphWeak").addEventListener("change", (e) => { showWeak = e.target.checked; if (RT.S) { build(); kick(0.7); } });
  $("graphReset").addEventListener("click", () => { view = { x: 0, y: 0, k: 1 }; nodes.forEach((n) => { if (n.type !== "subject") n.fixed = false; }); kick(0.9); });
  new ResizeObserver(() => draw()).observe(canvas);

  RT.graph = {
    update() {
      const cs = getComputedStyle(document.body);
      textColor = cs.color; lineColor = getComputedStyle(document.documentElement).getPropertyValue("--line2").trim() || "#3a4658";
      const before = nodes.length;
      build();
      kick(nodes.length !== before ? 0.7 : 0.15);
    },
    reset() { nodes = []; edges = []; byId = new Map(); view = { x: 0, y: 0, k: 1 }; hover = selected = null; draw(); },
  };
})();

"use strict";

// Location tab: the best-supported place, a map of every piece of evidence,
// the evidence table with sources, and the activity-hours timezone estimate.
// The map is drawn on <canvas> (no tiles, no external requests).
(function () {
  const { $, el } = RT;

  // coarse continent outlines [lon, lat]: enough to orient a dot, not a cartographic map
  const LAND = [
    [[-168,66],[-156,71],[-125,70],[-95,72],[-80,73],[-62,60],[-55,50],[-67,45],[-76,35],[-81,25],[-97,26],[-105,20],[-95,16],[-83,9],[-80,8],[-92,14],[-105,22],[-115,30],[-124,40],[-125,49],[-135,58],[-150,60],[-165,60]],
    [[-80,8],[-60,10],[-50,0],[-35,-6],[-40,-22],[-48,-28],[-58,-38],[-65,-42],[-68,-52],[-74,-50],[-72,-30],[-71,-18],[-81,-5]],
    [[-10,36],[-9,43],[-2,48],[5,53],[8,57],[12,56],[20,60],[25,66],[30,70],[60,69],[80,73],[110,77],[140,72],[170,70],[180,66],[160,58],[140,52],[135,43],[122,40],[122,30],[110,20],[106,10],[100,2],[98,15],[92,22],[80,15],[77,8],[72,20],[66,25],[57,25],[52,16],[43,12],[35,28],[35,36],[27,37],[20,40],[15,38],[8,44],[-1,37]],
    [[-17,21],[-10,32],[10,37],[32,31],[35,28],[43,12],[51,12],[40,-3],[40,-15],[33,-26],[20,-35],[14,-25],[12,-5],[9,4],[-8,4],[-17,14]],
    [[114,-22],[122,-18],[136,-12],[142,-11],[146,-19],[153,-26],[150,-37],[140,-38],[131,-31],[115,-34]],
    [[-55,60],[-45,60],[-22,70],[-20,82],[-60,82],[-70,76]],
  ];
  const KIND = {
    "self-declared": ["#35d08a", "stated in a profile"],
    exif: ["#f2b84b", "GPS inside a picture"],
    organisation: ["#a78bfa", "company / employer address"],
    ip: ["#4cc9f0", "IP geolocation"],
    phone: ["#f472b6", "phone number region"],
    activity: ["#8493a5", "activity hours"],
  };

  function drawMap(canvas, geo) {
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth || 800, H = Math.round(W / 2);
    canvas.width = W * dpr; canvas.height = H * dpr; canvas.style.height = H + "px";
    const g = canvas.getContext("2d");
    g.scale(dpr, dpr);
    const css = getComputedStyle(document.documentElement);
    const line = css.getPropertyValue("--line").trim() || "#233", panel = css.getPropertyValue("--panel2").trim() || "#111", text = css.getPropertyValue("--text").trim() || "#ddd";
    const X = (lon) => ((lon + 180) / 360) * W, Y = (lat) => ((90 - lat) / 180) * H;
    g.fillStyle = panel; g.fillRect(0, 0, W, H);
    g.strokeStyle = line; g.lineWidth = 0.5;
    for (let lon = -150; lon <= 180; lon += 30) { g.beginPath(); g.moveTo(X(lon), 0); g.lineTo(X(lon), H); g.stroke(); }
    for (let lat = -60; lat <= 60; lat += 30) { g.beginPath(); g.moveTo(0, Y(lat)); g.lineTo(W, Y(lat)); g.stroke(); }
    g.fillStyle = line; g.globalAlpha = 0.55;
    for (const poly of LAND) {
      g.beginPath();
      poly.forEach(([lo, la], i) => (i ? g.lineTo(X(lo), Y(la)) : g.moveTo(X(lo), Y(la))));
      g.closePath(); g.fill();
    }
    g.globalAlpha = 1;
    // timezone band: the estimated offset is a vertical strip 15 degrees wide
    if (geo.timezone) {
      const c = geo.timezone.utc_offset * 15;
      g.fillStyle = "rgba(242,184,75,0.10)"; g.fillRect(X(c - 7.5), 0, X(c + 7.5) - X(c - 7.5), H);
    }
    const pts = geo.points || [];
    const top = (geo.clusters || [])[0];
    pts.forEach((p) => {
      const col = (KIND[p.kind] || ["#fff"])[0];
      const r = 4 + p.weight * 6;
      g.beginPath(); g.arc(X(p.lon), Y(p.lat), r, 0, Math.PI * 2);
      g.fillStyle = col + "99"; g.fill(); g.strokeStyle = col; g.lineWidth = 1.5; g.stroke();
    });
    if (top) {
      g.beginPath(); g.arc(X(top.lon), Y(top.lat), 14, 0, Math.PI * 2);
      g.strokeStyle = "#35d08a"; g.lineWidth = 2; g.stroke();
      g.fillStyle = text; g.font = "600 12px system-ui, sans-serif"; g.textBaseline = "middle";
      const label = top.label, tw = g.measureText(label).width;
      const lx = X(top.lon) + 18 + tw > W ? X(top.lon) - 18 - tw : X(top.lon) + 18;
      g.fillText(label, lx, Y(top.lat));
    }
  }

  // Real map: OpenStreetMap tiles fetched through this server (/api/tile),
  // drawn on the canvas with the evidence markers on top. Zoom stops at city level.
  function drawTiles(canvas, geo, status) {
    const pts = geo.points || [];
    if (!pts.length) return;
    const W = canvas.clientWidth || 800, H = Math.round(W * 0.55);
    const dpr = window.devicePixelRatio || 1;
    canvas.width = W * dpr; canvas.height = H * dpr; canvas.style.height = H + "px";
    const g = canvas.getContext("2d");
    g.scale(dpr, dpr);
    const lat2y = (lat, z) => ((1 - Math.log(Math.tan((lat * Math.PI) / 180) + 1 / Math.cos((lat * Math.PI) / 180)) / Math.PI) / 2) * 256 * 2 ** z;
    const lon2x = (lon, z) => ((lon + 180) / 360) * 256 * 2 ** z;
    const lats = pts.map((p) => p.lat), lons = pts.map((p) => p.lon);
    const minLat = Math.min(...lats), maxLat = Math.max(...lats), minLon = Math.min(...lons), maxLon = Math.max(...lons);
    let z = 11;
    for (; z > 1; z--) {
      if (Math.abs(lon2x(maxLon, z) - lon2x(minLon, z)) < W * 0.8 && Math.abs(lat2y(minLat, z) - lat2y(maxLat, z)) < H * 0.8) break;
    }
    const cx = (lon2x(minLon, z) + lon2x(maxLon, z)) / 2, cy = (lat2y(minLat, z) + lat2y(maxLat, z)) / 2;
    const x0 = cx - W / 2, y0 = cy - H / 2;
    g.fillStyle = "#1b222b"; g.fillRect(0, 0, W, H);
    const n = 2 ** z;
    let pending = 0, failed = 0;
    const markers = () => {
      for (const p of pts) {
        const col = (KIND[p.kind] || ["#fff"])[0];
        const x = lon2x(p.lon, z) - x0, y = lat2y(p.lat, z) - y0;
        g.beginPath(); g.arc(x, y, 5 + p.weight * 6, 0, Math.PI * 2);
        g.fillStyle = col + "aa"; g.fill(); g.strokeStyle = "#fff"; g.lineWidth = 1.5; g.stroke();
      }
      const top = (geo.clusters || [])[0];
      if (top) {
        const x = lon2x(top.lon, z) - x0, y = lat2y(top.lat, z) - y0;
        g.beginPath(); g.arc(x, y, 16, 0, Math.PI * 2); g.strokeStyle = "#35d08a"; g.lineWidth = 3; g.stroke();
        g.font = "600 13px system-ui, sans-serif"; g.textBaseline = "middle";
        const tw = g.measureText(top.label).width;
        g.fillStyle = "rgba(10,13,18,0.8)"; g.fillRect(x + 20, y - 11, tw + 12, 22);
        g.fillStyle = "#fff"; g.fillText(top.label, x + 26, y);
      }
      g.font = "10px system-ui"; g.fillStyle = "rgba(255,255,255,0.8)"; g.fillText("© OpenStreetMap contributors", 6, H - 8);
      if (failed) status.textContent = failed + " tile(s) could not be loaded.";
    };
    const tx0 = Math.floor(x0 / 256), tx1 = Math.floor((x0 + W) / 256), ty0 = Math.floor(y0 / 256), ty1 = Math.floor((y0 + H) / 256);
    for (let tx = tx0; tx <= tx1; tx++) {
      for (let ty = ty0; ty <= ty1; ty++) {
        if (ty < 0 || ty >= n) continue;
        pending++;
        const img = new Image();
        const done = () => { if (--pending === 0) markers(); };
        img.onload = () => { g.drawImage(img, tx * 256 - x0, ty * 256 - y0); done(); };
        img.onerror = () => { failed++; done(); };
        img.src = `/api/tile/${z}/${((tx % n) + n) % n}/${ty}`;
      }
    }
    if (pending === 0) markers();
  }

  function osmLink(p) {
    return `https://www.openstreetmap.org/?mlat=${p.lat}&mlon=${p.lon}#map=${p.precision === "country" ? 5 : p.precision === "region" ? 7 : 11}/${p.lat}/${p.lon}`;
  }

  function hoursChart(tz) {
    const max = Math.max(1, ...tz.hours_utc);
    const quiet = new Set();
    // the quiet window in UTC: local 00:00-07:00 shifted back by the offset
    for (let h = 0; h < 7; h++) quiet.add((((h - tz.utc_offset) % 24) + 24) % 24);
    const wrap = el("div", { class: "hours" });
    tz.hours_utc.forEach((n, h) => {
      const bar = el("div", { class: "hbar" + (quiet.has(h) ? " quiet" : ""), title: `${String(h).padStart(2, "0")}:00 UTC · ${n} events` });
      const fill = el("div", { class: "hfill" });
      fill.style.height = Math.max(2, Math.round((n / max) * 100)) + "%";
      bar.append(fill, el("span", { text: String(h) }));
      wrap.append(bar);
    });
    return wrap;
  }

  function location() {
    const S = RT.S, root = $("tab-location");
    root.replaceChildren();
    const geo = S.report && S.report.geo;
    if (!geo) {
      root.append(el("div", { class: "panel muted", text: S.state === "running"
        ? "Location analysis runs when the scan finishes, once all profiles, IP/phone data, pictures and activity hours are in."
        : "No location evidence was found. Give a username (activity hours), an IP or phone number, or a full name with some context, and run again." }));
      return;
    }
    const top = (geo.clusters || [])[0];
    const head = el("div", { class: "panel loc-head" });
    head.append(el("div", { class: "muted", text: "Most likely location" }),
      el("h2", { class: "loc-main", text: top ? top.label : "Not determined" }));
    if (top) head.append(el("span", { class: "score " + (top.score >= 0.7 ? "hi" : top.score >= 0.4 ? "mid" : "lo"), text: "support " + Math.round(top.score * 100) + "%" }),
      el("span", { class: "hint-line", text: " from " + (top.kinds || []).map((k) => (KIND[k] || [0, k])[1]).join(", ") }));
    if (geo.given) {
      const fit = { agrees: "✔ agrees with the location you gave (" + geo.given + ")", differs: "⚠ differs from the location you gave (" + geo.given + ")", unknown: "" }[geo.given_fit] || "";
      if (fit) head.append(el("div", { class: geo.given_fit === "agrees" ? "ok-line" : "conflict", text: fit }));
    }
    if (geo.conflict) head.append(el("div", { class: "conflict", text: "⚠ " + geo.conflict }));
    for (const n of geo.notes || []) head.append(el("div", { class: "hint-line", text: "• " + n }));
    root.append(head);

    const mapPanel = el("div", { class: "panel" }, el("h3", { text: "Evidence map" }));
    const canvas = el("canvas", { class: "locmap" });
    mapPanel.append(canvas);
    const legend = el("div", { class: "chips", style: "margin-top:8px" });
    Object.entries(KIND).forEach(([k, [c, label]]) => {
      const dot = el("span", { class: "ldot" });
      dot.style.background = c;
      legend.append(el("span", { class: "chip" }, dot, el("span", { text: label })));
    });
    const mapBtn = el("button", { type: "button", class: "ghost small", text: "Load street map (OpenStreetMap tiles via rectool)" });
    const mapStatus = el("span", { class: "hint-line" });
    mapBtn.title = "The map tiles are downloaded by rectool from tile.openstreetmap.org (they reveal which area you are viewing to OpenStreetMap, nothing about the subject). Zoom stops at city level.";
    mapBtn.addEventListener("click", () => { mapBtn.disabled = true; mapStatus.textContent = " loading tiles…"; drawTiles(canvas, geo, mapStatus); mapStatus.textContent = ""; });
    mapPanel.append(el("div", { style: "margin-top:8px" }, mapBtn, mapStatus));
    mapPanel.append(legend, el("p", { class: "hint-line", text: "Dot size = how much that evidence is trusted. Green ring = best-supported place. Shaded strip = the timezone estimated from activity hours. Outlines are schematic." }));
    root.append(mapPanel);
    requestAnimationFrame(() => drawMap(canvas, geo));

    if ((geo.clusters || []).length > 1) {
      const p = el("div", { class: "panel" }, el("h3", { text: "Candidate places" }));
      for (const c of geo.clusters) {
        const r = el("div", { class: "frow" }, el("div", { class: "k", text: Math.round(c.score * 100) + "%" }),
          el("div", {}, el("b", { text: c.label }), el("span", { class: "muted", text: "  " + (c.kinds || []).join(" · ") + " · " + c.points.length + " clue(s)" })));
        p.append(r);
      }
      root.append(p);
    }

    const tp = el("div", { class: "panel" }, el("h3", { text: `Evidence (${geo.points.length})` }));
    const tbl = el("table", { class: "tbl" }, el("thead", {}, el("tr", {}, ...["Type", "As found", "Resolved to", "Precision", "Trust", "Sources"].map((h) => el("th", { text: h })))));
    const tb = el("tbody");
    for (const p of geo.points) {
      const col = (KIND[p.kind] || ["#fff"])[0];
      const dot = el("span", { class: "ldot" });
      dot.style.background = col;
      const href = RT.safeHref(osmLink(p));
      tb.append(el("tr", {},
        el("td", {}, dot, document.createTextNode(" " + p.kind)),
        el("td", { text: p.label }),
        el("td", {}, href ? el("a", { href, target: "_blank", rel: "noopener noreferrer", text: [p.city, p.region, p.country].filter(Boolean).join(", ") || p.place || "map" }) : document.createTextNode(p.place || "")),
        el("td", { text: p.precision }),
        el("td", { text: Math.round(p.weight * 100) + "%" }),
        el("td", { class: "muted", text: (p.sources || []).slice(0, 3).join(" · ") })));
    }
    tbl.append(tb);
    tp.append(tbl);
    root.append(tp);

    if (geo.timezone) {
      const tz = geo.timezone;
      const p = el("div", { class: "panel" }, el("h3", { text: "Timezone from activity hours" }),
        el("p", {}, el("b", { text: tz.label }), ` — confidence ${Math.round(tz.confidence * 100)}%, from ${tz.events} public events (${(tz.sources || []).join(", ")})`),
        el("p", { class: "muted", text: "Typical places: " + ((tz.regions || []).join("; ") || "—") }),
        hoursChart(tz),
        el("p", { class: "hint-line", text: "Bars = events per hour (UTC). Highlighted bars = the quiet window assumed to be local night (00:00–07:00). Shift work, automation, bots and travel weaken this signal." }));
      root.append(p);
    }
    root.append(el("p", { class: "hint-line", text: "Location here comes from what is publicly stated or technically visible, and is shown at city / region precision. IP and phone data describe an ISP or number range, not a person's home. rectool does not search for street addresses." }));
  }

  RT.timelinePanel = function timelinePanel(tl) {
    const p = el("div", { class: "panel" }, el("h3", { text: `Timeline (${tl.length})` }),
      el("p", { class: "hint-line", text: "Dated facts from the accounts, archives and files found, oldest first." }));
    const list = el("div", { class: "timeline" });
    for (const e of tl) {
      const href = RT.safeHref(e.url);
      list.append(el("div", { class: "tl-row" }, el("span", { class: "tl-date", text: e.date }), el("span", { class: "tl-dot" }),
        el("span", {}, el("b", { text: e.event }), document.createTextNode(" · "), href ? el("a", { href, target: "_blank", rel: "noopener noreferrer", text: e.source }) : document.createTextNode(e.source))));
    }
    p.append(list);
    return p;
  };

  RT.views.location = location;
  window.addEventListener("resize", () => { if (RT.tab === "location") RT.scheduleRender(true); });
})();

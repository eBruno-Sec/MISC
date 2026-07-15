/* Round Table // 2D block/rectangle attack-surface graph (layered, zoom/pan/filter). */
(function () {
  const SEV_COLOR = {
    CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706',
    LOW: '#65a30d', INFO: '#0891b2', UNKNOWN: '#64748b',
  };
  const COL_W = 230, ROW_H = 42, NODE_H = 30, PAD = 34;

  let cv, ctx, allNodes = [], links = [], nodesById = {}, raf = null;
  let drag = null, hover = null, onClick = null, panning = false;
  let W = 0, H = 0, dpr = 1;
  let labelColor = '#cbd5e1', nodeFill = '#111827', nodeBorder = '#263143';
  let visible = null;
  const cam = { s: 1, x: 0, y: 0 };
  const mouse = { x: 0, y: 0, lx: 0, ly: 0 };

  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const w2s = p => ({ x: p * cam.s + cam.x });
  const sx = x => x * cam.s + cam.x;
  const sy = y => y * cam.s + cam.y;
  const s2wx = x => (x - cam.x) / cam.s;
  const s2wy = y => (y - cam.y) / cam.s;
  const isVis = n => n.type === 'domain' || !visible || visible.has(n.type);

  function size() {
    const r = cv.getBoundingClientRect();
    dpr = window.devicePixelRatio || 1;
    W = r.width; H = r.height;
    cv.width = W * dpr; cv.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function readTheme() {
    const css = getComputedStyle(document.documentElement);
    nodeFill = (css.getPropertyValue('--panel') || '#111827').trim();
    nodeBorder = (css.getPropertyValue('--line2') || '#263143').trim();
    if (!labelColor) labelColor = (css.getPropertyValue('--topo-label') || '#cbd5e1').trim();
  }

  function render(canvas, data, opts) {
    cv = canvas; ctx = cv.getContext('2d');
    onClick = (opts && opts.onNodeClick) || null;
    labelColor = (opts && opts.labelColor) || '';
    visible = (opts && opts.visibleTypes) || null;
    cam.s = 1; cam.x = 0; cam.y = 0;
    size(); readTheme();
    nodesById = {};
    allNodes = (data.nodes || []).map(n => ({ ...n, x: 0, y: 0, w: 150, h: NODE_H }));
    allNodes.forEach(n => { nodesById[n.id] = n; });
    links = (data.links || []).map(l => ({ s: nodesById[l.source], t: nodesById[l.target] })).filter(l => l.s && l.t);
    layout();
    bind();
    if (!raf) loop();
  }

  // ── layered layout: BFS columns from the domain node ──
  function layout() {
    ctx.font = '12px -apple-system,Segoe UI,sans-serif';
    const vis = allNodes.filter(isVis);
    for (const n of vis) n.w = Math.min(200, Math.max(110, ctx.measureText(clip(n.label, 24)).width + 26));

    const level = {};
    const root = vis.find(n => n.type === 'domain') || vis[0];
    if (!root) return;
    level[root.id] = 0;
    const q = [root], adj = {};
    for (const l of links) {
      if (!isVis(l.s) || !isVis(l.t)) continue;
      (adj[l.s.id] = adj[l.s.id] || []).push(l.t.id);
      (adj[l.t.id] = adj[l.t.id] || []).push(l.s.id);
    }
    while (q.length) {
      const cur = q.shift();
      for (const nb of adj[cur.id] || []) {
        if (level[nb] === undefined) { level[nb] = level[cur.id] + 1; q.push(nodesById[nb]); }
      }
    }
    let maxLvl = 0;
    for (const n of vis) { if (level[n.id] === undefined) level[n.id] = 99; maxLvl = Math.max(maxLvl, level[n.id] === 99 ? 0 : level[n.id]); }
    // disconnected nodes → last column
    for (const n of vis) if (level[n.id] === 99) level[n.id] = maxLvl + 1;

    const byLvl = {};
    for (const n of vis) (byLvl[level[n.id]] = byLvl[level[n.id]] || []).push(n);
    const rank = s => ({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 }[s] || 0);

    let maxCount = 1;
    Object.values(byLvl).forEach(a => { maxCount = Math.max(maxCount, a.length); });
    const totalH = maxCount * ROW_H;

    Object.keys(byLvl).map(Number).sort((a, b) => a - b).forEach(lvl => {
      const col = byLvl[lvl].sort((a, b) => rank(b.severity) - rank(a.severity));
      const colH = col.length * ROW_H;
      const startY = PAD + (totalH - colH) / 2;
      col.forEach((n, i) => { n.x = PAD + lvl * COL_W; n.y = startY + i * ROW_H; });
    });
  }

  function bind() {
    cv.onmousedown = e => {
      const p = pos(e); mouse.lx = p.x; mouse.ly = p.y;
      const n = pick(p.x, p.y);
      if (n) drag = n; else panning = true;
    };
    cv.onmousemove = e => {
      const p = pos(e); mouse.x = p.x; mouse.y = p.y;
      if (drag) { drag.x = s2wx(p.x) - drag.w / 2; drag.y = s2wy(p.y) - drag.h / 2; }
      else if (panning) { cam.x += p.x - mouse.lx; cam.y += p.y - mouse.ly; mouse.lx = p.x; mouse.ly = p.y; }
      else { hover = pick(p.x, p.y); cv.style.cursor = hover ? 'pointer' : 'grab'; }
    };
    window.addEventListener('mouseup', () => { drag = null; panning = false; });
    cv.onmouseleave = () => { drag = null; panning = false; };
    cv.onclick = e => { const p = pos(e); const n = pick(p.x, p.y); if (n && onClick) onClick(n); };
    cv.onwheel = e => {
      e.preventDefault();
      const p = pos(e); const bx = s2wx(p.x), by = s2wy(p.y);
      cam.s = clamp(cam.s * (e.deltaY < 0 ? 1.12 : 0.89), 0.25, 3.5);
      cam.x = p.x - bx * cam.s; cam.y = p.y - by * cam.s;
    };
    window.addEventListener('resize', size);
  }

  function pos(e) { const r = cv.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; }
  function pick(mx, my) {
    for (let i = allNodes.length - 1; i >= 0; i--) {
      const n = allNodes[i]; if (!isVis(n)) continue;
      const x = sx(n.x), y = sy(n.y), w = n.w * cam.s, h = n.h * cam.s;
      if (mx >= x && mx <= x + w && my >= y && my <= y + h) return n;
    }
    return null;
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    // links: orthogonal connectors, parent-right → child-left
    ctx.lineWidth = 1.2; ctx.strokeStyle = 'rgba(148,163,184,0.35)';
    for (const l of links) {
      if (!isVis(l.s) || !isVis(l.t)) continue;
      const a = l.s.x <= l.t.x ? l.s : l.t, b = a === l.s ? l.t : l.s;
      const ax = sx(a.x + a.w), ay = sy(a.y + a.h / 2), bx = sx(b.x), by = sy(b.y + b.h / 2);
      const mid = (ax + bx) / 2;
      ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(mid, ay); ctx.lineTo(mid, by); ctx.lineTo(bx, by); ctx.stroke();
    }
    // rectangle nodes with a severity stripe
    ctx.font = '12px -apple-system,Segoe UI,sans-serif'; ctx.textBaseline = 'middle';
    for (const n of allNodes) {
      if (!isVis(n)) continue;
      const x = sx(n.x), y = sy(n.y), w = n.w * cam.s, h = n.h * cam.s, c = SEV_COLOR[n.severity] || SEV_COLOR.INFO;
      if (n === hover) { ctx.fillStyle = 'rgba(148,163,184,0.14)'; rrect(x - 3, y - 3, w + 6, h + 6, 8); ctx.fill(); }
      ctx.fillStyle = nodeFill; ctx.strokeStyle = nodeBorder; ctx.lineWidth = 1.2;
      rrect(x, y, w, h, 7); ctx.fill(); ctx.stroke();
      ctx.fillStyle = c; rrect(x, y, 5 * Math.max(0.7, cam.s), h, 7); ctx.fill();   // severity stripe
      ctx.fillStyle = labelColor;
      ctx.fillText(clip(n.label, 24), x + 12, y + h / 2 + 0.5);
    }
    if (hover && isVis(hover)) tooltip(hover);
  }

  function tooltip(n) {
    const lines = [n.label, `${n.type} · ${n.severity}`];
    const m = n.meta || {};
    if (m.tech && m.tech.length) lines.push('tech: ' + m.tech.slice(0, 4).join(', '));
    if (m.status) lines.push('status: ' + m.status);
    if (m.title) lines.push(m.title);
    if (m.line) lines.push(m.line);
    if (m.category) lines.push('cat: ' + m.category);
    ctx.font = '11px -apple-system,Segoe UI,sans-serif'; ctx.textBaseline = 'alphabetic';
    const w = Math.max(...lines.map(t => ctx.measureText(t).width)) + 16, h = lines.length * 15 + 10;
    let x = sx(n.x) + n.w * cam.s + 8, y = sy(n.y);
    if (x + w > W) x = sx(n.x) - w - 8; if (y + h > H) y = H - h - 4;
    ctx.fillStyle = 'rgba(15,21,32,0.97)'; ctx.strokeStyle = '#334155'; ctx.lineWidth = 1;
    rrect(x, y, w, h, 7); ctx.fill(); ctx.stroke();
    lines.forEach((t, i) => { ctx.fillStyle = i === 0 ? '#fff' : '#cbd5e1'; ctx.fillText(t, x + 8, y + 17 + i * 15); });
    ctx.textBaseline = 'middle';
  }

  function rrect(x, y, w, h, r) {
    r = Math.min(r, h / 2, w / 2);
    ctx.beginPath(); ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }
  const clip = (s, n) => { s = s || ''; return s.length > n ? s.slice(0, n - 1) + '…' : s; };
  function loop() { draw(); raf = requestAnimationFrame(loop); }

  function recenter() { cam.s = 1; cam.x = 0; cam.y = 0; layout(); }
  function zoom(f) {
    const bx = s2wx(W / 2), by = s2wy(H / 2);
    cam.s = clamp(cam.s * f, 0.25, 3.5);
    cam.x = W / 2 - bx * cam.s; cam.y = H / 2 - by * cam.s;
  }
  function setVisibleTypes(set) { visible = set; layout(); }
  function destroy() { if (raf) cancelAnimationFrame(raf); raf = null; allNodes = []; links = []; }

  window.Topology = { render, recenter, zoom, setVisibleTypes, destroy, SEV_COLOR };
})();

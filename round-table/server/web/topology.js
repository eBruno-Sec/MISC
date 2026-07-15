/* Round Table // 2D attack-surface topology (canvas force layout + zoom/pan/filter). */
(function () {
  const SEV_COLOR = {
    CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706',
    LOW: '#65a30d', INFO: '#0891b2', UNKNOWN: '#64748b',
  };
  const TYPE_R = { domain: 16, host: 10, port: 7, subdomain: 8, endpoint: 7 };

  let cv, ctx, nodes = [], links = [], raf = null;
  let drag = null, hover = null, onClick = null, panning = false;
  let W = 0, H = 0, dpr = 1;
  let labelColor = '#cbd5e1';
  let visible = null; // Set of visible types, or null = all
  const cam = { s: 1, x: 0, y: 0 };
  const mouse = { x: 0, y: 0, lx: 0, ly: 0 };

  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const w2s = p => ({ x: p.x * cam.s + cam.x, y: p.y * cam.s + cam.y });
  const s2w = (sx, sy) => ({ x: (sx - cam.x) / cam.s, y: (sy - cam.y) / cam.s });
  const isVis = n => n.type === 'domain' || !visible || visible.has(n.type);

  function size() {
    const r = cv.getBoundingClientRect();
    dpr = window.devicePixelRatio || 1;
    W = r.width; H = r.height;
    cv.width = W * dpr; cv.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function render(canvas, data, opts) {
    cv = canvas; ctx = cv.getContext('2d');
    onClick = (opts && opts.onNodeClick) || null;
    labelColor = (opts && opts.labelColor) || '#cbd5e1';
    visible = (opts && opts.visibleTypes) || null;
    cam.s = 1; cam.x = 0; cam.y = 0;
    size();
    const byId = {};
    nodes = (data.nodes || []).map((n, i) => {
      const angle = (i / Math.max(1, data.nodes.length)) * Math.PI * 2;
      const rad = n.type === 'domain' ? 0 : 120 + (i % 5) * 40;
      const node = {
        ...n,
        x: W / 2 + Math.cos(angle) * rad + (Math.random() - 0.5) * 40,
        y: H / 2 + Math.sin(angle) * rad + (Math.random() - 0.5) * 40,
        vx: 0, vy: 0, r: TYPE_R[n.type] || 7, pinned: n.type === 'domain',
      };
      byId[n.id] = node;
      return node;
    });
    if (nodes[0]) { nodes[0].x = W / 2; nodes[0].y = H / 2; }
    links = (data.links || []).map(l => ({ s: byId[l.source], t: byId[l.target] })).filter(l => l.s && l.t);
    bind();
    if (!raf) loop();
  }

  function bind() {
    cv.onmousedown = e => {
      const p = pos(e); mouse.lx = p.x; mouse.ly = p.y;
      const n = pick(p.x, p.y);
      if (n) { drag = n; n.pinned = true; } else { panning = true; }
    };
    cv.onmousemove = e => {
      const p = pos(e); mouse.x = p.x; mouse.y = p.y;
      if (drag) { const w = s2w(p.x, p.y); drag.x = w.x; drag.y = w.y; drag.vx = drag.vy = 0; }
      else if (panning) { cam.x += p.x - mouse.lx; cam.y += p.y - mouse.ly; mouse.lx = p.x; mouse.ly = p.y; }
      else { hover = pick(p.x, p.y); cv.style.cursor = hover ? 'pointer' : 'grab'; }
    };
    window.addEventListener('mouseup', endDrag);
    cv.onmouseleave = endDrag;
    cv.onclick = e => { const p = pos(e); const n = pick(p.x, p.y); if (n && onClick) onClick(n); };
    cv.onwheel = e => {
      e.preventDefault();
      const p = pos(e); const before = s2w(p.x, p.y);
      cam.s = clamp(cam.s * (e.deltaY < 0 ? 1.12 : 0.89), 0.2, 4);
      cam.x = p.x - before.x * cam.s; cam.y = p.y - before.y * cam.s;
    };
    window.addEventListener('resize', size);
  }
  function endDrag() { if (drag && drag.type !== 'domain') drag.pinned = false; drag = null; panning = false; }

  function pos(e) { const r = cv.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; }
  function nodeR(n) { return n.r * clamp(cam.s, 0.5, 2.4); }
  function pick(x, y) {
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i]; if (!isVis(n)) continue;
      const s = w2s(n); if (Math.hypot(s.x - x, s.y - y) <= nodeR(n) + 6) return n;
    }
    return null;
  }

  function tick() {
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy || 1;
        const f = 2600 / d2, d = Math.sqrt(d2), ux = dx / d, uy = dy / d;
        a.vx += ux * f; a.vy += uy * f; b.vx -= ux * f; b.vy -= uy * f;
      }
    }
    for (const l of links) {
      let dx = l.t.x - l.s.x, dy = l.t.y - l.s.y, d = Math.hypot(dx, dy) || 1;
      const f = (d - 90) * 0.02, ux = dx / d, uy = dy / d;
      l.s.vx += ux * f; l.s.vy += uy * f; l.t.vx -= ux * f; l.t.vy -= uy * f;
    }
    for (const n of nodes) {
      n.vx += (W / 2 - n.x) * 0.0015; n.vy += (H / 2 - n.y) * 0.0015;
      n.vx *= 0.86; n.vy *= 0.86;
      if (!n.pinned) { n.x += n.vx; n.y += n.vy; }
    }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    ctx.lineWidth = 1;
    for (const l of links) {
      if (!isVis(l.s) || !isVis(l.t)) continue;
      const a = w2s(l.s), b = w2s(l.t);
      ctx.strokeStyle = 'rgba(148,163,184,0.20)';
      ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    }
    for (const n of nodes) {
      if (!isVis(n)) continue;
      const s = w2s(n), r = nodeR(n), c = SEV_COLOR[n.severity] || SEV_COLOR.INFO;
      if (n === hover) { ctx.beginPath(); ctx.arc(s.x, s.y, r + 6, 0, Math.PI * 2); ctx.fillStyle = 'rgba(148,163,184,0.18)'; ctx.fill(); }
      ctx.beginPath(); ctx.arc(s.x, s.y, r, 0, Math.PI * 2); ctx.fillStyle = c; ctx.fill();
      ctx.lineWidth = 2; ctx.strokeStyle = 'rgba(10,14,22,0.85)'; ctx.stroke();
      const nVis = nodes.filter(isVis).length;
      if (n.type === 'domain' || n.type === 'host' || n === hover || nVis < 30) {
        ctx.fillStyle = labelColor; ctx.font = '11px -apple-system,Segoe UI,sans-serif'; ctx.textAlign = 'center';
        ctx.fillText(clip(n.label, 22), s.x, s.y + r + 12);
      }
    }
    if (hover && isVis(hover)) tooltip(hover);
  }

  function tooltip(n) {
    const s = w2s(n);
    const lines = [n.label, `type: ${n.type} · ${n.severity}`];
    const m = n.meta || {};
    if (m.tech && m.tech.length) lines.push('tech: ' + m.tech.slice(0, 4).join(', '));
    if (m.status) lines.push('status: ' + m.status);
    if (m.title) lines.push(m.title);
    if (m.line) lines.push(m.line);
    if (m.category) lines.push('cat: ' + m.category);
    ctx.font = '11px -apple-system,Segoe UI,sans-serif'; ctx.textAlign = 'left';
    const w = Math.max(...lines.map(t => ctx.measureText(t).width)) + 16;
    const h = lines.length * 15 + 10;
    let x = s.x + 14, y = s.y - h - 8;
    if (x + w > W) x = s.x - w - 14; if (y < 0) y = s.y + 14;
    ctx.fillStyle = 'rgba(15,21,32,0.96)'; ctx.strokeStyle = '#334155';
    roundRect(x, y, w, h, 7); ctx.fill(); ctx.stroke();
    lines.forEach((t, i) => { ctx.fillStyle = i === 0 ? '#fff' : '#cbd5e1'; ctx.fillText(t, x + 8, y + 17 + i * 15); });
  }

  function roundRect(x, y, w, h, r) {
    ctx.beginPath(); ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }
  const clip = (s, n) => { s = s || ''; return s.length > n ? s.slice(0, n - 1) + '…' : s; };
  function loop() { tick(); draw(); raf = requestAnimationFrame(loop); }

  function recenter() {
    cam.s = 1; cam.x = 0; cam.y = 0;
    for (const n of nodes) {
      if (n.type === 'domain') { n.x = W / 2; n.y = H / 2; }
      else { n.x = W / 2 + (Math.random() - 0.5) * 220; n.y = H / 2 + (Math.random() - 0.5) * 220; n.vx = n.vy = 0; }
    }
  }
  function zoom(factor) {
    const before = s2w(W / 2, H / 2);
    cam.s = clamp(cam.s * factor, 0.2, 4);
    cam.x = W / 2 - before.x * cam.s; cam.y = H / 2 - before.y * cam.s;
  }
  function setVisibleTypes(set) { visible = set; }
  function destroy() { if (raf) cancelAnimationFrame(raf); raf = null; nodes = []; links = []; }

  window.Topology = { render, recenter, zoom, setVisibleTypes, destroy, SEV_COLOR };
})();

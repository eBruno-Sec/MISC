/* Round Table // 2D attack-surface topology (self-contained canvas force layout). */
(function () {
  const SEV_COLOR = {
    CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706',
    LOW: '#65a30d', INFO: '#0891b2', UNKNOWN: '#64748b',
  };
  const TYPE_R = { domain: 16, host: 10, port: 7, subdomain: 8, endpoint: 7 };

  let cv, ctx, nodes = [], links = [], raf = null;
  let drag = null, hover = null, onClick = null;
  let W = 0, H = 0, dpr = 1;
  const mouse = { x: 0, y: 0, down: false };

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
    size();
    const byId = {};
    nodes = (data.nodes || []).map((n, i) => {
      const angle = (i / Math.max(1, data.nodes.length)) * Math.PI * 2;
      const rad = n.type === 'domain' ? 0 : 120 + (i % 5) * 40;
      const node = {
        ...n,
        x: W / 2 + Math.cos(angle) * rad + (Math.random() - 0.5) * 40,
        y: H / 2 + Math.sin(angle) * rad + (Math.random() - 0.5) * 40,
        vx: 0, vy: 0,
        r: TYPE_R[n.type] || 7,
        pinned: n.type === 'domain',
      };
      byId[n.id] = node;
      return node;
    });
    if (nodes[0]) { nodes[0].x = W / 2; nodes[0].y = H / 2; }
    links = (data.links || []).map(l => ({ s: byId[l.source], t: byId[l.target] })).filter(l => l.s && l.t);
    bind();
    loop();
  }

  function bind() {
    cv.onmousedown = e => {
      const p = pos(e); mouse.down = true;
      const n = pick(p.x, p.y);
      if (n) { drag = n; n.pinned = true; }
    };
    cv.onmousemove = e => {
      const p = pos(e); mouse.x = p.x; mouse.y = p.y;
      if (drag) { drag.x = p.x; drag.y = p.y; drag.vx = drag.vy = 0; }
      else { hover = pick(p.x, p.y); cv.style.cursor = hover ? 'pointer' : 'grab'; }
    };
    window.addEventListener('mouseup', () => {
      mouse.down = false;
      if (drag && drag.type !== 'domain') drag.pinned = false;
      drag = null;
    });
    cv.onclick = e => {
      const p = pos(e); const n = pick(p.x, p.y);
      if (n && onClick) onClick(n);
    };
    window.addEventListener('resize', size);
  }

  function pos(e) { const r = cv.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; }
  function pick(x, y) {
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i], d = Math.hypot(n.x - x, n.y - y);
      if (d <= n.r + 6) return n;
    }
    return null;
  }

  function tick() {
    // repulsion
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy || 1;
        const f = 2600 / d2, d = Math.sqrt(d2);
        const ux = dx / d, uy = dy / d;
        a.vx += ux * f; a.vy += uy * f; b.vx -= ux * f; b.vy -= uy * f;
      }
    }
    // springs
    for (const l of links) {
      let dx = l.t.x - l.s.x, dy = l.t.y - l.s.y, d = Math.hypot(dx, dy) || 1;
      const rest = 90, f = (d - rest) * 0.02, ux = dx / d, uy = dy / d;
      l.s.vx += ux * f; l.s.vy += uy * f; l.t.vx -= ux * f; l.t.vy -= uy * f;
    }
    // gravity + integrate
    for (const n of nodes) {
      n.vx += (W / 2 - n.x) * 0.0015;
      n.vy += (H / 2 - n.y) * 0.0015;
      n.vx *= 0.86; n.vy *= 0.86;
      if (!n.pinned) { n.x += n.vx; n.y += n.vy; }
      n.x = Math.max(n.r + 4, Math.min(W - n.r - 4, n.x));
      n.y = Math.max(n.r + 4, Math.min(H - n.r - 4, n.y));
    }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    // links
    ctx.lineWidth = 1;
    for (const l of links) {
      ctx.strokeStyle = 'rgba(148,163,184,0.18)';
      ctx.beginPath(); ctx.moveTo(l.s.x, l.s.y); ctx.lineTo(l.t.x, l.t.y); ctx.stroke();
    }
    // nodes
    for (const n of nodes) {
      const c = SEV_COLOR[n.severity] || SEV_COLOR.INFO;
      if (n === hover) {
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 6, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(255,255,255,0.06)'; ctx.fill();
      }
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = c; ctx.fill();
      ctx.lineWidth = 2; ctx.strokeStyle = 'rgba(10,14,22,0.9)'; ctx.stroke();
      if (n.type === 'domain' || n.type === 'host' || n === hover || nodes.length < 30) {
        ctx.fillStyle = '#cbd5e1'; ctx.font = '11px -apple-system,Segoe UI,sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(clip(n.label, 22), n.x, n.y + n.r + 12);
      }
    }
    if (hover) tooltip(hover);
  }

  function tooltip(n) {
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
    let x = n.x + 14, y = n.y - h - 8;
    if (x + w > W) x = n.x - w - 14; if (y < 0) y = n.y + 14;
    ctx.fillStyle = 'rgba(15,21,32,0.96)'; ctx.strokeStyle = '#263143';
    roundRect(x, y, w, h, 7); ctx.fill(); ctx.stroke();
    ctx.fillStyle = '#e5e7eb';
    lines.forEach((t, i) => { ctx.fillStyle = i === 0 ? '#fff' : '#94a3b8'; ctx.fillText(t, x + 8, y + 17 + i * 15); });
  }

  function roundRect(x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }
  function clip(s, n) { s = s || ''; return s.length > n ? s.slice(0, n - 1) + '…' : s; }

  function loop() { tick(); draw(); raf = requestAnimationFrame(loop); }

  function recenter() {
    for (const n of nodes) {
      if (n.type === 'domain') { n.x = W / 2; n.y = H / 2; }
      else {
        n.x = W / 2 + (Math.random() - 0.5) * 200;
        n.y = H / 2 + (Math.random() - 0.5) * 200;
        n.vx = n.vy = 0;
      }
    }
  }
  function destroy() { if (raf) cancelAnimationFrame(raf); raf = null; nodes = []; links = []; }

  window.Topology = { render, recenter, destroy, SEV_COLOR };
})();

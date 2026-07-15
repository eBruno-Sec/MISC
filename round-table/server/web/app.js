/* Round Table // SPA controller */
'use strict';

const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_COLOR = {
  CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706',
  LOW: '#65a30d', INFO: '#0891b2', UNKNOWN: '#64748b',
};

const state = {
  missions: [], currentId: null, mission: null,
  guidance: [], sevFilter: new Set(SEV), search: '',
  ws: null, tab: 'overview', topoRendered: false,
};

const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function api(path, opts) {
  const r = await fetch(path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts));
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail || msg; } catch (_) {}
    throw new Error(msg);
  }
  const ct = r.headers.get('content-type') || '';
  return ct.includes('application/json') ? r.json() : r.text();
}

function toast(msg) {
  const t = $('toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(t._t); t._t = setTimeout(() => t.classList.add('hidden'), 1800);
}
async function copy(text) { try { await navigator.clipboard.writeText(text); toast('Copied'); } catch (_) { toast('Copy failed'); } }

/* ── boot ── */
window.addEventListener('DOMContentLoaded', () => {
  loadConfig(); loadMissions(); health();
  setInterval(health, 15000);
  setInterval(loadMissions, 6000);

  $('launch-btn').onclick = launch;
  $('target').addEventListener('keydown', e => { if (e.key === 'Enter') launch(); });
  $('target').addEventListener('input', validateTarget);

  // Draft state engine (client-side .json backup/restore)
  $('draft-save').onclick = saveDraft;
  $('draft-load').onclick = () => $('draft-file').click();
  $('draft-file').addEventListener('change', e => { loadDraftFromFile(e.target.files[0]); e.target.value = ''; });
  (() => {
    const dz = $('draft-drop');
    ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drag'); }));
    ['dragleave', 'dragend'].forEach(ev => dz.addEventListener(ev, () => dz.classList.remove('drag')));
    dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('drag'); loadDraftFromFile(e.dataTransfer.files[0]); });
    dz.addEventListener('click', () => $('draft-file').click());
    dz.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('draft-file').click(); } });
  })();

  document.querySelectorAll('.tab').forEach(b => b.onclick = () => setTab(b.dataset.tab));
  document.querySelectorAll('.ctab').forEach(b => b.onclick = () => {
    document.querySelectorAll('.ctab').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    $('c-resp-body').classList.toggle('hidden', b.dataset.ctab !== 'body');
    $('c-resp-headers').classList.toggle('hidden', b.dataset.ctab !== 'headers');
  });

  $('pb-search').addEventListener('input', e => { state.search = e.target.value.toLowerCase(); renderPlaybooks(); });
  $('topo-reset').onclick = () => window.Topology && window.Topology.recenter();
  $('topo-zin').onclick = () => window.Topology && window.Topology.zoom(1.25);
  $('topo-zout').onclick = () => window.Topology && window.Topology.zoom(0.8);

  ['c-method', 'c-url', 'c-headers', 'c-body', 'c-insecure', 'c-follow'].forEach(id =>
    $(id).addEventListener('input', updateCurlCmd));
  $('c-follow').addEventListener('change', updateCurlCmd);
  $('c-send').onclick = sendCurl;
  $('c-copy').onclick = () => copy($('c-cmd').textContent);

  initTheme();
  $('theme-toggle').onclick = toggleTheme;

  // Delegated clicks (payloads/cURL can contain quotes, so no inline handlers).
  document.addEventListener('click', e => {
    const lc = e.target.closest('.loadcurlbtn');
    if (lc) { loadReq(parseCurl(lc.dataset.loadcurl)); return; }
    const cp = e.target.closest('.copybtn');
    if (cp && cp.dataset.copy !== undefined) { copy(cp.dataset.copy); return; }
    const tc = e.target.closest('[data-tocurl]');
    if (tc) { toCurl(tc.dataset.tocurl); return; }
    const eh = e.target.closest('.pb-head[data-expand]');
    if (eh) { expand(eh.parentNode); return; }
  });
});

/* ── theme ── */
function initTheme() {
  const t = localStorage.getItem('rt-theme') || 'dark';
  document.documentElement.dataset.theme = t;
  const b = $('theme-toggle'); if (b) b.textContent = t === 'light' ? '☾' : '☀';
}
function toggleTheme() {
  const t = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = t;
  localStorage.setItem('rt-theme', t);
  $('theme-toggle').textContent = t === 'light' ? '☾' : '☀';
  if (state.tab === 'topology') renderTopology();
}

async function health() {
  try { await api('/api/health'); $('health-dot').className = 'dot ok'; }
  catch (_) { $('health-dot').className = 'dot bad'; }
}
async function loadConfig() {
  try {
    const c = await api('/api/config');
    const b = $('ai-badge');
    if (c.ai.enabled) { b.textContent = `AI: ${c.ai.provider}`; b.className = 'badge badge-on'; b.title = c.ai.model; }
    else { b.textContent = 'AI: off (rule-based)'; b.className = 'badge badge-muted'; }
  } catch (_) {}
}

/* ── target validation (inline, real-time) ── */
function validateTarget() {
  const el = $('target'), field = $('field-target'), st = $('target-status');
  const v = el.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  field.classList.remove('is-error', 'is-valid'); st.textContent = ''; st.className = 'field-status';
  if (!v) { el.removeAttribute('aria-invalid'); return true; }
  const ok = /^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?(:\d{1,5})?$/.test(v);
  el.setAttribute('aria-invalid', ok ? 'false' : 'true');
  if (ok) { field.classList.add('is-valid'); st.textContent = 'Looks good'; st.className = 'field-status ok'; }
  else { field.classList.add('is-error'); st.textContent = 'Enter a domain, host, or host:port'; st.className = 'field-status err'; }
  return ok;
}

/* ── draft state engine (deterministic .json export / validated import) ── */
const DRAFT_VERSION = 1;
function currentDraft() {
  return {
    app: 'round-table', type: 'mission_draft', version: DRAFT_VERSION,
    saved_at: new Date().toISOString(),
    data: { target: $('target').value, mode: $('mode').value, scope_text: $('scope').value },
  };
}
function saveDraft() {
  const blob = new Blob([JSON.stringify(currentDraft(), null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `FORM_draft_backup_${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast('Draft saved');
}
function validateDraft(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  if (o.type !== 'mission_draft') return false;
  if (typeof o.version !== 'number') return false;
  if (typeof o.saved_at !== 'string') return false;
  const d = o.data;
  if (!d || typeof d !== 'object' || Array.isArray(d)) return false;
  if (typeof d.target !== 'string') return false;
  if (!['passive', 'active', 'full'].includes(d.mode)) return false;
  if (!(typeof d.scope_text === 'string' || d.scope_text == null)) return false;
  return true;
}
function draftError(show) {
  const b = $('draft-error');
  if (show) { b.textContent = 'Invalid or corrupted draft file'; b.hidden = false; }
  else { b.hidden = true; b.textContent = ''; }
}
function hydrateDraft(d) {
  $('target').value = d.target || '';
  $('mode').value = ['passive', 'active', 'full'].includes(d.mode) ? d.mode : 'passive';
  $('scope').value = d.scope_text || '';
  if (d.scope_text) { const sc = document.querySelector('.scope'); if (sc) sc.open = true; }
  draftError(false); validateTarget();
  toast('Draft restored');
}
function loadDraftFromFile(file) {
  draftError(false);
  if (!file) return;
  if (!/\.json$/i.test(file.name || '') && file.type !== 'application/json') { draftError(true); return; }
  if (file.size > 2 * 1024 * 1024) { draftError(true); return; }
  const reader = new FileReader();
  reader.onload = () => {
    let obj;
    try { obj = JSON.parse(reader.result); } catch (_) { draftError(true); return; }
    if (!validateDraft(obj)) { draftError(true); return; }
    hydrateDraft(obj.data);
  };
  reader.onerror = () => draftError(true);
  reader.readAsText(file);
}

/* ── missions ── */
async function launch() {
  const btn = $('launch-btn');
  const target = $('target').value.trim();
  const mode = $('mode').value;
  const scope_text = $('scope').value.trim() || null;
  const msg = $('launch-msg');
  if (!target) { msg.textContent = 'Enter a target domain.'; msg.className = 'msg err'; $('target').focus(); return; }
  if (!validateTarget()) { msg.textContent = 'Fix the target format first.'; msg.className = 'msg err'; $('target').focus(); return; }
  msg.textContent = 'Launching…'; msg.className = 'msg';
  btn.disabled = true; btn.classList.add('is-loading');
  try {
    const r = await api('/api/missions', { method: 'POST', body: JSON.stringify({ target, mode, scope_text }) });
    msg.textContent = `Launched ${r.target} (${r.mode})`; msg.className = 'msg ok';
    await loadMissions();
    selectMission(r.id);
  } catch (e) { msg.textContent = 'Error: ' + e.message; msg.className = 'msg err'; }
  finally { btn.disabled = false; btn.classList.remove('is-loading'); }
}

async function loadMissions() {
  try { const r = await api('/api/missions'); state.missions = r.missions; renderMissionList(); }
  catch (_) {}
}

function renderMissionList() {
  const box = $('mission-list');
  if (!state.missions.length) { box.innerHTML = '<p class="muted small">No missions yet.</p>'; return; }
  box.innerHTML = state.missions.map(m => {
    const bs = (m.stats && m.stats.guidance && m.stats.guidance.by_severity) || {};
    const dots = SEV.filter(s => bs[s]).map(s =>
      `<span class="sevdot" style="background:${SEV_COLOR[s]}" title="${s}: ${bs[s]}"></span>`).join('');
    return `<div class="mcard ${m.id === state.currentId ? 'active' : ''}" onclick="selectMission('${m.id}')">
      <div class="mtop">
        <div class="mt">${esc(m.target)}</div>
        <button class="delbtn" title="Delete mission" onclick="event.stopPropagation();deleteMission('${m.id}')">✕</button>
      </div>
      <div class="mrow">
        <span class="status ${m.status}">${m.status}</span>
        <span class="muted">${m.mode}</span>
      </div>
      <div class="mrow"><div class="sevdots">${dots}</div><span class="muted">${timeago(m.created_at)}</span></div>
    </div>`;
  }).join('');
}

async function deleteMission(id) {
  if (!confirm('Delete this mission and all its data? This cannot be undone.')) return;
  try {
    await api('/api/missions/' + id, { method: 'DELETE' });
    if (state.currentId === id) {
      state.currentId = null; state.mission = null; state.guidance = [];
      if (state.ws) { try { state.ws.close(); } catch (_) {} }
      $('mission-view').classList.add('hidden');
      $('no-mission').classList.remove('hidden');
    }
    await loadMissions();
    toast('Mission deleted');
  } catch (e) { toast('Delete failed: ' + e.message); }
}

function timeago(ts) {
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

async function selectMission(id) {
  state.currentId = id; state.topoRendered = false;
  $('no-mission').classList.add('hidden');
  $('mission-view').classList.remove('hidden');
  renderMissionList();
  $('feed').innerHTML = '';
  connectWS(id);
  await refreshMission();
  setTab('overview');
}

async function refreshMission() {
  try {
    const m = await api('/api/missions/' + state.currentId);
    state.mission = m;
    state.guidance = (m.result && m.result.guidance) || [];
    renderHead(); renderOverview(); renderPlaybooks(); renderReportLinks();
    if (state.tab === 'topology') renderTopology();
    // default cURL url to the first live host / target
    if (!$('c-url').value) {
      const live = (m.result && m.result.recon && m.result.recon.live_hosts) || [];
      $('c-url').value = (live[0] && live[0].url) || ('https://' + m.target);
      updateCurlCmd();
    }
  } catch (_) {}
}

function renderHead() {
  const m = state.mission;
  $('m-target').textContent = m.target;
  $('m-mode').textContent = m.mode;
  const st = $('m-status'); st.textContent = m.status; st.className = 'pill status ' + m.status;
  $('m-id').textContent = '#' + m.id;
  $('pb-count').textContent = state.guidance.length || '';
}

/* ── websocket feed ── */
function connectWS(id) {
  if (state.ws) { try { state.ws.close(); } catch (_) {} }
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/missions/${id}`);
  state.ws = ws;
  ws.onmessage = ev => {
    const d = JSON.parse(ev.data);
    if (d.type === 'log') appendFeed(d);
    else if (d.type === 'status') { if (state.mission) { state.mission.status = d.status; renderHead(); } }
    else if (d.type === 'done') { refreshMission(); loadMissions(); toast('Mission ' + d.status); }
  };
}

function appendFeed(d) {
  const feed = $('feed');
  const cls = d.level || 'info';
  const time = new Date((d.ts || Date.now() / 1000) * 1000).toLocaleTimeString();
  const near = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 40;
  const div = document.createElement('div');
  div.className = 'ln';
  div.innerHTML = `<span class="t">${time}</span><span class="${cls}">${esc(d.message)}</span>`;
  feed.appendChild(div);
  if (near) feed.scrollTop = feed.scrollHeight;
}

/* ── overview ── */
function renderOverview() {
  const m = state.mission, stats = (m.result && m.result.stats) || {};
  const bs = (stats.guidance && stats.guidance.by_severity) || {};
  const cells = [
    ['Subdomains', stats.subdomains || 0, ''],
    ['Live hosts', stats.live_hosts || 0, ''],
    ['Open ports', stats.open_ports || 0, ''],
    ['Nuclei', stats.nuclei || 0, ''],
    ['Playbooks', (stats.guidance && stats.guidance.total) || 0, ''],
  ];
  SEV.forEach(s => { if (bs[s]) cells.push([s, bs[s], 'sev-' + s]); });
  $('statgrid').innerHTML = cells.map(([label, val, cls]) =>
    `<div class="stat ${cls}"><b>${val}</b><span>${esc(label)}</span></div>`).join('');

  const top = state.guidance.slice(0, 6);
  $('top-playbooks').innerHTML = top.length ? top.map(g =>
    `<div class="tp" style="border-left-color:${SEV_COLOR[g.severity]}" onclick="jumpTo('${g.id}')">
      <div class="tpt">${esc(g.title)}</div>
      <div class="tps">${esc(g.severity)} · ${esc(g.confidence_label)} · ${esc(g.surface)}</div>
    </div>`).join('') : '<p class="muted small">No playbooks yet. Run Active mode against a live app for more.</p>';

  const ai = (m.result && m.result.ai) || {};
  const box = $('ai-summary');
  if (ai.triage) {
    box.classList.remove('hidden');
    box.innerHTML = `<h3>AI Executive Summary <span class="muted small">(${esc(ai.model || '')})</span></h3><pre>${esc(ai.triage)}</pre>`;
  } else box.classList.add('hidden');
}

function jumpTo(gid) {
  setTab('playbooks');
  setTimeout(() => {
    const el = document.querySelector(`[data-gid="${gid}"]`);
    if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); expand(el, true); }
  }, 60);
}

/* ── playbooks ── */
function renderSevFilter() {
  $('sevfilter').innerHTML = SEV.map(s =>
    `<button class="sevbtn ${state.sevFilter.has(s) ? 'on' : ''}" style="${state.sevFilter.has(s) ? 'background:' + SEV_COLOR[s] + ';border-color:' + SEV_COLOR[s] : ''}" onclick="toggleSev('${s}')">${s}</button>`).join('');
}
function toggleSev(s) {
  if (state.sevFilter.has(s)) state.sevFilter.delete(s); else state.sevFilter.add(s);
  renderPlaybooks();
}

function renderPlaybooks() {
  renderSevFilter();
  const list = state.guidance.filter(g => {
    if (!state.sevFilter.has(g.severity)) return false;
    if (state.search) {
      const hay = (g.title + ' ' + g.surface + ' ' + (g.tags || []).join(' ') + ' ' + g.category).toLowerCase();
      if (!hay.includes(state.search)) return false;
    }
    return true;
  });
  const box = $('playbooks');
  if (!list.length) { box.innerHTML = '<p class="muted">No playbooks match. Adjust filters, or launch an Active/Full mission.</p>'; return; }
  box.innerHTML = list.map(cardHTML).join('');
}

function cardHTML(g) {
  const c = SEV_COLOR[g.severity] || SEV_COLOR.INFO;
  const steps = (g.how_to_test || []).map(s => `<li>${esc(s)}</li>`).join('');
  const payloads = (g.payloads || []).map(p =>
    `<li><code>${esc(p)}</code> <button class="copybtn" data-copy="${esc(p)}">copy</button></li>`).join('');
  const curls = (g.curl_steps || []).map(cs => {
    const isCurl = /^\s*curl\b/.test(cs.cmd || '');
    const load = isCurl ? `<button class="loadcurlbtn" data-loadcurl="${esc(cs.cmd)}" title="Load method/URL/headers/body into the cURL console">→ console</button>` : '';
    return `<div class="curlstep"><div class="cs-desc"><span>${esc(cs.desc)}</span>
       <span class="cs-btns">${load}<button class="copybtn" data-copy="${esc(cs.cmd)}">copy</button></span></div>
       <pre>${esc(cs.cmd)}</pre></div>`;
  }).join('');
  const refs = (g.references || []).map(r => `<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.title)}</a>`).join('');
  return `<div class="pb" data-gid="${g.id}">
    <div class="pb-head" style="border-left-color:${c}" data-expand="1">
      <span class="sev-tag" style="background:${c}">${esc(g.severity)}</span>
      <h4>${esc(g.title)}</h4>
      <span class="conf-tag">${esc(g.confidence_label)} · ${g.confidence}% · ${esc(g.wstg || '')}</span>
    </div>
    <div class="pb-body hidden">
      <p><strong>Where:</strong> <code>${esc(g.surface)}</code></p>
      <p><strong>Evidence:</strong> ${esc(g.evidence)}</p>
      <p><strong>What to test:</strong> ${esc(g.what_to_test)}</p>
      ${steps ? `<div class="pb-block"><strong>How to test</strong><ol>${steps}</ol></div>` : ''}
      ${payloads ? `<div class="pb-block payloads"><strong>Recommended payloads / injections</strong><ul>${payloads}</ul></div>` : ''}
      ${curls ? `<div class="pb-block"><strong>Step-by-step cURL</strong>${curls}</div>` : ''}
      <p class="pb-tools"><strong>Tools:</strong> ${esc((g.tools || []).join(', '))}</p>
      ${refs ? `<p class="pb-refs"><strong>References:</strong> ${refs}</p>` : ''}
      <div class="pb-cta"><button class="btn btn-ghost" data-tocurl="${esc(g.surface)}">Open in cURL console →</button></div>
    </div>
  </div>`;
}

function expand(pb, force) {
  const body = pb.querySelector('.pb-body');
  if (force) body.classList.remove('hidden');
  else body.classList.toggle('hidden');
}

/* ── topology ── */
function renderTopology() {
  if (!window.Topology) return;
  api('/api/missions/' + state.currentId + '/topology').then(data => {
    const nodes = data.nodes || [];
    if (!nodes.length) {
      $('topo-legend').innerHTML = '<span class="muted">No topology yet — launch an Active/Full mission.</span>';
      $('topo-filter').innerHTML = '';
    } else {
      $('topo-legend').innerHTML = SEV.map(s =>
        `<span><i style="background:${SEV_COLOR[s]}"></i>${s}</span>`).join('');
      const types = [...new Set(nodes.map(n => n.type))].filter(t => t !== 'domain');
      state.topoTypes = new Set(types); // reset to all visible on (re)render
      $('topo-filter').innerHTML = types.map(t =>
        `<label class="tfilter"><input type="checkbox" data-ttype="${t}" checked> ${t} (${nodes.filter(n => n.type === t).length})</label>`).join('');
      $('topo-filter').querySelectorAll('input[data-ttype]').forEach(cb => cb.onchange = () => {
        if (cb.checked) state.topoTypes.add(cb.dataset.ttype); else state.topoTypes.delete(cb.dataset.ttype);
        window.Topology.setVisibleTypes(new Set([...state.topoTypes, 'domain']));
      });
    }
    const labelColor = getComputedStyle(document.documentElement).getPropertyValue('--topo-label').trim() || '#cbd5e1';
    window.Topology.render($('topo-canvas'), data, {
      labelColor,
      onNodeClick: n => { if (n.meta && n.meta.gid) jumpTo(n.meta.gid); },
    });
    state.topoRendered = true;
  });
}

/* ── curl console ── */
function parseHeaders() {
  const out = {};
  $('c-headers').value.split('\n').forEach(l => {
    const i = l.indexOf(':'); if (i > 0) out[l.slice(0, i).trim()] = l.slice(i + 1).trim();
  });
  return out;
}
function curlPayload() {
  return {
    method: $('c-method').value, url: $('c-url').value.trim(),
    headers: parseHeaders(), body: $('c-body').value || null,
    follow_redirects: $('c-follow').checked, insecure: $('c-insecure').checked,
    mission_id: state.currentId,
  };
}
async function updateCurlCmd() {
  const p = curlPayload(); if (!p.url) { $('c-cmd').textContent = ''; return; }
  try { const r = await api('/api/curl/build', { method: 'POST', body: JSON.stringify(Object.assign({ execute: false }, p)) }); $('c-cmd').textContent = r.curl; }
  catch (_) {}
}
async function sendCurl() {
  const p = curlPayload();
  if (!/^https?:\/\//i.test(p.url)) { toast('URL must start with http:// or https://'); return; }
  const st = $('c-status'); st.textContent = 'Sending…'; st.className = 'curl-status';
  try {
    const r = await api('/api/curl/execute', { method: 'POST', body: JSON.stringify(Object.assign({ execute: true }, p)) });
    $('c-cmd').textContent = r.curl || $('c-cmd').textContent;
    if (r.blocked) { st.textContent = '⛔ ' + r.reason; st.className = 'curl-status bad'; return; }
    if (r.error) { st.textContent = '✕ ' + r.error; st.className = 'curl-status bad'; return; }
    st.textContent = `${r.status} ${r.reason_phrase || ''} · ${r.elapsed_ms}ms · ${r.body_bytes} bytes${r.truncated ? ' (truncated)' : ''}`;
    st.className = 'curl-status ' + (r.status < 400 ? 'ok' : 'bad');
    $('c-resp-body').textContent = r.body || '(empty body)';
    $('c-resp-headers').textContent = Object.entries(r.response_headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
  } catch (e) { st.textContent = '✕ ' + e.message; st.className = 'curl-status bad'; }
}
function toCurl(url) { setTab('curl'); $('c-url').value = url.replace('{payload}', 'FUZZ'); updateCurlCmd(); }

// Tokenize a shell command respecting single/double quotes (our curl strings
// are shlex-single-quoted), then extract method/url/headers/body.
function tokenizeCmd(cmd) {
  const toks = []; let cur = '', q = null, has = false;
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (q) { if (ch === q) q = null; else cur += ch; continue; }
    if (ch === "'" || ch === '"') { q = ch; has = true; continue; }
    if (/\s/.test(ch)) { if (cur || has) { toks.push(cur); cur = ''; has = false; } continue; }
    cur += ch; has = true;
  }
  if (cur || has) toks.push(cur);
  return toks;
}
function parseCurl(cmd) {
  const t = tokenizeCmd(cmd);
  const res = { method: '', url: '', headers: {}, body: null, follow: false, insecure: false, head: false };
  const takesArg = new Set(['-o', '-w', '-D', '--max-time', '-m', '-e', '-b', '-A', '-u', '-x', '--connect-timeout', '-y', '-Y']);
  for (let i = 0; i < t.length; i++) {
    const a = t[i];
    if (a === 'curl') continue;
    if (a === '-X' || a === '--request') res.method = (t[++i] || '').toUpperCase();
    else if (a === '-H' || a === '--header') { const h = t[++i] || ''; const j = h.indexOf(':'); if (j > 0) res.headers[h.slice(0, j).trim()] = h.slice(j + 1).trim(); }
    else if (a === '-d' || a === '--data' || a === '--data-raw' || a === '--data-binary' || a === '--data-ascii') res.body = t[++i] || '';
    else if (a === '-L' || a === '--location') res.follow = true;
    else if (a === '-k' || a === '--insecure') res.insecure = true;
    else if (a === '-I' || a === '--head') res.head = true;
    else if (a === '--url') res.url = t[++i] || '';
    else if (takesArg.has(a)) i++;                 // skip flag + its argument
    else if (a.startsWith('-')) { /* boolean flag, ignore */ }
    else if (/^https?:\/\//i.test(a) || a.includes('://')) res.url = a;
  }
  if (!res.method) res.method = res.head ? 'HEAD' : (res.body != null ? 'POST' : 'GET');
  return res;
}
function loadReq(req) {
  setTab('curl');
  const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  $('c-method').value = methods.includes(req.method) ? req.method : 'GET';
  $('c-url').value = (req.url || '').replace('{payload}', 'FUZZ');
  $('c-headers').value = Object.entries(req.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
  $('c-body').value = req.body || '';
  $('c-follow').checked = !!req.follow;
  $('c-insecure').checked = req.insecure !== false;
  updateCurlCmd();
  toast('Loaded into cURL console');
}

/* ── report ── */
function renderReportLinks() {
  const id = state.currentId;
  $('r-html').href = `/api/missions/${id}/report?format=html`;
  $('r-md').href = `/api/missions/${id}/report?format=md`;
  $('r-csv').href = `/api/missions/${id}/report?format=csv`;
  $('r-json').href = `/api/missions/${id}/report?format=json`;
}

/* ── tabs ── */
function setTab(tab) {
  state.tab = tab;
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('hidden', p.dataset.panel !== tab));
  if (tab === 'topology') renderTopology();
  if (tab === 'report') { $('r-frame').src = `/api/missions/${state.currentId}/report?format=html`; }
}

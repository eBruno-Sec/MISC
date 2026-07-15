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

  document.querySelectorAll('.tab').forEach(b => b.onclick = () => setTab(b.dataset.tab));
  document.querySelectorAll('.ctab').forEach(b => b.onclick = () => {
    document.querySelectorAll('.ctab').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    $('c-resp-body').classList.toggle('hidden', b.dataset.ctab !== 'body');
    $('c-resp-headers').classList.toggle('hidden', b.dataset.ctab !== 'headers');
  });

  $('pb-search').addEventListener('input', e => { state.search = e.target.value.toLowerCase(); renderPlaybooks(); });
  $('topo-reset').onclick = () => window.Topology && window.Topology.recenter();

  ['c-method', 'c-url', 'c-headers', 'c-body', 'c-insecure', 'c-follow'].forEach(id =>
    $(id).addEventListener('input', updateCurlCmd));
  $('c-follow').addEventListener('change', updateCurlCmd);
  $('c-send').onclick = sendCurl;
  $('c-copy').onclick = () => copy($('c-cmd').textContent);

  // Delegated clicks (payloads/cURL can contain quotes, so no inline handlers).
  document.addEventListener('click', e => {
    const cp = e.target.closest('.copybtn');
    if (cp && cp.dataset.copy !== undefined) { copy(cp.dataset.copy); return; }
    const tc = e.target.closest('[data-tocurl]');
    if (tc) { toCurl(tc.dataset.tocurl); return; }
    const eh = e.target.closest('.pb-head[data-expand]');
    if (eh) { expand(eh.parentNode); return; }
  });
});

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

/* ── missions ── */
async function launch() {
  const target = $('target').value.trim();
  const mode = $('mode').value;
  const scope_text = $('scope').value.trim() || null;
  const msg = $('launch-msg');
  if (!target) { msg.textContent = 'Enter a target domain.'; msg.className = 'msg err'; return; }
  msg.textContent = 'Launching…'; msg.className = 'msg';
  try {
    const r = await api('/api/missions', { method: 'POST', body: JSON.stringify({ target, mode, scope_text }) });
    msg.textContent = `Launched ${r.target} (${r.mode})`; msg.className = 'msg ok';
    await loadMissions();
    selectMission(r.id);
  } catch (e) { msg.textContent = 'Error: ' + e.message; msg.className = 'msg err'; }
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
      <div class="mt">${esc(m.target)}</div>
      <div class="mrow">
        <span class="status ${m.status}">${m.status}</span>
        <span class="muted">${m.mode}</span>
      </div>
      <div class="mrow"><div class="sevdots">${dots}</div><span class="muted">${timeago(m.created_at)}</span></div>
    </div>`;
  }).join('');
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
  const curls = (g.curl_steps || []).map(cs =>
    `<div class="curlstep"><div class="cs-desc"><span>${esc(cs.desc)}</span>
       <button class="copybtn" data-copy="${esc(cs.cmd)}">copy</button></div>
       <pre>${esc(cs.cmd)}</pre></div>`).join('');
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
    if (!data.nodes || !data.nodes.length) {
      $('topo-legend').innerHTML = '<span class="muted">No topology yet — launch an Active/Full mission.</span>';
    } else {
      $('topo-legend').innerHTML = SEV.map(s =>
        `<span><i style="background:${SEV_COLOR[s]}"></i>${s}</span>`).join('') +
        '<span class="muted">· ● domain / host / port / endpoint</span>';
    }
    window.Topology.render($('topo-canvas'), data, { onNodeClick: n => {
      if (n.meta && n.meta.gid) jumpTo(n.meta.gid);
    }});
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

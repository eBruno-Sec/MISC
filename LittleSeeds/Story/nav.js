// ── Little Seeds — Shared Story Page Logic ───────────────────────────────────

// PWA: inject manifest link (story pages don't have it in their <head>)
(function() {
  if (!document.querySelector('link[rel="manifest"]')) {
    const link = document.createElement('link');
    link.rel = 'manifest';
    link.href = '../manifest.json';
    document.head.appendChild(link);
  }
  // Register service worker
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('../sw.js', { scope: '/MISC/LittleSeeds/' }).catch(() => {});
  }
})();

const _stories = [
  { day:1,  emoji:'🌰', title:'The Brave Seed and the Giant Oak' },
  { day:2,  emoji:'⭐', title:'The Dream That Built the Stars' },
  { day:3,  emoji:'🐯', title:'Kaito and the Spirit of the White Tiger' },
  { day:4,  emoji:'🦋', title:'Kaito and the Words That Made Him Fly' },
  { day:5,  emoji:'🥕', title:'Leo and the Power Plates' },
  { day:6,  emoji:'👟', title:'Ethan and the Little Steps' },
  { day:7,  emoji:'🌳', title:'The Thankful Tree' },
  { day:8,  emoji:'⏰', title:'Milo and the Race Against Later' },
  { day:9,  emoji:'🖊️', title:'Jonah and the Broken Pen' },
  { day:10, emoji:'⚡', title:'Eli and the Storm Inside' },
  { day:11, emoji:'🎒', title:'The Heavy Backpack' },
  { day:12, emoji:'🗣️', title:'The Talking Stick' },
  { day:13, emoji:'🧠', title:'Nilo and the Brain Nap' },
  { day:14, emoji:'🥋', title:'Kai and the Practice Path' },
  { day:15, emoji:'🪞', title:"Nari's Mirror" },
  { day:16, emoji:'🦁', title:'Eli and the Little Lion Voice' },
  { day:17, emoji:'🤝', title:'Zane and the Circle of Good Friends' },
  { day:18, emoji:'🧵', title:'Miko and the Heart Rope' },
  { day:19, emoji:'🕯️', title:'Jonah and the Cave of Shadows' },
  { day:20, emoji:'🧱', title:'Niko and the Falling Tower' },
];

const _currentDay = parseInt(location.pathname.match(/Day(\d+)/i)?.[1] || 0);
const FREE_DAYS    = 3;
const LS_PREMIUM   = 'ls_premium';
const LS_READ      = 'ls_read';
const LS_BRIGHT    = 'ls_brightness';
// Demo access codes — replace with server-side verification before production
const _ACCESS_CODES = ['SEEDS2025', 'LITTLESEEDS', 'FAMILY2025'];

// ── PREMIUM ───────────────────────────────────────────────────────────────────

function isPremium() {
  return localStorage.getItem(LS_PREMIUM) === 'true';
}

function unlockWithCode(code) {
  if (_ACCESS_CODES.includes(code.toUpperCase().trim())) {
    localStorage.setItem(LS_PREMIUM, 'true');
    return true;
  }
  return false;
}

// ── READING PROGRESS ──────────────────────────────────────────────────────────

function getReadStories() {
  try { return new Set(JSON.parse(localStorage.getItem(LS_READ) || '[]')); }
  catch { return new Set(); }
}

function markRead(day) {
  if (!day) return;
  const s = getReadStories();
  s.add(day);
  localStorage.setItem(LS_READ, JSON.stringify([...s]));
}

// Auto-mark when a reader reaches the story page, then check for Day 3 completion
if (_currentDay) {
  markRead(_currentDay);

  // After finishing the last free story, show a friendly upgrade nudge
  if (_currentDay === FREE_DAYS && !isPremium()) {
    const read = getReadStories();
    const allFreeRead = [1, 2, 3].every(d => read.has(d));
    if (allFreeRead) {
      document.addEventListener('DOMContentLoaded', () => {
        const wrapper = document.querySelector('.story-wrapper');
        if (!wrapper) return;
        const nudge = document.createElement('div');
        nudge.className = 'free-complete-nudge';
        nudge.innerHTML = `
          <span class="nudge-icon">🌟</span>
          <h3>You've read all 3 free stories!</h3>
          <p>Your little reader is off to a wonderful start. Continue the journey with all 20 nights of courage, kindness, and wonder.</p>
          <a href="../upgrade.html#pricing" class="nudge-btn">🌱 Unlock All 20 Stories</a>
          <p class="nudge-sub">From $2.99/month · Cancel any time</p>
        `;
        wrapper.appendChild(nudge);
      });
    }
  }
}

// ── STARS ─────────────────────────────────────────────────────────────────────

(function() {
  const layer = document.getElementById('stars');
  if (!layer) return;
  const count = window.matchMedia('(max-width:640px)').matches ? 40 : 80;
  for (let i = 0; i < count; i++) {
    const s = document.createElement('div');
    s.className = 'star';
    const sz = Math.random() * 3 + 1;
    s.style.cssText = `width:${sz}px;height:${sz}px;top:${Math.random()*100}%;left:${Math.random()*100}%;--d:${(Math.random()*3+2).toFixed(1)}s;animation-delay:${(Math.random()*4).toFixed(1)}s`;
    layer.appendChild(s);
  }
})();

// ── NAV: day indicator + progress bar ────────────────────────────────────────

(function() {
  if (!_currentDay) return;
  const navMain = document.querySelector('.nav-main');
  if (!navMain) return;
  const dayEl = document.createElement('span');
  dayEl.className = 'nav-day';
  dayEl.innerHTML = `<strong>Day ${_currentDay}</strong>&thinsp;/&thinsp;20`;
  const btn = navMain.querySelector('.nav-stories-btn');
  if (btn) navMain.insertBefore(dayEl, btn);
  const nav = document.querySelector('nav');
  const prog = document.createElement('div');
  prog.className = 'nav-progress';
  prog.innerHTML = `<div class="nav-progress-bar" style="width:${(_currentDay / 20 * 100).toFixed(1)}%"></div>`;
  nav.appendChild(prog);
})();

// ── NAV: dimmer button + night controls popup ─────────────────────────────────

(function() {
  const navMain = document.querySelector('.nav-main');
  if (!navMain) return;

  const dimBtn = document.createElement('button');
  dimBtn.className = 'dimmer-btn';
  dimBtn.setAttribute('aria-label', 'Night mode controls');
  dimBtn.setAttribute('aria-expanded', 'false');
  dimBtn.title = 'Night controls';
  dimBtn.innerHTML = '🌙';
  navMain.insertBefore(dimBtn, navMain.querySelector('.nav-stories-btn'));

  const popup = document.createElement('div');
  popup.className = 'dimmer-popup';
  popup.id = 'dimmerPopup';
  popup.setAttribute('role', 'dialog');
  popup.setAttribute('aria-label', 'Night mode controls');
  popup.innerHTML = `
    <span class="dimmer-label">Screen Brightness</span>
    <div class="dimmer-row">
      <span aria-hidden="true">🌑</span>
      <input type="range" id="dimSlider" min="15" max="100" value="100" aria-label="Brightness" />
      <span aria-hidden="true">☀️</span>
    </div>
    <button class="dimmer-sound-btn" id="soundBtn" onclick="toggleSound()">
      <span id="soundBtnIcon">🌧️</span> Gentle Rain
    </button>
    <div style="border-top:1px solid rgba(255,255,255,0.07);padding-top:0.85rem;margin-top:0.85rem">
      <span class="dimmer-label">Text Size</span>
      <div class="font-size-row">
        <button class="fz-btn" id="fzNormal" onclick="setFontSize('normal')" style="font-size:0.85rem" aria-label="Normal text">A</button>
        <button class="fz-btn" id="fzLarge"  onclick="setFontSize('large')"  style="font-size:1.05rem" aria-label="Large text">A</button>
        <button class="fz-btn" id="fzXl"     onclick="setFontSize('xl')"     style="font-size:1.25rem" aria-label="Extra large text">A</button>
      </div>
    </div>
  `;
  document.body.appendChild(popup);

  dimBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const isOpen = popup.classList.toggle('open');
    dimBtn.setAttribute('aria-expanded', isOpen);
  });
  document.addEventListener('click', () => {
    popup.classList.remove('open');
    dimBtn.setAttribute('aria-expanded', 'false');
  });
  popup.addEventListener('click', e => e.stopPropagation());

  // Restore saved brightness on load
  const slider = document.getElementById('dimSlider');
  const saved = localStorage.getItem(LS_BRIGHT) || '100';
  slider.value = saved;
  document.documentElement.style.filter = `brightness(${saved}%)`;

  slider.addEventListener('input', () => {
    const v = slider.value;
    document.documentElement.style.filter = `brightness(${v}%)`;
    localStorage.setItem(LS_BRIGHT, v);
  });

  // Restore saved font size and highlight active button
  const savedSize = localStorage.getItem('ls_fontsize') || 'normal';
  _applyFontSize(savedSize);
})();

// ── FONT SIZE ─────────────────────────────────────────────────────────────────

const LS_FONTSIZE = 'ls_fontsize';

function _applyFontSize(size) {
  document.body.classList.remove('font-large', 'font-xl');
  if (size === 'large') document.body.classList.add('font-large');
  if (size === 'xl')    document.body.classList.add('font-xl');
  ['fzNormal', 'fzLarge', 'fzXl'].forEach(id => {
    document.getElementById(id)?.classList.remove('active');
  });
  const map = { normal: 'fzNormal', large: 'fzLarge', xl: 'fzXl' };
  document.getElementById(map[size])?.classList.add('active');
}

function setFontSize(size) {
  _applyFontSize(size);
  localStorage.setItem(LS_FONTSIZE, size);
}

// ── AMBIENT RAIN SOUND ────────────────────────────────────────────────────────

let _sndCtx = null, _sndSrc = null, _sndPlaying = false;

function toggleSound() {
  const btn   = document.getElementById('soundBtn');
  const icon  = document.getElementById('soundBtnIcon');

  if (_sndPlaying) {
    _sndCtx?.suspend();
    _sndPlaying = false;
    if (btn)  { btn.classList.remove('playing'); btn.innerHTML = '<span id="soundBtnIcon">🌧️</span> Gentle Rain'; }
    return;
  }

  if (_sndCtx && _sndCtx.state === 'suspended') {
    _sndCtx.resume();
  } else {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    _sndCtx = new AC();

    // Pink-noise approximation: white noise + two cascaded lowpass filters
    const rate   = _sndCtx.sampleRate;
    const buf    = _sndCtx.createBuffer(1, 2 * rate, rate);
    const data   = buf.getChannelData(0);
    for (let i = 0; i < data.length; i++) data[i] = Math.random() * 2 - 1;

    _sndSrc       = _sndCtx.createBufferSource();
    _sndSrc.buffer = buf;
    _sndSrc.loop   = true;

    const lp1 = _sndCtx.createBiquadFilter();
    lp1.type = 'lowpass'; lp1.frequency.value = 550; lp1.Q.value = 0.3;
    const lp2 = _sndCtx.createBiquadFilter();
    lp2.type = 'lowpass'; lp2.frequency.value = 900;

    const gain = _sndCtx.createGain();
    gain.gain.value = 0.09;

    _sndSrc.connect(lp1); lp1.connect(lp2); lp2.connect(gain); gain.connect(_sndCtx.destination);
    _sndSrc.start();
  }

  _sndPlaying = true;
  if (btn) { btn.classList.add('playing'); btn.innerHTML = '<span id="soundBtnIcon">⏹</span> Stop Rain'; }
}

// ── SHARE BUTTON ──────────────────────────────────────────────────────────────

(function() {
  if (!_currentDay) return;
  const navMain = document.querySelector('.nav-main');
  if (!navMain) return;

  const btn = document.createElement('button');
  btn.className = 'share-btn';
  btn.setAttribute('aria-label', 'Share this story');
  btn.title = 'Share';
  btn.innerHTML = '📤';
  navMain.insertBefore(btn, navMain.querySelector('.nav-stories-btn'));
  btn.addEventListener('click', shareStory);
})();

async function shareStory() {
  const story = _stories.find(s => s.day === _currentDay);
  if (!story) return;
  const data = {
    title: `${story.emoji} ${story.title} — Little Seeds`,
    text: `We're doing bedtime stories with Little Seeds 🌱 Tonight: "${story.title}"`,
    url: location.href,
  };
  try {
    if (navigator.share && navigator.canShare?.(data)) {
      await navigator.share(data);
    } else {
      await navigator.clipboard.writeText(location.href);
      showToast('🌱 Link copied!');
    }
  } catch(e) {
    if (e.name !== 'AbortError') {
      await navigator.clipboard.writeText(location.href).catch(() => {});
      showToast('🌱 Link copied!');
    }
  }
}

function showToast(msg, ms = 2600) {
  const existing = document.getElementById('ls-toast');
  existing?.remove();
  const t = document.createElement('div');
  t.id = 'ls-toast';
  t.className = 'ls-toast';
  t.textContent = msg;
  t.setAttribute('role', 'status');
  t.setAttribute('aria-live', 'polite');
  document.body.appendChild(t);
  requestAnimationFrame(() => requestAnimationFrame(() => t.classList.add('show')));
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 320); }, ms);
}

// ── STORIES DRAWER ────────────────────────────────────────────────────────────

(function() {
  const grid = document.getElementById('drawerGrid');
  if (!grid) return;
  _stories.forEach(s => {
    const a = document.createElement('a');
    a.href = `./Day${s.day}.html`;
    a.className = 'drawer-story-link' + (s.day === _currentDay ? ' current' : '');
    a.innerHTML = `<span class="drawer-emoji">${s.emoji}</span><span><span class="drawer-meta-day">Day ${s.day}</span><span class="drawer-meta-title">${s.title}</span></span>`;
    grid.appendChild(a);
  });
})();

function toggleDrawer() {
  const drawer  = document.getElementById('storiesDrawer');
  const overlay = document.getElementById('drawerOverlay');
  const btn     = document.getElementById('drawerToggle');
  if (!drawer) return;
  const isOpen = drawer.classList.toggle('open');
  overlay?.classList.toggle('open', isOpen);
  btn?.setAttribute('aria-expanded', isOpen);
  drawer.setAttribute('aria-hidden', !isOpen);
  document.body.style.overflow = isOpen ? 'hidden' : '';
}

// ── PREMIUM GATE (injected on locked story pages) ─────────────────────────────

(function() {
  if (!_currentDay || _currentDay <= FREE_DAYS || isPremium()) return;

  const gate = document.createElement('div');
  gate.className = 'premium-gate';
  gate.id = 'premiumGate';
  gate.innerHTML = `
    <div class="premium-gate-card">
      <span class="gate-icon" aria-hidden="true">🌙</span>
      <h2>Continue the Journey</h2>
      <p>Day ${_currentDay} is part of the full Little Seeds library — 20 stories to grow with, one magical night at a time.</p>
      <a href="../upgrade.html#pricing" class="gate-btn-primary">🌱 Unlock All 20 Stories</a>
      <button class="gate-btn-secondary" id="gateCodeToggle" onclick="showGateCodeEntry()">
        Already a member? Enter code
      </button>
      <div class="gate-code-section" id="gateCodeSection" style="display:none">
        <label for="gateCodeInput">Access Code</label>
        <div class="gate-code-row">
          <input type="text" id="gateCodeInput" placeholder="SEEDS2025" autocomplete="off" spellcheck="false" />
          <button onclick="submitGateCode()">Unlock</button>
        </div>
        <p class="gate-err" id="gateErr"></p>
      </div>
      <a href="../index.html" class="gate-back">← Back to stories</a>
    </div>
  `;
  document.body.appendChild(gate);
  document.body.style.overflow = 'hidden';
})();

function showGateCodeEntry() {
  document.getElementById('gateCodeSection').style.display = 'block';
  document.getElementById('gateCodeToggle').style.display = 'none';
  document.getElementById('gateCodeInput')?.focus();
}

function submitGateCode() {
  const input = document.getElementById('gateCodeInput');
  const err   = document.getElementById('gateErr');
  if (!input) return;
  if (unlockWithCode(input.value)) {
    location.reload();
  } else {
    err.textContent = 'Invalid code — check your email after purchase.';
    input.value = '';
    input.focus();
  }
}

// ── PARENTAL GATE (wrap any external link) ────────────────────────────────────

function parentalGate(url, label) {
  const a = Math.floor(Math.random() * 9) + 1;
  const b = Math.floor(Math.random() * 9) + 1;

  const existing = document.getElementById('parentalGateOverlay');
  existing?.remove();

  const overlay = document.createElement('div');
  overlay.className = 'parental-gate-overlay';
  overlay.id = 'parentalGateOverlay';
  overlay.innerHTML = `
    <div class="parental-gate-card">
      <h3>🔐 Parental Check</h3>
      <p>Just making sure a grown-up is here before visiting<br><strong>${label || 'an external link'}</strong>.</p>
      <div class="math-q">${a} + ${b} = ?</div>
      <input type="number" id="pgAnswer" placeholder="?" aria-label="Answer" />
      <button onclick="checkParentalGate(${a + b}, '${encodeURIComponent(url)}')">Continue</button>
      <p class="gate-err" id="pgErr"></p>
      <button class="gate-cancel" onclick="document.getElementById('parentalGateOverlay').remove()">Cancel</button>
    </div>
  `;
  document.body.appendChild(overlay);
  setTimeout(() => document.getElementById('pgAnswer')?.focus(), 60);
}

function checkParentalGate(answer, encodedUrl) {
  const input = document.getElementById('pgAnswer');
  if (!input) return;
  if (parseInt(input.value) === answer) {
    document.getElementById('parentalGateOverlay')?.remove();
    window.open(decodeURIComponent(encodedUrl), '_blank', 'noopener,noreferrer');
  } else {
    const err = document.getElementById('pgErr');
    if (err) err.textContent = 'Not quite — try again!';
    input.value = '';
    input.focus();
  }
}

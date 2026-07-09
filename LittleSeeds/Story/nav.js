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

// Stars
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

// Nav: day indicator + progress bar
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

// Drawer: build story list
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
  const drawer = document.getElementById('storiesDrawer');
  const overlay = document.getElementById('drawerOverlay');
  const btn = document.getElementById('drawerToggle');
  if (!drawer) return;
  const isOpen = drawer.classList.toggle('open');
  if (overlay) overlay.classList.toggle('open', isOpen);
  if (btn) btn.setAttribute('aria-expanded', isOpen);
  drawer.setAttribute('aria-hidden', !isOpen);
  document.body.style.overflow = isOpen ? 'hidden' : '';
}

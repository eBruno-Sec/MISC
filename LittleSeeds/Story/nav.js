const _stories = [
  { day:1,  emoji:'🌰', title:'The Brave Seed and the Giant Oak' },
  { day:2,  emoji:'🦋', title:'The Caterpillar Who Doubted Her Wings' },
  { day:3,  emoji:'🐢', title:'The Turtle Who Learned to Rest' },
  { day:4,  emoji:'🌊', title:'The Wave That Was Afraid to Break' },
  { day:5,  emoji:'🐝', title:'The Little Bee and the Broken Hive' },
  { day:6,  emoji:'🦊', title:'The Fox Who Told the Truth' },
  { day:7,  emoji:'⭐', title:'The Star Who Was Scared of the Dark' },
  { day:8,  emoji:'🌸', title:'The Flower That Bloomed in Winter' },
  { day:9,  emoji:'🐋', title:'The Whale Who Sang Alone' },
  { day:10, emoji:'🍄', title:'The Mushroom Who Fed the Forest' },
  { day:11, emoji:'🦁', title:'The Lion Who Cried' },
  { day:12, emoji:'🌈', title:'The Rainbow After the Storm' },
  { day:13, emoji:'🐧', title:'The Penguin Who Learned to Swim' },
  { day:14, emoji:'🌙', title:'The Moon Who Forgot to Shine' },
  { day:15, emoji:'🐘', title:'The Elephant Who Never Forgot Kindness' },
  { day:16, emoji:'🌻', title:'The Sunflower Who Faced the Storm' },
  { day:17, emoji:'🦅', title:'The Eagle Who Learned to Land' },
  { day:18, emoji:'🍂', title:'The Leaf That Let Go' },
  { day:19, emoji:'🦌', title:'The Deer Who Found Her Herd' },
  { day:20, emoji:'🌟', title:'The Child Who Changed the Sky' },
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

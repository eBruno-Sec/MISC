/* ═══════════════════════════════════════════════
   NAV — shrink + shadow on scroll
   ═══════════════════════════════════════════════ */
const nav          = document.getElementById('mainNav');
const marqueeTrack = document.querySelector('.marquee-track');

window.addEventListener('scroll', () => {
  nav.classList.toggle('scrolled', window.scrollY > 40);
}, { passive: true });


/* ═══════════════════════════════════════════════
   MOBILE DRAWER
   ═══════════════════════════════════════════════ */
const burger = document.getElementById('navBurger');
const drawer = document.getElementById('navDrawer');
let drawerOpen = false;

function openDrawer() {
  drawerOpen = true;
  drawer.style.display = 'flex';
  requestAnimationFrame(() => drawer.classList.add('open'));
  burger.classList.add('open');
  burger.setAttribute('aria-expanded', 'true');
  drawer.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
}

function closeDrawer() {
  drawerOpen = false;
  drawer.classList.remove('open');
  burger.classList.remove('open');
  burger.setAttribute('aria-expanded', 'false');
  drawer.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
  setTimeout(() => { if (!drawerOpen) drawer.style.display = 'none'; }, 400);
}

burger.addEventListener('click', () => drawerOpen ? closeDrawer() : openDrawer());
document.addEventListener('keydown', e => { if (e.key === 'Escape' && drawerOpen) closeDrawer(); });

// Close when a drawer link is tapped
drawer.querySelectorAll('a').forEach(a => a.addEventListener('click', closeDrawer));


/* ═══════════════════════════════════════════════
   SCROLL REVEAL
   ═══════════════════════════════════════════════ */
const revealObserver = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.12, rootMargin: '0px 0px -32px 0px' });

document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));

// Stagger transition delays for grouped reveals
document.querySelectorAll('.menu-item.reveal').forEach((el, i) => {
  el.style.transitionDelay = `${i * 0.08}s`;
});
document.querySelectorAll('.craft-step.reveal').forEach((el, i) => {
  el.style.transitionDelay = `${i * 0.1}s`;
});


/* ═══════════════════════════════════════════════
   FOOD PHOTOS — hero
   Hero right panel: shows images/hero.jpg when present,
   falls back silently to the CSS illustration.
   ═══════════════════════════════════════════════ */
const heroPhoto = document.querySelector('.hero-photo');
if (heroPhoto) {
  heroPhoto.addEventListener('load', () => heroPhoto.classList.add('loaded'));
  // error: stays at opacity 0 — CSS illustration shows through
}


/* ═══════════════════════════════════════════════
   FOOD PHOTOS — menu cards
   Each card looks for its image (images/menu-*.jpg).
   Photo slot stays hidden until the image loads;
   missing photos leave the card looking fine.
   ═══════════════════════════════════════════════ */
document.querySelectorAll('.item-photo').forEach(img => {
  img.addEventListener('load', function () {
    this.closest('.item-photo-wrap').classList.add('has-photo');
  });
  // error: photo-wrap stays display:none
});


/* ═══════════════════════════════════════════════
   ADD-TO-ORDER button feedback
   ═══════════════════════════════════════════════ */
document.querySelectorAll('.item-add').forEach(btn => {
  btn.addEventListener('click', function () {
    if (this.classList.contains('added')) return;
    this.classList.add('added');
    this.textContent = '✓';
    setTimeout(() => {
      this.classList.remove('added');
      this.textContent = '+';
    }, 1400);
  });
});

/* ============================================================
   dev.com — script.js
   ============================================================ */

(function () {
  'use strict';

  /* ── Nav scroll effect ─────────────────────────────────── */
  const nav = document.getElementById('nav');

  function onScroll() {
    nav.classList.toggle('scrolled', window.scrollY > 50);
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll(); // run once on load

  /* ── Hamburger / mobile menu ───────────────────────────── */
  const hamburger  = document.getElementById('hamburger');
  const mobileMenu = document.getElementById('mobile-menu');

  hamburger.addEventListener('click', function () {
    const open = mobileMenu.classList.toggle('open');
    hamburger.classList.toggle('open', open);
    hamburger.setAttribute('aria-expanded', String(open));
  });

  mobileMenu.querySelectorAll('a').forEach(function (link) {
    link.addEventListener('click', function () {
      mobileMenu.classList.remove('open');
      hamburger.classList.remove('open');
      hamburger.setAttribute('aria-expanded', 'false');
    });
  });

  /* ── Scroll reveal ─────────────────────────────────────── */
  const revealObserver = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('revealed');
        }
      });
    },
    { threshold: 0.1, rootMargin: '0px 0px -32px 0px' }
  );

  document.querySelectorAll('.reveal').forEach(function (el) {
    revealObserver.observe(el);
  });

  /* ── Animated stat counters ────────────────────────────── */
  function animateCount(el, target, duration) {
    const start     = performance.now();
    const initial   = 0;
    const easeOut   = function (t) { return 1 - Math.pow(1 - t, 3); };

    function tick(now) {
      const elapsed  = now - start;
      const progress = Math.min(elapsed / duration, 1);
      el.textContent = Math.floor(easeOut(progress) * (target - initial) + initial);
      if (progress < 1) requestAnimationFrame(tick);
      else el.textContent = target;
    }
    requestAnimationFrame(tick);
  }

  const counterObserver = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          const target = parseInt(entry.target.getAttribute('data-target'), 10);
          animateCount(entry.target, target, 1600);
          counterObserver.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.6 }
  );

  document.querySelectorAll('.stat-count[data-target]').forEach(function (el) {
    counterObserver.observe(el);
  });

  /* ── Typewriter effect ─────────────────────────────────── */
  const words     = ['Convert', 'Impress', 'Perform', 'Rank', 'Engage', 'Last'];
  const typeEl    = document.getElementById('typewriter');
  let   wordIndex = 0;
  let   charIndex = 0;
  let   deleting  = false;
  let   paused    = false;

  function typeLoop() {
    if (!typeEl || paused) return;

    const word = words[wordIndex];

    if (deleting) {
      charIndex--;
      typeEl.textContent = word.slice(0, charIndex);
    } else {
      charIndex++;
      typeEl.textContent = word.slice(0, charIndex);
    }

    let delay = deleting ? 55 : 105;

    if (!deleting && charIndex === word.length) {
      delay   = 2000;
      deleting = true;
    } else if (deleting && charIndex === 0) {
      deleting  = false;
      wordIndex = (wordIndex + 1) % words.length;
      delay     = 300;
    }

    setTimeout(typeLoop, delay);
  }

  // Kick off after brief delay so page feels settled
  setTimeout(typeLoop, 700);

  /* ── Smooth anchor scrolling ───────────────────────────── */
  const NAV_OFFSET = 80;

  document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
    anchor.addEventListener('click', function (e) {
      const id     = this.getAttribute('href');
      const target = document.querySelector(id);
      if (!target) return;
      e.preventDefault();
      const top = target.getBoundingClientRect().top + window.scrollY - NAV_OFFSET;
      window.scrollTo({ top: top, behavior: 'smooth' });
    });
  });

  /* ── CTA form micro-interaction ────────────────────────── */
  const ctaForm  = document.querySelector('.cta-form');
  const ctaInput = document.querySelector('.cta-input');
  const ctaBtn   = ctaForm ? ctaForm.querySelector('.btn-primary') : null;

  if (ctaBtn && ctaInput) {
    ctaBtn.addEventListener('click', function () {
      const email = ctaInput.value.trim();
      const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

      if (!valid) {
        ctaInput.style.borderColor = 'rgba(239,68,68,.6)';
        ctaInput.focus();
        setTimeout(function () {
          ctaInput.style.borderColor = '';
        }, 1600);
        return;
      }

      ctaBtn.textContent = '✓ We'll be in touch!';
      ctaBtn.style.background = 'linear-gradient(135deg,#059669,#10b981)';
      ctaBtn.disabled  = true;
      ctaInput.value   = '';
      ctaInput.disabled = true;
    });
  }

  /* ── Active nav link on scroll ─────────────────────────── */
  const sections = document.querySelectorAll('section[id], div[id]');
  const navAnchors = document.querySelectorAll('.nav-links a');

  const sectionObserver = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          navAnchors.forEach(function (a) {
            a.style.color = '';
          });
          const active = document.querySelector('.nav-links a[href="#' + entry.target.id + '"]');
          if (active) active.style.color = 'var(--text)';
        }
      });
    },
    { rootMargin: '-40% 0px -55% 0px' }
  );

  sections.forEach(function (s) { sectionObserver.observe(s); });

})();

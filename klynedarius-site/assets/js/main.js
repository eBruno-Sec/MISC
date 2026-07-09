/* KlyneDarius Construction — site interactions */
(function () {
  "use strict";

  /* ---------- Mobile nav ---------- */
  var toggle    = document.querySelector(".nav-toggle");
  var mobileNav = document.querySelector(".mobile-nav");

  if (toggle && mobileNav) {
    toggle.addEventListener("click", function () {
      var open = toggle.classList.toggle("is-open");
      mobileNav.classList.toggle("is-open", open);
      toggle.setAttribute("aria-expanded", String(open));
      document.body.style.overflow = open ? "hidden" : "";
    });
    mobileNav.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        toggle.classList.remove("is-open");
        mobileNav.classList.remove("is-open");
        toggle.setAttribute("aria-expanded", "false");
        document.body.style.overflow = "";
      });
    });
  }

  /* ---------- Scroll reveal ---------- */
  var prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var revealEls      = document.querySelectorAll(".reveal");

  if (revealEls.length && !prefersReduced && "IntersectionObserver" in window) {
    var revealIO = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("in");
          revealIO.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1, rootMargin: "0px 0px -36px 0px" });
    revealEls.forEach(function (el) { revealIO.observe(el); });
  } else {
    revealEls.forEach(function (el) { el.classList.add("in"); });
  }

  /* ---------- Animated counters ---------- */
  function animateCount(el, target, duration) {
    var start   = performance.now();
    var easeOut = function (t) { return 1 - Math.pow(1 - t, 3); };
    function tick(now) {
      var progress = Math.min((now - start) / duration, 1);
      el.textContent = Math.floor(easeOut(progress) * target);
      if (progress < 1) requestAnimationFrame(tick);
      else el.textContent = target;
    }
    requestAnimationFrame(tick);
  }

  if ("IntersectionObserver" in window) {
    var counterIO = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          var el     = entry.target;
          var target = parseInt(el.getAttribute("data-count"), 10);
          if (!isNaN(target)) animateCount(el, target, 1400);
          counterIO.unobserve(el);
        }
      });
    }, { threshold: 0.7 });

    document.querySelectorAll("[data-count]").forEach(function (el) {
      counterIO.observe(el);
    });
  }

  /* ---------- Process step highlight on scroll ---------- */
  var processSteps = document.querySelectorAll(".process-step");
  if (processSteps.length && "IntersectionObserver" in window) {
    var stepIO = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        entry.target.classList.toggle("is-active", entry.isIntersecting);
      });
    }, { threshold: 0.5, rootMargin: "-20% 0px -20% 0px" });
    processSteps.forEach(function (step) { stepIO.observe(step); });
  }

  /* ---------- Field validation ---------- */
  function setError(field, message) {
    field.classList.toggle("has-error", Boolean(message));
    var errEl = field.querySelector(".field-error");
    if (errEl) errEl.textContent = message || "";
  }

  function validateField(field) {
    var input = field.querySelector("input, select, textarea");
    if (!input) return true;
    if (input.hasAttribute("required") && !input.value.trim()) {
      setError(field, "This field is required."); return false;
    }
    if (input.type === "email" && input.value) {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.value)) {
        setError(field, "Enter a valid email address."); return false;
      }
    }
    if (input.type === "tel" && input.value) {
      if (input.value.replace(/\D/g, "").length < 10) {
        setError(field, "Enter a valid phone number."); return false;
      }
    }
    setError(field, ""); return true;
  }

  /* ---------- Form submit ---------- */
  function bindForm(formEl) {
    if (!formEl) return;
    var statusEl  = formEl.querySelector(".form-status");
    var submitBtn = formEl.querySelector('button[type="submit"]');

    formEl.addEventListener("submit", function (e) {
      e.preventDefault();
      var valid = true;
      formEl.querySelectorAll(".field").forEach(function (f) { if (!validateField(f)) valid = false; });

      if (!valid) {
        if (statusEl) { statusEl.textContent = "Please fix the highlighted fields and resubmit."; statusEl.className = "form-status show error"; }
        var firstErr = formEl.querySelector(".has-error input, .has-error select, .has-error textarea");
        if (firstErr) firstErr.focus();
        return;
      }

      var data = {};
      new FormData(formEl).forEach(function (v, k) { data[k] = v; });
      var endpoint     = window.KD_FORM_ENDPOINT;
      var originalText = submitBtn ? submitBtn.textContent : "";
      if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = "Sending…"; }

      var finish = function (success) {
        if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = originalText; }
        if (statusEl) {
          statusEl.textContent = success
            ? "Request received — a project lead will follow up within one business day."
            : "We could not reach the server. Your email app has been opened so the request reaches us.";
          statusEl.className = "form-status show " + (success ? "success" : "error");
        }
        if (success) formEl.reset();
      };

      if (endpoint) {
        fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) })
          .then(function (r) { finish(r.ok); })
          .catch(function () { mailFallback(data); finish(false); });
      } else { mailFallback(data); finish(false); }
    });
  }

  function mailFallback(data) {
    var lines   = Object.keys(data).map(function (k) { return k + ": " + data[k]; });
    var subject = encodeURIComponent("New website request — " + (data.name || "KlyneDarius site"));
    var body    = encodeURIComponent(lines.join("\n"));
    window.location.href = "mailto:info@klynedariusconstruction.com?subject=" + subject + "&body=" + body;
  }

  document.querySelectorAll("form[data-kd-form]").forEach(bindForm);

  /* ---------- Checkbox pill state ---------- */
  document.querySelectorAll(".checkbox-pill input").forEach(function (input) {
    input.addEventListener("change", function () {
      input.closest(".checkbox-pill").classList.toggle("is-checked", input.checked);
    });
  });

  /* ---------- Footer year ---------- */
  document.querySelectorAll("[data-year]").forEach(function (el) {
    el.textContent = new Date().getFullYear();
  });

})();

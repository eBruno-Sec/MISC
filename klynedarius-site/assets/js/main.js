/* KlyneDarius Construction — site interactions */
(function () {
  "use strict";

  /* ---------- Mobile nav ---------- */
  var toggle = document.querySelector(".nav-toggle");
  var mobileNav = document.querySelector(".mobile-nav");

  if (toggle && mobileNav) {
    toggle.addEventListener("click", function () {
      var open = toggle.classList.toggle("is-open");
      mobileNav.classList.toggle("is-open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      document.body.style.overflow = open ? "hidden" : "";
    });

    mobileNav.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        toggle.classList.remove("is-open");
        mobileNav.classList.remove("is-open");
        document.body.style.overflow = "";
      });
    });
  }

  /* ---------- Scroll reveal ---------- */
  var prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var revealEls = document.querySelectorAll(".reveal");

  if (revealEls.length && !prefersReduced && "IntersectionObserver" in window) {
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("in");
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -40px 0px" }
    );
    revealEls.forEach(function (el) { io.observe(el); });
  } else {
    revealEls.forEach(function (el) { el.classList.add("in"); });
  }

  /* ---------- Generic field validation ---------- */
  function setError(field, message) {
    field.classList.toggle("has-error", Boolean(message));
    var errEl = field.querySelector(".field-error");
    if (errEl) errEl.textContent = message || "";
  }

  function validateField(field) {
    var input = field.querySelector("input, select, textarea");
    if (!input) return true;

    if (input.hasAttribute("required") && !input.value.trim()) {
      setError(field, "This field is required.");
      return false;
    }
    if (input.type === "email" && input.value) {
      var emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.value);
      if (!emailOk) {
        setError(field, "Enter a valid email address.");
        return false;
      }
    }
    if (input.type === "tel" && input.value) {
      var digits = input.value.replace(/\D/g, "");
      if (digits.length < 10) {
        setError(field, "Enter a valid phone number.");
        return false;
      }
    }
    setError(field, "");
    return true;
  }

  /* ---------- Form submit handling ----------
     No backend is wired up yet (see README "Connecting the forms").
     This performs full client-side validation, then POSTs to
     window.KD_FORM_ENDPOINT if one is configured; otherwise it falls
     back to a mailto draft so leads are never silently dropped. */
  function bindForm(formEl) {
    if (!formEl) return;
    var statusEl = formEl.querySelector(".form-status");
    var submitBtn = formEl.querySelector('button[type="submit"]');

    formEl.addEventListener("submit", function (e) {
      e.preventDefault();

      var fields = formEl.querySelectorAll(".field");
      var valid = true;
      fields.forEach(function (field) {
        if (!validateField(field)) valid = false;
      });

      if (!valid) {
        if (statusEl) {
          statusEl.textContent = "Please fix the highlighted fields and resubmit.";
          statusEl.className = "form-status show error";
        }
        var firstError = formEl.querySelector(".has-error input, .has-error select, .has-error textarea");
        if (firstError) firstError.focus();
        return;
      }

      var data = {};
      new FormData(formEl).forEach(function (value, key) { data[key] = value; });

      var endpoint = window.KD_FORM_ENDPOINT;
      var originalLabel = submitBtn ? submitBtn.textContent : "";
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = "Sending\u2026";
      }

      var finish = function (success) {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = originalLabel;
        }
        if (statusEl) {
          statusEl.textContent = success
            ? "Request received. A KlyneDarius project lead will follow up within one business day."
            : "We could not reach the server. Your email app has been opened so the request still reaches us.";
          statusEl.className = "form-status show " + (success ? "success" : "error");
        }
        if (success) formEl.reset();
      };

      if (endpoint) {
        fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data)
        })
          .then(function (res) { finish(res.ok); })
          .catch(function () { mailFallback(data); finish(false); });
      } else {
        mailFallback(data);
        finish(false);
      }
    });
  }

  function mailFallback(data) {
    var lines = Object.keys(data).map(function (k) { return k + ": " + data[k]; });
    var body = encodeURIComponent(lines.join("\n"));
    var subject = encodeURIComponent("New website request — " + (data.name || "KlyneDarius site"));
    window.location.href = "mailto:info@klynedariusconstruction.com?subject=" + subject + "&body=" + body;
  }

  document.querySelectorAll("form[data-kd-form]").forEach(bindForm);

  /* ---------- Checkbox pill state for service interest tags ---------- */
  document.querySelectorAll(".checkbox-pill input").forEach(function (input) {
    input.addEventListener("change", function () {
      input.closest(".checkbox-pill").classList.toggle("is-checked", input.checked);
    });
  });

  /* ---------- Footer year ---------- */
  var yearEl = document.querySelector("[data-year]");
  if (yearEl) yearEl.textContent = new Date().getFullYear();
})();

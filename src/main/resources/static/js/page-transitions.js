(function () {
  "use strict";
  if (window.__ptInit) return;
  window.__ptInit = true;

  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  document.documentElement.classList.add("pt-ready");

  function ensureChrome() {
    if (!document.getElementById("pt-progress")) {
      var bar = document.createElement("div");
      bar.id = "pt-progress";
      document.body.appendChild(bar);
    }
    if (!document.getElementById("pt-veil")) {
      var veil = document.createElement("div");
      veil.id = "pt-veil";
      document.body.appendChild(veil);
    }
  }

  function showProgress() {
    var bar = document.getElementById("pt-progress");
    var veil = document.getElementById("pt-veil");
    if (!bar) return;
    bar.classList.add("pt-on");
    bar.style.width = "0%";
    requestAnimationFrame(function () {
      bar.style.width = "70%";
    });
    if (veil) veil.classList.add("pt-on");
  }

  function finishProgress() {
    var bar = document.getElementById("pt-progress");
    if (!bar) return;
    bar.style.width = "100%";
    setTimeout(function () {
      bar.classList.remove("pt-on");
      bar.style.width = "0%";
    }, 200);
  }

  function enter() {
    ensureChrome();
    requestAnimationFrame(function () {
      document.body.classList.add("pt-visible");
      document.documentElement.classList.add("pt-visible");
      finishProgress();
    });
  }

  function isInternal(href) {
    if (!href) return false;
    if (href.charAt(0) === "#") return false;
    if (href.indexOf("mailto:") === 0 || href.indexOf("tel:") === 0) return false;
    if (href.indexOf("javascript:") === 0) return false;
    try {
      var url = new URL(href, window.location.href);
      if (url.origin !== window.location.origin) return false;
      // only same-site document navigations
      return true;
    } catch (e) {
      return false;
    }
  }

  function navigate(url) {
    if (reduce) {
      window.location.href = url;
      return;
    }
    ensureChrome();
    showProgress();
    document.body.classList.remove("pt-visible");
    document.body.classList.add("pt-exit");
    setTimeout(function () {
      window.location.href = url;
    }, 260);
  }

  document.addEventListener("DOMContentLoaded", function () {
    enter();

    document.body.addEventListener("click", function (e) {
      if (e.defaultPrevented) return;
      if (e.button !== 0) return;
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;

      var a = e.target.closest("a");
      if (!a) return;
      if (a.target && a.target !== "" && a.target !== "_self") return;
      if (a.hasAttribute("download")) return;

      var href = a.getAttribute("href");
      if (!isInternal(href)) return;

      // allow in-page anchors
      try {
        var url = new URL(href, window.location.href);
        if (url.pathname === window.location.pathname && url.hash) return;
        // same page no-op
        if (url.href === window.location.href) return;
      } catch (err) {
        return;
      }

      e.preventDefault();
      navigate(url.href);
    });
  });

  // BFCache back/forward
  window.addEventListener("pageshow", function (ev) {
    if (ev.persisted) {
      document.body.classList.remove("pt-exit");
      enter();
    }
  });
})();

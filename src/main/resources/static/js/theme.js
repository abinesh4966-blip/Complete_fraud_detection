(function () {
  "use strict";
  if (window.__themeInit) return;
  window.__themeInit = true;

  function isDark() {
    try { return localStorage.getItem("theme") === "dark"; } catch (e) { return false; }
  }

  function applyTheme() {
    var dark = isDark();
    document.documentElement.classList.toggle("dark", dark);
    if (document.body) document.body.classList.toggle("dark", dark);
    var btns = document.querySelectorAll("#themeBtn, [data-theme-btn]");
    btns.forEach(function (btn) {
      btn.textContent = dark ? "Light Mode" : "Dark Mode";
    });
  }

  window.toggleTheme = function () {
    try {
      localStorage.setItem("theme", isDark() ? "light" : "dark");
    } catch (e) {}
    applyTheme();
  };

  window.applyTheme = applyTheme;

  // Apply ASAP to reduce flash
  applyTheme();
  document.addEventListener("DOMContentLoaded", applyTheme);
})();

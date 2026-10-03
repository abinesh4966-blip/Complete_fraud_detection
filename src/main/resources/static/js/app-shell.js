(function () {
  "use strict";
  if (window.__shellInit) return;
  window.__shellInit = true;

  var path = (location.pathname.split("/").pop() || "").toLowerCase();
  var NO_SHELL = {
    "":1, "index.html":1, "splash.html":1, "access.html":1,
    "admin-login.html":1, "user-login.html":1, "user-register.html":1,
    "register.html":1, "login.html":1
  };
  if (NO_SHELL[path]) return;

  function isDark() {
    try { return localStorage.getItem("theme") === "dark"; } catch (e) { return false; }
  }
  function applyTheme() {
    var dark = isDark();
    document.documentElement.classList.toggle("dark", dark);
    if (document.body) document.body.classList.toggle("dark", dark);
    var btns = document.querySelectorAll("[data-theme-btn]");
    btns.forEach(function (b) { b.textContent = dark ? "Light Mode" : "Dark Mode"; });
  }
  window.toggleTheme = function () {
    try { localStorage.setItem("theme", isDark() ? "light" : "dark"); } catch (e) {}
    applyTheme();
  };
  window.applyTheme = applyTheme;
  window.logout = function () {
    try { sessionStorage.clear(); } catch (e) {}
    location.href = "access.html";
  };

  var ADMIN = [
    ["dashboard.html", "Dashboard"],
    ["admin-review.html", "Case Review"],
    ["checker.html", "Transaction Checker"],
    ["history.html", "History"],
    ["admin-reports.html", "Reports"],
    ["admin-users.html", "Users"],
    ["profile.html", "Profile Centre"]
  ];
  var USER = [
    ["user-dashboard.html", "Dashboard"],
    ["user-transactions.html", "My Transactions"],
    ["user-alerts.html", "Alerts"],
    ["user-report.html", "Report"],
    ["profile.html", "Profile Centre"]
  ];

  function role() {
    return (sessionStorage.getItem("role") || "").toUpperCase();
  }
  function isAdmin() {
    var r = role();
    return r === "ADMIN" || r === "SUPER_ADMIN";
  }

  function build() {
    if (document.getElementById("appSidebar")) return;
    document.body.classList.add("has-shell");

    var links = isAdmin() ? ADMIN : USER;
    var navHtml = links.map(function (pair) {
      var href = pair[0], label = pair[1];
      var active = path === href.toLowerCase() ? " active" : "";
      return '<a class="' + active.trim() + '" href="' + href + '">' + label + "</a>";
    }).join("");

    var who = sessionStorage.getItem("fullName") || sessionStorage.getItem("username") || (isAdmin() ? "Officer" : "Customer");
    var roleLabel = role() || (isAdmin() ? "ADMIN" : "USER");

    var sidebar = document.createElement("aside");
    sidebar.className = "shell-sidebar";
    sidebar.id = "appSidebar";
    sidebar.innerHTML =
      '<div class="shell-brand"><div class="mark">BSN</div><div><strong>BSN Fraud Detection</strong><span>Secure operations console</span></div></div>' +
      '<div class="shell-user"><b>' + who + '</b><br>' + roleLabel + "</div>" +
      '<nav class="shell-nav">' + navHtml + "</nav>" +
      '<div class="shell-foot">' +
      '<button type="button" data-theme-btn onclick="toggleTheme()">Dark Mode</button>' +
      '<button type="button" class="danger" onclick="logout()">Logout</button>' +
      "</div>";

    var overlay = document.createElement("div");
    overlay.className = "shell-overlay";
    overlay.id = "appOverlay";
    overlay.addEventListener("click", close);

    var top = document.createElement("header");
    top.className = "shell-topbar";
    top.innerHTML =
      '<div class="left">' +
      '<button type="button" class="shell-menu-btn" id="shellMenuBtn" aria-label="Open menu">☰</button>' +
      '<div class="shell-title">BSN Fraud Detection System<small id="shellPageTitle">Operations</small></div>' +
      "</div>" +
      '<div class="shell-top-actions">' +
      '<button type="button" data-theme-btn onclick="toggleTheme()">Dark Mode</button>' +
      '<button type="button" onclick="logout()">Logout</button>' +
      "</div>";

    // Move existing body children into main
    var main = document.createElement("main");
    main.className = "shell-main";
    var nodes = Array.prototype.slice.call(document.body.childNodes);
    nodes.forEach(function (n) { main.appendChild(n); });

    document.body.appendChild(overlay);
    document.body.appendChild(sidebar);
    document.body.appendChild(top);
    document.body.appendChild(main);

    document.getElementById("shellMenuBtn").addEventListener("click", open);

    // page title from active link
    var active = sidebar.querySelector("a.active");
    if (active) {
      var st = document.getElementById("shellPageTitle");
      if (st) st.textContent = active.textContent;
    }

    applyTheme();
  }

  function open() {
    document.getElementById("appSidebar").classList.add("open");
    document.getElementById("appOverlay").classList.add("open");
  }
  function close() {
    document.getElementById("appSidebar").classList.remove("open");
    document.getElementById("appOverlay").classList.remove("open");
  }
  window.closeShell = close;

  // Close drawer after internal nav click
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest(".shell-nav a");
    if (a) close();
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", build);
  } else {
    build();
  }
  applyTheme();
})();

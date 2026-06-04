(function () {
  const pages = [
    { key: "command", label: "Command Center", caption: "Governance posture", href: "/", icon: "M4 6h16M4 12h10M4 18h7" },
    { key: "ops", label: "Operations", caption: "Alerts and actors", href: "/ops/", icon: "M12 3v18M3 12h18M6 6l12 12M18 6L6 18" },
    { key: "proof", label: "Evidence", caption: "Proof, approvals, ledger", href: "/proof/", icon: "M7 4h10v16H7zM9 8h6M9 12h6M9 16h4" },
    { key: "admin", label: "Administration", caption: "Users and runtime", href: "/demo/", icon: "M12 5a4 4 0 100 8 4 4 0 000-8zM4 21a8 8 0 0116 0" },
    { key: "license", label: "Licensing", caption: "Seats and plans", href: "/pricing/", icon: "M5 7h14v10H5zM8 7V5h8v2M8 12h8" }
  ];

  const tokenKey = "sovereign.accessToken";
  const refreshKey = "sovereign.refreshToken";
  const userKey = "sovereign.user";
  const apiKey = "sovereign.apiBase";

  const state = {
    apiBase: inferApiBase().replace(/\/$/, ""),
    token: localStorage.getItem(tokenKey) || "",
    refreshToken: localStorage.getItem(refreshKey) || "",
    user: readJson(localStorage.getItem(userKey)),
    health: null
  };

  function readJson(value) {
    try {
      return value ? JSON.parse(value) : null;
    } catch (_) {
      return null;
    }
  }

  function configuredApiBase() {
    return ((window.SOVEREIGN_CONFIG && window.SOVEREIGN_CONFIG.API_BASE_URL) || "").trim();
  }

  function inferApiBase() {
    const params = new URLSearchParams(window.location.search);
    const queryValue = params.get("api");
    if (queryValue) return queryValue;
    const stored = localStorage.getItem(apiKey);
    if (stored) return stored;
    const configured = configuredApiBase();
    if (configured) return configured;
    const protocol = window.location.protocol || "http:";
    const host = window.location.hostname || "localhost";
    if (window.location.port === "13000") return `${protocol}//${host}:18000`;
    return `${protocol}//${host}:8000`;
  }

  function icon(path) {
    return `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="${path}" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
    </svg>`;
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function fmtNumber(value) {
    const number = Number(value || 0);
    return Number.isFinite(number) ? number.toLocaleString() : "--";
  }

  function fmtTime(value) {
    if (!value) return "--";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "--" : date.toLocaleString();
  }

  function apiUrl(path) {
    if (!path.startsWith("/")) return path;
    return `${state.apiBase}${path}`;
  }

  async function request(path, options = {}) {
    if (options.auth !== false && !state.token) {
      const error = new Error("AUTH_REQUIRED");
      error.status = 401;
      throw error;
    }

    const headers = new Headers(options.headers || {});
    if (!headers.has("Content-Type") && options.body && !(options.body instanceof FormData)) {
      headers.set("Content-Type", "application/json");
    }
    if (options.auth !== false && state.token) {
      headers.set("Authorization", `Bearer ${state.token}`);
    }

    const response = await fetch(apiUrl(path), { ...options, headers });
    const text = await response.text();
    let data = text;
    try {
      data = text ? JSON.parse(text) : {};
    } catch (_) {
      data = text;
    }

    if (!response.ok) {
      const detail = typeof data === "object" && data && data.detail ? data.detail : `HTTP ${response.status}`;
      const error = new Error(Array.isArray(detail) ? JSON.stringify(detail) : detail);
      error.status = response.status;
      error.data = data;
      if (response.status === 401 && options.auth !== false) clearAuth(false);
      throw error;
    }
    return data;
  }

  async function login(email, password, mfaCode) {
    const payload = {
      email,
      password,
      mfa_code: mfaCode || undefined,
      device: {
        device_id: "web-command-center",
        platform: "web",
        app_version: "static-ui"
      }
    };
    const data = await request("/api/v2/auth/login", {
      auth: false,
      method: "POST",
      body: JSON.stringify(payload)
    });
    state.token = data.access_token;
    state.refreshToken = data.refresh_token;
    state.user = data.user;
    localStorage.setItem(tokenKey, state.token);
    localStorage.setItem(refreshKey, state.refreshToken);
    localStorage.setItem(userKey, JSON.stringify(state.user || {}));
    renderTopBar();
    closeAuth();
    toast("Signed in");
    window.dispatchEvent(new CustomEvent("shield:auth"));
  }

  async function logout() {
    try {
      if (state.token) {
        await request("/api/v2/auth/logout", {
          method: "POST",
          body: JSON.stringify({ refresh_token: state.refreshToken, revoke_current: true })
        });
      }
    } catch (_) {
      // Keep logout deterministic even if the token already expired.
    }
    clearAuth(true);
  }

  function clearAuth(notify) {
    state.token = "";
    state.refreshToken = "";
    state.user = null;
    localStorage.removeItem(tokenKey);
    localStorage.removeItem(refreshKey);
    localStorage.removeItem(userKey);
    renderTopBar();
    if (notify) {
      toast("Signed out");
      window.dispatchEvent(new CustomEvent("shield:auth"));
    }
  }

  function setApiBase(value) {
    state.apiBase = value.trim().replace(/\/$/, "");
    localStorage.setItem(apiKey, state.apiBase);
    renderTopBar();
    refreshHealth();
    window.dispatchEvent(new CustomEvent("shield:api"));
  }

  async function refreshHealth() {
    const pill = document.getElementById("health-pill");
    try {
      state.health = await request("/health", { auth: false });
      if (pill) {
        pill.className = "status-pill online";
        pill.innerHTML = `<span class="status-dot"></span>${escapeHtml(state.health.status || "online")}`;
      }
    } catch (_) {
      state.health = null;
      if (pill) {
        pill.className = "status-pill offline";
        pill.innerHTML = `<span class="status-dot"></span>offline`;
      }
    }
  }

  function currentPage() {
    const app = document.querySelector(".app-shell");
    return app ? app.dataset.page || "command" : "command";
  }

  function renderSideNav() {
    const root = document.getElementById("side-nav");
    if (!root) return;
    const active = currentPage();
    root.innerHTML = `
      <div class="brand-block">
        <div class="brand-mark"><img src="/icon.svg" alt="" /></div>
        <div>
          <strong class="brand-name">Sovereign Shield</strong>
          <span class="brand-subtitle">Security governance center</span>
        </div>
      </div>
      <div>
        <div class="nav-section-label">Workspace</div>
        <nav class="nav-list" aria-label="Primary">
          ${pages.map((page) => `
            <a class="nav-link${page.key === active ? " active" : ""}" href="${page.href}">
              <span class="nav-icon">${icon(page.icon)}</span>
              <span class="nav-text"><strong>${page.label}</strong><span>${page.caption}</span></span>
            </a>
          `).join("")}
        </nav>
      </div>
      <div class="nav-footer">
        <strong>Runtime API</strong>
        <code title="${escapeHtml(state.apiBase)}">${escapeHtml(state.apiBase)}</code>
      </div>
    `;
  }

  function renderTopBar() {
    const root = document.getElementById("top-bar");
    if (!root) return;
    const user = state.user;
    root.innerHTML = `
      <div class="top-left">
        <div class="top-title">
          <strong>${user ? escapeHtml(user.role || "Operator") : "Operator console"}</strong>
          <span>${user ? escapeHtml(user.email || user.sub || "") : "Sign in to load protected surfaces"}</span>
        </div>
        <span class="status-pill" id="health-pill"><span class="status-dot"></span>checking</span>
      </div>
      <div class="top-right">
        <div class="api-control">
          <label for="api-base-input">API</label>
          <input id="api-base-input" value="${escapeHtml(state.apiBase)}" autocomplete="off" spellcheck="false" />
          <button class="icon-btn" id="save-api-base" type="button" title="Save API base">${icon("M5 12h14M13 6l6 6-6 6")}</button>
        </div>
        ${user
          ? `<button class="btn-secondary" id="logout-button" type="button">Sign out</button>`
          : `<button class="btn" id="open-auth" type="button">Sign in</button>`
        }
      </div>
    `;
    document.getElementById("save-api-base")?.addEventListener("click", () => {
      setApiBase(document.getElementById("api-base-input").value);
    });
    document.getElementById("api-base-input")?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") setApiBase(event.currentTarget.value);
    });
    document.getElementById("open-auth")?.addEventListener("click", openAuth);
    document.getElementById("logout-button")?.addEventListener("click", logout);
    refreshHealth();
  }

  function renderAuthPanel() {
    if (document.getElementById("auth-panel")) return;
    const panel = document.createElement("div");
    panel.id = "auth-panel";
    panel.className = "auth-panel";
    panel.innerHTML = `
      <div class="auth-card" role="dialog" aria-modal="true" aria-labelledby="auth-title">
        <header>
          <h2 id="auth-title">Operator sign-in</h2>
          <button class="icon-btn" id="close-auth" type="button" title="Close">${icon("M6 6l12 12M18 6L6 18")}</button>
        </header>
        <form id="auth-form" class="form-grid">
          <div class="field">
            <label for="auth-email">Email</label>
            <input id="auth-email" name="email" type="email" value="admin@sovereign.local" autocomplete="username" required />
          </div>
          <div class="field">
            <label for="auth-password">Password</label>
            <input id="auth-password" name="password" type="password" autocomplete="current-password" required />
          </div>
          <div class="field">
            <label for="auth-mfa">MFA code</label>
            <input id="auth-mfa" name="mfa" inputmode="numeric" autocomplete="one-time-code" />
          </div>
          <button class="btn" type="submit">Sign in</button>
          <div id="auth-message" class="muted"></div>
        </form>
      </div>
    `;
    document.body.appendChild(panel);
    document.getElementById("close-auth")?.addEventListener("click", closeAuth);
    panel.addEventListener("click", (event) => {
      if (event.target === panel) closeAuth();
    });
    document.getElementById("auth-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const message = document.getElementById("auth-message");
      const button = form.querySelector("button[type='submit']");
      const elements = form.elements;
      button.disabled = true;
      message.textContent = "Signing in...";
      try {
        await login(elements.email.value, elements.password.value, elements.mfa.value);
        elements.password.value = "";
        message.textContent = "";
      } catch (error) {
        message.textContent = error.message;
      } finally {
        button.disabled = false;
      }
    });
  }

  function openAuth() {
    renderAuthPanel();
    document.getElementById("auth-panel").classList.add("open");
    setTimeout(() => document.getElementById("auth-password")?.focus(), 0);
  }

  function closeAuth() {
    document.getElementById("auth-panel")?.classList.remove("open");
  }

  function toast(message) {
    let root = document.getElementById("toast");
    if (!root) {
      root = document.createElement("div");
      root.id = "toast";
      root.className = "toast";
      document.body.appendChild(root);
    }
    root.textContent = message;
    root.classList.add("show");
    clearTimeout(root._timer);
    root._timer = setTimeout(() => root.classList.remove("show"), 2600);
  }

  function requireAuthMessage(targetId, message) {
    const target = document.getElementById(targetId);
    if (!target) return;
    target.innerHTML = `<div class="empty-state">${escapeHtml(message || "Sign in to load this surface.")}</div>`;
  }

  window.Shield = {
    state,
    request,
    apiUrl,
    setApiBase,
    refreshHealth,
    login,
    logout,
    openAuth,
    toast,
    escapeHtml,
    fmtNumber,
    fmtTime,
    requireAuthMessage
  };

  document.addEventListener("DOMContentLoaded", () => {
    renderSideNav();
    renderTopBar();
    renderAuthPanel();
  });
})();

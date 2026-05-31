const suitePages = {
  overview: {
    index: "01",
    label: "Asset Overview",
    href: "/",
    caption: "Product thesis and live system summary",
  },
  control: {
    index: "02",
    label: "Control Plane",
    href: "/ops/",
    caption: "Real-time operator console and event rail",
  },
  proof: {
    index: "03",
    label: "Verification Studio",
    href: "/proof/",
    caption: "Visual runtime proof and evidence chain",
  },
  trust: {
    index: "04",
    label: "Trust Center",
    href: "/demo/",
    caption: "Device checks, trust bundle, and artifacts",
  },
  commercial: {
    index: "05",
    label: "Commercial Layer",
    href: "/pricing/",
    caption: "Pricing signal, acquisition framing, and plans",
  },
};

function renderSuiteLink(key, currentPage) {
  const page = suitePages[key];
  const active = currentPage === key ? " active" : "";
  return `
    <a class="suite-link${active}" href="${page.href}">
      <div class="suite-link-top">
        <em class="suite-index">${page.index}</em>
        <strong>${page.label}</strong>
      </div>
      <span>${page.caption}</span>
    </a>
  `;
}

document.addEventListener("DOMContentLoaded", () => {
  const root = document.getElementById("asset-nav");
  const app = document.querySelector(".asset-app");
  if (!root || !app) return;

  const currentPage = app.dataset.suitePage || "overview";

  root.innerHTML = `
    <div class="suite-brand">
      <span class="suite-kicker">Xavira Tech Labs</span>
      <h1>Sovereign Shield</h1>
      <p>Enterprise AI Security Gateway for private LLM deployments, buyer proof, and compliance-grade evidence.</p>
      <div class="suite-stamp">Acquisition-grade operator asset</div>
    </div>

    <div class="suite-group">
      <div class="suite-group-label">Asset Layers</div>
      <div class="suite-links">
        ${renderSuiteLink("overview", currentPage)}
        ${renderSuiteLink("control", currentPage)}
        ${renderSuiteLink("proof", currentPage)}
        ${renderSuiteLink("trust", currentPage)}
        ${renderSuiteLink("commercial", currentPage)}
      </div>
    </div>

    <div class="suite-group">
      <div class="suite-group-label">Runtime Surfaces</div>
      <div class="suite-links">
        <a class="suite-link" href="http://localhost:8000/api/docs" target="_blank" rel="noreferrer">
          <div class="suite-link-top">
            <em class="suite-index">API</em>
            <strong>API Reference</strong>
          </div>
          <span>Open the FastAPI docs on localhost</span>
        </a>
        <a class="suite-link" href="/docs/demo/sovereign-shield-enterprise-demo.mp4" target="_blank" rel="noreferrer">
          <div class="suite-link-top">
            <em class="suite-index">VID</em>
            <strong>Recorded Demo</strong>
          </div>
          <span>Buyer-facing product walkthrough</span>
        </a>
      </div>
    </div>

    <div class="suite-ops-card">
      <div class="suite-group-label">Buyer Posture</div>
      <div class="suite-status-card">
        <div><span>Mode</span><strong>Local-first</strong></div>
        <div><span>Package</span><strong>Verified build</strong></div>
        <div><span>Audience</span><strong>CISO / AI infra</strong></div>
      </div>
      <div class="suite-group-label suite-command-label">Buyer Commands</div>
      <code>pnpm launch</code>
      <code>pnpm submit:ready</code>
      <code>pnpm generate:data-room</code>
    </div>
  `;
});

const API = "";

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(tab.dataset.tab + "-tab").classList.add("active");
  });
});

async function analyzeUrl() {
  const input = document.getElementById("url-input");
  const url = input.value.trim();
  if (!url) return;

  const container = document.getElementById("url-results");
  container.innerHTML = '<div class="loading">Scanning...</div>';

  try {
    const res = await fetch(API + "/api/analyze/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error((await res.json()).error || "Request failed");
    const data = await res.json();
    container.innerHTML = renderUrlResult(data);
  } catch (e) {
    container.innerHTML = `<div class="error-msg">${e.message}</div>`;
  }
}

async function analyzeEmail() {
  const input = document.getElementById("email-input");
  const email = input.value.trim();
  if (!email) return;

  const container = document.getElementById("email-results");
  container.innerHTML = '<div class="loading">Scanning...</div>';

  try {
    const res = await fetch(API + "/api/analyze/email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    if (!res.ok) throw new Error((await res.json()).error || "Request failed");
    const data = await res.json();
    container.innerHTML = renderEmailResult(data);
  } catch (e) {
    container.innerHTML = `<div class="error-msg">${e.message}</div>`;
  }
}

async function loadDemos() {
  const container = document.getElementById("demo-results");
  container.innerHTML = '<div class="loading">Loading demos...</div>';

  try {
    const res = await fetch(API + "/api/demos");
    const data = await res.json();

    let html = "<h2 style='margin-bottom:1rem;color:#38bdf8'>URL Analysis Demos</h2>";
    data.urls.forEach((r) => {
      html += `<div class="demo-label">${r.label}</div>` + renderUrlResult(r);
    });

    html += "<h2 style='margin:2rem 0 1rem;color:#38bdf8'>Email Analysis Demo</h2>";
    html += renderEmailResult(data.email);

    container.innerHTML = html;
  } catch (e) {
    container.innerHTML = `<div class="error-msg">${e.message}</div>`;
  }
}

async function loadStats() {
  const container = document.getElementById("stats-results");
  try {
    const res = await fetch(API + "/api/stats");
    const data = await res.json();
    container.innerHTML = `
      <div class="stat-grid">
        <div class="stat-card"><div class="number">${data.total}</div><div class="label">Total Scans</div></div>
        <div class="stat-card"><div class="number">${data.url_scans}</div><div class="label">URL Scans</div></div>
        <div class="stat-card"><div class="number">${data.email_scans}</div><div class="label">Email Scans</div></div>
        <div class="stat-card"><div class="number">${data.threats_found}</div><div class="label">Threats Found</div></div>
      </div>`;
  } catch (e) {
    container.innerHTML = `<div class="error-msg">${e.message}</div>`;
  }
}

function renderUrlResult(data) {
  return `
    <div class="result-card">
      <div class="result-header">
        <h3>${escapeHtml(data.url)}</h3>
        <span class="threat-badge threat-${data.threat_level}">${data.threat_level} (${data.score}/100)</span>
      </div>
      <div class="score-bar-container">
        <div class="score-bar ${data.threat_level}" style="width:${data.score}%"></div>
      </div>
      ${renderFindings(data.findings)}
    </div>`;
}

function renderEmailResult(data) {
  const h = data.headers || {};
  return `
    <div class="result-card">
      <div class="result-header">
        <h3>Email Analysis</h3>
        <span class="threat-badge threat-${data.threat_level}">${data.threat_level} (${data.score}/100)</span>
      </div>
      <div class="score-bar-container">
        <div class="score-bar ${data.threat_level}" style="width:${data.score}%"></div>
      </div>
      <div class="email-headers">
        <div><strong>From:</strong> ${escapeHtml(h.from || "N/A")}</div>
        <div><strong>To:</strong> ${escapeHtml(h.to || "N/A")}</div>
        <div><strong>Subject:</strong> ${escapeHtml(h.subject || "N/A")}</div>
      </div>
      ${renderFindings(data.findings)}
    </div>`;
}

function renderFindings(findings) {
  if (!findings || !findings.length) return '<div class="finding"><span style="color:#94a3b8">No issues found</span></div>';
  return findings
    .map(
      (f) => `
    <div class="finding">
      <div class="severity-dot severity-${f.severity}"></div>
      <div class="finding-text">
        <strong>${escapeHtml(f.indicator)}</strong>
        <span>${escapeHtml(f.detail)}</span>
      </div>
    </div>`
    )
    .join("");
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

document.getElementById("url-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") analyzeUrl();
});

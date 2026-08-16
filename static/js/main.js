const form = document.getElementById("scanForm");
const scanBtn = document.getElementById("scanBtn");
const loading = document.getElementById("loading");
const results = document.getElementById("results");
const errorBox = document.getElementById("errorBox");

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function summaryRow(label, value) {
  return `<div class="summary-item"><span>${escapeHtml(label)}</span><span>${escapeHtml(value ?? "—")}</span></div>`;
}

function listOrEmpty(items, emptyText) {
  if (!items || !items.length) return `<p class="muted">${escapeHtml(emptyText)}</p>`;
  return `<ul class="friendly-list">${items.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>`;
}

function renderFinding(f, index) {
  return `
    <details class="finding-simple">
      <summary>
        <div>
          <strong>${escapeHtml(f.friendly_title || f.title)}</strong>
          <small>${escapeHtml(f.category)}</small>
        </div>
        <div class="finding-tags">
          <span class="badge ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
          <span class="confidence-badge">${escapeHtml(f.confidence)} confidence</span>
        </div>
      </summary>
      <div class="finding-body">
        <p><strong>What it means:</strong> ${escapeHtml(f.what_it_means)}</p>
        <p><strong>Why it matters:</strong> ${escapeHtml(f.why_care)}</p>
        <p><strong>Does it mean hacked?</strong> ${escapeHtml(f.does_it_mean_hacked)}</p>
        <p><strong>Recommended action:</strong> ${escapeHtml(f.recommendation)}</p>
        ${f.evidence ? `<p><strong>Evidence:</strong> <code>${escapeHtml(f.evidence)}</code></p>` : ""}
        <p class="muted"><strong>Status:</strong> ${escapeHtml(f.status)} · <strong>ID:</strong> ${escapeHtml(f.code)}</p>
      </div>
    </details>
  `;
}

function render(data) {
  results.classList.remove("hidden");
  errorBox.classList.add("hidden");

  document.getElementById("score").textContent = data.score == null ? "N/A" : `${data.score}/100`;
  document.getElementById("posture").textContent = data.posture_text || data.posture;

  const important = (data.counts.High || 0) + (data.counts.Critical || 0) + (data.counts.Medium || 0);
  const manual = (data.status_counts["Manual Review Required"] || 0) + (data.status_counts["Potential Concern"] || 0);
  const coverage = Number(data.coverage_percent || 0);

  document.getElementById("importantCount").textContent = important;
  document.getElementById("manualCount").textContent = manual;
  document.getElementById("coverageValue").textContent = `${coverage}%`;

  document.getElementById("reportBtn").href = `/api/report/${data.scan_id}`;

  const h = data.hackability || {};
  document.getElementById("hackability").innerHTML = `
    <div class="hack-answer">
      <h3>${escapeHtml(h.level || "")}</h3>
      <p>${escapeHtml(h.answer || "")}</p>
      <p>${escapeHtml(h.message || "")}</p>
    </div>
  `;

  const bs = data.beginner_summary || {};
  document.getElementById("beginnerSummary").innerHTML = `
    <div class="summary-columns">
      <div class="friendly-panel good-panel">
        <h3>✓ Already good</h3>
        ${listOrEmpty(bs.good_news, "No positive control was highlighted.")}
      </div>
      <div class="friendly-panel improve-panel">
        <h3>⚠ Improve these</h3>
        ${listOrEmpty(bs.improvements, "No confirmed improvement was highlighted.")}
      </div>
      <div class="friendly-panel review-panel">
        <h3>🔎 Check manually</h3>
        ${listOrEmpty(bs.manual_review, "No manual-review item was highlighted.")}
      </div>
    </div>
    <div class="important-note"><strong>Important:</strong> ${escapeHtml(bs.important_note || "")}</div>
  `;

  const cia = data.cia || {};
  document.getElementById("ciaCards").innerHTML = Object.entries(cia).map(([name, item]) => `
    <div class="cia-card">
      <div class="cia-head">
        <strong>${escapeHtml(name)}</strong>
        <span>${escapeHtml(item.level || "")}</span>
      </div>
      <p><strong>${escapeHtml(item.status || "")}</strong></p>
      <p>${escapeHtml(item.explanation || "")}</p>
      ${item.related_findings && item.related_findings.length
        ? `<small>Related findings: ${item.related_findings.map(escapeHtml).join("; ")}</small>`
        : ""}
    </div>
  `).join("");

  const comparisonCard = document.getElementById("comparisonCard");
  if (data.comparison) {
    comparisonCard.classList.remove("hidden");
    const c = data.comparison;
    const hasComparableScores = c.previous_score != null && c.current_score != null && c.score_change != null;
    const change = hasComparableScores ? Number(c.score_change) : null;
    document.getElementById("comparison").innerHTML = `
      <div class="comparison-score">
        <div><span>Previous</span><strong>${c.previous_score == null ? "N/A" : `${c.previous_score}/100`}</strong></div>
        <div class="arrow">→</div>
        <div><span>Current</span><strong>${c.current_score == null ? "N/A" : `${c.current_score}/100`}</strong></div>
        <div class="change ${change >= 0 ? "positive" : "negative"}">${change == null ? "Not comparable" : `${change > 0 ? "+" : ""}${change}`}</div>
      </div>
      <div class="summary-columns two">
        <div class="friendly-panel good-panel">
          <h3>Resolved</h3>
          ${listOrEmpty(c.resolved, "No confirmed finding was resolved.")}
        </div>
        <div class="friendly-panel improve-panel">
          <h3>New</h3>
          ${listOrEmpty(c.new, "No new confirmed finding appeared.")}
        </div>
      </div>
    `;
  } else {
    comparisonCard.classList.add("hidden");
  }

  document.getElementById("aiPrompt").textContent = data.ai_remediation_prompt || "";

  document.getElementById("findings").innerHTML =
    data.findings.length
      ? data.findings.map(renderFinding).join("")
      : `<div class="empty">No finding was recorded by the checks performed.</div>`;

  document.getElementById("categoryScores").innerHTML =
    Object.entries(data.categories).map(([name, item]) => {
      if (item.state === "evaluated") {
        return `
          <div class="category-row">
            <div class="bar-head">
              <span>${escapeHtml(name)}</span>
              <strong>${item.score}/100</strong>
            </div>
            <div class="bar-track">
              <div class="bar-fill" style="width:${Math.max(0, Math.min(100, item.score))}%"></div>
            </div>
            <small class="category-note">${escapeHtml(item.note || "")}</small>
          </div>`;
      }

      const label = item.state === "not_observed" ? "N/A - Not observed" : "Limited";
      return `
        <div class="category-row category-na">
          <div class="bar-head">
            <span>${escapeHtml(name)}</span>
            <strong>${escapeHtml(label)}</strong>
          </div>
          <small class="category-note">${escapeHtml(item.note || "")}</small>
        </div>`;
    }).join("");

  document.getElementById("summary").innerHTML = [
    summaryRow("Final URL", data.final_url),
    summaryRow("HTTP Status", data.status_code),
    summaryRow("Redirects", data.redirect_count),
    summaryRow("Findings", data.findings.length),
    summaryRow("External Domains", data.external_domains.length),
    summaryRow("WebShield Version", data.version),
  ].join("");

  document.getElementById("headers").innerHTML = data.headers.map(h => `
    <div class="check">
      <div>
        <strong>${escapeHtml(h.name)}</strong>
        ${h.value ? `<small>${escapeHtml(h.value)}</small>` : ""}
      </div>
      <strong class="${h.present ? "ok" : "missing"}">${h.present ? "✓ Present" : "⚠ Not detected"}</strong>
    </div>
  `).join("");

  const tls = data.tls || {};
  document.getElementById("tls").innerHTML = [
    summaryRow("HTTPS", tls.enabled ? "Enabled" : "Not detected"),
    summaryRow("Certificate", tls.valid ? "Validated" : "Could not validate"),
    summaryRow("TLS Protocol", tls.protocol || "—"),
    summaryRow("Cipher", tls.cipher || "—"),
    summaryRow("Issuer", tls.issuer || "—"),
    summaryRow("Days Remaining", tls.days_remaining ?? "—"),
  ].join("");

  const cors = data.cors || {};
  document.getElementById("application").innerHTML = [
    summaryRow("Forms", data.forms.length),
    summaryRow("Cookies", data.cookies.length),
    summaryRow("CORS Origin", cors.allow_origin || "Not advertised"),
    summaryRow("CORS Credentials", cors.allow_credentials || "Not advertised"),
  ].join("");

  document.getElementById("client").innerHTML = [
    summaryRow("External Domains", data.external_domains.length),
    summaryRow("Third-Party Scripts", data.third_party_scripts.length),
    summaryRow("Mixed Content", data.mixed_content.length),
    summaryRow("Client Review Indicators", data.client_side.reduce((a, b) => a + b.count, 0)),
  ].join("");

  document.getElementById("techChips").innerHTML = data.technologies.length
    ? data.technologies.map(t => `<span class="chip">${escapeHtml(t)}</span>`).join("")
    : `<span class="muted">No clear technology signature detected.</span>`;

  window.scrollTo({ top: results.offsetTop - 70, behavior: "smooth" });
}

document.getElementById("copyPromptBtn").addEventListener("click", async () => {
  const text = document.getElementById("aiPrompt").textContent;
  try {
    await navigator.clipboard.writeText(text);
    const btn = document.getElementById("copyPromptBtn");
    const old = btn.textContent;
    btn.textContent = "Copied ✓";
    setTimeout(() => btn.textContent = old, 1600);
  } catch {
    alert("Could not copy automatically. Select the prompt and copy it manually.");
  }
});

async function runScan(url) {
  loading.classList.remove("hidden");
  results.classList.add("hidden");
  errorBox.classList.add("hidden");
  scanBtn.disabled = true;
  scanBtn.textContent = "Checking…";

  const body = new URLSearchParams();
  body.set("url", url);

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Scan failed");
    render(data);
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove("hidden");
  } finally {
    loading.classList.add("hidden");
    scanBtn.disabled = false;
    scanBtn.textContent = "Check Website";
  }
}

form.addEventListener("submit", event => {
  event.preventDefault();
  runScan(document.getElementById("url").value.trim());
});

document.querySelectorAll(".history-row").forEach(row => {
  row.addEventListener("click", async () => {
    try {
      const response = await fetch(`/api/scans/${row.dataset.id}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not load scan");
      render(data);
    } catch (err) {
      errorBox.textContent = err.message;
      errorBox.classList.remove("hidden");
    }
  });
});

/**
 * MCP RedTeam Scanner — Report Renderer
 *
 * Renders a full scan report into a DOM container with:
 * - KPI cards (total findings, risk score, severity breakdown)
 * - Module-by-module results table (Clean Summary)
 * - Prioritized Vulnerability Assessment (Sorted List)
 * - Export functions (PDF, JSON, Markdown)
 */

// ══════════════════════════════════════════════════════════════
// RENDER REPORT
// ══════════════════════════════════════════════════════════════

function renderReport(report, container) {
  if (!report || !container) return;

  const summary = report.summary || {};
  const sev = summary.severity_breakdown || {};
  const modules = summary.modules_summary || [];
  const phase0 = report.phase0_findings || [];
  const attackResults = report.attack_results || [];
  const discovery = report.discovery || {};

  container.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
      <h2 class="card-title" style="margin:0;">Security Assessment Report</h2>
      <button class="btn primary" onclick="downloadReportPDF()">Download PDF Report</button>
    </div>

    <!-- KPI CARDS -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px;">
      ${renderKPI("Total Findings", sev.total || 0, "#f8fbff")}
      ${renderKPI("Risk Score", `${sev.risk_score || 0}/100`, riskColor(sev.risk_level))}
      ${renderKPI("Critical", sev.critical || 0, "var(--color-red)")}
      ${renderKPI("High", sev.high || 0, "var(--color-orange)")}
      ${renderKPI("Medium", sev.medium || 0, "var(--color-yellow)")}
      ${renderKPI("Low", sev.low || 0, "var(--color-green)")}
    </div>

    <!-- DISCOVERY INFO -->
    <div style="display:flex;gap:20px;margin-bottom:20px;font-size:13px;color:var(--text-muted);">
      <span>🔗 Target: <strong style="color:var(--text);">${report.target_url || "?"}</strong></span>
      <span>⏱ Duration: <strong style="color:var(--text);">${summary.total_duration_ms ? (summary.total_duration_ms / 1000).toFixed(1) + "s" : "?"}</strong></span>
      <span>🔍 Discovery: ${discovery.tools || 0} tools | ${discovery.resources || 0} resources</span>
    </div>

    <!-- MODULE RESULTS TABLE -->
    <table class="results-table">
      <thead>
        <tr>
          <th>Attack Module</th>
          <th>Severity Status</th>
          <th>Findings</th>
          <th>Execution Time</th>
        </tr>
      </thead>
      <tbody>
        ${modules.map((m) => renderModuleRow(m)).join("")}
      </tbody>
    </table>

    <!-- DETAILED VULNERABILITY ASSESSMENT -->
    <div id="reportFindings" style="margin-top:32px;">
      <h3 style="font-size:18px;font-weight:700;color:#f8fbff;margin-bottom:16px;border-bottom:1px solid rgba(148,163,184,0.1);padding-bottom:8px;">Detailed Vulnerability Assessment</h3>
      ${(() => {
        const allFindings = [];
        // Add Phase 0
        phase0.forEach(f => allFindings.push({ ...f, origin: "Blueprint Analysis (Phase 0)" }));
        // Add Active
        attackResults.forEach(res => {
          (res.findings || []).forEach(f => {
            allFindings.push({ ...f, origin: `${res.attack_id} — ${res.name}` });
          });
        });

        if (allFindings.length === 0) {
          return '<div style="color:var(--text-muted);font-size:14px;padding:30px;text-align:center;background:rgba(2,6,23,0.2);border-radius:var(--radius-md);border:1px dashed rgba(148,163,184,0.2);">No security vulnerabilities identified in this assessment.</div>';
        }

        // Custom sort: Critical > High > Medium > Low > Info
        const severityOrder = { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4 };
        allFindings.sort((a, b) => {
          const sA = (a.severity || "INFO").toString().toUpperCase();
          const sB = (b.severity || "INFO").toString().toUpperCase();
          return (severityOrder[sA] ?? 99) - (severityOrder[sB] ?? 99);
        });

        return allFindings.map(f => `
          <div style="margin-top:24px;">
            <div style="font-size:11px;font-weight:700;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.05em;display:flex;align-items:center;gap:6px;">
              <span style="width:8px;height:8px;border-radius:50%;background:rgba(148,163,184,0.4);"></span>
              Source: ${f.origin}
            </div>
            ${renderFinding(f)}
          </div>
        `).join("");
      })()}
    </div>

    <!-- EXPORT OPTIONS -->
    <div style="margin-top:40px;padding-top:20px;border-top:1px solid rgba(148,163,184,0.1);display:flex;gap:12px;align-items:center;">
      <span style="font-size:13px;color:var(--text-muted);">Export Report:</span>
      <button class="btn primary" onclick="downloadReportPDF()">Download PDF</button>
      <button class="btn secondary" onclick="downloadReportJSON()">JSON Data</button>
      <button class="btn secondary" onclick="downloadReportMarkdown()">Markdown (Docs)</button>
    </div>
  `;

  // Store report globally for export
  window.__currentReport = report;
}

// ══════════════════════════════════════════════════════════════
// HELPER RENDERERS
// ══════════════════════════════════════════════════════════════

function renderKPI(label, value, color) {
  return `
    <div style="background:rgba(2,6,23,0.35);border:1px solid rgba(148,163,184,0.15);border-radius:var(--radius-md);padding:16px;text-align:center;">
      <div style="font-family:var(--font-mono);font-size:1.5rem;font-weight:700;color:${color};">${value}</div>
      <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">${label}</div>
    </div>
  `;
}

function riskColor(level) {
  const colors = {
    critical: "var(--color-red)",
    high: "var(--color-orange)",
    medium: "var(--color-yellow)",
    low: "var(--color-green)",
  };
  return colors[level] || "var(--text-muted)";
}

function renderModuleRow(module) {
  const sev = (module.max_severity || "PASS").toUpperCase();
  const sevValue = sev.toLowerCase();

  const statusBadge =
    module.status === "error"
      ? '<span class="severity-badge severity-medium">ERROR</span>'
      : module.finding_count > 0
      ? `<span class="severity-badge severity-${sevValue}">${sev}</span>`
      : '<span class="severity-badge severity-low">PASS</span>';

  return `
    <tr>
      <td><strong>${module.attack_id}</strong> ${module.name}</td>
      <td>${statusBadge}</td>
      <td>${module.finding_count} finding${module.finding_count !== 1 ? "s" : ""}</td>
      <td style="font-family:var(--font-mono);font-size:12px;">${module.duration_ms}ms</td>
    </tr>
  `;
}

function renderFinding(finding) {
  const sev = (finding.severity || "INFO").toString().toUpperCase();
  const sevValue = sev.includes("CRITICAL") ? "critical" : sev.includes("HIGH") ? "high" : sev.includes("MEDIUM") ? "medium" : "low";

  let evidenceHtml = "";
  if (finding.evidence && finding.evidence.length > 0) {
    evidenceHtml = `
      <details style="margin-top:10px;">
        <summary style="font-size:12px;color:var(--text-muted);cursor:pointer;font-weight:600;padding:4px 0;">View Evidence Data</summary>
        <div style="margin-top:8px;display:flex;flex-direction:column;gap:8px;">
          ${finding.evidence.map(e => `
            <div style="background:rgba(2,6,23,0.5);border:1px solid rgba(148,163,184,0.1);padding:12px;border-radius:var(--radius-sm);font-size:11px;">
              <div style="color:#93c5fd;margin-bottom:6px;font-family:var(--font-mono);font-weight:600;text-transform:uppercase;font-size:10px;">${e.type || 'unknown_type'}</div>
              ${e.request ? `<div><strong style="color:var(--text-muted);">Request:</strong><pre style="margin-top:4px;white-space:pre-wrap;color:var(--text-subtle);background:rgba(0,0,0,0.2);padding:8px;border-radius:4px;">${JSON.stringify(e.request, null, 2)}</pre></div>` : ""}
              ${e.response ? `<div style="margin-top:8px;"><strong style="color:var(--text-muted);">Response:</strong><pre style="margin-top:4px;white-space:pre-wrap;color:var(--text-subtle);background:rgba(0,0,0,0.2);padding:8px;border-radius:4px;">${JSON.stringify(e.response, null, 2)}</pre></div>` : ""}
            </div>
          `).join("")}
        </div>
      </details>
    `;
  }

  return `
    <div style="border:1px solid rgba(148,163,184,0.15);border-radius:var(--radius-md);padding:18px;margin-bottom:12px;background:rgba(15,23,42,0.4);box-shadow:0 4px 12px rgba(0,0,0,0.1);">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
        <span class="severity-badge severity-${sevValue}" style="padding:4px 10px; font-size:11px;">${sevValue.toUpperCase()}</span>
        <strong style="font-size:15px;color:#f8fbff;letter-spacing:-0.01em;">${finding.title || "Untitled Finding"}</strong>
      </div>
      <div style="font-size:14px;color:var(--text-muted);line-height:1.6;margin-bottom:16px;">${finding.description || ""}</div>
      
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">
        ${finding.fixability ? `<div style="font-size:12px;"><strong style="color:var(--text-muted);display:block;margin-bottom:2px;">FIXABILITY</strong> <span style="color:#f8fbff;">${finding.fixability}</span></div>` : ""}
        ${finding.surface ? `<div style="font-size:12px;"><strong style="color:var(--text-muted);display:block;margin-bottom:2px;">SURFACE</strong> <span style="color:#f8fbff;">${finding.surface}</span></div>` : ""}
      </div>
      
      ${finding.fixability_rationale ? `<div style="font-size:13px;color:var(--text-muted);margin-bottom:16px;background:rgba(148,163,184,0.05);padding:10px;border-radius:4px;border-left:3px solid rgba(148,163,184,0.2);"><strong>Rationale:</strong> ${finding.fixability_rationale}</div>` : ""}
      
      ${finding.recommendation ? `
        <div style="margin-top:12px;font-size:13px;color:var(--color-green);background:var(--color-green-bg);padding:12px;border-radius:var(--radius-sm);border:1px solid rgba(34,197,94,0.2);">
          <strong style="display:block;margin-bottom:4px;text-transform:uppercase;font-size:11px;letter-spacing:0.05em;">Fix Recommendation</strong>
          ${finding.recommendation}
        </div>` : ""}
      
      ${finding.attack_narrative ? `
        <details style="margin-top:12px;" open>
          <summary style="font-size:12px;color:var(--text-muted);cursor:pointer;font-weight:600;padding:4px 0;">Exploit Narrative</summary>
          <div style="font-size:13px;color:var(--text-subtle);margin-top:8px;white-space:pre-wrap;background:rgba(2,6,23,0.5);padding:12px;border-radius:var(--radius-sm);border:1px solid rgba(148,163,184,0.1);font-family:var(--font-sans);line-height:1.6;">${finding.attack_narrative}</div>
        </details>` : ""}
        
      ${evidenceHtml}
    </div>
  `;
}

// ══════════════════════════════════════════════════════════════
// EXPORT FUNCTIONS
// ══════════════════════════════════════════════════════════════

function downloadReportJSON() {
  const report = window.__currentReport;
  if (!report) return alert("No report available");

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `mcp-scan-${(report.scan_id || "report").slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadReportMarkdown() {
  const report = window.__currentReport;
  if (!report) return alert("No report available");

  const summary = report.summary || {};
  const sev = summary.severity_breakdown || {};
  const modules = summary.modules_summary || [];

  let md = `# MCP RedTeam Scan Report\n\n`;
  md += `**Target:** ${report.target_url || "?"}\n`;
  md += `**Date:** ${report.completed_at || new Date().toISOString()}\n`;
  md += `**Risk Score:** ${sev.risk_score || 0}/100 (${sev.risk_level || "unknown"})\n\n`;

  md += `## Summary\n\n`;
  md += `| Severity | Count |\n|----------|-------|\n`;
  md += `| Critical | ${sev.critical || 0} |\n`;
  md += `| High | ${sev.high || 0} |\n`;
  md += `| Medium | ${sev.medium || 0} |\n`;
  md += `| Low | ${sev.low || 0} |\n`;
  md += `| **Total** | **${sev.total || 0}** |\n\n`;

  md += `## Module Results\n\n`;
  md += `| Module | Status | Findings | Duration |\n|--------|--------|----------|----------|\n`;
  modules.forEach((m) => {
    md += `| ${m.attack_id} ${m.name} | ${m.status} | ${m.finding_count} | ${m.duration_ms}ms |\n`;
  });

  md += `\n## Detailed Findings\n\n`;

  const phase0 = report.phase0_findings || [];
  if (phase0.length > 0) {
    md += `### Blueprint Analysis (Phase 0)\n\n`;
    phase0.forEach(f => md += renderMarkdownFinding(f));
  }

  (report.attack_results || []).forEach((result) => {
    if (result.findings && result.findings.length > 0) {
      md += `### ${result.attack_id} — ${result.name}\n\n`;
      result.findings.forEach(f => md += renderMarkdownFinding(f));
    }
  });

  function renderMarkdownFinding(f) {
    let block = `#### ${f.title || "Finding"}\n`;
    block += `- **Severity:** ${f.severity || "?"}\n`;
    if (f.surface) block += `- **Surface:** ${f.surface}\n`;
    if (f.fixability) block += `- **Fixability:** ${f.fixability}\n`;
    block += `- **Description:** ${f.description || ""}\n`;
    if (f.fixability_rationale) block += `- **Rationale:** ${f.fixability_rationale}\n`;
    if (f.recommendation) block += `- **Recommendation:** ${f.recommendation}\n`;
    if (f.attack_narrative) block += `\n**Attack Narrative:**\n\`\`\`text\n${f.attack_narrative}\n\`\`\`\n`;
    block += `\n---\n\n`;
    return block;
  }

  const blob = new Blob([md], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `mcp-scan-${(report.scan_id || "report").slice(0, 8)}.md`;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadReportPDF() {
  try {
    const report = window.__currentReport;
    if (!report) return alert("No report available");

    const summary = report.summary || {};
    const sev = summary.severity_breakdown || {};
    const modules = summary.modules_summary || [];
    const phase0 = report.phase0_findings || [];
    const attackResults = report.attack_results || [];

    let html = `
      <div style="padding:30px; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1e293b; background: #fff;">
      <h1 style="color:#0f172a; border-bottom:3px solid #3b82f6; padding-bottom:15px; margin-bottom:20px;">Security Penetration Test Report</h1>
      
      <div style="background:#f8fafc; padding:15px; border-radius:8px; margin-bottom:30px; border:1px solid #e2e8f0;">
        <p style="margin:5px 0;"><strong>Target URL:</strong> ${report.target_url || "Unknown"}</p>
        <p style="margin:5px 0;"><strong>Scan ID:</strong> ${report.scan_id || "N/A"}</p>
        <p style="margin:5px 0;"><strong>Date Generated:</strong> ${new Date().toLocaleString()}</p>
        <p style="margin:5px 0;"><strong>Risk Rating:</strong> <span style="color:#dc2626; font-weight:bold;">${sev.risk_level?.toUpperCase() || "UNKNOWN"}</span> (${sev.risk_score || 0}/100)</p>
      </div>
      
      <h2 style="color:#1e293b; border-bottom:1px solid #cbd5e1; padding-bottom:10px;">1. Executive Summary</h2>
      <p>The following table summarizes the status of all security test modules executed against the target.</p>
      <table style="width:100%; border-collapse:collapse; margin-top:15px;">
        <tr style="background-color:#334155; color:#fff;">
          <th style="padding:10px; border:1px solid #475569; text-align:left;">Attack Module</th>
          <th style="padding:10px; border:1px solid #475569; text-align:center;">Status</th>
          <th style="padding:10px; border:1px solid #475569; text-align:center;">Vulnerabilities</th>
        </tr>
    `;

    modules.forEach(m => {
      const statusColor = m.finding_count > 0 ? "#dc2626" : (m.status === "error" ? "#ca8a04" : "#16a34a");
      const statusText = m.finding_count > 0 ? "VULNERABLE" : (m.status === "error" ? "ERROR" : "PASS");
      
      html += `
        <tr>
          <td style="padding:10px; border:1px solid #e2e8f0;"><strong>${m.attack_id}</strong> ${m.name}</td>
          <td style="padding:10px; border:1px solid #e2e8f0; text-align:center; color:${statusColor}; font-weight:bold;">${statusText}</td>
          <td style="padding:10px; border:1px solid #e2e8f0; text-align:center;">${m.finding_count}</td>
        </tr>
      `;
    });

    html += `</table>`;
    html += `<h2 style="color:#1e293b; margin-top:40px; border-bottom:1px solid #cbd5e1; padding-bottom:10px;">2. Detailed Findings & Evidence</h2>`;

    function escapeHtml(unsafe) {
      if (!unsafe) return "";
      return unsafe.toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    function renderPdfFinding(f) {
      let fHtml = `<div style="margin-top:20px; padding:20px; border:1px solid #e2e8f0; background-color:#fff; page-break-inside:avoid; border-radius:6px; box-shadow:0 2px 4px rgba(0,0,0,0.05);">`;
      fHtml += `<div style="background:#fef2f2; padding:10px; border-left:4px solid #dc2626; margin-bottom:15px;">`;
      fHtml += `<h4 style="margin:0; color:#991b1b; text-transform:uppercase; font-size:12px;">VULNERABILITY IDENTIFIED</h4>`;
      fHtml += `<h3 style="margin:5px 0 0 0; color:#0f172a;">${escapeHtml(f.title || "Untitled Finding")}</h3>`;
      fHtml += `</div>`;
      fHtml += `<p style="font-size:13px; margin:0 0 10px 0;"><strong>Severity:</strong> <span style="color:#dc2626; font-weight:bold;">${escapeHtml(f.severity || "Unknown")}</span></p>`;
      fHtml += `<p style="font-size:13px; line-height:1.6; color:#334155;"><strong>Description:</strong> ${escapeHtml(f.description || "")}</p>`;
      
      if (f.attack_narrative) {
          fHtml += `<h5 style="margin:15px 0 5px 0; font-size:12px; color:#475569;">ATTACK NARRATIVE / EXPLOITATION PATH</h5>`;
          fHtml += `<div style="font-size:12px; background:#f1f5f9; padding:12px; white-space:pre-wrap; border:1px solid #cbd5e1; border-radius:4px; color:#1e293b; line-height:1.5;">${escapeHtml(f.attack_narrative)}</div>`;
      }

      if (f.recommendation) {
          fHtml += `<div style="margin-top:15px; padding:12px; background:#f0fdf4; border:1px solid #bbf7d0; border-radius:4px;">`;
          fHtml += `<strong style="color:#166534; font-size:12px; display:block; margin-bottom:4px;">REMEDIATION GUIDANCE</strong>`;
          fHtml += `<p style="margin:0; font-size:12px; color:#14532d;">${escapeHtml(f.recommendation)}</p>`;
          fHtml += `</div>`;
      }
      fHtml += `</div>`;
      return fHtml;
    }

    const allFindings = [];
    phase0.forEach(f => allFindings.push(f));
    attackResults.forEach(res => (res.findings || []).forEach(f => allFindings.push(f)));

    if (allFindings.length === 0) {
      html += `<p style="color:#16a34a; font-weight:bold; padding:20px; background:#f0fdf4; border:1px solid #bbf7d0; text-align:center; margin-top:20px;">No vulnerabilities were found during this scan.</p>`;
    } else {
      // Sort for PDF as well
      const severityOrder = { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4 };
      allFindings.sort((a, b) => {
        const sA = (a.severity || "INFO").toString().toUpperCase();
        const sB = (b.severity || "INFO").toString().toUpperCase();
        return (severityOrder[sA] ?? 99) - (severityOrder[sB] ?? 99);
      });
      
      allFindings.forEach(f => html += renderPdfFinding(f));
    }

    html += `</div>`;

    const opt = {
      margin: 10,
      filename: `mcp-security-report.pdf`,
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true },
      jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
    };

    html2pdf().set(opt).from(html).save();

  } catch (err) {
    console.error(err);
    alert("Error generating PDF: " + err.message);
  }
}

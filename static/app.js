/**
 * MCP RedTeam Scanner — Core Frontend JavaScript
 *
 * Handles: auth flows, config management, scan execution,
 * real-time polling, results rendering, and scan history.
 *
 * All API calls use credentials:'include' for cookie-based auth.
 */

// ══════════════════════════════════════════════════════════════
// STATE
// ══════════════════════════════════════════════════════════════

const STATE = {
  authenticated: false,
  demoMode: false,
  email: null,
  full_name: null,
  customer_id: null,
  currentRunId: null,
  pollTimer: null,
};

// Attack metadata — pre-loaded with defaults, upgraded from API if available
let ATTACKS = [
  { id: "E1", name: "Weak Authentication", description: "Flags endpoints running without auth", risk: "HIGH" },
  { id: "E3", name: "TLS Origin Validation", description: "Tests HTTPS enforcement", risk: "MEDIUM" },
  { id: "E5", name: "Rate Limit Probe", description: "Tests throttling and DoS protection", risk: "LOW" },
  { id: "MCP", name: "Excessive Permission Scope", description: "Checks for privileged capabilities visible to current identity", risk: "HIGH" },
  { id: "A1", name: "Description Poisoning", description: "Tests for prompt injection in tool descriptions", risk: "CRITICAL" },
  { id: "A2", name: "Schema Manipulation", description: "Tests schema validation strictness", risk: "MEDIUM" },
  { id: "A3", name: "Tool Shadowing", description: "Detects benign names with risky capabilities", risk: "HIGH" },
  { id: "A4", name: "Enumeration Leakage", description: "Tests for excessive tool exposure", risk: "MEDIUM" },
  { id: "B1", name: "Parameter Injection", description: "Injection probes against risky parameters", risk: "MEDIUM" },
  { id: "B2", name: "SSRF Probe", description: "Tests URL parameters with localhost targets", risk: "MEDIUM" },
  { id: "B3", name: "Path Traversal", description: "Directory traversal attacks", risk: "HIGH" },
  { id: "B5", name: "Error Info Disclosure", description: "Tests for debug info in error responses", risk: "MEDIUM" },
  { id: "E2", name: "Auth Wall Break", description: "Tests authorization boundaries", risk: "HIGH" },
  { id: "D1", name: "Sensitive Data Exposure", description: "Scans responses for PII and credentials", risk: "CRITICAL" },
  { id: "D2", name: "API Key & Secret Extraction", description: "Triggers errors to extract API keys and cloud credentials", risk: "CRITICAL" },
];

// ══════════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════════

document.addEventListener("DOMContentLoaded", async () => {
  // Check for demo mode in URL
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('demo') === 'true') {
    STATE.demoMode = true;
  }

  // Render attacks immediately with defaults (no server needed)
  populateAttacks();

  // Then try API calls (will silently fail if no server)
  await checkAccessState();
  await loadAttacks();     // upgrades ATTACKS if API is available
  populateAttacks();       // re-render with API data if upgraded
  
  if (!STATE.authenticated) {
      if (STATE.demoMode) {
          loadDemoReport();
      }
  } else {
      loadRunHistory();
  }
});

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════

async function checkAccessState() {
  try {
    const res = await fetch("/api/access-state", { credentials: "include" });
    const data = await res.json();
    STATE.authenticated = data.authenticated;
    // Keep local demoMode if URL said so, otherwise use server's
    STATE.demoMode = STATE.demoMode || data.demo_mode;
    STATE.email = data.email;
    STATE.full_name = data.full_name;
    STATE.customer_id = data.customer_id;
    updateAuthUI();
  } catch (e) {
    console.error("Failed to check access state:", e);
  }
}

async function loadDemoReport() {
    try {
        const res = await fetch("/api/demo/report");
        if (!res.ok) return;
        const report = await res.json();
        
        // Show the results section
        document.getElementById("scanProgress").style.display = "none";
        document.getElementById("scanResults").style.display = "block";
        
        // Render it
        const container = document.getElementById("scanResults");
        if (typeof renderReport === "function") {
            renderReport(report, container);
            
            // Add a demo badge to the report
            const title = container.querySelector('.card-title');
            if (title) {
                title.innerHTML += ' <span style="font-size:12px;background:var(--accent-soft);color:var(--accent);padding:2px 8px;border-radius:4px;margin-left:10px;vertical-align:middle;">DEMO MODE</span>';
            }

            // Disable export and action buttons in demo mode
            const reportButtons = container.querySelectorAll("button");
            reportButtons.forEach(btn => {
                btn.disabled = true;
                btn.style.opacity = "0.5";
                btn.style.cursor = "not-allowed";
                btn.onclick = (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    alert("This action is disabled in Demo Mode. Please sign in to download or manage reports.");
                    return false;
                };
            });
        }
    } catch (e) {
        console.error("Demo report error:", e);
    }
}

function updateAuthUI() {
  const userEmail = document.querySelector(".user-email");
  const logoutBtn = document.querySelector(".btn-logout");
  const runBtn = document.getElementById("runBtn");
  const historyTab = document.querySelector('.tab[onclick*="history"]');

  const accountCard = document.getElementById("accountAccessCard");
  const accWelcome = document.getElementById("accountWelcome");
  const accEmail = document.getElementById("accountEmailText");
  const accId = document.getElementById("accountCustomerIdText");

  // Hide logout in demo mode
  if (logoutBtn) {
    logoutBtn.style.display = (STATE.authenticated && !STATE.demoMode) ? "block" : "none";
  }

  if (STATE.authenticated && !STATE.demoMode) {
    if (accountCard) {
      accountCard.style.display = "block";
      if (accWelcome) accWelcome.textContent = `Welcome, ${STATE.full_name || "User"}`;
      if (accEmail) accEmail.textContent = STATE.email || "";
      if (accId) accId.textContent = STATE.customer_id || "";
    }
    if (historyTab) historyTab.style.display = "block";
  } else {
    if (accountCard) accountCard.style.display = "none";
    if (historyTab) historyTab.style.display = "none";
  }

  // Disable scan in demo mode for guests
  if (STATE.demoMode) {
    // Disable all inputs and buttons in the scan tab
    const scanTab = document.getElementById("tab-scan");
    if (scanTab) {
        const elements = scanTab.querySelectorAll("input, select, button");
        elements.forEach(el => {
            // Check if element is inside scanResults
            const isResultElement = el.closest("#scanResults");
            if (isResultElement) return;

            el.disabled = true;
            el.style.opacity = "0.6";
            el.style.cursor = "not-allowed";
            // If it's a button, prevent clicks
            if (el.tagName === "BUTTON" && el.id !== "runBtn") {
                el.onclick = (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    alert("This feature is disabled in Demo Mode. Please sign in to run your own scans.");
                    return false;
                };
            }
        });
    }

    if (runBtn) {
        runBtn.disabled = false; // Enable the click but change behavior
        runBtn.style.opacity = "0.7";
        runBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Subscribe to Run Scans';
        runBtn.onclick = (e) => {
            e.preventDefault();
            alert("Sign in or create an account to run your own security scans.");
            window.location.href = "/#signup";
        };
    }
  }
}

async function handleLogin(e) {
  if (e) e.preventDefault();

  const emailInput =
    document.getElementById("loginEmail") ||
    document.querySelector('.auth-form input[type="email"]');
  const passInput =
    document.getElementById("loginPassword") ||
    document.querySelector('.auth-form input[type="password"]');
  const errorEl = document.querySelector(".auth-error");

  if (!emailInput || !passInput) return;

  const email = emailInput.value.trim();
  const password = passInput.value;

  if (!email || !password) {
    showAuthError("Please enter email and password");
    return;
  }

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      const err = await res.json();
      showAuthError(err.detail || "Invalid email or password");
      return;
    }

    const data = await res.json();
    STATE.authenticated = true;
    STATE.email = data.email;
    STATE.demoMode = false;

    // If on landing page, redirect to app
    if (
      window.location.pathname === "/" ||
      window.location.pathname.endsWith("index.html")
    ) {
      window.location.href = "/app";
    } else {
      updateAuthUI();
      await loadRunHistory();
    }
  } catch (e) {
    showAuthError("Connection error. Please try again.");
  }
}

async function handleSignup(e) {
  if (e) e.preventDefault();

  const emailInput =
    document.getElementById("signupEmail") ||
    document.querySelector('.auth-form input[type="email"]');
  const passInput =
    document.getElementById("signupPassword") ||
    document.querySelector('.auth-form input[type="password"]');
  const nameInput = document.getElementById("signupName");

  if (!emailInput || !passInput) return;

  const email = emailInput.value.trim();
  const password = passInput.value;
  const full_name = nameInput ? nameInput.value.trim() : null;

  if (!email || !password) {
    showAuthError("Please enter email and password");
    return;
  }

  if (!full_name) {
    showAuthError("Please enter your full name");
    return;
  }

  if (password.length < 8) {
    showAuthError("Password must be at least 8 characters");
    return;
  }

  try {
    const res = await fetch("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ email, password, full_name }),
    });

    if (!res.ok) {
      const err = await res.json();
      showAuthError(err.detail || "Signup failed");
      return;
    }

    const data = await res.json();
    
    // Switch to Sign In tab
    const tabs = document.querySelectorAll(".auth-tab");
    if (tabs.length > 0) {
      tabs[0].click(); // Click the Sign In tab
    }
    
    // Clear input fields for security
    if (emailInput) emailInput.value = "";
    if (passInput) passInput.value = "";
    if (nameInput) nameInput.value = "";
    
    // Show success message
    const errorEl = document.querySelector(".auth-error");
    if (errorEl) {
      errorEl.textContent = "Account created successfully. Please sign in.";
      errorEl.style.color = "#4ade80"; // Green color for success
      errorEl.classList.add("show");
    }
    
  } catch (e) {
    showAuthError("Connection error. Please try again.");
  }
}

function showAuthError(msg) {
  const errorEl = document.querySelector(".auth-error");
  if (errorEl) {
    errorEl.textContent = msg;
    errorEl.classList.add("show");
    setTimeout(() => errorEl.classList.remove("show"), 5000);
  } else {
    alert(msg);
  }
}

async function handleLogout() {
  try {
    await fetch("/api/logout", { method: "POST", credentials: "include" });
  } catch (e) {}
  window.location.href = "/";
}

// Global logout function (called from HTML onclick)
function logout() {
  handleLogout();
}

// ══════════════════════════════════════════════════════════════
// AUTH TABS (Landing Page)
// ══════════════════════════════════════════════════════════════

function initAuthTabs() {
  const tabs = document.querySelectorAll(".auth-tab");
  const form = document.querySelector(".auth-form");

  if (!tabs.length || !form) return;

  tabs.forEach((tab, idx) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");

      const isSignup = idx === 1;
      const submitBtn = form.querySelector(".auth-submit");
      const nameInput = form.querySelector("#signupName");

      if (submitBtn) {
        submitBtn.textContent = isSignup ? "Create Account" : "Sign In";
        submitBtn.onclick = isSignup ? handleSignup : handleLogin;
      }
      
      if (nameInput) {
        nameInput.style.display = isSignup ? "block" : "none";
        nameInput.required = isSignup;
      }
    });
  });

  // Default: sign-in
  const submitBtn = form.querySelector(".auth-submit");
  if (submitBtn) {
    submitBtn.type = "button";
    submitBtn.onclick = handleLogin;
  }

  // Prevent form default submit
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const activeTab = document.querySelector(".auth-tab.active");
    const isSignup =
      activeTab && activeTab.textContent.trim() === "Create Account";
    if (isSignup) {
      handleSignup(e);
    } else {
      handleLogin(e);
    }
  });

  // Handle CTA click to show auth section
  const ctaButtons = document.querySelectorAll('a[href="#signup"]');
  ctaButtons.forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const authSection = document.getElementById("signup");
      if (authSection) {
        authSection.style.display = "block";
        // Switch to "Create Account" tab
        if (tabs.length > 1) tabs[1].click();
        // Smooth scroll
        authSection.scrollIntoView({ behavior: "smooth", block: "start" });
        // Focus the email input after a short delay
        setTimeout(() => {
          const emailInput = document.querySelector('.auth-form input[type="email"]');
          if (emailInput) emailInput.focus();
        }, 300);
      }
    });
  });
}

// Init auth tabs if on landing page
if (document.querySelector(".auth-tabs")) {
  initAuthTabs();
}

// ══════════════════════════════════════════════════════════════
// ATTACKS
// ══════════════════════════════════════════════════════════════

async function loadAttacks() {
  try {
    const res = await fetch("/api/attacks");
    const data = await res.json();
    ATTACKS = data.attacks || [];
  } catch (e) {
    // Fallback to hardcoded
    ATTACKS = [
      { id: "E1", name: "Weak Authentication", description: "Flags endpoints running without auth", risk: "HIGH" },
      { id: "E3", name: "TLS Origin Validation", description: "Tests HTTPS enforcement", risk: "MEDIUM" },
      { id: "E5", name: "Rate Limit Probe", description: "Tests throttling and DoS protection", risk: "LOW" },
      { id: "A1", name: "Description Poisoning", description: "Tests for prompt injection in tool descriptions", risk: "CRITICAL" },
      { id: "A2", name: "Schema Manipulation", description: "Tests schema validation strictness", risk: "MEDIUM" },
      { id: "A3", name: "Tool Shadowing", description: "Detects benign names with risky capabilities", risk: "HIGH" },
      { id: "A4", name: "Enumeration Leakage", description: "Tests for excessive tool exposure", risk: "MEDIUM" },
      { id: "B1", name: "Parameter Injection", description: "Injection probes against risky parameters", risk: "MEDIUM" },
      { id: "B2", name: "SSRF Probe", description: "Tests URL parameters with localhost targets", risk: "MEDIUM" },
      { id: "B3", name: "Path Traversal", description: "Directory traversal attacks", risk: "HIGH" },
      { id: "B5", name: "Error Info Disclosure", description: "Tests for debug info in error responses", risk: "MEDIUM" },
      { id: "E2", name: "Auth Wall Break", description: "Tests authorization boundaries", risk: "HIGH" },
      { id: "D1", name: "Sensitive Data Exposure", description: "Scans responses for PII and credentials", risk: "CRITICAL" },
    ];
  }
}

function populateAttacks() {
  const grid = document.getElementById("attackGrid");
  if (!grid || !ATTACKS.length) return;

  grid.innerHTML = ATTACKS.map(
    (a) => `
    <label class="attack-checkbox">
      <input type="checkbox" value="${a.id}" checked />
      <div class="attack-info">
        <span class="attack-id">${a.id}</span>
        <div class="attack-name">${a.name}</div>
        <div class="attack-desc">${a.description}</div>
      </div>
    </label>
  `
  ).join("");
}

function selectAllAttacks() {
  document
    .querySelectorAll('#attackGrid input[type="checkbox"]')
    .forEach((cb) => (cb.checked = true));
}

function deselectAllAttacks() {
  document
    .querySelectorAll('#attackGrid input[type="checkbox"]')
    .forEach((cb) => (cb.checked = false));
}

// ══════════════════════════════════════════════════════════════
// SCAN EXECUTION
// ══════════════════════════════════════════════════════════════

async function runScan() {
  const serverUrl = document.getElementById("serverUrl").value.trim();

  if (!serverUrl) {
    alert("Please enter a server URL");
    return;
  }

  const selectedAttacks = Array.from(
    document.querySelectorAll('#attackGrid input[type="checkbox"]:checked')
  ).map((cb) => cb.value);

  if (selectedAttacks.length === 0) {
    alert("Please select at least one attack module");
    return;
  }

  // Get auth settings
  const authType = document.getElementById("authType").value;
  let token = "";
  if (authType === "bearer")
    token = document.getElementById("bearerToken")?.value || "";
  else if (authType === "apikey")
    token = document.getElementById("apiKey")?.value || "";
  else if (authType === "basic") {
    const username = document.getElementById("username")?.value || "";
    const password = document.getElementById("password")?.value || "";
    if (!username || !password) {
      alert("Please enter username and password");
      return;
    }
    token = btoa(`${username}:${password}`);
  }

  // Show progress, disable button
  document.getElementById("scanProgress").style.display = "block";
  document.getElementById("scanResults").style.display = "none";
  document.getElementById("runBtn").disabled = true;

  const progressText = document.getElementById("progressText");
  progressText.textContent = "Queuing scan...";

  try {
    const res = await fetch("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({
        target_url: serverUrl,
        auth_method: authType,
        token: token,
        attacks: selectedAttacks,
      }),
    });

    if (!res.ok) {
      const err = await res.json();
      alert(err.detail || "Failed to start scan");
      document.getElementById("runBtn").disabled = false;
      document.getElementById("scanProgress").style.display = "none";
      return;
    }

    const data = await res.json();
    STATE.currentRunId = data.run_id;

    progressText.textContent = "Scan queued. Waiting for worker...";

    // Start polling
    pollRunStatus(data.run_id);
  } catch (e) {
    alert("Failed to connect to API. Is the server running?");
    document.getElementById("runBtn").disabled = false;
    document.getElementById("scanProgress").style.display = "none";
  }
}

function pollRunStatus(runId) {
  if (STATE.pollTimer) clearInterval(STATE.pollTimer);

  STATE.pollTimer = setInterval(async () => {
    try {
      const res = await fetch(`/api/runs/${runId}`, {
        credentials: "include",
      });
      if (!res.ok) return;

      const run = await res.json();
      const progressText = document.getElementById("progressText");
      const progressDetails = document.getElementById("progressDetails");

      if (run.status === "running" && run.progress) {
        const p = typeof run.progress === 'string' ? JSON.parse(run.progress) : run.progress;
        progressText.textContent = `Running: ${p.current_module || "..."}`;
        progressDetails.innerHTML = `
          <div style="font-size:13px;color:var(--text-muted);margin-top:8px;">
            Phase: ${p.phase || "..."}<br/>
            Progress: ${p.modules_done || 0} / ${p.modules_total || "?"} modules
          </div>
        `;
      } else if (run.status === "completed") {
        clearInterval(STATE.pollTimer);
        STATE.pollTimer = null;
        progressText.textContent = "Scan completed!";
        document.getElementById("runBtn").disabled = false;
        await showCompletedResults(runId);
        loadRunHistory();
      } else if (run.status === "failed") {
        clearInterval(STATE.pollTimer);
        STATE.pollTimer = null;
        progressText.textContent = `Scan failed: ${run.error_message || "Unknown error"}`;
        document.getElementById("runBtn").disabled = false;
        document.getElementById("scanProgress").querySelector(".scan-status").className = "scan-status failed";
        document.getElementById("scanProgress").querySelector(".scan-status").innerHTML =
          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Failed';
      } else if (run.status === "queued") {
        progressText.textContent = "Waiting for worker to pick up scan...";
      }
    } catch (e) {
      console.error("Poll error:", e);
    }
  }, 2000);
}

async function showCompletedResults(runId) {
  try {
    const res = await fetch(`/api/runs/${runId}/report`, {
      credentials: "include",
    });
    if (!res.ok) return;

    const report = await res.json();

    document.getElementById("scanProgress").style.display = "none";
    document.getElementById("scanResults").style.display = "block";

    const container = document.getElementById("scanResults");
    if (typeof renderReport === "function") {
        renderReport(report, container);
    } else {
        renderBasicResults(report);
    }
  } catch (e) {
    console.error("Failed to load report:", e);
  }
}

function renderBasicResults(report) {
  const summary = report.summary || {};
  const breakdown = summary.severity_breakdown || {};
  const modules = summary.modules_summary || [];

  const resultsText = document.getElementById("resultsText");
  if (resultsText) {
    resultsText.textContent = `Found ${breakdown.total || 0} vulnerabilities | Risk Score: ${breakdown.risk_score || 0}/100`;
  }

  const tbody = document.getElementById("resultsBody");
  if (tbody) {
    tbody.innerHTML = modules
      .map(
        (m) => {
          const sev = m.max_severity || (m.finding_count > 0 ? 'VULNERABLE' : (m.status === 'error' ? 'ERROR' : 'PASS'));
          const sevClass = (m.max_severity || (m.finding_count > 0 ? 'high' : (m.status === 'error' ? 'medium' : 'low'))).toLowerCase();
          
          return `
            <tr>
              <td><strong>${m.attack_id}</strong> ${m.name}</td>
              <td><span class="severity-badge severity-${sevClass}">${sev}</span></td>
              <td>${m.status}</td>
              <td>${m.finding_count} finding${m.finding_count !== 1 ? "s" : ""}</td>
            </tr>
          `;
        }
      )
      .join("");
  }
}

// ══════════════════════════════════════════════════════════════
// SCAN HISTORY
// ══════════════════════════════════════════════════════════════

async function loadRunHistory() {
  if (!STATE.authenticated) return;

  const historyList = document.getElementById("historyList");
  if (!historyList) return;

  try {
    const res = await fetch("/api/runs", { credentials: "include" });
    if (!res.ok) return;

    const data = await res.json();
    const runs = data.runs || [];

    if (runs.length === 0) {
      historyList.innerHTML =
        '<div style="text-align:center;padding:40px;color:var(--text-muted);">No scan history yet. Run your first scan!</div>';
      return;
    }

    historyList.innerHTML = runs
      .map(
        (run) => `
      <div class="history-item">
        <div class="history-header">
          <div class="history-url">${run.target_url || "Unknown"}</div>
          <span class="scan-status ${run.status}">${run.status === "completed"
            ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>'
            : run.status === "running"
            ? '<span class="pulse"></span>'
            : ""
          } ${run.status}</span>
        </div>
        <div class="history-meta">
          <span>${new Date(run.created_at).toLocaleString()}</span>
          <span>${(typeof run.attacks_selected === 'string' ? JSON.parse(run.attacks_selected) : (run.attacks_selected || [])).length} attacks</span>
        </div>
        <div class="history-actions">
          ${run.status === "completed"
            ? `<button class="btn" style="padding:6px 12px;font-size:12px;" onclick="viewRunReport('${run.id}')">View Report</button>`
            : ""
          }
          ${run.status === "running" || run.status === "queued"
            ? `<button class="btn" style="padding:6px 12px;font-size:12px;" onclick="abortScan('${run.id}')">Abort</button>`
            : ""
          }
        </div>
      </div>
    `
      )
      .join("");
  } catch (e) {
    console.error("Failed to load history:", e);
  }
}

async function viewRunReport(runId) {
  try {
    const res = await fetch(`/api/runs/${runId}/report`, {
      credentials: "include",
    });
    if (!res.ok) {
      alert("Failed to load report");
      return;
    }

    const report = await res.json();

    // Switch to scan tab and show results
    showTab("scan");
    document.getElementById("scanProgress").style.display = "none";
    document.getElementById("scanResults").style.display = "block";

    if (typeof renderReport === "function") {
      renderReport(report, document.getElementById("scanResults"));
    } else {
      renderBasicResults(report);
    }
  } catch (e) {
    alert("Failed to load report");
  }
}

async function abortScan(runId) {
  if (!confirm("Are you sure you want to abort this scan?")) return;

  try {
    await fetch(`/api/runs/${runId}/abort`, {
      method: "POST",
      credentials: "include",
    });
    loadRunHistory();
  } catch (e) {
    alert("Failed to abort scan");
  }
}

// ══════════════════════════════════════════════════════════════
// UI HELPERS
// ══════════════════════════════════════════════════════════════

function showTab(tabName) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
  document
    .querySelectorAll(".tab-content")
    .forEach((c) => (c.style.display = "none"));

  // Find the clicked tab
  document.querySelectorAll(".tab").forEach((t) => {
    if (
      t.textContent.toLowerCase().includes(tabName) ||
      t.onclick?.toString().includes(tabName)
    ) {
      t.classList.add("active");
    }
  });

  const tabEl = document.getElementById("tab-" + tabName);
  if (tabEl) tabEl.style.display = "block";

  if (tabName === "history") loadRunHistory();
}

function toggleAuthFields() {
  const authType = document.getElementById("authType").value;
  const authFields = document.getElementById("authFields");
  const bearerField = document.getElementById("bearerField");
  const apikeyField = document.getElementById("apikeyField");
  const basicFields = document.getElementById("basicFields");

  if (authFields) authFields.style.display = authType === "none" ? "none" : "block";
  if (bearerField) bearerField.style.display = authType === "bearer" ? "block" : "none";
  if (apikeyField) apikeyField.style.display = authType === "apikey" ? "block" : "none";
  if (basicFields) basicFields.style.display = authType === "basic" ? "block" : "none";
}

function resetForm() {
  document.getElementById("serverUrl").value = "";
  document.getElementById("authType").value = "none";
  toggleAuthFields();
  selectAllAttacks();
  document.getElementById("scanProgress").style.display = "none";
  document.getElementById("scanResults").style.display = "none";
}

function viewFindingDetails(attackId) {
  // Instead of an alert, show the full report and scroll to the module
  if (STATE.currentRunId) {
    viewRunReport(STATE.currentRunId).then(() => {
      setTimeout(() => {
        const row = document.getElementById(`findings-${attackId}`);
        if (row) {
          row.scrollIntoView({ behavior: 'smooth', block: 'center' });
          if (row.style.display === "none") {
            toggleModuleFindings(attackId);
          }
        }
      }, 100);
    });
  }
}

function downloadReport() {
  if (!STATE.currentRunId) {
    alert("No report to download");
    return;
  }

  fetch(`/api/runs/${STATE.currentRunId}/report`, { credentials: "include" })
    .then((r) => r.json())
    .then((report) => {
      const blob = new Blob([JSON.stringify(report, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `mcp-redteam-report-${STATE.currentRunId.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    })
    .catch(() => alert("Failed to download report"));
}

function viewDetailedReport() {
  if (STATE.currentRunId) {
    viewRunReport(STATE.currentRunId);
  }
}

/* ============================================================
   Velbrix - Frontend Application
   ============================================================ */

const API = {
  async get(url) {
    const resp = await fetch(url);
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      throw new Error(err.detail || "Request failed");
    }
    return resp.json();
  },
  async post(url, body) {
    const resp = await fetch(url, {
      method: "POST",
      headers: body instanceof FormData ? {} : { "Content-Type": "application/json" },
      body: body instanceof FormData ? body : JSON.stringify(body),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      throw new Error(err.detail || "Request failed");
    }
    return resp.json();
  },
};

const state = {
  currentView: "upload",
  scanId: null,
  scanResults: null,
  currentFinding: null,
  currentPatch: null,
  aiStatus: null,
};

// ============================================================
// Navigation
// ============================================================
function navigateTo(view) {
  state.currentView = view;
  document.querySelectorAll(".nav-item").forEach(el => {
    el.classList.toggle("active", el.dataset.view === view);
  });
  renderView(view);
}

document.addEventListener("DOMContentLoaded", () => {
  // Nav click handlers
  document.querySelectorAll(".nav-item").forEach(el => {
    el.addEventListener("click", () => navigateTo(el.dataset.view));
  });

  // Load AI status
  loadAIStatus();

  // Render initial view
  renderView("upload");
});

async function loadAIStatus() {
  try {
    const status = await API.get("/api/ai/status");
    state.aiStatus = status;
    document.getElementById("aiEngine").textContent = status.active_provider;
    document.getElementById("aiNote").textContent = status.note;
  } catch (e) {
    document.getElementById("aiEngine").textContent = "Local heuristic mode";
  }
}

// ============================================================
// View Rendering
// ============================================================
function renderView(view) {
  const container = document.getElementById("mainContent");
  switch (view) {
    case "upload": renderUpload(container); break;
    case "dashboard": renderDashboard(container); break;
    case "finding": renderFindingDetail(container); break;
    case "fixme": renderFixMe(container); break;
    case "agentguard": renderAgentGuard(container); break;
    case "sessionguard": renderSessionGuard(container); break;
    case "report": renderReport(container); break;
  }
}

// ============================================================
// View 1: Upload
// ============================================================
function renderUpload(container) {
  container.innerHTML = `
    <div class="view active">
      <div class="view-header">
        <div class="view-title">Upload Project</div>
        <div class="view-subtitle">Upload a ZIP file or load the authorized VibeBank demo project to begin scanning.</div>
      </div>

      <div class="card">
        <div class="upload-zone" id="uploadZone">
          <div class="upload-icon">[ZIP]</div>
          <div class="upload-title">Drop ZIP file here or click to browse</div>
          <div class="upload-desc">Only .zip files are supported. The project is extracted to an isolated workspace.</div>
          <input type="file" id="fileInput" accept=".zip" style="display:none">
          <button class="btn btn-primary" onclick="document.getElementById('fileInput').click()">Choose ZIP File</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Or Load Demo Project</div>
        <p style="color:var(--text-secondary); margin: 12px 0 20px; font-size:14px;">
          Load the bundled <strong>VibeBank</strong> demo project — a deliberately vulnerable app for testing Velbrix.
        </p>
        <button class="btn btn-secondary" onclick="loadDemo()">Load VibeBank Demo Project</button>
      </div>

      <div id="uploadStatus"></div>
    </div>
  `;

  const zone = document.getElementById("uploadZone");
  const input = document.getElementById("fileInput");

  zone.addEventListener("click", (e) => {
    if (e.target.tagName !== "BUTTON") input.click();
  });

  input.addEventListener("change", (e) => {
    if (e.target.files[0]) uploadFile(e.target.files[0]);
  });

  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("dragover"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("dragover");
    if (e.dataTransfer.files[0]) uploadFile(e.dataTransfer.files[0]);
  });
}

async function uploadFile(file) {
  const statusDiv = document.getElementById("uploadStatus");
  statusDiv.innerHTML = `
    <div class="card">
      <div style="display:flex; align-items:center; gap:12px;">
        <div class="spinner"></div>
        <div>Uploading <strong>${file.name}</strong>...</div>
      </div>
    </div>
  `;

  try {
    const formData = new FormData();
    formData.append("file", file);
    const result = await API.post("/api/upload", formData);

    statusDiv.innerHTML = `
      <div class="card">
        <div class="card-title">Upload Successful</div>
        <div style="margin: 16px 0;">
          <div style="display:flex; gap:24px; flex-wrap:wrap;">
            <div><span style="color:var(--text-muted)">Project:</span> <strong>${result.project_name}</strong></div>
            <div><span style="color:var(--text-muted)">Files:</span> <strong>${result.file_count}</strong></div>
            <div><span style="color:var(--text-muted)">Stack:</span> <strong>${result.stack}</strong></div>
            <div><span style="color:var(--text-muted)">Scan ID:</span> <strong>${result.scan_id}</strong></div>
          </div>
        </div>
        <button class="btn btn-primary" onclick="startScan('${result.scan_id}')">Start Scan</button>
      </div>
    `;
    state.scanId = result.scan_id;
  } catch (e) {
    statusDiv.innerHTML = `<div class="card"><div style="color:var(--critical)">Error: ${e.message}</div></div>`;
  }
}

async function loadDemo() {
  const statusDiv = document.getElementById("uploadStatus");
  statusDiv.innerHTML = `
    <div class="card">
      <div style="display:flex; align-items:center; gap:12px;">
        <div class="spinner"></div>
        <div>Loading VibeBank demo project...</div>
      </div>
    </div>
  `;

  try {
    const result = await API.post("/api/upload/demo", {});
    state.scanId = result.scan_id;
    statusDiv.innerHTML = `
      <div class="card">
        <div class="card-title">VibeBank Demo Loaded</div>
        <div style="margin: 16px 0;">
          <div style="display:flex; gap:24px; flex-wrap:wrap;">
            <div><span style="color:var(--text-muted)">Project:</span> <strong>${result.project_name}</strong></div>
            <div><span style="color:var(--text-muted)">Files:</span> <strong>${result.file_count}</strong></div>
            <div><span style="color:var(--text-muted)">Stack:</span> <strong>${result.stack}</strong></div>
            <div><span style="color:var(--text-muted)">Scan ID:</span> <strong>${result.scan_id}</strong></div>
          </div>
        </div>
        <button class="btn btn-primary" onclick="startScan('${result.scan_id}')">Start Scan</button>
      </div>
    `;
  } catch (e) {
    statusDiv.innerHTML = `<div class="card"><div style="color:var(--critical)">Error: ${e.message}</div></div>`;
  }
}

async function startScan(scanId) {
  state.scanId = scanId;
  navigateTo("dashboard");
  try {
    await API.post(`/api/scan/${scanId}/start`, {});
    pollScanStatus(scanId);
  } catch (e) {
    document.getElementById("mainContent").innerHTML = `<div class="card">Error: ${e.message}</div>`;
  }
}

// ============================================================
// View 2: Dashboard
// ============================================================
async function pollScanStatus(scanId) {
  const poll = async () => {
    try {
      const status = await API.get(`/api/scan/${scanId}/status`);
      renderScanProgress(scanId, status);
      if (status.status === "scanning") {
        setTimeout(poll, 1000);
      } else if (status.status === "completed") {
        loadDashboard(scanId);
      } else if (status.status === "error") {
        document.getElementById("mainContent").innerHTML = `<div class="card">Scan error: ${status.error || "Unknown"}</div>`;
      }
    } catch (e) {
      console.error("Poll error:", e);
    }
  };
  poll();
}

function renderScanProgress(scanId, status) {
  const container = document.getElementById("mainContent");
  container.innerHTML = `
    <div class="view active">
      <div class="view-header">
        <div class="view-title">ShipScan In Progress</div>
        <div class="view-subtitle">Running multi-layer security analysis on your project...</div>
      </div>

      <div class="card">
        <div class="progress-container">
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${status.progress}%"></div>
          </div>
          <div class="progress-text">
            <span class="spinner"></span>
            <strong>${status.current_scanner || "Processing..."}</strong> — ${status.progress}%
          </div>
        </div>

        <div style="margin-top: 24px; font-size: 13px; color: var(--text-secondary);">
          <div style="margin-bottom: 8px;">Scan pipeline:</div>
          <ul style="list-style:none; padding-left:0;">
            <li style="padding:4px 0;">${status.progress > 15 ? "[OK]" : "[...]"} Secret Scanner (regex-based, Gitleaks-style)</li>
            <li style="padding:4px 0;">${status.progress > 35 ? "[OK]" : "[...]"} Code Security Scanner (injection, XSS, eval, shell)</li>
            <li style="padding:4px 0;">${status.progress > 55 ? "[OK]" : "[...]"} Dependency Scanner (CVE database + pip-audit)</li>
            <li style="padding:4px 0;">${status.progress > 70 ? "[OK]" : "[...]"} Prompt Injection Scanner (README, comments, agent files)</li>
            <li style="padding:4px 0;">${status.progress > 85 ? "[OK]" : "[...]"} Deploy Readiness Scanner (config, tests, CI/CD)</li>
            <li style="padding:4px 0;">${status.progress > 95 ? "[OK]" : "[...]"} Bandit (Python AST analysis, if available)</li>
          </ul>
        </div>
      </div>
    </div>
  `;
}

async function loadDashboard(scanId) {
  try {
    const results = await API.get(`/api/scan/${scanId}/results`);
    state.scanResults = results;
    renderDashboard(document.getElementById("mainContent"));
  } catch (e) {
    document.getElementById("mainContent").innerHTML = `<div class="card">Error: ${e.message}</div>`;
  }
}

function renderDashboard(container) {
  const r = state.scanResults;
  if (!r) {
    container.innerHTML = `
      <div class="view active">
        <div class="view-header">
          <div class="view-title">ShipScan Dashboard</div>
          <div class="view-subtitle">Run a scan to see results here.</div>
        </div>
        <div class="empty-state">
          <div class="empty-state-icon">[SCAN]</div>
          <div>No scan results yet. Upload a project to begin.</div>
          <button class="btn btn-primary" style="margin-top:20px;" onclick="navigateTo('upload')">Go to Upload</button>
        </div>
      </div>
    `;
    return;
  }

  const scoreClass = r.overall_score < 50 ? "score-critical" : r.overall_score < 75 ? "score-high" : "score-low";
  const sevCounts = r.counts;

  container.innerHTML = `
    <div class="view active">
      <div class="view-header">
        <div class="view-title">ShipScan Dashboard</div>
        <div class="view-subtitle">Project: ${r.project_name} | Stack: ${r.stack} | ${r.file_count} files scanned</div>
      </div>

      <!-- Score Overview -->
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-number ${scoreClass}">${r.overall_score}</div>
          <div class="stat-label">Security Score / 100</div>
          <div class="decision-badge decision-${r.decision}">${r.decision}</div>
        </div>
        <div class="stat-card">
          <div class="stat-number" style="color:var(--critical)">${sevCounts.Critical || 0}</div>
          <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
          <div class="stat-number" style="color:var(--high)">${sevCounts.High || 0}</div>
          <div class="stat-label">High</div>
        </div>
        <div class="stat-card">
          <div class="stat-number" style="color:var(--medium)">${sevCounts.Medium || 0}</div>
          <div class="stat-label">Medium</div>
        </div>
        <div class="stat-card">
          <div class="stat-number" style="color:var(--low)">${sevCounts.Low || 0}</div>
          <div class="stat-label">Low</div>
        </div>
      </div>

      <!-- Category Scores -->
      <div class="card">
        <div class="card-title">Category Scores</div>
        <div style="margin-top: 16px;">
          ${Object.entries(r.category_scores).map(([cat, score]) => {
            const color = score < 50 ? "var(--critical)" : score < 75 ? "var(--high)" : "var(--low)";
            return `
              <div class="category-score-row">
                <div class="category-name">${cat}</div>
                <div class="category-bar-container">
                  <div class="category-bar-fill" style="width: ${score}%; background: ${color};"></div>
                </div>
                <div class="category-score-value" style="color:${color}">${score}</div>
              </div>
            `;
          }).join("")}
        </div>
      </div>

      <!-- Filters -->
      <div class="card">
        <div class="filter-bar">
          <select class="filter-select" id="severityFilter" onchange="applyFilters()">
            <option value="all">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
          </select>
          <select class="filter-select" id="categoryFilter" onchange="applyFilters()">
            <option value="all">All Categories</option>
            ${[...new Set(r.findings.map(f => f.category))].map(c => `<option value="${c}">${c}</option>`).join("")}
          </select>
          <input type="text" class="filter-input" id="searchFilter" placeholder="Search findings..." oninput="applyFilters()">
          <div style="color:var(--text-muted); font-size:13px;">
            ${r.patched_count > 0 ? `${r.patched_count} patched | ` : ""}${r.total_findings} total
          </div>
        </div>

        <!-- Findings Table -->
        <table class="findings-table" id="findingsTable">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Title</th>
              <th>Category</th>
              <th>File</th>
              <th>Line</th>
              <th>Scanner</th>
            </tr>
          </thead>
          <tbody>
            ${r.findings.map(f => `
              <tr onclick="viewFinding('${f.id}')">
                <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
                <td class="finding-title">${f.title}${f.patched ? ' <span style="color:var(--low);font-size:11px;">[PATCHED]</span>' : ""}</td>
                <td>${f.category}</td>
                <td class="finding-file">${f.file}</td>
                <td>${f.line}</td>
                <td><span style="font-size:11px; color:var(--text-muted);">${f.scanner_source}</span></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function applyFilters() {
  const sev = document.getElementById("severityFilter").value;
  const cat = document.getElementById("categoryFilter").value;
  const search = document.getElementById("searchFilter").value.toLowerCase();

  const rows = document.querySelectorAll("#findingsTable tbody tr");
  rows.forEach(row => {
    const sevText = row.cells[0].textContent.trim();
    const titleText = row.cells[1].textContent.toLowerCase();
    const catText = row.cells[2].textContent;
    const fileText = row.cells[3].textContent.toLowerCase();

    const sevMatch = sev === "all" || sevText.includes(sev);
    const catMatch = cat === "all" || catText === cat;
    const searchMatch = !search || titleText.includes(search) || fileText.includes(search);

    row.style.display = (sevMatch && catMatch && searchMatch) ? "" : "none";
  });
}

// ============================================================
// View 3: Finding Details
// ============================================================
async function viewFinding(findingId) {
  state.currentFinding = findingId;
  navigateTo("finding");
}

async function renderFindingDetail(container) {
  if (!state.currentFinding) {
    container.innerHTML = `<div class="card">No finding selected. Go to Dashboard.</div>`;
    return;
  }

  container.innerHTML = `<div class="card"><div class="spinner"></div> Loading finding...</div>`;

  try {
    const f = await API.get(`/api/scan/${state.scanId}/findings/${state.currentFinding}`);

    container.innerHTML = `
      <div class="view active">
        <div class="view-header">
          <div class="view-title">${f.title}</div>
          <div class="view-subtitle">
            <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
            <span style="margin-left:12px;">${f.category}</span>
            <span style="margin-left:12px; color:var(--blue); font-family:monospace;">${f.file}:${f.line}</span>
          </div>
        </div>

        <div style="margin-bottom: 20px;">
          <button class="btn btn-secondary" onclick="navigateTo('dashboard')">Back to Dashboard</button>
          <button class="btn btn-primary" onclick="goToFixMe('${f.id}')">Fix in FixMe Space</button>
        </div>

        <div class="card">
          <div class="card-title">What It Is</div>
          <p style="margin-top:12px; line-height:1.6;">${f.description}</p>
        </div>

        <div class="card">
          <div class="card-title">Why It Matters</div>
          <p style="margin-top:12px; line-height:1.6;">${f.why_it_matters}</p>
        </div>

        <div class="card">
          <div class="card-title">Evidence</div>
          <div class="code-block" style="margin-top:12px;">${f.evidence}</div>
        </div>

        <div class="card">
          <div class="card-title">Code Context</div>
          <div class="code-block" style="margin-top:12px;">
            ${f.context_lines.map(l => `
              <div class="code-line ${l.is_finding ? "line-finding" : ""}">
                <span class="line-num">${l.line_number}</span>
                <span class="line-content">${escapeHtml(l.content)}</span>
              </div>
            `).join("")}
          </div>
        </div>

        <div class="card">
          <div class="card-title">Recommended Fix</div>
          <p style="margin-top:12px; line-height:1.6;">${f.recommended_fix}</p>
          <div style="margin-top:12px; font-size:12px; color:var(--text-muted);">
            Detected by: ${f.scanner_source} | Confidence: ${(f.confidence * 100).toFixed(0)}%
          </div>
        </div>
      </div>
    `;
  } catch (e) {
    container.innerHTML = `<div class="card">Error: ${e.message}</div>`;
  }
}

function goToFixMe(findingId) {
  state.currentFinding = findingId;
  navigateTo("fixme");
  renderFixMe(document.getElementById("mainContent"));
}

// ============================================================
// View 4: FixMe Space
// ============================================================
async function renderFixMe(container) {
  if (!state.scanId) {
    container.innerHTML = `<div class="card">No scan loaded. Go to Upload.</div>`;
    return;
  }

  if (!state.scanResults) {
    try {
      state.scanResults = await API.get(`/api/scan/${state.scanId}/results`);
    } catch (e) {
      container.innerHTML = `<div class="card">Error: ${e.message}</div>`;
      return;
    }
  }

  const findings = state.scanResults.findings;

  container.innerHTML = `
    <div class="view active">
      <div class="view-header">
        <div class="view-title">FixMe Space</div>
        <div class="view-subtitle">AI-powered secure patch generation, verification, and human approval.</div>
      </div>

      <div class="card">
        <div class="card-title">Select a Finding to Fix</div>
        <div style="margin-top:12px;">
          <select class="filter-select" id="fixFindingSelect" style="width:100%; padding:12px;">
            ${findings.map(f => `<option value="${f.id}">[${f.severity}] ${f.title} — ${f.file}:${f.line}</option>`).join("")}
          </select>
        </div>
        <button class="btn btn-primary" style="margin-top:16px;" onclick="generatePatch()">Generate Secure Patch</button>
      </div>

      <div id="patchResult"></div>
      <div id="verificationResult"></div>

      <!-- Before/After Comparison -->
      <div class="card">
        <div class="card-title">Before / After Comparison</div>
        <div id="beforeAfter" style="margin-top:12px;">
          <div style="color:var(--text-muted); font-size:13px;">Generate and verify a patch to see the comparison.</div>
        </div>
      </div>
    </div>
  `;

  // If a finding was pre-selected, set the dropdown
  if (state.currentFinding) {
    document.getElementById("fixFindingSelect").value = state.currentFinding;
  }

  // Load existing before/after
  loadBeforeAfter();
}

async function generatePatch() {
  const findingId = document.getElementById("fixFindingSelect").value;
  if (!findingId) return;

  const resultDiv = document.getElementById("patchResult");

  // Show AI provider in status
  const aiProvider = state.aiStatus?.active_provider || "AI";
  resultDiv.innerHTML = `
    <div class="card">
      <div style="display:flex; align-items:center; gap:12px;">
        <div class="spinner"></div>
        <div>Generating secure patch using <strong style="color:var(--accent)">${aiProvider}</strong>...</div>
      </div>
      <div style="margin-top:8px; font-size:12px; color:var(--text-muted);">
        Secret values are redacted before AI processing.
      </div>
    </div>
  `;

  try {
    const result = await API.post(`/api/fixme/${state.scanId}/generate/${findingId}`, {});
    state.currentPatch = result.patch_id;

    resultDiv.innerHTML = `
      <div class="card">
        <div class="card-title">Patch Generated</div>
        <div style="margin: 12px 0; display:flex; gap:12px; align-items:center;">
          <span class="badge badge-low">${result.provider}</span>
          <span style="font-size:13px; color:var(--text-secondary);">${result.status}</span>
        </div>

        <div style="margin: 16px 0; padding:12px; background:var(--bg-elev); border-radius:8px;">
          <strong style="color:var(--accent);">Explanation:</strong> ${result.explanation}
        </div>

        <div class="diff-container">
          <div class="diff-panel diff-before">
            <div class="diff-header">Before (Vulnerable)</div>
            <div class="diff-content">${escapeHtml(result.before)}</div>
          </div>
          <div class="diff-panel diff-after">
            <div class="diff-header">After (Fixed)</div>
            <div class="diff-content">${escapeHtml(result.after)}</div>
          </div>
        </div>

        <div style="margin-top:16px;">
          <button class="btn btn-primary" onclick="verifyPatch('${result.patch_id}')">
            Apply to Temp Copy & Verify
          </button>
        </div>
      </div>
    `;
  } catch (e) {
    resultDiv.innerHTML = `<div class="card">Error: ${e.message}</div>`;
  }
}

async function verifyPatch(patchId) {
  const verDiv = document.getElementById("verificationResult");
  verDiv.innerHTML = `
    <div class="card">
      <div style="display:flex; align-items:center; gap:12px;">
        <div class="spinner"></div>
        <div>Applying patch to isolated temp copy and running verification...</div>
      </div>
    </div>
  `;

  try {
    const result = await API.post(`/api/fixme/${state.scanId}/verify/${patchId}`, {});
    const v = result.verification;

    const statusColor = v.status === "passed" ? "var(--low)" : v.status === "partial" ? "var(--high)" : "var(--critical)";

    verDiv.innerHTML = `
      <div class="card">
        <div class="card-title">Verification Results</div>
        <div style="margin: 16px 0;">
          <div style="font-size: 24px; font-weight: 700; color: ${statusColor}; text-transform: uppercase;">${v.status}</div>
        </div>
        <table class="findings-table" style="margin-top:12px;">
          <tr><td>Original finding resolved:</td><td><strong style="color:${v.original_finding_resolved ? "var(--low)" : "var(--critical)"}">${v.original_finding_resolved ? "YES" : "NO"}</strong></td></tr>
          <tr><td>New findings introduced:</td><td><strong>${v.new_findings_introduced}</strong></td></tr>
          <tr><td>Syntax valid:</td><td><strong style="color:${v.syntax_valid ? "var(--low)" : "var(--critical)"}">${v.syntax_valid ? "YES" : "NO"}</strong></td></tr>
          <tr><td>Rescan findings count:</td><td>${v.rescan_findings_count}</td></tr>
          <tr><td>Patched file:</td><td style="font-family:monospace; color:var(--blue);">${v.patched_file}</td></tr>
        </table>

        <div style="margin-top: 20px; display:flex; gap:12px;">
          <button class="btn btn-success" onclick="approvePatch('${patchId}', true)">Approve Patch</button>
          <button class="btn btn-danger" onclick="approvePatch('${patchId}', false)">Reject</button>
          <button class="btn btn-secondary" onclick="rollbackPatch('${patchId}')">Rollback</button>
        </div>

        <div style="margin-top:16px; padding:12px; background:var(--bg-elev); border-radius:8px; font-size:12px; color:var(--text-muted);">
          Note: Patch is applied only to an isolated temporary copy. The original project is never modified without explicit export/approval.
        </div>
      </div>
    `;

    loadBeforeAfter();
  } catch (e) {
    verDiv.innerHTML = `<div class="card">Error: ${e.message}</div>`;
  }
}

async function approvePatch(patchId, approved) {
  try {
    await API.post(`/api/fixme/${state.scanId}/approve/${patchId}`, { approved });
    showToast(approved ? "Patch approved!" : "Patch rejected.");
    loadBeforeAfter();
  } catch (e) {
    showToast("Error: " + e.message);
  }
}

async function rollbackPatch(patchId) {
  try {
    await API.post(`/api/fixme/${state.scanId}/rollback/${patchId}`, {});
    showToast("Patch rolled back. Temp copy removed.");
    loadBeforeAfter();
  } catch (e) {
    showToast("Error: " + e.message);
  }
}

async function loadBeforeAfter() {
  const div = document.getElementById("beforeAfter");
  if (!div) return;
  try {
    const comp = await API.get(`/api/fixme/${state.scanId}/before-after`);
    div.innerHTML = `
      <div class="comparison-grid">
        <div class="comparison-panel comparison-before">
          <div class="comparison-label">Before</div>
          <div class="comparison-stat"><span>Score</span><strong style="color:var(--critical)">${comp.before.score}/100</strong></div>
          <div class="comparison-stat"><span>Decision</span><strong class="decision-${comp.before.decision}" style="padding:2px 8px; border-radius:4px; font-size:12px;">${comp.before.decision}</strong></div>
          <div class="comparison-stat"><span>Critical</span><strong>${comp.before.critical}</strong></div>
          <div class="comparison-stat"><span>High</span><strong>${comp.before.high}</strong></div>
          <div class="comparison-stat"><span>Exposed Secrets</span><strong>${comp.before.exposed_secrets}</strong></div>
          <div class="comparison-stat"><span>Prompt Injection</span><strong>${comp.before.prompt_injection_risk}</strong></div>
        </div>
        <div class="comparison-panel comparison-after">
          <div class="comparison-label">After</div>
          <div class="comparison-stat"><span>Score</span><strong style="color:var(--low)">${comp.after.score}/100</strong></div>
          <div class="comparison-stat"><span>Decision</span><strong class="decision-${comp.after.decision}" style="padding:2px 8px; border-radius:4px; font-size:12px;">${comp.after.decision}</strong></div>
          <div class="comparison-stat"><span>Critical</span><strong>${comp.after.critical}</strong></div>
          <div class="comparison-stat"><span>High</span><strong>${comp.after.high}</strong></div>
          <div class="comparison-stat"><span>Exposed Secrets</span><strong>${comp.after.exposed_secrets}</strong></div>
          <div class="comparison-stat"><span>Patch Verification</span><strong style="color:var(--low)">${comp.after.patch_verification}</strong></div>
        </div>
      </div>
      <div style="font-size:11px; color:var(--text-muted); margin-top:8px;">
        * Synthetic demo data / target values shown until measured.
      </div>
    `;
  } catch (e) {
    div.innerHTML = `<div style="color:var(--text-muted); font-size:13px;">Before/after data available after patches.</div>`;
  }
}

// ============================================================
// View 5: AgentGuard
// ============================================================
async function renderAgentGuard(container) {
  if (!state.scanId) {
    container.innerHTML = `<div class="card">No scan loaded. Go to Upload.</div>`;
    return;
  }

  container.innerHTML = `<div class="card"><div class="spinner"></div> Loading AgentGuard...</div>`;

  try {
    const data = await API.get(`/api/agentguard/${state.scanId}/scenarios`);
    const log = await API.get(`/api/agentguard/${state.scanId}/log`);

    container.innerHTML = `
      <div class="view active">
        <div class="view-header">
          <div class="view-title">AgentGuard</div>
          <div class="view-subtitle">Sandboxed AI-agent action evaluation. Simulates policy decisions for AI coding agents.</div>
        </div>

        <div class="card">
          <div class="card-title">Test an AI Agent Action</div>
          <p style="color:var(--text-secondary); font-size:13px; margin: 8px 0 16px;">
            Click an action below to simulate an AI agent requesting it. AgentGuard will evaluate the action against its policy.
          </p>

          <div class="action-grid">
            ${data.scenarios.map(s => `
              <div class="action-card" onclick="testAgentAction('${s.action_type}')">
                <div class="action-card-title">${s.action_type.replace(/_/g, " ").toUpperCase()}</div>
                <div class="action-card-desc">${s.description}</div>
                <div style="font-family:monospace; font-size:11px; color:var(--blue); background:var(--bg-deep); padding:6px 8px; border-radius:4px;">${escapeHtml(s.evidence)}</div>
              </div>
            `).join("")}
          </div>
        </div>

        <div class="card">
          <div class="card-title">Action Log</div>
          <div class="action-log" id="actionLog">
            ${log.actions.length === 0 ? '<div style="color:var(--text-muted); padding:20px; text-align:center;">No actions tested yet. Click an action above.</div>' :
              log.actions.map(a => `
                <div class="log-entry">
                  <div class="log-entry-header">
                    <div><strong>${a.action}</strong></div>
                    <div class="log-entry-time">${new Date(a.created_at).toLocaleTimeString()}</div>
                  </div>
                  <div>
                    <span class="decision-tag ${a.decision.includes("ALLOW") ? "ALLOW" : a.decision.includes("BLOCK") ? "BLOCK" : "ASK"}">${a.decision}</span>
                  </div>
                  <div class="log-entry-reason">${a.reason}</div>
                  <div class="log-entry-evidence">${escapeHtml(a.evidence)}</div>
                  <div class="log-entry-policy">${a.policy_rule}</div>
                </div>
              `).join("")
            }
          </div>
        </div>

        <div class="card">
          <div class="card-title">AgentGuard Policy Rules</div>
          <table class="findings-table" style="margin-top:12px;">
            <thead>
              <tr><th>Policy</th><th>Decision</th><th>Risk</th><th>Reason</th></tr>
            </thead>
            <tbody>
              ${data.policies.map(p => `
                <tr>
                  <td style="font-family:monospace;">${p.name}</td>
                  <td><span class="decision-tag ${p.decision.includes("ALLOW") ? "ALLOW" : p.decision.includes("BLOCK") ? "BLOCK" : "ASK"}">${p.decision}</span></td>
                  <td style="color:var(--${p.risk_level === "Critical" ? "critical" : p.risk_level === "High" ? "high" : p.risk_level === "Medium" ? "medium" : "low"})">${p.risk_level}</td>
                  <td style="font-size:12px;">${p.reason}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (e) {
    container.innerHTML = `<div class="card">Error: ${e.message}</div>`;
  }
}

async function testAgentAction(actionType) {
  try {
    const result = await API.post(`/api/agentguard/${state.scanId}/test`, { action_type: actionType });

    // Show result as toast
    showToast(`${actionType}: ${result.decision}`);

    // Reload the view to show updated log
    renderAgentGuard(document.getElementById("mainContent"));
  } catch (e) {
    showToast("Error: " + e.message);
  }
}

// ============================================================
// View 6: SessionGuard
// ============================================================
async function renderSessionGuard(container) {
  if (!state.scanId) {
    container.innerHTML = `<div class="card">No scan loaded. Go to Upload.</div>`;
    return;
  }

  container.innerHTML = `
    <div class="view active">
      <div class="view-header">
        <div class="view-title">SessionGuard</div>
        <div class="view-subtitle">Cookie & session security audit on authorized local test app using synthetic tokens.</div>
      </div>

      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
          <div class="card-title">Session Security Audit</div>
          <button class="btn btn-primary" onclick="runSessionAudit()">Run Session Audit</button>
        </div>

        <div style="padding:12px; background:var(--bg-elev); border-radius:8px; margin-bottom:16px; font-size:12px; color:var(--text-muted);">
          [SHIELD] Tested against authorized local test app with synthetic tokens. No real cookies, passwords, or browser profiles used.
        </div>

        <div id="sessionResults">
          <div style="color:var(--text-muted); padding:20px; text-align:center;">Click "Run Session Audit" to begin.</div>
        </div>
      </div>
    </div>
  `;

  // Try loading existing results
  try {
    const existing = await API.get(`/api/sessionguard/${state.scanId}/results`);
    if (existing.results.length > 0) {
      displaySessionResults(existing.results);
    }
  } catch (e) {}
}

async function runSessionAudit() {
  document.getElementById("sessionResults").innerHTML = `
    <div style="display:flex; align-items:center; gap:12px; padding:20px;">
      <div class="spinner"></div>
      <div>Running session security checks...</div>
    </div>
  `;

  try {
    const result = await API.post(`/api/sessionguard/${state.scanId}/run`, {});
    displaySessionResults(result.results);
    showToast(`Session audit complete: ${result.passed} passed, ${result.failed} failed`);
  } catch (e) {
    document.getElementById("sessionResults").innerHTML = `<div style="color:var(--critical)">Error: ${e.message}</div>`;
  }
}

function displaySessionResults(results) {
  const passed = results.filter(r => r.result === "PASS").length;
  const failed = results.filter(r => r.result === "FAIL").length;

  document.getElementById("sessionResults").innerHTML = `
    <div style="display:flex; gap:24px; margin-bottom:20px;">
      <div class="stat-card" style="flex:1;">
        <div class="stat-number" style="color:var(--low)">${passed}</div>
        <div class="stat-label">Passed</div>
      </div>
      <div class="stat-card" style="flex:1;">
        <div class="stat-number" style="color:var(--critical)">${failed}</div>
        <div class="stat-label">Failed</div>
      </div>
      <div class="stat-card" style="flex:1;">
        <div class="stat-number">${results.length}</div>
        <div class="stat-label">Total Checks</div>
      </div>
    </div>

    ${results.map(r => `
      <div class="session-check">
        <div class="session-status session-${r.result}">${r.result}</div>
        <div class="session-detail">
          <div class="session-name">${r.check_name}</div>
          <div class="session-desc">${r.description}</div>
          <div class="session-evidence">${escapeHtml(r.evidence)}</div>
          <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Pass criteria: ${r.pass_criteria}</div>
          <div style="font-size:11px; color:var(--text-muted); margin-top:4px; font-style:italic;">${r.synthetic_note || ""}</div>
        </div>
      </div>
    `).join("")}
  `;
}

// ============================================================
// View 7: Trust Report
// ============================================================
async function renderReport(container) {
  if (!state.scanId) {
    container.innerHTML = `<div class="card">No scan loaded. Go to Upload.</div>`;
    return;
  }

  container.innerHTML = `<div class="card"><div class="spinner"></div> Generating Trust Report...</div>`;

  try {
    const report = await API.get(`/api/report/${state.scanId}`);

    const scoreClass = report.overall_score < 50 ? "score-critical" : report.overall_score < 75 ? "score-high" : "score-low";

    container.innerHTML = `
      <div class="view active">
        <div class="view-header">
          <div class="view-title">Trust Report</div>
          <div class="view-subtitle">Final security assessment for ${report.project_name}</div>
        </div>

        <div class="card">
          <div style="padding:12px; background:var(--bg-elev); border-radius:8px; margin-bottom:20px; font-size:13px; color:var(--text-secondary); border-left:3px solid var(--high);">
            <strong>Automated assessment, not a guarantee.</strong> This report is generated by automated scanners and AI-assisted analysis.
          </div>

          <div class="score-display">
            <div class="score-number ${scoreClass}">${report.overall_score}/100</div>
            <div class="score-label">Overall Security Score</div>
            <div class="decision-badge decision-${report.decision}">DECISION: ${report.decision}</div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Category Scores</div>
          <div style="margin-top:16px;">
            ${Object.entries(report.category_scores).map(([cat, score]) => {
              const color = score < 50 ? "var(--critical)" : score < 75 ? "var(--high)" : "var(--low)";
              return `
                <div class="category-score-row">
                  <div class="category-name">${cat}</div>
                  <div class="category-bar-container">
                    <div class="category-bar-fill" style="width: ${score}%; background: ${color};"></div>
                  </div>
                  <div class="category-score-value" style="color:${color}">${score}/100</div>
                </div>
              `;
            }).join("")}
          </div>
        </div>

        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-number" style="color:var(--critical)">${report.counts.Critical || 0}</div>
            <div class="stat-label">Critical</div>
          </div>
          <div class="stat-card">
            <div class="stat-number" style="color:var(--high)">${report.counts.High || 0}</div>
            <div class="stat-label">High</div>
          </div>
          <div class="stat-card">
            <div class="stat-number" style="color:var(--medium)">${report.counts.Medium || 0}</div>
            <div class="stat-label">Medium</div>
          </div>
          <div class="stat-card">
            <div class="stat-number" style="color:var(--low)">${report.counts.Low || 0}</div>
            <div class="stat-label">Low</div>
          </div>
          <div class="stat-card">
            <div class="stat-number" style="color:var(--accent)">${report.patched_count}</div>
            <div class="stat-label">Patched</div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Patch Verification Summary</div>
          <div style="margin-top:12px;">
            ${report.patches.length === 0 ?
              '<div style="color:var(--text-muted);">No patches applied yet. Use FixMe Space to generate and verify patches.</div>' :
              report.patches.map(p => `
                <div style="padding:8px 0; border-bottom:1px solid var(--border); display:flex; justify-content:space-between;">
                  <span style="font-family:monospace; color:var(--blue);">${p.id}</span>
                  <span class="badge badge-${p.status === 'approved' ? 'low' : p.status === 'rejected' ? 'critical' : 'medium'}">${p.status}</span>
                </div>
              `).join("")
            }
          </div>
        </div>

        <div class="card">
          <div class="card-title">Limitations</div>
          <ul style="margin-top:12px; padding-left:20px; line-height:1.8; color:var(--text-secondary); font-size:13px;">
            <li>Automated scanners may produce false positives or miss context-specific vulnerabilities.</li>
            <li>AI-generated patches require human review before production deployment.</li>
            <li>Session tests use synthetic tokens against an authorized local test app only.</li>
            <li>Supply chain checks use a known-vulnerability database and may miss very recent CVEs.</li>
            <li>This assessment does not cover infrastructure, network, or physical security.</li>
          </ul>
        </div>

        <div class="card" style="text-align:center;">
          <div class="card-title">Download Full Report</div>
          <div style="margin-top:16px; display:flex; gap:12px; justify-content:center;">
            <a class="btn btn-primary" href="/api/report/${report.scan_id}/html" target="_blank">Download HTML Report</a>
            <a class="btn btn-secondary" href="/api/report/${report.scan_id}/markdown" target="_blank">Download Markdown</a>
          </div>
          <div style="margin-top:16px; font-size:12px; color:var(--text-muted);">
            AgentGuard: ${report.agent_actions_count} actions evaluated | SessionGuard: ${report.session_checks_count} checks run
          </div>
        </div>
      </div>
    `;
  } catch (e) {
    container.innerHTML = `<div class="card">Error: ${e.message}</div>`;
  }
}

// ============================================================
// Utilities
// ============================================================
function escapeHtml(text) {
  if (!text) return "";
  const div = document.createElement("div");
  div.textContent = String(text);
  return div.innerHTML;
}

function showToast(message) {
  const existing = document.querySelector(".toast");
  if (existing) existing.remove();

  const toast = document.createElement("div");
  toast.className = "toast";
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => toast.remove(), 4000);
}

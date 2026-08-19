/*
STRIDE-Lite Command Deck

Browser front-end for the local GUI. I wrote this so model.py and
scenario.py can be driven from a hash-routed deck without a framework:
status poll, job submit, report preview, vault hand-off.

Notes:
- Served as /app.js last (after graph.js, score.js, vault.js).
- Hash routes are VIEWS; unknown hashes fall back to overview.
- Jobs POST to /api/jobs/{model,scenario} and poll /api/status every 4s.
  lastJobStatuses is so a running→done flip can toast without a second
  round-trip.
- catalogFingerprint skips CMDB/template/report re-renders when the
  inventory has not changed.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
*/
// Hash-routed panes (unknown hashes fall back to overview in go())
const VIEWS = ["overview", "model", "scenario", "reports", "activity", "vault", "atlas", "about"];

// Session state (status is the last /api/status payload)
const appState = {
  status: null,
  reportType: "stride",
  selectedJobId: null,
  selectedReportPath: null,
  lastJobStatuses: new Map(),
  view: "overview",
};

// Shortcut for getElementById (every bind below uses this)
const $ = (id) => document.getElementById(id);

// Function to flash a short notice (one timer so toasts do not stack)
function showToast(message) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("visible"), 3200);
}

// Function to fetch JSON and throw on non-OK (uses payload.error when present)
async function fetchJson(url, options) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || response.statusText);
  }
  return payload;
}

// Function to pretty-print a byte count (blank if the number is not finite)
function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// Function to render a boolean as yes/no (leaves other values untouched)
function formatYesNo(value) {
  if (value === true) return "yes";
  if (value === false) return "no";
  return value;
}

// Function to shorten argv for the job list (last two path segments)
function shortCommand(command) {
  return command
    .map((part) => {
      if (part.includes("/")) return part.split("/").slice(-2).join("/");
      return part;
    })
    .join(" ");
}

// Function to look up a provider row by id (from the last status payload)
function providerById(id) {
  return (appState.status?.provider.providers || []).find((provider) => provider.id === id);
}

// Function to parse location.hash into view + rest (Vault.openFromHash uses rest)
function parseHash() {
  const raw = decodeURIComponent(location.hash.slice(1));
  if (!raw) return { view: "overview", rest: "" };
  const [view, ...parts] = raw.split("/");
  return { view, rest: parts.join("/") };
}

// Function to switch panes (replaceState so Back does not pile hashes)
function go(view, push = true, rest = "") {
  if (!VIEWS.includes(view)) view = "overview";
  appState.view = view;
  document.querySelectorAll(".view").forEach((node) => {
    node.classList.toggle("active", node.id === `view-${view}`);
  });
  document.querySelectorAll(".nav-btn").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  // Vault is a global from vault.js; rest is the hash tail after the view
  if (view === "vault" && window.Vault) {
    Vault.ensure().then(() => {
      if (rest) Vault.openFromHash(rest);
    }).catch((error) => showToast(error.message));
  }
  if (push) {
    history.replaceState(null, "", rest ? `#${view}/${rest}` : `#${view}`);
  }
}

// Function to rebuild a provider <select> (keeps the current value if still valid)
function fillProviderSelect(select, defaultProvider) {
  const requested = defaultProvider || appState.status.provider.default;
  select.replaceChildren();
  for (const provider of appState.status.provider.providers) {
    const option = document.createElement("option");
    option.value = provider.id;
    option.textContent = `${provider.label} ${provider.ready ? "" : "(missing key)"}`.trim();
    select.appendChild(option);
  }
  if (requested && appState.status.provider.providers.some((provider) => provider.id === requested)) {
    select.value = requested;
  }
}

// Function to fill both job forms plus the default-provider chip
function populateProviderControls() {
  fillProviderSelect($("model-provider"), $("model-provider").value || appState.status.provider.default);
  fillProviderSelect($("scenario-provider"), $("scenario-provider").value || appState.status.provider.default);
  const provider = providerById(appState.status.provider.default);
  const chip = $("default-provider");
  chip.textContent = provider ? `${provider.label} · ${provider.model}` : "PROVIDER";
  chip.className = `badge ${provider?.ready ? "ready" : "warn"}`;
  updateProviderState("model-provider", "model-provider-state");
  updateProviderState("scenario-provider", "scenario-provider-state");
}

// Function to paint the ready/missing-key indicator next to a provider select
function updateProviderState(selectId, stateId) {
  const provider = providerById($(selectId).value);
  const target = $(stateId);
  if (!provider) {
    target.textContent = "Provider";
    target.className = "state-indicator";
    return;
  }
  target.textContent = provider.ready ? `${provider.label} ready` : `${provider.label} key missing`;
  target.className = `state-indicator ${provider.ready ? "ready" : "warning"}`;
}

// Function to rebuild the CMDB <select> (keeps the current id if still in inventory)
function populatecmdb() {
  const select = $("cmdb-id");
  const current = select.value;
  select.replaceChildren();
  for (const row of appState.status.cmdb) {
    const option = document.createElement("option");
    option.value = row.cmdb_id;
    option.textContent = `${row.cmdb_id} · ${row.name}`;
    select.appendChild(option);
  }
  if (current && appState.status.cmdb.some((row) => row.cmdb_id === current)) {
    select.value = current;
  }
  rendercmdbDetail();
}

// Function to paint CIA/sourcing fields for the selected application
function rendercmdbDetail() {
  const selected = $("cmdb-id").value;
  const row = appState.status.cmdb.find((item) => item.cmdb_id === selected);
  const target = $("cmdb-detail");
  target.replaceChildren();
  if (!row) {
    target.innerHTML = '<div class="empty">No application selected</div>';
    return;
  }
  const title = document.createElement("div");
  title.className = "panel-title";
  title.textContent = "Application context";
  const fields = [
    ["Application", row.name],
    ["Business area", row.business_area],
    ["Confidentiality", row.confidentiality],
    ["Integrity", row.integrity],
    ["Availability", row.availability],
    ["Internet facing", formatYesNo(row.internet_facing)],
    ["Sourcing", row.sourcing],
    ["Customer data", formatYesNo(row.customer_data)],
    ["Platform", Array.isArray(row.platform) ? row.platform.join(", ") : row.platform],
    ["Architecture", row.architecture],
  ];
  const grid = document.createElement("div");
  grid.className = "detail-grid";
  for (const [label, value] of fields) {
    const item = document.createElement("div");
    item.className = "detail-item";
    const labelEl = document.createElement("span");
    labelEl.textContent = label;
    const valueEl = document.createElement("strong");
    valueEl.textContent = value || "Not specified";
    item.append(labelEl, valueEl);
    grid.appendChild(item);
  }
  target.append(title, grid);
}

// Function to rebuild the attack-template <select> (then the technique chips)
function populateTemplates() {
  const select = $("attack-template");
  const current = select.value;
  select.replaceChildren();
  for (const template of appState.status.attack_templates) {
    const option = document.createElement("option");
    option.value = template.name;
    option.textContent = template.name;
    select.appendChild(option);
  }
  if (current && appState.status.attack_templates.some((template) => template.name === current)) {
    select.value = current;
  }
  renderTechniques();
}

// Function to list MITRE techniques for the selected template (capped at 16)
function renderTechniques() {
  const selected = $("attack-template").value;
  const template = appState.status.attack_templates.find((item) => item.name === selected);
  const target = $("technique-list");
  target.replaceChildren();
  if (!template || !template.techniques.length) {
    target.innerHTML = '<div class="empty">No attack template selected</div>';
    return;
  }
  for (const technique of template.techniques.slice(0, 16)) {
    const item = document.createElement("div");
    item.className = "technique";
    item.textContent = technique;
    target.appendChild(item);
  }
}

// Function to fill the scenario JSON picker (stride outputs only)
function populateJsonFiles() {
  const select = $("json-file");
  const current = select.value;
  select.replaceChildren();
  const files = appState.status.outputs.stride || [];
  if (!files.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No threat model JSON files";
    select.appendChild(option);
    return;
  }
  for (const file of files) {
    const option = document.createElement("option");
    option.value = file.path;
    option.textContent = file.name;
    select.appendChild(option);
  }
  if (current && files.some((file) => file.path === current)) {
    select.value = current;
  }
}

// Function to write workspace metrics and the nav report count
function updateMetrics() {
  $("workspace").textContent = appState.status.workspace;
  $("metric-cmdb").textContent = String(appState.status.cmdb.length);
  $("metric-templates").textContent = String(appState.status.attack_templates.length);
  $("metric-stride").textContent = String(appState.status.outputs.stride.length);
  $("metric-scenarios").textContent = String(appState.status.outputs.scenarios.length);
  const reports = appState.status.outputs.stride.length + appState.status.outputs.scenarios.length;
  $("nav-report-count").textContent = reports || "";
}

// Function to fill the reports table for appState.reportType (click row to preview)
function renderReports() {
  const table = $("reports-table");
  table.replaceChildren();
  const files = appState.status.outputs[appState.reportType] || [];
  if (!files.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 3;
    cell.textContent = "No JSON files";
    row.appendChild(cell);
    table.appendChild(row);
    $("report-preview").textContent = "No artifacts";
    return;
  }
  for (const file of files) {
    const row = document.createElement("tr");
    if (file.path === appState.selectedReportPath) row.classList.add("selected");
    row.addEventListener("click", () => previewReport(file.path));

    const name = document.createElement("td");
    const nameText = document.createElement("span");
    nameText.className = "file-name";
    nameText.textContent = file.name;
    name.appendChild(nameText);

    const modified = document.createElement("td");
    modified.textContent = file.modified;

    const size = document.createElement("td");
    size.textContent = formatBytes(file.size);

    row.append(name, modified, size);
    table.appendChild(row);
  }
}

// Function to load a report JSON via /api/file (path is query-encoded)
async function previewReport(path) {
  appState.selectedReportPath = path;
  renderReports();
  $("report-preview").textContent = "Loading artifact";
  try {
    const payload = await fetchJson(`/api/file?path=${encodeURIComponent(path)}`);
    $("report-preview").textContent = JSON.stringify(payload.content, null, 2);
  } catch (error) {
    $("report-preview").textContent = error.message;
  }
}

// Function to rebuild the job list (picks a running job if the selection is stale)
function renderJobs() {
  const list = $("job-list");
  const jobs = appState.status.jobs || [];
  list.replaceChildren();
  $("job-count").textContent = jobs.length || "";
  if (!jobs.length) {
    list.innerHTML = '<div class="empty">No jobs</div>';
    renderConsole(null);
    return;
  }
  if (!appState.selectedJobId || !jobs.some((job) => job.id === appState.selectedJobId)) {
    const running = jobs.find((job) => job.status === "running");
    appState.selectedJobId = (running || jobs[0]).id;
  }
  for (const job of jobs) {
    const previous = appState.lastJobStatuses.get(job.id);
    // Toast on running→done so the operator sees the flip without opening the row
    if (previous && previous === "running" && job.status !== "running") {
      showToast(`${job.kind} ${job.status}`);
    }
    appState.lastJobStatuses.set(job.id, job.status);

    const row = document.createElement("button");
    row.type = "button";
    row.className = `job-row ${job.id === appState.selectedJobId ? "active" : ""}`;
    row.addEventListener("click", () => {
      appState.selectedJobId = job.id;
      renderJobs();
    });

    const title = document.createElement("strong");
    title.textContent = `${job.kind} · ${job.status}`;
    const command = document.createElement("code");
    command.textContent = shortCommand(job.command);
    row.append(title, command);
    list.appendChild(row);
  }
  renderConsole(jobs.find((job) => job.id === appState.selectedJobId));
}

// Function to dump a job's log into the console pane (scrolls to the bottom)
function renderConsole(job) {
  if (!job) {
    $("console-title").textContent = "No active job";
    $("console-state").textContent = "Idle";
    $("console-state").className = "state-indicator";
    $("console-log").textContent = "Awaiting execution";
    return;
  }
  $("console-title").textContent = `${job.kind} ${job.id}`;
  $("console-state").textContent = job.status;
  $("console-state").className = `state-indicator ${job.status}`;
  $("console-log").textContent = job.log.length ? job.log.join("\n") : "Process started";
  $("console-log").scrollTop = $("console-log").scrollHeight;
}

// Function to fingerprint inventory (skip select rebuilds when unchanged)
function catalogFingerprint(status) {
  const files = [
    ...(status.outputs?.stride || []),
    ...(status.outputs?.scenarios || []),
  ].map((file) => `${file.path}:${file.modified}:${file.size}`);
  const cmdb = (status.cmdb || []).map((row) => row.cmdb_id).join(",");
  const templates = (status.attack_templates || []).map((row) => row.name).join(",");
  return `${files.join("|")}#${cmdb}#${templates}`;
}

// Last catalog fingerprint (compared on every poll)
let lastCatalogFp = "";

// Function to pull /api/status (force=true rebuilds selects even if unchanged)
async function refreshStatus(force = false) {
  appState.status = await fetchJson("/api/status");
  const fingerprint = catalogFingerprint(appState.status);
  const catalogChanged = fingerprint !== lastCatalogFp;
  lastCatalogFp = fingerprint;
  updateMetrics();
  renderJobs();
  if (force || catalogChanged) {
    populateProviderControls();
    populatecmdb();
    populateTemplates();
    populateJsonFiles();
    renderReports();
    // Swallow vault refresh errors (the pane still has the last graph)
    if (appState.view === "vault" && window.Vault) {
      Vault.refresh(Boolean(force)).catch(() => {});
    }
  }
}

// Function to POST a job and jump to the activity pane
async function submitJob(url, body) {
  const job = await fetchJson(url, {
    method: "POST",
    body: JSON.stringify(body),
  });
  appState.selectedJobId = job.id;
  showToast(`${job.kind} started`);
  go("activity");
  await refreshStatus();
}

// Function to write UTC clock (ISO time slice, no local timezone)
function tickClock() {
  const now = new Date();
  $("clock").textContent = `${now.toISOString().slice(11, 19)} UTC`;
}

// Function to draw the background particle field (mouse repels; wrap at edges)
function startAmbient() {
  const cv = $("bg-canvas");
  const ctx = cv.getContext("2d");
  let width = 0;
  let height = 0;
  let pts = [];
  const count = 70;
  const link = 130;
  const mouse = { x: -9999, y: -9999 };

  // Resize resets points (canvas pixel size, not CSS)
  function resize() {
    width = cv.width = innerWidth;
    height = cv.height = innerHeight;
    pts = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.28,
      vy: (Math.random() - 0.5) * 0.28,
      r: Math.random() * 1.5 + 0.5,
    }));
  }

  addEventListener("resize", resize);
  resize();
  // CSS vars --mx/--my drive the cursor glow in styles.css
  addEventListener("mousemove", (event) => {
    mouse.x = event.clientX;
    mouse.y = event.clientY;
    document.documentElement.style.setProperty("--mx", `${event.clientX}px`);
    document.documentElement.style.setProperty("--my", `${event.clientY}px`);
  });

  // IIFE frame loop (requestAnimationFrame, not setInterval)
  (function frame() {
    ctx.clearRect(0, 0, width, height);
    for (const point of pts) {
      point.x += point.vx;
      point.y += point.vy;
      const dx = point.x - mouse.x;
      const dy = point.y - mouse.y;
      const dist = Math.hypot(dx, dy);
      if (dist < 140 && dist > 0.1) {
        point.x += (dx / dist) * 0.5;
        point.y += (dy / dist) * 0.5;
      }
      if (point.x < -10) point.x = width + 10;
      if (point.x > width + 10) point.x = -10;
      if (point.y < -10) point.y = height + 10;
      if (point.y > height + 10) point.y = -10;
    }
    ctx.lineWidth = 0.6;
    for (let i = 0; i < count; i += 1) {
      for (let j = i + 1; j < count; j += 1) {
        const a = pts[i];
        const b = pts[j];
        const dist = Math.hypot(a.x - b.x, a.y - b.y);
        if (dist < link) {
          ctx.strokeStyle = `rgba(34,211,238,${(1 - dist / link) * 0.09})`;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }
    for (const point of pts) {
      ctx.fillStyle = "rgba(94,234,212,0.4)";
      ctx.beginPath();
      ctx.arc(point.x, point.y, point.r, 0, 7);
      ctx.fill();
    }
    requestAnimationFrame(frame);
  })();
}

// Function to wire clicks, submits, and hashchange (called once from boot)
function bindEvents() {
  $("refresh").addEventListener("click", () => {
    refreshStatus(true).catch((error) => showToast(error.message));
  });

  $("cmdb-id").addEventListener("change", rendercmdbDetail);
  $("attack-template").addEventListener("change", renderTechniques);
  $("model-provider").addEventListener("change", () => updateProviderState("model-provider", "model-provider-state"));
  $("scenario-provider").addEventListener("change", () => updateProviderState("scenario-provider", "scenario-provider-state"));

  // Job forms (preventDefault so the page does not reload)
  $("model-form").addEventListener("submit", (event) => {
    event.preventDefault();
    submitJob("/api/jobs/model", {
      cmdb_id: $("cmdb-id").value,
      provider: $("model-provider").value,
    }).catch((error) => showToast(error.message));
  });

  $("scenario-form").addEventListener("submit", (event) => {
    event.preventDefault();
    submitJob("/api/jobs/scenario", {
      json_file: $("json-file").value,
      attack_template: $("attack-template").value,
      provider: $("scenario-provider").value,
      cve_feed: $("cve-feed")?.value?.trim() || undefined,
      min_cvss: $("min-cvss").value,
      db_path: "cve_database.db",
    }).catch((error) => showToast(error.message));
  });

  // Segment buttons switch stride vs scenario in the reports table
  document.querySelectorAll(".segment").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".segment").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      appState.reportType = button.dataset.reportType;
      appState.selectedReportPath = null;
      renderReports();
    });
  });

  document.querySelectorAll(".nav-btn").forEach((button) => {
    button.addEventListener("click", () => go(button.dataset.view));
  });

  document.querySelectorAll("[data-go]").forEach((button) => {
    button.addEventListener("click", () => go(button.dataset.go));
  });

  addEventListener("hashchange", () => {
    const parsed = parseHash();
    go(VIEWS.includes(parsed.view) ? parsed.view : "overview", false, parsed.rest);
  });
  if (window.Vault) Vault.bind();
}

// Function to run the boot overlay, then poll status every 4s
async function boot() {
  const log = $("boot-log");
  const fill = $("boot-fill");
  const steps = [
    "reading workspace…",
    "checking providers…",
    "loading applications…",
    "indexing attack templates…",
    "rendering command deck…",
  ];
  let index = 0;
  // Overlay copy (interval is visual only; real work is refreshStatus below)
  const timer = setInterval(() => {
    if (index < steps.length) {
      log.textContent = steps[index];
      index += 1;
      fill.style.width = `${(index / (steps.length + 1)) * 100}%`;
    }
  }, 160);

  const started = performance.now();
  bindEvents();
  startAmbient();
  tickClock();
  setInterval(tickClock, 1000);

  try {
    await refreshStatus();
    // Poll every 4s; catalogFingerprint keeps the selects still
    window.setInterval(() => {
      refreshStatus(false).catch(() => {});
    }, 4000);
  } catch (error) {
    showToast(error.message);
    $("workspace").textContent = "Workspace unavailable";
  }

  clearInterval(timer);
  fill.style.width = "100%";
  // Keep the overlay up at least 900ms so it does not flash
  const wait = Math.max(0, 900 - (performance.now() - started));
  setTimeout(() => {
    $("boot").classList.add("done");
    const parsed = parseHash();
    go(VIEWS.includes(parsed.view) ? parsed.view : "overview", false, parsed.rest);
  }, wait);
}

boot();

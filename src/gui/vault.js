/*
STRIDE-Lite Vault Pane

Browser-side vault: tree, list, note, outline, compare, and the ⌘P
switcher. I wrote this so the graph (graph.js) and the note panel stay
in one IIFE — fetch /api/vault, paint, and deep-link #vault/type/id.

Notes:
- Two modes: vault (models / scenarios / kill chains / apps) and local
  (expand the selected killchain or model by one hop).
- Markdown is a subset I render here (headings, tables, fences) so the
  pane does not pull a library; wikilinks become buttons that select() nodes.
- Compare hits /api/killchains/compare and mounts Score side-by-side.
- lastIndexFp fingerprints the index so a no-op refresh skips the GraphCanvas write.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
*/
const Vault = (() => {
  // Six STRIDE buckets (same order as the model JSON keys)
  const STRIDE = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"];
  let index = { nodes: [], edges: [] };
  let catalog = { templates: [], techniques: [], ambiguities: [] };
  let graph = null;
  let mode = "vault";
  let selectedId = null;
  let rawMode = false;
  let familyFilter = new Set();
  let strideFilter = new Set();
  let dreadMin = 0;
  let normalizeTypos = false;
  // Fingerprint of last loaded index (skip GraphCanvas write when unchanged)
  let lastIndexFp = "";
  let loaded = false;
  let lastExpandRoot = "";

  const $ = (id) => document.getElementById(id);

  // Function to look up a node by id (index is a flat list)
  function nodeById(id) {
    return index.nodes.find((node) => node.id === id);
  }

  // Function to list outbound edges with their target nodes
  function outgoing(id) {
    return index.edges
      .filter((edge) => edge.from === id)
      .map((edge) => ({ edge, node: nodeById(edge.to) }))
      .filter((item) => item.node);
  }

  // Function to list inbound edges (backlinks pane)
  function backlinks(id) {
    return index.edges
      .filter((edge) => edge.to === id)
      .map((edge) => ({ edge, node: nodeById(edge.from) }))
      .filter((item) => item.node);
  }

  // Function to parse a node's DREAD average (unscored / blank → null, so the slider can hide it)
  function dreadOf(node) {
    const value = node.props?.dread;
    if (value === "unscored" || value == null || value === "") return null;
    const num = Number(value);
    return Number.isFinite(num) ? num : null;
  }

  // Function to apply vault/local + family + STRIDE + DREAD filters
  function filteredNodes() {
    let nodes = index.nodes.filter((node) => {
      // Vault mode hides techniques, threats, and hiddenInVault cards
      if (mode === "vault" && (node.type === "technique" || node.type === "threat" || node.hiddenInVault)) return false;
      return true;
    });
    if (familyFilter.size) {
      const keep = new Set();
      for (const node of nodes) {
        if (node.type !== "killchain") continue;
        const families = String(node.props?.families || "").split(",").map((item) => item.trim());
        if (families.some((item) => familyFilter.has(item))) keep.add(node.id);
      }
      // Pull in uses-template / about / derived-from neighbors so a kept killchain is not a lone node
      for (const edge of index.edges) {
        if (keep.has(edge.to) || keep.has(edge.from)) {
          if (["uses-template", "about", "derived-from"].includes(edge.rel)) {
            keep.add(edge.from);
            keep.add(edge.to);
          }
        }
      }
      nodes = nodes.filter((node) => keep.has(node.id));
    }
    if (strideFilter.size) {
      nodes = nodes.filter((node) => node.type !== "threat" || strideFilter.has(node.props?.category));
    }
    if (dreadMin > 0) {
      nodes = nodes.filter((node) => {
        if (node.type !== "threat") return true;
        const avg = dreadOf(node);
        return avg != null && avg >= dreadMin;
      });
    }
    return nodes;
  }

  // Function to escape HTML (notes are attacker-shaped JSON)
  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // Function to slug a heading for outline jump links
  function slugHeading(text) {
    const slug = String(text || "")
      .toLowerCase()
      .replace(/&amp;/g, "and")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
    return slug || "section";
  }

  // Function to render a markdown subset (headings, tables, fences — no library)
  function renderMarkdown(text) {
    const escaped = escapeHtml(text || "");
    const lines = escaped.split("\n");
    const out = [];
    const used = new Map();
    let inFence = false;
    let inTable = false;
    let tableRow = 0;
    const heading = (tag, body) => {
      // Dedup ids so two "## Impact" headings do not collide
      let id = slugHeading(body);
      const count = (used.get(id) || 0) + 1;
      used.set(id, count);
      if (count > 1) id = `${id}-${count}`;
      return `<${tag} id="${id}" data-heading="${id}">${body}</${tag}>`;
    };
    for (const line of lines) {
      if (line.startsWith("```")) {
        inFence = !inFence;
        out.push(inFence ? "<pre class='md-fence'>" : "</pre>");
        continue;
      }
      if (inFence) {
        out.push(`${line}\n`);
        continue;
      }
      if (/^\|/.test(line)) {
        if (!inTable) {
          out.push("<table class='md-table'>");
          inTable = true;
          tableRow = 0;
        }
        const cells = line.split("|").slice(1, -1);
        // Skip markdown separator rows (|---|---|)
        if (cells.every((cell) => /^[\s:-]+$/.test(cell))) continue;
        const tag = tableRow === 0 ? "th" : "td";
        tableRow += 1;
        out.push(`<tr>${cells.map((cell) => `<${tag}>${cell.trim()}</${tag}>`).join("")}</tr>`);
        continue;
      }
      if (inTable) {
        out.push("</table>");
        inTable = false;
      }
      if (/^### /.test(line)) out.push(heading("h3", line.slice(4)));
      else if (/^## /.test(line)) out.push(heading("h2", line.slice(3)));
      else if (/^# /.test(line)) out.push(heading("h1", line.slice(2)));
      else if (/^[-*] /.test(line)) out.push(`<li>${line.slice(2)}</li>`);
      else if (line.trim() === "") out.push("<br>");
      else out.push(`<p>${line.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")}</p>`);
    }
    if (inTable) out.push("</table>");
    if (inFence) out.push("</pre>");
    return linkify(out.join(""));
  }

  // Function to turn CVE / T-ID / SL-NN tokens into wiki buttons
  function linkify(html) {
    return html
      .replace(/\b(CVE-\d{4}-\d+)\b/g, '<button type="button" class="wiki" data-kind="cve" data-id="$1">$1</button>')
      .replace(/\b(T\d{4}(?:\.\d{3})?)\b/g, '<button type="button" class="wiki" data-kind="tech" data-id="$1">$1</button>')
      .replace(/\b(SL-\d{2})\b/g, '<button type="button" class="wiki" data-kind="control" data-id="$1">$1</button>');
  }

  // Function to bind wiki buttons so a click select()s the node
  function bindWikilinks(root) {
    root.querySelectorAll(".wiki").forEach((button) => {
      button.addEventListener("click", () => {
        const kind = button.dataset.kind;
        const id = (button.dataset.id || "").toUpperCase();
        if (kind === "tech") select(`tech:${id}`, true);
        if (kind === "cve") select(`cve:${id}`, true);
        if (kind === "control") select(`control:${id}`, true);
      });
    });
  }

  // Function to paint the left-hand tree (models / scenarios / kill chains / apps)
  function renderTree() {
    const host = $("vault-tree");
    if (!host) return;
    const groups = { model: [], scenario: [], killchain: [], app: [] };
    for (const node of filteredNodes()) {
      if (groups[node.type]) groups[node.type].push(node);
    }
    const labels = { model: "Models", scenario: "Scenarios", killchain: "Kill chains", app: "Applications" };
    host.replaceChildren();
    for (const [type, label] of Object.entries(labels)) {
      const heading = document.createElement("div");
      heading.className = "tree-head";
      heading.textContent = `${label} (${groups[type].length})`;
      host.appendChild(heading);
      for (const node of groups[type]) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = `tree-item ${node.id === selectedId ? "active" : ""}`;
        button.textContent = node.label;
        button.addEventListener("click", () => select(node.id, true));
        host.appendChild(button);
      }
    }
  }

  // Function to paint the mobile list (graph hides under 760px)
  function renderList() {
    const list = $("vault-list");
    if (!list) return;
    list.replaceChildren();
    for (const node of filteredNodes().filter((item) => !["technique", "threat"].includes(item.type))) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `job-row ${node.id === selectedId ? "active" : ""}`;
      button.innerHTML = `<strong>${escapeHtml(node.label)}</strong><code>${escapeHtml(node.type)}</code>`;
      button.addEventListener("click", () => select(node.id, true));
      list.appendChild(button);
    }
  }

  // Function to paint outbound + backlink chips
  function renderLinks() {
    const paint = (el, items) => {
      el.replaceChildren();
      if (!items.length) {
        el.innerHTML = '<div class="empty">None</div>';
        return;
      }
      for (const item of items) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "link-chip";
        button.textContent = `${item.node.type}: ${item.node.label}`;
        button.addEventListener("click", () => select(item.node.id, true));
        el.appendChild(button);
      }
    };
    paint($("vault-out"), selectedId ? outgoing(selectedId) : []);
    paint($("vault-back"), selectedId ? backlinks(selectedId) : []);
  }

  // Function to dump node.props into the meta pane
  function renderProps(props) {
    const target = $("vault-props");
    target.replaceChildren();
    if (!props) return;
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === "") continue;
      const field = document.createElement("div");
      field.className = "m-field";
      field.innerHTML = `<div class="f-label">${escapeHtml(key)}</div><div class="f-value">${escapeHtml(String(value))}</div>`;
      target.appendChild(field);
    }
  }

  // Function to paint the outline pane (scenario headings only)
  function renderOutline(items) {
    const host = $("vault-outline");
    host.replaceChildren();
    if (!items || !items.length) return;
    const title = document.createElement("div");
    title.className = "panel-title";
    title.textContent = "Outline";
    host.appendChild(title);
    const used = new Map();
    for (const item of items) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "outline-item";
      row.textContent = item;
      let id = slugHeading(item);
      const count = (used.get(id) || 0) + 1;
      used.set(id, count);
      if (count > 1) id = `${id}-${count}`;
      row.dataset.heading = id;
      row.addEventListener("click", () => {
        // Outline lives on the Threat tab; switch first then scroll
        const threatTab = $("vault-note")?.querySelector('[data-tab="threat"]');
        if (threatTab) threatTab.click();
        const target = $("vault-note")?.querySelector(`[data-heading="${id}"]`);
        if (target) {
          target.scrollIntoView({ block: "start", behavior: "smooth" });
          target.classList.add("heading-flash");
          window.setTimeout(() => target.classList.remove("heading-flash"), 1200);
        }
      });
      host.appendChild(row);
    }
  }

  // Function to render a STRIDE model as category cards
  function renderModel(note) {
    const groups = {};
    for (const threat of note.threats || []) (groups[threat.category] ||= []).push(threat);
    const parts = STRIDE.map((category) => {
      const threats = groups[category] || [];
      const cards = threats.map((threat, index) => `
        <button type="button" class="detail-item threat-card" data-threat="${escapeHtml(note.path.split("/").pop())}:${index}">
          <span>${escapeHtml(category)}${threat.avg != null ? ` · DREAD ${threat.avg}` : " · unscored"}</span>
          <strong>${escapeHtml(threat.title)}</strong>
          ${threat.description ? `<p class="lede">${escapeHtml(threat.description)}</p>` : ""}
          ${threat.impact ? `<p class="lede dim">Impact: ${escapeHtml(threat.impact)}</p>` : ""}
          ${threat.mitigation ? `<p class="lede dim">Mitigation: ${escapeHtml(threat.mitigation)}</p>` : ""}
        </button>`).join("");
      return `<div class="panel-title">${escapeHtml(category)} · ${threats.length}</div><div class="detail-grid">${cards || '<div class="empty">Empty</div>'}</div>`;
    });
    if (note.warnings?.length) parts.unshift(`<p class="lede dim">${note.warnings.length} parse warnings: ${escapeHtml(note.warnings.join(", "))}</p>`);
    return parts.join("");
  }

  // Function to render a scenario (Threat / CVE / CTI tabs)
  function renderScenario(note) {
    const tabs = [
      ["threat", "Scenario", note.Threat_Report],
      ["cve", "CVE", note.CVE_Report],
      ["cti", "CTI", note.CTI_Report],
    ];
    return `
      <div class="segmented scenario-tabs">
        ${tabs.map(([id, label], index) => `<button class="segment ${index === 0 ? "active" : ""}" data-tab="${id}" type="button">${label}</button>`).join("")}
      </div>
      ${tabs.map(([id, , body], index) => `<div class="md-body ${index === 0 ? "" : "hidden"}" data-pane="${id}">${renderMarkdown(body || "")}</div>`).join("")}
    `;
  }

  // Function to render a kill-chain note (score mount + USE IN SCENARIO)
  function renderKillchain(note) {
    const notes = (note.notes || []).map((item) => `<div class="lede dim">${escapeHtml(item)}</div>`).join("");
    return `
      <p class="lede dim">${escapeHtml(note.order_quality || "")} · ${(note.families || []).join(", ")}</p>
      <div id="score-root"></div>
      ${notes ? `<div class="score-notes">${notes}</div>` : ""}
      <button class="btn primary" type="button" id="vault-run-template">USE IN SCENARIO</button>
      ${(note.disclaimer || "") ? `<p class="lede dim">${escapeHtml(note.disclaimer)}</p>` : ""}
    `;
  }

  // Function to render a CMDB app card (first 14 meta keys)
  function renderApp(note) {
    const meta = note.meta || {};
    return `<div class="detail-grid">${Object.entries(meta).slice(0, 14).map(([key, value]) => `
      <div class="detail-item"><span>${escapeHtml(key)}</span><strong>${escapeHtml(Array.isArray(value) ? value.join(", ") : value || "—")}</strong></div>
    `).join("")}</div>`;
  }

  // Function to render a technique note (STIX name / tactics / used_by)
  function renderTechnique(note) {
    const stixName = note.stix_name ? `<p class="lede">STIX · ${escapeHtml(note.stix_name)}</p>` : "";
    const tactics = (note.stix_tactics || []).join(", ");
    const platforms = (note.stix_platforms || []).join(", ");
    const desc = note.stix?.description ? `<p class="lede dim">${escapeHtml(note.stix.description)}</p>` : "";
    return `
      <p class="lede">${escapeHtml(note.name || note.id)}</p>
      <p class="lede dim">${escapeHtml(note.id_status || "ok")}${note.suggested_id && note.suggested_id !== note.id ? ` → ${escapeHtml(note.suggested_id)}` : ""}</p>
      ${stixName}
      ${tactics ? `<p class="lede dim">${escapeHtml(tactics)}</p>` : ""}
      ${platforms ? `<p class="lede dim">${escapeHtml(platforms)}</p>` : ""}
      ${desc}
      <div class="technique-list">${(note.used_by || []).map((name) => `<div class="technique">${escapeHtml(name)}</div>`).join("")}</div>
    `;
  }

  // Function to render SL- control rows from the taxonomy
  function renderControl(note) {
    return (note.rows || []).map((row) => `
      <div class="detail-item">
        <span>${escapeHtml(row.id)} · ${escapeHtml(row.topic)}</span>
        <strong>${escapeHtml(row.title)}</strong>
        <p class="lede">${escapeHtml(row.description)}</p>
      </div>`).join("");
  }

  // Function to render a CVE record (or the unknown stub)
  function renderCve(note) {
    if (!note.known) return `<p class="lede dim">${escapeHtml(note.note || "Unknown CVE")}</p><p>${escapeHtml(note.cve_id)}</p>`;
    const rec = note.record || {};
    return `<div class="detail-grid">${Object.entries(rec).map(([key, value]) => `
      <div class="detail-item"><span>${escapeHtml(key)}</span><strong>${escapeHtml(String(value))}</strong></div>`).join("")}</div>`;
  }

  // Function to render a single threat card (OPEN MODEL jumps to parent)
  function renderThreat(note) {
    return `
      <p class="lede">${escapeHtml(note.category || "")}${note.avg != null ? ` · DREAD ${note.avg}` : ""}</p>
      <p>${escapeHtml(note.title || "")}</p>
      ${note.description ? `<p class="lede">${escapeHtml(note.description)}</p>` : ""}
      ${note.impact ? `<p class="lede dim">Impact: ${escapeHtml(note.impact)}</p>` : ""}
      ${note.mitigation ? `<p class="lede dim">Mitigation: ${escapeHtml(note.mitigation)}</p>` : ""}
      <button class="btn ghost" type="button" id="open-parent-model">OPEN MODEL</button>
    `;
  }

  // Function to fetch /api/vault/note and paint the note pane
  async function loadNote(id) {
    const node = nodeById(id);
    $("vault-note-title").textContent = node ? node.label : id;
    renderProps(node?.props);
    $("vault-note").innerHTML = '<div class="empty">Loading…</div>';
    $("vault-compare-out").hidden = true;
    try {
      const note = await fetchJson(`/api/vault/note?id=${encodeURIComponent(id)}`);
      if (rawMode) {
        // Raw JSON dump (debug toggle)
        $("vault-note").innerHTML = `<pre class="note-md">${escapeHtml(JSON.stringify(note, null, 2))}</pre>`;
        renderOutline([]);
        return;
      }
      if (note.type === "model") $("vault-note").innerHTML = renderModel(note);
      else if (note.type === "scenario") {
        $("vault-note").innerHTML = renderScenario(note);
        renderOutline(note.outline || []);
        $("vault-note").querySelectorAll("[data-tab]").forEach((button) => {
          button.addEventListener("click", () => {
            $("vault-note").querySelectorAll("[data-tab]").forEach((item) => item.classList.remove("active"));
            $("vault-note").querySelectorAll("[data-pane]").forEach((item) => item.classList.add("hidden"));
            button.classList.add("active");
            const pane = $("vault-note").querySelector(`[data-pane="${button.dataset.tab}"]`);
            if (pane) pane.classList.remove("hidden");
          });
        });
      } else if (note.type === "killchain") {
        $("vault-note").innerHTML = renderKillchain(note);
        if (note.score && window.Score) {
          window.Score.mount($("score-root"), note.score, {
            onTech: (techId) => select(`tech:${techId}`, true),
          });
        }
        $("vault-run-template")?.addEventListener("click", () => {
          // Local select is the <select>, not the function above
          const select = $("attack-template");
          if (select && note.name) {
            select.value = note.name;
            select.dispatchEvent(new Event("change"));
          }
          if (typeof go === "function") go("scenario");
        });
      } else if (note.type === "app") $("vault-note").innerHTML = renderApp(note);
      else if (note.type === "technique") $("vault-note").innerHTML = renderTechnique(note);
      else if (note.type === "control") $("vault-note").innerHTML = renderControl(note);
      else if (note.type === "cve") $("vault-note").innerHTML = renderCve(note);
      else if (note.type === "threat") {
        $("vault-note").innerHTML = renderThreat(note);
        $("open-parent-model")?.addEventListener("click", () => select(note.model, true));
      } else $("vault-note").innerHTML = `<pre class="note-md">${escapeHtml(JSON.stringify(note, null, 2))}</pre>`;
      if (note.type !== "scenario") renderOutline([]);
      bindWikilinks($("vault-note"));
      $("vault-note").querySelectorAll("[data-threat]").forEach((button) => {
        button.addEventListener("click", () => select(`threat:${button.dataset.threat}`, true));
      });
    } catch (error) {
      $("vault-note").innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }

  // Function to select a node (graph highlight, hash, local-mode expand)
  function select(id, push) {
    selectedId = id;
    if (graph) graph.setSelection(id);
    renderTree();
    renderList();
    renderLinks();
    if (id) loadNote(id);
    const expandRoot = id && (id.startsWith("killchain:") || id.startsWith("model:")) ? id : lastExpandRoot;
    if (mode === "local" && expandRoot && expandRoot !== lastExpandRoot) {
      lastExpandRoot = expandRoot;
      applyGraph();
    }
    if (push && window.history && id) {
      // Hash is #vault/type/id so a refresh lands on the same note
      history.replaceState(null, "", `#vault/${id.replace(":", "/")}`);
    }
  }

  // Function to paint family + STRIDE filter chips
  function renderFilters() {
    const host = $("vault-filters");
    if (!host) return;
    host.replaceChildren();
    for (const family of ["ai-saas", "ransomware", "api", "apt", "other"]) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `chip ${familyFilter.has(family) ? "active" : ""}`;
      button.textContent = family;
      button.addEventListener("click", () => {
        if (familyFilter.has(family)) familyFilter.delete(family);
        else familyFilter.add(family);
        applyGraph();
        renderFilters();
      });
      host.appendChild(button);
    }
    const strideHost = $("stride-chips");
    if (strideHost) {
      strideHost.replaceChildren();
      for (const category of STRIDE) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = `chip ${strideFilter.has(category) ? "active" : ""}`;
        button.textContent = category.split(" ")[0];
        button.title = category;
        button.addEventListener("click", () => {
          if (strideFilter.has(category)) strideFilter.delete(category);
          else strideFilter.add(category);
          applyGraph();
          renderFilters();
        });
        strideHost.appendChild(button);
      }
    }
  }

  // Function to fill compare-a / compare-b from the killchain catalog
  function fillCompareSelects() {
    for (const id of ["compare-a", "compare-b"]) {
      const select = $(id);
      if (!select) continue;
      const current = select.value;
      select.replaceChildren();
      for (const template of catalog.templates || []) {
        const option = document.createElement("option");
        option.value = template.id;
        option.textContent = template.name;
        select.appendChild(option);
      }
      if (current) select.value = current;
      // Default B to the second template so Compare is one click
      if (id === "compare-b" && select.options.length > 1 && select.selectedIndex === 0) select.selectedIndex = 1;
    }
  }

  // Function to list flagged technique IDs (typos / suggested_id)
  function renderQuality() {
    const host = $("vault-quality");
    const rows = catalog.ambiguities || [];
    host.innerHTML = rows.length
      ? `<div class="panel-title">Flagged technique IDs (${rows.length})</div>` +
        rows.map((row) => `<div class="outline-item">${escapeHtml(row.template)} · ${escapeHtml(row.raw)} → ${escapeHtml(row.suggested)}</div>`).join("")
      : '<div class="empty">No flagged IDs</div>';
  }

  // Function to expand local-mode neighborhood (killchain steps or model threats)
  function expandLocal(nodes, edges) {
    if (mode !== "local" || !selectedId) return { nodes, edges };
    if (selectedId.startsWith("killchain:")) {
      const template = (catalog.templates || []).find((item) => item.id === selectedId);
      if (!template) return { nodes, edges };
      const extraNodes = [];
      const extraEdges = [];
      for (const step of template.steps || []) {
        for (const meta of step.id_meta || step.ids || []) {
          // Prefer suggested_id when the normalize-typos checkbox is on
          const techId = typeof meta === "string" ? meta : (normalizeTypos && meta.suggested_id ? meta.suggested_id : meta.id);
          if (!techId) continue;
          const nodeId = `tech:${techId}`;
          extraNodes.push({ id: nodeId, type: "technique", label: `${techId} ${step.name || ""}`.trim(), group: "technique", tags: ["technique"], props: { id: techId } });
          extraEdges.push({ id: `${selectedId}->${nodeId}-${step.ord}`, from: selectedId, to: nodeId, rel: "step" });
        }
      }
      return { nodes: nodes.concat(extraNodes), edges: edges.concat(extraEdges) };
    }
    if (selectedId.startsWith("model:")) {
      const extras = index.nodes.filter((node) => node.type === "threat" && node.props?.model === selectedId.slice(6));
      const extraEdges = index.edges.filter((edge) => extras.some((node) => node.id === edge.to || node.id === edge.from));
      return { nodes: nodes.concat(extras), edges: edges.concat(extraEdges) };
    }
    return { nodes, edges };
  }

  // Function to push the filtered (and locally expanded) graph to GraphCanvas
  function applyGraph() {
    const baseNodes = filteredNodes();
    const ids = new Set(baseNodes.map((node) => node.id));
    const baseEdges = index.edges.filter((edge) => ids.has(edge.from) && ids.has(edge.to));
    const { nodes, edges } = expandLocal(baseNodes, baseEdges);
    if (graph) graph.setGraph({ nodes, edges });
    renderTree();
    renderList();
  }

  // Function to open the ⌘P switcher (label / id / tags)
  function openSwitcher() {
    const box = $("switcher");
    const input = $("switcher-input");
    const results = $("switcher-results");
    box.hidden = false;
    input.value = "";
    input.focus();
    const paint = () => {
      const query = input.value.trim().toLowerCase();
      const matches = index.nodes.filter((node) => {
        const hay = `${node.label} ${node.id} ${(node.tags || []).join(" ")}`.toLowerCase();
        return !query || hay.includes(query);
      }).slice(0, 24);
      results.replaceChildren();
      for (const node of matches) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "job-row";
        button.innerHTML = `<strong>${escapeHtml(node.label)}</strong><code>${escapeHtml(node.type)}</code>`;
        button.addEventListener("click", () => {
          box.hidden = true;
          if (typeof go === "function") go("vault", false);
          select(node.id, true);
        });
        results.appendChild(button);
      }
    };
    input.oninput = paint;
    paint();
  }

  // Function to compare two kill chains (Jaccard + Score.mountCompare)
  async function runCompare() {
    const a = $("compare-a").value;
    const b = $("compare-b").value;
    const out = $("vault-compare-out");
    out.hidden = false;
    out.innerHTML = "Comparing…";
    try {
      const data = await fetchJson(`/api/killchains/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}&normalize=${normalizeTypos ? "1" : "0"}`);
      out.innerHTML = `
        <div class="panel-title">Compare · Jaccard ${data.jaccard}</div>
        <p class="lede">${escapeHtml(data.a.name)} (${data.a.count}) vs ${escapeHtml(data.b.name)} (${data.b.count})</p>
        <div id="score-compare-root"></div>
        <p><strong>Shared</strong> ${data.shared.map((id) => escapeHtml(id)).join(", ") || "none"}</p>
        <p><strong>Only A</strong> ${data.only_a.map((id) => escapeHtml(id)).join(", ") || "none"}</p>
        <p><strong>Only B</strong> ${data.only_b.map((id) => escapeHtml(id)).join(", ") || "none"}</p>
      `;
      if (data.scores && window.Score) {
        window.Score.mountCompare($("score-compare-root"), data.scores, {
          onTech: (techId) => select(`tech:${techId}`, true),
        });
      }
    } catch (error) {
      out.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }

  // Function to fingerprint the index (node+edge ids, for no-op refresh)
  function indexFingerprint(vault) {
    const nodes = (vault.nodes || []).map((node) => node.id).sort().join("|");
    const edges = (vault.edges || []).map((edge) => edge.id).sort().join("|");
    return `${nodes}#${edges}`;
  }

  // Function to pull /api/vault + /api/killchains and refresh the pane
  async function refresh(force = false) {
    const [vault, chains] = await Promise.all([
      fetchJson("/api/vault"),
      fetchJson("/api/killchains"),
    ]);
    const fingerprint = indexFingerprint(vault);
    const unchanged = fingerprint === lastIndexFp && loaded;
    index = vault;
    catalog = chains;
    lastIndexFp = fingerprint;
    $("vault-disclaimer").textContent = vault.disclaimer || chains.disclaimer || "";
    if (!graph && $("vault-graph")) {
      graph = GraphCanvas.mount($("vault-graph"));
      graph.onSelect((node) => {
        if (node) select(node.id, true);
      });
    }
    if (unchanged && !force) {
      // Same index as last pass — skip the GraphCanvas write
      loaded = true;
      return;
    }
    fillCompareSelects();
    renderQuality();
    applyGraph();
    renderFilters();
    renderTree();
    renderList();
    renderLinks();
    loaded = true;
  }

  // Function to lazy-load the vault the first time the tab is shown
  function ensure() {
    return loaded ? Promise.resolve() : refresh(true);
  }

  // Function to bind vault chrome (modes, raw, compare, ⌘P, mobile swap)
  function bind() {
    $("vault-mode-vault")?.addEventListener("click", () => {
      mode = "vault";
      $("vault-mode-vault").classList.add("active");
      $("vault-mode-local").classList.remove("active");
      graph?.setMode("vault");
      applyGraph();
    });
    $("vault-mode-local")?.addEventListener("click", () => {
      mode = "local";
      $("vault-mode-local").classList.add("active");
      $("vault-mode-vault").classList.remove("active");
      graph?.setMode("local");
      applyGraph();
    });
    $("vault-raw-btn")?.addEventListener("click", () => {
      rawMode = !rawMode;
      if (selectedId) loadNote(selectedId);
    });
    $("vault-switcher-btn")?.addEventListener("click", openSwitcher);
    $("vault-quality-btn")?.addEventListener("click", () => {
      const panel = $("vault-quality");
      panel.hidden = !panel.hidden;
    });
    $("compare-go")?.addEventListener("click", runCompare);
    $("normalize-typos")?.addEventListener("change", (event) => {
      normalizeTypos = event.target.checked;
      applyGraph();
    });
    $("dread-slider")?.addEventListener("input", (event) => {
      dreadMin = Number(event.target.value);
      $("dread-value").textContent = String(dreadMin);
      applyGraph();
    });
    document.addEventListener("keydown", (event) => {
      // ⌘P / Ctrl+P opens the switcher instead of print
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "p") {
        event.preventDefault();
        if (typeof go === "function") go("vault", false);
        openSwitcher();
      }
      if (event.key === "Escape") $("switcher").hidden = true;
    });
    $("switcher")?.addEventListener("click", (event) => {
      if (event.target.id === "switcher") $("switcher").hidden = true;
    });
    const mobile = window.matchMedia("(max-width: 760px)");
    const syncMobile = () => {
      // Under 760px the graph hides and the list takes its place
      const graphEl = $("vault-graph");
      const listEl = $("vault-list");
      if (!graphEl || !listEl) return;
      graphEl.hidden = mobile.matches;
      listEl.hidden = !mobile.matches;
    };
    mobile.addEventListener("change", syncMobile);
    syncMobile();
  }

  // Function to open a note from #vault/type/id
  function openFromHash(rest) {
    if (!rest) return;
    const [type, ...tail] = rest.split("/");
    const id = tail.length ? `${type}:${tail.join("/")}` : rest;
    if (nodeById(id) || id.includes(":")) select(id, false);
  }

  // Public surface app.js calls after bind()
  const api = { refresh, ensure, bind, openFromHash, openSwitcher, select, runCompare };
  window.Vault = api;
  return api;
})();

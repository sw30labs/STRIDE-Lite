/*
STRIDE-Lite Campaign Score Viewer

Interactive SVG for a Campaign Score IR. I wrote this so vault.js can
hand over a compiled score and get a phase × lane grid back, plus
sequence and storyboard tabs when the IR attached those views.
PLAY walks the spine; +N opens toolbox chips for that phase.

Notes:
- Geometry comes from the IR lists, not an LLM. campaign_score.py is
  the source of truth; score_export.py paints the same grid statically.
- One lead glyph per cell: climax, then spine, then first. The rest
  sit in toolbox overflow.
- Phase order inferred from T-IDs is a placement heuristic, not a
  proven kill chain — the banner says so.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
*/
window.Score = (() => {
  // Constants for glyph path fragments (same `d` keys the IR already chose)
  const ICONS = {
    user: "M8 7a4 4 0 1 0 8 0a4 4 0 0 0 -8 0 M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2",
    mail: "M3 7a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v10a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-10 M3 7l9 6l9 -6",
    terminal: "M5 7l5 5l-5 5 M12 19h7",
    lock: "M5 13a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-6 M8 11v-4a4 4 0 1 1 8 0v4",
    key: "M8 15a4 4 0 1 0 8 0a4 4 0 1 0 -8 0 M16.5 9.5l3.5 -3.5l-2 -2 M18 7l2 2",
    globe: "M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0 M3.6 9h16.8 M3.6 15h16.8 M11.5 3a17 17 0 0 0 0 18 M12.5 3a17 17 0 0 1 0 18",
    cloud: "M6.7 18c-2.6 0 -4.7 -2 -4.7 -4.5s2.1 -4.5 4.7 -4.5c.4 -1.8 1.8 -3.2 3.7 -3.8c1.9 -.6 4 -.2 5.4 1c1.5 1.2 2.2 3 1.8 4.8h1c1.9 0 3.5 1.6 3.5 3.5s-1.6 3.5 -3.5 3.5h-11.9",
    database: "M4 6a8 3 0 1 0 16 0a8 3 0 1 0 -16 0 M4 6v6a8 3 0 0 0 16 0v-6 M4 12v6a8 3 0 0 0 16 0v-6",
    bug: "M9 9v-1a3 3 0 0 1 6 0v1 M8 9h8a6 6 0 0 1 1 3v3a5 5 0 0 1 -10 0v-3a6 6 0 0 1 1 -3 M3 13h4 M17 13h4 M12 20v-6",
    alert: "M12 9v4 M10.4 3.6l-8.1 13.5a1.9 1.9 0 0 0 1.6 2.9h16.2a1.9 1.9 0 0 0 1.6 -2.9l-8.1 -13.5a1.9 1.9 0 0 0 -3.3 0 M12 16h.01",
    robot: "M6 6a2 2 0 0 1 2 -2h8a2 2 0 0 1 2 2v4a2 2 0 0 1 -2 2h-8a2 2 0 0 1 -2 -2z M12 2v2 M9 12v9 M15 12v9 M10 8h.01 M14 8h.01",
    file: "M14 3v4a1 1 0 0 0 1 1h4 M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2",
    server: "M3 7a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3 M3 15a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3",
  };

  // Function to HTML-escape SVG text (T-IDs land in attributes; unescaped < would split the markup)
  function esc(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // Function to wrap a path `d` in a translated <g> (0.55 fits the 36px cell)
  function iconMarkup(name, x, y, color, scale = 0.55) {
    const d = ICONS[name] || ICONS.terminal;
    return `<g transform="translate(${x},${y}) scale(${scale})" fill="none" stroke="${color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="${d}"/></g>`;
  }

  // Function to trigger a blob download (revoke after click so we don't leak object URLs)
  function download(filename, text, type) {
    const blob = new Blob([text], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  }

  // Function to serialize an SVG node (xmlns so Inkscape / browsers treat it as SVG, not HTML)
  function serializeSvg(svg) {
    const clone = svg.cloneNode(true);
    if (!clone.getAttribute("xmlns")) clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    return `<?xml version="1.0" encoding="UTF-8"?>\n${clone.outerHTML}`;
  }

  // Function to rasterize SVG via canvas (2× viewBox; paper fill so PNG isn't transparent)
  function exportPng(svg, filename) {
    const xml = serializeSvg(svg);
    const blob = new Blob([xml], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const image = new Image();
    image.onload = () => {
      const canvas = document.createElement("canvas");
      const box = svg.viewBox.baseVal;
      canvas.width = Math.max(box.width, 1) * 2;
      canvas.height = Math.max(box.height, 1) * 2;
      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#04060c";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
      canvas.toBlob((png) => {
        if (!png) return;
        const href = URL.createObjectURL(png);
        const link = document.createElement("a");
        link.href = href;
        link.download = filename;
        link.click();
        URL.revokeObjectURL(href);
        URL.revokeObjectURL(url);
      }, "image/png");
    };
    image.onerror = () => URL.revokeObjectURL(url);
    image.src = url;
  }

  // Phase × lane grid from the IR (same cell sizes as score_export.py)
  function gridSvg(score, state, highlight) {
    const phases = score.phases || [];
    const lanes = score.lanes || [];
    const labelW = 56;
    const colW = 92;
    const rowH = 44;
    const headH = 28;
    const width = labelW + phases.length * colW + 8;
    const height = headH + lanes.length * rowH + 8;
    // PLAY cursor: the spine glyph at state.index (column highlight follows this)
    const current = (score.spine || [])
      .map((id) => score.glyphs.find((item) => item.id === id))
      .filter(Boolean)[state.index];
    const cells = [];
    for (let c = 0; c < phases.length; c += 1) {
      const phase = phases[c];
      const x = labelW + c * colW;
      cells.push(
        `<rect class="score-col${phase.id === current?.phase ? " is-current" : ""}" x="${x}" y="${headH - 4}" width="${colW}" height="${lanes.length * rowH + 4}" rx="4"/>`,
      );
      cells.push(`<text class="score-phase" x="${x + colW / 2}" y="16">${esc(phase.label)}</text>`);
      for (let r = 0; r < lanes.length; r += 1) {
        const lane = lanes[r];
        const y = headH + r * rowH;
        if (c === 0) cells.push(`<text class="score-lane" x="6" y="${y + 26}">${esc(lane.label)}</text>`);
        const here = (score.glyphs || []).filter((item) => item.phase === phase.id && item.lane === lane.id);
        // Prefer climax, then spine, then first glyph (one lead per occupied cell)
        const lead = here.find((item) => item.role === "climax") || here.find((item) => item.role === "spine") || here[0];
        if (!lead) continue;
        const extras = here.filter((item) => item.id !== lead.id);
        const shared = highlight.has(lead.tech_id);
        // Climax is amber; shared T-IDs (compare) are green; current spine step is teal
        const color = lead.role === "climax" ? "#fbbf24" : shared ? "#34d399" : current && lead.id === current.id ? "#5eead4" : "#8493aa";
        cells.push(`<g class="score-glyph${lead.role === "climax" ? " is-climax" : ""}${shared ? " is-shared" : ""}" data-tech="${esc(lead.tech_id)}">
          <rect x="${x + 6}" y="${y + 4}" width="${colW - 12}" height="36" rx="4"/>
          ${iconMarkup(lead.icon, x + 10, y + 10, color)}
          <text class="score-tid" x="${x + 28}" y="${y + 18}">${esc(lead.tech_id || "—")}</text>
          <text class="score-lab" x="${x + 28}" y="${y + 30}">${esc(lead.label)}</text>
        </g>`);
        if (extras.length) {
          // +N overflow; click opens toolbox chips for this phase
          cells.push(`<text class="score-more" data-phase="${esc(phase.id)}" x="${x + colW - 14}" y="${y + 14}">+${extras.length}</text>`);
        }
      }
    }
    return { width, height, body: cells.join("") };
  }

  // Sequence view (actor lifelines + messages; null if the IR omitted the view)
  function sequenceSvg(score) {
    const view = score.views?.sequence;
    if (!view?.available) return null;
    const actors = view.actors || [];
    const messages = view.messages || [];
    const left = 24;
    const col = 88;
    const top = 36;
    const row = 28;
    const width = left + actors.length * col + 16;
    const height = top + messages.length * row + 16;
    const xs = Object.fromEntries(actors.map((actor, index) => [actor.id, left + index * col + col / 2]));
    const parts = actors.map((actor, index) => {
      const x = xs[actor.id];
      return `<text class="score-phase" x="${x}" y="16">${esc(actor.label)}</text>
        <line class="score-life" x1="${x}" y1="${top - 8}" x2="${x}" y2="${height - 8}"/>`;
    });
    messages.forEach((message, index) => {
      const y = top + index * row;
      // Fallback if from/to is missing — attacker column is the usual left edge
      const x1 = xs[message.from] ?? xs.attacker;
      const x2 = xs[message.to] ?? x1;
      const color = message.climax ? "#fbbf24" : "#5eead4";
      const dir = x2 >= x1 ? 1 : -1;
      parts.push(`<line class="score-msg" x1="${x1}" y1="${y}" x2="${x2 - 6 * dir}" y2="${y}" stroke="${color}"/>`);
      parts.push(`<polygon points="${x2},${y} ${x2 - 6 * dir},${y - 3} ${x2 - 6 * dir},${y + 3}" fill="${color}"/>`);
      parts.push(`<text class="score-tid" x="${(x1 + x2) / 2}" y="${y - 4}" text-anchor="middle">${esc(message.tech_id)} ${esc(message.label)}</text>`);
    });
    return { width, height, body: parts.join("") };
  }

  // Storyboard view (spine frames only; collapsed banner is set on the IR)
  function storyboardSvg(score) {
    const view = score.views?.storyboard;
    if (!view?.available) return null;
    const frames = view.frames || [];
    const cardW = 112;
    const gap = 10;
    const height = 108;
    const width = 8 + frames.length * (cardW + gap);
    const parts = frames.map((frame, index) => {
      const x = 8 + index * (cardW + gap);
      const color = frame.climax ? "#fbbf24" : "#5eead4";
      return `<g class="score-glyph" data-tech="${esc(frame.tech_id)}">
        <rect x="${x}" y="8" width="${cardW}" height="92" rx="6"/>
        <text class="score-phase" x="${x + 10}" y="22">${esc(String(frame.n).padStart(2, "0"))}</text>
        ${iconMarkup(frame.icon, x + 44, 28, color, 0.9)}
        <text class="score-tid" x="${x + 10}" y="72">${esc(frame.tech_id)}</text>
        <text class="score-lab" x="${x + 10}" y="86">${esc(frame.title)}</text>
      </g>`;
    });
    return { width, height, body: parts.join("") };
  }

  // Public surface vault.js calls after a killchain note loads
  function mount(root, score, options = {}) {
    if (!root || !score) return null;
    const highlight = new Set(options.highlightIds || []);
    const state = {
      index: 0,
      openPhase: null,
      score,
      timer: null,
      view: options.view || "grid",
    };
    const onTech = options.onTech || (() => {});
    // Compact mode drops tabs and PLAY (compare pane has two grids side by side)
    const compact = Boolean(options.compact);
    const slug = score.slug || "score";

    // Function to resolve spine ids onto glyphs (PLAY walks this list)
    function spineGlyphs() {
      return (score.spine || []).map((id) => score.glyphs.find((item) => item.id === id)).filter(Boolean);
    }

    // Function to pick the SVG body for the current tab
    function currentSvg() {
      if (state.view === "sequence") return sequenceSvg(score);
      if (state.view === "storyboard") return storyboardSvg(score);
      return gridSvg(score, state, highlight);
    }

    function render() {
      const drawn = currentSvg();
      const seqOn = score.views?.sequence?.available;
      const storyOn = score.views?.storyboard?.available;
      const toolbox = state.openPhase
        ? (score.glyphs || []).filter((item) => item.phase === state.openPhase && item.role === "toolbox")
        : [];
      const tabs = compact
        ? ""
        : `<div class="score-tabs">
            <button type="button" class="segment${state.view === "grid" ? " active" : ""}" data-view="grid">SCORE</button>
            ${seqOn ? `<button type="button" class="segment${state.view === "sequence" ? " active" : ""}" data-view="sequence">SEQUENCE</button>` : ""}
            ${storyOn ? `<button type="button" class="segment${state.view === "storyboard" ? " active" : ""}" data-view="storyboard">STORYBOARD</button>` : ""}
          </div>`;
      const controls = state.view === "grid" && !compact
        ? `<div class="score-controls">
            <button type="button" class="btn ghost" data-score="prev">PREV</button>
            <button type="button" class="btn ghost" data-score="play">PLAY</button>
            <button type="button" class="btn ghost" data-score="next">NEXT</button>
            <span class="score-pos">${state.index + 1} / ${Math.max(spineGlyphs().length, 1)}</span>
            <button type="button" class="btn ghost" data-score="svg">SVG</button>
            <button type="button" class="btn ghost" data-score="png">PNG</button>
          </div>`
        : compact
          ? ""
          : `<div class="score-controls">
              <button type="button" class="btn ghost" data-score="svg">SVG</button>
              <button type="button" class="btn ghost" data-score="png">PNG</button>
            </div>`;
      root.innerHTML = `
        <div class="score-wrap">
          ${score.inferred && !compact ? `<p class="score-banner">Phase order inferred from T-IDs, not a proven kill chain.</p>` : ""}
          ${tabs}
          ${score.views?.storyboard?.collapsed && state.view === "storyboard" ? `<p class="lede dim">Storyboard is the spine, not every technique.</p>` : ""}
          <svg class="score-svg" viewBox="0 0 ${drawn.width} ${drawn.height}" role="img" aria-label="${esc(score.name || "Campaign score")}">${drawn.body}</svg>
          ${controls}
          ${
            toolbox.length
              ? `<div class="score-toolbox">${toolbox
                  .map((item) => `<button type="button" class="score-chip" data-tech="${esc(item.tech_id)}">${esc(item.tech_id)} ${esc(item.label)}</button>`)
                  .join("")}</div>`
              : ""
          }
        </div>
      `;
      // Re-bind every pass (innerHTML wipes the previous listeners)
      root.querySelectorAll("[data-view]").forEach((button) => {
        button.addEventListener("click", () => {
          state.view = button.getAttribute("data-view");
          render();
        });
      });
      root.querySelectorAll(".score-glyph").forEach((node) => {
        node.addEventListener("click", () => {
          const tech = node.getAttribute("data-tech");
          if (tech) onTech(tech);
        });
      });
      root.querySelectorAll(".score-more").forEach((node) => {
        node.addEventListener("click", (event) => {
          event.stopPropagation();
          const phase = node.getAttribute("data-phase");
          state.openPhase = state.openPhase === phase ? null : phase;
          render();
        });
      });
      root.querySelectorAll(".score-chip").forEach((node) => {
        node.addEventListener("click", () => {
          const tech = node.getAttribute("data-tech");
          if (tech) onTech(tech);
        });
      });
      root.querySelector('[data-score="prev"]')?.addEventListener("click", () => step(-1));
      root.querySelector('[data-score="next"]')?.addEventListener("click", () => step(1));
      root.querySelector('[data-score="play"]')?.addEventListener("click", play);
      root.querySelector('[data-score="svg"]')?.addEventListener("click", () => {
        const svg = root.querySelector("svg.score-svg");
        if (svg) download(`${slug}-${state.view}.svg`, serializeSvg(svg), "image/svg+xml");
      });
      root.querySelector('[data-score="png"]')?.addEventListener("click", () => {
        const svg = root.querySelector("svg.score-svg");
        if (svg) exportPng(svg, `${slug}-${state.view}.png`);
      });
    }

    // Function to step the PLAY cursor (clamp to spine length)
    function step(delta) {
      const max = Math.max(spineGlyphs().length - 1, 0);
      state.index = Math.min(max, Math.max(0, state.index + delta));
      render();
    }

    // Function to play the spine at 700ms (clears any leftover interval first)
    function play() {
      if (state.timer) window.clearInterval(state.timer);
      state.index = 0;
      render();
      const total = spineGlyphs().length;
      let tick = 0;
      state.timer = window.setInterval(() => {
        tick += 1;
        if (tick >= total) {
          window.clearInterval(state.timer);
          state.timer = null;
          return;
        }
        state.index = tick;
        render();
      }, 700);
    }

    render();
    return { next: () => step(1), prev: () => step(-1) };
  }

  // Side-by-side compact grids (green = Jaccard shared T-IDs)
  function mountCompare(root, payload, options = {}) {
    if (!root || !payload?.a || !payload?.b) return null;
    const shared = payload.shared || [];
    root.innerHTML = `
      <div class="score-compare">
        <div>
          <div class="panel-title flush">${esc(payload.a.name)}</div>
          <div data-score-a></div>
        </div>
        <div>
          <div class="panel-title flush">${esc(payload.b.name)}</div>
          <div data-score-b></div>
        </div>
      </div>
      <p class="lede dim">Shared ${shared.length} · Jaccard ${payload.jaccard} · green = in both</p>
    `;
    mount(root.querySelector("[data-score-a]"), payload.a, { ...options, highlightIds: shared, compact: true, view: "grid" });
    mount(root.querySelector("[data-score-b]"), payload.b, { ...options, highlightIds: shared, compact: true, view: "grid" });
  }

  return { mount, mountCompare };
})();

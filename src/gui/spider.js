/*
STRIDE-Lite Catalog Map

Polar + ternary SVG for the vault catalog. Geometry comes from
catalog_map.py — this file paints slices, rings, and dots. I wrote
it so vault mode can stop using a force-directed pile of labels.

Notes:
- Polar: six fixed wedges, radius = data/cloud share.
- Ternary: Human / Infra / Data (the 3-axis view, still 2D).
- LOCAL 1-hop still belongs to vis-network (graph.js).

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
*/
window.CatalogMap = (() => {
  let host = null;
  let svg = null;
  let tip = null;
  let legend = null;
  let caption = null;
  let ir = { slices: [], points: [], rings: [], polar: {}, ternary: {} };
  let layout = "polar";
  let visible = null;
  let selected = null;
  let sliceFilter = new Set();
  let onSelect = () => {};
  let onSlice = () => {};

  const INNER = 0.18;
  const RIM = {
    identity: "IDENTITY",
    exploit: "EXPLOIT",
    espionage: "ESPIONAGE",
    "cloud-api": "CLOUD",
    "agent-ai": "AGENT",
    ransomware: "RANSOM",
  };

  function esc(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function shortLabel(name) {
    const text = String(name || "").replace(/\s*\[.*?\]\s*$/, "");
    return text.length <= 28 ? text : `${text.slice(0, 26).trim()}…`;
  }

  function visiblePoints() {
    const points = ir.points || [];
    return points.filter((point) => {
      if (visible && !visible.has(point.id)) return false;
      if (sliceFilter.size && !sliceFilter.has(point.slice)) return false;
      return true;
    });
  }

  function wedgePath(start, end, r0, r1) {
    const large = end - start > Math.PI ? 1 : 0;
    const pt = (radius, theta) => [radius * Math.cos(theta), radius * Math.sin(theta)];
    const [ax, ay] = pt(r0, start);
    const [bx, by] = pt(r1, start);
    const [cx, cy] = pt(r1, end);
    const [dx, dy] = pt(r0, end);
    return `M ${ax} ${ay} L ${bx} ${by} A ${r1} ${r1} 0 ${large} 1 ${cx} ${cy} L ${dx} ${dy} A ${r0} ${r0} 0 ${large} 0 ${ax} ${ay} Z`;
  }

  function ternaryY(y) {
    return 0.86602540378 - y;
  }

  function showTip(point, event) {
    if (!tip || !point) return;
    const pct = (value) => `${Math.round((value || 0) * 100)}%`;
    tip.hidden = false;
    tip.innerHTML = `<strong>${esc(point.name)}</strong>
      <span>${esc(point.slice_label)}</span>
      <span>H ${pct(point.human)} · I ${pct(point.infra)} · D ${pct(point.data)}</span>
      <span>${point.step_count} techniques</span>`;
    const stage = host.getBoundingClientRect();
    const x = event.clientX - stage.left + 12;
    const y = event.clientY - stage.top + 12;
    tip.style.left = `${Math.min(x, stage.width - 240)}px`;
    tip.style.top = `${Math.min(y, stage.height - 90)}px`;
  }

  function hideTip() {
    if (tip) tip.hidden = true;
  }

  function paintLegend() {
    if (!legend) return;
    legend.innerHTML = (ir.slices || [])
      .map((slice) => {
        const active = !sliceFilter.size || sliceFilter.has(slice.id);
        return `<button type="button" class="spider-leg ${active ? "is-on" : ""}" data-slice="${esc(slice.id)}">
          <i style="background:${esc(slice.color)}"></i>${esc(slice.label)}
        </button>`;
      })
      .join("");
    legend.querySelectorAll("[data-slice]").forEach((button) => {
      button.addEventListener("click", (event) => {
        event.stopPropagation();
        toggleSlice(button.dataset.slice);
      });
    });
  }

  function toggleSlice(sliceId) {
    if (sliceFilter.has(sliceId)) sliceFilter.delete(sliceId);
    else sliceFilter.add(sliceId);
    onSlice([...sliceFilter]);
    paint();
  }

  function polarMarkup(points) {
    const slices = ir.slices || [];
    const rings = ir.rings || [];
    const inner = INNER;
    const outer = (ir.polar && ir.polar.outer) || 0.9;
    const wedges = slices
      .map((slice, index) => {
        const active = !sliceFilter.size || sliceFilter.has(slice.id);
        const mid = (slice.theta_start + slice.theta_end) / 2;
        const lx = 1.14 * Math.cos(mid);
        const ly = 1.14 * Math.sin(mid);
        const rim = RIM[slice.id] || slice.label;
        return `<path class="spider-wedge ${active ? "is-on" : "is-off"}" data-slice="${esc(slice.id)}" d="${wedgePath(slice.theta_start, slice.theta_end, inner, outer)}" fill="${esc(slice.color)}" stroke="rgba(215,227,244,0.12)" stroke-width="0.006" />
          <text class="spider-slice-lab ${active ? "is-on" : "is-off"}" data-slice="${esc(slice.id)}" x="${lx}" y="${ly}" text-anchor="middle" dominant-baseline="middle" fill="${esc(slice.color)}" font-size="0.068" font-family="ui-monospace, SF Mono, monospace" stroke="#04060c" stroke-width="0.016" paint-order="stroke">${esc(rim)}</text>
          <path class="spider-spoke" d="M 0 0 L ${outer * Math.cos(slice.theta_start)} ${outer * Math.sin(slice.theta_start)}" fill="none" stroke="rgba(94,234,212,0.14)" stroke-width="0.006" />`;
      })
      .join("");
    const ringMarks = rings
      .map((ring) => `<circle class="spider-ring" r="${ring.r}" fill="none" stroke="rgba(94,234,212,0.16)" stroke-width="0.007" stroke-dasharray="0.028 0.02" />`)
      .join("");
    const hub = `<circle class="spider-hub" r="${inner}" fill="rgba(8,12,22,0.94)" stroke="rgba(94,234,212,0.32)" stroke-width="0.012" />
      <text class="spider-hub-count" x="0" y="-0.015" text-anchor="middle" fill="#fff" font-size="0.1" font-family="ui-monospace, SF Mono, monospace">${points.length}</text>
      <text class="spider-hub-lab" x="0" y="0.07" text-anchor="middle" fill="#77869e" font-size="0.04" font-family="ui-monospace, SF Mono, monospace">${points.length === 1 ? "CHAIN" : "CHAINS"}</text>`;
    const dots = points
      .map((point, index) => {
        const isSel = point.id === selected;
        const delay = (point.slice_index || 0) * 40 + index * 8;
        const lab = isSel
          ? `<text class="spider-dot-lab" x="${(point.polar_r + 0.1) * Math.cos(point.theta)}" y="${(point.polar_r + 0.1) * Math.sin(point.theta)}" text-anchor="middle" fill="#fff" font-size="0.055" font-family="-apple-system, Segoe UI, sans-serif">${esc(shortLabel(point.name))}</text>`
          : "";
        return `<g class="spider-dot ${isSel ? "is-selected" : ""}" data-id="${esc(point.id)}" style="--in:${delay}ms">
          <circle class="spider-hit" cx="${point.polar_x}" cy="${point.polar_y}" r="0.08" fill="transparent" />
          <circle class="spider-glow" cx="${point.polar_x}" cy="${point.polar_y}" r="${(point.dot_r || 0.05) * 1.8}" fill="${esc(point.color)}" />
          <circle class="spider-core" cx="${point.polar_x}" cy="${point.polar_y}" r="${point.dot_r || 0.05}" fill="${esc(point.color)}" stroke="${isSel ? "#fff" : "rgba(4,8,16,0.85)"}" stroke-width="${isSel ? 0.012 : 0.008}" />
          ${lab}
        </g>`;
      })
      .join("");
    return `<g class="spider-polar">${wedges}${ringMarks}${hub}${dots}</g>`;
  }

  function ternaryMarkup(points) {
    const H = 0.86602540378;
    const human = [0.5, ternaryY(H)];
    const infra = [0.0, ternaryY(0)];
    const data = [1.0, ternaryY(0)];
    const tri = `${human[0]},${human[1]} ${infra[0]},${infra[1]} ${data[0]},${data[1]}`;
    const grid = [0.25, 0.5, 0.75]
      .map((t) => {
        const a = [t * 0.5, ternaryY(t * H)];
        const b = [1 - t * 0.5, ternaryY(t * H)];
        const c = [t, ternaryY(0)];
        const d = [0.5 + t * 0.5, ternaryY((1 - t) * H)];
        const e = [t * 0.5, ternaryY((1 - t) * H)];
        const f = [t, ternaryY(0)];
        return `<line class="spider-tgrid" x1="${a[0]}" y1="${a[1]}" x2="${b[0]}" y2="${b[1]}" stroke="rgba(94,234,212,0.14)" stroke-width="0.006" />
          <line class="spider-tgrid" x1="${c[0]}" y1="${c[1]}" x2="${d[0]}" y2="${d[1]}" stroke="rgba(94,234,212,0.14)" stroke-width="0.006" />
          <line class="spider-tgrid" x1="${e[0]}" y1="${e[1]}" x2="${f[0]}" y2="${f[1]}" stroke="rgba(94,234,212,0.14)" stroke-width="0.006" />`;
      })
      .join("");
    const verts = `
      <text class="spider-tlab" x="0.5" y="${human[1] - 0.05}" text-anchor="middle" fill="#fbbf24" font-size="0.05" font-family="ui-monospace, SF Mono, monospace">HUMAN</text>
      <text class="spider-tlab" x="-0.02" y="${infra[1] + 0.07}" text-anchor="start" fill="#22d3ee" font-size="0.05" font-family="ui-monospace, SF Mono, monospace">INFRA</text>
      <text class="spider-tlab" x="1.02" y="${data[1] + 0.07}" text-anchor="end" fill="#5eead4" font-size="0.05" font-family="ui-monospace, SF Mono, monospace">DATA</text>`;
    const dots = points
      .map((point, index) => {
        const x = point.ternary_x;
        const y = ternaryY(point.ternary_y);
        const isSel = point.id === selected;
        const delay = (point.slice_index || 0) * 40 + index * 8;
        const lab = isSel
          ? `<text class="spider-dot-lab" x="${x}" y="${y - 0.045}" text-anchor="middle" fill="#fff" font-size="0.04" font-family="-apple-system, Segoe UI, sans-serif">${esc(shortLabel(point.name))}</text>`
          : "";
        return `<g class="spider-dot ${isSel ? "is-selected" : ""}" data-id="${esc(point.id)}" style="--in:${delay}ms">
          <circle class="spider-glow" cx="${x}" cy="${y}" r="${(point.dot_r || 0.04) * 1.7}" fill="${esc(point.color)}" />
          <circle class="spider-core" cx="${x}" cy="${y}" r="${(point.dot_r || 0.04) * 0.9}" fill="${esc(point.color)}" stroke="${isSel ? "#fff" : "rgba(4,8,16,0.85)"}" stroke-width="${isSel ? 0.01 : 0.006}" />
          ${lab}
        </g>`;
      })
      .join("");
    return `<g class="spider-ternary" transform="translate(0,0.04)">
      <polygon class="spider-triangle" points="${tri}" fill="rgba(94,234,212,0.05)" stroke="rgba(94,234,212,0.38)" stroke-width="0.012" />
      ${grid}${verts}${dots}
    </g>`;
  }

  function bindDots() {
    svg.querySelectorAll(".spider-dot").forEach((node) => {
      const id = node.getAttribute("data-id");
      const point = (ir.points || []).find((item) => item.id === id);
      node.addEventListener("click", (event) => {
        event.stopPropagation();
        selected = id;
        onSelect(point || { id });
        paint();
      });
      node.addEventListener("mouseenter", (event) => showTip(point, event));
      node.addEventListener("mousemove", (event) => showTip(point, event));
      node.addEventListener("mouseleave", hideTip);
    });
    svg.querySelectorAll("[data-slice]").forEach((node) => {
      node.addEventListener("click", (event) => {
        event.stopPropagation();
        toggleSlice(node.getAttribute("data-slice"));
      });
    });
  }

  function paint() {
    if (!svg) return;
    const points = visiblePoints();
    const polarBox = "-1.38 -1.38 2.76 2.76";
    const ternaryBox = "-0.14 -0.16 1.28 1.18";
    svg.setAttribute("viewBox", layout === "ternary" ? ternaryBox : polarBox);
    svg.setAttribute("data-layout", layout);
    svg.innerHTML = `
      <defs>
        <filter id="spider-soft" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="0.012" />
        </filter>
      </defs>
      ${layout === "ternary" ? ternaryMarkup(points) : polarMarkup(points)}`;
    if (caption) {
      caption.textContent =
        layout === "ternary"
          ? "Human · Infra · Data  —  3-axis composition, still 2D"
          : "Radius = data/cloud share  ·  click a wedge to isolate a slice";
    }
    paintLegend();
    bindDots();
  }

  function mount(el) {
    host = el;
    el.classList.add("spider-host");
    el.innerHTML = `<div class="spider-stage">
      <svg class="spider-svg" viewBox="-1.38 -1.38 2.76 2.76" role="img" aria-label="Kill-chain catalog map"></svg>
      <div class="spider-tip" hidden></div>
    </div>
    <div class="spider-legend"></div>
    <div class="spider-caption"></div>`;
    svg = el.querySelector(".spider-svg");
    tip = el.querySelector(".spider-tip");
    legend = el.querySelector(".spider-legend");
    caption = el.querySelector(".spider-caption");
    svg.addEventListener("click", () => {
      selected = null;
      hideTip();
      onSelect(null);
      paint();
    });
    return api;
  }

  const api = {
    setMap(next) {
      ir = next || { slices: [], points: [], rings: [], polar: {}, ternary: {} };
      paint();
    },
    setLayout(next) {
      layout = next === "ternary" ? "ternary" : "polar";
      paint();
    },
    getLayout() {
      return layout;
    },
    setVisible(ids) {
      visible = ids ? new Set(ids) : null;
      paint();
    },
    setSelection(id) {
      selected = id || null;
      paint();
    },
    setSliceFilter(ids) {
      sliceFilter = new Set(ids || []);
      paint();
    },
    onSelect(fn) {
      onSelect = fn || (() => {});
    },
    onSlice(fn) {
      onSlice = fn || (() => {});
    },
    destroy() {
      if (host) host.innerHTML = "";
      host = svg = tip = legend = caption = null;
    },
  };

  return { mount };
})();

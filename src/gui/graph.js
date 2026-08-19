/*
STRIDE-Lite Vault Graph Canvas

vis-network wrapper for the vault pane. I wrote this so vault.js can
hand over nodes and edges and get a force-directed canvas back, without
talking to vis.Network itself. Two modes: vault (the whole graph) and
local (the selected node plus one hop).

Notes:
- vis-network is vendored at /vendor/vis-network.min.js. I used it for
  the DataSet add/remove API — setData would restart physics on every
  filter tick.
- If the script tag fails, mount() returns a no-op API and the list
  view still works.
- lastVisible is a fingerprint of the visible ids so a no-op render
  skips the DataSet write.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
*/
const GraphCanvas = (() => {
  // Constants for node-type colors (same hex as the vault list chips)
  const COLORS = {
    model: "#22d3ee",
    scenario: "#5eead4",
    killchain: "#a78bfa",
    app: "#8493aa",
    technique: "#fbbf24",
    threat: "#f87171",
    control: "#34d399",
    cve: "#fbbf24",
  };

  let network = null;
  let nodesDS = null;
  let edgesDS = null;
  let allNodes = [];
  let allEdges = [];
  let mode = "vault";
  let selected = null;
  let onSelect = () => {};
  // Fingerprint of last painted ids (avoids a no-op DataSet write)
  let lastVisible = "";

  // Function to build vis-network options (forceAtlas2Based clusters by type; 80-iter stabilize keeps the GUI snappy)
  function options() {
    return {
      autoResize: true,
      nodes: {
        shape: "dot",
        font: { color: "#d7e3f4", face: "SF Mono, ui-monospace, monospace", size: 12 },
        borderWidth: 1,
        shadow: false,
      },
      edges: {
        color: { color: "rgba(94,234,212,0.28)", highlight: "#22d3ee" },
        arrows: { to: { enabled: true, scaleFactor: 0.45 } },
        smooth: { type: "continuous" },
        width: 1,
      },
      physics: {
        solver: "forceAtlas2Based",
        forceAtlas2Based: { gravitationalConstant: -38, springLength: 110, springConstant: 0.06 },
        stabilization: { iterations: 80 },
      },
      interaction: { hover: true, tooltipDelay: 80 },
    };
  }

  // Function to map a vault node onto a vis DataSet item
  function visNode(node) {
    const color = COLORS[node.type] || COLORS.app;
    return {
      id: node.id,
      label: node.label,
      group: node.type,
      title: `${node.type} · ${node.label}`,
      color: { background: color, border: color, highlight: { background: color, border: "#fff" } },
      value: 12,
    };
  }

  // Local mode keeps the selected node plus one hop; vault mode shows everything
  function visibleSet() {
    if (mode !== "local" || !selected) {
      return new Set(allNodes.map((node) => node.id));
    }
    const ids = new Set([selected]);
    for (const edge of allEdges) {
      if (edge.from === selected) ids.add(edge.to);
      if (edge.to === selected) ids.add(edge.from);
    }
    return ids;
  }

  // Incremental DataSet update (setData would restart physics on every filter tick)
  function render(force) {
    if (!nodesDS) return;
    const allowed = visibleSet();
    const nextNodes = allNodes.filter((node) => allowed.has(node.id)).map(visNode);
    const nextEdges = allEdges.filter((edge) => allowed.has(edge.from) && allowed.has(edge.to));
    const mark = `${nextNodes.map((node) => node.id).sort().join("|")}#${nextEdges.map((edge) => edge.id).sort().join("|")}`;
    if (!force && mark === lastVisible) {
      // Same visible ids as last pass — skip the DataSet write
      syncSelection(allowed);
      return;
    }
    lastVisible = mark;
    const nextIds = new Set(nextNodes.map((node) => node.id));
    const prevIds = new Set(nodesDS.getIds());
    const removeNodes = [...prevIds].filter((id) => !nextIds.has(id));
    const addNodes = nextNodes.filter((node) => !prevIds.has(node.id));
    if (removeNodes.length) nodesDS.remove(removeNodes);
    if (addNodes.length) nodesDS.add(addNodes);
    const nextEdgeIds = new Set(nextEdges.map((edge) => edge.id));
    const prevEdgeIds = new Set(edgesDS.getIds());
    const removeEdges = [...prevEdgeIds].filter((id) => !nextEdgeIds.has(id));
    const addEdges = nextEdges.filter((edge) => !prevEdgeIds.has(edge.id));
    if (removeEdges.length) edgesDS.remove(removeEdges);
    if (addEdges.length) edgesDS.add(addEdges);
    syncSelection(allowed);
  }

  // Function to keep the vis highlight in step with selected
  function syncSelection(allowed) {
    if (!network) return;
    if (selected && allowed.has(selected)) {
      const current = network.getSelectedNodes()[0];
      if (current !== selected) network.selectNodes([selected]);
      return;
    }
    if (!selected && network.getSelectedNodes().length) network.unselectAll();
  }

  function mount(el) {
    if (!window.vis) {
      // Fallback if vis-network failed to load (script tag / CSP) — list view still works
      el.innerHTML = '<div class="empty">Graph library failed to load. Use the list.</div>';
      return {
        setGraph() {},
        setMode() {},
        setSelection() {},
        onSelect(fn) { onSelect = fn; },
        fit() {},
        destroy() {},
      };
    }
    nodesDS = new vis.DataSet([]);
    edgesDS = new vis.DataSet([]);
    // vis.Network owns the canvas; DataSets so later diffs stay cheap
    network = new vis.Network(el, { nodes: nodesDS, edges: edgesDS }, options());
    network.on("selectNode", (event) => {
      selected = event.nodes[0] || null;
      onSelect(allNodes.find((node) => node.id === selected) || null);
    });
    network.on("deselectNode", () => {
      selected = null;
      onSelect(null);
    });
    return api;
  }

  // Public surface vault.js calls after mount()
  const api = {
    setGraph({ nodes, edges }) {
      allNodes = nodes || [];
      allEdges = (edges || []).map((edge) => ({ ...edge, id: edge.id || `${edge.from}->${edge.to}` }));
      render(false);
    },
    setMode(next) {
      mode = next === "local" ? "local" : "vault";
      // Wipe the fingerprint so the next pass is forced
      lastVisible = "";
      render(true);
    },
    setSelection(id) {
      selected = id;
      if (mode === "local") {
        // In local mode a new selection changes the neighborhood, so re-render
        render(false);
        return;
      }
      syncSelection(visibleSet());
    },
    onSelect(fn) {
      onSelect = fn;
    },
    fit() {
      if (network) network.fit({ animation: false });
    },
    destroy() {
      if (network) network.destroy();
      network = null;
    },
  };

  return { mount };
})();

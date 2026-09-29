let cy = null;
let currentGraphData = null;

const typeColorMap = {
  DOMAIN: "#3b82f6",
  SUBDOMAIN: "#06b6d4",
  IP: "#10b981",
  ASN: "#a855f7",
  CLOUD_RESOURCE: "#f97316",
  DNS_RECORD: "#94a3b8"
};

const typeShapeMap = {
  DOMAIN: "hexagon",
  SUBDOMAIN: "round-rectangle",
  IP: "ellipse",
  ASN: "octagon",
  CLOUD_RESOURCE: "diamond",
  DNS_RECORD: "rectangle"
};

function initCytoscape() {
  cy = cytoscape({
    container: document.getElementById('cy'),
    style: [
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'color': '#f0f6fc',
          'font-size': '11px',
          'font-family': 'Fira Code, monospace',
          'text-valign': 'bottom',
          'text-margin-y': 6,
          'background-color': function(ele) {
            if (ele.data('risk') === 'CRITICAL') return '#ef4444';
            if (ele.data('risk') === 'HIGH') return '#f97316';
            return typeColorMap[ele.data('type')] || '#64748b';
          },
          'shape': function(ele) {
            return typeShapeMap[ele.data('type')] || 'ellipse';
          },
          'width': function(ele) {
            if (ele.data('type') === 'DOMAIN') return 42;
            if (ele.data('type') === 'ASN') return 36;
            return 28;
          },
          'height': function(ele) {
            if (ele.data('type') === 'DOMAIN') return 42;
            if (ele.data('type') === 'ASN') return 36;
            return 28;
          },
          'border-width': function(ele) {
            return ele.data('risk') === 'CRITICAL' ? 3 : 1;
          },
          'border-color': function(ele) {
            return ele.data('risk') === 'CRITICAL' ? '#ff7878' : '#30363d';
          },
          'overlay-padding': '4px'
        }
      },
      {
        selector: 'node[risk = "CRITICAL"]',
        style: {
          'background-color': '#ef4444',
          'border-color': '#fca5a5',
          'border-width': 3,
          'shadow-blur': 15,
          'shadow-color': '#ef4444',
          'shadow-opacity': 0.8
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 1.5,
          'line-color': '#334155',
          'target-arrow-color': '#475569',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'arrow-scale': 0.8,
          'label': 'data(label)',
          'color': '#64748b',
          'font-size': '9px',
          'text-rotation': 'autorotate',
          'text-margin-y': -6
        }
      },
      {
        selector: 'edge[type = "DANGLING_TARGET"]',
        style: {
          'width': 3,
          'line-color': '#ef4444',
          'line-style': 'dashed',
          'target-arrow-color': '#ef4444',
          'color': '#f87171',
          'font-weight': 'bold',
          'font-size': '10px'
        }
      },
      {
        selector: 'edge[type = "ALIAS_OF"]',
        style: {
          'line-style': 'dashed',
          'line-color': '#0284c7',
          'target-arrow-color': '#0284c7'
        }
      },
      {
        selector: ':selected',
        style: {
          'border-width': 4,
          'border-color': '#38bdf8',
          'shadow-blur': 12,
          'shadow-color': '#38bdf8'
        }
      }
    ],
    elements: [],
    layout: { name: 'cose', animate: false }
  });

  cy.on('tap', 'node', function(evt) {
    showNodeInspector(evt.target.data());
  });

  cy.on('tap', 'edge', function(evt) {
    showEdgeInspector(evt.target.data());
  });
}

function updateMetrics(stats) {
  if (!stats) return;
  document.getElementById('statNodes').textContent = stats.total_nodes || 0;
  document.getElementById('statSubdomains').textContent = stats.subdomains_count || 0;
  document.getElementById('statIPs').textContent = stats.ips_count || 0;
  document.getElementById('statASNs').textContent = stats.asns_count || 0;
  document.getElementById('statTakeovers').textContent = stats.dangling_records_count || 0;
}

function renderGraph(graphData) {
  currentGraphData = graphData;
  updateMetrics(graphData.stats);

  cy.elements().remove();
  cy.add(graphData.elements);

  applyLayout();
}

function applyLayout() {
  const layoutName = document.getElementById('layoutSelect').value;
  const layoutOptions = {
    name: layoutName,
    animate: true,
    animationDuration: 400,
    fit: true,
    padding: 50
  };

  if (layoutName === 'cose') {
    layoutOptions.nodeRepulsion = 450000;
    layoutOptions.idealEdgeLength = 80;
  }

  cy.layout(layoutOptions).run();
}

function showNodeInspector(node) {
  const drawer = document.getElementById('inspector');
  const title = document.getElementById('inspectorTitle');
  const content = document.getElementById('inspectorContent');

  title.textContent = `${node.type}: ${node.label}`;
  
  let html = `
    <div class="detail-section">
      <span class="detail-label">Asset Identifier</span>
      <div class="detail-value">${node.id}</div>
    </div>
    <div class="detail-section">
      <span class="detail-label">Risk Level</span>
      <div class="detail-value" style="color:${node.risk === 'CRITICAL' ? '#f87171' : (node.risk === 'HIGH' ? '#fb923c' : '#38bdf8')}">
        ${node.risk}
      </div>
    </div>
  `;

  if (node.attributes && node.attributes.dangling_vulnerability) {
    const v = node.attributes.dangling_vulnerability;
    html += `
      <div class="vuln-box">
        <div class="vuln-title">🚨 DANGLING SUBDOMAIN TAKEOVER</div>
        <div class="vuln-text"><strong>Service:</strong> ${v.cloud_service} (${v.provider})</div>
        <div class="vuln-text"><strong>Target:</strong> ${v.cname_target}</div>
        <div class="vuln-text" style="margin-top:4px;"><strong>Evidence:</strong> ${v.evidence}</div>
      </div>
      <div class="remediation-box">
        <strong>Remediation:</strong> ${v.remediation}
      </div>
    `;
  }

  if (node.attributes) {
    html += `<div class="detail-section"><span class="detail-label">Attributes & Telemetry</span>`;
    for (const [key, val] of Object.entries(node.attributes)) {
      if (key === 'dangling_vulnerability') continue;
      const formattedVal = Array.isArray(val) ? val.join(', ') : (typeof val === 'object' ? JSON.stringify(val) : val);
      html += `<div class="detail-value" style="margin-bottom:4px;"><strong>${key}:</strong> ${formattedVal}</div>`;
    }
    html += `</div>`;
  }

  content.innerHTML = html;
  drawer.style.display = 'flex';
}

function showEdgeInspector(edge) {
  const drawer = document.getElementById('inspector');
  const title = document.getElementById('inspectorTitle');
  const content = document.getElementById('inspectorContent');

  title.textContent = `Relation: ${edge.label || edge.type}`;
  let html = `
    <div class="detail-section">
      <span class="detail-label">Source Node</span>
      <div class="detail-value">${edge.source}</div>
    </div>
    <div class="detail-section">
      <span class="detail-label">Target Node</span>
      <div class="detail-value">${edge.target}</div>
    </div>
    <div class="detail-section">
      <span class="detail-label">Relation Type</span>
      <div class="detail-value">${edge.type}</div>
    </div>
  `;

  if (edge.attributes && edge.attributes.evidence) {
    html += `
      <div class="vuln-box">
        <div class="vuln-title">Takeover Finding</div>
        <div class="vuln-text">${edge.attributes.evidence}</div>
      </div>
      <div class="remediation-box">
        <strong>Fix:</strong> ${edge.attributes.remediation}
      </div>
    `;
  }

  content.innerHTML = html;
  drawer.style.display = 'flex';
}

async function loadSample() {
  showStatus("Loading demo attack surface graph...");
  try {
    const res = await fetch('/api/sample');
    const data = await res.json();
    renderGraph(data);
  } catch (err) {
    alert("Error loading sample: " + err);
  } finally {
    hideStatus();
  }
}

async function performScan() {
  const domain = document.getElementById('targetInput').value.trim();
  if (!domain) return alert("Please enter a target domain!");

  showStatus(`Scanning target '${domain}' (CT logs, DNS resolution, ASN mapping, Takeovers)...`);
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: domain, enable_bruteforce: true, concurrency: 50 })
    });
    const data = await res.json();
    renderGraph(data);
  } catch (err) {
    alert("Scan failed: " + err);
  } finally {
    hideStatus();
  }
}

function showStatus(text) {
  const banner = document.getElementById('statusBanner');
  document.getElementById('statusText').textContent = text;
  banner.classList.remove('hidden');
}

function hideStatus() {
  document.getElementById('statusBanner').classList.add('hidden');
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  initCytoscape();
  loadSample();

  document.getElementById('btnScan').addEventListener('click', performScan);
  document.getElementById('btnSample').addEventListener('click', loadSample);
  document.getElementById('layoutSelect').addEventListener('change', applyLayout);
  document.getElementById('btnFit').addEventListener('click', () => cy.fit());
  document.getElementById('btnCloseInspector').addEventListener('click', () => {
    document.getElementById('inspector').style.display = 'none';
  });

  document.getElementById('filterType').addEventListener('change', (e) => {
    const filter = e.target.value;
    if (filter === 'ALL') {
      cy.nodes().show();
      cy.edges().show();
    } else if (filter === 'CRITICAL') {
      cy.nodes().hide();
      cy.edges().hide();
      cy.nodes('[risk = "CRITICAL"], [risk = "HIGH"]').show();
      cy.edges('[type = "DANGLING_TARGET"]').show();
    } else {
      cy.nodes().hide();
      cy.edges().hide();
      cy.nodes(`[type = "${filter}"]`).show();
      cy.edges().show();
    }
  });

  document.getElementById('btnExportJson').addEventListener('click', () => {
    if (!currentGraphData) return;
    const blob = new Blob([JSON.stringify(currentGraphData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `infragraph-export-${Date.now()}.json`;
    a.click();
  });

  document.getElementById('btnExportDot').addEventListener('click', async () => {
    const res = await fetch('/api/export/dot');
    const data = await res.json();
    const blob = new Blob([data.dot], { type: 'text/vnd.graphviz' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `infragraph-${Date.now()}.dot`;
    a.click();
  });
});

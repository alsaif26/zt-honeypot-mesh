/* ==========================================================================
   Zero-Trust Honeypot Mesh — SOC Command Center front-end
   Every value rendered here comes from /api/stats. When the backend has no
   data for a field we render "N/A" or an empty state — never invented values.
   ========================================================================== */

(() => {
  "use strict";

  /* ---------------- state ---------------- */
  const state = {
    data: null,
    attacks: [],
    filtered: [],
    page: 1,
    pageSize: 25,
    sort: { key: "timestamp", dir: "desc" },
    refreshMs: 10000,
    timer: null,
    charts: {},
  };

  const $  = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  const COLORS = {
    ssh: "#f0883e", http: "#58a6ff", smb: "#3fb950",
    accent: "#4f9cf9",
    LOW: "#3fb950", MEDIUM: "#d29922", HIGH: "#f85149", CRITICAL: "#da3633",
    grid: "#1e2733", tick: "#8a97a8",
  };

  /* ---------------- helpers ---------------- */
  const NA = "N/A";

  function esc(value) {
    if (value === null || value === undefined || value === "") return "";
    return String(value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  const txt = (value) => (value === null || value === undefined || value === "" ? NA : esc(value));

  function fmtTime(iso) {
    if (!iso) return NA;
    const d = new Date(iso);
    if (isNaN(d)) return esc(iso);
    return d.toLocaleTimeString([], { hour12: false });
  }

  function fmtDateTime(iso) {
    if (!iso) return NA;
    const d = new Date(iso);
    if (isNaN(d)) return esc(iso);
    return d.toLocaleString([], { hour12: false });
  }

  function relative(iso) {
    if (!iso) return NA;
    const d = new Date(iso);
    if (isNaN(d)) return esc(iso);
    const secs = Math.round((Date.now() - d.getTime()) / 1000);
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
    return `${Math.round(secs / 86400)}d ago`;
  }

  function severityBadge(level) {
    if (!level) return `<span class="badge badge-NA">${NA}</span>`;
    return `<span class="badge badge-${esc(level)}">${esc(level)}</span>`;
  }

  function scoreCell(score) {
    if (score === null || score === undefined) return `<span class="muted">${NA}</span>`;
    const pct = Math.max(0, Math.min(100, Number(score)));
    const tone = pct >= 61 ? "high" : pct >= 31 ? "medium" : "low";
    return `<span class="score-cell">
        <span class="score-bar"><span class="score-fill ${tone}" style="width:${pct}%"></span></span>
        <span class="score-num">${pct}</span></span>`;
  }

  function techTag(id) {
    return id ? `<span class="tech-tag">${esc(id)}</span>` : `<span class="muted">${NA}</span>`;
  }

  function emptyRow(cols, message) {
    return `<tr class="empty-row"><td colspan="${cols}">${esc(message)}</td></tr>`;
  }

  /* ---------------- data fetch ---------------- */
  async function load() {
    try {
      const res = await fetch("/api/stats", { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      state.data = data;
      state.attacks = Array.isArray(data.attacks) ? data.attacks : [];
      $("#conn-error").classList.add("hidden");
      render();
    } catch (err) {
      console.error("Failed to load /api/stats:", err);
      $("#conn-error").classList.remove("hidden");
    }
  }

  /* ---------------- render root ---------------- */
  function render() {
    const d = state.data;
    if (!d) return;
    renderKpis(d);
    renderSidebar(d);
    renderTopbar(d);
    renderCharts(d);
    renderTopIps(d.top_ips || []);
    syncFilterOptions();
    applyFilters();
    renderMitre(d.mitre || []);
    renderAi(d.ai || {});
    renderHealth(d.health || []);
    renderQuarantine(d.quarantine || {});
    renderAlerts(d.alerts || []);
    renderSettings(d);
  }

  function renderKpis(d) {
    const set = (id, value) => { $(id).textContent = (value === null || value === undefined) ? NA : value; };
    set("#kpi-total", d.total);
    set("#kpi-ssh", d.ssh);
    set("#kpi-http", d.http);
    set("#kpi-smb", d.smb);
    set("#kpi-high", d.high_profiles);
    set("#kpi-quarantine", (d.quarantine && d.quarantine.count) ?? NA);

    $("#kpi-total-foot").textContent =
      d.unique_ips ? `${d.unique_ips} unique source IP${d.unique_ips === 1 ? "" : "s"}` : "No source IPs observed";
    $("#kpi-high-foot").textContent =
      d.ai && d.ai.log_present ? "High-severity source IPs" : "AI detector log not present";
    $("#kpi-quarantine-foot").textContent =
      d.quarantine && d.quarantine.log_present
        ? `Threshold: ${d.quarantine.threshold} attempts`
        : "Mesh controller log not present";
  }

  function renderSidebar(d) {
    (d.health || []).forEach((h) => {
      const row = $(`.svc-row[data-svc="${h.service}"]`);
      if (!row) return;
      const dot = row.querySelector(".dot");
      const label = row.querySelector(".svc-state");
      row.classList.remove("online", "offline");
      dot.className = "dot";
      if (h.status === "ONLINE") { row.classList.add("online"); dot.classList.add("dot-online"); }
      else if (h.status === "OFFLINE") { row.classList.add("offline"); dot.classList.add("dot-offline"); }
      else { dot.classList.add("dot-unknown"); }
      label.textContent = h.status;
    });

    const online = (d.health || []).filter((h) => h.status === "ONLINE").length;
    const totalSvc = (d.health || []).length;
    $("#sys-mesh").textContent = totalSvc ? `${online}/${totalSvc} online` : NA;
    $("#sys-ips").textContent = d.unique_ips ?? NA;
    $("#nav-count-attacks").textContent = d.total ?? NA;
    $("#nav-count-quarantine").textContent = (d.quarantine && d.quarantine.count) ?? NA;
  }

  function renderTopbar(d) {
    $("#last-updated").textContent = fmtTime(d.generated_at);
    const pill = $("#refresh-pill");
    const label = $("#refresh-label");
    if (state.refreshMs === 0) {
      pill.classList.add("paused");
      label.textContent = "PAUSED";
    } else {
      pill.classList.remove("paused");
      label.textContent = `LIVE · ${state.refreshMs / 1000}s`;
    }
  }

  /* ---------------- charts ---------------- */
  function chartEmpty(canvasId, isEmpty) {
    const note = document.querySelector(`.chart-empty[data-for="${canvasId}"]`);
    const canvas = document.getElementById(canvasId);
    if (note) note.classList.toggle("hidden", !isEmpty);
    if (canvas) canvas.style.visibility = isEmpty ? "hidden" : "visible";
  }

  function upsert(canvasId, config, isEmpty) {
    chartEmpty(canvasId, isEmpty);
    if (isEmpty) {
      if (state.charts[canvasId]) { state.charts[canvasId].destroy(); delete state.charts[canvasId]; }
      return;
    }
    const existing = state.charts[canvasId];
    if (existing) {
      existing.data.labels = config.data.labels;
      existing.data.datasets.forEach((ds, i) => {
        const next = config.data.datasets[i];
        if (!next) return;
        ds.data = next.data;
        if (next.backgroundColor) ds.backgroundColor = next.backgroundColor;
      });
      existing.update("none");
      return;
    }
    const ctx = document.getElementById(canvasId);
    if (ctx && window.Chart) state.charts[canvasId] = new window.Chart(ctx, config);
  }

  const baseScales = {
    x: { ticks: { color: COLORS.tick, font: { size: 10 } }, grid: { color: COLORS.grid, drawBorder: false } },
    y: { beginAtZero: true, ticks: { color: COLORS.tick, precision: 0, font: { size: 10 } },
         grid: { color: COLORS.grid, drawBorder: false } },
  };

  function renderCharts(d) {
    if (!window.Chart) return;

    // Attack distribution
    const dist = [d.ssh || 0, d.http || 0, d.smb || 0];
    upsert("chart-dist", {
      type: "doughnut",
      data: {
        labels: ["SSH", "HTTP", "SMB"],
        datasets: [{
          data: dist,
          backgroundColor: [COLORS.ssh, COLORS.http, COLORS.smb],
          borderColor: "#10151d", borderWidth: 2, hoverOffset: 6,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "62%",
        plugins: { legend: { position: "bottom",
          labels: { color: COLORS.tick, boxWidth: 10, boxHeight: 10, font: { size: 11 } } } },
      },
    }, dist.every((v) => !v));

    // Activity over time
    const tl = d.timeline || [];
    upsert("chart-time", {
      type: "line",
      data: {
        labels: tl.map((b) => b.label),
        datasets: [{
          label: "Events", data: tl.map((b) => b.total),
          borderColor: COLORS.accent, backgroundColor: "rgba(79,156,249,.14)",
          fill: true, tension: .32, pointRadius: 2, borderWidth: 2,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: baseScales,
      },
    }, tl.length === 0);

    // Severity
    const sev = d.severity || {};
    const sevKeys = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const sevVals = sevKeys.map((k) => sev[k] || 0);
    upsert("chart-sev", {
      type: "bar",
      data: {
        labels: sevKeys,
        datasets: [{
          data: sevVals,
          backgroundColor: sevKeys.map((k) => COLORS[k]),
          borderRadius: 4, barThickness: 34,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: baseScales,
      },
    }, sevVals.every((v) => !v));

    // MITRE frequency
    const mitre = (d.mitre || []).slice(0, 8);
    upsert("chart-mitre", {
      type: "bar",
      data: {
        labels: mitre.map((m) => m.technique_id || m.technique),
        datasets: [{
          data: mitre.map((m) => m.count),
          backgroundColor: COLORS.accent, borderRadius: 4, barThickness: 20,
        }],
      },
      options: {
        indexAxis: "y",
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { color: COLORS.tick, precision: 0, font: { size: 10 } },
               grid: { color: COLORS.grid, drawBorder: false } },
          y: { ticks: { color: COLORS.tick, font: { size: 10, family: "monospace" } }, grid: { display: false } },
        },
      },
    }, mitre.length === 0);
  }

  /* ---------------- tables ---------------- */
  function renderTopIps(ips) {
    const body = $("#tbody-ips");
    if (!ips.length) { body.innerHTML = emptyRow(8, "No attacker IPs recorded yet"); return; }
    body.innerHTML = ips.map((ip, i) => `
      <tr>
        <td class="rank">${i + 1}</td>
        <td class="mono">${txt(ip.ip)}</td>
        <td class="mono">${txt(ip.count)}</td>
        <td>${(ip.services && ip.services.length)
              ? ip.services.map((s) => `<span class="badge badge-svc-${esc(s)}">${esc(s)}</span>`).join(" ")
              : `<span class="muted">${NA}</span>`}</td>
        <td>${scoreCell(ip.threat_score)}</td>
        <td>${severityBadge(ip.threat_level)}</td>
        <td class="muted">${relative(ip.first_seen)}</td>
        <td class="muted">${relative(ip.last_seen)}</td>
      </tr>`).join("");
  }

  function syncFilterOptions() {
    const fill = (sel, values) => {
      const el = $(sel);
      const current = el.value;
      const opts = ['<option value="">' + el.dataset.allLabel + "</option>"]
        .concat(values.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`));
      el.innerHTML = opts.join("");
      if (values.includes(current)) el.value = current;
    };

    const events = [...new Set(state.attacks.map((a) => a.event_type).filter(Boolean))].sort();
    const techs  = [...new Set(state.attacks.map((a) => a.mitre_technique).filter(Boolean))].sort();

    const evSel = $("#f-event");
    const mtSel = $("#f-mitre");
    evSel.dataset.allLabel = "All events";
    mtSel.dataset.allLabel = "All techniques";
    fill("#f-event", events);
    fill("#f-mitre", techs);
  }

  function applyFilters() {
    const q       = ($("#global-search").value || "").trim().toLowerCase();
    const ip      = ($("#f-ip").value || "").trim().toLowerCase();
    const service = $("#f-service").value;
    const sev     = $("#f-severity").value;
    const event   = $("#f-event").value;
    const tech    = $("#f-mitre").value;

    state.filtered = state.attacks.filter((a) => {
      if (ip && !(a.src_ip || "").toLowerCase().includes(ip)) return false;
      if (service && a.service !== service) return false;
      if (sev && a.severity !== sev) return false;
      if (event && a.event_type !== event) return false;
      if (tech && a.mitre_technique !== tech) return false;
      if (q) {
        const hay = [a.src_ip, a.username, a.event_type, a.mitre_technique,
                     a.mitre_technique_name, a.mitre_tactic, a.service, a.path, a.node_id]
          .filter(Boolean).join(" ").toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    sortFiltered();
    const maxPage = Math.max(1, Math.ceil(state.filtered.length / state.pageSize));
    if (state.page > maxPage) state.page = maxPage;
    renderFeed();
  }

  function sortFiltered() {
    const { key, dir } = state.sort;
    const order = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    state.filtered.sort((a, b) => {
      let x = a[key], y = b[key];
      if (key === "severity") { x = order[x] || 0; y = order[y] || 0; }
      if (x === null || x === undefined) x = "";
      if (y === null || y === undefined) y = "";
      if (typeof x === "number" && typeof y === "number") return dir === "asc" ? x - y : y - x;
      return dir === "asc" ? String(x).localeCompare(String(y)) : String(y).localeCompare(String(x));
    });
  }

  function renderFeed() {
    const body  = $("#tbody-feed");
    const total = state.filtered.length;

    $("#feed-count").textContent = state.attacks.length
      ? `${total} of ${state.attacks.length} event${state.attacks.length === 1 ? "" : "s"} shown`
      : "No attack events captured yet";

    if (!total) {
      body.innerHTML = emptyRow(9, state.attacks.length
        ? "No events match the current filters"
        : "No attack events captured yet");
      $("#pg-info").textContent = "0 results";
      $("#pg-prev").disabled = true;
      $("#pg-next").disabled = true;
      return;
    }

    const start = (state.page - 1) * state.pageSize;
    const rows  = state.filtered.slice(start, start + state.pageSize);

    body.innerHTML = rows.map((a) => `
      <tr>
        <td class="mono" title="${txt(a.timestamp)}">${fmtDateTime(a.timestamp)}</td>
        <td class="mono">${txt(a.src_ip)}</td>
        <td>${a.service ? `<span class="badge badge-svc-${esc(a.service)}">${esc(a.service)}</span>`
                        : `<span class="badge badge-NA">${NA}</span>`}</td>
        <td class="mono">${txt(a.event_type)}</td>
        <td class="mono">${txt(a.username)}</td>
        <td>${scoreCell(a.threat_score)}</td>
        <td>${severityBadge(a.severity)}</td>
        <td title="${txt(a.mitre_technique_name)}">${techTag(a.mitre_technique)}</td>
        <td><span class="badge badge-status-${esc(a.status || "MONITORED")}">${txt(a.status)}</span></td>
      </tr>`).join("");

    const maxPage = Math.ceil(total / state.pageSize);
    $("#pg-info").textContent = `Page ${state.page} / ${maxPage} · ${total} results`;
    $("#pg-prev").disabled = state.page <= 1;
    $("#pg-next").disabled = state.page >= maxPage;
  }

  function renderMitre(techniques) {
    const grid = $("#mitre-grid");
    const body = $("#tbody-mitre");

    if (!techniques.length) {
      grid.innerHTML = `<p class="empty">No MITRE techniques observed yet</p>`;
      body.innerHTML = emptyRow(5, "No MITRE techniques observed yet");
      return;
    }

    const max = Math.max(...techniques.map((t) => t.count || 0), 1);

    grid.innerHTML = techniques.map((t) => `
      <article class="mitre-card">
        <div class="mitre-id">${txt(t.technique_id || t.technique)}</div>
        <p class="mitre-name">${txt(t.technique_name)}</p>
        <p class="mitre-tactic">${txt(t.tactic)}</p>
        <div class="mitre-meter"><span style="width:${Math.round((t.count / max) * 100)}%"></span></div>
        <div class="mitre-count"><span>Occurrences</span><strong>${txt(t.count)}</strong></div>
      </article>`).join("");

    body.innerHTML = techniques.map((t) => {
      const sev = severityForTechnique(t.technique_id || t.technique);
      return `<tr>
        <td>${techTag(t.technique_id || t.technique)}</td>
        <td>${txt(t.technique_name)}</td>
        <td class="muted">${txt(t.tactic)}</td>
        <td class="mono">${txt(t.count)}</td>
        <td>${sev ? severityBadge(sev) : `<span class="badge badge-NA">${NA}</span>`}</td>
      </tr>`;
    }).join("");
  }

  /** Highest observed severity among source IPs that triggered this technique. */
  function severityForTechnique(id) {
    if (!id) return null;
    const order = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    let best = null;
    state.attacks.forEach((a) => {
      if (a.mitre_technique !== id || !a.severity) return;
      if (!best || (order[a.severity] || 0) > (order[best] || 0)) best = a.severity;
    });
    return best;
  }

  function renderAi(ai) {
    $("#ai-engine").textContent = ai.engine || NA;
    const rows = ai.analyses || [];
    const summary = $("#ai-summary");

    const counts = rows.reduce((acc, r) => {
      if (r.threat_level) acc[r.threat_level] = (acc[r.threat_level] || 0) + 1;
      return acc;
    }, {});
    const topScore = rows.reduce((m, r) => Math.max(m, r.threat_score || 0), 0);

    summary.innerHTML = `
      <div class="ai-stat">
        <div class="ai-stat-label">Detection Engine</div>
        <div class="ai-stat-value" style="font-size:13px">${ai.available ? "Active" : "Unavailable"}</div>
        <div class="ai-stat-note">Rule-based scoring, not an ML model</div>
      </div>
      <div class="ai-stat">
        <div class="ai-stat-label">Analyses Logged</div>
        <div class="ai-stat-value">${rows.length}</div>
        <div class="ai-stat-note">${ai.log_present ? "ai_detector.json present" : "ai_detector.json not found"}</div>
      </div>
      <div class="ai-stat">
        <div class="ai-stat-label">Peak Threat Score</div>
        <div class="ai-stat-value">${rows.length ? topScore + "/100" : NA}</div>
        <div class="ai-stat-note">Highest recorded score</div>
      </div>
      <div class="ai-stat">
        <div class="ai-stat-label">High Severity</div>
        <div class="ai-stat-value">${rows.length ? (counts.HIGH || 0) : NA}</div>
        <div class="ai-stat-note">MEDIUM: ${rows.length ? (counts.MEDIUM || 0) : NA}</div>
      </div>`;

    const body = $("#tbody-ai");
    if (!rows.length) {
      body.innerHTML = emptyRow(8, ai.log_present
        ? "No anomaly analyses recorded yet"
        : "AI detector is not running — no analyses available");
      return;
    }
    body.innerHTML = rows.map((r) => `
      <tr>
        <td class="mono" title="${txt(r.timestamp)}">${fmtDateTime(r.timestamp)}</td>
        <td class="mono">${txt(r.src_ip)}</td>
        <td>${scoreCell(r.threat_score)}</td>
        <td>${severityBadge(r.threat_level)}</td>
        <td class="mono">${txt(r.total_attempts)}</td>
        <td title="${txt(r.technique_name)}">${techTag(r.technique_id)}</td>
        <td class="muted">${txt(r.tactic)}</td>
        <td class="reason-cell muted">${txt(r.message)}</td>
      </tr>`).join("");
  }

  function renderHealth(health) {
    const grid = $("#hp-grid");
    if (!health.length) { grid.innerHTML = `<p class="empty">No honeypot data available</p>`; return; }

    grid.innerHTML = health.map((h) => {
      const cls = h.status === "ONLINE" ? "online" : h.status === "OFFLINE" ? "offline" : "unknown";
      const dot = h.status === "ONLINE" ? "dot-online" : h.status === "OFFLINE" ? "dot-offline" : "dot-unknown";
      return `
      <article class="hp-card ${cls}">
        <div class="hp-head">
          <span class="dot ${dot}" aria-hidden="true"></span>
          <span class="hp-title">${txt(h.label)}</span>
          <span class="hp-state">${txt(h.status)}</span>
        </div>
        <dl class="meta-list">
          <dt>Port</dt><dd>${txt(h.port)}</dd>
          <dt>Node ID</dt><dd>${txt(h.node_id)}</dd>
          <dt>Attack events</dt><dd>${txt(h.attack_count)}</dd>
          <dt>Total log events</dt><dd>${txt(h.event_count)}</dd>
          <dt>Last event</dt><dd>${relative(h.last_event)}</dd>
          <dt>Last attack</dt><dd>${relative(h.last_attack)}</dd>
        </dl>
      </article>`;
    }).join("");
  }

  function renderQuarantine(q) {
    const body = $("#tbody-quarantine");
    const entries = q.entries || [];
    $("#q-note").textContent = q.log_present
      ? `Mesh controller threshold: ${q.threshold} attempts per IP`
      : "Mesh controller log not present — quarantine data unavailable";

    if (!entries.length) {
      body.innerHTML = emptyRow(7, q.log_present
        ? "No IPs currently quarantined"
        : "Mesh controller is not running — no quarantine data");
      return;
    }
    body.innerHTML = entries.map((e) => `
      <tr>
        <td class="mono">${txt(e.ip)}</td>
        <td class="muted">${txt(e.reason)}</td>
        <td class="mono">${txt(e.attempts)}</td>
        <td>${scoreCell(e.threat_score)}</td>
        <td class="mono" title="${txt(e.detected_at)}">${fmtDateTime(e.detected_at)}</td>
        <td>${techTag(e.mitre_technique)}</td>
        <td><span class="badge badge-status-QUARANTINED">${txt(e.status)}</span></td>
      </tr>`).join("");
  }

  function renderAlerts(alerts) {
    const list = $("#alert-list");
    const count = $("#alert-count");
    if (!alerts.length) {
      list.innerHTML = `<li class="empty">No active alerts</li>`;
      count.classList.add("hidden");
      return;
    }
    count.textContent = alerts.length;
    count.classList.remove("hidden");
    list.innerHTML = alerts.map((a) => `
      <li class="sev-${esc(a.severity)}">
        <div class="alert-title">${txt(a.title)}</div>
        <div class="alert-detail">${txt(a.detail)}${a.timestamp ? " · " + relative(a.timestamp) : ""}</div>
      </li>`).join("");
  }

  function renderSettings(d) {
    $("#settings-meta").innerHTML = `
      <dt>Data generated at</dt><dd>${fmtDateTime(d.generated_at)}</dd>
      <dt>Backend refresh hint</dt><dd>${txt(d.refresh_interval_s)}s</dd>
      <dt>Detection engine</dt><dd>${d.ai && d.ai.available ? "Active" : "Unavailable"}</dd>
      <dt>AI detector log</dt><dd>${d.ai && d.ai.log_present ? "Present" : "Missing"}</dd>
      <dt>Mesh controller log</dt><dd>${d.quarantine && d.quarantine.log_present ? "Present" : "Missing"}</dd>
      <dt>Quarantine threshold</dt><dd>${txt(d.quarantine && d.quarantine.threshold)}</dd>
      <dt>Unique source IPs</dt><dd>${txt(d.unique_ips)}</dd>`;
  }

  /* ---------------- PDF export ---------------- */
  async function exportPdf() {
    const btn = $("#btn-pdf");
    if (!window.jspdf) { alert("PDF library failed to load. Use CSV or JSON export."); return; }
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = "Generating…";
    try {
      const res = await fetch("/api/stats", { cache: "no-store" });
      const d = await res.json();
      const { jsPDF } = window.jspdf;
      const doc = new jsPDF();
      let y = 20;
      const line = (text, size = 11) => {
        doc.setFontSize(size);
        doc.text(text, 20, y);
        y += size > 14 ? 10 : 7;
        if (y > 275) { doc.addPage(); y = 20; }
      };

      line("Zero-Trust Honeypot Mesh - SOC Report", 17);
      line(`Generated: ${new Date().toLocaleString()}`, 10);
      line(`Data snapshot: ${d.generated_at || "N/A"}`, 10);
      y += 4;

      line("Summary", 13);
      line(`Total attacks : ${d.total}`);
      line(`SSH / HTTP / SMB : ${d.ssh} / ${d.http} / ${d.smb}`);
      line(`Unique source IPs : ${d.unique_ips}`);
      line(`High or critical source IPs : ${d.high_profiles}`);
      line(`Quarantined IPs : ${d.quarantine ? d.quarantine.count : "N/A"}`);
      y += 4;

      const sev = d.severity || {};
      line("Severity distribution (per source IP)", 13);
      ["LOW", "MEDIUM", "HIGH", "CRITICAL"].forEach((k) => line(`${k} : ${sev[k] || 0}`));
      y += 4;

      line("Top attacker IPs", 13);
      if (!(d.top_ips || []).length) line("No data available");
      d.top_ips.forEach((ip, i) =>
        line(`${i + 1}. ${ip.ip} - ${ip.count} events - score ${ip.threat_score} (${ip.threat_level})`));
      y += 4;

      line("Observed MITRE ATT&CK techniques", 13);
      if (!(d.mitre || []).length) line("No data available");
      d.mitre.forEach((t) =>
        line(`${t.technique_id || t.technique} - ${t.technique_name || "N/A"} - ${t.count} occurrence(s)`));
      y += 4;

      line("Honeypot health", 13);
      (d.health || []).forEach((h) =>
        line(`${h.label} (port ${h.port}) : ${h.status} - ${h.attack_count} attack events`));

      doc.save("honeypot_soc_report.pdf");
    } catch (err) {
      console.error("PDF export failed:", err);
      alert("PDF export failed. See the browser console for details.");
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  }

  /* ---------------- refresh scheduling ---------------- */
  function schedule() {
    if (state.timer) clearInterval(state.timer);
    if (state.refreshMs > 0) state.timer = setInterval(load, state.refreshMs);
    if (state.data) renderTopbar(state.data);
  }

  /* ---------------- events ---------------- */
  function bind() {
    // filters
    ["#global-search", "#f-ip"].forEach((sel) =>
      $(sel).addEventListener("input", () => { state.page = 1; applyFilters(); }));
    ["#f-service", "#f-severity", "#f-event", "#f-mitre"].forEach((sel) =>
      $(sel).addEventListener("change", () => { state.page = 1; applyFilters(); }));

    $("#f-reset").addEventListener("click", () => {
      ["#f-ip", "#global-search"].forEach((s) => { $(s).value = ""; });
      ["#f-service", "#f-severity", "#f-event", "#f-mitre"].forEach((s) => { $(s).value = ""; });
      state.page = 1;
      applyFilters();
    });

    // sorting
    $$(".tbl-feed th.sortable").forEach((th) => {
      th.setAttribute("tabindex", "0");
      const activate = () => {
        const key = th.dataset.sort;
        state.sort = { key, dir: state.sort.key === key && state.sort.dir === "desc" ? "asc" : "desc" };
        $$(".tbl-feed th.sortable").forEach((o) => o.removeAttribute("aria-sort"));
        th.setAttribute("aria-sort", state.sort.dir === "asc" ? "ascending" : "descending");
        state.page = 1;
        applyFilters();
      };
      th.addEventListener("click", activate);
      th.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activate(); }
      });
    });

    // pagination
    $("#pg-prev").addEventListener("click", () => {
      if (state.page > 1) { state.page--; renderFeed(); }
    });
    $("#pg-next").addEventListener("click", () => {
      const maxPage = Math.ceil(state.filtered.length / state.pageSize);
      if (state.page < maxPage) { state.page++; renderFeed(); }
    });

    // refresh interval
    $("#s-refresh").addEventListener("change", (e) => {
      state.refreshMs = Number(e.target.value) * 1000;
      schedule();
    });

    // alerts panel
    const btn = $("#alert-btn");
    const panel = $("#alert-panel");
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const open = panel.classList.toggle("hidden");
      btn.setAttribute("aria-expanded", String(!open));
    });
    document.addEventListener("click", (e) => {
      if (!panel.classList.contains("hidden") && !panel.contains(e.target) && e.target !== btn) {
        panel.classList.add("hidden");
        btn.setAttribute("aria-expanded", "false");
      }
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        panel.classList.add("hidden");
        btn.setAttribute("aria-expanded", "false");
        $("#sidebar").classList.remove("open");
      }
    });

    // exports
    $("#btn-pdf").addEventListener("click", exportPdf);

    // sidebar toggle (small screens)
    const toggle = $("#nav-toggle");
    toggle.addEventListener("click", () => {
      const open = $("#sidebar").classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });

    // nav active state + close drawer on navigate
    $$("[data-nav]").forEach((link) => {
      link.addEventListener("click", () => {
        $$("[data-nav]").forEach((l) => l.classList.remove("active"));
        link.classList.add("active");
        $("#sidebar").classList.remove("open");
      });
    });

    // highlight nav on scroll
    const sections = $$("main .section");
    if ("IntersectionObserver" in window) {
      const obs = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          const link = document.querySelector(`[data-nav][href="#${entry.target.id}"]`);
          if (!link) return;
          $$("[data-nav]").forEach((l) => l.classList.remove("active"));
          link.classList.add("active");
        });
      }, { rootMargin: "-45% 0px -50% 0px" });
      sections.forEach((s) => obs.observe(s));
    }
  }

  /* ---------------- init ---------------- */
  function init() {
    bind();
    load();
    schedule();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

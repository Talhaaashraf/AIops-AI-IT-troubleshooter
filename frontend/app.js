// ============================================================================
// DOM helpers
// ============================================================================

function $(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  $(id).textContent = value;
}

function percent(value) {
  return typeof value === 'number' ? `${value.toFixed(1)}%` : '--';
}

function levelFor(value, warning = 75, critical = 90) {
  if (value >= critical) return 'critical';
  if (value >= warning) return 'warning';
  return 'ok';
}

// ============================================================================
// Shared state
// ============================================================================

let latestReport = null;
let socket = null;
let reconnectTimer = null;
let chatHistory = [];
let generatedToken = '';
let selectedPlatform = 'windows';

// ============================================================================
// Dashboard — live monitor
// ============================================================================

function renderReport(report) {
  latestReport = report;

  const cpu = report.cpu || {};
  const ram = report.memory?.ram || {};
  const disks = report.disk || [];
  const network = report.network || {};
  const battery = report.battery;
  const diskValue = disks.reduce((max, disk) => Math.max(max, disk.usage_percent || 0), 0);

  const gauges = [
    ['cpu', cpu.total_usage_percent, levelFor(cpu.total_usage_percent || 0, 75, 85)],
    ['ram', ram.usage_percent, levelFor(ram.usage_percent || 0, 75, 85)],
    ['disk', diskValue, levelFor(diskValue, 75, 90)],
  ];
  for (const [name, value, state] of gauges) {
    $(`${name}-gauge`).closest('.metric-card').className = `metric-card ${state}`;
    $(`${name}-gauge`).style.setProperty('--value', typeof value === 'number' ? Math.min(100, value) : 0);
    setText(`${name}-value`, typeof value === 'number' ? value.toFixed(1) : '--');
    setText(`${name}-state`, state.toUpperCase());
  }

  setText('cpu-detail', `${cpu.logical_cores || '--'} logical cores / ${cpu.current_frequency_mhz || '--'} MHz`);
  setText('ram-detail', `${ram.available || '--'} available`);
  setText('disk-detail', disks.length ? `${disks.length} mounted volume${disks.length === 1 ? '' : 's'}` : 'No volumes');

  const interfacesUp = (network.interfaces || []).filter((item) => item.status === 'UP').length;
  setText('network-value', network.interfaces ? `${interfacesUp} up` : '--');
  setText('network-state', 'LIVE');
  setText('network-detail', `${network.bytes_received || '--'} received`);

  setText('battery-value', battery ? percent(battery.percent) : 'N/A');
  setText('battery-state', battery ? (battery.charging ? 'CHARGING' : 'ON BATTERY') : 'N/A');
  setText('battery-detail', battery ? battery.time_remaining : 'No battery detected');

  setText('hostname', report.system?.hostname || '--');
  setText('os-name', `${report.system?.os_name || '--'} ${report.system?.os_release || ''}`);
  setText('uptime', report.system?.uptime || '--');
  setText('architecture', report.system?.architecture || '--');
  setText('process-count', `${report.processes_count ?? '--'} processes`);
  setText('last-updated', `Updated ${new Date().toLocaleTimeString()}`);

  // The chat context follows the device picked in Ask Technician; the live stream is this server.
  if (($('chat-device').value || 'local') === 'local') {
    setText('chat-host', report.system?.hostname || '--');
    setText('chat-cpu', percent(cpu.total_usage_percent));
    setText('chat-ram', percent(ram.usage_percent));
    setText('chat-disk', percent(diskValue));
  }
}

function renderHealth(health) {
  const banner = $('health-banner');
  banner.className = `health-banner ${health.status}`;
  setText('health-title', health.status === 'ok' ? 'System healthy' : `${health.status} signals detected`);
  setText('health-message', health.message);
}

function setConnection(state, detail) {
  $('connection-state').className = `connection-state ${state}`;
  const labels = { connected: 'Monitor connected', disconnected: 'Disconnected', error: 'No live data' };
  setText('connection-label', labels[state] || 'Connecting');
  setText('connection-detail', detail);
}

// Which machine the dashboard shows: the AIops agent on the server's host, or (in Docker, until that agent is
// installed) only the AIops container.
function renderServerSource(source) {
  const kind = source?.kind;
  const stale = source?.stale ? ' (its last report is old)' : '';
  setText('server-source', kind === 'host-agent' ? `Via the AIops agent on ${source.label}${stale}` : kind === 'container' ? 'AIops container, not the server itself' : 'This computer');
  $('server-container-note').classList.toggle('hidden', kind !== 'container');
  return kind === 'host-agent' ? `Live from the server's agent${stale}` : kind === 'container' ? 'Live / AIops container view' : 'Live stream / 5 second interval';
}

let monitorWatchdog = null;

function connectMonitor() {
  clearTimeout(reconnectTimer);
  clearTimeout(monitorWatchdog);
  setConnection('', 'Opening monitor stream');
  const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
  socket = new WebSocket(`${protocol}://${location.host}/ws/monitor`);
  // An open socket is not live data yet: say "connected" only when a report arrives.
  socket.onopen = () => {
    setConnection('', 'Connected, waiting for the first data...');
    monitorWatchdog = setTimeout(() => setConnection('error', 'Connected, but no data yet: the server may be busy. Still waiting...'), 20000);
  };
  socket.onmessage = (event) => {
    clearTimeout(monitorWatchdog);
    const data = JSON.parse(event.data);
    if (data.error) {
      setConnection('error', data.error);
      return;
    }
    renderReport(data);
    // The server's agent stopped reporting: its last report is shown, but it is not live.
    setConnection(data.source?.stale ? 'error' : 'connected', renderServerSource(data.source));
  };
  socket.onclose = () => {
    clearTimeout(monitorWatchdog);
    setConnection('disconnected', 'Retrying in 3 seconds');
    reconnectTimer = setTimeout(connectMonitor, 3000);
  };
  socket.onerror = () => socket.close();
}

async function loadHealth() {
  try {
    const response = await fetch('/api/diagnostics/health');
    if (!response.ok) throw new Error('Health unavailable');
    renderHealth(await response.json());
  } catch (error) {
    renderHealth({ status: 'critical', message: error.message });
  }
}

// ============================================================================
// Alerts
// ============================================================================

function renderDiagnosis(container, data) {
  container.replaceChildren();

  const summary = document.createElement('strong');
  summary.textContent = data.summary || data.plain_explanation || 'No summary returned.';
  container.appendChild(summary);

  const root = document.createElement('p');
  root.textContent = `Likely root cause: ${data.root_cause || data.technical_root_cause || 'Unknown'}`;
  container.appendChild(root);

  const list = document.createElement('ul');
  (data.steps || data.recommendations || []).forEach((step) => {
    const item = document.createElement('li');
    item.textContent = String(step);
    list.appendChild(item);
  });
  container.appendChild(list);
}

async function loadAlerts() {
  const body = $('alerts-body');
  try {
    const response = await fetch('/api/alerts');
    if (!response.ok) throw new Error('Alert history unavailable');
    const data = await response.json();
    setText('alert-count', data.alerts.length);

    if (!data.alerts.length) {
      body.innerHTML = '<tr><td colspan="5" class="empty-state">No alerts recorded. The local rules engine is watching.</td></tr>';
      return;
    }

    body.innerHTML = data.alerts.map((alert) => `
      <tr>
        <td>${escapeHtml(new Date(alert.timestamp).toLocaleString())}</td>
        <td><span class="severity severity-${escapeHtml(alert.severity)}">${escapeHtml(alert.severity)}</span></td>
        <td>${escapeHtml(alert.category)}</td>
        <td>${escapeHtml(alert.description)}</td>
        <td><button class="diagnose-button" data-diagnose="${Number(alert.id)}">Diagnose with AI</button></td>
      </tr>
      <tr id="diagnosis-${Number(alert.id)}" class="diagnosis-row hidden">
        <td colspan="5"><div class="diagnosis" id="diagnosis-content-${alert.id}"></div></td>
      </tr>
    `).join('');
  } catch (error) {
    body.innerHTML = `<tr><td colspan="5" class="empty-state">${escapeHtml(error.message)}</td></tr>`;
  }
}

async function diagnoseAlert(id) {
  const row = $(`diagnosis-${id}`);
  const content = $(`diagnosis-content-${id}`);
  row.classList.remove('hidden');
  content.textContent = 'Consulting technician...';
  try {
    const response = await fetch('/api/agent/diagnose', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ diagnostics: latestReport, alert_history: [] }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'AI unavailable');
    renderDiagnosis(content, data);
  } catch (error) {
    content.textContent = error.message;
  }
}

// ============================================================================
// Security
// ============================================================================

const RISKY_PORTS = { 21: 'FTP', 23: 'Telnet', 445: 'SMB', 3389: 'RDP', 5900: 'VNC' };

function isLoopbackAddress(address) {
  return address === '127.0.0.1' || address === '::1' || address.startsWith('127.');
}

function setStatusCard(prefix, ok, detail, unknownMessage) {
  const card = $(`${prefix}-card`);
  const state = $(`${prefix}-state`);
  const detailElement = $(`${prefix}-detail`);
  if (ok === null || ok === undefined) {
    card.className = 'metric-card';
    state.textContent = 'UNKNOWN';
    detailElement.textContent = detail || unknownMessage;
    return;
  }
  card.className = `metric-card ${ok ? 'ok' : 'critical'}`;
  state.textContent = ok ? 'OK' : 'ATTENTION';
  detailElement.textContent = detail;
}

function renderSecurity(security) {
  const firewall = security.firewall || {};
  const antivirus = security.antivirus || {};
  const encryption = security.disk_encryption || {};
  const updates = security.updates || {};
  const admin = security.running_as_admin;

  setStatusCard('firewall', firewall.available ? firewall.enabled : null, firewall.detail, 'Not available on this platform');
  setStatusCard('antivirus', antivirus.available ? antivirus.enabled : null, antivirus.detail, 'Not available on this platform');
  setStatusCard('encryption', encryption.available ? encryption.encrypted : null, encryption.detail, 'Not available on this platform');

  $('updates-card').className = 'metric-card';
  setText('updates-state', updates.available ? 'CHECKED' : 'UNKNOWN');
  setText('updates-detail', updates.detail || 'Not available');

  $('admin-card').className = 'metric-card';
  setText('admin-state', admin === null || admin === undefined ? 'UNKNOWN' : admin ? 'ELEVATED' : 'STANDARD');
  setText('admin-detail', admin ? 'Running with administrator/root privileges' : 'Running with standard user privileges');

  const ports = (security.listening_ports || {}).ports || [];
  setText('ports-count', `${ports.length} open`);

  const body = $('ports-body');
  if (!ports.length) {
    body.innerHTML = '<tr><td colspan="4" class="empty-state">No listening ports detected.</td></tr>';
    return;
  }
  body.innerHTML = ports.map((port) => {
    const risky = RISKY_PORTS[port.port] && !isLoopbackAddress(port.address);
    const riskCell = risky ? `<span class="severity severity-high">${RISKY_PORTS[port.port]}</span>` : '<span class="soft-label">--</span>';
    return `<tr><td>${escapeHtml(port.port)}</td><td>${escapeHtml(port.address)}</td><td>${escapeHtml(port.process)}</td><td>${riskCell}</td></tr>`;
  }).join('');
}

async function loadSecurity() {
  try {
    const response = await fetch('/api/diagnostics/security');
    if (!response.ok) throw new Error('Security data unavailable');
    renderSecurity(await response.json());
  } catch (error) {
    $('ports-body').innerHTML = `<tr><td colspan="4" class="empty-state">${escapeHtml(error.message)}</td></tr>`;
  }
}

// ============================================================================
// Performance (per device): one full test, shown section by section; OS and app updates with Update
// buttons; deep AI analysis (3-4 suggestions, nothing runs without approval); keyboard and mouse testers
// for the computer running this browser.
// ============================================================================

const PERF_SECTIONS = [
  { id: 'system', title: 'Live load', tool: 'system_overview' },
  { id: 'processes', title: 'Busiest programs (CPU)', tool: 'top_processes' },
  { id: 'memory', title: 'Biggest programs (memory)', tool: null },
  { id: 'benchmark', title: 'Speed benchmark', tool: 'performance_benchmark' },
  { id: 'boot', title: 'Start-up', tool: 'boot_performance' },
  { id: 'hardware', title: 'Hardware', tool: 'hardware_health' },
  { id: 'disks', title: 'Disk health', tool: 'disk_health' },
  { id: 'battery', title: 'Battery', tool: 'battery_health' },
  { id: 'input', title: 'Keyboard & mouse (device)', tool: 'input_devices' },
];
const PERF_TONES = { critical: 'critical', high: 'critical', medium: 'warning', low: 'ok' };
let perfDeviceId = null;
let perfJob = null;
let perfPollTimer = null;
const perfBusy = new Set(); // update ids being installed right now
const perfDone = new Map(); // update id -> outcome text, for the current test
const perfPicked = new Map(); // OS update id -> ticked, so re-renders keep the person's choice

function setPerfStatus(text, tone = '') {
  const status = $('perf-status');
  status.className = `sw-status perf-status${tone ? ` ${tone}` : ''}`;
  status.textContent = text;
}

function perfKv(rows) {
  const shown = rows.filter(([, value]) => value !== null && value !== undefined && value !== '');
  return shown.length ? `<dl class="perf-kv">${shown.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`).join('')}</dl>` : '';
}

function perfList(items) {
  return items.length ? `<ul class="perf-list">${items.map(([name, value]) => `<li><span>${escapeHtml(name)}</span><span>${escapeHtml(value)}</span></li>`).join('')}</ul>` : '';
}

function seconds(value) {
  return typeof value === 'number' ? `${value.toFixed(value >= 10 ? 0 : 1)} s` : null;
}

function perfDetails(id, data) {
  if (!data) return '';
  if (id === 'system') {
    const disks = (data.disks || []).slice(0, 4).map((disk) => usageBar(`Disk ${disk.mount}`, disk.used_percent, `${disk.free} free of ${disk.total}`)).join('');
    return usageBar('CPU', data.cpu_percent, `${data.cpu_cores_logical || '?'} threads`) + usageBar('Memory', data.ram_percent, `${data.ram_used} of ${data.ram_total}`)
      + disks + perfKv([['Swap', data.swap_percent != null ? `${data.swap_percent}%` : null], ['Running for', data.uptime], ['Processes', data.process_count]]);
  }
  if (id === 'processes' || id === 'memory') {
    const rows = Array.isArray(data) ? data.slice(0, 6) : [];
    return perfList(rows.map((item) => [item.name, id === 'processes' ? `${item.cpu_percent}% CPU` : `${item.memory} (${item.memory_percent}%)`]));
  }
  if (id === 'benchmark') {
    const net = data.network || {};
    return perfKv([['CPU (one core)', data.cpu?.ops_per_second ? `${Number(data.cpu.ops_per_second).toLocaleString()} hashes/s` : null],
      ['Disk write', data.disk?.write_mbps != null ? `${data.disk.write_mbps} MB/s` : null], ['Disk read', data.disk?.read_mbps != null ? `${data.disk.read_mbps} MB/s` : null],
      ['Network latency', net.average_latency_ms != null ? `${net.average_latency_ms} ms` : (net.available === false ? 'unreachable' : null)]]);
  }
  if (id === 'boot') {
    const slow = (data.slowed_by || []).map((item) => [`${item.name} (${item.kind})`, item.slower_by_ms ? `+${(item.slower_by_ms / 1000).toFixed(1)} s` : seconds(item.total_ms / 1000) || '']);
    return perfKv([['Last start-up', seconds(data.last_boot_seconds)], ['Average', data.boots_measured > 1 ? seconds(data.average_boot_seconds) : null],
      ['Desktop ready after', seconds(data.desktop_ready_seconds)], ['Startup programs', data.startup_programs], ['Running for', data.uptime_days != null ? `${data.uptime_days} days` : null],
      ['Fast startup', data.fast_startup === undefined ? null : (data.fast_startup ? 'on' : 'off')], ['Last start', data.last_boot_type]])
      + (slow.length ? `<p class="perf-sub-label">Slowed the start-up down</p>${perfList(slow)}` : '');
  }
  if (id === 'hardware') {
    const cpu = data.cpu || {};
    const problems = (data.problem_devices || []).slice(0, 4).map((item) => [item.name, item.problem || `code ${item.code}`]);
    return perfKv([['Model', data.model], ['CPU', cpu.name], ['CPU speed', cpu.performance_percent != null ? `${cpu.performance_percent}% of base clock` : null],
      ['Temperature', data.max_temperature_c != null ? `${data.max_temperature_c} °C` : 'no sensor'], ['Memory', data.ram_total],
      ['Graphics', (data.gpus || []).map((gpu) => `${gpu.name}${gpu.ok ? '' : ' (problem)'}`).join(', ')], ['Hardware errors (7 days)', data.hardware_errors_7d]])
      + (problems.length ? `<p class="perf-sub-label">Devices with problems</p>${perfList(problems)}` : '');
  }
  if (id === 'disks') {
    const rows = Array.isArray(data) ? data : [];
    return perfList(rows.map((row) => (row.FriendlyName
      ? [`${row.FriendlyName} (${row.MediaType || 'disk'}, ${row.SizeGB || '?'} GB)`, row.HealthStatus || 'unknown']
      : [row.disk || 'disk', row.smart || 'unknown'])));
  }
  if (id === 'battery') {
    return perfKv([['Health', data.health_percent != null ? `${data.health_percent}% of design capacity` : null],
      ['Holds now', data.full_charge_mwh ? `${data.full_charge_mwh} mWh` : null], ['Designed for', data.design_mwh ? `${data.design_mwh} mWh` : null],
      ['Charge cycles', data.cycle_count], ['Condition', data.condition], ['Maximum capacity', data.maximum_capacity]]);
  }
  if (id === 'input') {
    const devices = (data.devices || []).filter((item) => item.connection !== 'virtual');
    return perfList(devices.map((item) => [`${item.name} (${item.kind}, ${item.connection})`, item.status === 'working' ? 'working' : `${item.status}${item.problem ? `: ${item.problem}` : ''}`]));
  }
  return '';
}

function perfCard(meta, section, job) {
  if (!section) return '';
  const issues = meta.tool ? (job.findings || []).filter((item) => item.source === meta.tool) : [];
  const worst = issues.map((item) => PERF_TONES[item.severity]).sort((a, b) => ['critical', 'warning', 'ok'].indexOf(a) - ['critical', 'warning', 'ok'].indexOf(b))[0];
  const states = {
    queued: ['unknown', 'Waiting'], running: ['unknown', 'Testing'], skipped: ['', 'Not available'], failed: ['critical', 'Failed'],
    done: [worst || 'ok', worst === 'critical' ? 'Problem' : worst === 'warning' ? 'Attention' : 'OK'],
  };
  const [tone, label] = states[section.state] || ['', section.state];
  const busy = section.state === 'queued' || section.state === 'running';
  return `<article class="perf-card ${section.state === 'done' ? tone : ''}" data-perf-section="${escapeHtml(meta.id)}">
    <div class="perf-card-head"><h3>${escapeHtml(meta.title)}</h3><span class="status-pill ${tone}">${busy ? '<span class="spinner"></span>' : ''}${escapeHtml(label)}</span></div>
    ${section.state === 'done' ? perfDetails(meta.id, section.data) : ''}
    ${section.summary ? `<p class="perf-summary">${escapeHtml(section.summary)}</p>` : ''}
    ${issues.length ? `<div class="perf-issues">${issues.map((item) => `<div class="perf-issue"><span class="sev-pill ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span> <strong>${escapeHtml(item.title)}</strong><br><small>${escapeHtml(item.detail || '')}</small></div>`).join('')}</div>` : ''}
  </article>`;
}

function renderPerfFindings(job) {
  const box = $('perf-findings');
  const items = job?.findings || [];
  if (!items.length || job.state === 'running') {
    box.classList.add('hidden');
    return;
  }
  box.classList.remove('hidden');
  box.innerHTML = `<p class="kicker">Problems found by the rules (instant)</p>${items.map((item) => `<div class="perf-finding"><span class="sev-pill ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><div><strong>${escapeHtml(item.title)}</strong><br><small class="soft-label">${escapeHtml(item.detail || '')}</small></div></div>`).join('')}`;
}

function renderPerfAi(job) {
  const panel = $('perf-ai');
  if (!job) {
    panel.classList.add('hidden');
    return;
  }
  panel.classList.remove('hidden');
  const running = job.state === 'running';
  panel.innerHTML = `<div class="section-heading">
      <div><p class="kicker">AI analysis</p><h2>What is slowing this computer down?</h2>
        <p class="soft-label">${running ? 'Available when the test finishes.' : 'The AI reads these results, thinks it through and suggests 3-4 ranked fixes. It never changes anything itself: each fix runs only if you approve it.'}</p></div>
      <div class="button-row">
        <label class="think-toggle" title="Also lets the AI run extra read-only checks; takes several minutes longer"><input type="checkbox" id="perf-think"> Think deeper</label>
        ${job.analysis_session_id ? '<button class="ghost-button" type="button" data-perf-open-analysis>Open last analysis</button>' : ''}
        <button class="primary-button" type="button" data-perf-analyse ${running ? 'disabled' : ''}><svg><use href="#i-spark"/></svg>Analyse with AI</button>
      </div></div>`;
}

function perfUpdateState(id, fallback) {
  if (perfBusy.has(id)) return '<span class="status-pill unknown"><span class="spinner"></span>Installing</span>';
  const done = perfDone.get(id);
  if (!done) return fallback;
  const tone = ['installed', 'updated', 'installed already'].includes(done) ? 'ok' : /^(installed with errors|skipped)/.test(done) ? 'warning' : 'critical';
  return `<span class="status-pill ${tone}" title="${escapeHtml(done)}">${escapeHtml(done.length > 60 ? `${done.slice(0, 59)}…` : done)}</span>`;
}

function renderOsUpdates(section, deviceOs) {
  if (!section) return '';
  if (section.state === 'queued' || section.state === 'running') return '<p class="soft-label"><span class="spinner"></span>Searching for OS updates (Windows Update can take a minute)...</p>';
  if (section.state !== 'done') return `<p class="soft-label">${escapeHtml(section.summary || 'Not available')}</p>`;
  const data = section.data || {};
  const updates = data.updates || [];
  const restartNote = data.reboot_pending ? '<p class="perf-note warn">A restart is pending to finish earlier updates. AIops never restarts the computer: restart it when it suits you.</p>' : '';
  if (!updates.length) return `<p class="soft-label">${escapeHtml(section.summary)}</p>${restartNote}${data.note ? `<p class="soft-label">${escapeHtml(data.note)}</p>` : ''}`;
  const canInstall = data.can_install && deviceOs !== 'Darwin';
  const rows = updates.map((update) => {
    const selectable = canInstall && update.installable && !perfBusy.has(update.id) && !perfDone.has(update.id);
    const checked = perfPicked.has(update.id) ? perfPicked.get(update.id) : update.recommended;
    return `<tr>
      <td>${selectable ? `<input type="checkbox" data-os-update="${escapeHtml(update.id)}" ${checked ? 'checked' : ''} aria-label="Select ${escapeHtml(update.title)}">` : ''}</td>
      <td><strong>${escapeHtml(update.title)}</strong>${update.note ? `<small class="soft-label perf-row-note">${escapeHtml(update.note)}</small>` : ''}</td>
      <td><span class="sev-pill ${update.kind === 'security' ? 'high' : update.kind === 'driver' ? 'medium' : ''}">${escapeHtml(update.kind)}</span></td>
      <td>${escapeHtml(update.size_text || '--')}</td>
      <td>${perfUpdateState(update.id, update.may_restart ? '<small class="soft-label">may need a restart</small>' : '')}</td></tr>`;
  }).join('');
  const reason = data.install_note || (deviceOs === 'Darwin' ? 'Install macOS updates from System Settings > General > Software Update on the Mac.'
    : 'The agent is not running with administrator/root rights, so it cannot install updates. Re-run the install command from Add Agent (it runs the agent as SYSTEM).');
  const blocked = !canInstall ? `<p class="perf-note">${escapeHtml(reason)}</p>` : '';
  return `${restartNote}${blocked}<div class="table-wrap flat"><table><thead><tr><th></th><th>Update</th><th>Kind</th><th>Size</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
    ${canInstall ? '<div class="button-row perf-actions"><button class="primary-button" type="button" data-perf-install-os>Install selected OS updates</button><small class="soft-label">Downloads and installs in the background. The computer is never restarted for you.</small></div>' : ''}
    ${data.note ? `<p class="soft-label">${escapeHtml(data.note)}</p>` : ''}`;
}

function renderAppUpdates(section) {
  if (!section) return '';
  if (section.state === 'queued' || section.state === 'running') return '<p class="soft-label"><span class="spinner"></span>Listing installed programs and checking for updates...</p>';
  if (section.state !== 'done') return `<p class="soft-label">${escapeHtml(section.summary || 'Not available')}</p>`;
  const data = section.data || {};
  const updates = data.updates || [];
  const note = data.updates_note ? `<p class="soft-label">${escapeHtml(data.updates_note)}</p>` : '';
  if (!updates.length) return `<p class="soft-label">All ${Number(data.count) || 0} programs are up to date.</p>${note}`;
  const canUpdate = data.can_update !== false;
  const pending = updates.filter((item) => !perfBusy.has(item.update_id) && !perfDone.has(item.update_id));
  const rows = updates.map((item) => `<tr><td><strong>${escapeHtml(item.name)}</strong></td>
      <td>${escapeHtml(item.version || '--')} <span class="sw-new">→ ${escapeHtml(item.available_version || 'newer')}</span></td>
      <td class="sw-actions">${canUpdate ? perfUpdateState(item.update_id, `<button class="ghost-button" type="button" data-perf-app-update="${escapeHtml(item.update_id)}">Update</button>`) : ''}</td></tr>`).join('');
  return `<div class="table-wrap flat"><table><thead><tr><th>Program</th><th>Version</th><th class="sw-actions-col"></th></tr></thead><tbody>${rows}</tbody></table></div>
    <div class="button-row perf-actions">${canUpdate && pending.length > 1 ? `<button class="ghost-button" type="button" data-perf-app-all>Update all (${pending.length})</button>` : ''}<button class="ghost-button" type="button" data-goto-software>All programs in the Software tab</button></div>${note}`;
}

function renderPerfUpdates(job) {
  const panel = $('perf-updates');
  const sections = job?.sections || {};
  if (!sections.os_updates && !sections.apps) {
    panel.classList.add('hidden');
    return;
  }
  panel.classList.remove('hidden');
  panel.innerHTML = `<div class="section-heading"><div><p class="kicker">Updates · nothing installs until you click and confirm</p><h2>Updates available</h2></div></div>
    <h3 class="perf-sub-title">Operating system</h3>${renderOsUpdates(sections.os_updates, job.os_type)}
    <h3 class="perf-sub-title">Apps</h3>${renderAppUpdates(sections.apps)}`;
}

function renderPerformanceJob() {
  const job = perfJob;
  const running = job?.state === 'running';
  $('perf-run').disabled = Boolean(running);
  if (!job) {
    $('perf-sections').innerHTML = '';
    ['perf-findings', 'perf-ai', 'perf-updates'].forEach((id) => $(id).classList.add('hidden'));
    return;
  }
  const sections = Object.values(job.sections || {});
  const finished = sections.filter((section) => !['queued', 'running'].includes(section.state)).length;
  const end = job.finished_at ? new Date(job.finished_at).getTime() : Date.now();
  const elapsed = Math.max(0, Math.round((end - new Date(job.started_at).getTime()) / 1000));
  const problems = (job.findings || []).length;
  setPerfStatus(running
    ? `Testing ${job.device}: ${finished} of ${sections.length} checks done (${elapsed}s; about 1-3 min, the update search is the slowest)...`
    : `Tested ${job.device} on ${new Date(job.finished_at || job.started_at).toLocaleString()} in ${elapsed}s: ${problems ? `${problems} problem${problems === 1 ? '' : 's'} found` : 'no problems found by the rules'}.`);
  renderPerfFindings(job);
  $('perf-sections').innerHTML = PERF_SECTIONS.map((meta) => perfCard(meta, job.sections?.[meta.id], job)).join('');
  renderPerfUpdates(job);
  renderPerfAi(job);
}

async function pollPerformance(jobId, failures = 0) {
  clearTimeout(perfPollTimer);
  let response;
  try {
    response = await fetch(`/api/performance/jobs/${encodeURIComponent(jobId)}`);
    const job = await response.json();
    if (!response.ok) throw new Error(job.detail || 'The test was lost');
    if (job.device_id !== perfDeviceId) return;
    perfJob = job;
    renderPerformanceJob();
    if (job.state === 'running') perfPollTimer = setTimeout(() => pollPerformance(jobId), 2000);
  } catch (error) {
    // A lost test (404) is final; a network hiccup or a busy server gets a few more tries.
    if (response?.status !== 404 && failures < 5) {
      perfPollTimer = setTimeout(() => pollPerformance(jobId, failures + 1), 4000);
      return;
    }
    setPerfStatus(friendlyError(error), 'error');
    $('perf-run').disabled = false;
  }
}

async function loadPerformance() {
  resizeMouseTrail();
  const deviceId = await fillDeviceSelect($('perf-device'), () => loadPerformance());
  if (deviceId !== perfDeviceId) {
    clearTimeout(perfPollTimer);
    perfDeviceId = deviceId;
    perfJob = null;
    [perfDone, perfPicked].forEach((map) => map.clear());
    renderPerformanceJob();
  }
  try {
    const response = await fetch(`/api/agents/${encodeURIComponent(deviceId)}/performance/latest`);
    if (deviceId !== perfDeviceId) return;
    if (response.status === 204 || !response.ok) {
      if (!perfJob) setPerfStatus('No full test on this device yet. Click Run full test (about 1-3 minutes; it only reads).');
      return;
    }
    const job = await response.json();
    if (perfJob?.job_id !== job.job_id || job.state === 'running') {
      perfJob = job;
      renderPerformanceJob();
      if (job.state === 'running') pollPerformance(job.job_id);
    }
  } catch (error) {
    setPerfStatus(friendlyError(error), 'error');
  }
}

async function runPerformanceTest() {
  const deviceId = $('perf-device').value || perfDeviceId;
  if (!deviceId) return;
  perfDeviceId = deviceId;
  $('perf-run').disabled = true;
  try {
    const response = await fetch(`/api/agents/${encodeURIComponent(deviceId)}/performance/test`, { method: 'POST' });
    const job = await response.json();
    if (!response.ok) throw new Error(job.detail || 'Could not start the test');
    [perfDone, perfPicked].forEach((map) => map.clear());
    perfJob = job;
    renderPerformanceJob();
    pollPerformance(job.job_id);
  } catch (error) {
    setPerfStatus(friendlyError(error), 'error');
    $('perf-run').disabled = false;
  }
}

async function analysePerformance() {
  const job = perfJob;
  if (!job || job.state === 'running') return;
  const button = document.querySelector('[data-perf-analyse]');
  if (button) button.disabled = true;
  try {
    const response = await fetch(`/api/agents/${encodeURIComponent(job.device_id)}/performance/analyse`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ job_id: job.job_id, think: Boolean($('perf-think')?.checked) }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'AI analysis failed to start');
    job.analysis_session_id = data.session_id;
    openPerfAnalysis(data.session_id, job.device_id);
  } catch (error) {
    toast(friendlyError(error), 'error');
    if (button) button.disabled = false;
  }
}

function openPerfAnalysis(sessionId, deviceId) {
  switchTab('troubleshoot');
  loadTroubleshootTargets(deviceId);
  openTroubleshootSession(sessionId);
}

async function installOsUpdates() {
  const job = perfJob;
  const updates = job?.sections?.os_updates?.data?.updates || [];
  const ids = [...document.querySelectorAll('#perf-updates [data-os-update]:checked')].map((box) => box.dataset.osUpdate);
  if (!ids.length) {
    toast('Tick at least one update first', 'error');
    return;
  }
  const chosen = updates.filter((update) => ids.includes(update.id));
  const list = chosen.slice(0, 8).map((update) => `- ${update.title}`).join('\n') + (chosen.length > 8 ? `\n...and ${chosen.length - 8} more` : '');
  const restart = chosen.some((update) => update.may_restart) ? '\n\nSome may need a restart to finish. AIops never restarts the computer: you restart it when it suits you.' : '';
  if (!window.confirm(`Install ${ids.length} OS update${ids.length === 1 ? '' : 's'} on ${job.device}?\n\n${list}\n\nThey download and install in the background, which can take a long time.${restart}`)) return;
  ids.forEach((id) => perfBusy.add(id));
  renderPerfUpdates(job);
  try {
    const result = await runSoftwareJob(`/api/agents/${encodeURIComponent(job.device_id)}/os-updates/install`, { update_ids: ids }, 'Installing OS updates...', (text) => setPerfStatus(text));
    const data = result.data || {};
    (data.installed || []).forEach((row) => perfDone.set(row.id, row.result));
    (data.skipped || []).forEach((row) => perfDone.set(row.id, `skipped: ${row.reason}`));
    (data.no_longer_offered || []).forEach((id) => perfDone.set(id, 'installed already'));
    if (!data.installed && result.state === 'done') ids.forEach((id) => perfDone.set(id, 'installed'));
    toast(result.summary || 'Done', result.state === 'done' ? 'ok' : 'error');
    setPerfStatus(result.summary || '', result.state === 'done' ? '' : 'error');
  } catch (error) {
    toast(friendlyError(error), 'error');
    setPerfStatus(friendlyError(error), 'error');
  } finally {
    ids.forEach((id) => perfBusy.delete(id));
    if (perfJob === job) renderPerfUpdates(job);
  }
}

async function updatePerfApps(items) {
  const job = perfJob;
  if (!items.length) return;
  const names = items.map((item) => item.name);
  const question = items.length === 1
    ? `Update "${names[0]}" to the latest version?\n\nThe program may close while it updates.`
    : `Update ${items.length} programs one after another?\n\n${names.slice(0, 10).map((name) => `- ${name}`).join('\n')}${names.length > 10 ? `\n...and ${names.length - 10} more` : ''}\n\nEach program may close while it updates.`;
  if (!window.confirm(question)) return;
  items.forEach((item) => perfBusy.add(item.update_id));
  renderPerfUpdates(job);
  for (const item of items) {
    try {
      const result = await runSoftwareJob(`/api/agents/${encodeURIComponent(job.device_id)}/software/update`, { package_id: item.update_id, name: item.name }, `Updating ${item.name}...`, (text) => setPerfStatus(text));
      perfDone.set(item.update_id, result.state === 'done' ? 'updated' : `failed: ${result.summary || ''}`);
      toast(result.summary || item.name, result.state === 'done' ? 'ok' : 'error');
    } catch (error) {
      perfDone.set(item.update_id, `failed: ${friendlyError(error)}`);
      toast(friendlyError(error), 'error');
    }
    perfBusy.delete(item.update_id);
    if (perfJob === job) renderPerfUpdates(job);
  }
  const failed = items.filter((item) => !/^updated/.test(perfDone.get(item.update_id) || '')).length;
  setPerfStatus(failed ? `${items.length - failed} of ${items.length} updated; ${failed} failed (see the list).` : `${items.length} program${items.length === 1 ? '' : 's'} updated.`, failed ? 'error' : '');
}

function onPerfUpdatesClick(event) {
  const apps = perfJob?.sections?.apps?.data?.updates || [];
  if (event.target.closest('[data-perf-install-os]')) installOsUpdates();
  const one = event.target.closest('[data-perf-app-update]');
  if (one) updatePerfApps(apps.filter((item) => item.update_id === one.dataset.perfAppUpdate));
  if (event.target.closest('[data-perf-app-all]')) updatePerfApps(apps.filter((item) => !perfBusy.has(item.update_id) && !perfDone.has(item.update_id)));
  if (event.target.closest('[data-goto-software]') && perfJob) openSoftware(perfJob.device_id);
}

// ----------------------------------------------------------------------------
// Keyboard and mouse testers (the computer running this browser)
// ----------------------------------------------------------------------------

const KB_STUCK_MS = 2000;
const KB_CHATTER_MS = 35; // a key or button that re-triggers this fast after release is bouncing (worn switch)
const MOUSE_CHATTER_MS = 30; // a fast human double-click still leaves 60+ ms between release and press
const KB_ROWS = [
  [['Escape', 'Esc'], ...Array.from({ length: 12 }, (_, i) => [`F${i + 1}`, `F${i + 1}`]), ['Delete', 'Del', 1.2]],
  [['Backquote', '`'], ...'1234567890'.split('').map((digit) => [`Digit${digit}`, digit]), ['Minus', '-'], ['Equal', '='], ['Backspace', 'Backspace', 2]],
  [['Tab', 'Tab', 1.5], ...'QWERTYUIOP'.split('').map((key) => [`Key${key}`, key]), ['BracketLeft', '['], ['BracketRight', ']'], ['Backslash', '\\', 1.5]],
  [['CapsLock', 'Caps', 1.8], ...'ASDFGHJKL'.split('').map((key) => [`Key${key}`, key]), ['Semicolon', ';'], ['Quote', "'"], ['Enter', 'Enter', 2.2]],
  [['ShiftLeft', 'Shift', 2.3], ...'ZXCVBNM'.split('').map((key) => [`Key${key}`, key]), ['Comma', ','], ['Period', '.'], ['Slash', '/'], ['ShiftRight', 'Shift', 2.7]],
  [['ControlLeft', 'Ctrl', 1.4], ['MetaLeft', 'Win', 1.2], ['AltLeft', 'Alt', 1.2], ['Space', 'Space', 6], ['AltRight', 'Alt', 1.2], ['ControlRight', 'Ctrl', 1.4],
    ['ArrowLeft', '←'], ['ArrowUp', '↑'], ['ArrowDown', '↓'], ['ArrowRight', '→']],
];
const KB_CODES = new Set(KB_ROWS.flat().map(([code]) => code));
const kbState = { tested: new Set(), down: new Map(), released: new Map(), stuck: new Set(), chatter: new Set(), extra: new Set(), timer: null };
const MOUSE_LABELS = { 0: 'Left', 1: 'Middle', 2: 'Right', 3: 'Back', 4: 'Forward', dbl: 'Double-click', up: 'Scroll up', down: 'Scroll down' };
const mouseState = { tested: new Set(), released: {}, chatter: new Set(), moves: 0, last: null, firstMove: 0, lastMove: 0 };

function buildKeyboard() {
  $('kb-layout').innerHTML = KB_ROWS.map((row) => `<div class="kb-row">${row.map(([code, label, width]) => `<span class="kb-key" data-key="${escapeHtml(code)}" style="--w:${width || 1}">${escapeHtml(label)}</span>`).join('')}</div>`).join('');
}

function kbKey(code) {
  return document.querySelector(`#kb-layout [data-key="${CSS.escape(code)}"]`);
}

function renderKeyboardResult() {
  const total = KB_CODES.size;
  const tested = [...kbState.tested].filter((code) => KB_CODES.has(code)).length;
  const parts = [`${tested} of ${total} keys registered.`];
  if (kbState.stuck.size) parts.push(`Held down over ${KB_STUCK_MS / 1000} s: ${[...kbState.stuck].join(', ')} (if you were not holding it, the key may be stuck).`);
  if (kbState.chatter.size) parts.push(`Typed twice by one press: ${[...kbState.chatter].join(', ')} (a worn or dirty key switch).`);
  if (kbState.extra.size) parts.push(`Other keys: ${[...kbState.extra].slice(0, 12).join(', ')}.`);
  if (tested && tested < total) parts.push('Fn and some media keys never reach the browser.');
  $('kb-result').textContent = kbState.tested.size || kbState.extra.size ? parts.join(' ') : 'No keys tested yet.';
}

function onKeyDown(event) {
  event.preventDefault();
  const code = event.code || event.key;
  if (event.repeat) return;
  const now = performance.now();
  if (now - (kbState.released.get(code) || -Infinity) < KB_CHATTER_MS) kbState.chatter.add(code);
  kbState.down.set(code, now);
  const key = kbKey(code);
  if (key) key.classList.add('down');
  else kbState.extra.add(code);
  renderKeyboardResult();
}

function onKeyUp(event) {
  event.preventDefault();
  const code = event.code || event.key;
  kbState.down.delete(code);
  kbState.released.set(code, performance.now());
  kbState.tested.add(code);
  const key = kbKey(code);
  if (key) key.classList.remove('down');
  if (key) key.classList.add('tested');
  renderKeyboardResult();
  if (code === 'Escape') event.currentTarget.blur(); // Tab is a key under test, so Esc is the way out
}

function checkStuckKeys() {
  const now = performance.now();
  kbState.down.forEach((since, code) => {
    if (now - since > KB_STUCK_MS && !kbState.stuck.has(code)) {
      kbState.stuck.add(code);
      kbKey(code)?.classList.add('stuck');
      renderKeyboardResult();
    }
  });
}

function onKeyboardFocus(focused) {
  clearInterval(kbState.timer);
  if (focused) {
    kbState.timer = setInterval(checkStuckKeys, 400);
    return;
  }
  // Keys released while the tester was not focused never send keyup.
  kbState.down.forEach((_since, code) => kbKey(code)?.classList.remove('down'));
  kbState.down.clear();
}

function markMouse(id, down) {
  const element = document.querySelector(`#mouse-pad [data-mouse-btn="${id}"]`);
  mouseState.tested.add(String(id));
  if (element) {
    element.classList.add('tested');
    element.classList.toggle('down', Boolean(down));
  }
}

function renderMouseResult() {
  const tested = Object.keys(MOUSE_LABELS).filter((id) => mouseState.tested.has(id)).map((id) => MOUSE_LABELS[id]);
  const parts = [tested.length ? `Working: ${tested.join(', ')}.` : 'No button tested yet.'];
  if (mouseState.chatter.size) parts.push(`${[...mouseState.chatter].join(', ')} registered two clicks for one press: a worn switch causes unwanted double-clicks.`);
  if (mouseState.moves > 20) {
    const span = (mouseState.lastMove - mouseState.firstMove) / 1000;
    parts.push(`Movement: ${mouseState.moves} events${span > 0.5 ? `, about ${Math.round(mouseState.moves / span)} per second` : ''}; the trail should be smooth with no jumps.`);
  }
  $('mouse-result').textContent = mouseState.tested.size || mouseState.moves ? parts.join(' ') : 'No mouse input yet.';
}

function resizeMouseTrail() {
  const canvas = $('mouse-trail');
  const pad = $('mouse-pad');
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.round(pad.clientWidth * ratio);
  canvas.height = Math.round(pad.clientHeight * ratio);
  canvas.getContext('2d').setTransform(ratio, 0, 0, ratio, 0, 0);
  mouseState.last = null;
}

function onMouseMove(event) {
  const pad = $('mouse-pad');
  if (!$('mouse-trail').width) resizeMouseTrail(); // the canvas has no size while its tab is hidden
  const box = pad.getBoundingClientRect();
  const point = { x: event.clientX - box.left, y: event.clientY - box.top };
  const now = performance.now();
  if (!mouseState.moves) mouseState.firstMove = now;
  mouseState.moves += 1;
  mouseState.lastMove = now;
  const context = $('mouse-trail').getContext('2d');
  if (mouseState.last && now - mouseState.last.at < 200) {
    context.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#5b8cff';
    context.lineWidth = 2;
    context.lineCap = 'round';
    context.beginPath();
    context.moveTo(mouseState.last.x, mouseState.last.y);
    context.lineTo(point.x, point.y);
    context.stroke();
  }
  mouseState.last = { ...point, at: now };
  if (mouseState.moves % 15 === 0) renderMouseResult();
}

function onMouseButton(event, down) {
  if (event.button > 4) return;
  event.preventDefault(); // stops Back/Forward navigation, middle-click autoscroll and text selection
  const now = performance.now();
  if (down && now - (mouseState.released[event.button] || -Infinity) < MOUSE_CHATTER_MS) mouseState.chatter.add(MOUSE_LABELS[event.button]);
  if (!down) mouseState.released[event.button] = now;
  markMouse(event.button, down);
  renderMouseResult();
}

function resetInputTests() {
  [kbState.tested, kbState.stuck, kbState.chatter, kbState.extra].forEach((set) => set.clear());
  kbState.down.clear();
  kbState.released.clear();
  document.querySelectorAll('#kb-layout .kb-key').forEach((key) => key.classList.remove('down', 'tested', 'stuck'));
  Object.assign(mouseState, { released: {}, moves: 0, last: null, firstMove: 0, lastMove: 0 });
  mouseState.tested.clear();
  mouseState.chatter.clear();
  document.querySelectorAll('#mouse-pad .mouse-btn').forEach((button) => button.classList.remove('tested', 'down'));
  resizeMouseTrail();
  renderKeyboardResult();
  renderMouseResult();
}

function wireInputTesters() {
  buildKeyboard();
  const keyboard = $('kb-tester');
  keyboard.addEventListener('keydown', onKeyDown);
  keyboard.addEventListener('keyup', onKeyUp);
  keyboard.addEventListener('focus', () => onKeyboardFocus(true));
  keyboard.addEventListener('blur', () => onKeyboardFocus(false));
  const pad = $('mouse-pad');
  pad.addEventListener('mousedown', (event) => onMouseButton(event, true));
  pad.addEventListener('mouseup', (event) => onMouseButton(event, false));
  pad.addEventListener('auxclick', (event) => event.preventDefault());
  pad.addEventListener('contextmenu', (event) => event.preventDefault());
  pad.addEventListener('dblclick', () => { markMouse('dbl'); renderMouseResult(); });
  pad.addEventListener('wheel', (event) => {
    event.preventDefault();
    if (event.deltaY) markMouse(event.deltaY < 0 ? 'up' : 'down');
    renderMouseResult();
  }, { passive: false });
  pad.addEventListener('pointermove', onMouseMove);
  window.addEventListener('resize', resizeMouseTrail);
  $('input-reset').addEventListener('click', resetInputTests);
}

// ============================================================================
// Event Logs
// ============================================================================

function setLogCountCard(prefix, count, tone) {
  const card = $(`logs-${prefix}-card`);
  card.className = `metric-card ${count > 0 ? tone : 'ok'}`;
  setText(`logs-${prefix}-state`, count > 0 ? String(count) : 'CLEAR');
  setText(`logs-${prefix}-detail`, count > 0 ? `${count} in the last window` : 'None recorded');
}

function renderEventLogs(report) {
  setLogCountCard('critical', report.critical_count || 0, 'critical');
  setLogCountCard('error', report.error_count || 0, 'critical');
  setLogCountCard('warning', report.warning_count || 0, 'warning');

  const events = report.events || [];
  const body = $('logs-body');
  if (!report.available) {
    body.innerHTML = `<tr><td colspan="4" class="empty-state">${escapeHtml(report.detail || 'Event log data unavailable on this platform.')}</td></tr>`;
    return;
  }
  if (!events.length) {
    body.innerHTML = `<tr><td colspan="4" class="empty-state">${escapeHtml(report.detail || 'No warning, error, or critical events found.')}</td></tr>`;
    return;
  }
  body.innerHTML = events.map((event) => `
    <tr>
      <td>${event.time ? escapeHtml(new Date(event.time).toLocaleString()) : '--'}</td>
      <td><span class="severity severity-${(event.level || '').toLowerCase() === 'warning' ? 'medium' : 'critical'}">${escapeHtml(event.level || 'Unknown')}</span></td>
      <td>${escapeHtml(event.source || '--')}</td>
      <td>${escapeHtml(event.message || '')}</td>
    </tr>
  `).join('');
}

// The server's own agent first, then online agents, then offline ones, then this AIops process.
function targetRank(target) {
  return target.server ? -1 : target.device_id === 'local' ? 2 : target.status === 'online' ? 0 : 1;
}

const NO_DEVICES_OPTION = '<option value="">No devices yet: add one under Add Agent</option>';

// Fill a device <select> (best target first).
async function fillDeviceSelect(select, onChange) {
  const current = select.value;
  try {
    const data = await fetch('/api/troubleshoot/targets').then((response) => response.json());
    const targets = (data.targets || []).sort((a, b) => targetRank(a) - targetRank(b));
    select.innerHTML = targets.length
      ? targets.map((target) => `<option value="${escapeHtml(target.device_id)}">${escapeHtml(target.label)} / ${escapeHtml(target.os_type)}${target.status !== 'online' ? ' - offline' : ''}</option>`).join('')
      : NO_DEVICES_OPTION;
    if (current && [...select.options].some((option) => option.value === current)) select.value = current;
  } catch (_error) {
    if (!select.options.length) select.innerHTML = '<option value="local">This server</option>';
  }
  if (!select.dataset.wired) {
    select.dataset.wired = '1';
    select.addEventListener('change', onChange);
  }
  return select.value || 'local';
}

function logsPath(deviceId, suffix = '') {
  return deviceId === 'local' ? `/api/diagnostics/logs${suffix}` : `/api/agents/${deviceId}/logs${suffix}`;
}

async function loadEventLogs() {
  try {
    const deviceId = await fillDeviceSelect($('logs-device'), () => { $('logs-diagnosis').classList.add('hidden'); loadEventLogs(); });
    const response = await fetch(logsPath(deviceId));
    if (!response.ok) throw new Error('Event log data unavailable');
    renderEventLogs(await response.json());
  } catch (error) {
    $('logs-body').innerHTML = `<tr><td colspan="4" class="empty-state">${escapeHtml(error.message)}</td></tr>`;
  }
}

async function diagnoseEventLogs() {
  const output = $('logs-diagnosis');
  output.classList.remove('hidden');
  output.textContent = 'Consulting technician... (about 1-2 min on a laptop CPU)';
  try {
    const response = await fetch(`${logsPath($('logs-device').value || 'local', '/diagnose')}?think=${Boolean($('logs-think')?.checked)}`, { method: 'POST' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'AI unavailable');
    renderDiagnosis(output, data);
  } catch (error) {
    output.textContent = friendlyError(error);
  }
}

// ============================================================================
// Ask Technician (chat)
// ============================================================================

async function checkAI() {
  try {
    const status = await fetch('/api/ai/status').then((response) => response.json());
    applyAiAvailability(Boolean(status.available), status.diagnosis_mode);
    $('ai-banner').classList.toggle('hidden', Boolean(status.available));
    if (!status.available) setText('ai-banner-detail', `${status.message} Local monitoring remains active.`);
    setText('ai-model-label', `AI: ${status.provider} / ${status.base_model || status.model || '--'} ${status.available ? '(ready)' : '(unavailable)'} · suggest-only${status.diagnosis_thinking ? ' · deep thinking' : ''}`);
    const learned = status.learned_model_active;
    const version = status.learned_model?.version;
    $('ai-chip').className = `ai-chip ${status.available && !status.load_error ? 'ok' : 'off'}${learned ? ' learned' : ''}`;
    setText('ai-chip-text', !status.available
      ? 'AI offline'
      : status.load_error
        ? `Model: ${status.model} · failed to load`
        : `Model: ${status.base_model || status.model}${learned ? ` · AIops brain${version ? ` v${version}` : ''}` : ''}`);
  } catch (_error) {
    applyAiAvailability(false);
    $('ai-banner').classList.remove('hidden');
    $('ai-chip').className = 'ai-chip off';
    setText('ai-chip-text', 'AI offline');
  }
}

// ============================================================================
// AI model switcher (topbar chip)
// ============================================================================

let modelPollTimer = null;

function formatGb(bytes) {
  return `${(bytes / 1e9).toFixed(1)} GB`;
}

function setModelPanel(open) {
  $('model-panel').classList.toggle('hidden', !open);
  $('ai-chip').setAttribute('aria-expanded', String(open));
  if (open) loadModels();
}

function modelAction(model) {
  if (model.active) return '<span class="status-pill ok">Active</span>';
  if (model.pull?.state === 'downloading') return '<span class="status-pill unknown">Downloading</span>';
  if (model.installed) return `<button class="ghost-button" type="button" data-model-select="${escapeHtml(model.name)}">Switch</button>`;
  return `<button class="ghost-button" type="button" data-model-pull="${escapeHtml(model.name)}">Download ${model.size_gb} GB</button>`;
}

function modelProgress(pull) {
  if (pull?.state === 'error') return `<small class="model-error">Download failed: ${escapeHtml(pull.error)}</small>`;
  if (pull?.state !== 'downloading') return '';
  const done = pull.total ? Math.round((pull.completed / pull.total) * 100) : 0;
  return `<div class="model-progress" role="progressbar" aria-valuenow="${done}" aria-valuemin="0" aria-valuemax="100"><span style="width:${done}%"></span></div>
    <small class="model-progress-text">${escapeHtml(pull.status || 'starting')}${pull.total ? ` · ${formatGb(pull.completed)} of ${formatGb(pull.total)}` : ''}</small>`;
}

function renderModels(data) {
  const list = $('model-list');
  if (!data.switchable) {
    list.innerHTML = `<p class="soft-label">Model switching needs the local Ollama provider (current: ${escapeHtml(data.provider)}).</p>`;
    return;
  }
  list.innerHTML = data.models.map((model) => `
    <div class="model-option${model.active ? ' active' : ''}">
      <div class="model-option-main">
        <strong>${escapeHtml(model.label)}</strong>
        <small class="model-meta">${escapeHtml(model.name)} · ${model.size_gb} GB · needs ~${model.ram_gb} GB free RAM · <span class="${model.commercial ? '' : 'model-warn'}">${escapeHtml(model.license)}${model.commercial ? '' : ' (no commercial use)'}</span></small>
        <p>${escapeHtml(model.note)} <span class="model-speed">${escapeHtml(model.speed)}.</span></p>
        ${modelProgress(model.pull)}
      </div>
      <div class="model-option-action">${modelAction(model)}</div>
    </div>`).join('');
  const status = $('model-panel-status');
  status.className = `model-panel-status${data.load_error ? ' error' : ''}`;
  status.textContent = data.load_error ? `${data.load_error} Close memory-heavy apps or switch to a smaller model.` : '';
}

async function loadModels() {
  clearTimeout(modelPollTimer);
  try {
    const data = await fetch('/api/ai/models').then((response) => response.json());
    renderModels(data);
    if ((data.models || []).some((model) => model.pull?.state === 'downloading')) modelPollTimer = setTimeout(loadModels, 1500);
  } catch (error) {
    $('model-list').innerHTML = `<p class="soft-label">${escapeHtml(friendlyError(error))}</p>`;
  }
}

async function modelRequest(path, name) {
  return readJson(await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model: name }) }));
}

function showModelError(error) {
  const status = $('model-panel-status');
  status.className = 'model-panel-status error';
  status.textContent = friendlyError(error);
}

async function selectModel(name) {
  document.querySelectorAll('[data-model-select]').forEach((button) => { button.disabled = true; });
  $('model-panel-status').className = 'model-panel-status';
  setText('model-panel-status', `Switching to ${name}...`);
  try {
    renderModels(await modelRequest('/api/ai/models/select', name));
    setText('model-panel-status', `Now using ${name}. It is loading into memory, so the first answer takes longer.`);
    toast(`AI model switched to ${name}`);
    checkAI();
    // A model that does not fit in RAM fails while loading; re-check so the failure shows up.
    setTimeout(checkAI, 20000);
  } catch (error) {
    showModelError(error);
    document.querySelectorAll('[data-model-select]').forEach((button) => { button.disabled = false; });
  }
}

async function pullModel(name) {
  try {
    await modelRequest('/api/ai/models/pull', name);
    loadModels();
  } catch (error) {
    showModelError(error);
  }
}

function storedMode() {
  try {
    return localStorage.getItem('sentinel-ts-mode');
  } catch (_error) {
    return null;
  }
}

function setMode(mode, remember = true) {
  if (!['instant', 'fast', 'deep'].includes(mode)) return;
  if (!tsAiAvailable && mode !== 'instant') mode = 'instant';
  tsMode = mode;
  document.querySelectorAll('.mode-option').forEach((option) => {
    const active = option.dataset.mode === mode;
    option.classList.toggle('active', active);
    option.setAttribute('aria-checked', String(active));
  });
  if (remember) {
    try {
      localStorage.setItem('sentinel-ts-mode', mode);
    } catch (_error) { /* storage unavailable: keep the choice for this page only */ }
  }
}

function applyAiAvailability(available, defaultMode) {
  tsAiAvailable = available;
  document.querySelectorAll('.mode-option').forEach((option) => {
    if (option.dataset.mode !== 'instant') {
      option.disabled = !available;
      option.title = available ? '' : 'AI is offline: the instant rule-based diagnosis still works';
    }
  });
  setMode(storedMode() || defaultMode || 'fast', false);
}

// ============================================================================
// Toast + theme
// ============================================================================

let toastTimer = null;

function toast(message, tone = 'ok') {
  const element = $('toast');
  element.textContent = message;
  element.className = `toast ${tone}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.add('hidden'), 4200);
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('sentinel-theme', next); } catch (_error) { /* private mode */ }
}

function addChatMessage(text, role) {
  const message = document.createElement('div');
  message.className = `chat-message ${role}`;
  if (role === 'assistant' && text && typeof text === 'object') {
    renderDiagnosis(message, text);
  } else {
    message.textContent = String(text);
  }
  $('chat-messages').appendChild(message);
  $('chat-messages').scrollTop = $('chat-messages').scrollHeight;
}

function renderChatContext(report) {
  const disk = (report?.disk || []).reduce((max, item) => Math.max(max, item.usage_percent || 0), 0);
  setText('chat-host', report?.system?.hostname || '--');
  setText('chat-cpu', percent(report?.cpu?.total_usage_percent));
  setText('chat-ram', percent(report?.memory?.ram?.usage_percent));
  setText('chat-disk', report ? percent(disk) : '--');
}

async function loadChatDevice() {
  const deviceId = await fillDeviceSelect($('chat-device'), () => { chatHistory = []; loadChatDevice(); });
  if (deviceId === 'local') {
    if (latestReport) renderChatContext(latestReport);
    return;
  }
  try {
    const snapshot = await fetch(`/api/agents/${deviceId}/diagnostics`).then((response) => response.json());
    renderChatContext(snapshot.diagnostics);
  } catch (_error) {
    renderChatContext(null);
  }
}

async function sendChat(event) {
  event.preventDefault();
  const input = $('chat-input');
  const message = input.value.trim();
  if (!message) return;

  input.value = '';
  addChatMessage(message, 'user');

  try {
    const deviceId = $('chat-device').value || 'local';
    const response = await fetch('/api/agent/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, device_id: deviceId, think: Boolean($('chat-think')?.checked), diagnostics: deviceId === 'local' ? latestReport : null, conversation_history: chatHistory }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Chat request failed (${response.status})`);
    addChatMessage(data.reply, 'assistant');
    chatHistory.push({ role: 'user', content: message }, { role: 'assistant', content: data.reply });
    chatHistory = chatHistory.slice(-6);
  } catch (error) {
    console.error('Chat request failed:', error);
    addChatMessage(friendlyError(error), 'assistant');
  }
}

// ============================================================================
// Agents — fleet list, device detail, provisioning
// ============================================================================

function statusPill(label, ok) {
  const state = ok === null || ok === undefined ? 'unknown' : ok ? 'ok' : 'critical';
  const text = ok === null || ok === undefined ? 'unknown' : ok ? 'ok' : 'attention';
  return `<span class="status-pill ${state}">${escapeHtml(label)}: ${text}</span>`;
}

function renderOsCountSummary(agentsList) {
  const summary = $('os-count-summary');
  if (!agentsList.length) {
    summary.innerHTML = '';
    return;
  }
  const counts = agentsList.reduce((totals, agent) => {
    const osName = agent.os_type || 'Unknown';
    totals[osName] = (totals[osName] || 0) + 1;
    return totals;
  }, {});
  const order = ['Windows', 'Darwin', 'Linux'];
  const labels = { Windows: 'Windows', Darwin: 'macOS', Linux: 'Linux' };
  const entries = Object.keys(counts).sort((a, b) => order.indexOf(a) - order.indexOf(b));
  summary.innerHTML = entries.map((osName) => `<span><b>${counts[osName]}</b>${escapeHtml(labels[osName] || osName)}</span>`).join('');
}

async function loadAgents() {
  const grid = $('agents-grid');
  try {
    const response = await fetch('/api/agents');
    if (!response.ok) throw new Error('Agent list unavailable');
    const data = await response.json();
    setText('agent-count', data.agents.length);
    renderOsCountSummary(data.agents);

    if (!data.agents.length) {
      grid.innerHTML = '<div class="empty-state">No devices connected yet - download the agent to get started.</div>';
      return;
    }

    grid.innerHTML = data.agents.map((agent) => {
      const osBadge = agent.os_type === 'Windows' ? 'W' : agent.os_type === 'Darwin' ? 'M' : 'L';
      return `
        <button class="agent-card" data-device="${escapeHtml(agent.device_id)}">
          <div class="agent-card-top">
            <span class="os-badge">${osBadge}</span>
            <span class="device-status ${escapeHtml(agent.status)}">${escapeHtml(agent.status)}</span>
          </div>
          <strong>${escapeHtml(agent.nickname)}</strong>
          <small>${escapeHtml(agent.hostname)} / ${escapeHtml(agent.os_type)}</small>
          <div class="agent-card-foot"><span>${escapeHtml(new Date(agent.last_seen).toLocaleString())}</span><b>${escapeHtml(agent.health?.status)}</b></div>
        </button>
      `;
    }).join('');
  } catch (error) {
    grid.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
  }
}

async function fetchDeviceExtra(path) {
  const response = await fetch(path);
  if (!response.ok) return null;
  return response.json();
}

async function loadDevice(deviceId) {
  const detail = $('device-detail');
  detail.classList.remove('hidden');
  detail.innerHTML = '<p>Loading device snapshot...</p>';

  try {
    const [snapshot, alerts, security, performanceData] = await Promise.all([
      fetch(`/api/agents/${deviceId}/diagnostics`).then((response) => response.json()),
      fetch(`/api/agents/${deviceId}/alerts`).then((response) => response.json()),
      fetchDeviceExtra(`/api/agents/${deviceId}/security`),
      fetchDeviceExtra(`/api/agents/${deviceId}/performance`),
    ]);

    const report = snapshot.diagnostics;
    const disk = (report.disk || []).reduce((max, item) => Math.max(max, item.usage_percent || 0), 0);

    const securitySection = security
      ? `<div class="device-security"><h3>Security</h3>${statusPill('Firewall', security.firewall?.available ? security.firewall.enabled : null)}${statusPill('Antivirus', security.antivirus?.available ? security.antivirus.enabled : null)}${statusPill('Encryption', security.disk_encryption?.available ? security.disk_encryption.encrypted : null)}</div>`
      : '<div class="device-security"><h3>Security</h3><p class="soft-label">Not reported yet.</p></div>';

    const performanceSection = performanceData
      ? `<div class="device-performance"><h3>Performance</h3><p class="soft-label">${escapeHtml(performanceData.cpu?.detail || '')}</p><p class="soft-label">${escapeHtml(performanceData.disk?.detail || '')}</p><p class="soft-label">${escapeHtml(performanceData.network?.detail || '')}</p></div>`
      : '<div class="device-performance"><h3>Performance</h3><p class="soft-label">Not reported yet.</p></div>';

    detail.innerHTML = `
      <div class="section-heading">
        <div><p class="kicker">SELECTED ENDPOINT</p><h2>${escapeHtml(report.system?.hostname || deviceId)}</h2></div>
        <div class="button-row"><button class="primary-button" data-device-troubleshoot="${escapeHtml(deviceId)}">Troubleshoot this device</button><button class="ghost-button" data-device-diagnose="${escapeHtml(deviceId)}">AI health report</button><label class="think-toggle" title="The AI reasons step by step before answering: better answers, but several minutes on a laptop CPU"><input type="checkbox" id="device-think"> Think deeper</label><button class="ghost-button" data-device-software="${escapeHtml(deviceId)}">Software</button></div>
      </div>
      <div class="mini-metrics">
        <div><small>CPU</small><strong>${percent(report.cpu?.total_usage_percent)}</strong></div>
        <div><small>RAM</small><strong>${percent(report.memory?.ram?.usage_percent)}</strong></div>
        <div><small>DISK</small><strong>${percent(disk)}</strong></div>
        <div><small>ALERTS</small><strong>${alerts.alerts.length}</strong></div>
      </div>
      <div id="device-onboarding" class="onboarding-card"><p class="soft-label">Checking the onboarding health check...</p></div>
      ${securitySection}
      ${performanceSection}
      <div id="device-diagnosis" class="health-report"></div>
    `;
    currentDeviceId = deviceId;
    loadOnboarding(deviceId);
  } catch (error) {
    detail.innerHTML = `<p>${escapeHtml(friendlyError(error))}</p>`;
  }
}

// fetch() rejects with a bare "Failed to fetch" when the connection drops (server restart,
// network change); say what happened instead.
function friendlyError(error) {
  if (error instanceof TypeError && /fetch|network/i.test(error.message)) {
    return 'Lost the connection to the AIops server (it may have restarted or the network changed). Try again.';
  }
  return error.message;
}

// A JSON reply, or a readable error. During a deploy nginx answers 502 with an HTML page, which made
// response.json() fail with "Unexpected token '<'".
async function readJson(response) {
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch (_error) {
    throw new Error(response.ok ? 'The server sent an unexpected reply.' : `The server answered ${response.status}; it may be restarting. Try again in a minute.`);
  }
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}

// ----------------------------------------------------------------------------
// AI health report: instant rule-based report, then the AI explains each issue
// ----------------------------------------------------------------------------

let currentDeviceId = null;
const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
const RATING_LABEL = { good: 'Healthy', fair: 'Needs attention', poor: 'Unhealthy', critical: 'Critical' };

function kvList(object) {
  const rows = Object.entries(object || {}).filter(([, value]) => value !== null && value !== undefined && value !== '');
  if (!rows.length) return '<p class="soft-label">Not reported.</p>';
  const show = (value) => (typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value);
  return `<dl class="kv">${rows.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(show(value))}</dd>`).join('')}</dl>`;
}

function usageBar(label, value, detail) {
  const number = typeof value === 'number' ? value : null;
  const level = number === null ? '' : levelFor(number, 75, 90);
  return `<div class="usage"><div class="usage-label"><span>${escapeHtml(label)}</span><strong>${number === null ? '--' : `${number.toFixed(1)}%`}</strong></div>
    <div class="usage-bar ${level}"><span style="width:${Math.min(100, number || 0)}%"></span></div>${detail ? `<small>${escapeHtml(detail)}</small>` : ''}</div>`;
}

function processList(items, unit) {
  if (!items?.length) return '<p class="soft-label">Not reported.</p>';
  return `<ol class="proc-list">${items.map((item) => `<li><span>${escapeHtml(item.name)}</span><strong>${escapeHtml(item.value)}${unit}</strong></li>`).join('')}</ol>`;
}

function renderHealthReport(report) {
  const d = report.details || {};
  const issues = report.issues || [];
  const issueList = issues.length
    ? `<ul class="hr-issues">${issues.map((item) => `<li><span class="sev-pill ${escapeHtml(item.severity)}">${escapeHtml(SEVERITY_LABEL[item.severity] || item.severity)}</span><div><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.category)}</small></div></li>`).join('')}</ul>`
    : '<p class="soft-label">No issues detected by the health rules.</p>';
  const logs = d.event_logs || {};
  const logSection = logs.available
    ? `${kvList({ [`Critical (${logs.lookback_hours || 24}h)`]: logs.critical, Errors: logs.errors, Warnings: logs.warnings })}${logs.most_frequent?.length ? `<ul class="hr-log-list">${logs.most_frequent.map((line) => `<li>${escapeHtml(line)}</li>`).join('')}</ul>` : ''}`
    : '<p class="soft-label">Event logs not reported.</p>';
  const battery = d.battery ? { Charge: `${d.battery.percent}%`, Charging: d.battery.charging, 'Time remaining': d.battery.time_remaining } : {};
  const collected = report.collected_at ? new Date(report.collected_at).toLocaleString() : 'the latest snapshot';
  return `
    <div class="hr-head">
      <div class="hr-score ${escapeHtml(report.rating)}"><strong>${report.score}</strong><small>/100</small></div>
      <div><p class="kicker">AI health report</p><h3>${escapeHtml(RATING_LABEL[report.rating] || report.rating)} · ${issues.length} issue${issues.length === 1 ? '' : 's'} found</h3><small class="soft-label">Based on the snapshot from ${escapeHtml(collected)}</small></div>
    </div>
    <div class="hr-section"><h4>Detected issues</h4>${issueList}</div>
    <div class="hr-section"><h4>AI analysis</h4><div id="ai-analysis" class="hr-ai"></div></div>
    <div class="hr-grid">
      <div class="hr-card"><h4>System</h4>${kvList(d.system)}</div>
      <div class="hr-card"><h4>Resources</h4>${usageBar('CPU', d.resources?.cpu_percent)}${usageBar('Memory', d.resources?.ram_percent, d.resources?.ram)}<small class="soft-label">Swap: ${escapeHtml(d.resources?.swap || '--')}</small>
        ${(d.disks || []).map((disk) => usageBar(`Disk ${disk.name}`, disk.percent, `${disk.free} free of ${disk.total}`)).join('')}</div>
      <div class="hr-card"><h4>Top processes</h4><p class="hr-sub">By CPU</p>${processList(d.top_cpu, '%')}<p class="hr-sub">By memory</p>${processList(d.top_memory, '%')}</div>
      <div class="hr-card"><h4>Security</h4>${kvList(d.security)}</div>
      <div class="hr-card"><h4>Event logs</h4>${logSection}</div>
      <div class="hr-card"><h4>Performance, network &amp; battery</h4>${kvList({ ...d.performance, ...d.network, ...battery })}</div>
    </div>`;
}

function renderAiAnalysis(container, data) {
  const issues = (data.issues || []).map((item) => `
    <div class="hr-ai-issue"><strong>${escapeHtml(item.title)}</strong>${item.explanation ? `<p>${escapeHtml(item.explanation)}</p>` : ''}
      ${item.fix_steps?.length ? `<ol>${item.fix_steps.map((step) => `<li>${escapeHtml(step)}</li>`).join('')}</ol>` : ''}</div>`).join('');
  const list = (items, tag = 'ol') => (items?.length ? `<${tag}>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</${tag}>` : '');
  container.innerHTML = `
    <p class="hr-summary">${escapeHtml(data.summary || 'No summary returned.')}</p>
    ${data.root_cause ? `<p><strong>Likely root cause:</strong> ${escapeHtml(data.root_cause)}</p>` : ''}
    ${issues ? `<div class="hr-ai-issues">${issues}</div>` : ''}
    ${data.steps?.length ? `<h5>Recommended actions</h5>${list(data.steps)}` : ''}
    ${data.prevention?.length ? `<h5>Keep it healthy</h5>${list(data.prevention, 'ul')}` : ''}`;
}

async function diagnoseDevice(deviceId) {
  const output = $('device-diagnosis');
  output.innerHTML = '<p class="soft-label">Building the health report...</p>';
  try {
    const response = await fetch(`/api/agents/${deviceId}/health-report`);
    const report = await response.json();
    if (!response.ok) throw new Error(report.detail || 'No diagnostics for this device yet');
    output.innerHTML = renderHealthReport(report);
  } catch (error) {
    output.textContent = friendlyError(error);
    return;
  }
  const ai = $('ai-analysis');
  const started = Date.now();
  const expected = $('device-think')?.checked ? 'thinking deeply: about 5-10 min' : 'about 2-3 min';
  const tick = () => { ai.innerHTML = `<p class="soft-label">The AI is analysing every issue... ${Math.round((Date.now() - started) / 1000)}s (${expected} on a laptop CPU)</p>`; };
  tick();
  const timer = setInterval(tick, 1000);
  try {
    const think = Boolean($('device-think')?.checked);
    const response = await fetch(`/api/agents/${deviceId}/agent-diagnose?think=${think}`, { method: 'POST' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'AI unavailable');
    clearInterval(timer);
    renderAiAnalysis(ai, data);
  } catch (error) {
    clearInterval(timer);
    ai.innerHTML = `<p class="soft-label">${escapeHtml(friendlyError(error))} The rule-based report above is still accurate.</p>`;
  }
}

// ----------------------------------------------------------------------------
// Onboarding health check (full check-up run when a device first connects)
// ----------------------------------------------------------------------------

const SESSION_FINISHED = new Set(['diagnosed', 'resolved', 'unresolved', 'not_resolved', 'failed', 'interrupted', 'fixing']);

function renderOnboarding(deviceId, data) {
  const rerun = `<button class="ghost-button" type="button" data-onboarding-rerun="${escapeHtml(deviceId)}">Run full health check</button>`;
  if (data.status === 'none') {
    return `<div class="onb-head"><div><h3>Onboarding health check</h3><p class="soft-label">Not run yet. It starts automatically when a device first reports.</p></div>${rerun}</div>`;
  }
  if (!SESSION_FINISHED.has(data.status)) {
    return `<div class="onb-head"><div><h3>Onboarding health check <span class="status-pill unknown">running</span></h3><p class="soft-label">Diagnosing every system on this device (network, disks, security, hardware, updates, event logs) and asking the AI for a diagnosis...</p></div></div>`;
  }
  const failed = data.status === 'failed' || data.status === 'interrupted';
  const findings = data.findings?.length ? `<ul class="onb-findings">${data.findings.map((title) => `<li>${escapeHtml(title)}</li>`).join('')}</ul>` : '<p class="soft-label">No problems found by the checks.</p>';
  return `
    <div class="onb-head">
      <div><h3>Onboarding health check <span class="status-pill ${failed ? 'critical' : 'ok'}">${escapeHtml(data.status)}</span></h3>
        <small class="soft-label">${data.created_at ? escapeHtml(new Date(data.created_at).toLocaleString()) : ''}</small></div>
      <div class="button-row"><button class="primary-button" type="button" data-onboarding-open="${escapeHtml(data.session_id)}">Open full report</button>${rerun}</div>
    </div>
    ${data.root_cause ? `<p><strong>Diagnosis:</strong> ${escapeHtml(data.root_cause)}</p>` : ''}
    ${findings}
    ${data.fixes ? `<p class="soft-label">${data.fixes} one-click fix${data.fixes === 1 ? '' : 'es'} proposed in the full report.</p>` : ''}`;
}

async function loadOnboarding(deviceId) {
  if (!$('device-onboarding') || currentDeviceId !== deviceId) return;
  try {
    const data = await fetch(`/api/agents/${deviceId}/onboarding`).then((response) => response.json());
    if (currentDeviceId !== deviceId || !$('device-onboarding')) return;
    $('device-onboarding').innerHTML = renderOnboarding(deviceId, data);
    if (data.status !== 'none' && !SESSION_FINISHED.has(data.status)) setTimeout(() => loadOnboarding(deviceId), 5000);
  } catch (error) {
    if ($('device-onboarding')) $('device-onboarding').innerHTML = `<p class="soft-label">${escapeHtml(friendlyError(error))}</p>`;
  }
}

async function rerunOnboarding(deviceId) {
  try {
    const response = await fetch(`/api/agents/${deviceId}/onboarding`, { method: 'POST' });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || 'Could not start the health check');
    toast('Full health check started');
    loadOnboarding(deviceId);
  } catch (error) {
    toast(friendlyError(error), 'error');
  }
}

function openOnboardingReport(sessionId) {
  switchTab('troubleshoot');
  openTroubleshootSession(sessionId);
}

// ============================================================================
// Software tab
// ============================================================================

let swDeviceId = null;
let swInventory = null;
let swFilter = 'all';
const swJobs = new Map(); // job_id -> entry id, so rows show their running action

function swSetStatus(text, tone = '') {
  const status = $('sw-status');
  status.className = `sw-status${tone ? ` ${tone}` : ''}`;
  status.textContent = text;
}

async function loadSoftwareTargets(selectedId) {
  const select = $('sw-device');
  const current = selectedId || select.value || swDeviceId;
  try {
    const data = await fetch('/api/troubleshoot/targets').then((response) => response.json());
    const targets = (data.targets || []).filter((target) => target.device_id !== 'local').sort((a, b) => targetRank(a) - targetRank(b));
    select.innerHTML = targets.length
      ? targets.map((target) => `<option value="${escapeHtml(target.device_id)}">${escapeHtml(target.label)} / ${escapeHtml(target.os_type)}${target.status !== 'online' ? ' - offline' : ''}</option>`).join('')
      : '<option value="">No agents enrolled yet</option>';
    if (current && [...select.options].some((option) => option.value === current)) select.value = current;
  } catch (error) {
    swSetStatus(friendlyError(error), 'error');
  }
}

async function loadSoftware(selectedId) {
  await loadSoftwareTargets(selectedId);
  const deviceId = $('sw-device').value;
  if (!deviceId) {
    $('sw-body').innerHTML = '<tr><td colspan="6" class="empty-state">Enroll a device under Add Agent to manage its software.</td></tr>';
    return;
  }
  swDeviceId = deviceId;
  try {
    const data = await fetch(`/api/agents/${deviceId}/software`).then((response) => response.json());
    swInventory = data.inventory;
    renderSoftware();
    const scan = (data.jobs || []).find((job) => job.action === 'scan');
    if (scan) pollSoftwareJob(scan.job_id);
    else if (!swInventory) startSoftwareScan();
  } catch (error) {
    swSetStatus(friendlyError(error), 'error');
  }
}

function swRowActions(item) {
  const running = [...swJobs.values()].includes(item.id) || [...swJobs.values()].includes(item.update_id);
  if (running) return '<span class="status-pill unknown">Working...</span>';
  const update = item.update_available && item.update_id
    ? `<button class="ghost-button sw-update" type="button" data-sw-update="${escapeHtml(item.update_id)}" data-sw-name="${escapeHtml(item.name)}" title="Update to ${escapeHtml(item.available_version || 'latest')}">Update</button>` : '';
  const uninstall = item.can_uninstall
    ? `<button class="ghost-button sw-uninstall" type="button" data-sw-uninstall="${escapeHtml(item.id)}" data-sw-name="${escapeHtml(item.name)}">Uninstall</button>`
      + `<button class="ghost-button sw-remove" type="button" data-sw-remove="${escapeHtml(item.id)}" data-sw-name="${escapeHtml(item.name)}" title="Uninstall, then find and quarantine what it left behind">Remove completely</button>`
    : '<span class="soft-label sw-manual" title="No silent uninstaller: remove it from Settings > Apps on the device">Manual</span>';
  return `${update}${uninstall}`;
}

function renderSoftware() {
  const body = $('sw-body');
  if (!swInventory) {
    body.innerHTML = '<tr><td colspan="6" class="empty-state">No inventory yet. Click Scan now.</td></tr>';
    return;
  }
  const term = $('sw-search').value.trim().toLowerCase();
  const items = (swInventory.software || []).filter((item) => (swFilter !== 'updates' || item.update_available)
    && (!term || item.name.toLowerCase().includes(term) || (item.publisher || '').toLowerCase().includes(term)));
  body.innerHTML = items.length ? items.map((item) => `
    <tr>
      <td><strong>${escapeHtml(item.name)}</strong>${item.scope === 'user' ? ' <small class="soft-label">(user)</small>' : ''}</td>
      <td>${escapeHtml(item.version || '--')}${item.update_available ? `<br><span class="sw-new">→ ${escapeHtml(item.available_version || 'newer')}</span>` : ''}</td>
      <td>${escapeHtml(item.publisher || '--')}</td>
      <td>${escapeHtml(item.install_date || '--')}</td>
      <td>${Number(item.size_mb) > 0 ? (Number(item.size_mb) >= 1024 ? `${(Number(item.size_mb) / 1024).toFixed(1)} GB` : `${Number(item.size_mb)} MB`) : '--'}</td>
      <td class="sw-actions">${swRowActions(item)}</td>
    </tr>`).join('') : '<tr><td colspan="6" class="empty-state">No programs match.</td></tr>';
  const scanned = swInventory.collected_at ? new Date(swInventory.collected_at).toLocaleString() : 'unknown';
  const note = swInventory.updates_note ? ` ${swInventory.updates_note}` : '';
  if (!swJobs.size) swSetStatus(`${swInventory.count} programs, ${swInventory.updates_available || 0} with updates available. Scanned ${scanned}.${note}`);
}

async function startSoftwareScan() {
  if (!swDeviceId) return;
  try {
    const response = await fetch(`/api/agents/${swDeviceId}/software/scan`, { method: 'POST' });
    const job = await response.json();
    if (!response.ok) throw new Error(job.detail || 'Scan failed');
    pollSoftwareJob(job.job_id);
  } catch (error) {
    swSetStatus(friendlyError(error), 'error');
  }
}

const swPolling = new Set();

async function pollSoftwareJob(jobId) {
  if (swPolling.has(jobId)) return;
  swPolling.add(jobId);
  const started = Date.now();
  $('sw-scan').disabled = true;
  for (;;) {
    let job;
    try {
      job = await fetch(`/api/software/jobs/${jobId}`).then((response) => response.json());
    } catch (error) {
      swSetStatus(friendlyError(error), 'error');
      break;
    }
    if (!job.state) {
      swSetStatus(job.detail || 'The job was lost (the server restarted). Scan again.', 'error');
      break;
    }
    if (job.state === 'running') {
      swSetStatus(`Scanning ${job.device}: listing installed programs and checking for updates... ${Math.round((Date.now() - started) / 1000)}s (about 1-3 min)`);
      await new Promise((resolve) => { setTimeout(resolve, 2000); });
      continue;
    }
    if (job.state === 'done') {
      const data = await fetch(`/api/agents/${job.device_id}/software`).then((response) => response.json());
      if (job.device_id === swDeviceId) {
        swInventory = data.inventory;
        renderSoftware();
      }
    } else if (job.device_id === swDeviceId) {
      swSetStatus(job.summary || 'Scan failed', 'error');
    }
    break;
  }
  swPolling.delete(jobId);
  $('sw-scan').disabled = false;
}

async function runSoftwareAction(kind, key, name) {
  const question = kind === 'uninstall'
    ? `Uninstall "${name}" from this device?\n\nIt runs the program's own silent uninstaller and cannot be undone from AIops.`
    : `Update "${name}" to the latest version?\n\nThe program may close while it updates.`;
  if (!window.confirm(question)) return;
  const deviceId = swDeviceId;
  const payload = kind === 'uninstall' ? { id: key, name } : { package_id: key, name };
  try {
    const response = await fetch(`/api/agents/${deviceId}/software/${kind}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const job = await response.json();
    if (!response.ok) throw new Error(job.detail || `${kind} failed`);
    swJobs.set(job.job_id, key);
    renderSoftware();
    swSetStatus(`${kind === 'uninstall' ? 'Uninstalling' : 'Updating'} ${name}... this can take a few minutes.`);
    for (;;) {
      await new Promise((resolve) => { setTimeout(resolve, 3000); });
      const state = await fetch(`/api/software/jobs/${job.job_id}`).then((r) => r.json()).catch(() => ({}));
      if (state.state === 'running') continue;
      swJobs.delete(job.job_id);
      if (state.state === 'done') toast(state.summary || `${name}: done`);
      else toast(state.summary || state.detail || `${name}: failed`, 'error');
      break;
    }
    if (deviceId === swDeviceId) {
      const data = await fetch(`/api/agents/${deviceId}/software`).then((response) => response.json());
      swInventory = data.inventory;
    }
  } catch (error) {
    toast(friendlyError(error), 'error');
  }
  renderSoftware();
}

// ----------------------------------------------------------------------------
// Remove completely: uninstall -> leftover preview -> quarantine (restorable) -> restore
// ----------------------------------------------------------------------------

let swLeftoverJob = null;
const LEFTOVER_ADVICE = { remove: 'AI: remove', keep: 'AI: keep', unsure: 'AI: unsure' };

async function runSoftwareJob(path, payload, waitingText, onProgress = swSetStatus) {
  const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload || {}) });
  const job = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(job.detail || 'Request failed');
  const started = Date.now();
  for (;;) {
    const state = await fetch(`/api/software/jobs/${job.job_id}`).then((r) => r.json()).catch(() => ({}));
    if (state.state && state.state !== 'running') return state;
    if (!state.state) throw new Error(state.detail || 'The job was lost (the server restarted).');
    onProgress(`${waitingText} ${Math.round((Date.now() - started) / 1000)}s`);
    await new Promise((resolve) => { setTimeout(resolve, 2500); });
  }
}

async function removeCompletely(entryId, name) {
  if (!window.confirm(`Remove "${name}" completely?\n\nStep 1 runs its own silent uninstaller (cannot be undone from AIops).\nStep 2 shows what it left behind; nothing else is removed until you choose items and approve.`)) return;
  const deviceId = swDeviceId;
  swJobs.set(`remove-${entryId}`, entryId);
  renderSoftware();
  try {
    const removed = await runSoftwareJob(`/api/agents/${deviceId}/software/uninstall`, { id: entryId, name }, `Uninstalling ${name}...`);
    if (removed.state !== 'done') throw new Error(removed.summary || `${name} could not be uninstalled`);
    toast(removed.summary || `Uninstalled ${name}`);
    await scanLeftovers(deviceId, entryId, name);
  } catch (error) {
    toast(friendlyError(error), 'error');
    swSetStatus(friendlyError(error), 'error');
  } finally {
    swJobs.delete(`remove-${entryId}`);
    const data = await fetch(`/api/agents/${deviceId}/software`).then((r) => r.json()).catch(() => null);
    if (data && deviceId === swDeviceId) swInventory = data.inventory;
    renderSoftware();
  }
}

async function scanLeftovers(deviceId, entryId, name) {
  const job = await runSoftwareJob(`/api/agents/${deviceId}/software/leftovers`, { id: entryId, name }, `Looking for what ${name} left behind...`);
  if (job.state !== 'done') throw new Error(job.summary || 'Leftover scan failed');
  swLeftoverJob = job;
  renderLeftovers();
  swSetStatus(job.summary);
}

function renderLeftovers(advice) {
  const panel = $('sw-leftovers');
  const data = swLeftoverJob?.data;
  if (!data) {
    panel.classList.add('hidden');
    return;
  }
  panel.classList.remove('hidden');
  const verdicts = Object.fromEntries((advice?.items || []).map((item) => [item.id, item]));
  if (!data.candidates.length) {
    panel.innerHTML = `<div class="section-heading"><div><p class="kicker">Remove completely</p><h2>${escapeHtml(data.program)}: nothing left behind</h2></div><button class="ghost-button" type="button" data-lo-close>Close</button></div>`;
    return;
  }
  const rows = data.candidates.map((item) => {
    const verdict = verdicts[item.id];
    const checked = verdict ? verdict.verdict !== 'keep' : item.confidence !== 'low';
    return `<tr>
      <td><input type="checkbox" data-lo-id="${escapeHtml(item.id)}" ${checked ? 'checked' : ''} aria-label="Select ${escapeHtml(item.path)}"></td>
      <td><span class="sev-pill ${item.kind === 'registry' ? 'medium' : 'low'}">${escapeHtml(item.kind)}</span></td>
      <td class="lo-path"><strong>${escapeHtml(item.path)}</strong><small>${escapeHtml(item.reason)}</small>${verdict ? `<small class="lo-advice ${escapeHtml(verdict.verdict)}">${escapeHtml(LEFTOVER_ADVICE[verdict.verdict])}: ${escapeHtml(verdict.reason)}</small>` : ''}</td>
      <td>${escapeHtml(item.size_text || '--')}</td>
      <td><span class="status-pill ${item.confidence === 'high' ? 'ok' : 'unknown'}">${escapeHtml(item.confidence)}</span></td>
    </tr>`;
  }).join('');
  panel.innerHTML = `
    <div class="section-heading">
      <div><p class="kicker">Remove completely · step 2 of 2</p><h2>${escapeHtml(data.program)} left ${Number(data.count) || 0} item${Number(data.count) === 1 ? '' : 's'} behind (${escapeHtml(data.total_size_text)})</h2>
        <p class="soft-label">Tick what to remove. Ticked items move to a quarantine you can restore for 7 days; registry keys are exported to .reg files first. Low-confidence matches start unticked.${advice ? ' The AI unticked items it advises keeping.' : ''}</p>
        ${advice?.summary ? `<p class="lo-summary">${escapeHtml(advice.summary)}</p>` : ''}</div>
      <div class="button-row">
        <label class="think-toggle"><input type="checkbox" id="lo-think"> Think deeper</label>
        <button class="ghost-button" type="button" data-lo-review>Ask AI to review</button>
        <button class="primary-button" type="button" data-lo-quarantine>Move selected to quarantine</button>
        <button class="ghost-button" type="button" data-lo-close>Keep all</button>
      </div>
    </div>
    <div class="table-wrap flat"><table><thead><tr><th></th><th>Kind</th><th>Location</th><th>Size</th><th>Match</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

async function reviewLeftovers() {
  const button = document.querySelector('[data-lo-review]');
  if (button) button.disabled = true;
  swSetStatus('The AI is reviewing the leftovers (advice only)...');
  try {
    const response = await fetch(`/api/agents/${swDeviceId}/software/leftovers/review`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ job_id: swLeftoverJob.job_id, think: Boolean($('lo-think')?.checked) }) });
    const advice = await response.json();
    if (!response.ok) throw new Error(advice.detail || 'AI review failed');
    renderLeftovers(advice);
    swSetStatus('AI review done. You decide what moves to quarantine.');
  } catch (error) {
    swSetStatus(friendlyError(error), 'error');
    if (button) button.disabled = false;
  }
}

async function quarantineSelected() {
  const data = swLeftoverJob?.data;
  const ids = [...document.querySelectorAll('#sw-leftovers [data-lo-id]:checked')].map((box) => box.dataset.loId);
  if (!data || !ids.length) {
    toast('Tick at least one item first', 'error');
    return;
  }
  const chosen = data.candidates.filter((item) => ids.includes(item.id));
  const preview = chosen.slice(0, 8).map((item) => `- ${item.path}`).join('\n') + (chosen.length > 8 ? `\n...and ${chosen.length - 8} more` : '');
  if (!window.confirm(`Move ${ids.length} item${ids.length === 1 ? '' : 's'} left by "${data.program}" to quarantine?\n\n${preview}\n\nYou can restore them from Quarantine for 7 days.`)) return;
  try {
    const job = await runSoftwareJob(`/api/agents/${swDeviceId}/software/quarantine`, { scan_id: data.scan_id, candidate_ids: ids, name: data.program }, `Moving ${ids.length} item(s) to quarantine...`);
    toast(job.summary || 'Done', job.state === 'done' ? 'ok' : 'error');
    swSetStatus(job.summary || '', job.state === 'done' ? '' : 'error');
    swLeftoverJob = null;
    renderLeftovers();
  } catch (error) {
    swSetStatus(friendlyError(error), 'error');
  }
}

async function loadQuarantine() {
  const panel = $('sw-quarantine');
  panel.classList.remove('hidden');
  panel.innerHTML = '<p class="soft-label"><span class="spinner"></span> Loading the quarantine...</p>';
  try {
    const job = await runSoftwareJob(`/api/agents/${swDeviceId}/software/quarantine-list`, {}, 'Loading the quarantine...');
    if (job.state !== 'done') throw new Error(job.summary || 'Could not read the quarantine');
    const batches = job.data?.batches || [];
    swSetStatus(job.summary);
    panel.innerHTML = `<div class="section-heading"><div><p class="kicker">Quarantine · restorable for ${Number(job.data?.days) || 7} days</p><h2>${batches.length} batch${batches.length === 1 ? '' : 'es'}</h2></div><button class="ghost-button" type="button" data-q-close>Close</button></div>`
      + (batches.length ? `<div class="table-wrap flat"><table><thead><tr><th>Program</th><th>Moved</th><th>Items</th><th>Size</th><th>Restorable until</th><th></th></tr></thead><tbody>${batches.map((batch) => `
        <tr><td><strong>${escapeHtml(batch.program || '--')}</strong><small class="lo-paths">${batch.paths.map((path) => escapeHtml(path)).join('<br>')}</small></td>
          <td>${escapeHtml(new Date(batch.created).toLocaleString())}</td><td>${Number(batch.items)}</td><td>${escapeHtml(batch.size_text)}</td>
          <td>${escapeHtml(new Date(batch.expires).toLocaleDateString())}</td>
          <td><button class="ghost-button" type="button" data-q-restore="${escapeHtml(batch.batch_id)}" data-q-name="${escapeHtml(batch.program || '')}">Restore</button></td></tr>`).join('')}</tbody></table></div>`
        : '<p class="soft-label">Nothing in quarantine.</p>');
  } catch (error) {
    panel.innerHTML = `<p class="soft-label">${escapeHtml(friendlyError(error))}</p>`;
  }
}

async function restoreBatch(batchId, name) {
  if (!window.confirm(`Restore what "${name || 'this program'}" left behind?\n\nFolders go back where they were and registry keys are re-imported.`)) return;
  try {
    const job = await runSoftwareJob(`/api/agents/${swDeviceId}/software/restore`, { batch_id: batchId, name }, 'Restoring...');
    toast(job.summary || 'Restored', job.state === 'done' ? 'ok' : 'error');
  } catch (error) {
    toast(friendlyError(error), 'error');
  }
  loadQuarantine();
}

function openSoftware(deviceId) {
  switchTab('software');
  loadSoftware(deviceId);
}

// ============================================================================
// Add Agent — one-line enrollment
// ============================================================================

const INSTALL_COMMANDS = {
  windows: {
    hint: 'Open PowerShell as Administrator on the Windows device and run:',
    // The header gets past ngrok's browser warning page (PowerShell looks like a browser to ngrok).
    install: (server, token) => `irm -Headers @{'ngrok-skip-browser-warning'='1'} "${installUrl(server, "windows.ps1", token)}" | iex`,
    uninstall: (server) => `irm -Headers @{'ngrok-skip-browser-warning'='1'} "${server}/install/uninstall-windows.ps1" | iex`,
  },
  linux: {
    hint: 'Open a terminal on the Linux device and run (needs sudo):',
    install: (server, token) => `curl -fsSL -H "ngrok-skip-browser-warning: 1" "${installUrl(server, "linux.sh", token)}" | sudo bash`,
    uninstall: (server) => `curl -fsSL -H "ngrok-skip-browser-warning: 1" "${server}/install/uninstall-linux.sh" | sudo bash`,
  },
  mac: {
    hint: 'Open Terminal on the Mac and run (needs an admin password):',
    install: (server, token) => `curl -fsSL -H "ngrok-skip-browser-warning: 1" "${installUrl(server, "macos.sh", token)}" | sudo bash`,
    uninstall: (server) => `curl -fsSL -H "ngrok-skip-browser-warning: 1" "${server}/install/uninstall-macos.sh" | sudo bash`,
  },
};

let enrollWaitTimer = null;
let openEnrollment = false;
let generatedTokenExpires = 0;

function installUrl(server, script, token) {
  const query = new URLSearchParams();
  if (token) query.set('token', token);
  if (server !== location.origin) query.set('server', server);
  const text = query.toString();
  return `${server}/install/${script}${text ? `?${text}` : ''}`;
}

function enrollServer() {
  return ($('enroll-server').value.trim() || location.origin).replace(/\/+$/, '');
}

function isLocalOnlyServer(server) {
  try {
    const host = new URL(server).hostname;
    return host === 'localhost' || host === '::1' || host === '[::1]' || host.startsWith('127.');
  } catch (_error) {
    return true;
  }
}

function updateInstallInstructions() {
  const server = enrollServer();
  const commands = INSTALL_COMMANDS[selectedPlatform];
  $('enroll-server-warning').classList.toggle('hidden', !isLocalOnlyServer(server));
  setText('install-hint', commands.hint);
  setText('uninstall-command', commands.uninstall(server));
  const ready = openEnrollment || generatedToken;
  setText('install-command', ready ? commands.install(server, generatedToken) : 'Waiting for a token (see step 2).');
  $('copy-install').disabled = !ready;
}

// The dashboard login is enough to make a token: it is created when Add Agent opens, no key to paste.
// wait: also watch for the device that uses it (false right after a device connected, to keep that message).
async function generateToken(wait = true) {
  const result = $('token-result');
  result.textContent = 'Creating a one-time token...';
  result.classList.remove('hidden');
  try {
    const data = await readJson(await fetch('/api/agents/generate-token', { method: 'POST' }));
    generatedToken = data.token;
    generatedTokenExpires = Date.parse(data.expires_at) || 0;
    // Not kept across reloads on purpose: a device may have claimed it meanwhile, and a token a device owns
    // re-installs that device, so a second device would take over the first one's identity.
    showTokenReady();
    if (wait) waitForNewDevice();
  } catch (error) {
    generatedToken = '';
    result.textContent = friendlyError(error);
  }
  updateInstallInstructions();
}

function showTokenReady() {
  $('token-result').textContent = `Token ready (single use, expires ${new Date(generatedTokenExpires).toLocaleString()})`;
  $('token-result').classList.remove('hidden');
}


async function waitForNewDevice() {
  clearInterval(enrollWaitTimer);
  const known = new Set(((await fetch('/api/agents').then((response) => response.json()).catch(() => ({ agents: [] }))).agents || []).map((agent) => agent.device_id));
  $('enroll-wait').classList.remove('hidden');
  setText('enroll-wait-text', 'Waiting for the device to connect... run the command above on it.');
  enrollWaitTimer = setInterval(async () => {
    try {
      const data = await fetch('/api/agents').then((response) => response.json());
      const fresh = (data.agents || []).find((agent) => !known.has(agent.device_id));
      if (fresh) {
        clearInterval(enrollWaitTimer);
        enrollWaitTimer = null;
        setText('enroll-wait-text', `Connected: ${fresh.nickname} (${fresh.hostname}, ${fresh.os_type}). You can now troubleshoot it from "What's the issue?".`);
        setText('agent-count', data.agents.length);
        // The token just used now belongs to that device: the next device gets a fresh one, and the address
        // goes back to the usual one if this was the server's own install.
        if (enrollingServer) {
          enrollingServer = false;
          $('enroll-server').value = defaultEnrollServer || location.origin;
        }
        if (!openEnrollment) generateToken(false);
      }
    } catch (_error) {
      // keep waiting
    }
  }, 4000);
}

async function copyInstallCommand() {
  const text = $('install-command').textContent;
  try {
    await navigator.clipboard.writeText(text);
    setText('copy-install', 'Copied');
  } catch (_error) {
    const range = document.createRange();
    range.selectNodeContents($('install-command'));
    getSelection().removeAllRanges();
    getSelection().addRange(range);
    setText('copy-install', 'Press Ctrl+C');
  }
  setTimeout(() => setText('copy-install', 'Copy'), 2000);
  // Watch for the device this command is for (also after an earlier device connected).
  if (!enrollWaitTimer) waitForNewDevice();
}

async function downloadAgent() {
  const result = $('install-instructions');
  result.classList.remove('hidden');
  result.textContent = 'Checking for a built installer...';
  try {
    const response = await fetch(`/api/agents/download/${selectedPlatform}`);
    const contentType = response.headers.get('content-type') || '';
    if (!response.ok || contentType.includes('application/json')) {
      const data = await response.json();
      result.textContent = `${data.message}\n\nManual fallback:\n${data.manual_install}`;
      return;
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = selectedPlatform === 'windows' ? 'DeviceHealthAgent.exe' : 'DeviceHealthAgent';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    result.textContent = 'Downloaded. Place agent_config.json beside the binary before starting it.';
  } catch (error) {
    console.error('Agent download failed:', error);
    result.textContent = `Download failed: ${error.message}\n\nManual fallback: pip install -r agent_requirements.txt && python monitor_agent.py`;
  }
}

async function loadAddAgent() {
  try {
    const info = await fetch('/api/agents/enrollment').then((response) => response.json());
    openEnrollment = Boolean(info.open);
    defaultEnrollServer = info.server_url || location.origin;
    // Public ngrok address: explain that the free URL changes when ngrok restarts.
    $('enroll-ngrok-note').classList.toggle('hidden', !info.ngrok_url);
    if (info.ngrok_url) {
      $('enroll-ngrok-note').innerHTML = `Public address (ngrok): <code>${escapeHtml(info.ngrok_url)}</code> <button class="ghost-button" type="button" id="use-ngrok-url">Use it</button><br>${escapeHtml(info.ngrok_note || '')}`;
      $('use-ngrok-url').addEventListener('click', () => { $('enroll-server').value = info.ngrok_url; updateInstallInstructions(); });
    }
  } catch (_error) {
    defaultEnrollServer = defaultEnrollServer || location.origin;
  }
  // The server's own install reaches AIops on the host itself; every other device uses the usual address.
  if (enrollingServer) $('enroll-server').value = SERVER_SELF_URL;
  else if (!$('enroll-server').value) $('enroll-server').value = defaultEnrollServer;
  $('enroll-token-step').classList.toggle('hidden', openEnrollment);
  setText('enroll-run-number', openEnrollment ? '2' : '3');
  updateInstallInstructions();
  if (openEnrollment && !enrollWaitTimer) waitForNewDevice();
  // A token is made as the page opens; one with under an hour left is replaced.
  if (!openEnrollment && (!generatedToken || generatedTokenExpires - Date.now() < 3600 * 1000)) await generateToken();
}

const SERVER_SELF_URL = 'http://127.0.0.1';
let enrollingServer = false;
let defaultEnrollServer = '';

// Dashboard callout: set Add Agent up for the server AIops runs on (Linux, reached from the host itself).
function installAgentOnServer() {
  enrollingServer = true;
  selectedPlatform = 'linux';
  document.querySelectorAll('.platform-tab').forEach((item) => item.classList.toggle('active', item.dataset.platform === 'linux'));
  switchTab('add-agent');
}

// ============================================================================
// What's the issue? — agentic troubleshooting
// ============================================================================

const TERMINAL_STATUSES = ['diagnosed', 'resolved', 'unresolved', 'failed'];
const STATUS_LABELS = {
  queued: 'Queued', running: 'Investigating', diagnosed: 'Diagnosed', fixing: 'Applying fix',
  verifying: 'Verifying', resolved: 'Resolved', unresolved: 'Not resolved', failed: 'Failed',
};
const STATUS_TONES = { resolved: 'ok', diagnosed: 'ok', unresolved: 'critical', failed: 'critical' };

let tsSocket = null;
let tsPollTimer = null;
let tsSessionId = null;
let tsPlaybookId = null;
let tsPlaybooks = [];
let tsRefreshPending = false;
const tsFeedback = {};
// Checks run in parallel, so several can be in flight at once (keyed by tool + args).
const tsPendingSteps = new Map();
let tsMode = 'fast';
let tsAiAvailable = true;

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function toolLabel(toolId) {
  const text = String(toolId || '').replace(/_/g, ' ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function argsLabel(args) {
  const entries = Object.entries(args || {});
  return entries.length ? ` (${entries.map(([key, value]) => `${key}: ${value}`).join(', ')})` : '';
}

async function loadTroubleshoot() {
  loadTroubleshootTargets();
  loadTroubleshootHistory();
  if (!tsPlaybooks.length) {
    try {
      tsPlaybooks = (await fetch('/api/troubleshoot/playbooks').then((response) => response.json())).playbooks || [];
    } catch (_error) {
      tsPlaybooks = [];
    }
    $('ts-playbooks').innerHTML = tsPlaybooks.map((playbook) => `<button class="playbook-chip" data-playbook="${escapeHtml(playbook.id)}">${escapeHtml(playbook.title)}</button>`).join('');
  }
}

async function loadTroubleshootTargets(selectedId) {
  const select = $('ts-device');
  const current = selectedId || select.value;
  try {
    const data = await fetch('/api/troubleshoot/targets').then((response) => response.json());
    select.innerHTML = (data.targets || []).sort((a, b) => targetRank(a) - targetRank(b)).map((target) => {
      const offline = target.status !== 'online' ? ' - offline' : '';
      return `<option value="${escapeHtml(target.device_id)}">${escapeHtml(target.label)} / ${escapeHtml(target.os_type)}${offline}</option>`;
    }).join('') || NO_DEVICES_OPTION;
    select.value = [...select.options].some((option) => option.value === current) ? current : (select.options[0]?.value ?? '');
  } catch (_error) {
    select.innerHTML = '<option value="local">This server</option>';
  }
}

async function loadTroubleshootHistory() {
  const list = $('ts-history');
  try {
    const data = await fetch('/api/troubleshoot/sessions?limit=15').then((response) => response.json());
    if (!data.sessions.length) {
      list.innerHTML = '<p class="soft-label">No sessions yet.</p>';
      return;
    }
    list.innerHTML = data.sessions.map((session) => `
      <button class="ts-history-item" data-session="${escapeHtml(session.session_id)}">
        <span class="status-pill ${STATUS_TONES[session.status] || 'unknown'}">${escapeHtml(STATUS_LABELS[session.status] || session.status)}</span>
        <strong>${escapeHtml(session.issue)}</strong>
        <small>${escapeHtml(session.device_label || session.device_id)} / ${new Date(session.created_at).toLocaleString()}</small>
      </button>`).join('');
  } catch (error) {
    list.innerHTML = `<p class="soft-label">${escapeHtml(error.message)}</p>`;
  }
}

function selectPlaybook(playbookId) {
  const playbook = tsPlaybooks.find((item) => item.id === playbookId);
  if (!playbook) return;
  const same = tsPlaybookId === playbookId;
  tsPlaybookId = same ? null : playbookId;
  document.querySelectorAll('.playbook-chip').forEach((chip) => chip.classList.toggle('active', chip.dataset.playbook === tsPlaybookId));
  if (!same) $('ts-issue').value = playbook.issue;
}

async function startTroubleshoot() {
  const issue = $('ts-issue').value.trim();
  if (!issue) {
    setText('ts-form-status', 'Describe the issue or pick a common problem first.');
    return;
  }
  const button = $('ts-start');
  button.disabled = true;
  setText('ts-form-status', tsMode === 'instant' ? 'Running instant checks...' : 'Starting the AI agent...');
  try {
    const response = await fetch('/api/troubleshoot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issue, device_id: $('ts-device').value, playbook_id: tsPlaybookId, mode: tsMode }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Could not start troubleshooting');
    setText('ts-form-status', '');
    openTroubleshootSession(data.session_id);
    loadTroubleshootHistory();
  } catch (error) {
    setText('ts-form-status', error.message);
  } finally {
    button.disabled = false;
  }
}

function pendingKey(item) {
  return `${item.tool_id}|${JSON.stringify(item.args || {})}`;
}

function openTroubleshootSession(sessionId) {
  tsSessionId = sessionId;
  tsThinking = null;
  tsPendingSteps.clear();
  $('ts-session').classList.remove('hidden');
  $('ts-steps').innerHTML = '';
  $('ts-report').innerHTML = '<p class="soft-label">Loading session...</p>';
  connectTroubleshootStream(sessionId);
  $('ts-session').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function connectTroubleshootStream(sessionId) {
  if (tsSocket) tsSocket.close();
  clearInterval(tsPollTimer);
  const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
  const socket = new WebSocket(`${protocol}://${location.host}/ws/troubleshoot/${sessionId}`);
  tsSocket = socket;
  socket.onmessage = (event) => {
    if (sessionId !== tsSessionId) return;
    const message = JSON.parse(event.data);
    if (message.type === 'snapshot') renderTroubleshootSession(message.session);
    else if (message.type === 'thinking') {
      tsThinking = message;
      renderThinking();
    }
    else if (message.type === 'step_started') {
      tsPendingSteps.set(pendingKey(message), message);
      $('ts-steps').appendChild(pendingStepElement(message));
    } else {
      if (message.type === 'step' && message.step.tool_id) tsPendingSteps.delete(pendingKey(message.step));
      if (message.type === 'error' || message.type === 'report') {
        tsPendingSteps.clear();
        tsThinking = null;
      }
      refreshTroubleshootSession();
    }
  };
  socket.onclose = () => {
    if (tsSocket !== socket || sessionId !== tsSessionId) return;
    // Fall back to polling until the session settles.
    tsPollTimer = setInterval(async () => {
      const session = await refreshTroubleshootSession();
      if (session && TERMINAL_STATUSES.includes(session.status)) clearInterval(tsPollTimer);
    }, 3000);
  };
}

async function refreshTroubleshootSession() {
  if (!tsSessionId || tsRefreshPending) return null;
  tsRefreshPending = true;
  try {
    const response = await fetch(`/api/troubleshoot/${tsSessionId}`);
    if (!response.ok) return null;
    const session = await response.json();
    if (session.session_id === tsSessionId) renderTroubleshootSession(session);
    if (TERMINAL_STATUSES.includes(session.status)) loadTroubleshootHistory();
    return session;
  } finally {
    tsRefreshPending = false;
  }
}

function pendingStepElement(message) {
  const item = document.createElement('li');
  item.className = 'ts-step pending';
  const verb = message.kind === 'fix' ? 'Applying fix' : message.kind === 'verify' ? 'Re-checking' : 'Running';
  item.innerHTML = `<span class="ts-step-icon"></span><div><strong>${verb}: ${escapeHtml(toolLabel(message.tool_id))}${escapeHtml(argsLabel(message.args))}</strong><small>working...</small></div>`;
  return item;
}

function renderFindings(findings) {
  if (!findings || !findings.length) return '<p class="soft-label">The instant checks found nothing abnormal.</p>';
  return `<ul class="ts-findings">${findings.map((item) => `
    <li><span class="severity severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.detail)}</small></li>`).join('')}</ul>`;
}

function renderStep(step) {
  if (step.kind === 'findings') {
    return `<li class="ts-step findings"><span class="ts-step-icon"></span><div><small>INSTANT CHECKS</small><p>${escapeHtml(step.text)}</p></div></li>`;
  }
  if (step.kind === 'thought') {
    return `<li class="ts-step thought"><span class="ts-step-icon"></span><div><small>AI</small><p>${escapeHtml(step.text)}</p></div></li>`;
  }
  const result = step.result || {};
  const prefix = step.kind === 'fix' ? 'FIX ' : step.kind === 'verify' ? 'RE-CHECK ' : '';
  return `<li class="ts-step ${result.ok ? 'ok' : 'failed'} ${step.kind}">
    <span class="ts-step-icon"></span>
    <div>
      <strong>${prefix}${escapeHtml(toolLabel(step.tool_id))}${escapeHtml(argsLabel(step.args))}</strong>
      <p>${escapeHtml(result.summary || 'No result')}</p>
      <details><summary>Raw data</summary><pre>${escapeHtml(JSON.stringify(result.data, null, 2) || 'null')}</pre></details>
    </div>
  </li>`;
}

function renderFix(fix, index, session) {
  const busy = !TERMINAL_STATUSES.includes(session.status);
  const done = fix.status === 'applied';
  const label = done ? 'Applied' : fix.status === 'running' ? 'Applying...' : fix.status === 'failed' ? 'Retry' : 'Apply fix';
  const result = fix.result ? `<p class="ts-fix-result ${fix.result.ok ? 'ok' : 'failed'}">${escapeHtml(fix.result.summary)}</p>` : '';
  return `<div class="ts-fix ${fix.learned ? 'learned' : ''}">
    <div class="ts-fix-head">
      <strong>${escapeHtml(toolLabel(fix.tool_id))}${escapeHtml(argsLabel(fix.args))}</strong>
      <span class="button-row">${fix.learned ? '<span class="learned-badge">learned</span>' : ''}${fix.rule ? '<span class="rule-badge">rule</span>' : ''}<span class="risk risk-${escapeHtml(fix.risk)}">${escapeHtml(fix.risk)} risk</span></span>
    </div>
    <p>${escapeHtml(fix.why || fix.description)}</p>
    ${result}
    <button class="primary-button" data-apply-fix="${index}" ${done || busy ? 'disabled' : ''}>${label}</button>
  </div>`;
}

let tsThinking = null;
const SOLUTION_SOURCES = { ai: 'AI', rule: 'rule', learned: 'learned', playbook: 'tip' };
const SOLUTION_STATUS = { suggested: '', running: 'Running...', applied: 'Applied', failed: 'Failed', done: 'Done by hand', rejected: 'Rejected' };

function renderThinking() {
  const panel = $('ts-thinking');
  if (!panel || !tsThinking) return;
  panel.classList.remove('hidden');
  panel.innerHTML = `<small class="ts-label"><span class="spinner"></span> ${tsThinking.writing ? 'AI IS WRITING THE DIAGNOSIS' : 'AI IS THINKING'} · ${tsThinking.chars} characters of reasoning</small>
    <pre>${escapeHtml(tsThinking.thinking || '')}</pre>`;
  const pre = panel.querySelector('pre');
  pre.scrollTop = pre.scrollHeight;
}

function renderSolution(solution, index, report, session) {
  const busy = !TERMINAL_STATUSES.includes(session.status);
  const fix = solution.fix_index !== null && solution.fix_index !== undefined ? (report.proposed_fixes || [])[solution.fix_index] : null;
  const decided = solution.status && solution.status !== 'suggested' && solution.status !== 'failed';
  const result = fix?.result ? `<p class="ts-fix-result ${fix.result.ok ? 'ok' : 'failed'}">${escapeHtml(fix.result.summary)}</p>` : '';
  const steps = (solution.steps || []).length ? `<ol class="solution-steps">${solution.steps.map((step) => `<li>${escapeHtml(step)}</li>`).join('')}</ol>` : '';
  const actions = solution.status === 'applied' ? ''
    : fix
    ? `<button class="primary-button" data-apply-fix="${solution.fix_index}" ${decided || busy ? 'disabled' : ''}>${solution.status === 'failed' ? 'Retry' : 'Approve & run'}</button>`
    : `<button class="ghost-button" data-solution-decision="done" data-solution-index="${index}" ${decided || busy ? 'disabled' : ''}>Mark as done</button>`;
  const reject = `<button class="ghost-button solution-reject" data-solution-decision="rejected" data-solution-index="${index}" ${decided || busy ? 'disabled' : ''}>Reject</button>`;
  return `<div class="solution-card ${escapeHtml(solution.status || 'suggested')}">
    <div class="solution-head">
      <span class="solution-rank">${index + 1}</span>
      <strong>${escapeHtml(solution.title)}</strong>
      <span class="button-row"><span class="rule-badge">${escapeHtml(SOLUTION_SOURCES[solution.source] || solution.source || 'AI')}</span><span class="risk risk-${escapeHtml(solution.risk)}">${escapeHtml(solution.risk)} risk</span>${fix ? '<span class="learned-badge">AIops can run this</span>' : ''}</span>
    </div>
    ${solution.why ? `<p>${escapeHtml(solution.why)}</p>` : ''}
    ${steps}
    ${result}
    <div class="button-row">${actions}${reject}${SOLUTION_STATUS[solution.status] ? `<span class="soft-label">${escapeHtml(SOLUTION_STATUS[solution.status])}</span>` : ''}</div>
  </div>`;
}

function renderSolutions(report, session) {
  const solutions = report.solutions || [];
  if (!solutions.length) {
    // Sessions from before solutions existed.
    const fixes = (report.proposed_fixes || []).map((fix, index) => renderFix(fix, index, session)).join('');
    const manual = (report.manual_steps || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('');
    return `<small class="ts-label">PROPOSED FIXES</small>${fixes || '<p class="soft-label">No automatic fix applies.</p>'}${manual ? `<small class="ts-label">MANUAL STEPS</small><ol class="ts-list">${manual}</ol>` : ''}`;
  }
  return `<small class="ts-label">SUGGESTED SOLUTIONS · NOTHING RUNS UNTIL YOU APPROVE</small>
    <div class="solution-list">${solutions.map((solution, index) => renderSolution(solution, index, report, session)).join('')}</div>`;
}

async function decideSolution(index, decision) {
  const solution = (await fetch(`/api/troubleshoot/${tsSessionId}`).then((response) => response.json())).report?.solutions?.[index];
  if (!solution) return;
  const question = decision === 'done' ? `Mark "${solution.title}" as done by hand?` : `Reject "${solution.title}"? AIops will not run it.`;
  if (!confirm(question)) return;
  const response = await fetch(`/api/troubleshoot/${tsSessionId}/solutions/${index}/decision`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision }) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) toast(data.detail || 'Could not save the decision', 'error');
  else toast(decision === 'done' ? 'Marked as done' : 'Rejected');
  refreshTroubleshootSession();
}

function renderTroubleshootSession(session) {
  setText('ts-session-device', `SESSION / ${session.device_label || session.device_id} / ${session.os_type || ''}`);
  setText('ts-session-issue', session.issue);
  const pill = $('ts-session-status');
  pill.className = `status-pill ${STATUS_TONES[session.status] || 'unknown'}`;
  pill.textContent = STATUS_LABELS[session.status] || session.status;

  const steps = session.steps || [];
  // Steps that already finished are no longer pending (covers events missed while reconnecting).
  steps.forEach((step) => { if (step.tool_id) tsPendingSteps.delete(pendingKey(step)); });
  if (TERMINAL_STATUSES.includes(session.status)) tsPendingSteps.clear();
  $('ts-steps').innerHTML = steps.map(renderStep).join('') || (tsPendingSteps.size ? '' : '<li class="soft-label">Starting...</li>');
  tsPendingSteps.forEach((pending) => $('ts-steps').appendChild(pendingStepElement(pending)));

  const report = session.report;
  const container = $('ts-report');
  if (session.status === 'failed' && !report) {
    container.innerHTML = `<p class="ts-error">${escapeHtml(session.error || 'The agent failed.')}</p>`;
    return;
  }
  if (!report) {
    const findingsStep = steps.find((step) => step.kind === 'findings');
    container.innerHTML = (findingsStep
      ? `<small class="ts-label">INSTANT FINDINGS</small>${renderFindings(findingsStep.result?.data)}<p class="soft-label"><span class="spinner"></span> The AI is working on the full diagnosis from these results...</p>`
      : '<p class="soft-label"><span class="spinner"></span> Running the checks in parallel...</p>') + '<div id="ts-thinking" class="ts-thinking hidden"></div>';
    if (tsThinking) renderThinking();
    return;
  }
  const modeLabel = { instant: 'Instant rule-based diagnosis', fast: 'Fast AI diagnosis', deep: 'Deep AI diagnosis' }[report.mode] || 'Diagnosis';
  const timing = report.timing ? `<p class="ts-timing">${escapeHtml(modeLabel)} in ${report.timing.total_seconds}s (checks ${report.timing.evidence_seconds}s${report.mode === 'instant' ? '' : `, AI ${report.timing.ai_seconds}s`})</p>` : '';
  const quickFindings = report.mode !== 'instant' && (report.quick_findings || []).length
    ? `<details class="ts-similar"><summary class="ts-label">INSTANT FINDINGS (${report.quick_findings.length})</summary>${renderFindings(report.quick_findings)}</details>` : '';
  const evidence = (report.evidence || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('');
  const reasoning = report.reasoning ? `<details class="ts-similar ts-reasoning"><summary class="ts-label">HOW THE AI REASONED${report.ai?.model ? ` · ${escapeHtml(report.ai.model)}` : ''}</summary><pre>${escapeHtml(report.reasoning)}</pre></details>` : '';
  const verify = session.verify ? `
    <div class="ts-verify ${session.verify.resolved ? 'ok' : session.verify.resolved === false ? 'failed' : ''}">
      <small>VERIFICATION AFTER ${escapeHtml(toolLabel(session.verify.after_fix))}${session.verify.method === 'rules' ? ' · RULE RE-CHECK' : ''}</small>
      <strong>${session.verify.resolved ? 'Issue resolved' : session.verify.resolved === false ? 'Issue not resolved yet' : 'Not verified'}</strong>
      <p>${escapeHtml(session.verify.explanation)}</p>
      ${(session.verify.next_steps || []).length ? `<ul>${session.verify.next_steps.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : ''}
    </div>` : '';
  container.innerHTML = `
    ${session.status === 'failed' && session.error ? `<p class="ts-error">${escapeHtml(session.error)}</p>` : ''}
    ${timing}
    <div class="ts-root">
      <div class="ts-badges"><span class="severity severity-${escapeHtml(report.severity)}">${escapeHtml(report.severity)}</span><span class="soft-label">confidence: ${escapeHtml(report.confidence)}</span></div>
      <small>ROOT CAUSE</small>
      <strong>${escapeHtml(report.root_cause)}</strong>
    </div>
    ${evidence ? `<small class="ts-label">EVIDENCE</small><ul class="ts-list">${evidence}</ul>` : ''}
    ${quickFindings}
    ${verify}
    ${renderSolutions(report, session)}
    ${reasoning}
    ${renderSimilarCases(report.similar_cases)}
    ${TERMINAL_STATUSES.includes(session.status) ? renderFeedback(session) : ''}
  `;
}

function renderSimilarCases(cases) {
  if (!cases || !cases.length) return '';
  return `<div class="ts-similar"><small class="ts-label">FROM MEMORY · SIMILAR PAST TICKETS</small><ul>${cases.map((item) => `<li>${escapeHtml(item.issue)} → ${escapeHtml(item.root_cause || 'unknown cause')} <em>(${escapeHtml(item.outcome)})</em></li>`).join('')}</ul></div>`;
}

function renderFeedback(session) {
  const given = tsFeedback[session.session_id];
  return `<div class="ts-feedback">
    <small class="ts-label">TEACH THE AI</small>
    <p>Was this diagnosis right? Your answer is saved as a learned case and folded into the next model build.</p>
    <div class="button-row">
      <button class="ghost-button ${given === 'up' ? 'selected' : ''}" data-feedback="up">👍 Correct</button>
      <button class="ghost-button ${given === 'down' ? 'selected' : ''}" data-feedback="down">👎 Wrong</button>
    </div>
    <div id="ts-correction" class="${given === 'down-open' ? '' : 'hidden'}">
      <input id="ts-correct-cause" class="field-input" placeholder="What was the real root cause? (optional, but it teaches the model)">
      <div class="button-row" style="margin-top:8px"><button class="primary-button" data-feedback="down-submit">Save correction</button></div>
    </div>
  </div>`;
}

async function sendFeedback(kind) {
  if (kind === 'down') {
    tsFeedback[tsSessionId] = 'down-open';
    $('ts-correction').classList.remove('hidden');
    $('ts-correct-cause').focus();
    return;
  }
  const helpful = kind === 'up';
  const body = { helpful, corrected_root_cause: helpful ? '' : ($('ts-correct-cause')?.value || '') };
  try {
    const response = await fetch(`/api/troubleshoot/${tsSessionId}/feedback`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Could not save feedback');
    tsFeedback[tsSessionId] = helpful ? 'up' : 'down';
    toast(data.model_rebuilt ? 'Thanks! The AIops model was rebuilt with this lesson.' : 'Thanks! Saved as a learned case.');
    refreshTroubleshootSession();
    checkAI();
  } catch (error) {
    toast(error.message, 'error');
  }
}

// ============================================================================
// Learning — self-improving model
// ============================================================================

const OUTCOME_TONES = { resolved: 'ok', unresolved: 'critical', fix_failed: 'critical', diagnosed: 'unknown' };

async function loadLearning() {
  try {
    const [stats, cases, lessons] = await Promise.all([
      fetch('/api/learning/stats').then((response) => response.json()),
      fetch('/api/learning/cases?limit=50').then((response) => response.json()),
      fetch('/api/learning/lessons').then((response) => response.json()),
    ]);
    const model = stats.model || {};
    setText('learn-count', stats.total_cases || '');
    setText('learn-total', stats.total_cases);
    setText('learn-trusted', `${stats.trusted_cases} trusted (verified or confirmed by you)`);
    setText('learn-rate', `${Math.round((stats.resolution_rate || 0) * 100)}%`);
    setText('learn-outcomes', Object.entries(stats.outcomes || {}).map(([key, value]) => `${value} ${key.replace('_', ' ')}`).join(' · ') || 'No outcomes yet');
    setText('learn-version', model.version ? `v${model.version}` : 'not built');
    setText('learn-model-name', stats.learned_model_name);
    setText('learn-model-detail', model.version
      ? `${stats.learned_model_name} on ${model.base_model} · ${model.lessons} lessons · ${new Date(model.built_at).toLocaleString()}${model.created_in_ollama ? '' : ' · not loaded in Ollama'}`
      : `Builds automatically every ${stats.rebuild_every} trusted cases`);

    $('learn-lessons').innerHTML = (lessons.lessons || []).map((line) => `<li>${escapeHtml(line.replace(/^- /, ''))}</li>`).join('')
      || '<li class="soft-label">No lessons yet. Resolve a few issues and give feedback.</li>';
    $('learn-top-fixes').innerHTML = (stats.top_fixes || []).map((fix) => `<tr><td>${escapeHtml(toolLabel(fix.tool_id))}</td><td>${fix.resolved} / ${fix.attempts}</td><td>${Math.round(fix.rate * 100)}%</td></tr>`).join('')
      || '<tr><td colspan="3" class="empty-state">No applied fixes yet.</td></tr>';
    $('learn-cases').innerHTML = (cases.cases || []).map((item) => `
      <tr>
        <td>${new Date(item.created_at).toLocaleString()}</td>
        <td>${escapeHtml(item.issue)}</td>
        <td>${escapeHtml(item.effective_root_cause || '--')}${item.corrected_root_cause ? ' <span class="learned-badge">corrected</span>' : ''}</td>
        <td><span class="status-pill ${OUTCOME_TONES[item.outcome] || 'unknown'}">${escapeHtml(item.outcome.replace('_', ' '))}</span></td>
        <td>${item.feedback === 'up' ? '👍' : item.feedback === 'down' ? '👎' : '--'}</td>
      </tr>`).join('') || '<tr><td colspan="5" class="empty-state">No cases yet. Every finished ticket shows up here.</td></tr>';
  } catch (error) {
    setText('learn-status', error.message);
  }
}

async function rebuildLearnedModel() {
  const button = $('learn-rebuild');
  button.disabled = true;
  setText('learn-status', 'Rebuilding the AIops model from learned cases...');
  try {
    const response = await fetch('/api/learning/rebuild', { method: 'POST' });
    const info = await response.json();
    if (!response.ok) throw new Error(info.detail || 'Rebuild failed');
    setText('learn-status', info.created_in_ollama ? `Built ${info.model} v${info.version} from ${info.trusted_cases} trusted cases.` : `Wrote the Modelfile, but Ollama could not create the model: ${info.error}`);
    toast(info.created_in_ollama ? `${info.model} v${info.version} is ready` : 'Model files written; Ollama create failed', info.created_in_ollama ? 'ok' : 'error');
    loadLearning();
    checkAI();
  } catch (error) {
    setText('learn-status', error.message);
  } finally {
    button.disabled = false;
  }
}

async function applyTroubleshootFix(index) {
  const session = await fetch(`/api/troubleshoot/${tsSessionId}`).then((response) => response.json());
  const fix = session.report?.proposed_fixes?.[index];
  if (!fix) return;
  const warning = fix.risk === 'high' ? '\n\nHIGH RISK: this may need a reboot or take a long time.' : '';
  if (!confirm(`Approve and run "${toolLabel(fix.tool_id)}" on ${session.device_label}?\n\nWhat it does: ${fix.description}${warning}\n\nAIops only runs it because you approve it now; the approval is recorded.`)) return;
  const response = await fetch(`/api/troubleshoot/${tsSessionId}/fixes/${index}/apply`, { method: 'POST' });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) toast(data.detail || 'Could not apply the fix', 'error');
  else toast(`Applying ${toolLabel(fix.tool_id)}...`);
  refreshTroubleshootSession();
}

function troubleshootDevice(deviceId) {
  switchTab('troubleshoot');
  loadTroubleshootTargets(deviceId);
  $('ts-issue').focus();
}

// ============================================================================
// Decisions (audit trail of the AI and of human approvals)
// ============================================================================

const DECISION_LABELS = {
  diagnosis: 'Diagnosis', fix_approved: 'Fix approved', fix_rejected: 'Solution rejected', fix_done_manually: 'Done by hand',
  fix_result: 'Fix result', health_analysis: 'Health analysis', log_analysis: 'Log analysis', chat_answer: 'Chat answer',
  software_action: 'Software action', performance_analysis: 'Performance analysis', model_switch: 'Model switch',
  leftover_review: 'Leftover review',
};

// Who a decision belongs to when no approver is recorded: rejections are people, results are re-checks.
const DECISION_BY = { fix_rejected: 'operator', fix_result: 'verification' };

async function loadDecisions() {
  const body = $('decisions-body');
  try {
    const data = await fetch('/api/decisions?limit=100').then((response) => response.json());
    setText('decisions-folder', data.folder || 'decisions');
    body.innerHTML = (data.decisions || []).map((item) => `
      <tr>
        <td>${escapeHtml(item.recorded_at ? new Date(item.recorded_at).toLocaleString() : '--')}</td>
        <td><span class="status-pill ${item.approved_by ? 'ok' : 'unknown'}">${escapeHtml(DECISION_LABELS[item.kind] || item.kind)}</span></td>
        <td>${escapeHtml(item.device || '--')}</td>
        <td>${escapeHtml(item.summary || '')}</td>
        <td>${escapeHtml(item.approved_by || DECISION_BY[item.kind] || 'AI (suggestion)')}</td>
        <td>${escapeHtml(item.model || '--')}${item.thinking ? ' · thinking' : ''}</td>
      </tr>`).join('') || '<tr><td colspan="6" class="empty-state">No decisions yet. Run a diagnosis to create the first one.</td></tr>';
  } catch (error) {
    body.innerHTML = `<tr><td colspan="6" class="empty-state">${escapeHtml(friendlyError(error))}</td></tr>`;
  }
}

// ============================================================================
// Tab switching
// ============================================================================

const TAB_LOADERS = {
  troubleshoot: loadTroubleshoot,
  learning: loadLearning,
  'add-agent': loadAddAgent,
  alerts: loadAlerts,
  agents: loadAgents,
  security: loadSecurity,
  performance: loadPerformance,
  logs: loadEventLogs,
  software: () => loadSoftware(),
  technician: loadChatDevice,
  decisions: loadDecisions,
};

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach((element) => element.classList.toggle('active-tab', element.id === tab));
  document.querySelectorAll('.nav-item').forEach((element) => element.classList.toggle('active', element.dataset.tab === tab));
  if (location.hash.slice(1) !== tab) history.replaceState(null, '', `#${tab}`);
  const loader = TAB_LOADERS[tab];
  if (loader) loader();
}

// ============================================================================
// Event wiring
// ============================================================================

function wireEvents() {
  document.querySelectorAll('.nav-item').forEach((button) => button.addEventListener('click', () => switchTab(button.dataset.tab)));
  document.querySelectorAll('[data-goto]').forEach((button) => button.addEventListener('click', () => switchTab(button.dataset.goto)));
  $('theme-toggle').addEventListener('click', toggleTheme);
  $('learn-rebuild').addEventListener('click', rebuildLearnedModel);

  $('refresh-alerts').addEventListener('click', loadAlerts);
  $('alerts-body').addEventListener('click', (event) => {
    if (event.target.dataset.diagnose) diagnoseAlert(event.target.dataset.diagnose);
  });

  $('refresh-security').addEventListener('click', loadSecurity);
  $('perf-run').addEventListener('click', runPerformanceTest);
  $('perf-ai').addEventListener('click', (event) => {
    if (event.target.closest('[data-perf-analyse]')) analysePerformance();
    if (event.target.closest('[data-perf-open-analysis]') && perfJob?.analysis_session_id) openPerfAnalysis(perfJob.analysis_session_id, perfJob.device_id);
  });
  $('perf-updates').addEventListener('click', onPerfUpdatesClick);
  $('perf-updates').addEventListener('change', (event) => {
    const box = event.target.closest('[data-os-update]');
    if (box) perfPicked.set(box.dataset.osUpdate, box.checked);
  });
  wireInputTesters();
  $('refresh-logs').addEventListener('click', loadEventLogs);
  $('diagnose-logs-button').addEventListener('click', diagnoseEventLogs);

  $('chat-form').addEventListener('submit', sendChat);

  $('add-agent-button').addEventListener('click', () => switchTab('add-agent'));
  $('generate-token-button').addEventListener('click', () => generateToken());
  $('install-server-agent').addEventListener('click', installAgentOnServer);
  $('download-agent-button').addEventListener('click', downloadAgent);
  $('copy-install').addEventListener('click', copyInstallCommand);
  $('enroll-server').addEventListener('input', updateInstallInstructions);

  $('ts-start').addEventListener('click', startTroubleshoot);
  $('ts-refresh-history').addEventListener('click', loadTroubleshootHistory);
  $('ts-playbooks').addEventListener('click', (event) => {
    const chip = event.target.closest('[data-playbook]');
    if (chip) selectPlaybook(chip.dataset.playbook);
  });
  $('ts-mode').addEventListener('click', (event) => {
    const option = event.target.closest('[data-mode]');
    if (option && !option.disabled) setMode(option.dataset.mode);
  });
  $('ts-history').addEventListener('click', (event) => {
    const item = event.target.closest('[data-session]');
    if (item) openTroubleshootSession(item.dataset.session);
  });
  $('ts-report').addEventListener('click', (event) => {
    const button = event.target.closest('[data-apply-fix]');
    if (button) applyTroubleshootFix(Number(button.dataset.applyFix));
    const decision = event.target.closest('[data-solution-decision]');
    if (decision) decideSolution(Number(decision.dataset.solutionIndex), decision.dataset.solutionDecision);
    const feedback = event.target.closest('[data-feedback]');
    if (feedback) sendFeedback(feedback.dataset.feedback === 'down-submit' ? 'down-submit' : feedback.dataset.feedback);
  });
  $('ts-issue').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) startTroubleshoot();
  });

  document.querySelectorAll('.platform-tab').forEach((button) => button.addEventListener('click', () => {
    selectedPlatform = button.dataset.platform;
    document.querySelectorAll('.platform-tab').forEach((item) => item.classList.toggle('active', item === button));
    if (enrollingServer && selectedPlatform !== 'linux') {
      enrollingServer = false;  // a different device after all: back to the usual address
      $('enroll-server').value = defaultEnrollServer || location.origin;
    }
    updateInstallInstructions();
  }));

  $('agents-grid').addEventListener('click', (event) => {
    const card = event.target.closest('[data-device]');
    if (card) loadDevice(card.dataset.device);
  });
  $('device-detail').addEventListener('click', (event) => {
    const button = event.target.closest('button');
    if (!button) return;
    if (button.dataset.deviceDiagnose) diagnoseDevice(button.dataset.deviceDiagnose);
    if (button.dataset.deviceTroubleshoot) troubleshootDevice(button.dataset.deviceTroubleshoot);
    if (button.dataset.deviceSoftware) openSoftware(button.dataset.deviceSoftware);
    if (button.dataset.onboardingOpen) openOnboardingReport(button.dataset.onboardingOpen);
    if (button.dataset.onboardingRerun) rerunOnboarding(button.dataset.onboardingRerun);
  });

  $('decisions-refresh').addEventListener('click', loadDecisions);
  $('sw-scan').addEventListener('click', startSoftwareScan);
  $('sw-device').addEventListener('change', () => loadSoftware($('sw-device').value));
  $('sw-search').addEventListener('input', renderSoftware);
  $('sw-filter').addEventListener('click', (event) => {
    const option = event.target.closest('[data-filter]');
    if (!option) return;
    swFilter = option.dataset.filter;
    document.querySelectorAll('#sw-filter [data-filter]').forEach((item) => {
      item.classList.toggle('active', item === option);
      item.setAttribute('aria-checked', String(item === option));
    });
    renderSoftware();
  });
  $('sw-body').addEventListener('click', (event) => {
    const update = event.target.closest('[data-sw-update]');
    if (update) runSoftwareAction('update', update.dataset.swUpdate, update.dataset.swName);
    const uninstall = event.target.closest('[data-sw-uninstall]');
    if (uninstall) runSoftwareAction('uninstall', uninstall.dataset.swUninstall, uninstall.dataset.swName);
    const remove = event.target.closest('[data-sw-remove]');
    if (remove) removeCompletely(remove.dataset.swRemove, remove.dataset.swName);
  });
  $('sw-quarantine-btn').addEventListener('click', () => { if (swDeviceId) loadQuarantine(); });
  $('sw-leftovers').addEventListener('click', (event) => {
    if (event.target.closest('[data-lo-review]')) reviewLeftovers();
    if (event.target.closest('[data-lo-quarantine]')) quarantineSelected();
    if (event.target.closest('[data-lo-close]')) { swLeftoverJob = null; renderLeftovers(); }
  });
  $('sw-quarantine').addEventListener('click', (event) => {
    const restore = event.target.closest('[data-q-restore]');
    if (restore) restoreBatch(restore.dataset.qRestore, restore.dataset.qName);
    if (event.target.closest('[data-q-close]')) $('sw-quarantine').classList.add('hidden');
  });

  $('ai-chip').addEventListener('click', () => setModelPanel($('model-panel').classList.contains('hidden')));
  $('model-list').addEventListener('click', (event) => {
    const select = event.target.closest('[data-model-select]');
    if (select) selectModel(select.dataset.modelSelect);
    const pull = event.target.closest('[data-model-pull]');
    if (pull) pullModel(pull.dataset.modelPull);
  });
  document.addEventListener('click', (event) => {
    if (!event.target.closest('.model-switcher')) setModelPanel(false);
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !$('model-panel').classList.contains('hidden')) {
      setModelPanel(false);
      $('ai-chip').focus();
    }
  });
}

// ============================================================================
// Bootstrap
// ============================================================================

wireEvents();
connectMonitor();
loadHealth();
loadAlerts();
checkAI();
loadLearning();
setInterval(loadHealth, 5000);
setInterval(checkAI, 30000);
if (location.hash && $(location.hash.slice(1))?.classList.contains('tab')) switchTab(location.hash.slice(1));

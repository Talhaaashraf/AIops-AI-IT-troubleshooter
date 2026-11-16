// Security, component tests and opt-in file reputation. All product copy is English.
let wbSecurityDevice = null;
let wbSecurityData = null;
let wbSecuritySequence = 0;
let wbSecurityBusy = false;
const wbSavedSections = new Map();

function wbPorts() {
  const source = wbSecurityData?.listening_ports;
  const terms = $('security-search').value.toLowerCase().trim().split(/\s+/).filter(Boolean);
  const ports = (source?.ports || []).filter((row) => terms.every((term) => `${row.port} ${row.address} ${row.process} ${RISKY_PORTS[row.port] || ''}`.toLowerCase().includes(term)));
  setText('ports-count', `${ports.length} of ${source?.ports?.length || 0} listeners`);
  $('ports-body').innerHTML = !source?.available
    ? `<tr><td colspan="4">${escapeHtml(source?.detail || 'Listening-port evidence unavailable; exposure is unknown.')}</td></tr>`
    : ports.length ? ports.map((row) => `<tr><td>${escapeHtml(row.port)}</td><td>${escapeHtml(row.address)}</td><td>${escapeHtml(row.process || 'Unknown')}</td><td>${escapeHtml(!isLoopbackAddress(row.address) ? RISKY_PORTS[row.port] || 'Review exposure' : 'Loopback only')}</td></tr>`).join('')
      : `<tr><td colspan="4">${terms.length ? 'No listeners match this search.' : 'No listeners returned by this check.'}</td></tr>`;
}

const wbRenderSecurity = renderSecurity;
renderSecurity = function (data) {
  wbSecurityData = data || {};
  wbRenderSecurity(wbSecurityData);
  if (wbSecurityData.running_as_admin == null) setText('admin-detail', 'Privilege information unavailable.');
  wbPorts();
};

loadSecurity = async function () {
  const sequence = ++wbSecuritySequence;
  const device = await fillDeviceSelect($('security-device'), loadSecurity);
  if (sequence !== wbSecuritySequence) return;
  wbSecurityDevice = device;
  renderSecurity({});
  setText('security-status', 'Loading selected-device evidence...');
  try {
    const url = device === 'local' ? '/api/diagnostics/security' : `/api/agents/${encodeURIComponent(device)}/diagnostics`;
    const data = await readJson(await fetch(url));
    if (sequence !== wbSecuritySequence || device !== wbSecurityDevice) return;
    renderSecurity(device === 'local' ? data : data.diagnostics?.security || {});
    setText('security-status', data.timestamp ? `Last reported snapshot: ${new Date(data.timestamp).toLocaleString()}. Run checks for fresh evidence.` : 'Snapshot time unavailable. Run security checks for fresh evidence.');
  } catch (error) {
    if (sequence === wbSecuritySequence) setText('security-status', friendlyError(error));
  }
};

async function wbSecurityScan() {
  if (wbSecurityBusy) return;
  const device = $('security-device').value;
  if (!device) return;
  wbSecurityBusy = true;
  $('refresh-security').disabled = true;
  $('security-device').disabled = true;
  ++wbSecuritySequence;
  setText('security-status', 'Collecting fresh security evidence from the selected device...');
  try {
    let job = await readJson(await fetch(`/api/agents/${encodeURIComponent(device)}/performance/test`, {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({section: 'security'}),
    }));
    const deadline = Date.now() + 240000;
    while (job.state === 'running' && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      job = await readJson(await fetch(`/api/performance/jobs/${encodeURIComponent(job.job_id)}`));
    }
    if (job.state === 'running') throw new Error('Security checks are still running. Refresh the device later.');
    const result = job.sections.security;
    if (!result?.ok) throw new Error(result?.summary || 'Security evidence unavailable');
    renderSecurity(result.data);
    setText('security-status', `Fresh evidence from ${job.device}: ${new Date(job.finished_at).toLocaleString()}. Missing checks remain unknown.`);
  } catch (error) {
    setText('security-status', friendlyError(error));
  } finally {
    wbSecurityBusy = false;
    $('refresh-security').disabled = false;
    $('security-device').disabled = false;
  }
}
$('security-search').addEventListener('input', wbPorts);

const wbHardwareRows = [
  ['CPU', 'cpu'], ['RAM', 'ram'], ['Storage / SMART', 'disks'], ['Power / AC status', 'power'],
  ['Heat / thermal readings', 'hardware'], ['Battery health', 'battery'], ['Graphics / GPU', 'hardware'],
  ['Sound / speakers inventory', 'peripherals'], ['Recording / microphone inventory', 'peripherals'], ['Camera inventory', 'peripherals'],
  ['LCD / monitor inventory', 'peripherals'], ['Keyboard detection', 'input'], ['Mouse / touchpad detection', 'input'],
];
function wbRow(label, section, saved, busy, stress = false) {
  const result = saved?.[section];
  const states = {queued: 'Queued', running: 'Running', done: 'Collected', failed: 'Failed / unavailable', skipped: 'Not supported'};
  const state = result ? states[result.state] || result.state : 'Not run';
  let detail = result?.summary || 'Run this check to collect evidence.';
  let body = '';
  if (result?.data != null) {
    const data = result.data;
    if (section === 'hardware' && label.startsWith('Heat')) body = data.max_temperature_c == null ? 'Temperature sensors unavailable; thermal health is unknown.' : `Maximum reported temperature: ${data.max_temperature_c} °C`;
    else if (section === 'hardware' && label.startsWith('Graphics')) body = JSON.stringify(data.gpus || [], null, 2);
    else body = JSON.stringify(data, null, 2);
  }
  if (stress && result?.state === 'done') detail = result.summary;
  return `<article class="workbench-row"><div><strong>${escapeHtml(label)}</strong><p class="soft-label">${escapeHtml(detail)}</p>${result?.observed_at ? `<small>Collected ${escapeHtml(new Date(result.observed_at).toLocaleString())}</small>` : ''}${body ? `<details><summary>Evidence</summary><pre>${escapeHtml(body)}</pre></details>` : ''}</div><span class="status-pill ${result?.state === 'failed' ? 'critical' : 'unknown'}">${escapeHtml(state)}</span><button type="button" class="ghost-button" data-component-run="${escapeHtml(section)}" ${busy ? 'disabled' : ''}>${stress ? 'Start load test' : 'Run'}</button></article>`;
}

const wbBaseRenderPerformance = renderPerformanceJob;
renderPerformanceJob = function () {
  wbBaseRenderPerformance();
  const device = perfDeviceId || $('perf-device').value;
  const saved = wbSavedSections.get(device) || {};
  if (perfJob?.device_id === device) {
    for (const [name, entry] of Object.entries(perfJob.sections || {})) saved[name] = {...entry, observed_at: perfJob.finished_at || perfJob.started_at};
    wbSavedSections.set(device, saved);
  }
  const busy = perfJob?.state === 'running';
  $('perf-sections').className = 'workbench-rows';
  $('perf-sections').innerHTML = [['Live load', 'system'], ['CPU processes', 'processes'], ['Memory processes', 'memory'], ['Short speed benchmark', 'benchmark'], ['Startup', 'boot'], ['OS updates', 'os_updates'], ['App updates', 'apps']].map(([label, section]) => wbRow(label, section, saved, busy)).join('');
  $('hardware-tests').innerHTML = wbHardwareRows.map(([label, section]) => wbRow(label, section, saved, busy)).join('');
  $('stress-tests').innerHTML = ['cpu', 'ram', 'storage'].map((name) => wbRow(name.toUpperCase(), 'stress_' + name, saved, busy, true)).join('');
};

async function wbRunComponent(section) {
  const device = $('perf-device').value;
  const stress = section.startsWith('stress_');
  if (!device || perfJob?.state === 'running') return;
  if (stress && !confirm(`Start ${section.replace('stress_', '')} load check on ${$('perf-device').selectedOptions[0]?.textContent}? Up to 10 seconds of work; it can temporarily slow the device. Temperature sensors may be unavailable. Storage uses a temporary file; RAM allocation is capped at 128 MiB. Keep important work saved.`)) return;
  try {
    const job = await readJson(await fetch(`/api/agents/${encodeURIComponent(device)}/performance/test`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({section, approved: stress})}));
    if (device !== $('perf-device').value) return;
    perfDeviceId = device;
    perfJob = job;
    renderPerformanceJob();
    pollPerformance(job.job_id);
  } catch (error) { setPerfStatus(friendlyError(error), 'error'); }
}
['perf-sections', 'hardware-tests', 'stress-tests'].forEach((id) => $(id).addEventListener('click', (event) => {
  const button = event.target.closest('[data-component-run]');
  if (button) wbRunComponent(button.dataset.componentRun);
}));
renderPerformanceJob();

let wbMediaStream = null;
let wbRecorder = null;
let wbRecordingUrl = null;
let wbMediaTimer = null;
let wbAudio = null;
let wbMediaGeneration = 0;
const wbColours = ['#ffffff', '#000000', '#ff0000', '#00ff00', '#0000ff', '#808080'];
let wbColourIndex = 0;
function wbStopMedia(clear = true) {
  ++wbMediaGeneration;
  clearTimeout(wbMediaTimer);
  if (wbRecorder?.state === 'recording') wbRecorder.stop();
  wbRecorder = null;
  wbMediaStream?.getTracks().forEach((track) => track.stop());
  wbMediaStream = null;
  $('hardware-camera').srcObject = null;
  $('hardware-camera').classList.add('hidden');
  $('display-test').classList.add('hidden');
  if (document.fullscreenElement === $('display-test')) document.exitFullscreen().catch(() => {});
  wbAudio?.close().catch(() => {});
  wbAudio = null;
  if (clear) {
    if (wbRecordingUrl) URL.revokeObjectURL(wbRecordingUrl);
    wbRecordingUrl = null;
    $('hardware-recording').removeAttribute('src');
    $('hardware-recording').classList.add('hidden');
  }
}
async function wbLocalTest(kind) {
  wbStopMedia();
  const generation = wbMediaGeneration;
  try {
    if (kind === 'display') {
      wbColourIndex = 0;
      const panel = $('display-test');
      panel.style.background = wbColours[0];
      panel.textContent = 'Click or Space: next colour · Escape: close. Inspect for dead pixels, lines and uneven lighting.';
      panel.classList.remove('hidden');
      panel.focus();
      if (panel.requestFullscreen) await panel.requestFullscreen().catch(() => {});
      setText('hardware-local-status', 'Visual inspection required. No automatic display pass is recorded.');
    } else if (kind === 'sound') {
      const Audio = window.AudioContext || window.webkitAudioContext;
      if (!Audio) throw new Error('Audio testing is not supported by this browser.');
      wbAudio = new Audio();
      await wbAudio.resume();
      for (const [index, pan] of [-1, 1].entries()) {
        const oscillator = wbAudio.createOscillator();
        const gain = wbAudio.createGain();
        const channel = wbAudio.createStereoPanner();
        gain.gain.value = 0.04;
        channel.pan.value = pan;
        oscillator.frequency.value = 440;
        oscillator.connect(gain).connect(channel).connect(wbAudio.destination);
        oscillator.start(wbAudio.currentTime + index);
        oscillator.stop(wbAudio.currentTime + index + 0.7);
      }
      setText('hardware-local-status', 'Listen for a quiet left tone, then right tone. Hearing the tones requires your confirmation.');
      wbMediaTimer = setTimeout(() => wbStopMedia(false), 2500);
    } else {
      if (!window.isSecureContext || !navigator.mediaDevices?.getUserMedia) throw new Error('Camera and microphone require HTTPS or localhost. The HTTP LAN address cannot request these permissions.');
      const stream = await navigator.mediaDevices.getUserMedia(kind === 'camera' ? {video: true, audio: false} : {audio: true, video: false});
      if (generation !== wbMediaGeneration) { stream.getTracks().forEach((track) => track.stop()); return; }
      wbMediaStream = stream;
      if (kind === 'camera') {
        $('hardware-camera').srcObject = stream;
        $('hardware-camera').classList.remove('hidden');
        setText('hardware-local-status', 'Camera preview on this browser device. Inspect the image; preview stops after 60 seconds.');
        wbMediaTimer = setTimeout(() => wbStopMedia(false), 60000);
      } else {
        if (!window.MediaRecorder) throw new Error('Audio recording is unavailable in this browser.');
        const chunks = [];
        const recorder = new MediaRecorder(stream);
        wbRecorder = recorder;
        recorder.ondataavailable = (event) => { if (event.data.size) chunks.push(event.data); };
        recorder.onstop = () => {
          stream.getTracks().forEach((track) => track.stop());
          if (generation !== wbMediaGeneration) return;
          wbRecordingUrl = URL.createObjectURL(new Blob(chunks, {type: recorder.mimeType}));
          $('hardware-recording').src = wbRecordingUrl;
          $('hardware-recording').classList.remove('hidden');
          setText('hardware-local-status', 'Recording complete. Play it to check clarity. Audio stays in this browser until you clear it or leave this tab.');
        };
        recorder.start();
        setText('hardware-local-status', 'Recording for five seconds on this browser device...');
        wbMediaTimer = setTimeout(() => { if (recorder.state === 'recording') recorder.stop(); }, 5000);
      }
    }
  } catch (error) { wbStopMedia(); setText('hardware-local-status', friendlyError(error)); }
}
$('interactive-hardware').addEventListener('click', (event) => {
  const button = event.target.closest('[data-local-test]');
  if (button) wbLocalTest(button.dataset.localTest);
});
$('hardware-stop').addEventListener('click', () => { wbStopMedia(); setText('hardware-local-status', 'Media stopped and cleared.'); });
function wbNextColour() { wbColourIndex = (wbColourIndex + 1) % wbColours.length; $('display-test').style.background = wbColours[wbColourIndex]; }
$('display-test').addEventListener('click', wbNextColour);
$('display-test').addEventListener('keydown', (event) => { if (event.code === 'Space') { event.preventDefault(); wbNextColour(); } if (event.key === 'Escape') wbStopMedia(); });
document.addEventListener('visibilitychange', () => { if (document.hidden) wbStopMedia(); });
window.addEventListener('pagehide', () => wbStopMedia());
const wbSwitchTab = switchTab;
switchTab = function (id) { if (id !== 'performance') wbStopMedia(); return wbSwitchTab(id); };


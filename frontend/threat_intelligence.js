// Provider requests go only to Sentinel. Keys never enter browser persistence.
(() => {
  const providers = {virustotal: 'VirusTotal', hybrid_analysis: 'Hybrid Analysis'};
  // Gemini is a second-opinion AI: it checks the local model's answers. Same key handling; it never gets files.
  const cards = {...providers, gemini: 'Gemini (second opinion)'};
  const panel = document.createElement('section');
  panel.className = 'panel intelligence-panel';
  panel.id = 'threat-intelligence';
  panel.innerHTML = `<div class="section-heading"><div><p class="kicker">Evidence and reputation</p><h2>Threat Intelligence</h2></div><button id="ti-refresh" class="ghost-button">Refresh status</button></div>
    <p class="soft-label">External reports describe reputation or sandbox activity. They do not prove that the behaviour occurred on the selected device. No detections is not a safety guarantee.</p>
    <details><summary>Threat Intelligence Settings</summary><p>Provider permission is required for this office/business workflow. Possession of an API key is not permission. VirusTotal public API restricts commercial use and certain business workflows. Remote key entry and sample transfers require HTTPS.</p><div class="ti-provider-grid" id="ti-settings"></div></details>
    <form id="ti-search" class="sw-toolbar"><label class="sw-field"><span>SHA-256 hash</span><input id="ti-hash" class="field-input" pattern="[A-Fa-f0-9]{64}" maxlength="64" required placeholder="64-character SHA-256"></label><button>Check authorized providers</button></form>
    <p id="ti-context" class="soft-label" role="status"></p><div class="ti-provider-grid" id="ti-results"></div>
    <button id="ti-explain" class="ghost-button" type="button">Explain provider evidence with AI</button><div id="ti-explanation" role="status"></div>
    <details><summary>Further analysis — separate upload approval</summary><p>Public submissions can be shared with provider partners. Only share files you are authorized to disclose. Samples are never executed by Sentinel and expire after ten minutes.</p>
    <label>Provider <select id="ti-provider" class="field-input"><option value="virustotal">VirusTotal</option><option value="hybrid_analysis">Hybrid Analysis</option></select></label>
    <form id="ti-file-form" class="sw-toolbar"><label class="sw-field"><span>File from this browser device (maximum 32 MiB)</span><input id="ti-file" type="file" required></label><button>Transfer to Sentinel for hash check</button></form>
    <form id="ti-transfer" class="sw-toolbar"><label class="sw-field"><span>Endpoint finding ID from the current scan</span><input id="ti-finding" class="field-input" required placeholder="T1"></label><label class="sw-field"><span>Expected size in bytes</span><input id="ti-size" class="field-input" type="number" min="1" max="33554432" required></label><button>Approve endpoint transfer to Sentinel</button></form>
    <p class="soft-label">Endpoint transfer uses the SHA-256 above and the current device/scan. Provider submission still needs its own approval below.</p>
    <div id="ti-sample" role="status"></div><div id="ti-approval" hidden><label id="ti-environment-label">Sandbox environment <select id="ti-environment" class="field-input"></select></label><button id="ti-upload">Approve external submission</button><button id="ti-cancel" class="ghost-button">Discard sample</button></div><button id="ti-analysis" class="ghost-button" hidden>Refresh analysis status</button></details>
    <div class="section-heading"><h3>Selected-device investigations</h3><button id="ti-investigate">Collect security evidence</button></div>
    <div id="ti-investigation" role="status"></div><div id="ti-history"></div>
    <form id="ti-findings-form" class="sw-toolbar"><label class="sw-field"><span>Search behaviour findings: path, process, hash, rule or source</span><input id="ti-findings-query" class="field-input" maxlength="200"></label><button>Search findings</button></form><div id="ti-findings" role="status"></div>`;
  $('threats').appendChild(panel);
  const securityLink = document.createElement('button');
  securityLink.className = 'ghost-button'; securityLink.textContent = 'Open Threat Intelligence settings and investigations';
  securityLink.onclick = () => { switchTab('threats'); panel.scrollIntoView({behavior: 'smooth'}); panel.querySelector('details').open = true; };
  $('security').appendChild(securityLink);
  let generation = 0, currentHash = '', sample = null, analysis = null;
  const settings = {}, requestIds = {};
  const selected = () => $('threat-device').value || threatDeviceId || 'local';
  const context = () => ({generation, device: selected(), hash: currentHash});
  const current = (ctx) => ctx.generation === generation && ctx.device === selected() && ctx.hash === currentHash;
  const api = async (path, options) => readJson(await fetch('/api/threat-intelligence' + path, options));
  const post = (body) => ({method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
  const stamp = (value) => value ? new Date(value * 1000).toLocaleString() : 'Not available';
  const errorText = (error) => friendlyError(error);
  function paragraph(parent, text) { const p = document.createElement('p'); p.textContent = text; parent.appendChild(p); }
  function textResult(id, text) { $(id).replaceChildren(); paragraph($(id), text); }
  async function action(button, run, output) {
    button.disabled = true;
    const ctx = context();
    try { await run(ctx); } catch (error) { if (current(ctx)) textResult(output, errorText(error)); }
    finally { button.disabled = false; }
  }
  for (const [provider, label] of Object.entries(cards)) {
    const verifier = provider === 'gemini';
    const card = document.createElement('form'); card.className = 'ti-provider-card'; card.id = `ti-config-${provider}`;
    card.innerHTML = `<h3>${label}</h3><label>API key<input id="ti-key-${provider}" class="field-input" type="password" autocomplete="off" maxlength="256" placeholder="Leave blank to keep the saved keys"></label><div class="button-row"><button type="button" class="ghost-button" data-show="${provider}">Show key</button><button type="button" class="ghost-button" data-add="${provider}">Add as extra key</button></div>
      <p class="soft-label">Up to 5 keys. When one key reaches its limit or is rejected, the next key is used. Uploads use key 1. A key typed here and saved with Save / update replaces all saved keys.</p><div id="ti-keys-${provider}" class="ti-keys"></div>
      <label><input id="ti-authorized-${provider}" type="checkbox"> Provider permission covers this business workflow</label><label>Permission or licence basis<input id="ti-basis-${provider}" class="field-input" maxlength="500" placeholder="Describe the licence or written provider permission"></label>
      ${verifier ? `<p class="soft-label">Checks the local AI's diagnoses, chat answers and threat/file verdicts against the same evidence and shows Agree / Partly / Disagree. Device names, users, IP and MAC addresses are masked before sending. It never runs or approves anything.</p><label>Model id<input id="ti-model-${provider}" class="field-input" maxlength="64" placeholder="gemini-3.8-flash"></label>
      <label><input id="ti-enabled-${provider}" type="checkbox"> Enable second-opinion checks</label>` : `<label><input id="ti-enabled-${provider}" type="checkbox"> Enable external hash lookups</label><label><input id="ti-submit-${provider}" type="checkbox"> Provider permission also covers public file submission</label>`}
      <div class="button-row"><label>Requests/minute per key<input id="ti-minute-${provider}" class="field-input" type="number" min="1" max="100"></label><label>Requests/day per key<input id="ti-day-${provider}" class="field-input" type="number" min="1" max="100000"></label></div>
      <div class="button-row"><button>Save / update</button><button type="button" data-test="${provider}" class="ghost-button">Test connection</button><button type="button" data-delete="${provider}" class="ghost-button">Delete all keys</button></div><p id="ti-status-${provider}" role="status">Loading configuration...</p>`;
    $('ti-settings').appendChild(card);
    card.onsubmit = (event) => { event.preventDefault(); action(card.querySelector('button:not([type="button"])'), async () => {
      const input = $(`ti-key-${provider}`);
      const payload = {business_authorized: $(`ti-authorized-${provider}`).checked, use_basis: $(`ti-basis-${provider}`).value,
        enabled: $(`ti-enabled-${provider}`).checked,
        per_minute: Number($(`ti-minute-${provider}`).value), per_day: Number($(`ti-day-${provider}`).value)};
      if (verifier) payload.model = $(`ti-model-${provider}`).value.trim(); else payload.upload_authorized = $(`ti-submit-${provider}`).checked;
      if (input.value.trim()) payload.api_key = input.value.trim();
      try { renderSettings(await api(`/${provider}/settings`, post(payload))); }
      finally { input.value = ''; input.type = 'password'; card.querySelector('[data-show]').textContent = 'Show key'; }
    }, `ti-status-${provider}`); };
    card.querySelector('[data-show]').onclick = (event) => { const input = $(`ti-key-${provider}`); input.type = input.type === 'password' ? 'text' : 'password'; event.target.textContent = input.type === 'password' ? 'Show key' : 'Hide key'; };
    card.querySelector('[data-add]').onclick = (event) => action(event.target, async () => {
      const input = $(`ti-key-${provider}`);
      if (!input.value.trim()) throw Error('Type the extra API key first.');
      try { renderSettings(await api(`/${provider}/settings`, post({add_api_key: input.value.trim()}))); }
      finally { input.value = ''; input.type = 'password'; card.querySelector('[data-show]').textContent = 'Show key'; }
    }, `ti-status-${provider}`);
    card.querySelector('[data-delete]').onclick = (event) => action(event.target, async () => { renderSettings(await api(`/${provider}/settings`, post({api_key: ''}))); }, `ti-status-${provider}`);
    card.querySelector('[data-test]').onclick = (event) => action(event.target, async () => {
      const job = await api(`/${provider}/test`, post({}));
      textResult(`ti-status-${provider}`, verifier ? 'Testing Gemini...' : 'Connection test queued. Hybrid Analysis environment discovery waits for the shared quota.');
      poll(job, () => true, async (value) => { if (['completed', 'restricted', 'failed'].includes(value.state)) { await refreshSettings(provider); if (value.result.detail) paragraph($(`ti-status-${provider}`), value.result.detail); } });
    }, `ti-status-${provider}`);
  }
  function renderSettings(data) {
    const p = data.provider; settings[p] = data;
    $(`ti-authorized-${p}`).checked = data.policy.business_authorized; $(`ti-enabled-${p}`).checked = data.policy.enabled;
    if ($(`ti-submit-${p}`)) $(`ti-submit-${p}`).checked = data.policy.upload_authorized;
    if ($(`ti-model-${p}`)) $(`ti-model-${p}`).value = data.policy.model || '';
    $(`ti-basis-${p}`).value = data.policy.use_basis;
    $(`ti-minute-${p}`).value = data.policy.per_minute; $(`ti-day-${p}`).value = data.policy.per_day;
    textResult(`ti-status-${p}`, `${data.configured ? `${(data.keys || []).length} key(s) configured` : 'No usable key'} · ${data.enabled ? 'Enabled' : 'Disabled'} · ${data.connection.state}. Storage: ${data.storage}. Requests: ${data.usage.minute}/${data.policy.per_minute} this minute; ${data.usage.day}/${data.policy.per_day} today. Last success: ${stamp(data.connection.last_success)}. ${data.credential_error || ''}`);
    renderKeys(p, data);
    paragraph($(`ti-status-${p}`), `Capabilities: ${data.capabilities.verified ? 'Account authentication checked' : 'Not verified'}. Private submission is not assumed. ${data.capabilities.phase === 'environments' ? 'Environment discovery pending.' : ''}`);
  }
  function renderKeys(p, data) {
    // Only slot numbers and usage come from the server: never key text.
    const box = $(`ti-keys-${p}`); box.replaceChildren();
    for (const item of data.keys || []) {
      const row = document.createElement('div'); row.className = 'button-row ti-key-row';
      const label = document.createElement('span');
      const waiting = item.wait_seconds > 0 ? `resting ${Math.ceil(item.wait_seconds / 60)} min` : 'ready';
      label.textContent = `Key ${item.slot}${item.primary ? ' (primary, used for uploads)' : ''} · ${waiting} · ${item.usage.minute}/${data.policy.per_minute} this minute, ${item.usage.day}/${data.policy.per_day} today`;
      const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'ghost-button'; remove.textContent = 'Remove';
      remove.onclick = () => {
        if (item.primary && !confirm('Remove key 1? The next key becomes the primary: pending approvals and in-flight submissions of key 1 are cancelled.')) return;
        action(remove, async () => renderSettings(await api(`/${p}/settings`, post({remove_key: item.slot}))), `ti-status-${p}`);
      };
      row.append(label, remove); box.appendChild(row);
    }
  }
  async function refreshSettings(provider) {
    if (provider) return renderSettings(await api(`/${provider}/settings`));
    await Promise.all(Object.keys(cards).map(async (p) => { try { await refreshSettings(p); } catch (e) { textResult(`ti-status-${p}`, errorText(e)); } }));
  }
  async function poll(initial, valid, render) {
    let job = initial;
    for (let attempt = 0; attempt < 180 && valid(); attempt++) {
      await render(job);
      if (['completed', 'restricted', 'failed'].includes(job.state) || job.provider_enabled === false) return;
      await new Promise((resolve) => setTimeout(resolve, 2000));
      if (!valid()) return;
      try { job = await api(`/jobs/${encodeURIComponent(job.job_id)}`); }
      catch (error) { if (valid()) await render({...job, state: 'failed', result: {detail: errorText(error)}}); return; }
    }
  }
  function renderReport(provider, job, ctx) {
    if (!current(ctx)) return;
    const box = $(`ti-result-${provider}`), result = job.result || job;
    box.replaceChildren(); paragraph(box, providers[provider]);
    paragraph(box, `${job.state || result.status || 'Report'} · ${result.classification || 'No verdict available'}${job.provider_enabled === false ? ' · Provider disabled' : ''}`);
    paragraph(box, result.detail || result.note || 'Queued results may be delayed by the provider request budget.');
    if (result.fetched_at) paragraph(box, `External provider evidence · ${stamp(result.fetched_at)}${result.cached ? ' · cached' : ''}`);
    if (result.stats) paragraph(box, Object.entries(result.stats).map(([k,v]) => `${k}: ${v}`).join(' · '));
    if (result.reputation != null) paragraph(box, `Reputation: ${result.reputation}. Last analysis: ${stamp(result.analysed_at)}`);
    if (result.threat_classification) paragraph(box, `Classification: ${JSON.stringify(result.threat_classification)}`);
    for (const row of result.detections || []) paragraph(box, `${row.engine}: ${row.category} — ${row.result}`);
    for (const row of result.reports || []) {
      paragraph(box, `${row.environment_description || 'Sandbox'} · ${row.verdict || 'Unknown verdict'} · score ${row.threat_score ?? 'unavailable'}`);
      if (row.job_id) { const button = document.createElement('button'); button.className = 'ghost-button'; button.textContent = 'Retrieve existing sandbox behaviour'; box.appendChild(button);
        button.onclick = () => action(button, async () => { const next = await api(`/hybrid_analysis/reports/${encodeURIComponent(row.job_id)}`, post({sha256: ctx.hash})); poll(next, () => current(ctx), (value) => renderReport(provider, value, ctx)); }, `ti-result-${provider}`); }
    }
    if (result.behaviour) { const pre = document.createElement('pre'); pre.textContent = JSON.stringify(result.behaviour, null, 2); box.appendChild(pre); }
  }
  function reset() {
    generation++; currentHash = ''; sample = analysis = null;
    $('ti-results').replaceChildren(); $('ti-explanation').replaceChildren(); $('ti-sample').replaceChildren();
    $('ti-history').replaceChildren(); $('ti-investigation').replaceChildren(); $('ti-findings').replaceChildren();
    $('ti-approval').hidden = $('ti-analysis').hidden = true;
    textResult('ti-context', `Selected device: ${selected()}. Hash searches alone do not establish that a file exists on this endpoint.`);
  }
  async function search() {
    const sha = $('ti-hash').value.trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(sha)) throw Error('Enter a valid SHA-256 hash.');
    reset(); currentHash = sha; const ctx = context();
    for (const p of Object.keys(providers)) { const box = document.createElement('article'); box.className = 'ti-provider-card'; box.id = `ti-result-${p}`; $('ti-results').appendChild(box); paragraph(box, `${providers[p]}: loading...`); }
    await Promise.all(Object.keys(providers).map(async (p) => {
      try { const job = await api(`/${p}/files/${sha}`); poll(job, () => current(ctx), (value) => renderReport(p, value, ctx)); }
      catch (error) { if (current(ctx)) textResult(`ti-result-${p}`, errorText(error)); }
    }));
  }
  $('ti-search').onsubmit = (event) => { event.preventDefault(); action(event.submitter, search, 'ti-context'); };
  $('ti-explain').onclick = (event) => action(event.target, async (ctx) => {
    if (!ctx.hash) throw Error('Look up a hash first.');
    textResult('ti-explanation', 'Preparing an evidence-based explanation...');
    const result = await api(`/explain/${ctx.hash}`, post({}));
    if (!current(ctx)) return;
    textResult('ti-explanation', result.summary); for (const step of result.next_steps || []) paragraph($('ti-explanation'), step);
    if (result.local_verdict) paragraph($('ti-explanation'), `Local AI verdict: ${result.local_verdict}`);
    const agree = result.agreement;
    if (agree) {
      const line = agree.state === 'match' ? `Cross-check: the local AI verdict matches VirusTotal / Hybrid Analysis (${agree.providers.join(', ')}).`
        : agree.state === 'mismatch' ? `MISMATCH: the local AI says "${agree.local}" but the providers report ${agree.providers.join(', ')}. Review this file by hand.`
        : 'Cross-check: not enough provider evidence to confirm the local AI verdict.';
      const p = document.createElement('p'); p.className = `ti-agreement ${agree.state}`; p.textContent = line; $('ti-explanation').appendChild(p);
    }
    $('ti-explanation').insertAdjacentHTML('beforeend', secondOpinionHtml(result.second_opinion));
    paragraph($('ti-explanation'), `Sources: ${(result.evidence_refs || []).join(', ') || 'Unavailable'}. Advice only; no endpoint action performed.`);
  }, 'ti-explanation');
  function renderSample(result, provider, ctx) {
    if (!current(ctx)) return;
    sample = result.upload_token ? {token: result.upload_token, provider, ctx, sha: result.sha256, size: result.size} : null;
    analysis = result.analysis_token ? {token: result.analysis_token, provider, ctx} : analysis;
    // A file the provider already knows comes back as its report (no upload offered): show the verdict too.
    const parts = [providers[provider], `SHA-256 ${result.sha256 || ''}`, result.size ? `${result.size} bytes` : '', result.status || 'unknown',
      result.classification ? `classification: ${result.classification}` : '', result.detail || result.note || ''];
    textResult('ti-sample', parts.filter(Boolean).join(' · '));
    $('ti-approval').hidden = !sample; $('ti-analysis').hidden = !analysis;
    $('ti-environment-label').hidden = provider !== 'hybrid_analysis';
    $('ti-environment').replaceChildren();
    for (const id of settings[provider]?.capabilities?.environments || []) { const option = document.createElement('option'); option.value = String(id); option.textContent = `Environment ${id}`; $('ti-environment').appendChild(option); }
  }
  $('ti-file-form').onsubmit = (event) => { event.preventDefault(); action(event.submitter, async (ctx) => {
    const file = $('ti-file').files[0], provider = $('ti-provider').value;
    if (!file || !file.size || file.size > 32*1024*1024) throw Error('Select a non-empty file no larger than 32 MiB.');
    const form = new FormData(); form.append('file', file);
    try { renderSample(await api(`/${provider}/check-file`, {method: 'POST', body: form}), provider, ctx); }
    finally { $('ti-file').value = ''; }
  }, 'ti-sample'); };
  $('ti-transfer').onsubmit = (event) => { event.preventDefault(); action(event.submitter, async (ctx) => {
    if (!ctx.hash || !threatData?.scan?.scan_id) throw Error('Select a current scan finding and enter its SHA-256 first.');
    const provider = $('ti-provider').value;
    if (!confirm(`Transfer this specific file from ${ctx.device} to Sentinel? This does not submit it to ${providers[provider]}.`)) return;
    const response = await readJson(await fetch(`/api/security/${encodeURIComponent(ctx.device)}/sample-transfer`, post({provider, sha256: ctx.hash, size: Number($('ti-size').value), finding_id: $('ti-finding').value, scan_id: threatData.scan.scan_id, approved_transfer: true})));
    if (response.ok) renderSample(response.data, provider, ctx); else if (current(ctx)) textResult('ti-sample', response.summary);
  }, 'ti-sample'); };
  $('ti-upload').onclick = (event) => action(event.target, async () => {
    const item = sample; if (!item || !current(item.ctx)) throw Error('Sample context changed; select it again.');
    if (!confirm(`Submit ${item.sha} (${item.size} bytes) to ${providers[item.provider]}? Public submission may share this file with security partners.`)) return;
    const result = await api(`/${item.provider}/uploads/${encodeURIComponent(item.token)}`, post({approved: true, environment_id: Number($('ti-environment').value)}));
    renderSample(result, item.provider, item.ctx);
  }, 'ti-sample');
  $('ti-cancel').onclick = (event) => action(event.target, async () => { const item = sample; if (!item) return; await api(`/${item.provider}/uploads/${encodeURIComponent(item.token)}`, {method: 'DELETE'}); if (current(item.ctx)) { sample = null; $('ti-approval').hidden = true; textResult('ti-sample', 'Sample discarded.'); } }, 'ti-sample');
  $('ti-analysis').onclick = (event) => action(event.target, async () => { const item = analysis; if (item && current(item.ctx)) renderSample(await api(`/${item.provider}/analyses/${encodeURIComponent(item.token)}`), item.provider, item.ctx); }, 'ti-sample');
  async function showInvestigation(initial) {
    const ctx = context(); if (initial.device !== ctx.device && !(ctx.device === 'local')) return;
    const sequence = requestIds.investigation = (requestIds.investigation || 0) + 1;
    let job = initial;
    for (let i=0; i<150 && current(ctx) && requestIds.investigation === sequence; i++) {
      textResult('ti-investigation', `${job.state}: ${job.summary || 'Collecting permitted read-only evidence...'} ${(job.unfinished || []).length ? 'Unfinished: '+job.unfinished.join(', ') : ''}`);
      for (const step of job.evidence || []) paragraph($('ti-investigation'), `${step.tool}: ${step.summary || 'Unavailable'}`);
      if (['completed', 'partial', 'failed'].includes(job.state)) { await loadHistory(); return; }
      await new Promise((resolve) => setTimeout(resolve, 2000));
      if (!current(ctx)) return;
      job = await readJson(await fetch(`/api/security/investigations/${encodeURIComponent(job.id)}`));
    }
  }
  window.showSecurityInvestigation = (job) => showInvestigation(job).catch((e) => textResult('ti-investigation', errorText(e)));
  $('ti-investigate').onclick = (event) => action(event.target, async (ctx) => { const job = await readJson(await fetch('/api/security/investigations', post({device_id: ctx.device, question: 'Collect security and permitted executable-hash evidence'}))); if (current(ctx)) await showInvestigation(job); }, 'ti-investigation');
  async function loadHistory() {
    const ctx = context(); const data = await api(`/history/${encodeURIComponent(ctx.device)}`); if (!current(ctx)) return;
    $('ti-history').replaceChildren();
    for (const row of data.files) { const button = document.createElement('button'); button.className = 'ghost-button ti-history-item'; button.textContent = `${row.path || 'Observed executable'} · ${row.sha256} · ${stamp(row.observed_at)}`; button.onclick = () => { $('ti-hash').value = row.sha256; if(row.size) $('ti-size').value = row.size; search().catch((e) => textResult('ti-context', errorText(e))); }; $('ti-history').appendChild(button); }
    for (const row of data.investigations) { const button = document.createElement('button'); button.className = 'ghost-button'; button.textContent = `${row.state} — ${row.question || 'Security investigation'}`; button.onclick = async () => { const job = await readJson(await fetch(`/api/security/investigations/${encodeURIComponent(row.id)}`)); if(current(ctx)) window.showSecurityInvestigation(job); }; $('ti-history').appendChild(button); }
    if (!data.files.length && !data.investigations.length) paragraph($('ti-history'), 'No collected file hashes or investigations for this device yet.');
  }
  $('ti-findings-form').onsubmit = (event) => { event.preventDefault(); action(event.submitter, async (ctx) => {
    const result = await readJson(await fetch(`/api/security/${encodeURIComponent(ctx.device)}/findings?q=${encodeURIComponent($('ti-findings-query').value)}`)); if (!current(ctx)) return;
    textResult('ti-findings', `${result.total} findings · ${result.stale ? 'Stale coverage' : 'Recent collection'} · ${result.device_status}`);
    paragraph($('ti-findings'), `Coverage: ${JSON.stringify(result.coverage)}`);
    for (const row of result.items) paragraph($('ti-findings'), `${row.severity}: ${row.title} — ${row.explanation || ''} · Endpoint evidence · ${row.source}`);
  }, 'ti-findings'); };
  $('ti-refresh').onclick = (event) => action(event.target, async () => { await refreshSettings(); await loadHistory(); }, 'ti-context');
  $('threat-device').addEventListener('change', () => { reset(); loadHistory().catch((e) => textResult('ti-context', errorText(e))); });
  $('threat-findings').addEventListener('click', (event) => { const button = event.target.closest('[data-vt-hash]'); if (button) { $('ti-hash').value = button.dataset.vtHash; panel.scrollIntoView({behavior:'smooth'}); search().catch((e)=>textResult('ti-context',errorText(e))); } });
  refreshSettings(); reset();
})();

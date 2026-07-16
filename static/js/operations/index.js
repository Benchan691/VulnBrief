const pageConfig = JSON.parse(document.getElementById('page-config').textContent);
const fields = [
  'catch_up.limit','catch_up.batch_size','catch_up.max_runs_per_provider','catch_up.interval_hours',
  'catch_up.periodic_enabled','review.providers'
];
let currentConfig = null;

function endpoint(template, placeholder, value) {
  return template.replace(placeholder, encodeURIComponent(value));
}

function get(obj, path) {
  return path.split('.').reduce((node, part) => node && node[part], obj);
}
function set(obj, path, value) {
  const parts = path.split('.');
  const last = parts.pop();
  const target = parts.reduce((node, part) => node[part] ||= {}, obj);
  target[last] = value;
}
function formConfig() {
  const data = {};
  for (const name of fields) {
    const input = document.querySelector(`[name="${name}"]`);
    if (!input) continue;
    set(data, name, input.type === 'checkbox' ? input.checked : input.value);
  }
  return data;
}
function fillForm(config) {
  currentConfig = config;
  for (const name of fields) {
    const input = document.querySelector(`[name="${name}"]`);
    if (!input) continue;
    const value = get(config, name);
    if (input.type === 'checkbox') input.checked = Boolean(value);
    else input.value = value ?? '';
  }
  updateSchedule();
}
function updateSchedule() {
  const box = document.getElementById('schedule-status');
  const startBtn = document.getElementById('start-schedule-btn');
  const stopBtn = document.getElementById('stop-schedule-btn');
  const catchUp = currentConfig?.catch_up;
  const enabled = Boolean(catchUp?.periodic_enabled);
  if (startBtn) startBtn.classList.toggle('d-none', enabled);
  if (stopBtn) stopBtn.classList.toggle('d-none', !enabled);
  if (!enabled) {
    box.textContent = 'Periodic catch-up is off';
    return;
  }
  const next = Date.parse(catchUp.next_run_at || '');
  const minutes = Number.isNaN(next) ? 0 : Math.max(0, Math.ceil((next - Date.now()) / 60000));
  if (minutes === 0) {
    box.textContent = 'Next catch-up scrape due soon (within ~1 minute)';
    return;
  }
  box.textContent = `Next catch-up scrape in ${minutes} minute${minutes === 1 ? '' : 's'}`;
}
function show(text) {
  const box = document.getElementById('message');
  box.textContent = text;
  box.style.display = text ? '' : 'none';
}
async function loadConfig() {
  const response = await fetch(pageConfig.configUrl);
  fillForm(await response.json());
}
async function loadRuns() {
  updateSchedule();
  const response = await fetch(pageConfig.runsUrl);
  const rows = (await response.json()).data || [];
  const body = document.getElementById('runs-body');
  body.replaceChildren();
  for (const run of rows) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${run.operation}</td><td>${run.status}</td><td>${run.started_at || ''}</td><td><code>${(run.command || []).join(' ')}</code></td><td class="text-end"></td>`;
    const actions = tr.lastElementChild;
    const logs = document.createElement('button');
    logs.className = 'btn btn-outline-secondary btn-sm me-1';
    logs.innerHTML = '<i class="bi bi-file-text"></i>';
    logs.onclick = () => loadLogs(run.id);
    actions.append(logs);
    if (run.status === 'running') {
      const stop = document.createElement('button');
      stop.className = 'btn btn-outline-danger btn-sm';
      stop.innerHTML = '<i class="bi bi-stop-fill"></i>';
      stop.onclick = async () => {
        await fetch(endpoint(pageConfig.stopUrlTemplate, '__RUN_ID__', run.id), {method:'POST'});
        await loadRuns();
      };
      actions.append(stop);
    }
    body.append(tr);
  }
}
async function loadLogs(id) {
  const response = await fetch(endpoint(pageConfig.logsUrlTemplate, '__RUN_ID__', id));
  document.getElementById('log-box').textContent = (await response.json()).log || '';
}
document.getElementById('config-form').onsubmit = async event => {
  event.preventDefault();
  const response = await fetch(pageConfig.configUrl, {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(formConfig())});
  const body = await response.json();
  if (!response.ok) return show(body.error || 'Save failed');
  fillForm(body); show('Saved');
};
document.getElementById('reset-config-btn').onclick = async () => {
  if (!confirm('Reset catch-up and review settings to defaults?')) return;
  const response = await fetch(pageConfig.configUrl, {method:'DELETE'});
  const body = await response.json();
  if (!response.ok) return show(body.error || 'Reset failed');
  fillForm(body);
  show('Reset to defaults');
};
document.querySelectorAll('.op-run').forEach(button => {
  button.onclick = async () => {
    const response = await fetch(endpoint(pageConfig.runUrlTemplate, '__OPERATION__', button.dataset.op), {method:'POST'});
    const body = await response.json();
    show(response.ok ? 'Started' : (body.error || 'Start failed'));
    await loadRuns();
  };
});
document.getElementById('start-schedule-btn').onclick = async () => {
  const response = await fetch(pageConfig.startScheduleUrl, {method:'POST'});
  const body = await response.json();
  if (!response.ok) return show(body.error || 'Unable to start schedule');
  fillForm(body);
  show('Catch-up schedule started');
};
document.getElementById('stop-schedule-btn').onclick = async () => {
  const response = await fetch(pageConfig.stopScheduleUrl, {method:'POST'});
  const body = await response.json();
  if (!response.ok) return show(body.error || 'Unable to stop schedule');
  fillForm(body);
  show('Catch-up schedule stopped');
};
document.getElementById('refresh-btn').onclick = async () => { await loadConfig(); await loadRuns(); };
document.getElementById('clear-history-btn').onclick = async () => {
  if (!confirm('Clear finished operation history?')) return;
  const response = await fetch(pageConfig.runsUrl, {method:'DELETE'});
  const body = await response.json();
  show(response.ok ? `Cleared ${body.deleted || 0} run${body.deleted === 1 ? '' : 's'}` : (body.error || 'Clear failed'));
  document.getElementById('log-box').textContent = '';
  await loadRuns();
};
loadConfig(); loadRuns(); setInterval(loadRuns, 5000);

/* Zenith UI logic */
'use strict';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  status: null,
  logWhich: 'app',
  busy: false,
};

/* ---------------- helpers ---------------- */
async function api(path, opts) {
  const res = await fetch(path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts));
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = { raw: text }; }
  if (!res.ok) throw new Error((data && (data.error || data.raw)) || ('HTTP ' + res.status));
  return data;
}

function bytes(n) {
  if (!n && n !== 0) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(n < 10 ? 2 : 1)) + ' ' + u[i];
}

function delayClass(d) {
  if (d === null || d === undefined || d <= 0) return 'none';
  if (d < 800) return 'good';
  if (d < 2000) return 'mid';
  return 'bad';
}

function delayText(d) {
  if (d === null || d === undefined || d <= 0) return '—';
  return d + ' ms';
}

let toastTimer = null;
function toast(msg, kind) {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast show' + (kind ? ' ' + kind : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = 'toast'; }, 2600);
}

/* ---------------- tabs ---------------- */
$$('.nav-item').forEach((btn) => {
  btn.addEventListener('click', () => {
    $$('.nav-item').forEach((b) => b.classList.toggle('active', b === btn));
    const tab = btn.dataset.tab;
    $$('.tab').forEach((t) => t.classList.toggle('hidden', t.id !== 'tab-' + tab));
    if (tab === 'logs') loadLogs();
  });
});

$$('.seg').forEach((btn) => {
  btn.addEventListener('click', () => {
    $$('.seg').forEach((b) => b.classList.toggle('active', b === btn));
    state.logWhich = btn.dataset.log;
    loadLogs();
  });
});

/* ---------------- render ---------------- */
function render() {
  const s = state.status;
  if (!s) return;

  $('#version').textContent = 'v' + s.version;

  const dot = $('#core-dot');
  dot.className = 'dot ' + (s.coreUp ? 'on' : 'off');
  $('#core-text').textContent = s.coreUp
    ? '内核运行中 · ' + Math.floor(s.coreUptime / 60) + ' 分钟'
    : '内核未运行';

  const auto = s.settings.autoOptimize;
  const modePill = $('#mode-pill');
  modePill.textContent = auto ? '自动优选' : '手动控制';
  modePill.className = 'pill' + (auto ? '' : ' ghost');

  const sp = s.systemProxy || {};
  const proxyPill = $('#proxy-pill');
  const on = sp.enabled && (sp.server || '').indexOf(String(s.ports.mixed)) >= 0;
  proxyPill.textContent = on ? ('系统代理 已开启 · ' + sp.server) : '系统代理 未接管';
  proxyPill.className = 'pill ' + (on ? 'good' : 'ghost');

  $('#current-node').textContent = s.current || '未选择节点';
  $('#hero-meta').textContent =
    '共 ' + s.nodeCount + ' 个节点' +
    (s.autoPick && s.autoPick !== s.current ? ' · 自动测速最优：' + s.autoPick : '') +
    (s.lastOptimize ? ' · 上次优选 ' + s.lastOptimize.replace('T', ' ') : '');

  const t = s.traffic || {};
  $('#up').textContent = bytes(t.up);
  $('#down').textContent = bytes(t.down);
  $('#conns').textContent = t.conns === undefined ? '—' : t.conns;

  // progress
  const pw = $('#progress-wrap');
  if (s.optimizing) {
    pw.classList.remove('hidden');
    $('#progress-text').textContent = (s.progress && s.progress.text) || '处理中…';
    const fill = $('#progress-fill');
    if (s.progress && s.progress.total > 0) {
      fill.classList.remove('slow');
      fill.style.width = Math.round(100 * s.progress.done / s.progress.total) + '%';
    } else {
      fill.classList.add('slow');
    }
  } else if (s.error) {
    pw.classList.remove('hidden');
    $('#progress-text').textContent = '出错：' + s.error;
    $('#progress-fill').classList.remove('slow');
    $('#progress-fill').style.width = '100%';
  } else {
    pw.classList.add('hidden');
  }

  $('#btn-optimize').disabled = !!s.optimizing;
  $('#btn-optimize').textContent = s.optimizing ? '优选进行中…' : '立即优选';

  renderNodes(s);
  renderSettings(s);
  $('#p-mixed').textContent = '127.0.0.1:' + s.ports.mixed;
  $('#p-api').textContent = '127.0.0.1:' + s.ports.api;
  $('#p-ui').textContent = '127.0.0.1:' + s.ports.ui;
}

function renderNodes(s) {
  const q = ($('#search').value || '').trim().toLowerCase();
  const list = $('#node-list');
  const nodes = (s.nodes || []).filter((n) => !q || (n.name || '').toLowerCase().includes(q) || (n.server || '').includes(q));

  if (!nodes.length) {
    list.innerHTML = '<div class="card"><div class="hint">还没有节点。点右上角「立即优选」开始扫描，或到「订阅」页刷新订阅。</div></div>';
    return;
  }

  list.innerHTML = nodes.map((n) => {
    const cls = delayClass(n.delay);
    const pct = n.delay && n.delay > 0 ? Math.max(6, Math.min(100, 100 - Math.min(n.delay, 3000) / 30)) : 0;
    const color = cls === 'good' ? 'var(--ok)' : cls === 'mid' ? 'var(--warn)' : 'var(--bad)';
    return `
      <div class="node ${n.active ? 'active' : ''}" data-name="${encodeURIComponent(n.name)}">
        <div class="node-name">${escapeHtml(n.name)}</div>
        <div class="node-server">${escapeHtml(n.server || '')}</div>
        <div class="bar"><i style="width:${pct}%;background:${color}"></i></div>
        <div class="delay ${cls}">${delayText(n.delay)}</div>
      </div>`;
  }).join('');

  list.querySelectorAll('.node').forEach((el) => {
    el.addEventListener('click', () => switchNode(decodeURIComponent(el.dataset.name)));
  });
}

function renderSettings(s) {
  const st = s.settings;
  $('#sw-auto').checked = !!st.autoOptimize;
  $('#sw-proxy').checked = !!(s.systemProxy && s.systemProxy.enabled);
  $('#sw-subauto').checked = !!st.subscriptionAutoUpdate;
  if (document.activeElement && document.activeElement.tagName !== 'INPUT') {
    $('#in-opt').value = st.optimizeIntervalMin;
    $('#in-sub').value = st.subscriptionIntervalHours;
    $('#in-keep').value = st.keepNodes;
  }
}

function escapeHtml(t) {
  return String(t == null ? '' : t)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ---------------- actions ---------------- */
async function switchNode(name) {
  if (state.busy) return;
  state.busy = true;
  try {
    const r = await api('/api/switch', { method: 'POST', body: JSON.stringify({ name }) });
    if (r.ok) { toast('已切换到 ' + name, 'ok'); await refresh(); }
    else toast('切换失败', 'err');
  } catch (e) { toast('切换失败：' + e.message, 'err'); }
  state.busy = false;
}

async function refresh() {
  try {
    state.status = await api('/api/status');
    render();
  } catch (e) {
    $('#core-text').textContent = '界面与后端失联';
    $('#core-dot').className = 'dot off';
  }
}

async function loadLogs() {
  try {
    const r = await api('/api/logs?which=' + state.logWhich + '&lines=300');
    const el = $('#logs');
    el.textContent = r.text || '（暂无日志）';
    el.scrollTop = el.scrollHeight;
  } catch (e) { $('#logs').textContent = '读取失败：' + e.message; }
}

async function loadSubscription() {
  try {
    const r = await api('/api/subscription');
    $('#sub-time').textContent = r.lastSubscription ? r.lastSubscription.replace('T', ' ') : '从未';
    $('#sub-base').textContent = r.baseNodes;
    $('#sub-opt').textContent = r.optimizedNodes;
    $('#sub-preview').innerHTML = (r.preview || []).map((n) =>
      `<div class="mini"><span>${escapeHtml(n.name)}</span><b>${escapeHtml(n.server || '')}:${n.port || ''}</b></div>`
    ).join('') || '<div class="hint">订阅还没有解析出节点。</div>';
  } catch (e) { /* ignore */ }
}

/* ---------------- bindings ---------------- */
$('#btn-optimize').addEventListener('click', async () => {
  try {
    await api('/api/optimize', { method: 'POST' });
    toast('已开始优选，预计 3～10 分钟', 'ok');
    refresh();
  } catch (e) { toast('启动失败：' + e.message, 'err'); }
});

$('#btn-test-all').addEventListener('click', async () => {
  toast('测速中…（节点较多时会慢一些）');
  const names = (state.status.nodes || []).map((n) => n.name);
  for (const nm of names) {
    try {
      const r = await api('/api/test-delay', { method: 'POST', body: JSON.stringify({ name: nm }) });
      const n = state.status.nodes.find((x) => x.name === nm);
      if (n) n.delay = r.delay;
      renderNodes(state.status);
    } catch (e) { /* keep going */ }
  }
  toast('测速完成', 'ok');
});

$('#btn-direct').addEventListener('click', async () => {
  try {
    // DIRECT is mihomo's built-in policy name
    await api('/api/switch', { method: 'POST', body: JSON.stringify({ name: 'DIRECT' }) });
    toast('已切到直连（不走代理）', 'ok');
    refresh();
  } catch (e) { toast('切换失败：' + e.message, 'err'); }
});

$('#btn-sub-refresh').addEventListener('click', async () => {
  toast('正在刷新订阅…');
  try {
    const r = await api('/api/subscription/refresh', { method: 'POST' });
    toast('订阅已更新，共 ' + r.nodes + ' 个节点', 'ok');
    loadSubscription();
  } catch (e) { toast('刷新失败：' + e.message, 'err'); }
});

$('#btn-log-refresh').addEventListener('click', loadLogs);

$('#sw-auto').addEventListener('change', async (e) => {
  const auto = e.target.checked;
  try {
    await api('/api/mode', { method: 'POST', body: JSON.stringify({ auto }) });
    toast(auto ? '已开启自动优选' : '已切换为手动控制，Zenith 不再自动改节点', 'ok');
    refresh();
  } catch (err) { toast('设置失败：' + err.message, 'err'); }
});

$('#sw-proxy').addEventListener('change', async (e) => {
  try {
    await api('/api/system-proxy', { method: 'POST', body: JSON.stringify({ enabled: e.target.checked }) });
    toast(e.target.checked ? '系统代理已开启' : '系统代理已关闭', 'ok');
    refresh();
  } catch (err) { toast('设置失败：' + err.message, 'err'); }
});

$('#sw-subauto').addEventListener('change', async (e) => {
  try {
    await api('/api/settings', { method: 'POST', body: JSON.stringify({ subscriptionAutoUpdate: e.target.checked }) });
    toast('已保存', 'ok');
  } catch (err) { toast('设置失败：' + err.message, 'err'); }
});

$('#btn-save').addEventListener('click', async () => {
  const patch = {
    optimizeIntervalMin: parseInt($('#in-opt').value, 10) || 30,
    subscriptionIntervalHours: parseInt($('#in-sub').value, 10) || 6,
    keepNodes: parseInt($('#in-keep').value, 10) || 16,
  };
  try {
    await api('/api/settings', { method: 'POST', body: JSON.stringify(patch) });
    toast('设置已保存', 'ok');
    refresh();
  } catch (e) { toast('保存失败：' + e.message, 'err'); }
});

$('#btn-quit').addEventListener('click', async () => {
  if (!confirm('退出 Zenith？\n\n会关闭代理内核并撤销系统代理。')) return;
  try { await api('/api/shutdown', { method: 'POST' }); } catch (e) { /* expected */ }
  document.body.innerHTML = '<div style="display:grid;place-items:center;height:100vh;color:#8d99ae;font-size:15px">Zenith 已退出，可以关闭这个窗口了。</div>';
});

$('#search').addEventListener('input', () => { if (state.status) renderNodes(state.status); });

/* ---------------- boot ---------------- */
refresh();
loadSubscription();
setInterval(refresh, 3000);
setInterval(() => { if (!$('#tab-logs').classList.contains('hidden')) loadLogs(); }, 5000);

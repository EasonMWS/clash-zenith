/* ==========================================================================
   Zenith — 界面逻辑（原生 JS，无任何依赖）
   所有服务端字符串在拼进 HTML 之前都必须经过 esc()。
   ========================================================================== */
'use strict';

const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.prototype.slice.call((r || document).querySelectorAll(s));

const LS_TAB = 'zenith.tab';
const TAB_TITLE = { overview: '概览', nodes: '节点', subs: '订阅', advanced: '高级', settings: '设置' };
const MODE_TEXT = { rule: '规则模式', global: '全局模式', direct: '直连模式' };
const DELAY_MAX = 3000;          // 延迟条满格对应的毫秒数
const TEST_CONCURRENCY = 4;      // 逐个测速时的并发数
const NUM_FIELDS = [['#in-optint', 'optimizeIntervalMin'], ['#in-subint', 'subscriptionIntervalHours'],
  ['#in-keep', 'keepNodes'], ['#in-rounds', 'probeRounds'], ['#in-workers', 'probeWorkers']];

const S = {
  tab: 'overview', status: null, online: true, subs: null, settings: null, delays: {}, testing: {},
  testBusy: false, logWhich: 'app', logAuto: false, confirmDel: '', loaded: {}
};

/* --------------------------------------------------------------- 基础工具 */

function esc(v) {
  return String(v === null || v === undefined ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function bytes(n) {
  n = Number(n) || 0;
  if (n <= 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? Math.round(n) : n.toFixed(n < 10 ? 2 : 1)) + ' ' + u[i];
}

function delayClass(d) {
  d = Number(d) || 0;
  if (d <= 0) return 'none';
  return d < 800 ? 'good' : d < 2000 ? 'mid' : 'bad';
}

function delayText(d) { d = Number(d) || 0; return d > 0 ? d + ' ms' : '—'; }

function delayPct(d) {
  d = Number(d) || 0;
  return d <= 0 ? 0 : Math.max(3, Math.min(100, (Math.min(d, DELAY_MAX) / DELAY_MAX) * 100));
}

function uptimeText(sec) {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  if (sec < 60) return sec + ' 秒';
  const m = Math.floor(sec / 60);
  return m < 60 ? m + ' 分钟' : Math.floor(m / 60) + ' 小时 ' + (m % 60) + ' 分';
}

function prettyTime(v) {
  if (!v) return '从未';
  const t = new Date(v);
  if (isNaN(t.getTime())) return String(v);
  const p = (x) => String(x).padStart(2, '0');
  return t.getFullYear() + '-' + p(t.getMonth() + 1) + '-' + p(t.getDate()) +
    ' ' + p(t.getHours()) + ':' + p(t.getMinutes());
}

function logTo(box, text) {
  const bottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 24;
  box.textContent = text;
  if (bottom) box.scrollTop = box.scrollHeight;
}

function patchOf(key, val) { const p = {}; p[key] = val; return p; }

/* --------------------------------------------------------------- 网络请求 */

async function api(path, body) {
  try {
    // 只在带请求体时才加 Content-Type，避免 GET 触发无谓的预检
    const opt = { method: body === undefined ? 'GET' : 'POST' };
    if (body !== undefined) {
      opt.headers = { 'Content-Type': 'application/json' };
      opt.body = JSON.stringify(body);
    }
    const res = await fetch(path, opt);
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { ok: false, error: '返回内容无法解析' }; }
    if (!data || typeof data !== 'object') data = { ok: false, error: '空响应' };
    if (!res.ok && data.ok !== true) return { ok: false, error: data.error || ('请求失败 HTTP ' + res.status) };
    return data;
  } catch (e) {
    return { ok: false, error: '无法连接本地服务', offline: true };  // 网络异常不外抛，交给调用方提示
  }
}

function toast(msg, kind) {
  const stack = $('#toast-stack');
  if (!stack) return;
  const el = document.createElement('div');
  el.className = 'toast ' + (kind || 'info');
  el.textContent = String(msg);
  stack.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => { if (el.parentNode) el.parentNode.removeChild(el); }, 240);
  }, kind === 'err' ? 4200 : 2600);
}

/* 请求期间禁用按钮，避免重复点击 */
async function guard(btn, fn) {
  if (!btn) return fn();
  if (btn.disabled) return;
  btn.disabled = true;
  try { return await fn(); } finally { if (btn.isConnected) btn.disabled = false; }
}

/* ------------------------------------------------------------ 侧栏与分页 */

function setTab(tab) {
  if (!TAB_TITLE[tab]) tab = 'overview';
  S.tab = tab;
  $$('#nav .nav-item').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  $$('.tab').forEach((sec) => { sec.classList.toggle('hidden', sec.id !== 'tab-' + tab); });
  try { localStorage.setItem(LS_TAB, tab); } catch (e) { /* 忽略 */ }
  if ($('.main')) $('.main').scrollTop = 0;
  S.logAuto = tab === 'settings';

  if (tab === 'subs' && !S.loaded.subs) { S.loaded.subs = true; loadSubs(); }
  if (tab === 'advanced' && !S.loaded.advanced) { S.loaded.advanced = true; loadRules(); }
  if (tab === 'nodes') renderNodes();
  if (tab === 'settings') {
    if (!S.loaded.settings) { S.loaded.settings = true; loadSettings(); loadAbout(); }
    loadLogs();
  }
}

/* ------------------------------------------------------------------- 概览 */

function renderOverview(st) {
  const mode = st.mode || 'rule';
  $$('#seg-mode .seg').forEach((b) => b.classList.toggle('active', b.dataset.mode === mode));
  $('#mode-badge').textContent = MODE_TEXT[mode] || mode;

  const sp = st.systemProxy || {};
  const proxy = $('#proxy-badge');
  if (sp.enabled) {
    proxy.textContent = '系统代理已开启 · ' + (sp.server || '');
    proxy.className = 'badge ok';
  } else {
    proxy.textContent = sp.blocked ? '系统代理未接管' : '系统代理已关闭';
    proxy.className = sp.blocked ? 'badge warn' : 'badge ghost';
  }

  const opt = $('#opt-badge');
  opt.textContent = st.isOptimized ? '已优选 ' + (st.nodeCount || 0) + ' 个节点' : '尚未优选（当前用订阅全部节点）';
  opt.className = st.isOptimized ? 'badge' : 'badge ghost';

  $('#hero-node').textContent = st.current || '未选择节点';
  const meta = ['共 ' + (st.nodeCount || 0) + ' 个节点'];
  if (st.autoPick && st.autoPick !== st.current) meta.push('自动测速最优：' + st.autoPick);
  if (st.lastOptimize) meta.push('上次优选 ' + prettyTime(st.lastOptimize));
  $('#hero-meta').textContent = meta.join(' · ');

  const tr = st.traffic || {};
  $('#st-down').textContent = bytes(tr.downloadTotal);
  $('#st-up').textContent = bytes(tr.uploadTotal);
  $('#st-conns').textContent = String(tr.count || 0);

  const sw = $('#sw-auto');
  if (document.activeElement !== sw) sw.checked = !!(st.settings && st.settings.autoOptimize);
  renderProgress(st.optimizing, st.progress, st.error);
}

function renderProgress(running, progress, error) {
  const wrap = $('#progress-wrap'), bar = $('#progress-bar');
  const optBtn = $('#btn-optimize'), p = progress || {};
  const show = (text, count, cls, width) => {
    wrap.classList.remove('hidden');
    $('#progress-text').textContent = text;
    $('#progress-count').textContent = count;
    bar.className = cls;
    bar.style.width = width;
  };

  $('#btn-cancel').classList.toggle('hidden', !running);
  optBtn.disabled = !!running;
  optBtn.textContent = running ? '优选进行中…' : '立即优选';
  if (running) {
    const done = Number(p.done) || 0, total = Number(p.total) || 0;
    return show(p.text || '正在优选…', total > 0 ? done + ' / ' + total : '',
      '', total > 0 ? Math.round((done / total) * 100) + '%' : '12%');
  }
  if (error) return show('上次优选出错：' + error, '', 'danger', '100%');
  if (p.stage === 'scan' || (Number(p.done) > 0 && p.stage !== 'idle')) {
    return show(p.text || '优选完成', (p.done || 0) + ' / ' + (p.total || 0), 'good', '100%');
  }
  wrap.classList.add('hidden');
  bar.className = '';
  bar.style.width = '0';
}

/* ------------------------------------------------------------------- 节点 */

/* 后端返回的是合并列表：优选节点在前，订阅节点在后 */
const NODE_SECTIONS = [
  { opt: true, title: '优选节点', desc: 'Zenith 实测可用的 Cloudflare 边缘，按延迟排序' },
  { opt: false, title: '订阅节点', desc: '来自你的订阅，优选不会改动它们' }
];

function visibleNodes() {
  const st = S.status;
  if (!st || !st.nodes.length) return [];
  const q = ($('#node-search').value || '').trim().toLowerCase();
  if (!q) return st.nodes;
  return st.nodes.filter((n) => String(n.name || '').toLowerCase().indexOf(q) >= 0 ||
    String(n.server || '').toLowerCase().indexOf(q) >= 0);
}

/* 手动测速的结果优先于轮询返回的延迟 */
function nodeDelay(n) {
  const d = S.delays[n.name];
  return d === undefined ? Number(n.delay) || 0 : d;
}

/* 用 dataset 比较定位行，避免选择器转义问题 */
function rowFor(name) {
  const rows = $$('#node-list .node-row');
  for (let i = 0; i < rows.length; i++) if (rows[i].dataset.name === name) return rows[i];
  return null;
}

function nodeRowHtml(n) {
  const d = nodeDelay(n), cls = delayClass(d), busy = S.testing[n.name];
  const net = n.network && n.network !== 'tcp' ? '<span class="node-net">' + esc(n.network) + '</span>' : '';
  return '<div class="node-row' + (n.optimized ? ' opt' : '') + (n.active ? ' active' : '') +
    (busy ? ' testing' : '') + '" data-name="' + esc(n.name) + '" title="点击切换到该节点">' +
    '<div class="node-name">' + (n.active ? '<span class="node-mark">使用中</span>' : '') +
      '<span>' + esc(n.name) + '</span>' + net + '</div>' +
    '<div class="node-server">' + esc((n.server || '') + (n.port ? ':' + n.port : '')) + '</div>' +
    '<div class="bar"><i class="' + (busy ? '' : cls) + '" style="width:' +
      (busy ? 100 : delayPct(d).toFixed(1)) + '%"></i></div>' +
    '<div class="node-delay ' + (busy ? '' : cls) + '">' + (busy ? '测速中' : delayText(d)) + '</div>' +
  '</div>';
}

function nodeGroupHtml(sec, list) {
  return '<div class="node-group' + (sec.opt ? ' opt' : '') + '">' +
      '<span class="node-group-title">' + sec.title + '</span>' +
      '<span class="node-group-count">' + list.length + '</span>' +
      '<span class="node-group-desc">' + sec.desc + '</span>' +
    '</div>' + list.map(nodeRowHtml).join('');
}

/* 保留节点数只影响显示：缓存够的话调大设置立刻生效，不需要重新扫描 */
function renderNodeHint(st) {
  const el = $('#node-hint');
  if (!el) return;
  const keep = Number(st.settings && st.settings.keepNodes) || 0;
  const stored = Number(st.storedCount) || 0;
  if (keep <= 0) { el.textContent = ''; el.className = 'node-hint'; return; }
  const short = stored < keep;
  el.className = 'node-hint' + (short ? ' warn' : '');
  el.textContent = (short
    ? '已缓存 ' + stored + ' 个，还差 ' + (keep - stored) + ' 个，点「立即优选」补足 · '
    : '') + '显示前 ' + keep + ' 个优选节点（可在设置中调整）';
}

function renderNodes() {
  const list = $('#node-list');
  if (!list) return;
  const st = S.status || {};
  renderNodeHint(st);
  if (!S.status) { list.innerHTML = '<div class="empty">正在读取节点…</div>'; return; }

  const nodes = visibleNodes();
  if (!nodes.length) {
    list.innerHTML = '<div class="empty">' + (S.status.nodeCount
      ? '没有匹配的节点，换个关键词试试。' : '还没有节点，先到「订阅」页添加一个订阅。') + '</div>';
    return;
  }

  // 分两组渲染；某一组没有（或全部被搜索过滤掉）时连标题一起隐藏
  list.innerHTML = NODE_SECTIONS.map((sec) => {
    const group = nodes.filter((n) => !!n.optimized === sec.opt);
    return group.length ? nodeGroupHtml(sec, group) : '';
  }).join('');
}

/* 测速过程中只重绘一行，不重建整个列表 */
function paintRow(name) {
  const st = S.status;
  if (!st || !st.nodes.length) return;
  const n = st.nodes.filter((x) => x.name === name)[0];
  const row = rowFor(name);
  if (!n || !row) return;
  const d = nodeDelay(n), cls = delayClass(d), busy = !!S.testing[name];
  row.classList.toggle('testing', busy);
  const fill = row.querySelector('.bar > i');
  fill.className = busy ? '' : cls;
  fill.style.width = busy ? '100%' : delayPct(d).toFixed(1) + '%';
  const cell = row.querySelector('.node-delay');
  cell.className = 'node-delay ' + (busy ? '' : cls);
  cell.textContent = busy ? '测速中' : delayText(d);
}

async function switchNode(name, row) {
  if (row) row.classList.add('busy');
  const r = await api('/api/switch', { name: name });
  if (row && row.isConnected) row.classList.remove('busy');
  if (!r.ok) { toast('切换失败：' + r.error, 'err'); return; }
  toast('已切换到 ' + name, 'ok');
  if (S.status) S.status.current = r.current || name;
  refresh();
}

/* 逐个调用 /api/test-delay，用小并发池边测边刷新，页面不会被卡住 */
async function testAll() {
  if (S.testBusy) return;
  const st = S.status;
  if (!st || !st.nodes.length) { toast('没有可测速的节点', 'err'); return; }
  // 优选节点与订阅节点一起测
  S.testBusy = true;
  const state = $('#node-test-state');
  const queue = st.nodes.map((n) => n.name);
  const total = queue.length;
  let done = 0, alive = 0;
  queue.forEach((n) => { S.testing[n] = true; });
  renderNodes();

  const worker = async () => {
    while (queue.length) {
      const name = queue.shift();
      const r = await api('/api/test-delay', { name: name });
      delete S.testing[name];
      S.delays[name] = r.ok && Number(r.delay) > 0 ? Number(r.delay) : 0;
      if (r.ok) alive++;
      done++;
      if (state) state.textContent = '测速中 ' + done + ' / ' + total;
      if (S.tab === 'nodes') paintRow(name);
    }
  };

  const runners = [];
  for (let i = 0; i < Math.min(TEST_CONCURRENCY, total); i++) runners.push(worker());
  await Promise.all(runners);
  S.testBusy = false;
  if (state) state.textContent = '测速完成：' + alive + ' / ' + total + ' 个节点可用';
  toast('测速完成，' + alive + ' 个节点可用', 'ok');
  renderNodes();
}

/* ------------------------------------------------------------------- 订阅 */

function subCard(s, selected) {
  const total = Number(s.total) || 0;
  const used = (Number(s.download) || 0) + (Number(s.upload) || 0);
  const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0;
  const cls = pct >= 90 ? 'bad' : pct >= 70 ? 'mid' : 'good';

  let expire = '长期有效';
  if (Number(s.expire) > 0) {
    const exp = new Date(Number(s.expire) * 1000);
    const days = Math.ceil((exp.getTime() - Date.now()) / 86400000);
    expire = (days > 0 ? '剩余 ' + days + ' 天' : '已过期') +
      '（' + prettyTime(exp.toISOString()).slice(0, 10) + '）';
  }

  return '<div class="card" data-id="' + esc(s.id) + '">' +
      '<div class="sub-head">' +
        '<span class="sub-name">' + esc(s.name || '未命名订阅') + '</span>' +
        (selected ? '<span class="badge ok">使用中</span>' : '') +
        (s.enabled === false ? '<span class="badge ghost">已停用</span>' : '') +
        '<div class="sub-actions">' +
          '<button class="btn sm" data-act="use">使用</button>' +
          '<button class="btn sm" data-act="update">更新</button>' +
          '<button class="btn sm danger" data-act="del">删除</button>' +
        '</div>' +
      '</div>' +
      '<div class="sub-url">' + esc(s.url || '') + '</div>' +
      '<div class="kv"><span>节点数量</span><b>' + (Number(s.nodeCount) || 0) + ' 个</b></div>' +
      '<div class="kv"><span>上次拉取</span><b>' + esc(prettyTime(s.lastFetch)) + '</b></div>' +
      '<div class="kv"><span>到期时间</span><b>' + esc(expire) + '</b></div>' +
      '<div class="traffic-line"><span>已用 ' + bytes(used) + '</span><span>' +
        (total > 0 ? '共 ' + bytes(total) + ' · ' + pct.toFixed(1) + '%' : '流量未知') + '</span></div>' +
      '<div class="bar"><i class="' + cls + '" style="width:' + (total > 0 ? pct.toFixed(1) : 0) +
        '%"></i></div>' +
      (s.lastError ? '<div class="sub-err">上次出错：' + esc(s.lastError) + '</div>' : '') +
    '</div>';
}

function renderSubs() {
  const box = $('#sub-list');
  if (!box) return;
  if (!S.subs) { box.innerHTML = '<div class="card"><div class="empty">正在读取订阅…</div></div>'; return; }
  const list = S.subs.subscriptions || [];
  box.innerHTML = list.length
    ? list.map((s) => subCard(s, s.id === S.subs.selected)).join('')
    : '<div class="card"><div class="empty">还没有订阅，把机场给的订阅地址粘到上面就能用。</div></div>';
}

async function loadSubs() {
  const r = await api('/api/subscriptions');
  if (r.ok) { S.subs = r; renderSubs(); }
  else if (!S.subs) {
    $('#sub-list').innerHTML = '<div class="card"><div class="empty">订阅读取失败：' + esc(r.error) + '</div></div>';
  }
}

/* ------------------------------------------------------------------- 高级 */

function showRuleError(msg) {
  const el = $('#rule-error');
  el.classList.toggle('hidden', !msg);
  el.textContent = msg || '';
}

async function loadRules() {
  const r = await api('/api/rules');
  if (!r.ok) { toast('规则读取失败：' + r.error, 'err'); return; }
  $('#rules').value = (r.rules || []).join('\n');
  $('#sw-directcn').checked = !!r.directCN;
  $('#sw-blockads').checked = !!r.blockAds;
  $('#current-cfg').textContent = r.currentCfg || '（配置为空）';
  $('#rule-target').innerHTML = (r.targets || ['PROXY'])
    .map((t) => '<option value="' + esc(t) + '">' + esc(t) + '</option>').join('');
  showRuleError('');
}

/* 在光标处插入「类型,,出口」，光标停在两个逗号之间等待输入 */
function insertTemplate(type) {
  const ta = $('#rules');
  const prefix = type + ',';
  const snippet = prefix + ',' + ($('#rule-target').value || 'PROXY');
  const start = ta.selectionStart === null ? ta.value.length : ta.selectionStart;
  const end = ta.selectionEnd === null ? ta.value.length : ta.selectionEnd;
  const before = ta.value.slice(0, start), after = ta.value.slice(end);
  const lead = before && !/\n$/.test(before) ? '\n' : '';
  const tail = after && !/^\n/.test(after) ? '\n' : '';
  ta.value = before + lead + snippet + tail + after;
  const caret = (before + lead + prefix).length;
  ta.focus();
  try { ta.setSelectionRange(caret, caret); } catch (e) { /* 忽略 */ }
}

async function saveRules(btn) {
  const lines = $('#rules').value.split('\n').map((s) => s.trim()).filter(Boolean);
  await guard(btn, async () => {
    const r = await api('/api/rules', { rules: lines });
    if (r.ok) {
      showRuleError('');
      toast('规则已保存，共 ' + lines.length + ' 条', 'ok');
      loadRules();
    } else {
      showRuleError('校验失败：' + r.error);
      toast('规则保存失败', 'err');
    }
  });
}

/* ------------------------------------------------------------------- 设置 */

function fillSettings(st) {
  const active = document.activeElement;
  NUM_FIELDS.forEach(([sel, key]) => {
    const el = $(sel);
    if (el && el !== active && st[key] !== undefined) el.value = st[key];
  });
  const sw = $('#sw-subauto');
  if (sw && sw !== active && st.subscriptionAutoUpdate !== undefined) sw.checked = !!st.subscriptionAutoUpdate;
}

async function loadSettings() {
  const r = await api('/api/settings');
  if (!r.ok) { toast('设置读取失败：' + r.error, 'err'); return; }
  S.settings = r.settings || {};
  fillSettings(S.settings);
}

let saveTimer = null;
function queueSave(patch) {
  const state = $('#settings-state');
  state.textContent = '保存中…';
  api('/api/settings', patch).then((r) => {
    if (!r.ok) { state.textContent = ''; toast('设置保存失败：' + r.error, 'err'); return; }
    S.settings = r.settings || S.settings;
    state.textContent = '已保存';
    setTimeout(() => { if (state.textContent === '已保存') state.textContent = ''; }, 1800);
  });
}

function saveNumber(el, key) {
  const val = parseInt(el.value, 10);
  if (isNaN(val)) { fillSettings(S.settings || {}); return; }
  const clamped = Math.max(parseInt(el.min, 10), Math.min(parseInt(el.max, 10), val));
  el.value = clamped;
  queueSave(patchOf(key, clamped));
}

async function loadLogs() {
  const box = $('#log-view');
  if (!box) return;
  const r = await api('/api/logs?which=' + encodeURIComponent(S.logWhich) + '&lines=300');
  if (!r.ok) { box.textContent = '日志读取失败：' + r.error; return; }
  logTo(box, r.text && r.text.trim() ? r.text : '（暂无日志）');
}

async function loadAbout() {
  const r = await api('/api/about');
  if (!r.ok) return;
  $('#about-version').textContent = 'v' + (r.version || '—');
  $('#ab-version').textContent = (r.name || 'Zenith') + ' ' + (r.version || '');
  $('#ab-go').textContent = r.go || '—';
  $('#ab-core').textContent = r.core || '—';
  $('#ab-license').textContent = r.license || 'GPL-3.0';
  const repo = $('#ab-repo');
  repo.textContent = r.repo || '—';
  repo.href = r.repo || '#';
  $('#ab-datadir').textContent = r.dataDir || '—';
}

/* --------------------------------------------------------- 轮询与状态渲染 */

function renderStatus(st) {
  $('#brand-sub').textContent = 'v' + (st.version || '1.0.0');
  $('#side-dot').className = 'dot ' + (st.coreUp ? 'on' : 'off');
  $('#side-core').textContent = st.coreUp ? '内核运行中' : '内核已停止';

  const meta = [];
  if (st.coreVersion) meta.push(st.coreVersion);
  meta.push(st.coreUp ? '已运行 ' + uptimeText(st.coreUptime) : (st.corePid ? 'PID ' + st.corePid : '未启动'));
  $('#side-meta').textContent = meta.join(' · ');
  $('#core-state-hint').textContent = st.coreUp
    ? '内核运行中 · ' + (st.coreVersion || '') + ' · 已运行 ' + uptimeText(st.coreUptime)
    : '内核未运行，重启内核可恢复代理';

  const p = st.ports || {};
  $('#p-mixed').textContent = '127.0.0.1:' + (p.mixed || '—');
  $('#p-api').textContent = '127.0.0.1:' + (p.api || '—');
  $('#p-ui').textContent = '127.0.0.1:' + (p.ui || '—');
  $('#p-control').textContent = '127.0.0.1:' + (p.control || '—');

  const sp = st.systemProxy || {};
  const swProxy = $('#sw-sysproxy');
  if (document.activeElement !== swProxy) swProxy.checked = !!sp.enabled;
  $('#sysproxy-desc').textContent = sp.blocked
    ? '未接管系统代理：' + sp.blocked
    : '把 Windows 系统代理指向 127.0.0.1:' + (p.mixed || '—') + '。';

  if (!S.settings && st.settings) { S.settings = st.settings; fillSettings(st.settings); }
  if (S.tab === 'overview') renderOverview(st);
  if (S.tab === 'nodes') renderNodes();
}

/* 每 2.5 秒轮询一次；失败时只显示失联横幅并继续重试 */
async function poll() {
  const st = await api('/api/status');
  if (st.ok) {
    const wasOffline = !S.online;
    S.online = true;
    $('#offline-bar').classList.add('hidden');
    S.status = st;
    renderStatus(st);
    if (wasOffline) { toast('已重新连上后端', 'ok'); loadSubs(); }
  } else {
    S.online = false;
    $('#offline-bar').classList.remove('hidden');
    $('#side-dot').className = 'dot off';
    $('#side-core').textContent = '与后端失联';
    $('#side-meta').textContent = '正在重试…';
  }
  setTimeout(poll, 2500);
}

async function refresh() {
  const st = await api('/api/status');
  if (st.ok) { S.status = st; renderStatus(st); }
  return st;
}

/* ------------------------------------------------------------------- 事件 */

function bindNav() {
  $('#nav').addEventListener('click', (e) => {
    const btn = e.target.closest('.nav-item');
    if (btn) setTab(btn.dataset.tab);
  });
}

function bindOverview() {
  $('#btn-optimize').addEventListener('click', function () {
    guard(this, async () => {
      const r = await api('/api/optimize', {});
      if (!r.ok) { toast('启动优选失败：' + r.error, 'err'); return; }
      toast(r.started ? '已开始优选，可能需要几分钟' : '优选已在进行中', 'ok');
      refresh();
    });
  });

  $('#btn-cancel').addEventListener('click', function () {
    guard(this, async () => {
      const r = await api('/api/optimize/cancel', {});
      toast(r.ok ? '已取消优选' : '取消失败：' + r.error, r.ok ? 'ok' : 'err');
      refresh();
    });
  });

  $('#seg-mode').addEventListener('click', (e) => {
    const btn = e.target.closest('.seg');
    if (!btn) return;
    guard(btn, async () => {
      const mode = btn.dataset.mode;
      const r = await api('/api/mode', { mode: mode });
      if (!r.ok) { toast('切换失败：' + r.error, 'err'); return; }
      toast('已切换到' + (MODE_TEXT[mode] || mode), 'ok');
      $$('#seg-mode .seg').forEach((b) => b.classList.toggle('active', b === btn));
      if (S.status) S.status.mode = mode;
    });
  });

  $('#sw-auto').addEventListener('change', function () {
    const on = this.checked, el = this;
    guard(el, async () => {
      const r = await api('/api/mode', { autoOptimize: on });
      if (!r.ok) { el.checked = !on; toast('设置失败：' + r.error, 'err'); return; }
      if (S.settings) S.settings.autoOptimize = on;
      toast(on ? '自动优选已开启：Zenith 会自己挑最快的节点' : '自动优选已关闭：它不会再动你的选择', 'ok');
    });
  });
}

function bindNodes() {
  $('#node-search').addEventListener('input', renderNodes);
  $('#node-list').addEventListener('click', (e) => {
    const row = e.target.closest('.node-row');
    if (row) switchNode(row.dataset.name, row);
  });

  $('#btn-test-all').addEventListener('click', function () { guard(this, testAll); });
  $('#btn-direct').addEventListener('click', function () {
    guard(this, async () => {
      const r = await api('/api/switch', { name: 'DIRECT' });
      if (r.ok) { toast('已切到直连，流量不再走代理', 'ok'); refresh(); }
      else toast('切换失败：' + r.error, 'err');
    });
  });
}

function addSub(btn) {
  const url = $('#sub-url').value.trim();
  if (!url) { toast('请先填写订阅地址', 'err'); return Promise.resolve(); }
  return guard(btn, async () => {
    const r = await api('/api/subscriptions/add', { url: url, name: $('#sub-name').value.trim() });
    if (!r.ok) { toast('添加失败：' + r.error, 'err'); return; }
    $('#sub-url').value = '';
    $('#sub-name').value = '';
    toast('订阅已添加', 'ok');
    loadSubs();
  });
}

async function subAct(btn, card, act) {
  const path = act === 'use' ? '/api/subscriptions/select' : '/api/subscriptions/update';
  if (act === 'update') btn.textContent = '更新中…';
  const r = await api(path, { id: card.dataset.id });
  if (act === 'update') btn.textContent = '更新';
  if (!r.ok) { toast((act === 'use' ? '切换失败：' : '更新失败：') + r.error, 'err'); return; }
  toast(act === 'use' ? '已切换订阅，共 ' + r.nodes + ' 个节点' : '订阅已更新，' + r.nodes + ' 个节点', 'ok');
  loadSubs();
  refresh();
}

function bindSubs() {
  $('#btn-sub-add').addEventListener('click', function () { addSub(this); });
  $('#sub-url').addEventListener('keydown', (e) => { if (e.key === 'Enter') addSub($('#btn-sub-add')); });

  $('#sub-list').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-act]');
    const card = e.target.closest('.card[data-id]');
    if (!btn || !card) return;
    const id = card.dataset.id, act = btn.dataset.act;
    if (act !== 'del') return void guard(btn, () => subAct(btn, card, act));

    // 删除用二次点击确认，避免误删（弹窗只留给退出）
    if (S.confirmDel !== id) {
      S.confirmDel = id;
      btn.textContent = '确认删除';
      btn.classList.add('primary');
      setTimeout(() => {
        if (S.confirmDel !== id) return;
        S.confirmDel = '';
        btn.textContent = '删除';
        btn.classList.remove('primary');
      }, 3200);
      return;
    }
    S.confirmDel = '';
    guard(btn, async () => {
      const r = await api('/api/subscriptions/remove', { id: id });
      toast(r.ok ? '订阅已删除' : '删除失败：' + r.error, r.ok ? 'ok' : 'err');
      loadSubs();
    });
  });
}

function bindAdvanced() {
  $('#rule-templates').addEventListener('click', (e) => {
    const chip = e.target.closest('.chip');
    if (chip) insertTemplate(chip.dataset.tpl);
  });
  $('#btn-save-rules').addEventListener('click', function () { saveRules(this); });
  $('#btn-cfg-refresh').addEventListener('click', function () { guard(this, loadRules); });

  [['#sw-directcn', 'directCNDomains', '国内直连'], ['#sw-blockads', 'blockAds', '广告拦截']].forEach((t) => {
    $(t[0]).addEventListener('change', function () {
      const on = this.checked, el = this;
      guard(el, async () => {
        const r = await api('/api/settings', patchOf(t[1], on));
        if (r.ok) { toast(t[2] + (on ? '已开启' : '已关闭'), 'ok'); loadRules(); }
        else { el.checked = !on; toast('设置失败：' + r.error, 'err'); }
      });
    });
  });
}

function bindSettings() {
  $('#sw-sysproxy').addEventListener('change', function () {
    const on = this.checked, el = this;
    guard(el, async () => {
      const r = await api('/api/system-proxy', { enabled: on });
      if (r.ok) { toast(on ? '系统代理已开启' : '系统代理已关闭', 'ok'); refresh(); }
      else { el.checked = !on; toast('设置失败：' + r.error, 'err'); }
    });
  });

  $('#sw-subauto').addEventListener('change', function () {
    const on = this.checked, el = this;
    guard(el, async () => {
      const r = await api('/api/settings', { subscriptionAutoUpdate: on });
      if (r.ok) toast(on ? '订阅自动更新已开启' : '订阅自动更新已关闭', 'ok');
      else { el.checked = !on; toast('设置失败：' + r.error, 'err'); }
    });
  });

  NUM_FIELDS.forEach(([sel, key]) => {
    const el = $(sel);
    el.addEventListener('change', () => {
      clearTimeout(saveTimer);
      saveTimer = setTimeout(() => saveNumber(el, key), 120);
    });
  });

  $('#seg-log').addEventListener('click', (e) => {
    const btn = e.target.closest('.seg');
    if (!btn) return;
    S.logWhich = btn.dataset.which;
    $$('#seg-log .seg').forEach((b) => b.classList.toggle('active', b === btn));
    loadLogs();
  });
  $('#btn-log-refresh').addEventListener('click', function () { guard(this, loadLogs); });

  $('#btn-core-restart').addEventListener('click', function () {
    guard(this, async () => {
      const r = await api('/api/core/restart', {});
      toast(r.ok ? '内核已重启' : '内核启动失败，请查看日志', r.ok ? 'ok' : 'err');
      refresh();
    });
  });

  $('#btn-quit').addEventListener('click', async () => {
    if (!window.confirm('退出 Zenith？\n\n内核会被关闭，系统代理也会被撤销。')) return;
    await api('/api/quit', {});
    document.body.innerHTML = '<div style="display:grid;place-items:center;height:100vh;color:#8b98b0;' +
      'font-size:15px;font-family:inherit">Zenith 已退出，这个窗口可以关掉了。</div>';
  });
}

/* --------------------------------------------------------------- 启动流程 */

function boot() {
  let tab = 'overview';
  try { tab = localStorage.getItem(LS_TAB) || 'overview'; } catch (e) { /* 忽略 */ }

  bindNav();
  bindOverview();
  bindNodes();
  bindSubs();
  bindAdvanced();
  bindSettings();
  setTab(tab);

  // 日志只在「设置」页且窗口可见时自动刷新
  setInterval(() => { if (S.logAuto && !document.hidden) loadLogs(); }, 4000);
  poll();
  loadSubs();
}

document.addEventListener('DOMContentLoaded', boot);

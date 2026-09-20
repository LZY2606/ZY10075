// Single-file UI. Pure rendering + fetch; all decisions happen server-side so
// results stay deterministic and auditable.
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  at: $('#at').value,
  meta: null,
  selectedScanId: null,
  selectedFinding: null,
  wiActions: [],
  lastExportId: null,
};

async function api(method, path, body, raw) {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { 'content-type': raw ? 'application/zip' : 'application/json' } : undefined,
    body: body !== undefined ? (raw ? body : JSON.stringify(body)) : undefined,
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) {
    const msg = typeof data === 'string' ? data : data.error || JSON.stringify(data);
    throw Object.assign(new Error(msg), { status: res.status, data });
  }
  return data;
}

function toast(msg, isErr = false) {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast' + (isErr ? ' err' : '');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add('hidden'), 4200);
  el.classList.remove('hidden');
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}
function shortCoord(key) {
  if (!key) return '';
  const [eco, grp, name, ver] = key.split('|');
  return `${eco}:${grp ? grp + '/' : ''}${name}@${ver}`;
}
function nodeName(key) {
  const p = key.split('|');
  return p[2].includes('/') ? p[2].split('/').pop() : p[2];
}

// ---------------- tabs ----------------
function switchTab(name) {
  $$('#tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  $$('.tab').forEach((t) => t.classList.toggle('active', t.id === 'tab-' + name));
  if (name === 'history') renderHistory();
  if (name === 'exceptions') renderExceptions();
  if (name === 'versions') initVersions();
  if (name === 'whatif') initWhatIf();
  if (name === 'audit') renderAuditList();
}
$$('#tabs button').forEach((btn) => btn.addEventListener('click', () => {
  history.replaceState(null, '', '#' + btn.dataset.tab);
  switchTab(btn.dataset.tab);
}));
$('#at').addEventListener('change', (e) => { state.at = e.target.value; });

// ---------------- boot ----------------
async function boot() {
  state.meta = await api('GET', '/api/meta');
  $('#at').value = state.meta.demoNow;
  state.at = state.meta.demoNow;
  fillManifestSelects();
  fillPolicySelect();
  fillScanSelects();
  await runScan();
}
function fillManifestSelects() {
  const opts = state.meta.manifests
    .map((m) => `<option value="${m.manifestId}">${esc(m.image.repository || m.fileName)} ${m.format} (${m.manifestId})</option>`)
    .join('');
  $('#scan-manifest').innerHTML = opts;
  $('#cmp-base').innerHTML = opts;
  $('#cmp-cand').innerHTML = opts;
  const ids = state.meta.manifests.map((m) => m.manifestId);
  if (ids[1]) $('#cmp-cand').value = ids[1];
}
function fillPolicySelect() {
  $('#scan-policy').innerHTML = state.meta.policies
    .map((p) => `<option value="${p.policyId}|${p.version}">${p.policyId} @${p.version}</option>`)
    .join('');
  // default v1 to match seed
}
async function fillScanSelects() {
  const scans = (await api('GET', '/api/scans')).scans;
  state.scans = scans;
  $('#wi-scan').innerHTML = scans
    .map((s) => `<option value="${s.scanId}">${s.scanId.slice(0, 14)}… ${s.decision} ${s.evaluatedAt} (${esc(s.policy.version)})</option>`)
    .join('');
}

// ---------------- scan ----------------
$('#scan-run').addEventListener('click', runScan);

async function runScan() {
  const manifestId = $('#scan-manifest').value;
  const [policyId, policyVersion] = $('#scan-policy').value.split('|');
  const evaluatedAt = state.at;
  $('#scan-status').textContent = '评估中…';
  try {
    const rec = await api('POST', '/api/scans', { manifestId, policyId, policyVersion, evaluatedAt });
    state.selectedScanId = rec.scan.scanId;
    state.scanRecord = rec;
    renderScan(rec);
    await fillScanSelects();
    $('#scan-status').textContent = `${rec.scan.scanId}`;
  } catch (err) {
    $('#scan-status').textContent = '失败: ' + err.message;
    toast(err.message, true);
  }
}

function renderScan(rec) {
  const { scan } = rec;
  const active = new Set(scan.activeFindings);
  const appliedById = new Map(scan.appliedExceptions.map((a) => [a.findingKey, a]));
  const findings = [...scan.findings].sort((a, b) => a.findingKey.localeCompare(b.findingKey));
  const rows = findings.map((f) => {
    const isActive = active.has(f.findingKey);
    const applied = appliedById.get(f.findingKey);
    const pathsHtml = f.paths
      .map((p, i) => {
        const depth = p.length - 1;
        const chain = p
          .map((k, idx) => `<span class="${idx === p.length - 1 ? 'depth' : ''}">${esc(nodeName(k))}@${esc(k.split('|')[3])}</span>`)
          .join(' <span class="arrow">→</span> ');
        return `<div class="path">路径 ${i + 1} <span class="chip">深度 ${depth}${depth === 0 ? '（根）' : depth === 1 ? '（直接）' : '（传递）'}</span><br>${chain}</div>`;
      })
      .join('');
    return `<div class="finding ${isActive ? '' : 'excused'}" data-key="${esc(f.findingKey)}" data-component="${esc(f.component)}">
      <div class="head">
        <div>
          <span class="chip rule">${esc(f.ruleId)}</span>
          <span class="chip">${esc(f.ruleType)}</span>
          <span class="chip">${f.pathCount} 条引入路径</span>
          ${applied ? `<span class="chip">已被例外 ${esc(applied.exceptionId.slice(0, 12))} v${applied.version} 覆盖</span>` : ''}
          <div class="coord">${esc(shortCoord(f.component))}</div>
          <div class="hint">${esc(f.reason)}${f.license ? ' · ' + esc(f.license) : ''}</div>
        </div>
        <div>
          <button class="small" data-exc="${esc(f.findingKey)}">申请例外</button>
        </div>
      </div>
      <div class="paths hidden">${pathsHtml}</div>
    </div>`;
  }).join('');

  $('#scan-result').innerHTML = `
    <div class="toolbar">
      <span class="verdict ${scan.decision}">${scan.decision === 'deny' ? '拒绝 DENY' : '放行 ALLOW'}</span>
      <span class="hint">${scan.findings.length} 条 finding，${active.size} 条未覆盖 · 评估于 ${esc(scan.evaluatedAt)}</span>
      <span class="hint">策略 ${esc(scan.policy.policyId)}@${esc(scan.policy.version)} · 证据版本 ${scan.evidenceVersion.slice(0, 12)}</span>
    </div>
    ${scan.equivalenceGroups && scan.equivalenceGroups.length ? `<div class="card"><h4>别名等价组（证据充分）</h4>${scan.equivalenceGroups.map((g) => g.map(shortCoord).join(' ≡ ')).join('<br>')}</div>` : ''}
    ${scan.rejectedEvidence && scan.rejectedEvidence.length ? `<div class="card"><h4>被拒绝的别名证据</h4><table>${scan.rejectedEvidence.map((r) => `<tr><td class="mono">${esc(r.id || r.kind)}</td><td>${esc(r.reason)}</td></tr>`).join('')}</table></div>` : ''}
    ${scan.unmatchedExceptions.length ? `<div class="card"><h4>已批准但未生效的例外（指纹/路径/时效不匹配）</h4><table>${scan.unmatchedExceptions.map((u) => `<tr><td class="mono">${esc(u.exceptionId.slice(0,12))} v${u.version}</td><td>${esc(u.reason)}</td></tr>`).join('')}</table></div>` : ''}
    ${rows || '<p class="hint">没有 finding。</p>'}
  `;

  $$('#scan-result .finding .head').forEach((head) => {
    head.addEventListener('click', (ev) => {
      if (ev.target.closest('button')) return;
      head.parentElement.querySelector('.paths').classList.toggle('hidden');
    });
  });
  $$('#scan-result button[data-exc]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.exc;
      const f = state.scanRecord.scan.findings.find((x) => x.findingKey === key);
      state.selectedFinding = f;
      $$('#tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === 'exceptions'));
      $$('.tab').forEach((t) => t.classList.toggle('active', t.id === 'tab-exceptions'));
      renderExceptions(true);
    });
  });
}

// ---------------- exceptions ----------------
$('#exc-new').addEventListener('click', () => {
  state.selectedFinding = null;
  renderExceptions(true);
});

async function renderExceptions(showForm = false) {
  state.meta = await api('GET', '/api/meta');
  const list = [...state.meta.exceptions].sort((a, b) => a.exceptionId.localeCompare(b.exceptionId));
  $('#exc-list').innerHTML = list.map((e) => `
    <div class="card">
      <div class="toolbar" style="margin:0">
        <span class="pill ${e.status}">${e.status} v${e.version}</span>
        <span class="chip rule">${esc(e.ruleId)}</span>
        <span class="mono">${esc(shortCoord(e.componentKey))}</span>
      </div>
      <table>
        <tr><th>例外 ID</th><td class="mono">${esc(e.exceptionId)}</td></tr>
        <tr><th>规则版本</th><td class="mono">${esc(e.policyId)} @${esc(e.policyVersion)}</td></tr>
        <tr><th>镜像指纹</th><td class="fp">${esc(e.bindFingerprint)}</td></tr>
        <tr><th>引入路径</th><td class="fp">${esc((e.pathKey || '').split('>').map(shortCoord).join(' → '))}</td></tr>
        <tr><th>有效期（含边界）</th><td class="mono">${esc(e.notBefore)}<br>… ${esc(e.notAfter)}</td></tr>
        <tr><th>理由</th><td>${esc(e.reason)}</td></tr>
        <tr><th>申请人</th><td>${esc(e.requestedBy)}</td></tr>
      </table>
      <div class="toolbar" style="margin:10px 0 0">
        <input class="dec-reason" placeholder="审批/拒绝/撤销理由（必填）" />
        <input class="dec-actor" placeholder="操作者" value="security-bob" />
        ${e.status === 'pending' ? `
          <button class="small primary dec" data-id="${e.exceptionId}" data-ver="${e.version}" data-dec="approve">批准</button>
          <button class="small danger dec" data-id="${e.exceptionId}" data-ver="${e.version}" data-dec="reject">拒绝</button>` : ''}
        ${e.status === 'approved' ? `<button class="small danger dec" data-id="${e.exceptionId}" data-ver="${e.version}" data-dec="revoke">撤销（产生新事件）</button>` : ''}
      </div>
    </div>`).join('');

  $$('#exc-list .dec').forEach((btn) => {
    btn.addEventListener('click', () => decide(btn, false));
  });

  if (showForm) renderExcForm();
  else $('#exc-form').classList.add('hidden');
}

function renderExcForm() {
  const f = state.selectedFinding;
  const manifests = state.meta.manifests;
  const defaultManifest = state.scanRecord ? state.scanRecord.manifestId : manifests[0].manifestId;
  $('#exc-form').classList.remove('hidden');
  $('#exc-form').innerHTML = `
    <h4>${f ? '为 finding 申请绑定例外' : '申请新例外'}</h4>
    <div class="form-row"><label>组件 key${f ? '（来自 finding）' : ''}</label><input id="ex-component" value="${esc(f ? f.component : '')}" ${f ? 'readonly' : ''}/></div>
    <div class="form-row"><label>规则 ID</label><input id="ex-rule" value="${esc(f ? f.ruleId : '')}" ${f ? 'readonly' : ''}/></div>
    <div class="form-row"><label>所属清单</label><select id="ex-manifest">${manifests.map((m) => `<option value="${m.manifestId}" ${m.manifestId === defaultManifest ? 'selected' : ''}>${esc(m.fileName)}</option>`).join('')}</select></div>
    <div class="form-row"><label>策略版本</label><select id="ex-policy">${state.meta.policies.map((p) => `<option value="${p.policyId}|${p.version}">${p.policyId}@${p.version}</option>`).join('')}</select></div>
    <div class="form-row"><label>绑定路径 pathKey（留空则不做路径绑定）</label><input id="ex-path" value="${esc(f && f.paths.length ? f.paths[0].join('>') : '')}"/></div>
    <div class="grid2">
      <div class="form-row"><label>notBefore</label><input id="ex-before" value="2026-09-15T00:00:00+09:00"/></div>
      <div class="form-row"><label>notAfter（含此刻）</label><input id="ex-after" value="2026-09-30T23:59:59+09:00"/></div>
    </div>
    <div class="form-row"><label>理由</label><textarea id="ex-reason" placeholder="为什么接受该风险、补偿控制、跟踪单号"></textarea></div>
    <div class="form-row"><label>申请人</label><input id="ex-by" value="analyst"/></div>
    <div class="toolbar"><button class="primary" id="ex-submit">提交申请</button><button id="ex-cancel">取消</button></div>
  `;
  $('#ex-cancel').addEventListener('click', () => $('#exc-form').classList.add('hidden'));
  $('#ex-submit').addEventListener('click', async () => {
    const [policyId, policyVersion] = $('#ex-policy').value.split('|');
    try {
      await api('POST', '/api/exceptions', {
        manifestId: $('#ex-manifest').value,
        policyId, policyVersion,
        componentKey: $('#ex-component').value,
        ruleId: $('#ex-rule').value,
        pathKey: $('#ex-path').value || null,
        license: f && f.license ? f.license : null,
        digest: f && f.digest ? f.digest : null,
        notBefore: $('#ex-before').value,
        notAfter: $('#ex-after').value,
        reason: $('#ex-reason').value,
        requestedBy: $('#ex-by').value,
        createdAt: state.at,
      });
      toast('例外申请已创建（pending）');
      renderExceptions(false);
    } catch (err) { toast(err.message, true); }
  });
}

async function decide(btn, batch) {
  const card = btn.closest('.card');
  const reason = card.querySelector('.dec-reason').value.trim();
  const actor = card.querySelector('.dec-actor').value.trim();
  if (!reason) return toast('必须填写决策理由', true);
  if (!actor) return toast('必须填写操作者', true);
  try {
    const rec = await api('POST', '/api/exceptions/decision', {
      exceptionId: btn.dataset.id, decision: btn.dataset.dec,
      expectedVersion: Number(btn.dataset.ver), reason, actor, at: state.at,
    });
    toast(`已${btn.dataset.dec === 'approve' ? '批准' : btn.dataset.dec === 'reject' ? '拒绝' : '撤销'}，版本 ${rec.results[0].version}`);
    renderExceptions(false);
  } catch (err) {
    if (err.status === 409 && err.data.conflicts) {
      const c = err.data.conflicts[0];
      toast(`版本冲突：当前为 v${c.actual}，你看到的是 v${c.expected}（状态 ${c.current.status}）`, true);
    } else toast(err.message, true);
  }
}

// ---------------- what-if ----------------
function initWhatIf() {
  fillScanSelects();
  renderWhatIfActions();
  renderSavedPlans();
}
$('#wi-add').addEventListener('click', () => {
  const action = $('#wi-action').value;
  const componentKey = $('#wi-component').value.trim();
  const version = $('#wi-version').value.trim();
  if (!componentKey) return toast('填写组件 key', true);
  if (action === 'upgrade-node' && !version) return toast('升级需要目标版本', true);
  state.wiActions.push(action === 'upgrade-node'
    ? { action, componentKey, to: { version } }
    : { action, componentKey });
  $('#wi-component').value = '';
  $('#wi-version').value = '';
  renderWhatIfActions();
});
function renderWhatIfActions() {
  $('#wi-actions').innerHTML = state.wiActions.map((a, i) =>
    `<li>${a.action === 'delete-node' ? '删除' : '升级'} <code>${esc(shortCoord(a.componentKey))}</code>${a.to ? ' → ' + esc(a.to.version) : ''} <button class="small" data-rm="${i}">移除</button></li>`).join('');
  $$('#wi-actions [data-rm]').forEach((b) => b.addEventListener('click', () => {
    state.wiActions.splice(Number(b.dataset.rm), 1);
    renderWhatIfActions();
  }));
}
$('#wi-run').addEventListener('click', async () => {
  try {
    const plan = await api('POST', '/api/plans', {
      baseScanId: $('#wi-scan').value,
      actions: state.wiActions,
      evaluatedAt: state.at,
      createdAt: state.at,
    });
    renderPlanResult(plan);
    renderSavedPlans();
  } catch (err) { toast(err.message, true); }
});

function renderPlanResult(plan) {
  const c = plan.comparison;
  const li = (x, tag) => `<li class="${tag}">${esc(shortCoord(x.component))} <span class="chip rule">${esc(x.ruleId)}</span> ${esc(x.reason || '')}</li>`;
  $('#wi-result').innerHTML = `
    <h4>风险消失 / 新增（候选组件数 ${plan.candidateComponentCount}）</h4>
    <div class="toolbar"><span class="verdict ${c.decisionBefore}">前:${c.decisionBefore}</span><span class="verdict ${c.decisionAfter}">后:${c.decisionAfter}</span></div>
    <div class="grid2">
      <div><b class="diff-rm">消失 (${c.risksRemoved.length})</b><ul class="small-list">${c.risksRemoved.map((x) => li(x, 'diff-rm')).join('') || '<li class=hint>无</li>'}</ul></div>
      <div><b class="diff-add">新增 (${c.risksAdded.length})</b><ul class="small-list">${c.risksAdded.map((x) => li(x, 'diff-add')).join('') || '<li class=hint>无</li>'}</ul></div>
    </div>
    <div><b class="diff-chg">仍存在 (${c.stillPresent.length})</b><ul class="small-list">${c.stillPresent.map((x) => `<li>${esc(shortCoord(x.component))} <span class="chip rule">${esc(x.ruleId)}</span> ${x.activeBefore === x.activeAfter ? '状态不变' : `覆盖状态 ${x.activeBefore}→${x.activeAfter}`}</li>`).join('') || '<li class=hint>无</li>'}</ul></div>
    <p class="hint">方案 ID <code>${esc(plan.planId)}</code> · 影响 ${plan.effects.map((e) => e.type + (e.keys ? ':' + e.keys.length : '')).join(', ')} · 原清单未被修改；例外不自动带入候选。</p>`;
}

async function renderSavedPlans() {
  const { plans } = await api('GET', '/api/plans');
  $('#wi-saved-list').innerHTML = plans.length
    ? `<table><tr><th>方案</th><th>基线</th><th>动作</th><th>结论</th><th></th></tr>${
      plans.map((p) => `<tr><td class="mono">${esc(p.planId.slice(0, 18))}</td><td class="mono">${esc(p.baseScanId.slice(0, 14))}</td><td>${p.actions.map((a) => esc(a.action.split('-')[0])).join(', ')}</td><td>${p.comparison.decisionBefore}→${p.comparison.decisionAfter}</td><td><button class="small" data-view="${esc(p.planId)}">查看</button></td></tr>`).join('')}</table>`
    : '<p class="hint">尚无方案。</p>';
  $$('#wi-saved-list [data-view]').forEach((b) => b.addEventListener('click', async () => {
    const p = await api('GET', '/api/plans/' + b.dataset.view);
    renderPlanResult(p);
  }));
}

// ---------------- version compare ----------------
async function initVersions() {
  // selects already filled at boot
}
$('#cmp-run').addEventListener('click', async () => {
  try {
    const d = await api('POST', '/api/compare/manifests', {
      baseManifestId: $('#cmp-base').value,
      candidateManifestId: $('#cmp-cand').value,
    });
    $('#cmp-result').innerHTML = `
      <div class="card">
        <h4>组件差异</h4>
        <div class="grid2">
          <div><b class="diff-add">新增 ${d.added.length}</b><ul class="small-list">${d.added.map((k) => `<li class="diff-add mono">${esc(shortCoord(k))}</li>`).join('')}</ul></div>
          <div><b class="diff-rm">移除 ${d.removed.length}</b><ul class="small-list">${d.removed.map((k) => `<li class="diff-rm mono">${esc(shortCoord(k))}</li>`).join('')}</ul></div>
        </div>
        <b class="diff-chg">变化 ${d.changed.length}</b>
        <table>${d.changed.map((c) => `<tr><td class="mono">${esc(shortCoord(c.key))}${c.renamedFrom ? ` <span class="hint">(别名自 ${esc(shortCoord(c.renamedFrom))})</span>` : ''}</td><td>${c.changes.map((x) => esc(x.field)).join(', ')}</td></tr>`).join('')}</table>
        <p class="hint">基线指纹 <span class="fp">${esc(d.base.fingerprint ? d.base.fingerprint.manifestFingerprint : '')}</span><br>候选指纹 <span class="fp">${esc(d.candidate.fingerprint ? d.candidate.fingerprint.manifestFingerprint : '')}</span></p>
      </div>`;
  } catch (err) { toast(err.message, true); }
});

// ---------------- history ----------------
async function renderHistory() {
  const [{ scans }, { events }] = await Promise.all([api('GET', '/api/scans'), api('GET', '/api/events')]);
  $('#hist-scans').innerHTML = `<table>
    <tr><th>扫描</th><th>时刻</th><th>策略</th><th>结论</th><th>finding</th><th>当时应用的例外</th></tr>
    ${scans.map((s) => `<tr>
      <td class="mono">${esc(s.scanId.slice(0, 18))}</td><td class="mono">${esc(s.evaluatedAt)}</td>
      <td>${esc(s.policy.version)}</td><td><span class="pill ${s.decision === 'allow' ? 'approved' : 'rejected'}">${s.decision}</span></td>
      <td>${s.totalFindings}（${s.activeFindings} 未覆盖）</td>
      <td>${s.appliedExceptions.map((e) => `<span class="chip">${esc(e)}</span>`).join('') || '—'}</td>
    </tr>`).join('')}</table>`;
  $('#hist-events').innerHTML = `<table>
    <tr><th>#</th><th>时刻</th><th>事件</th><th>操作者</th><th>例外</th><th>版本</th><th>理由</th></tr>
    ${[...events].reverse().map((e) => `<tr>
      <td>${e.seq}</td><td class="mono">${esc(e.at)}</td><td>${esc(e.type)}</td><td>${esc(e.actor || '')}</td>
      <td class="mono">${esc((e.exceptionId || '').slice(0, 12))}</td><td>${e.fromVersion ?? ''}→${e.toVersion ?? ''} (${esc(e.fromStatus || '—')}→${esc(e.toStatus)})</td>
      <td>${esc(e.reason || '')}</td>
    </tr>`).join('')}</table>`;
}

// ---------------- audit ----------------
$('#audit-export').addEventListener('click', async () => {
  $('#audit-status').textContent = '打包中…';
  try {
    const meta = await api('POST', '/api/audit/export', { createdAt: state.at });
    state.lastExportId = meta.exportId;
    $('#audit-status').textContent = `已导出 ${meta.exportId}（${meta.fileCount} 个文件，digest ${meta.digest.slice(0, 16)}…）`;
    renderAuditList();
  } catch (err) { $('#audit-status').textContent = '失败: ' + err.message; }
});
$('#audit-verify').addEventListener('click', async () => {
  if (!state.lastExportId) return toast('请先导出', true);
  const buf = await (await fetch(`/api/audit/exports/${state.lastExportId}/download`)).arrayBuffer();
  try {
    const v = await api('POST', '/api/audit/verify', buf, true);
    $('#audit-result').innerHTML = `<h4>校验结果</h4><p><span class="verdict ${v.ok ? 'allow' : 'deny'}">${v.ok ? '通过' : '失败'}</span></p>
      <p class="hint">digest ${esc(v.digest)} · 文件 ${v.fileCount} · 扫描 ${v.scans}</p>
      ${v.issues.length ? `<ul>${v.issues.map((i) => `<li class="diff-rm">${esc(i)}</li>`).join('')}</ul>` : '<p class="hint">原始清单字节未变、策略与例外版本齐全、排序一致、决策可复算。</p>'}`;
  } catch (err) {
    const v = err.data;
    $('#audit-result').innerHTML = `<h4>校验结果</h4><p><span class="verdict deny">失败</span></p><ul>${(v.issues || [err.message]).map((i) => `<li class="diff-rm">${esc(i)}</li>`).join('')}</ul>`;
  }
});
async function renderAuditList() {
  const { exports } = await api('GET', '/api/audit/exports');
  $('#audit-list').innerHTML = exports.length
    ? `<table><tr><th>包</th><th>时刻</th><th>digest</th><th>文件</th><th></th></tr>${exports.map((e) => `<tr><td class="mono">${esc(e.exportId)}</td><td class="mono">${esc(e.createdAt)}</td><td class="fp">${esc(e.digest.slice(0, 20))}…</td><td>${e.fileCount}</td><td><a href="/api/audit/exports/${e.exportId}/download">下载</a> <button class="small" data-load="${esc(e.exportId)}">载入校验</button></td></tr>`).join('')}</table>`
    : '<p class="hint">尚无导出。</p>';
  $$('#audit-list [data-load]').forEach((b) => b.addEventListener('click', () => {
    state.lastExportId = b.dataset.load;
    $('#audit-verify').click();
  }));
}

boot().then(() => {
  const initial = location.hash.replace('#', '');
  if (initial && $$('#tabs button').some((b) => b.dataset.tab === initial)) switchTab(initial);
}).catch((err) => {
  console.error(err);
  toast('初始化失败: ' + err.message, true);
});

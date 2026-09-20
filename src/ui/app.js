const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const state = {
  images: [],
  policies: [],
  exceptions: [],
  catalog: {},
  scans: [],
  model: null,
  actions: [],
  pack: null
};

const clock = () => $('#demoClock').value.trim();

async function api(path, body, method = 'GET') {
  const response = await fetch(path + (method === 'GET' ? (path.includes('?') ? '&' : '?') + 'at=' + encodeURIComponent(clock()) : ''), {
    method,
    headers: { 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await response.json();
  if (!response.ok) throw Object.assign(new Error(data.message ?? data.error ?? 'HTTP ' + response.status), { data, status: response.status });
  return data;
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
}
function short(hash, n = 14) {
  return hash ? String(hash).slice(0, n) + '…' : '—';
}

// ---- tabs -----------------------------------------------------------------
$$('#tabs button').forEach((button) => {
  button.addEventListener('click', () => {
    $$('#tabs button').forEach((b) => b.classList.toggle('active', b === button));
    $$('.panel').forEach((panel) => panel.classList.toggle('active', panel.dataset.tab === button.dataset.tab));
  });
});

// ---- boot -----------------------------------------------------------------
async function refreshState() {
  const data = await api('/api/state');
  Object.assign(state, {
    images: data.images,
    policies: data.policies,
    exceptions: data.exceptions,
    catalog: data.catalog,
    scans: data.scans
  });
  renderSelects();
  renderImages();
  renderExceptions();
  renderScans();
  renderPolicyDump();
}

function renderSelects() {
  const imageOptions = state.images.map((image) => `<option value="${esc(image.id)}">${esc(image.label)}</option>`).join('');
  for (const id of ['evalImage', 'planImage', 'auditImage']) {
    const select = $('#' + id);
    const current = select.value;
    select.innerHTML = imageOptions;
    if (current) select.value = current;
  }
  const policyOptions = state.policies.map((policy) => `<option value="${esc(policy.version)}">${esc(policy.version)}</option>`).join('');
  for (const id of ['evalPolicy', 'planPolicy', 'auditPolicy']) {
    const select = $('#' + id);
    const current = select.value;
    select.innerHTML = policyOptions;
    select.value = current || state.policies[state.policies.length - 1]?.version;
  }
}

// ---- evaluate -------------------------------------------------------------
$('#evalRun').addEventListener('click', runEvaluation);

async function runEvaluation() {
  const imageId = $('#evalImage').value;
  const policyVersion = $('#evalPolicy').value;
  const [evalData, modelData] = await Promise.all([
    api('/api/evaluate', { imageId, policyVersion }, 'POST'),
    api(`/api/images/${encodeURIComponent(imageId)}/model`)
  ]);
  state.model = modelData.model;
  state.currentEval = evalData;
  renderEvaluation(evalData, modelData.image);
}

function renderEvaluation(data, image) {
  const { result } = data;
  const pill = $('#evalConclusion');
  pill.textContent = result.conclusion + ' · open ' + result.openFindingIds.length + ' · waived ' + result.waivedCount;
  pill.className = 'conclusion ' + result.conclusion;
  $('#evalMeta').textContent =
    `image=${image.id}  manifest=${short(image.manifestSha256, 20)}  fingerprint=${short(image.imageFingerprint, 20)}  ` +
    `policy=${result.policyVersion}  at=${result.evaluatedAt}`;

  const container = $('#findings');
  if (!result.findings.length) {
    container.innerHTML = '<div class="finding"><div class="finding-head"><div class="finding-title">未发现违规</div></div></div>';
    return;
  }
  container.innerHTML = result.findings.map((finding) => findingCard(finding)).join('');
}

function findingCard(finding) {
  const waived = Boolean(finding.waivedBy);
  const pathCount = finding.paths.length;
  const paths = finding.paths
    .map((path, index) => {
      const nodes = path.map((id, nodeIndex) => {
        const isTarget = nodeIndex === path.length - 1;
        return `<span class="${isTarget ? 'target' : ''}">${esc(id)}</span>`;
      });
      return `<li><span class="pathidx">#${index + 1}</span>${nodes.join('<span class="arrow">→</span>')}</li>`;
    })
    .join('');
  const waiver = waived
    ? `<div class="waiver-box">已由例外 <strong>${esc(finding.waivedBy)}</strong> 豁免 · 操作者 ${esc(finding.waiver.operator)} · ` +
      `有效期 ${esc(finding.waiver.validFrom)} ～ ${esc(finding.waiver.validUntil)}<br/>理由：${esc(finding.waiver.reason)}</div>`
    : '';
  return `
    <div class="finding ${waived ? 'waived' : ''}">
      <div class="finding-head" data-toggle>
        <div>
          <div class="finding-title">${esc(finding.ruleId)} · ${esc(finding.componentName)} <code class="purl">${esc(finding.componentId)}</code></div>
          <div class="finding-sub">${esc(finding.message)} · depth=${finding.depth} · ${finding.scope} · ${esc(finding.findingId)}</div>
        </div>
        <span class="badge ${waived ? 'waived' : 'open'}">${waived ? '已豁免' : '未豁免'} · ${pathCount} 条路径</span>
      </div>
      <div class="finding-body" hidden>
        <div class="finding-sub">同一组件经 ${pathCount} 条不同依赖路径引入（分别列出，不合并）：</div>
        <ul class="paths">${paths}</ul>
        ${waiver}
        <div class="evidence">${esc(JSON.stringify(finding.evidence, null, 2))}</div>
      </div>
    </div>`;
}

$('#findings').addEventListener('click', (event) => {
  const head = event.target.closest('[data-toggle]');
  if (!head) return;
  const body = head.nextElementSibling;
  body.hidden = !body.hidden;
});

// ---- plan tab -------------------------------------------------------------
$('#planImage').addEventListener('change', loadPlanComponents);
$('#evalImage').addEventListener('change', () => {
  $('#planImage').value = $('#evalImage').value;
  loadPlanComponents();
});
$('#actionKind').addEventListener('change', () => {
  $('#actionVersion').style.display = $('#actionKind').value === 'upgrade' ? '' : 'none';
});

async function loadPlanComponents() {
  const imageId = $('#planImage').value;
  if (!imageId) return;
  const data = await api(`/api/images/${encodeURIComponent(imageId)}/model`);
  state.model = data.model;
  const graph = data.model;
  const rows = graph.components
    .filter((component) => !graph.rootIds.includes(component.id))
    .map((component) => {
      const catalog = state.catalog[component.coordinate];
      const versions = catalog ? Object.keys(catalog.versions ?? {}).join(', ') : '';
      return `<div class="component-item"><span>${esc(component.id)}</span><span class="badge">${esc(component.ecosystem)} · ${esc(component.licenses.join(' / ') || 'NOASSERTION')}${versions ? ' · 可升级: ' + esc(versions) : ''}</span></div>`;
    })
    .join('');
  $('#planComponents').innerHTML = rows;
  $('#actionComponent').innerHTML = graph.components
    .filter((component) => !graph.rootIds.includes(component.id))
    .map((component) => `<option value="${esc(component.id)}">${esc(component.id)}</option>`)
    .join('');
}

$('#addAction').addEventListener('click', () => {
  const id = $('#actionComponent').value;
  const kind = $('#actionKind').value;
  if (kind === 'upgrade') {
    const version = $('#actionVersion').value.trim();
    if (!version) return alert('升级需要填写目标版本');
    state.actions.push({ action: 'upgrade', id, toVersion: version });
  } else {
    state.actions.push({ action: 'remove', id });
  }
  renderActions();
});

function renderActions() {
  $('#actionList').innerHTML = state.actions
    .map((action, index) => {
      const label = action.action === 'remove'
        ? `删除 ${action.id}`
        : `升级 ${action.id} → ${action.toVersion}`;
      return `<li>${esc(label)}<button class="ghost small" data-remove-action="${index}">移除</button></li>`;
    })
    .join('');
}

$('#actionList').addEventListener('click', (event) => {
  const index = event.target.dataset.removeAction;
  if (index === undefined) return;
  state.actions.splice(Number(index), 1);
  renderActions();
});

$('#runPlan').addEventListener('click', async () => {
  const data = await api('/api/plans/compare', {
    imageId: $('#planImage').value,
    policyVersion: $('#planPolicy').value,
    actions: state.actions
  }, 'POST');
  renderPlanDiff(data);
});

function renderPlanDiff(data) {
  const entry = (item) =>
    `<div class="diff-entry">${esc(item.ruleId)} · ${esc(item.componentId)} · depth=${item.depth} · ${esc(item.scope)}</div>`;
  const { diff } = data;
  $('#planResult').innerHTML = `
    <div class="toolbar" style="margin-top:16px">
      <span class="badge">基线 ${esc(diff.baselineConclusion)}</span>
      <span>→</span>
      <span class="badge">候选 ${esc(diff.candidateConclusion)}</span>
      <span class="hint">风险消失 ${diff.disappeared.length} · 新增 ${diff.introduced.length} · 仍存在 ${diff.remaining.length}</span>
    </div>
    <div class="diff-cols">
      <div class="diff-box gone"><h4>风险消失</h4>${diff.disappeared.map(entry).join('') || '<div class="hint">无</div>'}</div>
      <div class="diff-box new"><h4>风险新增</h4>${diff.introduced.map(entry).join('') || '<div class="hint">无</div>'}</div>
    </div>
    <h4 style="margin-top:14px">候选完整结论（豁免不随版本/路径迁移）</h4>
    <pre class="output">${esc(JSON.stringify(data.candidate.findings.map((f) => ({ ruleId: f.ruleId, componentId: f.componentId, waivedBy: f.waivedBy ?? null })), null, 2))}</pre>`;
}

// ---- exceptions tab -------------------------------------------------------
function renderExceptions() {
  const rows = state.exceptions
    .map((record) => `
      <tr>
        <td><a href="#" data-exception="${esc(record.id)}">${esc(record.id)}</a></td>
        <td><span class="state-pill state-${esc(record.state)}">${esc(record.state)}</span><br/><span class="hint">rev ${esc(record.revision)}</span></td>
        <td><code class="purl">${esc(record.componentId)}</code><div class="hint">${esc(record.ruleId)} · policy ${esc(record.policyVersion)}</div></td>
        <td class="hint">${short(record.imageFingerprint, 18)}${record.boundPaths ? '<br/>路径绑定: ' + record.boundPaths.length + ' 条' : ''}</td>
        <td class="hint">${esc(record.validFrom)}<br/>～ ${esc(record.validUntil)}</td>
        <td>${esc(record.operator)}<div class="hint">${esc(record.reason)}</div></td>
        <td>
          ${record.state === 'requested' ? `<button class="small" data-approve="${esc(record.id)}">批准</button>` : ''}
          ${record.state === 'approved' ? `<button class="small danger" data-revoke="${esc(record.id)}">撤销</button>` : ''}
          <button class="small ghost" data-history="${esc(record.id)}">事件</button>
        </td>
      </tr>`)
    .join('');
  $('#exceptionTable').innerHTML = `<table><thead><tr><th>ID</th><th>状态/修订</th><th>绑定</th><th>指纹/路径</th><th>有效期（含时区）</th><th>理由/操作者</th><th>操作</th></tr></thead><tbody>${rows}</tbody></table>`;

  const sample = state.exceptions.find((record) => record.state === 'requested');
  if (sample) $('#batchInput').value = JSON.stringify({
    operator: 'ori.legal',
    at: clock(),
    commands: [
      { op: 'approve', exceptionId: sample.id, expectedRevision: sample.revision, reason: '批量审批：元数据问题已核实', at: clock() }
    ]
  }, null, 2);
}

$('#exceptionTable').addEventListener('click', async (event) => {
  const approveId = event.target.dataset.approve;
  const revokeId = event.target.dataset.revoke;
  const historyId = event.target.dataset.history;
  const linkId = event.target.dataset.exception;
  if (approveId) {
    const reason = prompt('批准理由（必须记录）');
    if (reason === null) return;
    const current = state.exceptions.find((record) => record.id === approveId);
    await api(`/api/exceptions/${encodeURIComponent(approveId)}/approve`, { expectedRevision: current.revision, reason }, 'POST');
    await refreshState();
  } else if (revokeId) {
    const reason = prompt('撤销理由（撤销产生新事件，不删除历史）');
    if (reason === null) return;
    const current = state.exceptions.find((record) => record.id === revokeId);
    await api(`/api/exceptions/${encodeURIComponent(revokeId)}/revoke`, { expectedRevision: current.revision, reason }, 'POST');
    await refreshState();
  } else if (historyId || linkId) {
    const id = historyId ?? linkId;
    const data = await api(`/api/exceptions/${encodeURIComponent(id)}/history`);
    $('#exceptionDetail').innerHTML = `<h3>${esc(id)} 事件链</h3>` + data.history
      .map((event) => `<div class="event-row"><span class="ev-type">${esc(event.type)}</span>${esc(event.at)} · ${esc(event.operator)} · rev ${esc(event.eventId)}<div class="hint">${esc(event.payload.reason ?? '')}</div></div>`)
      .join('');
  }
});

// ---- new exception modal --------------------------------------------------
let modalTarget = null;
$('#newExceptionBtn').addEventListener('click', () => {
  const evalFindings = state.currentEval?.result?.findings.filter((finding) => !finding.waivedBy) ?? [];
  const options = evalFindings.length
    ? evalFindings.map((finding) => `<option value="${esc(finding.componentId)}|${esc(finding.ruleId)}|${esc(finding.findingId)}">${esc(finding.ruleId)} · ${esc(finding.componentId)}</option>`).join('')
    : state.exceptions.map((record) => `<option value="${esc(record.componentId)}|${esc(record.ruleId)}|">${esc(record.ruleId)} · ${esc(record.componentId)}</option>`).join('');
  modalTarget = evalFindings[0] ?? null;
  $('#modalBody').innerHTML = `
    <label>违规（组件 | 规则）</label>
    <select id="mFinding">${options}</select>
    <label>生效时间 validFrom（RFC3339，含时区）</label>
    <input id="mFrom" value="${esc(clock())}" />
    <label>截止时间 validUntil（恰好此刻即失效）</label>
    <input id="mUntil" value="2026-12-31T23:59:59+09:00" />
    <label>理由（必填）</label>
    <textarea id="mReason" rows="3" placeholder="为何接受该风险、缓解措施、关联工单号"></textarea>
    <label>操作者</label>
    <input id="mOperator" value="kenji.ito" />
    <label><input type="checkbox" id="mBindPaths" checked /> 仅对当前这些引入路径生效</label>`;
  $('#modalBackdrop').classList.remove('hidden');
});
$('#modalCancel').addEventListener('click', () => $('#modalBackdrop').classList.add('hidden'));
$('#modalSave').addEventListener('click', async () => {
  const [componentId, ruleId] = $('#mFinding').value.split('|');
  const imageId = $('#evalImage').value || state.images[0]?.id;
  const image = state.images.find((item) => item.id === imageId);
  const boundFinding = state.currentEval?.result?.findings.find((finding) => finding.componentId === componentId && finding.ruleId === ruleId);
  const body = {
    componentId,
    ruleId,
    policyVersion: $('#evalPolicy').value || state.policies.at(-1).version,
    imageFingerprint: image.imageFingerprint,
    boundPaths: $('#mBindPaths').checked && boundFinding ? boundFinding.paths : null,
    validFrom: $('#mFrom').value.trim(),
    validUntil: $('#mUntil').value.trim(),
    reason: $('#mReason').value.trim(),
    operator: $('#mOperator').value.trim(),
    at: clock()
  };
  if (!body.reason) return alert('理由必填');
  try {
    await api('/api/exceptions', body, 'POST');
    $('#modalBackdrop').classList.add('hidden');
    await refreshState();
  } catch (error) {
    alert(error.message);
  }
});

// ---- batch ----------------------------------------------------------------
$('#batchRun').addEventListener('click', async () => runBatch(false));
$('#batchSimulate').addEventListener('click', async () => runBatch(true));

async function runBatch(simulate) {
  const out = $('#batchOutput');
  let payload;
  try {
    payload = JSON.parse($('#batchInput').value);
  } catch (error) {
    out.className = 'output fail';
    out.textContent = 'JSON 解析失败: ' + error.message;
    return;
  }
  try {
    if (simulate) {
      // Another operator approves the same item first, changing its revision.
      const first = payload.commands.find((command) => command.op === 'approve');
      if (first) {
        await api(`/api/exceptions/${encodeURIComponent(first.exceptionId)}/approve`, {
          expectedRevision: first.expectedRevision,
          reason: '他人先行批准（模拟并发修改）'
        }, 'POST');
        await refreshState();
      }
    }
    const result = await api('/api/batch', payload, 'POST');
    out.className = 'output ok';
    out.textContent = JSON.stringify(result, null, 2);
    await refreshState();
  } catch (error) {
    out.className = 'output fail';
    out.textContent =
      '整批失败，没有任何部分结果可见。服务端返回差异：\n\n' +
      JSON.stringify(error.data ?? { error: error.message }, null, 2);
    await refreshState();
  }
}

// ---- history --------------------------------------------------------------
function renderScans() {
  $('#scanList').innerHTML = state.scans
    .map((scan) => `
      <div class="scan-item" data-scan="${esc(scan.scanId)}">
        <div><strong>${esc(scan.scanId)}</strong> <span class="hint">${esc(scan.imageId)} · policy ${esc(scan.policyVersion)}</span></div>
        <div><span class="badge ${scan.conclusion === 'ALLOW' ? 'state-approved' : 'state-revoked'}">${esc(scan.conclusion)}</span>
        <span class="hint">${esc(scan.evaluatedAt)} · 例外 ${esc((scan.appliedExceptions ?? []).join(', ') || '无')}</span></div>
      </div>`)
    .join('');
}

$('#recordScan').addEventListener('click', async () => {
  await api('/api/scans', {
    imageId: $('#evalImage').value || state.images[0].id,
    policyVersion: $('#evalPolicy').value || state.policies.at(-1).version
  }, 'POST');
  await refreshState();
});

$('#scanList').addEventListener('click', async (event) => {
  const item = event.target.closest('[data-scan]');
  if (!item) return;
  const data = await api('/api/scans/' + encodeURIComponent(item.dataset.scan));
  const scan = data.scan;
  const rows = scan.result.findings
    .map((finding) => `<div class="event-row">${esc(finding.ruleId)} · ${esc(finding.componentId)} · ${finding.waivedBy ? '豁免 ' + esc(finding.waivedBy) : '未豁免'}</div>`)
    .join('');
  $('#scanDetail').innerHTML =
    `<h3>${esc(scan.scanId)} @ ${esc(scan.evaluatedAt)}</h3>
     <div class="hint">该记录保存评估时刻的完整结果快照与当时生效的例外：${esc((scan.appliedExceptions ?? []).join(', ') || '无')}</div>${rows}`;
});

// ---- audit ----------------------------------------------------------------
$('#exportAudit').addEventListener('click', async () => {
  const data = await api('/api/audit/export', {
    imageId: $('#auditImage').value,
    policyVersion: $('#auditPolicy').value
  }, 'POST');
  state.pack = data.pack;
  const out = $('#auditOutput');
  out.className = 'output ok';
  out.textContent = JSON.stringify({
    summary: data.pack.summary,
    packDigest: data.pack.packDigest
  }, null, 2);
});

$('#verifyAudit').addEventListener('click', async () => {
  if (!state.pack) return alert('请先导出审计包');
  const result = await api('/api/audit/verify', { pack: state.pack }, 'POST').catch((error) => error.data);
  const out = $('#auditOutput');
  out.className = 'output ' + (result.ok ? 'ok' : 'fail');
  out.textContent = JSON.stringify(result, null, 2);
});

$('#tamperAudit').addEventListener('click', () => {
  if (!state.pack) return alert('请先导出审计包');
  const tampered = structuredClone(state.pack);
  const parsed = JSON.parse(tampered.files['manifest.json'].bytes);
  parsed.metadata.timestamp = '2099-01-01T00:00:00Z';
  tampered.files['manifest.json'].bytes = JSON.stringify(parsed);
  const out = $('#auditOutput');
  out.className = 'output';
  out.textContent = '已在本地副本中篡改 manifest.json 字节（未保存到服务端）。点击“校验审计包”查看失败结果。';
  state.pack = tampered;
});

// ---- state tab ------------------------------------------------------------
function renderImages() {
  $('#imageList').innerHTML = state.images
    .map((image) => `
      <div class="component-item">
        <span>${esc(image.label)}</span>
        <span class="badge">${esc(image.format)} · ${image.componentCount} 组件 · ${image.edgeCount} 边</span>
      </div>
      <div class="component-item" style="flex-direction:column;align-items:flex-start">
        <span class="hint">manifest ${short(image.manifestSha256, 24)}</span>
        <span class="hint">fingerprint ${short(image.imageFingerprint, 24)}</span>
        ${image.aliases.length ? `<span class="hint">别名等价：${esc(image.aliases.map((alias) => alias.from + ' ≡ ' + alias.to).join('；'))}</span>` : ''}
      </div>`)
    .join('');
}

async function renderPolicyDump() {
  const data = await api('/api/policies');
  $('#policyDump').textContent = data.policies
    .map((policy) => `# ${policy.policyId} @ ${policy.version}\n` + policy.rules.map((rule) => `- ${rule.id} [${rule.type}] scope=${rule.scope ?? 'any'} ${JSON.stringify(rule).slice(0, 220)}`).join('\n'))
    .join('\n\n');
}

$('#importManifest').addEventListener('click', async () => {
  const id = $('#newImageId').value.trim() || 'img-custom-' + Date.now();
  try {
    const data = await api('/api/images', {
      id,
      label: 'custom: ' + id,
      rawText: $('#newManifest').value
    }, 'POST');
    $('#importOutput').textContent = '已导入: ' + JSON.stringify(data.image, null, 2);
    await refreshState();
  } catch (error) {
    $('#importOutput').textContent = error.message;
  }
});

$('#reseedBtn').addEventListener('click', async () => {
  await api('/api/admin/reseed', {}, 'POST');
  state.actions = [];
  renderActions();
  await refreshState();
});

// ---- go -------------------------------------------------------------------
$('#actionVersion').style.display = 'none';
refreshState()
  .then(() => loadPlanComponents())
  .then(() => runEvaluation())
  .catch((error) => {
    $('#findings').innerHTML = '<pre class="output fail">' + esc(error.stack || error.message) + '</pre>';
  });

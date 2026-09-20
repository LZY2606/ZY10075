# SBOM Policy Gate

安全团队用于比较多个镜像版本的 CycloneDX / SPDX 清单、执行依赖策略、并有边界地审批例外的系统。
纯 Node.js + 原生 HTTP API + 无框架网页（Vite 开发服务器），生产依赖为零。

## 运行

```bash
npm install
npm test -- --run
npm run dev -- --host 127.0.0.1 --port 5208 --strictPort
# 打开 http://127.0.0.1:5208
```

- API 与网页由同一个 Vite 进程提供（`/api/*` 走 Node 处理器）。
- 重置演示数据：`npm run reset`，或直接重启 dev（数据目录为 `data/state/`）。
- 重新生成确定性种子：`node server/seed.js`（固定时间线，不读取当前时钟）。

## 目录结构

- `shared/` 与运行时无关的规范模型与纯计算
  - `model.js` 组件身份（`ecosystem|group|name|version`）、哈希、许可证、依赖边
  - `parse.js` CycloneDX 1.4/1.5 JSON 与 SPDX 2.2/2.3 JSON 解析
  - `license.js` SPDX 表达式解析/规范化/DNF/许可证匹配
  - `paths.js` 根→组件的全部简单路径、深度、可达子树（环安全）
  - `aliases.js` 仅在证据充分时建立组件等价
  - `policy.js` 策略规则与 `exceptionCovers` 绑定判定
  - `scan.js` 一次评估：例外应用、未匹配诊断、确定性 scanId
  - `compare.js` 清单差异与扫描风险差异（消失/新增/仍在）
  - `plan.js` What-if：删除/升级节点只作用于副本
  - `exceptions.js` 例外创建、乐观并发（OCC）、审批/拒绝/撤销
  - `audit.js` / `zip.js` 审计包构建与零依赖 ZIP 校验
  - `canonical.js` / `fingerprint.js` / `id.js` 规范化 JSON 与 SHA-256 标识
- `server/` 文件存储、种子数据、HTTP API、Vite 中间件
- `web/` 单页界面（`index.html`、`app.js`、`styles.css`）
- `data/sbom/`、`data/policies/`、`data/evidence/` 演示输入
- `tests/` 61 个 Vitest 用例

## 核心不变量

1. **身份不混淆**：组件主键是 `ecosystem|group|name|version`。同名不同生态（如
   `pypi:readline` 与 `npm:lib-readline`）永远是两个组件，默认不合并。
2. **等价需要证据**：别名关系需要 1 条 high 或 2 条 medium 证据；跨生态等价必须有
   显式 `hash-equality` 记录。同生态同 SHA-256 工件可隐式等价。不足的证据进入
   “被拒绝的别名证据”，不产生静默合并。
3. **策略作用域明确**：每条规则可约束 `all` / `direct` / `transitive`；根组件深度 0，
   直接依赖深度 1。许可证规则区分“可选择 GPL”（`X OR GPL` 即拒绝）与“全部必须在允许集”。
4. **例外五重绑定**：组件坐标、规则+规则版本、镜像指纹（优先 image digest，否则
   清单指纹）、有效期（显式时区）、引入路径 pathKey。换版本、换镜像、路径改变都不会
   继续生效；未匹配会在扫描结果中给出原因。
5. **到期语义固定**：窗口为闭区间 `[notBefore, notAfter]`，**恰好等于两端时刻均有效**；
   后一秒失效；所有时刻必须是带 `Z` 或 `±HH:MM` 的 ISO-8601，禁止无时区字符串
   （有测试固定这些语义，见 `tests/policy-exception.test.js`）。
6. **历史不可变**：历史扫描保存当时的策略版本、证据版本和应用的例外（含版本号）。
   审批/拒绝/撤销都只产生新事件并递增版本；撤销是新事件，不删除历史。
7. **批量原子性**：批量审批先全部校验（含 OCC `expectedVersion`），任何一条已被他人
   修改则整批 HTTP 409，返回每条冲突的当前状态差异，不落任何可见的部分结果。
8. **完全可复算**：scanId 是
   `sha256(清单指纹, 策略 id/版本, 证据版本, evaluatedAt)`；同输入同结果，与遍历顺序、
   Map 迭代顺序、当前时间无关。What-if 不携带例外，候选必须独立通过策略。
9. **审计包自证**：ZIP 内文件按码位排序、固定 ZIP 时间戳；`audit/files.json` 记录每个
   文件 SHA-256，`audit/digest.txt` 为其摘要；校验时重新解析原始 SBOM、重新计算指纹，
   并从保存的输入+规则版本重放决策与 finding。原始字节改变、策略/证据版本缺失均失败。
10. **What-if 不改原件**：删除/升级只构造内存副本；删除节点仅移除“只能经该节点到达”的
    独占子树；升级会改变组件身份并重写相关边。两方案输出“风险消失/新增/仍在”。

## 测试数据含义（全部为确定性夹具）

镜像 `registry.example.com/payments-api`：

- `data/sbom/payments-1.4.0.cdx.json`（CycloneDX 1.5，digest `sha256:a100…001`）
  - `npm:left-pad`、`npm:logfmt`（直接依赖，MIT）
  - `maven:org.apache.logging.log4j:log4j-core@2.14.0`（被 left-pad 与 logfmt 同时引入）
  - `pypi:readline@0.1.0`（GPL-3.0-only；经 logfmt 直达和经 npm:lib-readline 中转
    两条路径——多路径组件示例）
  - `pypi:recalled-pkg@0.9.0`（SHA-256 全 1，命中哈希 denylist；经两条路径引入）
  - `npm:dark-mirror-lib@1.0.0`（供应商含 “malware-mirror” 且来源不在允许 registry）
  - `npm:chain-a..e`（深度 5，超过策略 v1 的 maxDepth=4；v2 收紧为 3）
- `data/sbom/payments-1.5.0.spdx.json`（SPDX 2.3，不同 digest；跨格式 + 新版本）
  - log4j 升至 2.17.1；recalled-pkg、dark-mirror-lib、深链消失
  - 新增 `npm:pdf-tool@3.0.0`，许可证 `(MIT OR AGPL-3.0-only)`——AGPL 在 v2 被拒
- `data/policies/policy-v1.json`（maxDepth 4）与 `policy-v2.json`（增加 AGPL，
  maxDepth 3）——规则版本升级的对照。
- `data/evidence/aliases.json` 三条证据：一条跨生态“同名”声明（被拒）、一条 high
  purl-alias（但端点不在同一批清单时被标为 endpoint not present）、一条孤证 medium
  （证据不足被拒）。

## 种子时间线（Asia/Tokyo，全部固定）

- `2026-09-02 10:00` 对 1.4.0 的历史扫描：4 条拒绝，无例外。
- `2026-09-02 11:00→13:30` alice 申请、security-bob 批准 recalled-pkg 哈希例外
  （有效期至 2026-10-15，绑定左路径）；`14:00` 的扫描显示 4 条 finding 中 1 条被覆盖。
- `2026-09-03` carol 申请 GPL 临时例外并获批，`2026-09-08` 被撤销——事件流保留申请、
  批准、撤销三个事件，状态从 v1→v2→v3。
- 另有两条 pending（R-PROV-SUPPLIER、R-DEPTH）用于单条/批量审批演示；演示时刻
  `2026-09-15T12:00:00+09:00` 时哈希例外仍有效。

## HTTP API 摘要

| 方法与路径 | 说明 |
| --- | --- |
| `GET /api/meta` | 清单/策略/例外/扫描/事件总览与固定演示时刻 |
| `POST /api/manifests` `GET /api/manifests/:id` | 上传原始 SBOM（按模型哈希去重）/查看规范模型 |
| `POST /api/scans` `GET /api/scans/:id` | 以显式 `evaluatedAt` 执行评估/查看完整 finding 与路径 |
| `POST /api/explain/paths` | 展开某组件在扫描中的全部引入路径与各 finding |
| `GET/POST /api/exceptions` | 列出/申请例外（五重绑定 + 理由 + 申请人） |
| `POST /api/exceptions/decision` | 单条批准/拒绝/撤销（OCC，body 带 `expectedVersion`） |
| `POST /api/exceptions/batch` | 批量决策：一条冲突整批 409，返回差异，无部分结果 |
| `POST /api/compare/manifests` `/api/compare/scans` | 清单组件差异 / 风险消失与新增 |
| `POST /api/plans` `GET /api/plans/:id` | What-if 候选方案（删除/升级节点的副本推演） |
| `GET /api/events` | 不可变决策事件流 |
| `POST /api/audit/export` | 构建确定性审计 ZIP |
| `GET /api/audit/exports/:id/download` | 下载 ZIP |
| `POST /api/audit/verify` | 上传 ZIP：校验字节、版本齐全并重放决策 |

所有时间字段都必须是带显式时区的 ISO-8601 字符串；服务端从不调用当前时间参与计算，
`DEMO_NOW`（`server/api.js`）仅作为网页默认值。

## 测试

```bash
npm test -- --run        # 61 个用例：许可证/模型/路径/策略/例外/别名/方案/审计/HTTP
```

关键用例：
- `tests/license.test.js` SPDX 表达式规范化、DNF、OR 中 GPL 可选择性、WITH 例外
- `tests/policy-exception.test.js` 闭区间两端恰好有效、跨时区换算、五种绑定失效、
  OCC、撤销产生版本化新事件
- `tests/aliases-whatif.test.js` 同名跨生态不合并、证据门槛、删除独占子树、升级改身份
- `tests/audit.test.js` 原始字节改动检出、策略版本缺失失败、跨格式重算、排序确定性
- `tests/api.test.js` 批量原子失败无部分结果、scanId 幂等、审计导出/校验往返

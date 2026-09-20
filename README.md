# SBOM Policy Guard

一个可在本机运行的依赖策略评估与有边界例外审批系统。它把 **CycloneDX 1.4/1.5** 与
**SPDX 2.3** 清单解析为统一规范模型，按不可变的策略文档版本求值，并把每一次人工
决定记录为只增事件；所有结论都可以用「保存的输入 + 规则版本 + 显式结算时间」重新得到。

## 运行

```bash
npm install
npm test -- --run
npm run dev -- --host 127.0.0.1 --port 5208 --strictPort
```

页面固定在 <http://127.0.0.1:5208>。前端是原生 ES 模块单页应用，`/api/*` 由同一个
Vite 进程的中间件提供（`src/server/plugin.js`），API 处理器本身是标准
`Request/Response` 纯函数（`src/server/handler.js`），测试无需起网络端口。

## 目录

- `src/core/` 领域核心（无任何 Web 依赖、纯函数）
  - `sbom.js` CycloneDX / SPDX 解析与别名证据校验
  - `purl.js` Package URL 规范化（组件身份）
  - `license.js` SPDX 表达式解析、DNF 展开、allow/block/combo 求值
  - `graph.js` 图、最短深度、**全部**引入路径、候选叠加（what-if）
  - `policy.js` 规则求值、多路径 finding、例外绑定、方案差异
  - `time.js` 有效期时区语义（半开区间）
  - `store.js` 事件溯源、例外生命周期、批量原子提交
  - `fingerprint.js` 原始清单哈希与镜像指纹
  - `audit.js` 审计包组装与自校验、确定性摘要
  - `canonical.js` 规范化 JSON 与稳定哈希/排序
- `src/server/` 服务层、HTTP 处理器、Vite 插件、确定性种子
- `src/ui/` 网页（评估路径、候选方案、例外审批、历史、审计、清单管理）
- `data/sbom/` 三份演示清单（两个 CycloneDX 版本 + 一个 SPDX）
- `data/policy/` 两个策略文档版本与升级目录
- `src/test/` 8 个测试文件、46 个用例

## 核心不变量

### 组件身份与别名

1. **节点身份是规范化 purl**（`src/core/purl.js`）。`pkg:npm/left-pad@1.3.0` 与
   `pkg:pypi/left-pad@0.1.4` 永远是两个节点，同名不同生态绝不合并；名字相同不构成
   等价证据。
2. **别名只在证据充分时成立**（`verifyAliases`）：文档中必须有显式别名声明
   （CycloneDX 属性 `sbomguard:aliasOf`，或 SPDX `OTHER` annotation 注释
   `aliasOf: SPDXRef-…`），**并且**两端至少有一个相同算法、相同值的密码学哈希。
   通过校验的别名进入并查集等价类，仅用于「同一组件坐标」的豁免匹配与规则匹配。

### 策略与 finding

3. 规则支持直接/传递范围（`scope: direct|transitive|any`）、最大深度
   （`depth.max`）、来源主机允许/阻断（`source.require|source.block`，按主机后缀
   匹配）、许可证阻断/允许（`license.block|license.allow`，对 SPDX 表达式的 DNF
   每个析取项求值）与许可证组合（`license.combo`，对某组件依赖闭包里观察到的
   许可证令牌集合检查表达式可满足性）。
4. **finding 身份**是 `SHA256(ruleId | componentId | policyVersion)` 的前 12 位。
   升级版本（id 变化）或发布新规则版本都会产生新 finding，旧豁免无法对上号。
5. 一个 finding 携带**从镜像根到该组件的全部简单路径**（`allPaths`，按节点
   序列字典序排序）。同一组件经多条路径引入时，页面分别列出每条路径，不折叠。
   直接依赖深度为 1，根组件自身深度为 0 且永不被规则命中。

### 例外的有边界绑定（`exceptionMatches`）

例外必须同时满足下列全部条件才能豁免一个 finding：

- `ruleId` 相同；
- `policyVersion` 与被评估的策略文档版本**完全相同**；
- `imageFingerprint` 与当前镜像指纹相同 —— 换版本、增删边、改许可证/来源都会改变
  指纹（`fingerprint.js` 对规范化模型取哈希），例外随即失配；
- 组件身份相同或属于已验证别名等价类；
- 当前时刻处于有效期；
- 若声明了 `boundPaths`，当前 finding 的路径集合必须与其中至少一条**逐边一致**；
  依赖路径变化后旧绑定失效。

### 时间语义（`src/core/time.js`）

6. 所有求值都接受显式 RFC 3339 时刻（含时区），核心代码从不读取系统时钟；API 用
   查询参数或请求体的 `at`，缺省使用页面上的固定演示时钟 `2026-09-21T03:00:00Z`。
7. 有效期是**半开区间 `[validFrom, validUntil)`**：在 `validFrom` 当刻有效，
   **恰好到达 `validUntil` 即失效**。带时区的截止时间先归约为同一 UTC 瞬时
   （`2026-12-31T23:59:59+09:00` ≡ `2026-12-31T14:59:59Z`）。边界语义由
   `src/test/time-exception.test.js` 固定。

### 候选方案（模拟删除/升级）

8. what-if 只在请求内构造叠加图（`applyOverlay`），原始清单文本与已保存扫描永不
   修改；升级会重映射节点 id 与所有入/出边，路径变化因此可被观察到。
9. 指纹绑定的例外**不进入候选评估**：候选必须重新评估、重新申请豁免。比较结果
   分为「风险消失 / 新增 / 仍存在」三类（`diffDecisions`）。

### 人工决定、批量与历史

10. 申请、批准、撤销都是只增事件（`store.js`），记录理由、操作者、发生时刻与
    修订号；**撤销产生新事件，不删除历史**。每个例外保存 `lastTransition
    {from,to}`（前后版本）。
11. 批量审批分两阶段：先在草稿投影上校验全部命令（含批内重复/顺序问题），提交前
    再对线上修订号做乐观并发检查；任意一条 `expectedRevision` 已被他人改动，整批
    返回 `BATCH_FAILED` 与差异（expected/actual/current），**不追加任何事件、
    没有部分结果可见**。
12. 记录扫描（`/api/scans`）会保存当时的完整结论快照与当时生效的例外 id；历史页
    显示当时用了哪条例外，例外之后到期或被撤销不会改写历史记录。

### 审计包与可复现性

13. 审计包（`audit.js`）内嵌：原始清单字节（`manifest.json` 及 sha256）、策略文档
    全文与版本、全部例外修订、完整事件链、摘要与升级目录。校验会：
    - 重算每个文件哈希（清单改动 → `Tampered file: manifest.json`）；
    - 用内嵌字节重新解析模型并重算镜像指纹；
    - 检查策略 `policyId/version` 与每条例外的 revision/policyVersion 齐全；
    - 重算事件链摘要，防止历史被删改。
14. 进入哈希/摘要的对象一律经 `canonicalJson`（递归排序键、无空白），路径、
    finding、事件列表均有稳定排序（`stableCompare`，基于 UTF-16 码元，与平台
    locale 无关）。相同输入与规则版本在任何机器、任何遍历顺序下输出一致
    （`audit-determinism.test.js` 随机打乱组件与边验证）。

## 测试数据含义

- `img-shop-api-2026-09`（CycloneDX v1）：故意包含多种违规，便于展开路径：
  - 直接依赖 `express@4.19.2`、`lodash@4.17.20`、`pypi/left-pad@0.1.4`（MIT，
    与 npm 同名包对照身份不合并）、`rogue-source-vendor@1.0.0`、两个互为别名的
    `acme-utils@2.0.0` / `@acme/utils@2.0.0`（哈希相同 + 显式别名证据）；
  - `npm/left-pad@1.3.0` 经 express 引入（depth 2），GPL-3.0-only 且命中精确
    版本封禁；
  - `ms@2.1.2` 同时经两条路径引入
    （root→express→send→debug→ms 与 root→express→body-parser→debug→ms），
    depth 4，命中 `R-DEPTH-3`，页面会列出两条路径；
  - `rogue-source-vendor` 引用了 `malware-mirror.test`，命中来源阻断；
  - express 闭包内含 MIT，`license.combo` 规则不触发（反向对照）。
- `img-shop-api-2026-10`（CycloneDX v2）：left-pad 升到 1.3.1（MIT）、lodash
  4.17.21、恶意镜像引用移除、`ms` 挂到 depth 3；指纹变化，v1 例外对它无效，
  在策略 v1 下结论为 ALLOW。
- `img-shop-api-spdx`（SPDX 2.3）：同样的 npm/pypi 同名组件，走第二条解析路径。
- 策略 `2026.09` 与 `2026.10`：v2 扩大了 GPL 阻断与镜像黑名单；两版规则 id 相同
  但文档版本不同，用于演示「换规则版本旧豁免失效」。
- 预置例外事件链（均为固定时刻与操作者，见 `src/server/seed.js`）：
  - `EX-001` 已批准，针对 v1 指纹 + left-pad 封禁 + 具体路径，截止
    `2026-12-31T23:59:59+09:00`（用于时区边界演示）；
  - `EX-002` 曾在 2026-09 月中对 GPL finding 生效，`2026-09-20T00:00:00Z` 已
    到期；两次历史扫描 `SCN-20260910-01`（用了 EX-002）与 `SCN-20260921-01`
    （用了 EX-001）保留当时快照；
  - `EX-003` 待批准，用于页面/批量审批与乐观修订冲突演示；
  - `EX-004` 批准后又撤销，展示「撤销是新事件、历史保留」。
- 升级目录（`data/policy/catalog.js`）：`left-pad → 1.3.1`、`lodash → 4.17.21`、
  `ms → 2.1.3`，作为候选方案的可复现输入。

## 常用 API

- `GET /api/state`、`GET /api/images`、`GET /api/images/:id/model`、`POST /api/images`
- `POST /api/evaluate`、`POST /api/plans/compare`
- `GET|POST /api/exceptions`、`POST /api/exceptions/:id/approve|revoke`、
  `GET /api/exceptions/:id/history`
- `POST /api/batch`（`{commands:[{op,exceptionId,expectedRevision,...}]}`）
- `GET|POST /api/scans`、`GET /api/scans/:id`
- `POST /api/audit/export`、`POST /api/audit/verify`
- 所有读写接口接受 `?at=<RFC3339>` 或请求体 `at` 作为结算时间。

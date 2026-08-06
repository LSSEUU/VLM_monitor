# ADR 0022：M6 V3 显式绑定所选 Case 的审计 action 与 object

- 状态：Accepted（契约、0013 Observation、0014 状态推进、Case reader 与 builder prerequisite 已实现）
- 日期：2026-08-04
- 影响范围：`UPGRADE_REGRESSION` Case selection、execution observation、ledger protocol、terminal inventory

## 背景

M6 已发布的 `M6UpgradeCandidateCaseBinding` 绑定 Case ID、revision、Case 正文摘要、audit
sequence 与完整 audit entry hash。该 hash 已经密码学承诺 audit action 与 object ref，但旧 observation
wire 没有把二者作为可规范化字段显式暴露。0010/0011 因而使用了一个过窄的历史假设：所选 Case
revision 的 audit object 必须是 `CASE/case_id`。

这个假设只覆盖 M2 的一部分路径。M3–M5 的合法 Case transition 还可能由
`SCREENING_RESULT`、`PROCEDURAL_REVIEW`、`BACKLOG_ITEM`、`APPEAL` 或 `ALERT` 对象提交。
共享的 Case transition recognizer 与 M6 sealed Case reader已经能验证这些历史，但旧 SQLite trigger
会在 observation/sample append 前拒绝它们。直接移除旧 trigger 中的 `CASE/case_id` 条件会把已冻结的
protocol V2 数据重新解释为一种从未声明过的更强保证，因此不可接受。

## 决策

1. 保留既有 `M6UpgradeCandidateCaseBinding`、Observation V1、Record V2、Pending V1、Seal V2 与
   Inventory V2 的字段、canonical bytes 和 hash domain。旧 protocol V2 继续保持
   `CASE/case_id` 的原语义，不原地放宽。
2. 新增 `M6UpgradeSelectedCaseAuditAnchor`。它绑定 legacy `case_binding_id`，并显式携带与
   `AuditEntry` 同义的 exact `action` 与 `object_ref`；derived anchor ID 使用独立 domain version 1，
   输入为 binding ID、action、object kind 与 object ID。
3. anchor 只接受 revision-1 genesis 特判与相邻 Case transition recognizer 并集能产生的保守矩阵：
   - `CASE_CREATED -> CASE`
   - `EVIDENCE_PACK_PUBLISHED -> CASE`
   - `CASE_STATE_CHANGED -> CASE | SCREENING_RESULT | PROCEDURAL_REVIEW | BACKLOG_ITEM | APPEAL`
   - `CASE_CLOSED -> CASE | ALERT`
   当 object kind 为 `CASE` 时，Observation V2 还必须要求 object ID 精确等于所选 Case ID；
   `case_revision == 1` 当且仅当 action 为 `CASE_CREATED`。
4. 新增 `M6UpgradeSampleExecutionObservationAuthorityV2`。`CASE_REPLAYED` 必须携带一个 anchor，
   `NO_CASE` 必须显式携带 `null`；anchor 的 binding ID 必须等于 observation 中 candidate Case 的
   derived binding ID。Observation V2 ID 使用 domain version 2，并把 anchor ID 纳入哈希。
5. Record V2 不升版。它已经把 `observation_authority_id` 纳入 sample record ID；Pending V1 又绑定
   observation ID、record ID、record canonical SHA-256/size；Seal V2 再通过完整 record chain 和 inventory
   绑定所有 record。因此 anchor 会沿 `ObservationV2 -> RecordV2 -> PendingV1 -> SealV2` 被密码学传递，
   修改 record/pending/seal wire 只会制造没有新增保证的版本膨胀。
6. 新增 `M6UpgradeCandidateOutputInventoryAuthorityV3`，严格嵌套 Observation V2 与 Seal V2，并继续执行
   observation、record、candidate output、artifact usage 与 model-call runtime facts 的双向 exact join。
   Inventory V2 仍只接受 Observation V1，不能读取或猜测 V2 observation。
7. ledger protocol 版本组合固定为：

| Protocol | Observation | Pending | Record | Seal | Terminal inventory | Case audit 语义 |
|---|---|---|---|---|---|---|
| V1 | 无 | 无 | V1 | V1 | V1 | legacy |
| V2 | V1 | V1 | V2 | V2 | V2 | `CASE/case_id` |
| V3 | V2 + anchor | V1 | V2 | V2 | V3 | exact action/object ref |

   各子契约版本本来就不要求齐步递增；protocol 是组合这些 wire 的 run 级状态机。0013 只开放该状态机的
   第一个可恢复状态：fresh V3 scope 可以持久化一个 Observation V2。Pending V1、Record V2 与 Seal V2
   的 V3 状态推进必须由新的 0014 migration 开放，不能回改已经发布的 0013。
8. 0013 migration 新增 protocol V3、observation schema marker，以及规范化的 audit action/object
   kind/object ID。V3 observation 写入把 binding 的 sequence/hash/document SHA、anchor action/ref、
   `case_versions` 与 `audit_entries` 做精确交叉；旧 V1/V2 分支继续执行原限制。同一个 run 禁止混用
   Observation V1/V2。0013 继续让既有 pending/sample/seal triggers 只接受 protocol V2，因此 V3 在
   observation 之后故障闭合；0014 必须以新增迁移扩展这些状态，不能修改 0013 的 SQL 或 checksum。
9. 独立 V3 Case reader 从已经验证的 selected `AuditEntry` 重建 anchor，并继续调用完整 Case transition
   recognizer；旧 reader 接口不放宽。builder 仍须在任何 physical plan、Pixel 或 Raw response 读取前调用
   该 V3 reader。anchor 不能替代 history、before/after SHA、audit-chain head 或 Case aggregate root 验证。
10. 0014 只增量扩展 protocol V3 的 Pending V1、Record V2 与 Seal V2 trigger/state codec，不重写 0013。
    V3 repository 必须区分 fresh、observation、pending、record-prefix 与 sealed 五种恢复状态；`begin` 的
    新建与精确重试都要在读取任意 child state 前执行有界 V3 scope 校验。
11. V3 builder 在同一个 B cut 内先恢复完整 V3 state，再读取 selected Case/anchor。首个 Case-scoped
    `EVIDENCE_PACK` 路由只能由当前 Observation 的 exact identity 打开；selected Case 提供 membership 与
    expected canonical bytes，独立正文只在全样本预算及 pending record 比较之后读取并逐字节复核。

## 保证边界

- 单独一个 Record V2 或 Seal V2 只能证明它绑定了某个 observation ID，不能脱离 protocol V3 repository
  或 Inventory V3 宣称该 observation 已验证 selected Case anchor。
- anchor 让 action/object ref 可检查、可投影，但不是新的 Case truth source。Case 正文、audit document、
  sequence/hash、before/after SHA 与 transition legality 仍来自 sealed M2–M5 authority。
- 当前实现已经完成 0013、0014、exact Observation V1/V2 codec、独立 V3 repository、五态恢复，以及 V3
  Case reader 与 whole-sample builder 的 exact anchor join。V3 repository 会对整个 run 的 artifact/model-call
  children 做有界盘点，拒绝无 parent 或属于其他 observation ID 的孤儿行；begin writer-lock 冲突与外部
  artifact verifier 失败也只发布 payload-free 的类型化存储拒绝，外部 verifier 不能伪造内部 reason code。
- 这仍不等于 terminal V3 ledger 已闭合：除首个 selected-Case-bound `EVIDENCE_PACK` 外，M3–M5 物理闭包、
  candidate execution/output、Seal 后 Inventory V3 双向 join 和执行编排仍必须按里程碑顺序完成。

## 后果

- 真实 M3–M5 Case revision 现在能在 protocol V3 的 Observation V2 中表达 exact audit action/object，
  并由独立 reader、完整历史、0014 状态机与 builder prerequisite 精确交叉；旧数据库与旧 wire 继续原样验证。
- V3 复用 Record V2/Pending V1/Seal V2，减少 migration、恢复和链式 hash 的不必要分叉；代价是文档与
  实现必须明确说明“protocol version 不是所有嵌套 schema version 的同义词”。
- schema registry 新增 anchor、Observation V2 与 Inventory V3 三个序列化根；所有 computed claim、旧版
  hash vector 与新版 hash vector 都由 contract tests 固定。

## 被拒绝的方案

- 直接放宽 0010/0011：会静默重解释 protocol V2。
- 修改 legacy Case binding：会改变现有 record/observation canonical wire 与 binding ID。
- 为 Record、Pending、Seal 全部升版：它们已经通过 observation ID 完整承诺 anchor，不产生额外保证。
- 只把 object kind 放进一个开放字符串：无法绑定 exact object ID，也绕开 `ArtifactRef` 的 kind-specific
  身份校验。
- 只依赖 audit entry hash 而不显式 anchor：密码学承诺存在，但 SQL/reader 无法在不重新解释旧 wire 的
  前提下规范化并验证 action/object 语义。

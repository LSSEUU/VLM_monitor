# ADR 0038：M8 通知状态以逐版本 authority、同序审计和原子 commit receipt 持久化

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.4 notification outbox、状态迁移、审计与 SQLite repository

## 背景

通知闭环包含自动 queue、外部 channel 事件、人工确认和学生回复。只在一行 current status 上更新会丢失
unknown delivery、重试、身份换版和回复来源；把 raw channel 回执、状态与审计分开提交又会产生无法证明的
部分状态。通知回复还可能被误当成 Case action，因此需要与案件链分离但同样可重放的 authority。

## 决策

1. notification authority 的 v1 只能是 `PLANNED`，完整内嵌 plan，且不存在 transition/channel/reply 字段。
   后续每版必须有 prior notification document hash、last command 和 last initiator authority。
2. 每个 notification version 恰好对应同序 audit event。v1 使用固定 genesis hash 和 plan authority ID；后续
   event 完整内嵌 transition command，并绑定前一 audit event hash。
3. transition event 交叉验证 command target version/status、initiator、dispatch result、delivery receipt、reply
   与 authority 的规范化 last-* 索引，任何嫁接均 fail closed。
4. actor transition 必须额外绑定仓库解引用后的当前 actor authority document SHA-256。system/channel transition
   不得伪造该字段；需要人工发送确认的 plan policy 禁止 system queue/retry。
5. ack/respond actor 必须是 planned target；delivery/reply 的 target authority 和 channel 必须匹配 plan。
   回复仍固定 `case_transition_permitted=false`，只能成为后续独立 Case command 的 supporting authority。
6. commit receipt 同时绑定 notification version/status/authority/document、audit event/hash 和 repository
   manifest。下一实现切片必须在一个 SQLite `BEGIN IMMEDIATE` 事务追加 authority、audit 与相关 raw bytes；
   不允许 update/delete/replace。

## 结果

- 重启后可以重放完整通知状态、发起人、发送/送达差异、失败重试和回复来源。
- human-confirmation policy、target binding 和 actor revision 会成为持久化校验的一部分，而非 UI 提示。
- 通知链与 Case 链相互引用但独立提交，通知失败或回复不会静默修改 Case。
- M0–M6 与 M8.0–M8.3 authority/migration 不变；下一 migration 只追加隔离 M8 表。

## 未选择的方案

- **单行 current status 原地更新**：无法验证历史、并发 source fence 或审计连续性。
- **状态与审计分别提交**：崩溃可留下无审计状态或无状态审计。
- **只保存 provider receipt ID**：缺少 exact raw response 和 adapter manifest，无法复核边界行为。
- **把通知回复直接写入 Case 状态**：绕过 authenticated explicit Case transition 与本人申诉权限。

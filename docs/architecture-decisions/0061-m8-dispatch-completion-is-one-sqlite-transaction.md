# ADR 0061：dispatch completion 与 notification transition 必须同事务提交

- 状态：Accepted
- 日期：2026-08-11
- 影响范围：M8 migration 0008、notification repository、external outbox runner

## 背景

ADR 0060 冻结了 claim/fence/completion wire，但如果 completion 和 notification transition 分别写入，
崩溃可能留下两种矛盾事实：provider result 已结算而通知仍是 `QUEUED`，或通知已是 `SENT`/`FAILED`
但 claim 仍显示待对账。worker owner token 也不能以明文进入 authority、SQLite 或错误信息。

## 决策

1. migration 0008 新增 append-only claim、call fence、completion 三张表；claim 对
   `(notification_id, source_notification_version)` 唯一，fence/completion 对 claim 各唯一。
2. claim transaction 从 SQLite 重新读取 current notification，必须与 request 的 version、document hash、
   status 与 plan 完全一致且为 `QUEUED`。worker clear token 只在调用栈中存在，数据库只保存 SHA-256。
3. fence transaction 重新检查 owner digest、未存在 fence、未过期 lease 与同一 current `QUEUED` version。
   fence API 对重复调用固定返回 conflict，不把已持久化 receipt 当成第二次调用许可。
4. completion transaction 读取 exact claim/fence/current notification，构造既有 typed transition，验证 card
   与 raw response bytes，然后依次写 raw artifact、notification successor 与 completion；任一步失败全部回滚。
5. completion 的 exact retry 可返回既有 receipt，但必须逐项匹配 result、raw bytes、supporting authority、
   command/audit/completion manifest 与时间；它不会重新调用 channel。
6. read/status 路径重新解析 canonical JSON、索引字段、依赖 claim/fence/notification 与 repository manifest；
   缺失、损坏或跨 repository 均 fail closed。

## 结果

- 两个 repository 实例竞争同一 source version 时，SQLite 唯一约束和 `BEGIN IMMEDIATE` 只允许一个 claim。
- provider result 与 outbox 状态不再出现可提交的半状态；坏 raw bytes 不留下任何新增 artifact/version。
- fence 后崩溃仍保留为 `RECONCILIATION_REQUIRED`；迁移不实现自动重试或自动接管。
- 当前仍只有 persistence authority，没有启用真实飞书 worker 或环境凭据。

## 未选择的方案

- **分别调用 `transition_notification` 再写 completion**：无法跨崩溃保持两者一致。
- **在 claim 表原地更新状态**：破坏 append-only 审计并掩盖调用边界历史。
- **把 owner token 放进 receipt**：会把 worker 控制凭据扩散到日志、schema 和备份。
- **重复 fence 返回原 receipt**：调用方可能把读取重放误当成新的 HTTP 许可。

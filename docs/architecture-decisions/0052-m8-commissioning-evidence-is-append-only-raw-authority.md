# ADR 0052：M8 准入证据使用 append-only 原始工件权威

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.7 candidate/evidence repository port、migration 0006、SQLite adapter

## 背景

ADR 0051 要求 production adapter readiness 只能消费已持久化的评审与现场证据。若只保存 readiness 布尔值、文件路径或客户端提交的 hash，后续无法证明原始材料存在、内容未变、reviewer 在提交时仍有效，也无法在重启后重算评估。

## 决策

1. migration 0006 新增 append-only candidate 与 commissioning evidence 表，不修改 M0–M6 或既有 M8 表语义。
2. candidate commit receipt 绑定 exact candidate document、提交时当前 in-scope OPERATIONS actor receipt 和 repository manifest；同一 adapter ID/revision 只能对应一个 candidate。
3. evidence commit 在单一 `BEGIN IMMEDIATE` 事务中解析已登记 candidate 和当前 reviewer authority，要求其与 evidence 内嵌历史 receipt 完全一致。
4. evidence 原始字节与 ref、SHA-256、size、storage manifest、repository manifest、canonical evidence document 和 commit receipt 原子写入；任何一项冲突均整体回滚。
5. candidate/evidence 的 update、delete、replace 由 SQL trigger 拒绝。幂等重试只有 exact candidate/evidence/raw/storage manifest 全部一致时才返回原 receipt。
6. 读取与重启恢复逐项复核 canonical JSON、索引列、外键、raw hash/size 和 manifest；损坏数据返回 repository integrity failure，不返回部分可信结果。
7. evidence list 使用稳定顺序、显式 limit 和 `limit + 1` 超界检测；超界时 fail closed，不把截断结果交给 readiness。
8. repository 不持久化 `enabled`、不启动 adapter，也不授予生产、生命安全或处分能力。

## 结果

- readiness 可以从可重放的 candidate/evidence receipt 重建，不依赖可变文件路径或 dashboard cache。
- reviewer 停用或换版后不能提交使用旧 authority 的新证据；历史 receipt 仍可审计。
- 原始现场/评审材料的存在与内容由 SQLite commit receipt 证明，而不是由 AI、客户端字段或自由文本声称。
- 后续 activation gate 可再次解析当前双人 authority 并消费这一闭合证据集合。

## 未选择的方案

- **只保存 readiness 布尔值**：丢失证据闭包，无法重算或审计。
- **只保存外部文件路径**：路径可变且不能证明字节内容。
- **更新同一 evidence 行**：会用未来评审覆盖历史准入事实。
- **证据提交时不复核 reviewer**：停用或换版人员仍可用旧 receipt 新增权威材料。

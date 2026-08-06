# ADR 0027：M6 Fast 与 M4 候选采用路由隔离存储并共享全局账本前缀

- 状态：Accepted（0017、双路由 executor/observer/coordinator 已实现）
- 日期：2026-08-04
- 影响范围：REPLAY_LOCKED Pending/Record/Seal、候选 Case 持久化与崩溃恢复

## 背景

0016 已冻结首个 M3 Fast 候选表，只允许 screening-only、无告警的 terminal Case。M4 成功路径还必须把
`ESCALATE` Screening、三角色 Hearing Verdict 与确定性 ProceduralReview/Gate 作为一个不可拆分单元；直接
放宽 0016 会改变已验证的 SQL 形状、迁移 checksum 和 Fast 路由信任边界。同时，两个路由仍属于同一个
candidate run，不能各自维护独立 sequence、字节预算或审计前缀。

## 决策

1. 0016 保持不变。0017 新增独立 STRICT、append-only 的 M4 candidate 表，只接受
   `M4_HEARING_GATE_TERMINAL_POST_PARSE`，并要求 Verdict 与 passing/failing Gate review 原子落入同一 Case。
2. Fast 与 M4 表共享一个 run-global ledger prefix、256 MiB Case 文档预算和 execution scope。跨表的
   sequence、sample、execution entry、Case/Event 与 Pending identity 冲突全部 fail closed。
3. 两张表都禁止 replace、update 与 delete；两侧交叉 no-replace trigger 防止同一 Pending 在另一表重放。
4. 路由只能从 durable source catalog 中已封存的 replay closure 形状严格分类。未知、混合、不完整或 component
   未声明支持的 closure 返回 `UNSUPPORTED_ROUTE`，不读取 Raw、Pixel 或外部能力。
5. M4 source 必须精确连接 HearingRecord、HearingVerdictBinding 与 Gate current-closure receipt；候选重新执行
   hearing mapping 和 Gate，不能复用调用者提交的 Verdict、review 或统计结论。
6. routed executor 与 routed observation 根据 durable Pending/Stored Case 的 exact route 分派。候选已提交但
   Record 尚未追加时，恢复从持久化 Case 重建 observation，不再次执行模型或候选写入。
7. 精确重试在 Seal 后只读；provider、cache write、recovery、embedding、tool、alert channel 与 live-tail
   capability 均不暴露，run trap 必须保持全零。
8. 该闭环目前停在 pre-policy terminal（`READY_FOR_ALERT_POLICY | REWORK_REQUIRED`）。它证明双路由执行与恢复，
   不等同于生产 evaluator 所需的 `CLOSED` replay，也不允许据此声称 M6 已完成。

## 后果

- 新路由不会削弱已冻结的 Fast 表与历史身份。
- 一个 candidate run 可安全混排 Fast/M4 样本，同时保持唯一审计头和精确恢复点。
- M4 candidate commit 是一个 Case revision；不会出现“有 Verdict、无 Gate”的中间持久状态。
- 后续 CLOSED policy route 必须采用新的 additive authority/storage 边界，不能在 0017 Case 上追加隐藏 revision。

## 被拒绝的方案

- 直接放宽 0016：破坏冻结迁移及 Fast-only SQL 信任边界。
- Verdict 与 Gate 分两次提交：会产生可被恢复误认成 terminal 的半成品。
- 两路由各自编号或计预算：允许跨表重复 sequence 并绕过 run-global 上限。
- 从自由文本、Case 状态或调用者提示猜路由：无法证明与 blinded closure 相同。


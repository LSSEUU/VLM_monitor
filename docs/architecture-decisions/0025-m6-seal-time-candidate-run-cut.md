# ADR 0025：M6 在 Seal 时固化候选运行切片，恢复不跟随当前审计尾部

- 状态：Accepted（0015、纯构造器与 SQLite repository 已实现）
- 日期：2026-08-04
- 影响范围：protocol V3 Seal、M5 验证报告、terminal Inventory V3 与崩溃恢复

## 背景

`M6UpgradeCandidateOutputInventoryAuthorityV3` 要求候选 run cut、Seal V2 与 M5 验证报告使用完全相同的
manifest、config、Case 数和 final audit head。Seal 之后，业务仍允许 run 的审计链合法向前推进；如果恢复时
重新读取“当前”M5 报告，历史 Seal 很可能再也无法与新审计头精确闭合。反过来，若只在内存中保留 Seal
时刻的报告，进程在 terminal inventory 完成前崩溃就会丢失唯一可审计的 historical cut。

已有 0014 已冻结 V3 的 Observation V2、Pending V1、Record V2、Seal V2 与五态恢复。修改这些 wire 或
回写 0014 会破坏已发布的 checksum 和身份语义，因此 run cut 必须采用独立、additive 的 authority。

## 决策

1. 新增 migration 0015 和 append-only `m6_upgrade_candidate_run_cuts`。每个 candidate run、scope 与 Seal
   最多一行；禁止 replace、update 与 delete。
2. public repository 只接受 `candidate_run_id` 与 `execution_scope_authority_id`。调用者不能提交 scope、Seal、
   report、摘要、大小或预组装 authority。
3. 首次构造必须从同一个受信 V3 state cut 读取完整 sealed scope/records/observations/commitments/Seal；未
   Seal、旧 protocol、损坏前缀或 scope 漂移全部类型化失败。
4. M5 report provider 在 composition root 固定，并且必须按 `(run_id, Seal audit sequence, Seal audit hash)`
   解析历史 passing report；不得静默替换为当前 run head 的报告。provider 不是 VLM/provider 调用，不产生
   模型推理，也不能由每次 public 调用注入。
5. run cut 精确绑定完整 candidate manifest/config 及其 canonical SHA、execution component、Seal audit
   head、M5→M4→M3→M2 passing 链、report canonical SHA，并要求 `report.counts.case_roots` 等于 Seal 中的
   candidate Case 数。authority 与 report 均执行 256 MiB fail-closed 上限和 canonical round-trip。
6. 首次成功写入后，所有精确重试先读取 durable run cut，不再调用 report provider，也不再跟随当前审计
   尾部。并发首次写入只允许逐字节相同的 authority 胜出；任何差异都作为冲突拒绝。
7. 0015 的 normalized columns 只是索引。SQLite trigger 交叉验证 protocol V3、Seal V2、scope、manifest、
   config、component、audit head、passing report 投影及 Case 数；Python codec 继续验证 canonical JSON、SHA、
   computed claims 和所有 normalized projections。
8. candidate coordinator 应在 Seal 成功后立即调用 run-cut repository，再进入 terminal Inventory V3 builder。
   如果首次构造前已经丢失 historical report，系统必须返回类型化失败，不能猜测或用当前报告替代。

## 后果

- Seal 后审计继续推进不会使已经持久化的 terminal 构建输入失效。
- 崩溃恢复拥有明确边界：Seal 之前依赖五态 ledger；Seal 之后依赖 immutable run cut。
- 0014、既有 wire schema 和 hash domain 保持不变；0015 只新增 storage authority。
- 首次 run-cut 写入仍依赖 historical report provider 可用，因此 coordinator 的 Seal→run-cut 顺序是必须的，
  不是性能优化。

## 被拒绝的方案

- 恢复时重跑当前 M5 validation：会把未来审计尾部冒充 Seal 时刻的 cut。
- 把 report 作为 public repository 参数：调用者可以与伪造的 scope/Seal 共同自洽。
- 修改 Seal V2 或 0014 以嵌入 report：破坏冻结 wire、hash 与 migration checksum。
- 单独保存 report staging 行再稍后拼接：会产生 report 已写但 run cut 未闭合的额外恢复状态。

# ADR 0034：M8 typed sample、raw BLOB 与 poll cache 使用同一 SQLite 原子提交

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8 sensor adapter 输出、raw signal 保留、持久化 replay 与后续本地 API

## 背景

M8.2 的默认离线 adapter 会返回 typed sample，同时保留可按引用读取的 exact raw JSON。若先写文件再写
SQLite，崩溃可能留下无主 raw；若先写 SQLite 再写文件，则已提交 sample 可能引用不存在的 bytes。
当前模拟 raw 每条很小，并且 M8.3 需要优先形成可重启、可回放、无网络的演示闭环，不需要对象存储规模。

## 决策

1. migration 0003 在隔离 M8 运营库新增 raw BLOB、sample receipt、poll cache 和有序 cache-sample link
   表。一次 poll 的新 raw、sample、cache 与 links 在同一 `BEGIN IMMEDIATE` 事务提交或整体回滚。
2. 每条 raw 最多 1 MiB，每个 poll raw 总量最多 64 MiB，sample 数继续受 M8.2 的 1024 上限约束。
   超限在契约/构造器边界失败，不开始数据库写入。
3. 仓库按 result 的 `source_catalog_id` 解引用已持久化 catalog receipt，并确认 request source 是该目录
   的 exact member。调用方不能自报 catalog receipt 或扩大 source inventory。
4. 写入前对每条 raw bytes 重算普通 SHA-256，并与 sample 的 raw ref/hash 精确核对。raw ref、hash、size、
   storage manifest、repository manifest 与 bytes 共同成为不可变行；相同 ref 不同 bytes 必须失败。
5. poll receipt 完整内嵌 sample receipts。读取 cache 时重新验证 canonical JSON、computed identities、全部
   规范化列、link 顺序、sample rows 和 raw BLOB hash/size；任何缺失或冲突均 fail closed。
6. request/cache identity 相同且 receipt、manifest、raw bytes 完全相同可幂等返回。source sequence 冲突、
   manifest graft 或 raw 冲突会回滚本次事务，不留下部分 raw/sample。
7. 所有表禁止 update/delete/replace。当前 BLOB 方案是默认离线演示 authority；未来对象存储 adapter
   必须另行提供 staging、原子发布、timeout、manifest、raw receipt 和恢复协议，不能静默替换本语义。

## 结果

- 进程重启后可从 SQLite 回放同一 poll result 并读取逐字节相同的模拟 raw JSON。
- 不存在数据库与 raw 文件之间的双提交窗口，断网不会影响默认路径。
- `SIMULATED · SENSOR`、非认证消防声明和禁止生命安全联动字段仍来自冻结 M8.2 authority，不因持久化
  而升级为真实或认证信号。
- M0–M6 表、migration、Case、SafetySignal 和 manifest 身份保持不变。

## 未选择的方案

- **本地目录 raw + SQLite metadata**：当前规模下增加双提交、清理和恢复复杂度，没有演示收益。
- **只保存 typed sample**：失去原始输入完整性与 adapter 调试依据。
- **只按 raw ref 幂等、不比较 bytes**：允许引用复用覆盖历史输入。
- **立即接对象存储或消息队列**：引入网络、凭据和外部可用性，违反默认离线门。

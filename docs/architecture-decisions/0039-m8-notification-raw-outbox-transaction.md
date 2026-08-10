# ADR 0039：M8 通知原始制品与状态版本在同一 append-only 事务提交

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.4 notification target、outbox、raw card/response/reply 与 SQLite repository

## 背景

ADR 0038 冻结了通知版本和审计链，但只保存 raw reference/hash 的状态如果先于原始字节提交，会在崩溃后
留下无法复核的 `SENT`、`DELIVERED` 或 `RESPONDED`。相反，先落原始字节再迁移状态会产生孤立制品。
target mapping 也必须以仓库当前 actor revision 为准，不能信任计划内嵌的历史或客户端权限声明。

## 决策

1. 增加 target commit receipt，按 actor/channel 连续追加 revision，并绑定 prior authority/document 与
   repository manifest。发布 target 前必须解引用当前 active actor。
2. 每个 rendered card、channel response、delivery response 和 inbound reply 都产生 raw artifact commit
   receipt，绑定 reference、SHA-256、严格非空且不超过 1 MiB 的 byte size、raw-storage manifest 和
   repository manifest；单次 transition 最多两个制品。
3. notification commit receipt 必须精确、按序绑定 transition command 所声明的 raw reference/hash 清单、
   inventory hash 和总字节数。无 channel/reply artifact 的 transition 必须提交空清单。
4. migration 0004 只向隔离 M8 数据库追加 target、raw artifact、notification version 和有序 link 表。
   所有 authority/link 表禁止 update/delete/replace，版本与 audit hash 由 SQL trigger 强制连续。
5. repository 在一个 `BEGIN IMMEDIATE` 内解引用当前 Case、target 和 actor，构造 commit receipt，再原子追加
   raw BLOB、notification version、audit 和 links。任一 hash、manifest、source fence 或唯一 identity 冲突
   整体回滚。
6. 重载时同时交叉验证 canonical receipt、规范化索引列、target FK、raw links、原始字节 hash/size 和所有
   manifest；损坏或部分状态转换为 typed integrity failure，不返回近似结果。
7. 本地 fake 的送达仍只能声明 `simulated=true` 与 `real_delivery_confirmed=false`。通知回复不构造或执行
   Case command，也不成为纪律处分依据。

## 结果

- `PLANNED -> QUEUED -> SENT -> DELIVERED -> RESPONDED` 可以在断电/重启后按 exact bytes 与同序审计重放。
- 幂等重试返回原 receipt；同 command 配不同字节/manifest、旧 source fence 或换版 actor/target 会拒绝。
- migration 0004 不修改 M0–M6 wire、manifest 或既有 migration；默认路径仍不需要网络、GPU 或云 SDK。
- 下一切片可在此仓库边界上实现确定性的离线 fake channel，而无需放宽真实送达声明。

## 未选择的方案

- **只存 provider receipt ID 或 raw hash**：无法证明本地实际接收并审计了哪些字节。
- **raw 文件与状态分别提交**：存在孤立制品或缺失证据的已发送状态。
- **覆盖 current notification 行**：丢失 source fence、失败重试、回复来源与审计链。
- **直接信任 plan 内嵌 target/actor**：无法使停用或换版权限即时生效。


# ADR 0033：M8 运营 authority 使用隔离 SQLite、追加版本与仓库解引用 RBAC

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8 actor authority、运营案件、审计、乐观并发与后续本地 API

## 背景

M8.1 已冻结 actor/capability 与运营案件命令，但命令为了形成确定性身份而内嵌了 actor authority。
该内嵌文档只能表示调用方主张，不能成为授权事实；否则旧角色、已停用账号或被缩小的地点作用域仍可
通过重放获得权限。M8 同时需要把自动建案限制在 `PENDING_VERIFICATION`，并把每次关键迁移、明确
人工确认、实际使用的 actor revision 和审计链原子保存。

直接把 M8 migration 加到冻结的 M0–M6 migration 链，会扩大既有案件 authority、回放和发布路径的
回归面。只保存可变 current row 又会覆盖历史，无法证明乐观并发、授权版本和审计事件的对应关系。

## 决策

1. M8 运营数据使用独立目录中的 `labcourt.sqlite3`，复用现有 `SQLiteAuthorityGuard`、连接 PRAGMA 和
   migration runner，但使用独立的 `m8_migrations/`。M0–M6 数据库、表、migration 编号和 wire 均不变。
2. 首个 M8 migration 只建立 append-only `m8_actor_authorities` 与
   `m8_operational_case_versions`。后续 M8 migration 可以在同一运营数据库增加拓扑、来源、信号和
   outbox；不得回写冻结核心表。
3. actor authority 以 `(actor_id, authority_revision)` 连续追加。每个 receipt 绑定前一 authority ID、
   前一 canonical document SHA-256 与 repository manifest；首版没有前驱。仓库读取时重算 Pydantic
   authority、computed identity、canonical JSON，并与所有规范化索引列交叉核对。
4. 运营案件以 `(case_id, case_version)` 连续追加。版本 1 只能由自动 create command 建立为
   `PENDING_VERIFICATION`；后续版本绑定前一 Case document SHA-256、transition command、仓库实际
   解引用的 actor authority 和前一 audit hash。Case version 与 audit event 在同一行、同一 SQLite
   事务提交，commit receipt 绑定结果版本、结果 authority hash、audit event 与 repository manifest。
5. transition 写入先在 `BEGIN IMMEDIATE` 中读取当前 Case 与当前持久化 actor revision。客户端命令
   内嵌 actor 必须与该 revision 完全一致，且仍需通过 active、role、capability、地点作用域或本人申诉
   校验；不一致、版本过期或 source authority 过期均返回 typed concurrency failure，不执行迁移。
6. 相同 command 与相同 case/audit manifest 可以幂等返回已有 receipt；相同 command 偷换 manifest
   必须拒绝。SQLite trigger 同时拒绝不连续 revision/version、断裂 audit chain、更新、删除和替换。
7. 本切片不开放 HTTP，不实现开发免认证，也不持久化拓扑、设备、signal/raw/cache。它是 M8.3a；
   M8.3b 先补齐这些 authority，M8.3c 再以 loopback API 暴露仓库解引用后的能力。

## 结果

- 领导和运维即使提交结构合法的旧 authority，也无法获得案件迁移能力；停用或换版会立即使旧命令
  在仓库边界失败。
- 两个基于同一 Case version 的不同命令最多一个提交成功，失败者不产生半条 audit 或新版本。
- 重启后可从 SQLite 恢复完全相同的 actor、Case receipt 和 audit chain；规范化列或 canonical JSON
  冲突会 fail closed。
- M0–M6 schema、migration、SQLite authority、审计和回放语义保持不变。

## 未选择的方案

- **信任命令内嵌 actor authority**：允许旧 revision、停用前权限和 scope graft 绕过持久化事实。
- **只在 API handler 做 RBAC**：离线 worker、重放或未来消息 adapter 可绕过同一规则。
- **覆盖 current Case/actor 行**：丢失授权历史、审计链和精确的并发失败依据。
- **给冻结核心 migration 链追加 M8 表**：把校园运营试验面的回滚和升级风险带入 M0–M6 authority。
- **先开放 API 再补持久化**：会让临时内存身份和未闭合数据生命周期变成事实标准。

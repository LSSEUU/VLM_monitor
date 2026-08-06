# ADR 0013：可移植 run 身份与 backlog 历史状态权威

- 状态：Accepted
- 日期：2026-07-28

## 背景

`run_id` 同时参与 SQLite 作用域和工作区目录命名。SQLite 的默认文本比较区分大小写，但
Windows 文件系统通常把仅 ASCII 大小写不同的目录名解析为同一身份；Windows 还会特殊解释
尾随点和设备名。若数据库允许 `run-case` 与 `RUN-CASE` 并存，两个独立的数据库作用域就可能
写入同一文件系统目录。投影的 `current.json` 若只比较 audit head 和内容，也可能把另一 run 的
指针误当成幂等重放。

M3 backlog 以 append-only 版本记录保存状态，但单行 contract 校验不能证明相邻版本之间的状态
迁移合法。绕过 repository 的直接 SQL 若能插入第二个 `LEASED` 版本，就能在旧租约未闭合时替换
owner，破坏租约的 compare-and-swap 权威。

## 决策

### 可移植的 run 文件系统身份

run 的文件系统身份使用 SQLite 内建 `COLLATE NOCASE` 的 **ASCII** 大小写等价关系；这不是
Unicode case folding。数据库通过唯一索引保证同一 ASCII NOCASE 身份只能对应一个 `run_id`。
repository 注册 run 时按同一规则查找既有记录：完全相同的 ID 仍按既有 manifest 绑定规则幂等，
仅大小写不同的既有 ID 则以受控 contract failure 拒绝，不创建第二个作用域。

可用作目录段的 `run_id` 还必须满足以下可移植性约束：

- 不得以 `.` 结尾；
- 不区分 ASCII 大小写时，首个 `.` 前的 basename 不得是 `CON`、`PRN`、`AUX`、`NUL`、
  `COM1`–`COM9` 或 `LPT1`–`LPT9`；因此带扩展名的 `CON.json` 也被拒绝。

这些约束由 contract/repository 边界执行，并由 SQLite insert trigger 阻止直接 SQL 绕过。
所有 M3 读写入口必须确认 v7 hardening migration 及其权威对象已经安装，不能在旧 schema 上静默
降级运行。

JsonProjector 在持有 run 的发布锁并读取既有 `current.json` 后，必须先验证
`existing_pointer.run_id == requested_run_id`，再判断 pointer bytes、audit head 或 generation 是否
幂等。另一 run 的 pointer 即使其余字段恰好一致，也属于完整性冲突，不得复用或覆盖。

### backlog 相邻版本状态机

每个 backlog item 的第一条历史必须是版本 1、`PENDING`、`attempt_count = 0`，其
`retry_generation` 必须与不可变 initial item 完全一致（继续服从既有 reason-dependent contract），
且没有租约。之后每个版本必须恰好承接同一 item 的前一版本；合法迁移只有：

| 前一状态 | 新状态 | `attempt_count` | `retry_generation` | 租约字段 |
| --- | --- | --- | --- | --- |
| `PENDING` | `LEASED` | 恰好加 1 | 不变 | `lease_id`、`lease_owner_sha256`、`lease_expires_at` 全部设置 |
| `LEASED` | `PENDING` | 不变 | 不变或恰好加 1 | 全部清空 |
| `LEASED` | `COMPLETED` | 不变 | 不变 | 全部清空 |
| `LEASED` | `EXHAUSTED` | 不变 | 不变 | 全部清空 |

除此之外的迁移全部非法，尤其禁止 `LEASED → LEASED` owner takeover，也禁止跳过相邻版本、
从终态继续迁移或直接从 `PENDING` 进入终态。既有 completion receipt、failure authority 和
retry-generation 语义约束继续适用；本矩阵只收紧相邻历史本身的最低权威条件。

SQLite v7 trigger 在每次写入 `backlog_item_versions` 时检查初态或相邻迁移，使直接 SQL 伪造也在
事务内失败。只读 artifact validation 不信任该 trigger 曾经存在，而是从私有 SQLite snapshot
独立重建并逐对验证完整历史；发现非法相邻迁移时输出 typed integrity finding。数据库写时拒绝与
只读重建校验构成两道独立防线。

### v6 到 v7 的迁移

v7 migration 在一个事务中先审计既有 run 身份和 backlog 历史，再创建 ASCII NOCASE 唯一索引及
写时 triggers。若已有大小写碰撞、不可移植 run ID、非法初态或非法相邻 backlog 历史，迁移
fail closed 并整体回滚：v7 不记入 `schema_migrations`，也不留下部分 hardening 对象。

迁移只增加约束和校验对象，不重写任何既有业务行，不重新序列化 canonical JSON，也不重新计算
document hash。合法的已填充 v6 数据升级后，其行字节、JSON 文本和哈希保持不变，外键完整性也
必须继续成立。

## 理由

数据库 run 主键与目录身份若使用不同的等价关系，数据库隔离就无法推出文件系统隔离。采用
Windows 可解释的 ASCII NOCASE 身份和保守设备名规则，可让默认离线路径在支持的平台上保持同一
作用域含义。投影指针的显式 run 绑定则封闭了从文件层跨 run 复用 current 的最后入口。

backlog 的所有权来自历史迁移，不只来自某个单行的字段合法性。把最小状态机落实到数据库 trigger，
并由只读重建再次验证，可以同时阻止新伪造和发现曾在约束缺失时写入的旧伪造，而不会篡改历史证据。

## 范围

本决策只处理 run 文件系统身份、current 指针 run 绑定、v7 原子迁移和 backlog 历史状态权威。
它不改变 recovery 流程、fixture、扫描或调用预算，也不扩展模型调用与业务裁决能力。

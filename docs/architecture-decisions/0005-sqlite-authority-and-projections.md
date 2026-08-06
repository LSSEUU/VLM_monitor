# ADR 0005：SQLite 权威状态、运行作用域与文件投影

- 状态：Accepted
- 日期：2026-07-27
- 修订：投影的文件发布协议已由
  [`ADR 0012`](0012-atomic-projection-generations.md) 取代；本 ADR 的 SQLite 权威、
  run 作用域和“投影不可反写权威”决策仍然有效。

## 决策

M2 起，`<workspace>/labcourt.sqlite3` 是工作区内唯一的可变业务状态真实来源。每个
`<workspace>/<run_id>/` 目录下的 JSON、JSONL、媒体、报告与索引都是可验证或可重建工件，
不得反向覆盖数据库状态。规格文件布局中的 `precedents.db` 若在后续里程碑生成，只能是
从主数据库重建的只读检索索引，不得保存主数据库中不存在的判例状态。

可写 SQLite adapter 只接受 basename 精确为 `labcourt.sqlite3` 的路径。每次连接前都经统一
authority guard 打开并锚定已经存在、非 symlink/junction/reparse 的工作区父目录；主库若已
存在，必须是同卷 regular、single-link 文件。普通 repository 只用 SQLite URI `mode=rw`
打开，缺库时 typed 失败，绝不让 `sqlite3.connect()` 隐式创建。只有 migration runner 可以
首次创建：POSIX 通过父 dir-fd 执行 `O_CREAT | O_EXCL | O_NOFOLLOW` 并复核 owner、single-link
与 `0600`；Windows 通过 `CreateFileW(CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT)` 和当前进程
TokenUser SID 的 protected 单 ACE DACL 创建，并从创建 handle 反查 owner/DACL、对象类型、
link count 与最终路径，然后 SQLite 仍以 `mode=rw` 打开这个已创建文件。

guard 在 SQLite 打开前、连接 PRAGMA 完成后和连接关闭前复核父目录与主库 identity/link
count。已有 `-wal`、`-shm` sidecar 在 SQLite 解释前也必须是同父目录下的 regular、
single-link、非 reparse 文件；连接创建的新 sidecar 在返回业务代码前及关闭前再次安全打开并
锚定。任何 rollback journal 存在时均 fail closed，不尝试猜测或自动恢复。Windows 持有父
目录与主库 handle 时不共享 delete；POSIX 持有父 dir-fd 与主库 fd。这样可阻断静态 hardlink
写穿、junction/symlink 逃逸以及普通检查后交换，并让异常只暴露 reason code 而不包含主机
绝对路径。

Windows 的 WAL/SHM 句柄使用 `FILE_SHARE_DELETE`，因此 SQLite 在最后一个连接关闭时可以先
删除 sidecar 的目录项，而 authority guard 仍短暂持有同一个 delete-pending 文件对象。该对象
的 link count 会从已验证的 `1` 变为 `0`；这不是 hardlink。guard 只对“先前已完整验证且
identity 未变”的 sidecar 接受这一单向退役状态，仍拒绝 `link count > 1`、reparse、非磁盘
regular file 或 identity 变化。随后先释放退役句柄，再对当前路径重新执行完整的路径、
identity、reparse 与 single-link 校验并重新锚定；不得把任意 `nlink != 1` 错误都忽略，也
不得在未验证新路径的情况下沿用旧 sidecar 权威。

数据库覆盖多个 run。`event_id`、`case_id` 和 `frame_id` 是稳定语义标识，同一输入在不同
run 中可以重复，因此所有运行内实体使用 `run_id` 参与操作主键和外键：

- case 主键为 `(run_id, case_id)`，并唯一约束 `(run_id, event_id)`；
- frame 主键为 `(run_id, frame_id)`；
- pack 主键为 `(run_id, pack_id)`，并唯一约束 `(run_id, case_id, version)`；
- audit 主键为 `(run_id, sequence)`；
- repository 和 application 接口不得只用 `case_id` 在全局数据库中定位案件。

`manifest_id` 仍是内容寻址的全局标识；run 记录引用不可变 manifest。跨 run 回归可以比较
相同语义 ID，但不得把一个 run 的可变状态写入另一个 run。

M2 的首个版本迁移至少创建：

- `schema_migrations`
- `run_manifests`
- `runs`
- `frames`
- `cases`
- `case_versions`
- `evidence_packs`
- `media_assets`
- `evidence_pack_crops`
- `retention_holds`
- `audit_entries`

`case_versions`、`evidence_packs`、`run_manifests` 和 `audit_entries` 是 append-only；SQLite
trigger 拒绝 `UPDATE` 与 `DELETE`。`cases` 只保存当前 revision、状态和头部引用。媒体的
相对路径、可用状态、TTL 和清除时间保存在 `media_assets`，不写入 pack 的语义投影。
`evidence_pack_crops` 提供 pack 到媒体的强外键和 retention 反向索引。

规格中其余第一阶段表在首次业务写入它们的里程碑中先迁移后实现：M3 创建 verdict、
procedural defect、model cache 与 backlog 表；M5 创建 alert/outbox、precedent/citation、
appeal 与 training label 表。不得在 M2 创建没有字段约束的占位表。

迁移使用仓库内按序命名的不可变 SQL 文件和等价于 Alembic 的轻量 runner：

- `schema_migrations` 保存版本、名称、SQL SHA-256 和应用墙钟；
- 已应用文件的 SHA-256 变化时拒绝启动；
- 每个迁移在独立事务中执行，失败不推进版本；
- 除迁移 runner 的首次 bootstrap 外，业务代码不得执行建表 DDL；
- 外键使用 `ON DELETE RESTRICT`，历史记录不得级联删除。

每个 SQLite 连接必须设置并核验：

```text
PRAGMA foreign_keys = ON
PRAGMA journal_mode = WAL
PRAGMA synchronous = FULL
PRAGMA busy_timeout = <配置中的固定毫秒数>
PRAGMA trusted_schema = OFF
```

所有标识符来自静态代码，值使用参数化查询；禁止启用可加载扩展。JSON 列保存 UTF-8
LCJ-1 canonical JSON，写入和读取时均重新通过对应 Pydantic contract 校验。数据库中的
document hash 对 canonical JSON 字节计算，不使用投影文件的路径或尾随换行。

上述 writer guard 不是 custom SQLite VFS。Python 标准库 SQLite 在 guard 检查后仍按绝对
路径重新打开主库和 sidecar；连接后的 identity 复核能发现普通替换，但无法保证在路径打开
与复核之间完全没有写入，也无法排除具备相同进程权限、能在检查间完成完美 identity/hash
ABA 的攻击者。消除此残余边界需要 custom VFS、操作系统快照或把工作区权限提升为独立安全
边界，超出 M2。实现和文档不得把当前方案表述为“SQLite 全程句柄打开”。

一次案件状态变更、case version、pack 元数据和对应 audit entry 必须在同一个
`BEGIN IMMEDIATE` 事务中提交。未来关闭案件与 alert outbox 也必须复用这个事务边界。
乐观 revision 或 audit head 不匹配时抛出 `ConcurrentModification`，不得覆盖新状态。

同一 event 在同一 run 重试返回既有 case。同一 pack 构建输入先计算不含版本号和本机路径的
`pack_input_sha256`；唯一约束 `(run_id, case_id, pack_input_sha256)` 保证重试返回既有
pack/version，而不是因为重新分配版本号产生另一个 `pack_id`。内容寻址目标已存在但 hash
不同时视为完整性错误，不覆盖原文件或记录。

数据库事务提交后才生成 JSON/JSONL 投影。projector 总是从数据库有序读取，不直接向
JSONL 追加。投影失败不回滚已经提交的权威状态，而是以 typed application failure 结束当前
命令；后续重建仍只以 SQLite 为来源。

最初的逐文件原子替换只能保证单个文件完整，不能让多文件集合原子可见。当前实现按
ADR 0012 先发布不可变、内容寻址的完整 generation，再以单个
`<run_id>/projections/current.json` 作为唯一可信提交点。旧固定路径、未被 current 引用的
完整代或半成品代都不是可信 current。

## 理由

稳定语义 ID 不包含 run，因此把它们误作全局操作主键会让重放互相覆盖。数据库与 JSONL
双写也无法形成单一原子事务。用一个工作区数据库保存状态、以 run 复合键隔离实例，并把
文件定义为原子重建投影，可以同时满足幂等、并发、审计和后续 outbox 的事务要求。

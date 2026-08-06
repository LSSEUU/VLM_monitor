# ADR 0007：逐运行 LCJ-1 审计哈希链

- 状态：Accepted
- 日期：2026-07-27

## 决策

审计链以 run 为作用域，每个 run 独立从 sequence `0` 开始。genesis hash 固定为 64 个
小写 ASCII 字符 `0`：

```text
GENESIS = "0000000000000000000000000000000000000000000000000000000000000000"
```

每条审计记录的 body 恰好包含：

```text
schema_version
run_id
sequence
actor
action
object_ref
before_sha256
after_sha256
manifest_id
recorded_at
```

`actor` 使用受限匿名 token 或固定系统角色，不保存姓名、邮箱、工号等直接身份信息；
`object_ref` 使用 typed artifact reference。`before_sha256` 与 `after_sha256` 是相应领域对象
canonical document 的 hash，可以为 null，但两者不得同时为 null。`recorded_at` 是规范 UTC
墙钟字符串，只用于运维审计，不进入业务 ID 或 `semantic_case_hash`。

LCJ-AUDIT-1 的精确计算为：

```text
body_bytes = UTF8(LCJ-1-canonical-json(body))
entry_hash = SHA256(ASCII-lowercase-hex(prev_entry_hash) || body_bytes)

stored_entry = body + {
    "prev_entry_hash": prev_entry_hash,
    "entry_hash": entry_hash
}
```

这里 `body` 不包含两个 hash 字段；不存在分隔符、换行、BOM 或额外 domain wrapper。
`prev_entry_hash` 固定为 64 字节小写 ASCII hex，所以拼接边界无歧义。sequence `0` 使用
GENESIS，sequence `n` 使用同一 run 中 sequence `n-1` 的 `entry_hash`。任何算法变化都使用
新的 audit schema/algorithm version，旧链按原版本验证。

数据库是审计权威。每个 run 的 `runs` 行保存 `audit_head_sequence` 和
`audit_head_hash`。追加过程必须在与业务状态修改相同的 `BEGIN IMMEDIATE` 事务中：

1. 读取并锁定 run 的当前 revision 与 audit head；
2. 计算下一个连续 sequence 和 hash；
3. 插入 `audit_entries`；
4. 以旧 revision/head 为条件更新 `runs` 头；
5. 提交业务状态和审计记录。

主键 `(run_id, sequence)`、唯一 hash 约束、乐观 head 条件与 SQLite 单写者事务共同防止链
分叉。条件失败抛出 `ConcurrentModification` 并整体回滚。不得为一次幂等、没有状态变化的
重试追加一条伪业务变更；投影恢复可以写独立的运维诊断，但不改变案件语义 timeline。

`audit_entries` 使用 trigger 禁止更新与删除。验证器按 sequence 读取整个 run，检查从 0
开始连续、prev 相等、body schema 合法、hash 重算一致、最后一条与 runs head 一致，并返回
首个失败 sequence 和 typed reason。媒体按 retention 清除后必须追加
`PURGED_BY_RETENTION`，其 object ref、清除前媒体 hash 和 manifest 仍保留。

`audit.jsonl` 是数据库链的可重建投影。每行是包含两个 hash 字段的完整 stored entry，使用
LCJ-1 canonical JSON UTF-8 字节和单个 `LF`，文件以 `LF` 结尾。projector 在写文件前验证
数据库链，写同目录临时文件并 flush/fsync，重读验证后原子替换正式文件；不得直接向正式
文件追加。投影验证同时检查行顺序、重复/缺失行和最后 hash 与数据库 head 一致。

该哈希链提供意外损坏和非协调篡改的可检测性，不是数字签名。能够同时改写数据库、文件和
程序的高权限攻击者仍可重算整条链；生产化的远端锚定、签名或 WORM 备份属于 M8，而不是
M2 的能力声明。

## 理由

若 sequence、genesis、前像字段或字符串编码不固定，不同实现会生成互不兼容的“合法”链。
把 append 与状态修改放在同一 SQLite 事务，并把 JSONL 降为原子重建投影，消除了业务记录
存在但审计缺失以及文件半行导致的双写不一致。


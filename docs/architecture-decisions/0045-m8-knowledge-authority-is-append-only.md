# ADR 0045：M8 知识目录、原文与回答收据采用追加式权威存储

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.5 knowledge migration、repository port、catalog/content/answer commit

## 背景

知识检索需要在重启后证明回答使用了哪一版目录、哪一组原始字节和哪一个当时有效的请求人权限。
只持久化回答文本或只保留最新文档会破坏历史重放；由客户端提交角色、目录或内容摘要又会绕过 M8.3
已经建立的持久化权限边界。

## 决策

1. 独立 M8 migration 0005 追加 raw content、catalog version、catalog-document link 和 answer receipt
   四类表；全部禁止 update/delete/replace。
2. catalog 发布在一个 `BEGIN IMMEDIATE` 事务中校验连续 revision、expected-prior CAS、完整 raw
   inventory、逐字节 size/SHA-256、raw-storage manifest 与 repository manifest；任一冲突整体回滚。
3. raw content 与不可变 document authority 一一绑定。相同 catalog revision 只有在 catalog、前序期望、
   raw bytes 和 storage manifest 全部相同时才作为幂等重试返回。
4. answer 提交前由仓库读取指定 catalog ID 的当前最高 revision，并从 actor authority 表读取请求人的当前
   revision；目录已经换版、actor 已停用或 authority ID 不一致时拒绝提交。
5. answer receipt 永久绑定 exact answer、catalog authority、requester actor authority、actor document hash、
   adapter manifest 和 repository manifest。历史读取验证当时的 actor receipt，而不要求它仍是当前 revision。
6. 仓库只记录检索证据，不修改 Case、不发布规则、不执行处分，也不调用网络、GPU、embedding 或模型。

## 结果

- catalog/content/answer 在断电边界内原子提交，重启后可用 canonical receipt、索引列、link 和 raw hash
  交叉验证。
- 当前权限与当前目录决定新回答能否落库；权限或目录换版不会抹去已经提交的历史回答。
- 普通知识文档继续不能成为案件规则或自动处分依据。
- authenticated loopback API 可以只接受查询意图，再由服务端解析当前 actor 与当前 catalog。

## 未选择的方案

- **可更新的知识表**：会覆盖回答当时引用的版本与原始字节。
- **仅保存 answer text**：无法证明 citation、目录、权限与 adapter manifest。
- **信任客户端 actor/catalog authority**：允许过期或伪造权限、目录参与新回答。
- **知识发布时自动更新规则或 Case**：违反知识证据与裁决权威隔离。

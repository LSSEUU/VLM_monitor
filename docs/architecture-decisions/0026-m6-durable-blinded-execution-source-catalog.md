# ADR 0026：M6 执行 source catalog 采用独立、不可变的本地内容寻址存储

- 状态：Accepted（端口、纯绑定门与本地文件 store 已实现）
- 日期：2026-08-04
- 影响范围：回归数据集发布、candidate execution scope、崩溃恢复与执行编排

## 背景

候选执行数据集只保存 `source_catalog_authority_id` 与 `source_catalog_document_sha256`，不会重复嵌入完整
`M6RegressionExecutionSourceCatalogAuthority`。这是必要的盲化边界：catalog 包含执行所需的 replay input
closure，但不能把 evaluator 的集合标签、金标或预期裁决泄漏给候选执行器。因此 coordinator 在开始
candidate scope 前，必须能够按这两个身份恢复完整、candidate-safe 的 catalog。

现有两类持久化都不适合承担该职责：`M6SourceAuthoritySeal` 的 wire 已冻结且只允许五类单样本 source
文档；`M6RegressionStore` 以最终 regression report 为 commit point，发生在候选执行完成之后。把 catalog
写入候选 run SQLite 还会把可跨 candidate run 复用的 baseline 依赖错误地绑定到某一个候选数据库，并混淆
evaluator 发布边界与 candidate ledger 边界。

## 决策

1. 新增独立 publisher/provider 端口。publisher 只接受 exact typed catalog 与它的 canonical JSON；provider
   只接受 `(source_catalog_authority_id, source_catalog_document_sha256)`，不接受路径、候选替代值或扫描条件。
2. catalog 使用本地 owner-only `SecureWorkspace` 发布到由双身份决定的固定内容寻址路径。单个 canonical
   文档就是 commit point；发布通过 staging 后原子、no-replace rename 完成，因此不新增 SQLite migration
   0016，也不新增可漂移的数据库 projection。
3. 文档总上限固定为 256 MiB。发布和读取都验证 exact Pydantic type、canonical JSON、computed authority ID、
   UTF-8 SHA-256 与字节数；错误只通过 payload-free typed code 暴露。
4. 逐字节相同的发布是幂等的。commit 前崩溃只留下不可解析的 staging 文件；精确重试可以继续发布。
   commit receipt 丢失时，publisher 只按同一双身份做完整 readback；目标已存在但内容不同则拒绝且不覆盖。
5. provider 永远不扫描其他 catalog。错误身份指向不存在的固定地址时返回 `CATALOG_NOT_FOUND`；只有该地址
   确实存在但物理 hash 或正文 authority 不符时才返回 `IDENTITY_MISMATCH`。
6. 纯 application binding gate 必须把已加载 catalog 与 durable execution scope 双向闭合：baseline manifest、
   catalog authority/document SHA、entry 数量和顺序，以及每项 sample、input authority、replay closure 的
   authority ID 与 document SHA 必须完全一致。
7. coordinator 的固定顺序是：发布并回读 source catalog，构造并提交 execution scope，随后才允许执行第一
   个 candidate sample。恢复时从 scope 中取得双身份加载，不跟随目录尾部或 evaluator 当前状态。

## 后果

- 完整 replay input closure 可以跨进程和崩溃恢复，同时 evaluator-only truth 仍不会进入 candidate dataset。
- baseline catalog 可被多个候选 run 精确复用，不需要复制进每个候选 SQLite。
- 孤立 staging 文件没有 commit 语义，也不会被 provider 发现。
- coordinator 仍需实现 catalog publish/load/bind 与 V3 ledger begin 的顺序编排；本 ADR 不把 source catalog
  当作候选 Case 的 M4/Gate authority。

## 被拒绝的方案

- 扩展冻结的 `M6SourceAuthoritySeal`：会改变既有五文档 inventory 与 wire/hash 语义。
- 把 catalog 延后写进最终 `M6RegressionStore`：candidate 执行开始时尚无可恢复输入。
- 新增 candidate SQLite 0016：错误耦合 baseline 依赖和 candidate run，且降低跨 run 复用性。
- provider 扫描目录并选择“最接近”的 catalog：允许错误身份静默替换，破坏盲化数据集与 scope 的 exact join。

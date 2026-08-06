# ADR 0024：M6 以两阶段计划重建 M5 历史先例物理闭包

- 状态：Accepted（已实现）
- 日期：2026-08-04
- 影响范围：M6 upgrade metadata plan、M5 query/embedding 恢复、whole-sample record

## 背景

M6 Observation V2 只记录候选执行实际观察到的 M5 artifact 身份与 usage，不能声明
digest、正文大小或历史 authority 内容。`m5_precedent_exposures` 的规范化列保存 Exposure
身份、M4/M5 query ID 和策略绑定，却没有单独保存 query embedding 正文；query vector 只嵌在
`exposure_json` 中。另一方面，历史 precedent embedding 有独立的
`precedent_embeddings.embedding_json` durable authority。

如果为了生成 Pending record 而提前读取 `exposure_json`，已有 Pending commitment 的冲突重试就会
在发现逐字节不一致之前读取 M5 正文，破坏 ADR 0021 的两阶段承诺。如果省略 query embedding，
则成功 retrieval 的 replay closure 不完整。如果新增 sidecar，又会在当前 deterministic fake 路径已经
可以纯重建时制造新的写入和迁移权威。

## 决策

1. M5 physical route 使用与 M3/M4/acquisition 相同的 `metadata plan -> Pending exact compare ->
   canonical body resolve` 顺序。Pending 比较前不得读取 Exposure、precedent authority、embedding
   或 M4 retrieval 的 JSON 正文。
2. M5 relevant cycle 只来自已验证的上游 M4 plan。只有 retriever version 与 manifest 同时等于冻结的
   M5 hearing bridge 常量时，该 cycle 才进入 M5 closure；半匹配、孤儿 Exposure 或跨 cycle 绑定全部
   fail closed。成功 cycle 必须恰有一个 Exposure，降级 cycle 必须没有 Exposure。
3. 当前 query embedding 不新增 sidecar。planner 从 execution scope 中已冻结的 AppConfig/RunManifest、
   selected Case 内嵌的完整 EvidencePack 历史，以及 M4 hearing/cycle/retrieval 规范化列重建
   `HearingSession`、`HearingCycleScope` 和 `HearingPrecedentRetrievalQuery`。它必须钉死 bridge 常量，
   逐字段验证 query SHA/ID、policy、model manifest 和 Exposure 的规范化 M4/M5 query ID，再调用
   `derive_m5_query_for_hearing` 纯函数得到唯一 TEXT query vector。该路径不得调用 embedding provider、
   cache、网络或恢复服务。
4. planner 从 Observation 取得待验证的 Exposure/Embedding 身份，但 digest、canonical byte size 与
   physical ref 只来自 durable normalized authority 或上述纯派生。Observation 不是历史 membership
   真相；正文阶段必须从 Exposure 的完整 M5 result 重新计算 query 与全部 candidate embedding exact set，
   拒绝 Observation 的缺失、额外、重复或 scope collision。
5. Exposure 所含每个历史 candidate authority 必须与 durable `(precedent_id, revision)` 相等，其 nested
   text/visual vectors 必须与 durable embedding rows 相等。为避免正文打开后出现未预检的跟随读取，
   metadata plan 在 Pending 前冻结候选 precedent revisions、相关 embedding rows、rowid、正文摘要与大小；
   这些只进入 bounded support plan，不自动制造 sample physical links。
6. query embedding 的 sample usage 为 `PRODUCED`，历史 precedent embedding 为 `CONSUMED`，Exposure 为
   `PRODUCED`。公开 Observation/Record wire 继续允许既有枚举；该语义在能看到 resolved embedding scope
   的 additive M5 authority validator 中执行，pure Record composer 只原样保存已验证的 Observation usage。
7. metadata 与 body resolver 必须在同一只读 B snapshot 中重建逐字段相同的 plan identity。正文恢复后的
   physical refs 必须与 Pending 前 planned refs 逐字段相同；有 Pending commitment 时，任何 M5 正文、
   M3/M4 Raw 或 Pixel 读取都只能发生在 commitment record 精确相等之后。
8. 若未来生产路径允许非 deterministic/provider-produced query embedding，则必须增加独立、追加式、
   可预检的 query-embedding durable authority（或等价 sidecar）并另写 ADR；不得从自由文本、Observation
   claim、当前 precedent head 或 Exposure 以外的可变状态猜测 vector bytes。

## 结果

- 当前默认离线路径无需 schema 迁移或外部模型调用即可完整记录 query 与历史 precedent embeddings。
- Pending 冲突继续保持 M5 body、Raw 与 Pixel 零读取；崩溃重试只能重建同一组 canonical record bytes。
- 后续 precedent revision 的撤销或替换不能改写已封存 Exposure 中的历史 ACTIVE authority。
- 支持文档与 physical links 明确分离：完整因果验证不会把未被 Observation 记录的历史 revision 自动加入
  当前 sample record。

## 放弃的方案

- **在 Pending 前读取 `exposure_json`**：破坏两阶段 exact commitment 边界。
- **只记录 durable precedent embeddings**：会静默丢失成功 query embedding。
- **只相信 Exposure 内嵌历史 authority**：无法发现 durable revision 或 embedding 被替换、缺失或篡改。
- **立即新增 query sidecar**：当前纯 deterministic 路径不需要新的持久化权威；增加迁移只会扩大故障面。
- **使用当前 precedent heads 重建历史集合**：未来合规状态会重写过去可见事实，违反 STRICT_CAUSAL。

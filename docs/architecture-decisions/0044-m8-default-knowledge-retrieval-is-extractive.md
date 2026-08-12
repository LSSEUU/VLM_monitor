# ADR 0044：M8 默认知识检索是离线确定性逐字引用

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.5 knowledge retriever port、synthetic fixture、lexical ranking、raw content access

## 背景

默认演示必须在无网络、无 GPU、无 embedding 和无模型 API 的环境回答校园安全问题，同时保证回答中的每段
文字都能在 exact document bytes 中定位。自由生成摘要或不固定 chunk/ranking 会使同一 query 无法重放，
也可能把普通文档表述误写为案件规则。

## 决策

1. retriever port 只暴露 exact catalog、typed query、query-ID replay 和 raw content read。所有边界失败使用
   closed reason code，不返回猜测结果。
2. adapter 初始化时要求 content-ref key inventory 与 catalog 完全一致，并逐文档校验 raw bytes size、
   SHA-256、严格 UTF-8 和受控字符；缺失、多余、损坏或不可解码内容均 fail closed。
3. 默认 fixture 使用六份显著合成/通用的中文 Markdown，覆盖制度、SOP、历史案例、应急预案、设备资料和
   FAQ；不含真实人员或未经脱敏现场图像。
4. chunk 使用原文非空行及固定 2000 字符上限，保留原文字符 offset。ranking 只计算 query 与 chunk 的
   小写 ASCII token/CJK 字符集合交集，再按 score、logical ID、version、chunk 和 offset 稳定排序。
5. 只检索 query as-of 时有效、locale/type 允许的文档。answer text 由 ranked citation snippets 逐字拼接；
   无匹配返回 typed no-match。adapter 不调用网络、模型、墙钟、随机数或 Case repository。

## 结果

- 相同 catalog/query/content bytes 始终得到相同 answer ID、citation 顺序和 raw offset。
- 展示层可回读 exact bytes 并验证 source/version/effective date/snippet hash。
- 默认离线问答不声称语义理解、检索准确率或模型能力，也不能发布规则或改变 Case。
- 下一切片可以把 catalog/content/query-answer receipt 原子持久化并接入 authenticated loopback API。

## 未选择的方案

- **默认 embedding 或 LLM RAG**：需要网络/模型并引入不可重放生成内容。
- **模糊自由文本 parser**：无法保证 typed document scope 与引用边界。
- **返回改写摘要**：无法证明每句话来自 citation snippet。
- **允许未在 catalog 中的临时内容**：绕过版本、生效期、manifest 和完整性 hash。


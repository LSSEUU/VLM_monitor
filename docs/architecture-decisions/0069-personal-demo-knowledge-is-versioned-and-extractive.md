# ADR 0069：个人 Demo 知识库保持版本化与抽取式引用

## 状态

Accepted for the offline personal Demo.

## 背景

知识仓库、确定性检索和 API 已存在，但默认 Demo 数据库没有 catalog，界面无法展示带来源问答。临时返回
硬编码答案会绕过文档版本、生效时间、内容哈希和 requester authority。

## 决策

API 装配时幂等提交既有六类离线知识 fixture：制度、SOP、合成历史案例、应急预案、设备资料和 FAQ。
catalog 使用固定生成时间、原始内容字节与 manifest；冲突 revision fail closed。查询继续经过 existing
`M8KnowledgeApiService` 与 deterministic offline retriever，回答只由 exact citation snippet 组成。

typed Demo receipt 固定声明不使用模型或网络，普通知识文档不能定义案件规则或直接作出案件决定。每个
citation 保留 source reference、document version、effective date 和 span hash。

## 后果

本机 API 和独立 UI 可以展示可追溯问答，不需要云模型或网络。未来 Agent 可总结检索结果，但不能绕过
catalog authority、伪造 citation 或把普通文档静默升级为风险/裁决规则。

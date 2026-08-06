# ADR 0003：验证流水线、程序门与告警类型

- 状态：Accepted
- 日期：2026-07-27

## 决策

模型响应依次经过：

1. JSON 与 Pydantic 结构解析；
2. 引用白名单诊断；
3. Verdict 程序审查；
4. 生成 tentative `AlertDecision`；
5. AlertPolicy 不变量检查；
6. 事务写入 outbox。

结构解析失败也生成结构化 `ProceduralDefect` 诊断，但不伪装成一个已通过 Pydantic 的
正常 Verdict。未知引用不得被“纠正”或静默删除；adapter 保存
`attempted_unknown_refs` 与原始响应引用，使程序门能产生
`FABRICATED_EVIDENCE_REFERENCE`。

系统区分两种通知：

- `AdjudicatedAlert`：必须先有 Verdict 并通过全部程序与策略门。
- `EmergencySafetyIncident`：来自认证 `SafetySignal`，允许先发送后补充最小事件审计。

界面和工件不得把后者描述成已经审判的违规判决。

## 理由

程序审查无法检查一个根本不能解析的对象；同时，若在审查前丢弃未知引用，审查器就失去
发现伪造引用的证据。硬安全信号不能等待 VLM，但也不应冒充已经完成的案件裁决。


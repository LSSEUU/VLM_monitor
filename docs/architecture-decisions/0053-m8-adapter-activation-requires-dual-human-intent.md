# ADR 0053：M8 真实适配器激活先形成双人 intent 且 intent 不执行外部调用

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.7 adapter activation intent、后续 activation persistence/runtime gate

## 背景

完整 commissioning evidence 只表示候选适配器具备进入人工激活流程的条件，不等于允许系统自行连接外部服务。真实 RTSP、OIDC、消息或物理信号会改变数据流、隐私边界和运营风险；单一 `enabled=true`、Agent 建议或单人操作不足以构成生产授权。

## 决策

1. readiness 完整后仍必须创建独立 `M8AdapterActivationIntentV1`；BLOCKED assessment 不能进入 intent。
2. intent 同时绑定 active、in-scope、彼此不同的 OPERATIONS 与 SAFETY_OFFICER authority receipt，且两者均显式确认。
3. intent 绑定 exact readiness assessment、无密钥 runtime config ref/hash/size、credential secret-store reference、显式 UTC 和 activation manifest；网络 adapter 缺少 secret reference 时 fail closed。
4. readiness evidence、operations actor 和 safety actor 必须来自同一 repository manifest，跨仓库嫁接拒绝。
5. intent 固定 `activation_commit_permitted=true`，但 `external_call_permitted=false`、`automatic_activation_permitted=false`。只有后续持久化 gate 再次解析当前双人 authority、验证 runtime config 原始字节后，才能产生独立 activation commit。
6. intent 永不授予生命安全联动、纪律处分、人脸识别或跨摄像头 ReID。

## 结果

- readiness、人工决策、持久化激活和实际外部调用成为四个可审计且不可跨越的阶段。
- Agent 可以总结材料或提示缺项，但不能代替任一人工确认，也不能通过构造 intent 调用 adapter。
- secret 只以外部 secret-store reference 出现，不进入 schema、日志、fixture 或 commit。
- 后续 activation repository/runtime runner 可以分别验证“允许落盘”和“允许调用”，避免一条命令同时越过全部边界。

## 未选择的方案

- **readiness 自动激活**：把评估结论升级为关键生产动作。
- **单个运维人员确认**：缺少校园安全责任人的独立判断。
- **把用户名密码放进 runtime config**：泄露 secret 并污染持久化工件。
- **intent 直接调用 SDK**：无法在调用前完成当前权限、原始配置和审计 commit point。

# ADR 0051：M8 真实适配器必须先闭合准入证据且不能自动激活

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.7 production adapter candidate、commissioning evidence、readiness assessment

## 背景

M8.7 将来需要接入 RTSP、物理传感器、OIDC、外部消息、监控和灾备系统。这些边界会引入网络、凭据、第三方许可、现场安全和运营连续性风险。仓库目前只有默认离线 fake，既没有已选定厂商，也没有许可证批准、校园安全评审、现场验收或灾备演练工件；因此不能因为某个 SDK 能建立连接就宣称具备生产启用资格。

## 决策

1. 所有真实适配器先登记为内容寻址 candidate，固定类型、版本、provider、校园/地点范围、timeout、幂等键、raw receipt、manifest 和不同于生产适配器的离线 fallback。
2. 类型与幂等键使用闭合矩阵：camera/sensor 使用 source sequence，OIDC 使用 subject assertion，通知使用 notification ID，监控使用 export batch，灾备使用 backup generation。
3. candidate 本身固定禁止生产激活、生命安全联动、纪律处分、人脸识别和跨摄像头 ReID，也不能嵌入 secret material。
4. readiness 必须同时拥有许可证评审、安全评审、校园安全评审、现场验收和离线 fallback 演练五类证据；每类证据绑定 exact candidate、人工 reviewer authority、UTC、结果、raw artifact ref/hash/size 和 manifest。
5. 评审与现场证据不能标为模拟；只有离线 fallback 演练允许显式 simulated。任何 evidence 都固定 `model_generated=false`，不能由 AI 生成现场事实。
6. readiness 只消费 evidence commit receipt；receipt 绑定 evidence canonical document、原始工件及 storage/repository manifest。缺失、失败、过期、重复、未来时间、越权 reviewer 或跨 candidate 嫁接均 fail closed。
7. 即使 readiness 为 `READY_FOR_HUMAN_ACTIVATION`，仍固定 `production_activation_permitted=false`。后续必须由独立、显式人工 activation authority 和持久化当前权限检查完成启用。

## 结果

- 未提供厂商凭据时仍可离线冻结生产准入边界，而不会偷跑真实连接。
- “能连上”与“允许生产启用”被明确分离，测试 fixture 不能冒充现场验收成绩。
- 任何后续真实 adapter 都必须带 timeout、幂等、raw receipt、manifest、许可证与回退证据。
- 生命安全资格仍由已验证传感器/消防 authority 单独决定，commissioning readiness 不授予该资格。

## 未选择的方案

- **直接集成首个可用 SDK**：缺少厂商选择、许可、安全评审、凭据治理和现场证据。
- **把配置文件中的 `enabled=true` 当作生产授权**：绕过人员权限、证据和审计。
- **允许 readiness 自动启动 adapter**：把评估结果升级为关键动作，违背明确人工确认边界。
- **用模型总结或测试 fixture 代替现场证据**：无法证明许可证、安全性或真实环境行为。

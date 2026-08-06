# ADR 0001：规格权威与 v0.1 范围

- 状态：Accepted
- 日期：2026-07-27

## 决策

`docs/request.md` 解释产品愿景；`docs/spec/labcourt-vibe-coding-spec.md` 是实现权威。
当两者在因果确认、硬安全信号、模型版本、训练标签质量或真实模型范围上冲突时，
采用可执行规格中的显式修正。

v0.1 先交付无 GPU、无网络的模块化单体纵向切片。演示重点是两个规则
`PPE_GOGGLES_MISSING`、`REAGENT_CONTAINER_OPEN` 和一个认证硬安全信号 fixture；
其余规则保留完整契约和测试场景，但不声称已完成现场感知验证。

真实 OpenAI-compatible 调用、真实 embedding、完整 HTTP API、RTSP 和生产身份体系均不
阻塞 v0.1。离线报告必须显著标记 `SIMULATED PERCEPTION / FAKE VLM`。

## 理由

产品价值是把有噪声的视觉怀疑转为可解释、可复现、可申诉的处置，而不是尽早接入更多
模型。薄穿全部关键层可以先验证系统信任内核，也避免用模型演示掩盖流程缺陷。


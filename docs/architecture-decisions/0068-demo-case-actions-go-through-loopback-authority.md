# ADR 0068：Demo 案件动作必须经过 loopback authority

## 状态

Accepted for the personal Demo operator flow.

## 背景

本机 API 已具备完整状态机与权限校验。若 Windows 演示脚本直接修改 SQLite 或在客户端复制案件状态机，
展示路径会绕过 current actor、源版本、审计和并发保护。

## 决策

增加 safety-officer 专用客户端，只允许确认、驳回、请求补证、返回核实和结案五个既有动作。客户端从 ignored
local access 读取 safety token，先 GET current Case，再构造 `M8ApiCaseTransitionRequestV1`，要求操作者输入
`APPLY` 后单次 POST。响应必须严格解析为 `M8OperationalCaseCommitReceiptV1` 并本机留存。

客户端不接受 actor authority，不提供领导或运维 token 选择，不自动重试，也不推断 action/reason。非法源
状态、过期版本或服务端拒绝均作为失败返回。

## 后果

个人 Demo 可以完整演示待核实、补证、确认、驳回和结案，同时所有变更仍由正式 repository 与审计链提交。
该便捷入口不属于生产工作台；后续 UI 只需复用相同 HTTP request，不得获得更宽权限。

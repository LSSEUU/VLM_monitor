# ADR 0041：M8 通知编排从持久化状态构造确定性请求并逐步原子提交

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.4 card rendering、queue、dispatch、delivery、ack/reply application service

## 背景

契约、outbox 与 channel adapter 已存在，但若调用端自行拼装 source fence、attempt、actor 或 manifest，仍会
出现旧版本发送、换版 actor 回复、崩溃重试生成不同请求，以及 raw response 未随状态提交的问题。需要一个
不隐藏权限判断、也不拥有 Case 迁移能力的最小编排层。

## 决策

1. workflow manifest authority 一次固定 card renderer、dispatch request、transition command、raw storage、
   audit 和 workflow manifest；system queue/retry 使用其 content ID 作为 automation authority。
2. service 每一步先读取当前 persisted notification；actor action 还必须从 operations repository 解引用当前
   actor。repository 在提交时再次解引用并校验，避免读写间换版绕过。
3. system queue 仅适用于 policy 不要求人工发送确认的 plan。要求确认时必须由当前 active
   `SAFETY_OFFICER` 显式 queue；contract/repository 保持最终权限裁决。
4. 本地 card 使用 exact plan、template authority、Case version/hash、target 和 renderer manifest 生成
   canonical JSON，并显著标记 `SIMULATED`。card action 不等于 Case action或纪律处分。
5. dispatch 的时间从已持久化 queue/retry command UTC 派生，attempt 从 audit chain 计数；因此进程在外部
   接受后、outbox 提交前崩溃时，重试仍生成同一 request ID 和 provider idempotency key。
6. dispatch、delivery 和 reply 分别读取 adapter/输入的 exact raw bytes，并通过 ADR 0039 repository 与状态
   和 audit 原子提交。dispatch accepted 不越级为 delivered；本地 delivery 永远是 simulated。
7. reply actor 由仓库解析，raw reply 只进入受控 BLOB 与 hash/reference receipt。reply authority 固定禁止
   Case transition；service 不调用任何 Case transition 方法。

## 结果

- 默认离线演示可从 `PLANNED` 走到 `QUEUED -> SENT -> DELIVERED -> RESPONDED`，每一步可重启重放。
- 人工发送策略、actor 换版、source fence、raw hash 和 manifest 冲突仍由多层 fail-closed 校验保护。
- Case 在完整通知与回复闭环后保持原版本；后续案件动作必须走独立、授权、显式确认的 M8.3 API。
- 下一切片实现 response deadline/escalation authority 与有界路由，不把催办 Agent 变成定责或结案主体。

## 未选择的方案

- **客户端直接提交完整 transition command**：可注入 actor、source fence 或 adapter authority。
- **dispatch 时读取当前墙钟**：崩溃重试会改变 request identity，削弱 provider 幂等。
- **发送、raw 保存和状态提交由三个调用完成**：可能留下不可复核的部分状态。
- **收到回复即改变 Case**：绕过 M8.1/M8.3 的角色、原因、证据和显式人工确认边界。


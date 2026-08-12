# ADR 0042：M8 通知升级是只读逾期评估与角色路由建议

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.4 response deadline、escalation assessment、Agent 催办候选

## 背景

通知策略已给出响应期限、最大投递次数和升级角色，但催办 Agent 如果能直接迁移 Case、给学生定责或绕过
human-send policy，就会突破产品权限公理。升级判断还必须绑定当时的 exact notification version，不能只按
可变 current status 或自由文本摘要判断。

## 决策

1. escalation assessment 完整绑定一个 persisted notification commit receipt、显式 UTC 和 evaluator
   manifest，并使用 content ID；不读取墙钟、不调用模型。
2. `ACKNOWLEDGED` 与 `RESPONDED` 固定为 `RESPONSE_SATISFIED`；未到 `response_due_at` 为 `NOT_DUE`；
   其余状态到期后才是 `OVERDUE`。overdue 秒数使用确定性整数计算。
3. 只有 `OVERDUE` 返回 plan 内冻结的 escalation roles 和 `notification_plan_recommended=true`。route 不接受
   开放角色，也不能把责任升级给学生。
4. `system_queue_permitted_by_policy` 只反映原 plan 是否要求人工发送确认；它不是发送动作。真正 queue 仍须
   经过 ADR 0041 service、current actor/policy 和 append-only repository 校验。
5. assessment 永远固定 `case_transition_permitted=false` 与
   `direct_disciplinary_action_permitted=false`。列表服务只读取当前非终态通知，排序并有界返回逾期候选。

## 结果

- Agent 可以确定性总结“哪些通知逾期、应路由给哪些角色、是否需要人工发送确认”。
- 评估本身没有 side effect；重复评估不会写 outbox、发送消息或改变 Case。
- 已确认/已回复通知从候选列表消失；历史 assessment 仍绑定原 exact receipt，可用于审计。
- M8.4 的 outbox、fake channel、卡片回复和升级最小闭环完成，真实平台 adapter 仍另行启用。

## 未选择的方案

- **逾期即自动迁移 Case**：把通知 SLA 错当成事实裁决或处分依据。
- **Agent 自由生成收件角色**：绕过 frozen escalation policy 的闭合角色清单。
- **内部读取当前时间**：同一输入无法确定性重放。
- **到期即无条件自动发送**：忽略 human-send-confirmation policy。


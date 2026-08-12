# ADR 0065：模拟紧急飞书卡片只承载待核实案件建议

## 状态

Accepted for the Windows personal Demo only.

## 背景

固定连通卡片已经证明企业自建应用可以接受一条消息，但不能展示 LabCourt 的传感器、风险策略和案件建议
如何衔接。直接写入正式案件或复用通知 outbox 会把个人 Demo 冒充为已完成 activation 的运营 authority。

## 决策

增加独立的模拟紧急演示探针。应用层必须运行既有确定性离线烟雾场景，取得绑定 source/device/location、
simulation tick、raw signal reference/hash、adapter/fixture/policy/evaluator manifest 的 typed poll result 和
risk assessment，再构造红色飞书卡片。契约只接受 active simulated smoke、EMERGENCY candidate、人工核实
和待核实案件建议；卡片显著声明 `PERSONAL DEMO`、`SIMULATED` 与非认证消防检测。

探针不接受正式 case/notification authority，不读写 SQLite，不执行自动建案、生命安全联动、通知迁移、
定责、处分或结案。离线 check 不调用 provider；Windows live 入口继续要求输入 `SEND`，每次只调用一次，
回执不声明真实送达。

## 后果

个人 Demo 可以展示一条真实的 typed 业务链路，同时保持默认离线和既有 authority 不变。该回执不是正式
案件、通知、消防检测或 commissioning evidence；后续需要互动按钮、学生回复或案件状态迁移时，必须回到
activation-gated outbox/webhook 与有权限用户明确确认的路径。

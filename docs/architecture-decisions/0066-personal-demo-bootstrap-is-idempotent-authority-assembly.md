# ADR 0066：个人 Demo bootstrap 只幂等装配既有 authority

## 状态

Accepted for the local product demonstration.

## 背景

M8 的拓扑、角色、传感器、案件、审计和投影能力已有独立契约与仓库，但测试夹具不能作为用户可启动的
产品数据集。若演示脚本绕开仓库直接拼 JSON，后续界面和 API 会看到没有持久化事实支撑的假状态。

## 决策

增加固定、默认离线、可重复运行的 bootstrap。它通过既有 SQLite repositories 依次提交四层拓扑、单一
模拟烟雾源、四角色 authority、两条 raw sensor signal 与 poll cache，并在确定性风险策略建议后创建唯一
`EMERGENCY` / `PENDING_VERIFICATION` 案件。随后通过稳定读取服务生成运营投影，最终输出只包含 commit
引用和计数的 content-addressed typed receipt。

bootstrap 不接收自由文本规则、真实身份或正式通知输入，不调用网络、GPU 或模型，也不执行案件或通知
迁移。相同数据库上的 exact replay 必须返回同一回执；冲突 authority fail closed。

## 后果

个人 Demo 获得一份 UI 与本机 API 可共同消费的真实 SQLite authority，而不复制 M8 状态机。安全负责人
处置、学生说明、通知闭环和飞书 adapter 继续作为后续显式切片接入，不能由 bootstrap 回执授权。

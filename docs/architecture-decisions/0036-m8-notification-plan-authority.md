# ADR 0036：M8 通知计划绑定隐私安全目标、版本化模板和独立升级策略

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.4 通知计划、消息卡片、外部通道路由、响应期限与升级

## 背景

通知闭环既要支持本地离线演示，也要为飞书、企业微信、钉钉等真实 adapter 保留边界。若计划直接保存
明文账号、信任客户端角色、允许普通模板决定案件动作，或把写入本地文件声称为真实送达，就会破坏隐私、
权限和来源真实性公理。响应期限也不能依赖隐藏墙钟或未经验证的性能承诺。

## 决策

1. notification target authority 只保存 actor ID、identity provider、外部 subject binding SHA-256、通道、
   revision、active、回复能力和 manifest，不保存明文手机号、邮箱或平台账号。后续仓库必须解引用当前 target
   revision，客户端不能提交 target 文档扩大收件范围。
2. 默认 `LOCAL_OFFLINE_FAKE` 目标只能使用 `labcourt-local-fake` identity provider，并派生固定
   `SIMULATED · LOCAL MESSAGE` badge。外部通道不得复用 fake provider，fake 也不得伪装外部通道。
3. message-card template authority 绑定 template ID/version、locale、生效 UTC、内容文档 SHA-256、允许的
   purpose/channel 和 manifest。它固定 `ordinary_document_can_define_case_rule=false`，不能静默成为裁决规则。
4. escalation policy 绑定 risk、明确响应秒数上限、有限投递次数、升级角色、人工发送确认策略和 manifest。
   它固定 `case_transition_permitted=false`；不得把责任升级给学生，也不把响应时间写成未经现场验证的 SLA。
5. notification plan 绑定 exact Case version/hash/status、subject、risk、location、purpose/audience、当前 target、
   template、policy、显式 UTC planned time 和 manifest，初态只能是 `PLANNED`，idempotency key 等于内容寻址 ID。
6. Case subject 消息必须投递给 exact subject actor；领导只接收 `SEVERE/EMERGENCY` 重大事件计划。模板通道、
   purpose、生效时间和 policy risk 必须与计划一致，否则 fail closed。
7. 计划固定禁止直接纪律处分、案件状态迁移和真实外部送达声明。真实送达、失败、确认与回复必须由后续
   channel/outbox receipt authority 独立证明；回复本身也不能直接执行案件关键动作。

## 结果

- 默认离线消息卡片从计划阶段即显著标为模拟，不会因后续 UI 呈现被误认为飞书/企业微信真实送达。
- 收件身份与平台地址保持分离，仓库和 adapter 可在不引入人脸识别/ReID 的前提下接入授权身份映射。
- 通知内容、升级策略和案件 authority 互相引用但不混淆；普通文档、Agent 摘要和学生回复都不能自行裁决。
- M0–M6 与 M8.0–M8.3 schema、manifest、SQLite authority 均保持不变；本决策只新增 M8.4 authority。

## 未选择的方案

- **计划内保存明文平台账号**：扩大日志、fixture 和导出工件中的个人信息风险。
- **fake adapter 直接标记真实 DELIVERED**：把本地工件写入伪装成外部平台回执。
- **模板文本驱动案件迁移**：允许普通文档绕过版本化规则和授权人工动作。
- **用人脸或跨机位身份选择收件人**：违反项目明确禁止的人脸识别和跨摄像头 ReID 公理。

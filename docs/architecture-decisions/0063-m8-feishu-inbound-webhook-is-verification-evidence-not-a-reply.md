# ADR 0063：飞书入站 webhook 先形成验证证据，不能直接成为回复或案件动作

- 状态：Accepted
- 日期：2026-08-11
- 影响范围：M8.7 Feishu inbound webhook、notification reply、student response

## 背景

飞书 `im.message.receive_v1` 可以承载学生说明，但公网请求、事件头和自由文本都不是 LabCourt 权威事实。
飞书可能重复推送事件；官方文档明确建议该事件按 `message_id` 而不是 `event_id` 去重。配置 Encrypt Key
后，来源校验需要对 `timestamp + nonce + encrypt_key + 原始请求 body` 计算 SHA-256，并在解析前比对
`X-Lark-Signature`。直接把 JSON body 转成通用 notification reply 会绕过来源、时效、收件人映射、父消息
关联和 append-only 防重放边界。

## 决策

1. 入站 profile 只保存 outbound profile、webhook/encrypt-key/verification-token reference 与 hash，固定
   `HTTPS_WEBHOOK`、事件 schema `2.0`、`im.message.receive_v1`、单聊 `p2p`、user sender 和 text message。
2. profile 固定 `external_ingress_permitted=false`；本切片不是公网启用或生产 activation，也不新增监听端口。
3. ingress request 只绑定原始密文 body ref/hash/size、timestamp、nonce、claimed signature、received time 和
   manifest；在验证前，signature/decryption/business acceptance 均固定为 false。
4. verification receipt 只接受 freshness window 内、exact app/token、单聊 user text 且含 parent message ID 的
   严格事件形状。open ID 和自由文本只进入 hash/raw reference，不进入 schema。
5. provider `message_id` 是防重放 key，`parent_id` 是未来关联 outbound provider receipt 的 key；`event_id`
   仅保留为审计引用，不作为业务幂等键。
6. verification receipt 固定禁止 notification reply commit、Case transition 和直接纪律处分。下一持久化切片
   必须先以 append-only message-id uniqueness 提交验证证据，后续映射服务才能另行创建通用 reply authority。

## 结果

- 密文请求、解密事件和内容文档保持三个不同 raw reference，避免覆盖或把解析结果冒充原始请求。
- 自由文本不能静默成为裁决规则、定责事实或处分依据；它只可能在后续显式映射中成为学生补充材料。
- 默认运行路径保持离线，不依赖飞书 SDK、DNS、公网 webhook、GPU 或真实凭据。

## 官方协议依据

- [飞书：接收事件与签名校验](https://open.feishu.cn/document/server-docs/event-subscription-guide/event-subscription-configure-/encrypt-key-encryption-configuration-case?lang=zh-CN)
- [飞书：接收消息 `im.message.receive_v1`](https://open.feishu.cn/document/server-docs/im-v1/message/events/receive?lang=zh-CN)
- [飞书：消息 ID 与回复关系](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/intro)

## 未选择的方案

- **只校验 Verification Token**：在可以配置 Encrypt Key 时安全性更低，也不能在解析前验证原始 body。
- **按 event ID 去重**：与飞书该事件的官方重复推送建议冲突。
- **保存 clear open ID 或把自由文本放入 receipt**：扩大隐私暴露并破坏 reference-first raw evidence 边界。
- **验证成功即修改 notification/Case**：来源验证不等于身份映射、回复意图或有权限用户的案件确认。

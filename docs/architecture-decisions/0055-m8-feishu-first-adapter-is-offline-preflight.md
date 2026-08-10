# ADR 0055：M8 首个飞书 adapter 先做离线厂商 preflight

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.7 Feishu contract、card renderer、offline conformance adapter、后续 live transport

## 背景

用户选择飞书作为首个真实通知平台。现有 M8.4 通知 wire 已冻结通用 outbox、dispatch 和 delivery
语义，但默认 renderer/channel 只适用于 `LOCAL_OFFLINE_FAKE`；直接把模拟响应包装成 `FEISHU`
dispatch result 会错误声称真实外部接受。飞书还具有独立的 token、recipient、卡片 JSON、`uuid` 去重、
错误码和事件重推语义，不能用通用自由文本或任意 JSON 代替。

## 决策

1. 首接类型固定为飞书企业自建应用机器人，以 `tenant_access_token` 调用
   `POST /open-apis/im/v1/messages`；第一阶段只支持官方推荐的 `open_id` 用户收件人和
   `interactive` JSON 卡片。
2. app secret 与 token 永不进入 authority。profile 只绑定 secret-store credential bundle reference、
   app ID SHA-256、exact endpoint/scope、timeout、provider限制和 manifest。
3. open ID 明文不持久化；recipient binding 只保存授权 mapping reference、明文 SHA-256、revision、
   exact M8 notification target 与 manifest。实际 live transport 将在调用时短暂解析并再次核对 hash。
4. provider `uuid` 由 LabCourt notification ID 确定性派生，长度不超过 50；同一次通知所有 retry 使用
   相同值，并记录飞书仅保证一小时去重的边界。timeout 之后不得把未知状态改写成 definite failure。
5. Feishu card content 从 typed plan 确定性生成并绑定 exact UTF-8 bytes/hash/size；不接受自由文本 parser
   猜测 card schema。卡片继续声明 AI 不定责、回复只形成 supporting authority。
6. 无凭据阶段只提供离线 conformance adapter。其 success/error/timeout raw response、cache 和 replay
   均显著 `SIMULATED`，`real_send_confirmed=false`，并且不能产生现有
   `M8NotificationDispatchResultV1`，从结构上阻止状态机进入 `SENT`。
7. event callback 留到独立切片：采用 v2 `event_id` 去重、验签/加密或长连接的 typed contract 后，才能
   把回复变成 `M8NotificationReplyAuthorityV1`；回复永不直接改变 Case。

## 结果

- 可以在无网络、无 SDK、无 secret 的默认路径验证飞书请求结构、限额、幂等和失败映射。
- 通用 M8.4 wire 保持冻结；厂商语义通过 additive authority 包装 exact notification request。
- 真实 transport 需要另行通过 commissioning、双人 activation、secret 注入、沙箱发送与断网验收。

## 未选择的方案

- **群自定义机器人 webhook**：官方发送消息 API 不支持该调用方式，也不足以完成学生回复闭环。
- **把 fake success 当成 FEISHU SENT**：会把模拟响应伪装成真实接受。
- **在 SQLite 保存 open ID/app secret/token**：扩大个人标识和凭据泄漏面。
- **直接依赖 provider `msg` 文本判断失败**：官方要求以数值 `code` 判定，文本只作非权威诊断。
- **首切片同时接事件回调**：会混合 outbound、验签、去重、身份映射和 reply authority，多出不可验证
  的失败面。

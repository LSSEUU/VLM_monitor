# ADR 0056：飞书首次外部调用只允许双人确认的测试收件人沙箱

- 状态：Accepted
- 日期：2026-08-11
- 影响范围：M8.7 Feishu runtime config、activation persistence、后续 sandbox transport

## 背景

M8.7c 已能在完全离线条件下验证飞书请求结构，但厂商 profile、recipient binding、readiness 或
activation intent 任一对象本身都不构成外部调用授权。直接把通用 activation intent 当作生产开关，会
同时放开未知收件人和生产流量；只校验客户端提交的 hash，也无法证明提交时 commissioning 证据与两位
确认人的权限仍然有效。

## 决策

1. 第一份可持久化飞书配置固定为 `SANDBOX`，只允许 1–32 个显式测试收件人 binding；allowlist 必须
   按 authority ID 稳定排序、无重复、active，并全部属于 exact 飞书 profile。
2. runtime config 只保存 app/open ID 的授权 reference 与 SHA-256，不保存 app secret、token 或 open ID
   明文。配置自身固定 `external_call_permitted=false`，不能绕过 activation commit 调用网络。
3. activation intent 必须绑定 runtime config 的 canonical UTF-8 bytes/hash/size、同一 credential bundle
   reference 和 exact readiness evidence inventory。
4. commit 时必须重新评估 readiness，并重新解析与 intent 完全相同、当前仍 active/in-scope 的
   OPERATIONS 与 SAFETY_OFFICER authority。证据 inventory、任一人员 receipt、candidate、profile、配置
   字节或 repository manifest 变化都 fail closed，并要求重新确认。
5. 只有 append-only `M8FeishuSandboxActivationCommitReceiptV1` 可声明
   `sandbox_external_call_permitted=true`；同时固定
   `production_external_call_permitted=false`、`test_recipient_allowlist_only=true`，且禁止自动激活、
   生命安全联动、直接纪律处分、人脸识别和跨摄像头 ReID。
6. 本 contract-first 子切片不落库、不读取 secret、不访问 DNS/HTTP，也不改变通知状态。后续 transport
   必须从 activation repository 读取当前未撤销回执，并在调用时短暂解析 secret/open ID、复核 hash 和
   allowlist，不能接受调用方自带的“已激活”对象。

## 结果

- 第一次真实调用的爆炸半径被限制在双人明确确认的测试账号集合，不会因为 generic enable flag 扩展到
  全校用户。
- runtime config、人工确认和 commissioning 证据形成同一个内容寻址审计边界；旧确认不能批准新配置。
- 默认离线路径保持不变，仓库仍未声称已经连接飞书测试租户或完成真实送达。

## 未选择的方案

- **通用 adapter `enabled=true`**：不能表达厂商环境、测试收件人和 secret 解析边界。
- **首次激活直接允许生产收件人**：在真实错误码、超时与断网恢复尚未验收时扩大影响范围。
- **客户端提交当前 actor/readiness**：允许用已停用权限或过期证据构造调用授权。
- **把 app secret/open ID 写入 SQLite**：扩大凭据和个人标识泄漏面。
- **配置 commit 自动发送测试消息**：把授权、网络副作用和通知状态转换合并成一个不可独立审计动作。

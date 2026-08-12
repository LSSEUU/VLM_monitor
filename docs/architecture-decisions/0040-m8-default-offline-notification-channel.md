# ADR 0040：M8 默认通知通道是确定性离线模拟器且不声称真实送达

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.4 notification channel port、默认 adapter、dispatch/delivery raw response

## 背景

演示产品必须在无 API key、无网络和无 GPU 环境完整运行，同时未来仍要接飞书、企业微信和钉钉。若默认
adapter 假装外部平台成功，演示数据会被误读为真实送达；若 adapter 内部读取墙钟或随机数，同一请求又
无法重放和审计。

## 决策

1. notification channel port 固定 capability、dispatch、显式模拟 delivery、dispatch/delivery replay 和
   raw response 读取六个边界。失败使用 closed typed reason code，不返回自由文本近似结果。
2. 默认 adapter 只接受 `LOCAL_OFFLINE_FAKE`、`offline_capable=true`、`network_required=false`、
   `simulated=true` 的完整 capability authority；外部 channel capability 直接拒绝。
3. dispatch 必须接收 exact rendered-card bytes 并核对 request hash/size。结果只声明 provider accepted 和
   `SENT` 所需 authority，固定 `real_delivery_confirmed=false`，不能顺带声明 delivery。
4. simulated delivery 必须由调用者提供显式 UTC，且只能引用本 adapter 已生成的 accepted dispatch。
   delivery receipt 固定 `simulated=true`、`real_delivery_confirmed=false`。
5. adapter 以 dispatch request/result content ID 缓存 exact result、delivery 和 raw canonical JSON；幂等重试
   返回同一对象，冲突输入 fail closed。它不读取网络、墙钟或随机数，不 sleep，也不触发 Case action。

## 结果

- 无外部凭据即可演示 send/delivery 闭环，且每个页面/API 可以持续显示 `SIMULATED`。
- 调用方可把 rendered card 与 adapter raw response 一起交给 ADR 0039 的原子 outbox。
- 将来外部 adapter 复用同一 port 和 lifecycle contract，但必须提供各自网络、timeout、manifest 与真实
  provider receipt 实现，不能继承本地模拟的送达声明。
- 本切片不修改 M0–M6 wire、manifest 或既有 adapter。

## 未选择的方案

- **默认调用真实 SaaS webhook**：离线验收依赖 API key 和网络，且扩大外部副作用。
- **dispatch 即标记 delivered**：混淆平台接受与最终送达。
- **使用当前时间或随机 receipt**：破坏幂等重放和确定性测试。
- **复用真实 channel 名称承载 fake**：会把模拟来源伪装成真实平台。


# ADR 0060：外部通知调用必须使用单次 dispatch claim 与不可接管 call fence

- 状态：Accepted
- 日期：2026-08-11
- 影响范围：M8.7 notification outbox worker、外部消息 adapter、unknown-delivery recovery

## 背景

M8 notification version 已是 append-only，provider `uuid` 也从 notification ID 确定性派生，但当前
`QUEUED` 列表没有 worker 独占语义。两个进程可以同时读取同一版本并各自发起 HTTP。仅依赖 provider
幂等窗口不足以成为本地 exactly-once 证据；尤其在 request timeout、进程崩溃或 provider 接受后 SQLite
尚未提交时，本地不能知道消息是否已经产生外部效果。

## 决策

1. claim 精确绑定一个 `QUEUED` notification version、attempt、dispatch request、worker owner digest、
   UTC claim/expiry 与 repository manifest。request 的 `dispatched_at` 必须等于 claim time，lease 必须覆盖
   channel timeout 且不超过 300 秒。
2. claim 只表示独占占用，不授权调用。一个 source notification version 最多持久化一个 claim；claim
   到期但尚未跨越调用边界时标记 `EXPIRED_PRE_CALL`，不得被另一个 worker 静默接管。
3. 真正调用前追加唯一 call fence。fence 证明边界已跨越，但任何读取或重放该 receipt 都固定
   `additional_dispatch_call_permitted=false`、`automatic_retry_permitted=false`。
4. provider result 与既有 notification `SENT`/`FAILED` transition 必须在一个 repository transaction 中
   形成 completion。`ACCEPTED` 只对应 `SENT`；`DEFINITELY_NOT_SENT` 与 `UNKNOWN_DELIVERY` 都对应
   `FAILED`，其中 unknown 标记不得丢失。
5. call fence 到期仍无 completion 时状态是 `RECONCILIATION_REQUIRED`，不能重新调用。只有后续显式、
   可审计的对账流程可以消除此状态；本切片不定义自动重试。
6. 所有 claim/fence/completion/status 都禁止 Case transition 与直接纪律处分。该机制是通用 notification
   authority，飞书先使用，后续企业微信/钉钉可复用而不改变 M8.4 生命周期 wire。

## 结果

- 并发 worker 的唯一调用权可在 SQLite 内用 source-version 唯一约束实现。
- 外部调用后本地提交失败不会伪装成“未发送”，而会留下可发现的待对账 fence。
- 当前子切片只冻结 contract/schema，尚未新增 migration、repository behavior 或真实 runner。

## 未选择的方案

- **仅靠飞书 `uuid` 去重**：provider 行为不是本地持久化 authority，且不能覆盖所有未来 channel。
- **lease 到期自动接管并重发**：无法区分 worker 在调用前还是调用后崩溃。
- **先发 HTTP 再写 claim**：并发进程可在首个持久化事实出现前重复发送。
- **把 claim 字段加入既有 notification wire**：会改变已发布 M8.4 schema 与内容身份。

# ADR 0023：M6 区分当前模型调用终态与追加式历史失败

- 状态：Accepted（M3 已实现；M4 路由按本规则继续接入）
- 日期：2026-08-04
- 影响范围：M6 upgrade metadata plan、同快照正文解析与 whole-sample record

## 背景

M6 Observation V2 对每个逻辑 `request_id` 只允许一个运行期终态：`RESPONSE` 或
`FAILURE`。这使 fixed executor 的观测保持稳定，也阻止调用方把同一逻辑请求重复计数。

M3 的持久化历史有意采用另一种形状。`model_call_failure_authorities` 是追加式权威；同一
`request_id` 可以在不同 `claim_takeover_count` 下留下多代已闭合失败。获得精确 backlog lease
之后，请求还可以加入不参与语义请求身份的 operational retry context，再以同一
`request_id` 成功。此时当前 claim 是 `COMPLETED`，response/cache/parse/usage 构成当前终态，
但较早的 failure authority 必须继续存在。

如果把全部 failure 行都送入当前模型调用 snapshot，同一请求会同时出现 response 与 failure，
违反 Observation 和 locked-call 契约；如果忽略旧 failure 行，又会丢失已持久化的因果权威并让
隐藏、替换或伪造历史无法被发现。

## 决策

1. M6 SQLite metadata planner 必须有界枚举所选 Case 范围内的全部模型调用主表行，包括每一代
   failure authority；不得用 Observation 的 `IN (...)` 列表隐藏额外行。
2. 当前终态由 Observation 与 current claim 精确交叉决定：
   - `RESPONSE` 要求 current claim 为 `COMPLETED`，并与唯一的当前 response 图闭合；
   - `FAILURE` 要求 current claim 为 `ACTIVE`，并由同一 claim epoch 的唯一 failure 闭合；
   - 小于 current `claim_takeover_count` 的 failure 是历史失败；未来 epoch、同 epoch 歧义或缺少
     当前终态均失败关闭。
3. 历史失败进入独立、类型化的 metadata binding。其行身份、canonical 正文长度与摘要、请求
   语义、claim epoch、backlog version、Case revision、audit 与 completion receipt 关系都必须在
   同一个 B snapshot 中验证。它计入每路由 256 行、单文档 64 MiB、总 canonical 256 MiB 预算，
   并进入 metadata plan identity。
4. 历史失败不进入当前 `M6M3ModelCallAuthoritySnapshot.failures`、不生成当前
   `planned_artifact_refs`，也不进入 sample record 的当前模型工件集合。Observation V2 是当前
   executor 终态的 exact-set authority，不能由存储适配器添加一个 Observation 无法承诺的第二终态。
5. claim 中冻结的原始 request 正文与 cache 中本次执行的 request 正文分别承诺。operational retry
   context 可以使两份 canonical 正文摘要不同，但二者必须具有相同的类型化 request projection；
   不允许 permissive free-text parser 或仅凭 `request_id` 猜测等价。
6. initial backlog 与 retry completion 分开验证。initial closure 不伪造 completion receipt；retry
   failure 必须绑定唯一的类型化 receipt，并由 receipt 正文中的 `response_refs` 与对应 usage 集合
   精确闭合。
7. M4 路由打开时复用同一“当前终态 + 历史支持”原则，但不得复用 M3 的具体 wire model、角色矩阵
   或表结构假设。

## 结果

- 合法的 known failure、精确 lease takeover 与后续 response 可以被重放，同时旧失败不能被删除、
  替换或伪装成当前终态。
- whole-sample record 仍与 Observation V2 一一对应；历史因果校验不会制造未被观测的物理链接。
- metadata plan 与正文 resolver 增加一组显式历史 binding 和预算，但不修改 M0–M5 wire schema、
  Observation V2、Record V2、Pending V1 或 Seal V2。

## 放弃的方案

- **把历史 failure 也加入当前 physical refs**：Observation V2 不能表达同一 `request_id` 的两个
  终态，会破坏 exact-set join。
- **只读取最高 failure epoch**：无法发现隐藏或损坏的较早追加式权威。
- **用 cache request 覆盖 claim request**：会重解释已经冻结的请求正文，并掩盖 operational context
  与语义身份的边界。
- **为 Observation 再升版以携带全部尝试历史**：当前问题可由存储支持闭包解决；为未改变的当前
  executor 终态扩大公开 wire 不产生额外保证。

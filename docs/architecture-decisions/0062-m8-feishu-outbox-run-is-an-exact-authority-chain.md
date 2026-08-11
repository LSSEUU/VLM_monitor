# ADR 0062：飞书 outbox run 必须绑定完整 authority chain

- 状态：Accepted
- 日期：2026-08-11
- 影响范围：M8.7 Feishu outbox runner、sandbox send、notification completion

## 背景

现有 authority 已分别证明飞书 preflight/send 和 notification claim/completion，但应用层若只返回其中一个
receipt，调用方无法证明它们属于同一个 request、activation cut、worker claim 与 SQLite notification
transition。provider message ID 只能证明飞书 API 接受，不能证明终端送达，也不能作为案件动作依据。

## 决策

1. `M8FeishuSandboxOutboxRunReceiptV1` 必须同时包含 exact claim、call fence、send receipt 与 completion。
2. claim request 必须等于 send preflight request；call fence 必须绑定 claim，且
   `dispatch_authorization_id` 必须等于 send 时的 current activation status ID。
3. completion 必须绑定同一个 claim/fence，并使用 send receipt 中完全相同的 generic dispatch result；
   repository manifest 必须一致。
4. provider acceptance、notification transition 与 delivery 是三个独立派生事实。accepted send 可以原子推进
   notification 到 `SENT`，但 `real_delivery_confirmed` 固定为 false，只有未来独立 delivery event 可以改变。
5. unknown delivery 必须保留并推进 notification 到 `FAILED`；run receipt 固定禁止 automatic retry、Case
   transition、直接纪律处分和 credential material persistence。

## 结果

- runner 的返回值可以离线复核从 current activation 到 outbox commit 的完整链，不能拼接另一尝试的结果。
- 凭据、token、open ID、raw bytes 不进入组合 receipt；它们继续分别受短租约和 raw artifact authority 管理。
- 当前仅冻结 contract/schema，没有创建 worker 或调用任何网络。

## 未选择的方案

- **只返回飞书 send receipt**：不能证明 notification 状态已原子提交。
- **只返回 notification completion**：不能证明调用使用了哪个 current activation cut。
- **把 provider acceptance 命名为 delivered**：超出 API 能证明的事实范围。
- **把组合 receipt 作为 Case command**：通知结果不是责任认定或处分 authority。

# ADR 0037：M8 通知发送接受、送达、回复与案件动作使用分离 authority

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.4 channel adapter、raw receipt、通知状态机、回复与重试

## 背景

消息平台接受一个发送请求并不等于目标已收到消息；timeout 后也不能武断重试并假设前一次未发送。默认离线
fake 还必须支持闭环演示，但不能把本地写入伪装成真实平台送达。学生卡片回复可以成为后续说明/申诉的
supporting authority，却不能直接绕过身份、权限和显式案件命令。

## 决策

1. channel capability 固定 adapter/revision/channel、请求 timeout 上限、网络/离线/模拟声明、回复能力、
   `notification_id` 幂等键和 manifest。默认 fake 必须 network-free/offline/simulated；外部通道反之。
2. 每个 dispatch request 绑定 exact PLANNED authority、当前 QUEUED version/hash fence、attempt、capability、
   rendered card ref/hash、显式 UTC、timeout、idempotency key 和 manifest。请求本身不得声称真实送达。
3. dispatch result 只表达 `ACCEPTED / DEFINITELY_NOT_SENT / UNKNOWN_DELIVERY`，并始终保存受控 raw response
   ref/hash、typed failure、完成 UTC 和 manifest。`ACCEPTED` 只允许进入 `SENT`，不等于 `DELIVERED`。
4. delivery receipt 独立表达 `DELIVERED / FAILED`，绑定 dispatch result、target、channel、provider event、
   raw response 和 manifest。本地 fake 的 delivered receipt 固定 `real_delivery_confirmed=false`；UI 必须继续
   展示模拟 badge。
5. inbound reply authority 只保存 notification/target/actor/channel、reply kind、reply document hash、raw
   reply ref/hash、UTC 和 manifest，不在 authority 中复制自由文本或平台账号。它固定禁止纪律处分和案件迁移。
6. 通知主链冻结为 `PLANNED -> QUEUED -> SENT`；SENT 可进入 `DELIVERED/FAILED`，SENT/DELIVERED 可进入
   `ACKNOWLEDGED/RESPONDED`，ACKNOWLEDGED 可进入 RESPONDED。失败可 bounded retry 回到 QUEUED；发送失败
   也可从 QUEUED 进入 FAILED。每个命令使用 source version/hash/status fence、typed initiator、supporting
   authority、显式时间和 manifest。
7. actor queue/retry 只允许 active `SAFETY_OFFICER` 且显式人工确认；ack/respond 必须是 active actor；
   system 只可按 authority queue/retry；channel adapter 只可记录发送/送达/失败。后续仓库仍须解引用当前
   actor/target，不能信任客户端嵌套 authority。
8. notification reply、acknowledgement 或 Agent 分类都不能直接改变 Case。若学生请求申诉，必须另行经过
   M8.3 authenticated API 构造本人 `SUBMIT_APPEAL` 命令并写入 Case audit。

## 结果

- unknown delivery、definitely-not-sent 和 provider-delivered 不再被压成一个不可靠布尔值。
- fake 可以演示完整状态和回复，但其 authority 可机器识别为模拟，不能冒充真实飞书/企微/钉钉回执。
- 所有未来外部调用具备 timeout、幂等、manifest 与 raw response reference 的冻结边界。
- M0–M6 和 M8.0–M8.3 authority 不变；通知回复只能作为后续案件命令的引用，不是处分事实。

## 未选择的方案

- **send 返回成功即标记 DELIVERED**：混淆平台接受与最终送达，无法安全处理 webhook 和 timeout。
- **timeout 后无条件重发**：在未知送达且平台无精确幂等时可能产生重复消息。
- **在回复 authority 内保存明文消息**：扩大审计、日志和导出中的个人信息面。
- **回复关键字直接结案/定责/申诉**：让自由文本或 Agent 分类越过 M8.1/M8.3 人工权限边界。

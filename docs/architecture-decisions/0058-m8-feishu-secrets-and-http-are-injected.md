# ADR 0058：飞书 secret lease 与 HTTP transport 必须注入且默认不可达

- 状态：Accepted
- 日期：2026-08-11
- 影响范围：M8.7 Feishu secret resolver、HTTP port、token cache、sandbox send receipt

## 背景

activation repository 已能判断某次 sandbox call 是否仍获授权，但不能把 app secret、token 或 open ID
加入 Pydantic authority、SQLite、日志或测试 fixture。token 获取与消息发送又有不同的 delivery certainty：
token timeout 可以确定消息未发，消息 request timeout 则不能把未知状态误写成失败。直接在 service 内读取
环境变量并调用 SDK，会把 secret 生命周期、网络错误和通知状态转换耦合在一起。

## 决策

1. secret resolver 只返回不可序列化的 `M8FeishuResolvedSecrets` 短租约；其 `repr` 永远脱敏，退出
   context 时覆盖 app ID、app secret 与 open ID mutable buffer。service 在任何 HTTP 前复核 profile、binding、
   credential reference、app ID hash 与 open ID hash。
2. token 与消息 HTTP 使用 provider-specific port；service 不依赖飞书 SDK，也不在默认构造路径创建网络
   client。测试只注入内存 fake。
3. token 成功响应立即严格解析；authority 只保存 token SHA-256、expiry、provider log ID 与脱敏 raw
   response。原始 token 明文不进入 receipt/raw store。token cache 仅存在于进程内，使用 expiry safety skew，
   close/替换时覆盖 buffer。
4. 每次 send 先从 activation repository 读取 current status。`REVOKED`/`INVALIDATED`、卡片 bytes 变化或
   secret hash 不一致均在 HTTP 前阻断。
5. provider 成功只由数值 `code=0` 与 typed `data.message_id` 确认；`msg` 文本不参与判定。230035 与
   230020 分别映射 permission denied 与 rate limited，其他非零数值保持 generic rejected。
6. token timeout 产生 `DEFINITELY_NOT_SENT` 且不调用消息 endpoint；消息 timeout/transport failure 保持
   `UNKNOWN_DELIVERY`。provider acceptance 永不冒充 delivery，任何 send receipt 都不能改变 Case 或形成
   纪律处分。
7. 本子切片返回可审计 generic dispatch result 与 raw response，但不自行写 notification repository。
   后续 outbox runner 必须原子复核 QUEUED authority 并立即提交 raw artifact/state transition。

## 结果

- 无 secret、无网络的默认路径仍可完整验证激活、hash 复核、token cache 和失败确定性。
- live transport 可以后续独立实现和替换，而不改变领域层、M8.4 wire 或 activation authority。
- 当前仍未配置环境 secret、创建真实 TLS 连接或声称飞书已发送/送达。

## 未选择的方案

- **把 token 放进 Pydantic/SQLite cache**：会把 bearer secret 扩散到序列化、日志和备份。
- **service 直接读取环境变量**：无法测试 resolver authority，也难以限制每次 secret 生命周期。
- **token 与 message 共用一个 timeout 结果**：会把确定未发与未知送达混为一谈。
- **按 provider `msg` 文本路由**：文本不稳定且不是官方成功判定 authority。
- **send receipt 直接声明 DELIVERED**：message API acceptance 不等于终端送达。

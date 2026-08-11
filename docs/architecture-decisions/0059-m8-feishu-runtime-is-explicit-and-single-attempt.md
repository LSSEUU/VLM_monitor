# ADR 0059：飞书 sandbox runtime 只接受显式环境引用与单次固定 TLS 调用

- 状态：Accepted
- 日期：2026-08-11
- 影响范围：M8.7 Feishu environment resolver、stdlib HTTPS transport、sandbox runtime wiring

## 背景

M8.7e1 已把 secret 与 HTTP 隔离成注入端口，但只有 fake，尚不能安全地连接测试租户。运行时实现必须
同时避免三类漂移：从任意环境变量猜测凭据、把 endpoint/证书策略交给调用者、在 delivery 状态未知时
自动重试。飞书 message request 一旦越过网络边界，timeout 或连接关闭异常都可能发生在 provider 已接受
请求之后，因此 transport 不能把这类故障降格为“确定未发送”。

## 决策

1. 环境 resolver 只接受启动时显式配置的 `credential_bundle_reference_id -> env names` 与
   `receive_id_reference -> env name` 映射；环境变量名必须是稳定的大写 token，profile 与 receive mapping
   不允许重复或隐式 fallback。
2. resolver 读取 clear app ID/open ID 后复核 authority 中的 SHA-256；缺值、非法值、未配置引用与 hash
   drift 均产生不包含值的 typed reason code。app secret、app ID 与 open ID 只进入可清零 lease，不进入
   Pydantic、SQLite、raw response 或 `repr`。
3. HTTP transport 固定 `open.feishu.cn:443`、现有 profile 的 exact token/message path、系统 CA trust store、
   hostname verification 与 `POST`。调用者不能传入任意 origin、CA 或 redirect target。
4. 每个 token/message 方法最多创建一个 connection 并执行一次 request；transport 不做 retry、redirect
   或 backoff。token timeout 是消息 `DEFINITELY_NOT_SENT`，message timeout/TLS/transport failure 保持
   `UNKNOWN`，后续只能由有持久化 claim 的 runner 对账。
5. response 最多读取 256 KiB，超界立即产生 typed failure；provider HTTP 非 2xx 仍按有界 raw response
   交给 send core，以数值 `code` 判定，不按自由文本猜测。
6. 默认应用构造仍不装配 resolver/HTTP transport，不读取环境变量、不解析 DNS、不访问网络。本切片
   仅提供显式注入的 runtime adapter 与完全离线 fake-connection 验证。

## 结果

- 有凭据时可在不引入飞书 SDK 的情况下建立最小、可替换的 verified-TLS 边界。
- 没有显式 runtime mapping 时系统 fail closed；仓库测试与默认演示路径保持离线。
- 当前没有真实租户证据，也没有把 send receipt 写回 notification outbox；因此不能声称消息已发送、
  送达或飞书集成已验收。

## 未选择的方案

- **扫描统一前缀的环境变量**：引用与 authority 不再一一对应，容易误用另一租户或收件人。
- **允许配置任意 URL/CA**：扩大 SSRF、错误证书与测试 endpoint 冒充生产的风险。
- **依赖 SDK 默认 retry**：message timeout 后可能重复通知，且隐藏真实尝试次数。
- **把环境值写入 runtime config**：会使 secret 进入 canonical authority、日志与备份。

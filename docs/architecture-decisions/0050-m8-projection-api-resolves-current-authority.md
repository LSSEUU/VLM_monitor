# ADR 0050：M8 投影 API 服务端解析当前 authority 并裁剪

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.6 projection API service、loopback HTTP route、RBAC integration

## 背景

完整运营投影包含校园拓扑、设备、传感器观察、案件、通知和审计。即使投影本身只读，也不能由客户端声明角色后自行过滤；actor 在认证后还可能被停用或换版。投影读取跨越多个 append-only repository，授权版本也可能在读取期间发生变化。

## 决策

1. 新增 `GET /api/m8/campuses/{campus_id}/operations-projection`，继续使用既有 loopback Host 限制、bearer authenticator、`no-store` 和安全响应头。
2. bearer credential 只解析 `actor_id`；projection API service 每次请求从 operations repository 读取当前 actor authority receipt，不接受请求中的 role、capability 或 authority。
3. 服务先读取完整 optimistic stable projection，再次读取当前 actor receipt；若授权版本在读取期间变化，返回 typed `CONCURRENT_MODIFICATION`，不返回旧权限视图。
4. active 校验通过后，服务调用 ADR 0049 的纯 role-scoped builder；学生和停用 actor 返回 typed `FORBIDDEN`。
5. projection reader 的缺失、并发和超界失败分别转换为稳定的 404、409 或 500 typed API reason；响应不泄露数据库路径、凭据或内部异常。
6. GET 投影不执行 Case transition、不写 dashboard cache、不改变通知或传感器状态，也不调用网络、GPU 或模型。

## 结果

- 角色裁剪发生在 HTTP 响应序列化之前，前端从未收到被排除的数据。
- actor 换版或停用立即影响后续请求；读取窗口内换版也会 fail closed。
- API 输出保留当前 actor receipt、源 projection ID、可见 projection ID 和现有 manifest，可重算且可审计。
- endpoint 仍是本机最小集成边界，不声明真实身份平台、公网投产或现场生命安全系统已经就绪。

## 未选择的方案

- **credential catalog 直接携带 role/capability**：认证缓存会成为过期授权事实源。
- **浏览器请求 role 参数**：客户端可伪造权限。
- **完整投影下发后前端过滤**：敏感案件、通知和审计已经越权泄露。
- **读取期间忽略 actor 换版**：长投影读取可能在停权后仍返回内容。

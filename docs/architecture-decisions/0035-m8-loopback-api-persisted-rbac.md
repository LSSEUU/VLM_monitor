# ADR 0035：M8 本地 API 只认证身份，授权始终解引用持久化 actor authority

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8 本地 API、生产认证边界、四角色 RBAC 与案件人工动作

## 背景

M8.3 需要为运营演示提供可重启的本地 API，但客户端、token catalog 或请求体都不能成为角色、权限或
案件动作 authority。开发期免认证、监听所有网卡、信任客户端嵌套 actor 文档，都会绕过 M8.1 冻结的
人工确认、学生本人申诉和安全负责人处置边界。

## 决策

1. API 只绑定 `127.0.0.1`，构造时必须显式提供 authenticator；不存在开发免认证、默认 token 或公网
   fallback。Host 非 `localhost`/`127.0.0.1` 的请求 fail closed。
2. bearer catalog 只保存 token SHA-256 到 `actor_id` 的映射。认证使用常量时间 hash 比较，不记录、返回
   或持久化明文 token；principal 不携带 role、scope 或 capability。
3. 每个 API 调用都按 principal 的 `actor_id` 从隔离 M8 SQLite 读取最新 actor authority。停用、缺失或
   revision 已被替换的 authority 立即影响后续请求，客户端不能提交 authority 来覆盖它。
4. 领导只读全局与严重/紧急案件及其审计，不执行审批；安全负责人按持久化 scope 查看并执行明确人工
   案件动作；学生只读本人案件并只能提交本人申诉；运维只读拓扑、来源与设备/传感器运行信息。
5. transition request 不含 actor authority，并要求 source version/hash/status fence、supporting authority、
   reason 与 `explicit_human_confirmation=true`。AI/Agent 不可通过该 API 直接定责、撤销或结案，且所有
   成功动作仍由 append-only Case/audit SQLite 事务提交。
6. HTTP 错误只返回冻结的 typed reason。认证、拒绝、缺失、并发冲突、无效输入和内部完整性失败不得泄露
   token、数据库路径或内部异常文本；存储完整性失败返回 `INTERNAL_FAILURE`，不伪装成用户输入错误。
7. 写请求拒绝跨站 `Origin`/`Sec-Fetch-Site`。请求体必须是有长度上限的 `application/json`；响应使用
   `no-store` 与严格浏览器安全头。本切片不引入网络、云服务、GPU、人脸识别或跨摄像头 ReID 依赖。

## 结果

- 演示产品获得默认离线、可重启、显式认证的最小运营 API，同时保留 SQLite 作为角色与案件唯一 authority。
- token 泄露只代表某个 actor 身份凭证泄露，不会携带可嫁接的角色/权限文档；停用 actor 可立即拒绝旧 token。
- 四角色职责在 HTTP 边界可执行验证，领导不再被误实现为审批人，学生申诉不会越权到他人案件。
- M0–M6 wire schema、数据库、manifest、案件和审计语义保持不变；M8 API 仅消费新增 M8 authority。

## 未选择的方案

- **开发期无认证或固定默认 token**：无法证明生产启动 fail closed，并容易被误带入演示部署。
- **JWT/客户端 role claims 直接授权**：把外部声明升级为当前 authority，不能响应 SQLite actor revision/停用。
- **监听 `0.0.0.0` 后依赖防火墙**：扩大默认攻击面，也违反当前仅本机集成界面的产品边界。
- **领导参与案件审批**：与已确认产品角色和 M8.1 权限公理冲突。
- **用 AI/Agent principal 执行关键动作**：把辅助总结/路由能力错误升级为处分或结案 authority。

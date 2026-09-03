# 运维手册

所有命令均可将 `.\labcourt.cmd` 替换为 `uv run --locked labcourt`。
命令默认失败关闭，并将失败转换为明确的退出码或 typed reason；不要把
staging、journal 或模型原始输出当成最终业务权威。

## 配置与 schema validation

```powershell
.\labcourt.cmd validate-config --config configs/default.yaml
.\labcourt.cmd schemas export --check
.\labcourt.cmd artifacts validate --run-id <run_id> --config configs/default.yaml
```

`validate-config` 校验配置合同并输出 schema/rule 版本与配置 hash。
`schemas export --check` 检查生成文件与 registry 是否一致。
`artifacts validate` 只读校验 SQLite authority、audit chain/head、当前
projection、媒体和 M3/M4/M5 闭包；它不重放模型调用，也不把 journal 提升
为权威。

## Recovery 与 backlog

启动恢复：

```powershell
.\labcourt.cmd maintenance recover --run-id <run_id>
```

它在有界预算内处理 retention、孤立工件和模型响应 publication journal，
不调用 provider、不解析模型输出、不推进案件。需要人工关注时返回非零退出码。

业务 backlog 重试只处理一个精确 lease/checkpoint：

```powershell
.\labcourt.cmd backlog retry `
  --run-id <run_id> --worker-id <worker_id> `
  --fixture-bundle <fake-vlm-fixtures.json>

.\labcourt.cmd hearing backlog retry `
  --run-id <run_id> --worker-id <worker_id> `
  --fixture-bundle <m4-fake-vlm-fixtures.json>
```

M4 publication journal 的无 provider 收敛单独执行：

```powershell
.\labcourt.cmd hearing recover-responses --run-id <run_id> --limit 10000
```

它不会推进 hearing 或重置预算；业务重试必须使用精确的 hearing backlog
lease。执行前先运行 `maintenance recover`，并保留命令 JSON 输出作为操作记录。

## Notification outbox

Feishu 出站发送是独立的、单条的 authority chain：

```powershell
.\labcourt.cmd feishu outbox-status --help
.\labcourt.cmd feishu outbox-activate --help
.\labcourt.cmd feishu outbox-run-one --help
.\labcourt.cmd feishu outbox-revoke --help
```

先用 `outbox-run-one --check --json` 验证 binding、manifest、allowlist 和
环境变量名；检查 `dispatch_claim_created=false`、`external_call_attempted=false`
后，才允许去掉 `--check` 执行一次发送。没有批量扫描模式。撤销使用
`outbox-revoke`，不能用 webhook activation 代替。

## Health、readiness 与审计

M8 HTTP 服务没有一个未认证的通用 `/health` 路由。使用带角色认证的只读
资源检查当前状态：

```text
GET /api/m8/campuses/{campus_id}/device-health
GET /api/m8/campuses/{campus_id}/sensors
GET /api/m8/adapter-candidates/{candidate_id}/readiness
GET /api/m8/demo/model-readiness
GET /api/m8/integrations/feishu/status
GET /api/m8/integrations/feishu/runtime-status
```

审计查询使用：

```text
GET /api/m8/cases/{case_id}/audit
GET /api/m8/notifications/{notification_id}/audit
```

校园 operations projection 是只读当前切面，不替代 SQLite append-only
authority。Feishu 入站状态则用：

```powershell
.\labcourt.cmd feishu webhook-status --help
```

撤销后，activated webhook 会逐请求重新读取 authority，challenge 和业务事件
应被拒绝；不要仅凭进程仍在监听就判断 ingress 可用。

## 服务停止与故障处理

本地服务使用 Ctrl+C 停止。遇到 `INTERNAL_FAILURE`、数据库完整性错误或
`attention required` 时，先保存 JSON 输出和 run/audit 标识，再执行只读
`artifacts validate`；不要直接删除 SQLite、WAL/SHM 或 staging。任何清理都
应通过受控 recovery 边界完成。

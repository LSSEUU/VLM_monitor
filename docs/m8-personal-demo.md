# LabCourt 校园运营个人 Demo

## 一键初始化

Windows 资源管理器中双击仓库根目录的 `labcourt-demo-bootstrap.cmd`。也可以在 PowerShell 执行：

```powershell
.\.venv\Scripts\labcourt.exe demo bootstrap --json
```

默认输出到被 Git 忽略的 `.labcourt-local/labcourt-demo/`：

- `labcourt.sqlite3`：追加式 M8 authority 数据库；
- `bootstrap-receipt.json`：内容寻址的初始化闭包摘要；
- `operations-projection.json`：供最小界面直接读取的当前运营投影。

命令可重复运行；相同 authority 返回同一回执，不追加重复案件。若已有工件与数据库 authority 冲突，命令
会停止而不会覆盖。需要全新演示环境时，应先退出后续 API 进程，再手工移走整个本机 Demo 目录。

## 固定场景

初始化内容为一个完全离线、确定性的演示校区：

- 校园 → 化学楼 → 三层 → 实验室 301；
- 领导、安全负责人、学生、运维四个 active 演示角色；
- 一个显著标注 `SIMULATED` 的烟雾传感器，保存 tick 0 未激活与 tick 5 激活的 typed 原始信号；
- typed 风险策略将激活信号评估为 `EMERGENCY` 候选；
- 自动化只建立一个 `PENDING_VERIFICATION` 案件，并记录原始信号 authority 与创建审计；
- 运营投影显示 4 个位置、1 个模拟源、1 个已观测传感器和 1 个待核实重大案件。

该数据集不是认证消防检测，不包含真实人员、真实摄像头或现实安全表现，也不允许 bootstrap 自动确认、
驳回、补证、结案或处分。下一阶段的本机 API 从同一 SQLite 数据库解引用角色 authority，由安全负责人
显式确认后才能执行关键案件迁移。

## 启动角色化本机 API

双击 `labcourt-demo-api.cmd`。脚本先执行一次 bind-and-close 预检，通过后启动
`http://127.0.0.1:8877`；保持终端打开，按 `Ctrl+C` 停止。也可以只检查：

```powershell
.\.venv\Scripts\labcourt.exe demo api --check --json
```

启动时会在 ignored Demo 目录生成：

- `api-profile.json`：只含 token hash 的 typed loopback runtime profile；
- `api-access.json`：四角色本机明文演示 token，供独立 UI 或手工 API 联调读取，不会输出到终端。
- `knowledge-receipt.json`：制度、SOP、历史案例、应急预案、设备资料和 FAQ 六类离线知识的提交摘要。

## 离线通知路由

在案件仍为初始 `PENDING_VERIFICATION` 时双击 `labcourt-demo-notification.cmd`。它会幂等发布安全负责人
本地模拟收件目标，把紧急案件的 `CASE_ACTION_REQUIRED` 通知推进到 `QUEUED`，并写入：

- `notification-route-receipt.json`：目标、案件版本、通知版本和排队提交的 typed 摘要；
- `notification-card.json`：显著标注 `SIMULATED · LOCAL MESSAGE CARD` 的离线卡片。

该路由不读取飞书凭据、不联网、不声称真实送达、不确认案件，也不形成处分。它完成后，安全负责人和领导
的运营投影会看到该重大案件通知；运维视图仍不暴露案件或通知。

随后可双击 `labcourt-demo-notification-deliver.cmd`。它只消费上述 exact route receipt，经现有离线 fake
channel 提交 `QUEUED -> SENT -> DELIVERED`，把卡片、模拟发送响应与模拟送达响应作为 raw artifacts 写入
SQLite，并生成 `notification-delivery-receipt.json`。进程在 `SENT` 后中断时可从已持久化卡片和 dispatch
authority 恢复；重复执行不会生成第二次尝试。这里的 `DELIVERED` 仅是本地模拟状态，固定
`real_delivery_confirmed=false`，不会调用飞书或改变案件。

最后可双击 `labcourt-demo-notification-acknowledge.cmd`。脚本只接受精确的 `APPLY`，随后用当前
`safety-officer-demo` authority 提交 `DELIVERED -> ACKNOWLEDGED`，并写入
`notification-acknowledgement-receipt.json`。重复执行返回同一 receipt；运营投影中的未闭环通知数变为 0。
确认通知只表示安全负责人已看到消息，不会确认、驳回、补证或结案对应案件。

主要路由沿用既有 M8 API：

- `GET /api/m8/campuses/campus-demo/operations-projection`：领导只看到全局与重大案件，安全负责人看到完整
  运营案件，运维只看到设备/来源；学生禁止访问运营投影；
- `GET /api/m8/cases/{case_id}`：按角色和案件范围读取；
- `POST /api/m8/cases/{case_id}/transitions`：服务端重新解析当前 actor authority，领导和运维不能审批，
  安全负责人必须提交 `explicit_human_confirmation=true` 和支持材料引用。
- `POST /api/m8/knowledge/catalogs/campus-safety-knowledge/queries`：确定性离线检索，回答的每条 citation 都
  带 `source_ref`、`source_version` 和 `source_effective_at`；`model_used=false`、`network_used=false`。

这些固定 token 不是生产身份凭据，API 只绑定 loopback，`production_ready=false`。未来接校园 OIDC 时替换
认证 adapter，不改变案件 capability 或审计契约。

## 安全负责人案件处置

保持 API 终端运行，再双击 `labcourt-demo-case-action.cmd`。依次输入动作、人工理由，并输入 `APPLY`。允许的
动作及合法源状态为：

- `CONFIRM` / `REJECT` / `REQUEST_EVIDENCE`：从 `PENDING_VERIFICATION` 执行；
- `RETURN_TO_VERIFICATION`：从 `EVIDENCE_REQUESTED` 返回；
- `RESOLVE`：从 `CONFIRMED` 结案。

脚本读取本机 safety token，但不会打印或作为命令行参数传递。客户端先读取服务器当前案件版本和 authority
hash，再构造既有 `M8ApiCaseTransitionRequestV1`；并发或非法状态会被 API 拒绝。成功回执保存在 ignored
目录的 `case-actions/`。该入口没有领导/运维审批模式，也不支持绕过 `APPLY`。

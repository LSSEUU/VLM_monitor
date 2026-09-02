# API 参考

## 入口与边界

首选使用项目入口：

```powershell
.\labcourt.cmd --help
```

等价入口是 `uv run --locked labcourt`。`pyproject.toml` 注册的唯一
console script 是 `labcourt = "labcourt.cli:app"`。

M8 API 使用 Python 标准库 `ThreadingHTTPServer` 实现，默认绑定 loopback，
请求必须通过服务端认证和角色裁剪。它不是公网 API，也没有通用 CORS 或匿名
访问。请求体使用严格的 Pydantic 合同；错误返回 typed error reason。

## 启动本地服务

个人离线 API：

```powershell
.\labcourt.cmd demo bootstrap
.\labcourt.cmd demo api --check
.\labcourt.cmd demo api
```

完整校园运营 Demo（带静态页面和 M8 平台 API）：

```powershell
.\labcourt.cmd demo platform --check
.\labcourt.cmd demo platform
```

`--check` 只装配、校验并绑定端口后关闭服务；不应把它当作长期服务。

## M8 API 路由

以下路由由 `src/labcourt/m8_api_server.py` 和
`src/labcourt/m8_platform_server.py` 直接分派。`{id}`、`{case_id}`、
`{run_id}` 等路径参数必须是合同允许的 reference token。

### 只读资源

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/m8/session` | 当前角色会话与权限范围 |
| GET | `/api/m8/cases`、`/api/m8/cases/{case_id}` | 案件列表与详情 |
| GET | `/api/m8/cases/{case_id}/audit` | 案件审计记录 |
| GET | `/api/m8/notifications`、`/api/m8/notifications/{id}` | 通知列表与详情 |
| GET | `/api/m8/notifications/{id}/audit` | 通知审计记录 |
| GET | `/api/m8/campuses/{id}/topology` | 校园拓扑 |
| GET | `/api/m8/campuses/{id}/sources` | 来源目录 |
| GET | `/api/m8/campuses/{id}/operations-projection` | 当前运营投影 |
| GET | `/api/m8/campuses/{id}/sensors`、`device-health` | 传感器与设备健康 |
| GET | `/api/m8/sensor-polls/{id}` | 传感器轮询记录 |
| GET | `/api/m8/adapter-candidates/{id}/readiness` | 适配器就绪度 |
| GET | `/api/m8/knowledge/catalogs/{id}`、`answers/{id}` | 知识目录与答案 |
| GET | `/api/m8/runs/{run_id}/cases/{case_id}/hearing` | 听证状态 |
| GET | `/api/m8/runs/{run_id}/cases/{case_id}/hearing-preparation` | 听证准备材料 |
| GET | `/api/m8/runs/{run_id}/cases/{case_id}/hearing-acquisitions` | 听证补证记录 |

平台 Demo 额外提供：

```text
GET /api/m8/demo/model-readiness
GET /api/m8/demo/scenario-runs/current
GET /api/m8/demo/scenario-runs/{run_id}
GET /api/m8/demo/scenario-runs/{run_id}/evidence/{evidence_id}
GET /api/m8/agent/status
GET /api/m8/agent/conversations
GET /api/m8/agent/conversations/{conversation_id}
GET /api/m8/integrations/feishu/status
GET /api/m8/integrations/feishu/runtime-status
GET /api/m8/integrations/feishu/duty-route
GET /api/m8/evaluation/dashboard
GET /api/m8/evaluation/calibration
```

平台页面由 `/`、`/login` 以及 `/app/monitor`、`cases`、`map`、
`notifications`、`knowledge`、`agent`、`profile`、`settings`、
`evaluation` 提供，并从 `/assets/*` 读取静态资源。

### 写入资源

```text
POST /api/m8/cases/{case_id}/transitions
POST /api/m8/runs/{run_id}/cases/{case_id}/hearing
POST /api/m8/knowledge/catalogs/{catalog_id}/queries
```

平台 Demo 还提供登录、场景运行、通知、Agent、评估、校准和 Feishu
测试操作，例如：

```text
POST /api/m8/demo/login
POST /api/m8/demo/scenario-runs
POST /api/m8/demo/reset
POST /api/m8/agent/conversations
POST /api/m8/agent/conversations/{id}/turns
POST /api/m8/notifications/{id}/acknowledgements
POST /api/m8/notifications/{id}/replies
POST /api/m8/cases/{id}/notification-dispatches
POST /api/m8/evaluation/campaigns
POST /api/m8/evaluation/campaigns/{id}/start
PUT  /api/m8/evaluation/media/{id}/ground-truth
DELETE /api/m8/agent/conversations/{id}
```

具体 JSON 字段以 `schemas/` 和 `labcourt.contracts` 中的版本化合同为准，
不要根据页面文本或模型输出推断字段。

## Feishu 入站边界

`labcourt feishu webhook-serve` 启动的是 activation-gated loopback 后端，
只接受已激活配置中的 callback path。challenge 和业务事件均需要当前
SQLite authority；撤销 activation 后，运行中的服务会逐请求重新检查状态。
它不是默认公网 webhook。出站通知另有独立的 `outbox-*` authority，不能用
webhook activation 替代。

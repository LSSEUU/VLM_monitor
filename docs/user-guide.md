# LabCourt 用户指南

## 入口选择

普通 CLI 命令支持以下两种前缀：

- Windows：`labcourt.cmd`（Windows 专用 Demo/平台动作按包装器分派）
- 跨平台：`uv run --locked labcourt`

下文用跨平台前缀示例；Windows 将其替换为 `labcourt.cmd` 即可。

```text
uv run --locked labcourt --help
labcourt.cmd --help
```

## 离线个人 Demo

这是默认展示路径，不调用真实模型或外部服务。Windows 推荐直接运行：

```text
labcourt.cmd demo start
```

需要逐步执行时使用跨平台 CLI：

```text
uv run --locked labcourt demo bootstrap --output .labcourt-local/labcourt-demo
uv run --locked labcourt demo camera-register --output .labcourt-local/labcourt-demo
uv run --locked labcourt demo media-bind --input inputs/goggles-missing.mp4 --output .labcourt-local/labcourt-demo
uv run --locked labcourt demo ppe-case-create --output .labcourt-local/labcourt-demo
```

只检查 API 是否能绑定、验证并关闭：

```text
uv run --locked labcourt demo api --output .labcourt-local/labcourt-demo --port 8877 --check
```

检查通过后启动：

```text
uv run --locked labcourt demo api --output .labcourt-local/labcourt-demo --port 8877
```

Windows 也可使用 `labcourt.cmd demo start` 一键完成上述准备并启动本机服务。服务只
监听 `127.0.0.1`；演示 token 和运行产物保存在 `.labcourt-local/`，不要提交到 Git。

## 正式校园平台 Demo

正式 M8 UI/API 使用独立的平台装配。Windows 执行 `labcourt.cmd platform`；跨平台先运行
`uv run --locked labcourt demo platform --check`，通过后再去掉 `--check` 启动。两者默认读取
受版本控制的 `inputs/goggles-missing.mp4`，只绑定 `127.0.0.1:8877`，无外部凭据时保持离线模式。

## 视频分析 Pilot

Pilot 只支持配置中的 `PPE_GOGGLES_MISSING` 规则。准备好 `configs/pilot.yaml` 指定的
本地 worker 和 screening 环境变量后运行：

```text
uv run --locked labcourt pilot run --config configs/pilot.yaml --video inputs/goggles-missing.mp4 --run-id goggles-missing-001 --json
```

需要分阶段执行时，可查看以下实际命令：

```text
uv run --locked labcourt pilot --help
uv run --locked labcourt pilot perceive --help
uv run --locked labcourt pilot screen --help
uv run --locked labcourt pilot report --help
uv run --locked labcourt pilot ui --help
```

`pilot ui` 是本机图形入口；已有完整运行的查看和回放不需要再次调用 detector 或 VLM。

## 案件、告警与审计

冻结 M0–M6 流程仍通过顶层 CLI 操作：

```text
uv run --locked labcourt process --run-id <run_id> --config configs/default.yaml
uv run --locked labcourt finalize --run-id <run_id> --config configs/default.yaml
uv run --locked labcourt alert dispatch --run-id <run_id> --config configs/default.yaml
uv run --locked labcourt artifacts validate --run-id <run_id> --config configs/default.yaml
```

延迟的 screening 工作可有限重试：

```text
uv run --locked labcourt backlog retry --run-id <run_id> --worker-id offline-worker-01 --config configs/default.yaml
```

会审、判例、申诉、训练导出和投影命令的参数较多，使用对应命令的 `--help`，不要猜测
参数或绕过 authority：

```text
uv run --locked labcourt hearing --help
uv run --locked labcourt precedent --help
uv run --locked labcourt appeal --help
uv run --locked labcourt training --help
uv run --locked labcourt projection --help
```

## 通知和 Feishu

个人 Demo 的 `demo notification-*` 与 `demo ppe-notification-*` 命令只使用本地 fake
channel；`DELIVERED` 是模拟状态，不代表真实送达。

需要 Feishu sandbox 时，Windows 使用统一入口：

```text
labcourt.cmd feishu setup
labcourt.cmd feishu preflight
labcourt.cmd feishu send-one
```

先执行 `preflight`，再按提示进行单条测试。完整 webhook/发送入口只消费已存在的
typed activation 和 runtime authority，不自动生成生产授权。

## 产物位置

- `runs/`：M0–M6 运行、案件、证据、告警和报告。
- `.labcourt-local/labcourt-demo/`：个人 Demo SQLite、投影、访问文件和通知回执。
- `.labcourt-local/labcourt-platform-demo/`：校园平台 Demo 运行文件。
- `.labcourt-local/` 下的凭据和访问文件只供本机演示，禁止提交或复制到日志。

## 结果边界

模型只提供结构化语义建议；人数、时长、坐标和证据是否存在来自确定性工件。模拟视频、
fake provider 和 machine weak label 不能证明真实现场准确率、延迟、成本或处分结论。

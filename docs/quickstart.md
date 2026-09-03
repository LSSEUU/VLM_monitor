# LabCourt 快速开始

## 1. 安装

项目要求 Python 3.11 或 3.12。首次安装使用锁定依赖：

```powershell
labcourt.cmd setup
# 或：uv sync --all-groups --locked
```

Windows 可用统一入口 `labcourt.cmd`；其他平台或不使用包装器时，在命令前加
`uv run --locked`：

```text
labcourt.cmd validate-config --config configs/default.yaml
uv run --locked labcourt validate-config --config configs/default.yaml
```

## 2. 验证安装

```text
labcourt.cmd schemas export --check
uv run --locked labcourt schemas export --check
```

## 3. 启动正式校园平台 Demo

默认 Demo 不需要 GPU、网络或密钥，产物写入 Git 忽略目录：

```text
labcourt.cmd platform
```

该 Windows 动作会先完成平台装配与端口预检，再启动正式 M8 UI/API
`http://127.0.0.1:8877`。保持终端运行，结束时按 `Ctrl+C`。

需要逐步执行或修改参数时使用实际 CLI：

```text
uv run --locked labcourt demo platform --output .labcourt-local/labcourt-platform-demo --input inputs/goggles-missing.mp4 --port 8877 --check
uv run --locked labcourt demo platform --output .labcourt-local/labcourt-platform-demo --input inputs/goggles-missing.mp4 --port 8877
```

较小的个人 API 流程仍可用 `labcourt.cmd demo start`；它会初始化、注册预录摄像头、
绑定示例媒体、创建 PPE 候选并执行 API 预检。

## 4. 运行本地视频 Pilot

`configs/pilot.yaml` 使用本地感知 worker 和外部 screening provider。先按
[`docs/pilot-quickstart.md`](pilot-quickstart.md) 准备 worker，再设置所需环境变量：

```text
uv run --locked labcourt pilot run --config configs/pilot.yaml --video inputs/goggles-missing.mp4 --run-id goggles-missing-001 --json
```

同一 `run-id` 会校验已有权威工件并恢复；新视频请使用新的匿名 `run-id`。

## 5. 发生问题时

先运行：

```text
uv run --locked labcourt validate-config --config configs/default.yaml --json
uv run --locked labcourt --help
```

常见边界和处理方式见 [`troubleshooting.md`](troubleshooting.md)。

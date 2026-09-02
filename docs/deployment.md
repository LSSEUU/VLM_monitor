# 部署与运行边界

## 当前交付形态

这是一个以本地、离线 Demo 为默认路径的 Python 项目，不是已经容器化的生产
服务。仓库当前没有 `Dockerfile`，也没有 CI workflow；部署自动化不能从仓库
现状推断出来。

运行时要求来自 `pyproject.toml`：Python `>=3.11,<3.13`，使用 Hatchling
构建 wheel。推荐用锁定依赖安装：

```powershell
uv sync --all-groups --locked
```

安装完成后的入口优先使用：

```powershell
.\labcourt.cmd --help
```

若 wrapper 尚未生成，使用 `uv run --locked labcourt --help`。

## 离线 Demo

默认路径不要求 GPU、网络、真实摄像头或真实人员图像，VLM 和传感器使用
明确的 fake/simulated/precomputed 边界。典型启动方式：

```powershell
.\labcourt.cmd demo bootstrap
.\labcourt.cmd demo platform --check
.\labcourt.cmd demo platform
```

服务使用 loopback HTTP；`--check` 用于验证装配、数据库迁移和端口绑定后立即
关闭。`labcourt demo api` 是个人 Demo API，`labcourt demo platform` 是完整
校园运营页面和平台 API。旧版 pilot 控制台通过：

```powershell
.\labcourt.cmd pilot ui --no-open
```

启动，同样只允许本机访问。

## 可选能力与生产适配器

基础安装不启用外部服务。可选依赖必须显式安装：

```powershell
uv sync --locked --extra feishu-inbound   # 加密入站适配器
uv sync --locked --extra feishu-live      # lark-oapi 实时适配器
uv sync --locked --extra video            # OpenCV 视频适配器
```

可选依赖本身不会改变默认 wiring。Feishu 入站必须先准备版本化 runtime
config、双人 activation intent 和 manifest，再执行 `feishu webhook-activate`；
运行时由 `feishu webhook-serve` 读取既有 activation。出站通知必须使用独立
的 `outbox-activate`、`outbox-status`、`outbox-revoke` 流程。

```powershell
.\labcourt.cmd feishu webhook-status --help
.\labcourt.cmd feishu webhook-serve --help
.\labcourt.cmd feishu outbox-run-one --help
```

这些命令不会把 secret 作为命令行参数传入；生产 adapter 的 secret loader、
公网反向代理、TLS、进程守护和网络策略属于部署方边界，不由当前仓库自动提供。

## 数据与端口

Demo 会在指定 `--output` 目录创建 SQLite 和派生的 access/profile/receipt
文件。默认端口为个人 API/平台 `8877`，pilot UI `8876`；端口可通过 CLI
选项修改。服务关闭应使用 Ctrl+C，让服务器执行正常 close；不要把临时
`--check` 进程当作健康探针的长期替代。

## 安装后最低检查

部署流水线至少应在临时环境完成：

```powershell
uv run --locked labcourt --help
uv run --locked labcourt schemas export --check
uv run --locked labcourt demo platform --check
```

此外应从新构建的 wheel 安装后再次导入 `labcourt`，并确认 M8 迁移 SQL、
`prompts` 和 UI 静态资源随包可读；这项安装 smoke 不等同于离线 Demo。

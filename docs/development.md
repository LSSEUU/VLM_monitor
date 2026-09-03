# 开发指南

## 入口与依赖

项目要求 Python `>=3.11,<3.13`，依赖由 `uv.lock` 锁定。首次准备：

```powershell
uv sync --all-groups --locked
```

基础环境足以运行默认离线路径；要连同真实视频、加密 Feishu inbound 和 Feishu
live provider smoke 一起验证，使用 `uv sync --all-groups --all-extras --locked`。
缺少对应 extra 时，provider 专属测试会明确跳过，而不是让默认质量门失败。

命令入口优先使用：

```powershell
.\labcourt.cmd --help
```

当前等价形式是 `uv run --locked labcourt`；构建入口由 `pyproject.toml` 的
`labcourt.cli:app` 提供。

## Contract-first 工作流

先改 Pydantic contracts、schema registry/export 和 contract tests，再实现
application/service 行为，最后接入 adapter、CLI 或 HTTP。每个切片都应说明：

- 输入/输出合同与 schema 版本；
- 状态转移、authority 和失败 reason；
- 场景覆盖与 recovery 语义；
- manifest、raw response、cache 或审计引用的影响。

`domain/` 只能依赖领域代码和标准库，不得导入 HTTP、数据库、OpenCV、Torch
或云 SDK。模型调用必须具备 fake、timeout、cache、manifest 和 raw response
引用；模型输出不能作为客观计数、持续时间、身份、坐标或证据存在性的来源。

## 最小本地 gate

单个切片先跑最小相关测试和静态检查：

```powershell
uv run --locked ruff format --check src tests scripts
uv run --locked ruff check src tests scripts
uv run --locked mypy
uv run --locked pytest tests/unit/<相关测试>.py
```

仓库提供的 Makefile gate：

```powershell
make format-check
make lint
make typecheck
make test
make schemas-check
make m4-coverage
make m5-coverage
make quality
```

Windows 没有 `make` 时，可直接执行对应的 `uv run --locked ...` 命令；M6
完整离线演示使用：

```powershell
make demo
```

不要为一个小改动反复运行全量测试；提交前再根据变更范围补齐质量门。

## Schema、CLI 与服务 smoke

schema 修改后至少检查生成器快照：

```powershell
.\labcourt.cmd schemas export --check
```

CLI 注册或选项修改后检查公开帮助，而不是只调用 Python 函数：

```powershell
.\labcourt.cmd --help
.\labcourt.cmd demo --help
.\labcourt.cmd feishu --help
.\labcourt.cmd pilot --help
```

HTTP 装配修改后使用 loopback check：

```powershell
.\labcourt.cmd demo bootstrap
.\labcourt.cmd demo platform --check
.\labcourt.cmd demo api --check
```

这些 check 会绑定并关闭本地服务，不代表公网部署或真实 Feishu 调用。

## Wheel 与 import smoke

发布前应在临时目录构建并安装 wheel，再验证包内资源，而不是只在源码树中
导入：

```powershell
uv build
uv run --locked python -c "import importlib.metadata; print(importlib.metadata.version('labcourt'))"
uv run --locked labcourt --help
```

安装 smoke 应覆盖：完整 `labcourt` 包递归 import、`schemas`/`prompts` 资源、
M8 `m8_migrations/*.sql`、UI 静态资源，以及 `labcourt.cmd`/console script
公开入口。当前仓库没有 Dockerfile 或 CI workflow，不能用它们替代这些本地
检查；`uv build` 产生的构建产物应留在临时目录或由开发者按需清理。

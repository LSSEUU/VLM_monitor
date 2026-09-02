# 仓库清理报告

## 范围、基线与回退

本次工作是行为保持型仓库整理，不是业务版本升级。删除前的完整审计见
[`cleanup-inventory.md`](../cleanup-inventory.md)。

| 项目 | 值 |
|---|---|
| 基线提交 | `dc09dedc4fbfb28ceecc102bcdd2470d9ae76b1d` |
| 回退标签 | `pre-cleanup-v0.1.0` |
| 工作分支 | `chore/repository-cleanup` |
| Python 验证版本 | CPython 3.11.15 |
| 审计/清理日期 | 2026-09-02 |

需要查看清理前状态时，可执行 `git switch --detach pre-cleanup-v0.1.0`；要在可写
分支上恢复，可从该标签创建新分支。标签不替代数据库、用户工件或外部系统备份。

以下用户工作区内容始终排除在提交外：

- `src/labcourt/m8_ui_web/app.css`
- `src/labcourt/m8_ui_web/app.html`
- `src/labcourt/m8_ui_web/app.js`
- `tests/unit/test_m8_ui_case_detail_loading.py`
- `prompt.md`

## 前后对比

| 指标 | 清理前 | 清理后 |
|---|---:|---:|
| tracked 文件 | 2,033 | 2,008 |
| 根目录 Windows `*.cmd` | 26 | 1 |
| Demo PowerShell 入口 | 18 个分散脚本 | 1 个 dispatcher + 2 个多步骤脚本 |
| `previews/` tracked 文件 | 24 | 0 |
| prompt 模板 | 17 | 17，字节不变 |
| Ruff format | 84 个文件未格式化 | 1,260 个文件通过检查 |
| Ruff lint | 通过 | 通过 |
| mypy | 23 errors / 6 files | 0 errors / 725 source files |
| pytest | 收集 6,107 项后因可选 `cv2` 导入中止 | 6,142 passed、7 skipped、0 failed |
| schema | 471 个模型通过 | 471 个模型通过，重生成无 diff |
| M4/M5 分支覆盖 | 各 100% | 各 100% |
| M6 Demo | 16 场景通过 | 16 场景通过 |

tracked 文件净减少 25 个；同时新增了当前文档、测试和一个可在干净 clone 中使用的
受控演示输入，因此净变化小于实际合并/删除数量。

## 删除、移动与合并

### 唯一实际媒体删除

只删除了三个已有等价副本的设计预览媒体。每个 hash 组仍保留一个可引用副本：

| 删除的副本 | 保留位置 | SHA-256 |
|---|---|---|
| `previews/labcourt-ops-ui/1786190627618...mp4` | `docs/design-reference/labcourt-ops-ui/assets/feed-301a.mp4` | `a3dae5a59000d12fdcadf068af2b4cb2cf6bdcae755f240bfdc6ce95ba47707d` |
| `previews/labcourt-ops-ui/assets/feed-301b.mp4` 的重复设计副本 | `inputs/goggles-missing.mp4` | `774e04b2a9f03135eecc5983454b8f006b891d829d29f0a7c1fef7bcf2d69726` |
| `previews/labcourt-ops-ui/1786193409682...mp4` | `docs/design-reference/labcourt-ops-ui/assets/feed-302a.mp4` | `4bd6c5939c4cbb9e48b1856582ad754c4b42107a2078bccd324536b546632fef` |

第二组的 surviving bytes 被提升为正式、离线可用的默认 Demo 输入。Git 可能把这一操作显示
为 timestamp 文件的 rename；内容层面的结果仍是二选一去重。没有删除 Python 模块、schema、
migration、prompt 内容、fixture 或正式 UI 资源。

### 归档与路径整理

| 原路径 | 新路径 | 原因 |
|---|---|---|
| `docs/milestones/**` | `docs/archive/milestones/**` | 历史完成记录，不再冒充当前规范 |
| `docs/progress/**` | `docs/archive/progress/**` | 历史验证记录 |
| `docs/spec/labcourt-v0.2-fast-pilot-spec.md` | `docs/archive/spec/...` | 被当前两份可执行规范取代 |
| `prompts/legacy/**` | `prompts/archive/**` | 保留 replay bundle，但退出默认路径 |
| `previews/labcourt-ops-ui/**` | `docs/design-reference/labcourt-ops-ui/**` | 明确 design-only 边界 |
| 受控 goggles 视频副本 | `inputs/goggles-missing.mp4` | 让正式默认 platform 在干净 clone 中可启动 |

当前规范仍只有：

- `docs/spec/labcourt-vibe-coding-spec.md`：冻结的 M0–M6；
- `docs/spec/labcourt-campus-operations-spec.md`：增量 M8。

### 根目录 Windows 入口迁移

所有旧根目录包装器由 `labcourt.cmd` 取代；Python Typer CLI 仍是命令权威。

| 旧命令 | 新命令 |
|---|---|
| `feishu-demo-card.cmd` | `labcourt.cmd feishu demo-card` |
| `feishu-demo-emergency.cmd` | `labcourt.cmd feishu demo-emergency` |
| `feishu-preflight.cmd` | `labcourt.cmd feishu preflight` |
| `feishu-send-one.cmd` | `labcourt.cmd feishu send-one` |
| `feishu-setup.cmd` | `labcourt.cmd feishu setup` |
| `feishu-webhook.cmd` | `labcourt.cmd feishu webhook` |
| `labcourt-demo-api.cmd` | `labcourt.cmd demo api` |
| `labcourt-demo-bootstrap.cmd` | `labcourt.cmd demo bootstrap` |
| `labcourt-demo-camera.cmd` | `labcourt.cmd demo camera` |
| `labcourt-demo-case-action.cmd` | `labcourt.cmd demo case-action` |
| `labcourt-demo-e2e.cmd` | `labcourt.cmd demo e2e` |
| `labcourt-demo-notification-acknowledge.cmd` | `labcourt.cmd demo notification-acknowledge` |
| `labcourt-demo-notification-deliver.cmd` | `labcourt.cmd demo notification-deliver` |
| `labcourt-demo-notification.cmd` | `labcourt.cmd demo notification` |
| `labcourt-demo-ppe-appeal-resolve.cmd` | `labcourt.cmd demo ppe-appeal-resolve` |
| `labcourt-demo-ppe-case.cmd` | `labcourt.cmd demo ppe-case` |
| `labcourt-demo-ppe-notification-deliver.cmd` | `labcourt.cmd demo ppe-notification-deliver` |
| `labcourt-demo-ppe-notification-reply.cmd` | `labcourt.cmd demo ppe-notification-reply` |
| `labcourt-demo-ppe-notification.cmd` | `labcourt.cmd demo ppe-notification` |
| `labcourt-demo-ppe-outcome-acknowledge.cmd` | `labcourt.cmd demo ppe-outcome-acknowledge` |
| `labcourt-demo-ppe-outcome-deliver.cmd` | `labcourt.cmd demo ppe-outcome-deliver` |
| `labcourt-demo-ppe-outcome-notification.cmd` | `labcourt.cmd demo ppe-outcome-notification` |
| `labcourt-demo-start.cmd` | `labcourt.cmd demo start` |
| `labcourt-demo-student-appeal.cmd` | `labcourt.cmd demo student-appeal` |
| `labcourt-platform-model-setup.cmd` | `labcourt.cmd model-setup` |
| `labcourt-platform-start.cmd` | `labcourt.cmd platform` |

十六个单动作 `scripts/windows/labcourt-demo-<action>.ps1` 合并为
`scripts/windows/labcourt-demo.ps1 -Action <action>`。多步骤且职责不同的
`labcourt-demo-start.ps1` 与 `labcourt-demo-e2e.ps1` 保留。Feishu、Qwen、模型环境和
platform 启动脚本也保留，因为它们包含独立预检、环境或进程生命周期逻辑。

## Prompt、配置与依赖决定

### Prompt

17 个模板按用途登记在 [`data-contracts.md`](data-contracts.md)：默认 M3 screening/repair、
默认 M4 三角色 hearing、显式 M8 v2 hearing，以及 archive 中的冻结 replay bundle。
archive move 后模板字节未改，renderer 和测试改用新资源路径；bundle identity 投影不含
文件名，因此 frozen hash、cache/replay 语义和 raw-response 引用不变。

### 配置

`configs/default.yaml`、`configs/demo.yaml` 和 `configs/pilot.yaml` 继续独立存在。
严格 loader 禁止 YAML alias/merge，且配置 canonical bytes/hash 参与 authority、manifest
和 replay；为了消除视觉重复而合并它们会改变契约。`default.yaml` 是基线，另外两份是
显式场景快照。

### 依赖

`pyproject.toml` 和 `uv.lock` 仍是主环境的唯一依赖权威，没有新增包：

- 基础安装保持离线 Demo 所需的最小集合；
- `video`、`feishu-inbound`、`feishu-live` 保持为锁定 extras；
- provider 专属测试缺少对应 extra 时明确 skip；完整 provider gate 使用
  `uv sync --all-groups --all-extras --locked`；
- `requirements/perception-worker.txt` 继续隔离 GPU/CUDA worker，不与主环境合并。

## 契约与行为影响

- Pydantic wire schema：无变更；471 个 schema 重生成无差异。
- SQLite：两套 migration 均保留 18 个 SQL 文件；历史 CRLF/LF 字节和校验和不变。
- M0–M6 authority、状态机、审计、回放和 `STRICT_CAUSAL` 语义：无变更。
- prompt：内容 hash 不变，只更新 archive 路径。
- manifest：仅 design manifest 的资源相对路径随归档更新；受控默认输入有明确 SHA-256。
- M8 ports：测试补登记 17 个已经存在的 Protocol 和一个既有方法，生产签名未变。
- application 边界：测试精确登记既有 M8 composition roots；普通 application 模块仍不能
  直接导入 adapters。
- Python 格式与 mypy 修复是机械/类型层改动；未新增宽松解析、模型事实来源、人脸识别或
  跨摄像头 ReID。

## 最终验证证据

验证在指向清理提交的独立 Git worktree 和锁定 Python 3.11 环境中完成。

| Gate | 结果 |
|---|---|
| fresh dependency sync | `uv sync --all-groups --all-extras --locked` 通过 |
| Ruff format/check | 1,260 files passed |
| Ruff lint | passed |
| mypy strict | 725 source files passed |
| 全量 pytest | 6,142 passed、7 POSIX-only skipped、0 failed |
| M4 branch coverage | 129 passed、100.00% |
| M5 branch coverage | 52 passed、100.00% |
| schema check/regeneration | 471 verified/exported，Git 无 diff |
| M6 acceptance demo | 16 passed，`status=PASSED` |
| M8 bootstrap/API/platform | bootstrap、个人 API `--check`、正式 platform `--check` 均通过 |
| Windows launcher | `labcourt.cmd demo bootstrap` 通过；CLI 参数转发有集成测试 |
| 人工确认 E2E | PPE 创建→确认→通知→解释→申诉→`OVERTURNED`→`APPEAL_RESOLVED`→结果确认，通过 |
| public surface smoke | 722 个 package modules 可导入；所有 Typer group/leaf `--help` 通过 |
| wheel | 796 files；17 prompts；18+18 migrations；13 UI assets；独立安装与 bootstrap 通过 |
| secret scan | 敏感文件名 0；高置信私钥/API key 匹配 0 |

全量 pytest 为四个互斥分片的总和：非 integration 4,149；M0–M5 integration 835；
M6 integration 922；M8/其余 integration 236。七个 skip 都是 Windows 不具备的 FIFO、
sealed memfd、POSIX 权限或原子 no-replace 语义，不是可选 provider 缺失。

## 保留但仍需关注的内容

| 内容 | 保留理由 | 后续触发条件 |
|---|---|---|
| `src/labcourt/m8_ui_web/fonts/noto-serif-sc.woff2`（10.5 MB） | 正式离线 UI 直接引用，避免运行时网络字体 | 发布前补齐精确字体来源/许可证记录，或用已验证的更小子集替换 |
| 三个演示 MP4 | 正式默认输入或 design reference；均有内容 hash | 对外再分发前确认原始生成工具和许可证 |
| `configs/default.yaml` / `demo.yaml` | frozen config bytes/hash 与严格 loader | 单独设计版本化配置迁移后再去重 |
| `prompts/archive/**` | frozen replay/cache bundle | 完成兼容窗口与 replay 迁移后才可删除 |
| `m8_feishu_webhook_server.py` 及测试 | 仍是被测试的 loopback 兼容表面 | 有公开弃用记录和替代入口后处理 |
| M8 application composition roots | 兼容现有入口，重排会扩大行为风险 | 独立架构里程碑中迁移并保留兼容 import |
| `requirements/perception-worker.txt` | 独立 CUDA worker 环境 | worker 发布流程改变时单独更新 |

## Docker、CI 与生产声明

仓库没有 Dockerfile 或 CI workflow，因此没有虚构 Docker build 成功或 CI 绿色结果。当前可验证
交付物是锁定的本地 Python/wheel、loopback 服务和离线 Demo。若要容器化或部署公网服务，需要
独立完成镜像基线、非 root 用户、只读文件系统/持久卷、健康检查、secret 注入、TLS 终止、
依赖许可证清单和 CI 重现；在这些工件出现前，本仓库不声明 production-ready。


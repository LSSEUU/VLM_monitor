# LabCourt

LabCourt 是一个本地优先、契约驱动、可离线复现的化学实验室安全案件系统。它把感知候选组织为带证据、初审、会审、程序审查、告警、申诉和审计记录的案件，不把模型输出直接当作违规事实。

当前架构由两部分组成：

- M0–M6：已冻结的核心契约、确定性证据链、SQLite authority、审计与回放语义。
- M8：不修改 M0–M6 的校园运营增量，包括拓扑、角色权限、运营案件、传感器、通知、知识库、Agent、评估和显式 Feishu 适配器。

## 架构

```text
CLI / loopback HTTP / M8 UI
            |
application -> services -> ports -> adapters
            |
       contracts -> domain rules/state machines
```

默认路径不需要 GPU、网络、真实摄像头或真实人员图像。正式 M8 UI/API 绑定本机 `127.0.0.1:8877`；旧 pilot UI 使用 `8876`。`previews/`（现归档为 `docs/design-reference/`）只是设计参考。

## 五分钟启动（Windows）

要求 Python 3.11 或 3.12，以及已安装的 [uv](https://docs.astral.sh/uv/)。

```powershell
.\labcourt.cmd setup
.\labcourt.cmd platform
```

然后打开 <http://127.0.0.1:8877/>。该路径只创建 Git 忽略的本机 Demo 数据，不联网、不调用真实模型、不发送外部通知。

不使用 Windows 包装器时：

```powershell
uv sync --all-groups --locked
uv run --locked labcourt demo platform
```

M6 离线报告演示：

```powershell
.\labcourt.cmd offline-demo
```

## 常用命令

```powershell
.\labcourt.cmd --help
.\labcourt.cmd validate-config --config configs/default.yaml
.\labcourt.cmd schemas export --check
.\labcourt.cmd demo bootstrap
uv run --locked labcourt demo api --check
.\labcourt.cmd demo e2e
uv run --locked labcourt pilot ui
make quality
```

Feishu、真实模型和传感器只通过显式的 preflight、activation 和操作命令启用；它们不是默认 Demo 路径。

## 文档导航

- [快速开始](docs/quickstart.md) · [用户指南](docs/user-guide.md) · [配置](docs/configuration.md)
- [架构](docs/architecture.md) · [数据契约](docs/data-contracts.md) · [API](docs/api.md)
- [部署](docs/deployment.md) · [运维](docs/operations.md) · [开发](docs/development.md)
- [安全与隐私](docs/security-and-privacy.md) · [故障排查](docs/troubleshooting.md)
- [产品基线](docs/request.md)
- [M0–M6 冻结规范](docs/spec/labcourt-vibe-coding-spec.md)
- [M8 校园运营规范](docs/spec/labcourt-campus-operations-spec.md)
- [历史资料索引](docs/archive/README.md)
- [仓库清理报告](docs/repository-cleanup.md)
- [模型许可证登记](docs/model-license-register.md) · [生产适配器准入](docs/m8-production-adapter-intake.md)

## 已知限制

- 这是本地 Demo/工程候选，不是已部署的公网生产系统；仓库当前没有 Docker 或生产部署声明。
- Python 包元数据版本是 `0.1.0`；本次清理不改变业务版本或冻结契约。
- 演示视频和机器弱标签不是 ground truth；尚未声明检测准确率、误报率、吞吐、成本或现场就绪度。
- 不实现人脸识别、face embedding 或跨摄像头 ReID；身份来自外部授权映射。
- VLM 不能提供客观计数、持续时间、身份、坐标或证据存在性；模型失败必须进入 typed failure、backlog 或案件状态。
- 案件自动创建只能产生 `PENDING_VERIFICATION`，不直接执行纪律处分；外部通知的 provider acceptance 不等于真实送达。

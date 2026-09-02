# LabCourt 配置

## 配置文件

配置由 `validate-config` 严格解析 YAML。推荐先复制现有样例，再修改已有字段，不要
新增未在契约中定义的键：

```text
configs/default.yaml   离线基础路径：precomputed 感知、fake screening/hearing
configs/demo.yaml      校园 Demo：离线 precomputed 感知和 fake provider，含演示安全信号
configs/pilot.yaml     本地视频 Pilot：local-worker 感知和外部 screening
```

`default.yaml` 是唯一通用基线。`demo.yaml` 与 `pilot.yaml` 是受版本控制的运行快照，暂不改成 YAML 继承：严格 loader 明确拒绝 alias/merge key，且完整配置字节的 SHA-256 已进入 manifest、回放和回归契约。清理时压缩它们会改变既有运行身份；待引入版本化 overlay contract 和迁移方案后再处理。

检查命令：

```text
uv run --locked labcourt validate-config --config configs/default.yaml --json
```

## 常用区段

- `run`：运行模式、`REPLAY_LOCKED` 重放模式、随机种子和 `runs` 工作区。
- `storage`：SQLite 文件名、锁等待时间、媒体和图像大小上限。
- `zones`、`l0`：摄像头区域、风险等级、所需 PPE 和本地预防提醒；`persist_events` 在样例中为 `false`。
- `perception`：`precomputed` 或 `local-worker`、检测提示词、关联和可观测性阈值。
- `absence`、`presence`：缺失型/存在型驻留阈值、`STRICT_CAUSAL` 和冷却策略。
- `evidence`：时间窗、裁切尺寸、隐私变换和编码版本。
- `screening`、`hearing`：provider profile、超时、图片/token/响应预算。
- `procedural_gate`、`precedents`、`alerts`：确定性守门、判例和告警策略。
- `regression`、`training`、`retention`、`safety`：回归门槛、标签发布、保留期和硬信号来源。

修改配置后应重新运行 `validate-config`；配置错误返回退出码 2。

provider 的 `model` 与 `revision` 可使用完整值 `${ENV_NAME}` 在装载时解析；缺失或空值会 fail closed。`endpoint_env`、`api_key_env`、感知 worker 及生产适配器配置保存的是大写环境变量名称，运行时再取值。manifest 只记录这些名称和模型部署身份，不记录 secret 值。

## Pilot 的额外配置

`configs/pilot.yaml` 的 `perception.provider` 为 `local-worker`，并固定了 detector、pose、
tracker、软件版本和 `local_files_only: true`。worker Python 路径由
`LABCOURT_PERCEPTION_PYTHON` 指定；若未设置，代码会尝试项目下的
`.venv-perception/Scripts/python.exe` 或 `.venv-perception/bin/python`。

`requirements/perception-worker.txt` 只服务这个隔离的 CUDA worker；基础项目仍以 `pyproject.toml`/`uv.lock` 为依赖权威。该文件不是自动生成物，目前按 `scripts/setup_perception_worker.ps1`、`configs/pilot.yaml` 的 `required_software_versions` 和模型许可证登记手工同步更新；变更后需重建 `.venv-perception` 并验证 READY handshake 与权重 hash。

该配置的外部 screening profile 使用：

```text
LABCOURT_SCREENING_ENDPOINT
LABCOURT_SCREENING_API_KEY
```

密钥只放入环境变量，不写入 YAML、命令参数、日志或 manifest。

## Qwen 会审和平台 Agent

`hearing qwen-demo` 与 M8 Agent 使用以下环境变量：

```text
LABCOURT_QWEN_ENDPOINT
LABCOURT_QWEN_API_KEY
```

它们只用于显式的真实 Qwen 演示；默认离线 fixture 不需要设置。Windows 可使用
`scripts/windows/setup-m8-qwen-hearing-env.ps1` 和
`scripts/windows/run-m8-qwen-hearing-demo.ps1`，脚本会遮罩输入 key。

校园平台把 fixture screening profile 的部署字段命名为
`LABCOURT_PLATFORM_FIXTURE_ENDPOINT` 和 `LABCOURT_PLATFORM_FIXTURE_API_KEY`。默认离线
fixture 流程不发起外部调用；这两个名称只出现在平台 readiness/config 组合中。

## Feishu optional extras

基础安装不包含可选 provider。按用途安装锁定 extra：

```text
uv sync --all-groups --extra video --locked
uv sync --all-groups --extra feishu-inbound --locked
uv sync --all-groups --extra feishu-live --locked
```

- `video`：安装固定版本的 `opencv-python-headless`，供真实视频 smoke 使用。
- `feishu-inbound`：安装固定版本的 `cryptography`，供加密 inbound webhook 使用。
- `feishu-live`：安装固定版本的 `lark-oapi`，供 Feishu long connection 使用。

## Feishu 环境变量

Feishu Windows 统一入口 `labcourt.cmd feishu ...` 使用：

```text
LABCOURT_FEISHU_APP_ID
LABCOURT_FEISHU_APP_SECRET
LABCOURT_FEISHU_TEST_OPEN_ID
LABCOURT_FEISHU_WORKER_TOKEN
```

启用完整 inbound webhook 时，另需：

```text
LABCOURT_FEISHU_ENCRYPT_KEY
LABCOURT_FEISHU_VERIFICATION_TOKEN
```

`labcourt.cmd feishu setup` 默认只配置快速 sandbox 演示；完整 webhook/发送流程还要求
上面的 authority 环境变量和已提交的 typed activation。真实租户、真实学生资料和生产
凭据不属于离线 Demo 配置。

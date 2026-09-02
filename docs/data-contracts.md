# LabCourt 数据契约

## 契约来源

运行时结构定义在 `src/labcourt/contracts/`，外部能力接口在 `src/labcourt/ports/`。核心契约和语义见 `docs/spec/labcourt-vibe-coding-spec.md`；M8 新增契约见 `docs/spec/labcourt-campus-operations-spec.md`。`schemas/` 是由 Pydantic 生成并提交的 JSON Schema 快照，不是另一份手工模型。

契约优先顺序是：先改 Pydantic model、schema 快照和 contract tests，再实现 application/services/adapters 行为。M0–M6 的 wire contract、确定性身份和 authority 语义冻结；M8 只能增量扩展，不能改变已有 schema 的字节内容。

## 核心不变量

- 所有输入、输出、命令、回执、失败和 manifest 使用严格 typed model；未知结构或模型自由文本不能被宽松解析为事实。
- 时间以权威 frame index/服务端注入时钟为准；对象 ID、版本和内容寻址值必须可确定重算。
- 证据包保存时间/空间引用、观测充分性、媒体或 raw artifact 引用及字节 hash，形成闭合引用链。
- `RunManifest` 记录配置、provider/model、schema hash、prompt bundle hash、输入/输出工件和运行模式，支持 offline/replay/production 区分。
- VLM 输出不是客观计数、时长、身份、坐标或证据存在性的来源；弱标签不是人工真值。
- 所有外部模型调用都必须有 fake、timeout、cache、manifest 和 raw response reference；失败转为 typed exit、backlog 或 case state。

## M0–M6 数据链

```text
FrameRef / 输入
  -> perception observation
  -> presence/absence FSM
  -> evidence pack
  -> screening request/response
  -> hearing/procedural review
  -> verdict/case
  -> alert_outbox / appeal / precedent / report
```

`STRICT_CAUSAL` 是生产默认确认策略。未来合规状态只能产生新的版本和审计，不得删除已经确认的历史违规区间。

## M8 契约域

M8 contracts 覆盖以下命名域（具体字段以对应 Pydantic model 和生成 schema 为准）：

- `m8_operations`、`m8_access_cases`、`m8_case_persistence`：校园拓扑、角色、作用域、运营案件和版本化迁移命令。
- `m8_sensor_signals`、`m8_sensor_persistence`：来源真实性、传感器信号、质量、raw signal 引用和设备健康。
- `m8_notifications`、`m8_notification_*`：通知意图、卡片、outbox、dispatch、回复、确认和升级回执。
- `m8_knowledge`、`m8_knowledge_*`：知识目录、文档版本、答案投影和精确 citation；普通知识文档不能成为 rule authority。
- `m8_agent_chat`、`m8_prehearing`、`m8_evaluation`、`m8_calibration`：Agent 对话、会审前门、评估数据和非 LLM 影子校准。
- `m8_feishu_*`：sandbox activation/revocation、inbound challenge、outbox transport、live 状态和个人离线 demo。

角色 authority 由服务端从持久化记录解析：`LEADER`（只读）、`SAFETY_OFFICER`（案件动作）、`STUDENT`（本人消息/申诉）、`OPERATIONS`（设备和健康）。案件自动创建只能为 `PENDING_VERIFICATION`，关键状态迁移绑定 actor、capability、源版本、源 authority hash、原因、证据/信号引用和审计序列。

## Schema、迁移与资源身份

- Schema 目录：`schemas/`；生成/校验入口：`labcourt schemas export`、`make schemas-check`。
- 核心 SQLite 迁移：`src/labcourt/adapters/storage/migrations/0001..0018.sql`。
- M8 使用独立迁移集合/命名空间；新增表不得重写冻结表语义。
- Prompt 当前版本在 `prompts/` 和 `prompts/m8_v2/`；历史兼容版本在 `prompts/archive/` 与 `prompts/archive/citation_required/`。
- screening/hearing request 中记录并校验支持的 prompt bundle SHA-256；渲染器通过固定路径映射 bundle，不能凭文件内容猜测版本。
- 工件、raw response、媒体、manifest、审计和迁移提交必须能够通过 ID/hash 互相引用；删除或改名会破坏 replay 和 authority closure。

## 兼容策略

任何字段、枚举、状态或路由变更都必须：

1. 先增加/修改 typed contract 与 schema 快照；
2. 增加 contract/兼容测试并检查 M0–M6 schema 未变化；
3. 更新 migration、manifest、文档和版本号；
4. 对旧 prompt、旧回放和 Windows CLI 入口保留兼容 shim，直到有明确迁移证明。

## 当前有效 Prompt 清单

仓库共保留 17 个 Jinja 文件；没有无引用模板。路径只决定装载位置，bundle identity 仍由模板字节、role、schema、变量集和 renderer version 计算。

| 用途 | 文件 | 装载定义 | 运行调用方 |
|---|---|---|---|
| 当前 M3 screening/repair | `prompts/screening_{presence,absence,structure_repair}_v1.jinja` | `PROMPT_DEFINITIONS` | `services/m3.py`、`application/screening_request.py`、`application/structure_repair.py` |
| 冻结 M4 hearing | `prompts/hearing_{prosecutor,defender,judge}_v1.jinja` | `HEARING_PROMPT_DEFINITIONS` | `services/m4_operations.py`、`application/hearing_request.py` |
| M8 hearing v2 | `prompts/m8_v2/hearing_{prosecutor,defender,judge}_v1.jinja` | `M8_HEARING_PROMPT_V2_DEFINITIONS` | `services/m8_hearing_runtime.py`、`services/m4_operations.py` |
| M3 历史回放 | `prompts/archive/screening_{presence,absence,structure_repair}_v1.jinja` | `LEGACY_PROMPT_DEFINITIONS` | `services/m3.py` 按已记录 bundle SHA 选择 |
| M3 citation 回放 | `prompts/archive/citation_required/screening_{presence,absence}_v1.jinja`，复用 archive repair | `CITATION_REQUIRED_PROMPT_DEFINITIONS` | `services/m3.py` 按已记录 bundle SHA 选择 |
| M4 历史回放 | `prompts/archive/hearing_{prosecutor,defender,judge}_v1.jinja` | `LEGACY_HEARING_PROMPT_DEFINITIONS` | `services/m4_operations.py` 按已记录 bundle SHA 选择 |

archive 模板不在默认 current definition 中，但仍是 replay contract，不能删除或改字节。

不要把 `docs/archive/` 中的历史叙述当作当前数据定义；当前定义以源码、schema、迁移和测试为准。

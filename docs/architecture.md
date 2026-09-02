# LabCourt 当前架构

## 范围与权威来源

当前系统是一个离线优先的模块化单体：冻结的 M0–M6 实验室裁决核心，加上不改变旧 wire contract、确定性身份、SQLite authority、审计和回放语义的增量 M8 campus-operations 平台。

权威来源按以下顺序理解：

1. `docs/spec/labcourt-vibe-coding-spec.md`：M0–M6 冻结契约和裁决语义。
2. `docs/spec/labcourt-campus-operations-spec.md`：M8 增量产品化契约；明确 M0–M6 继续冻结。
3. `src/labcourt/`、`schemas/`、迁移文件和 contract tests：当前 HEAD 的可执行事实。

`docs/archive/milestones/M8.md` 是历史进度记录。它只覆盖到 f2b，而当前代码还包含 Agent、Feishu live、evaluation、prehearing、calibration 等 M8 能力；不要把它当作当前完整实现清单。历史 milestones/progress 已统一放在 `docs/archive/`，保留作追溯资料。

## 模块边界

```text
CLI / loopback HTTP / 正式 UI
            |
        application       编排、权限解引用、状态迁移、失败路由
            |
        services           业务流程和投影
            |
        ports              外部能力的稳定接口
            |
        adapters           SQLite、文件工件、Jinja、模型/传感器/Feishu 适配器
            |
        contracts          Pydantic 输入、输出、命令、回执和 manifest
            |
        domain             纯规则、状态机、确定性计算
```

`domain/` 不依赖 HTTP、数据库、OpenCV、Torch 或云 SDK。模型、传感器和外部通知只能通过 ports/adapters 接入；默认路径不需要 GPU、网络或真实外部账户。

正式 M8 平台由 `m8_platform_server.py`、`m8_platform_demo_api.py` 和 `m8_ui_web/` 组成；较小的 loopback API 由 `m8_api_server.py` 提供。`pilot_ui_web/` 是兼容的 M0–M6 pilot 入口，不是正式 M8 UI。`docs/design-reference/labcourt-ops-ui/` 仅为 design-only 预览。

## 数据流与 authority

M0–M6 主链为：

```text
输入媒体/事件
  -> L0 预防
  -> L1 确定性感知与存在/缺失状态机
  -> L2 时间/空间证据包
  -> L3 初审（严格 schema 输出）
  -> L4 控辩会审与主动取证
  -> L5 程序审查
  -> L6 判例、申诉、反哺
  -> 告警 outbox / 报告 / 可回放工件
```

M8 在同一核心旁增加校园拓扑、来源、传感器、运营案件、角色投影、通知 outbox、知识库、Agent、评估和 Feishu 适配器。所有关键写操作都由服务端从持久化 actor/capability authority 解引用，使用源版本和 authority hash 做乐观并发检查，并写入审计链；客户端自报的 role、scope 或 capability 不是事实。

权威边界：

- 帧索引、持续时间、身份、坐标、计数和证据存在性来自确定性代码、存储或已授权信号，不来自 VLM 自报。
- VLM 只能提出结构化建议；解析失败、超时、模型不适用或证据不足必须转为 typed failure/backlog/case state。
- `STRICT_CAUSAL` 下，后续恢复不能抹去已经发生的违规区间。
- 案件自动创建的初态是 `PENDING_VERIFICATION`；禁止直接纪律处分，关键迁移必须有明确人工确认。
- 通知采用 outbox 和幂等 dispatch；Feishu、传感器和模型都不能进入 domain 层。

## 运行入口

```powershell
uv run --locked labcourt demo platform   # 正式 M8 UI/API，默认 127.0.0.1:8877
uv run --locked labcourt demo api        # 较小的个人 Demo API
uv run --locked labcourt pilot ui        # 兼容 pilot UI，默认 127.0.0.1:8876
uv run --locked labcourt --help
```

Feishu live、webhook 和 outbox worker 必须通过显式 CLI/脚本启用；它们不是默认网络路径。Windows 包装器属于公开兼容入口，清理时只能在保留兼容 shim 和测试覆盖的前提下合并。

## 版本与变更规则

- Pydantic contracts 是单一结构定义；`schemas/` 由代码生成并提交，不能手工维护第二份 schema。
- JSON Schema 使用 Draft 2020-12；兼容加字段升 minor，破坏性变更升 major。
- M0–M6 schema、确定性 ID、authority 语义和 prompt bundle identity 视为冻结；M8 只新增命名空间/表/contract。
- `src/labcourt/adapters/storage/migrations/` 保存核心 SQLite 迁移；M8 迁移位于 M8 专用存储路径，迁移不可重写或删除。
- prompt 文件路径与 SHA-256 bundle identity 参与 replay/缓存/审计。`prompts/archive/` 和 `prompts/archive/citation_required/` 虽是历史版本，仍需保留以支持兼容回放。
- 当前生成 schema、迁移、prompt、manifest、ADR 和测试是可删除性判断的依据；历史说明文档只可归档，不能替代运行时契约。

## 清理边界

可整理的是文档索引、重复说明和设计预览媒体；必须保留 contracts、schemas、migrations、prompts、manifests、正式 UI、CLI 包装器和相关测试。任何删除前先进行引用扫描并提供兼容测试；不要通过重命名历史资源来改变其内容身份。

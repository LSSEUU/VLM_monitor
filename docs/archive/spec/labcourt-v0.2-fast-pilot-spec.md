# LabCourt v0.2 快速初版实施规格

**文档版本**：0.2.0-draft
**日期**：2026-08-07
**状态**：Agent 可执行规格
**目标仓库**：`LSSEUU/VLM_monitor`
**建议仓库路径**：`docs/spec/v0.2/labcourt-v0.2-fast-pilot-spec.md`
**需求基线**：`docs/request.md`
**现有实现权威**：`docs/spec/labcourt-vibe-coding-spec.md`、`docs/architecture-decisions/`、现有 Pydantic contracts 与测试
**主要执行者**：本地 Codex / coding agent，配合一名项目负责人和一名安全业务审核人

---

## 0. 使用说明

本规格用于尽快做出一份具备主要功能、可用真实视频演示的 LabCourt 初版。它不是对 M0–M6 的重新设计，也不是生产化总规格。

当前仓库已经具备较完整的案件、证据、初审、会审、程序审查、告警、判例、申诉、训练数据、恢复和回放能力，但主运行路径仍以预计算感知和 Fake VLM 为主。本阶段只解决最关键的产品缺口：

> 让真实本地视频经过真实视觉感知和真实 VLM，产出真实证据包、案件结论和可读报告。

### 0.1 执行原则

1. **先纵向打通，再横向扩展。** 第一条可运行链路优先于更多规则、更多模型或更多基础设施。
2. **复用现有契约。** 能使用 `FrameRef`、`Detection`、`FrameBundle`、`CandidateEvent`、`EvidencePack`、`ScreeningResult`、`Verdict` 和 `Case` 时，不新增平行模型。
3. **不重做 M0–M6。** 只有现有实现实际阻塞真实链路时，才做局部修复。
4. **初版只保证本地 MP4。** RTSP、NVR、多机位和长期在线服务不阻塞本阶段。
5. **真实感知先支持一个规则。** 首条主链只要求 `PPE_GOGGLES_MISSING`；主链稳定后再加入 `REAGENT_CONTAINER_OPEN`。
6. **灰区允许人工接管。** 初版不要求真实三角色会审成为发布阻塞项，`ESCALATED`、模型不可用和证据不足案件可进入现有人工复核或申诉路径。
7. **测试够用即可。** 每个阶段运行最小相关测试；全量质量门只在准备合并或发布候选时运行一次。
8. **阶段性成果必须进入 Git。** Codex 不得把大量未提交修改长期堆在工作区。
9. **不使用破坏性 Git 命令。** 禁止 `git reset --hard`、`git clean -fd`、强制推送以及未经确认丢弃已有修改。
10. **不虚构性能结论。** 准确率、延迟、吞吐和成本只记录实测值，不预先宣称达标。

### 0.2 初版一句话完成标准

在一台本地开发机上执行：

```bash
labcourt pilot run \
  --config configs/pilot.yaml \
  --video inputs/pilot-demo.mp4 \
  --run-id pilot-001
```

系统能够完成：

```text
真实 MP4
→ 真实人物/护目镜检测与匿名跟踪
→ L0 软提醒
→ PPE 缺失候选事件
→ 隐私安全 EvidencePack
→ 真实 OpenAI-compatible VLM 初审
→ 确定性程序审查
→ 案件结论与告警决定
→ 静态 HTML 报告
→ 人工复核/申诉入口
→ REPLAY_LOCKED 重放
```

---

## 1. 本阶段产品范围

### 1.1 必须交付：基础功能主链

初版必须具备以下能力：

1. 从受控本地路径读取一段 MP4。
2. 逐帧运行真实检测器，至少输出 `person` 和 `goggles`。
3. 为人物生成仅在单视频/单相机内有效的匿名 `track_ref`。
4. 使用现有区域和 PPE 关联逻辑判断当前人物是否存在护目镜检测。
5. 触发一次仅在内存中去抖、不建案、不持久化的 L0 软提醒。
6. 使用现有缺失型状态机形成 `PPE_GOGGLES_MISSING` 候选事件。
7. 使用真实视频像素建立隐私安全 EvidencePack。
8. 通过真实 OpenAI-compatible endpoint 执行 L3 初审。
9. 使用现有严格解析、证据引用校验和确定性程序审查。
10. 对非灰区案件完成结案和告警决策。
11. 对灰区、超时、证据不足案件进入 backlog 或人工复核，不丢案、不伪造成功。
12. 输出案件索引和单案 HTML 报告。
13. 支持一次人工维持或改判，并进入现有申诉/终局链路。
14. 支持使用已保存模型响应执行 `REPLAY_LOCKED`，且不再次调用 provider。
15. 输出一份简单的 `metrics.json`，记录候选数、案件数、模型调用数、延迟和失败数。

### 1.2 第二条规则：主链稳定后加入

在 `PPE_GOGGLES_MISSING` 完成后，增加：

```text
REAGENT_CONTAINER_OPEN
```

它用于证明存在型规则也能复用同一条证据与裁决主链。

第二条规则的初始候选条件可以保持简单：

```text
reagent_bottle 位于指定区域
且 bottle_cap 未在瓶口关联区域内匹配
且条件连续达到配置的 dwell threshold
```

该条件只产生候选事件，最终是否构成违规仍由 VLM 和程序审查决定。

### 1.3 不阻塞初版的能力

以下项目明确延后：

- RTSP 长连接、摄像头发现、NVR 集成；
- 完整前后端管理系统；
- 多租户、账号、细粒度权限；
- 多机位主动取证；
- 真实 BGE-M3/CLIP 判例向量检索；
- 检测器训练、LoRA、灰度发布；
- 生产企业微信/钉钉告警；
- 明火、烟雾和无人值守加热的安全认证；
- 人脸识别和跨摄像头 ReID；
- Kafka、Kubernetes、分布式任务队列；
- 将真实三角色会审设为首个可演示版本的强制依赖。

这些能力不得被用作推迟主链交付的理由。

---

## 2. 当前仓库基线与实际缺口

| 能力 | 当前基线 | 本阶段动作 |
|---|---|---|
| 本地视频解码 | 已有受控 OpenCV 视频源、帧哈希和像素读取 | 直接复用 |
| 统一帧/检测契约 | 已有 `FrameRef`、`Detection`、`FrameBundle` | 直接复用 |
| 感知编排 | 已有区域、PPE 关联、L0、缺失型 FSM | 接真实 Detection 输入 |
| 存在型 FSM | 已有 `PresenceFSM` | 第二条规则时接入主编排 |
| 证据构建 | 已有 EvidenceBuilder、时序选帧、隐私裁切 | 直接接真实视频像素 |
| VLM 请求核心 | 已有 OpenAI-compatible 请求封装、媒体校验和严格响应提取 | 实现真实 HTTP transport 和组合根 |
| M3 主运行 | 当前组合根偏向 `precomputed + Fake VLM` | 新增 pilot 组合根，不复制业务逻辑 |
| M4 会审 | 状态机和存储较完整，但默认 Fake 角色和 Fake 取证 | 初版保留，灰区可人工接管；后续接真实角色 |
| L5 程序审查 | 已有确定性验证 | 直接复用 |
| M5 结案、告警、申诉 | 已有 SQLite 逻辑和 Fake 告警通道 | 接本地真实输出，复用申诉 |
| M6 报告和回放 | 已有离线报告与回归基础 | 生成真实 pilot 报告，不再标记 synthetic/fake |
| Git/CI | 有 Makefile 质量门，仓库提交历史较少 | 增加阶段提交和进度日志 |

本阶段不得为了“统一得更漂亮”重写上述已有模块。

---

## 3. 快速主链架构

### 3.1 主流程

```text
Verified local MP4
  → OpenCvVideoSource
  → RealPerceptionAdapter
      ├─ detector: person / goggles
      ├─ tracker: anonymous track_ref
      └─ optional pose/keypoints
  → FrameBundle stream
  → existing PerceptionPipeline / AbsenceFSM
      ├─ L0 in-memory reminder
      └─ CandidateEvent
  → existing EvidenceBuilder
  → EvidencePack + privacy-safe crops
  → existing ScreeningCoordinator
      └─ OpenAICompatibleVLMClient + real HTTP transport
  → existing deterministic procedural review
  → existing M5 finalization / alert decision
  → pilot static report
```

### 3.2 最小新增组件

建议新增以下组件，名称可根据仓库现有命名规范调整：

```text
src/labcourt/adapters/perception/local_worker.py
src/labcourt/adapters/vlm/http_transport.py
src/labcourt/services/pilot_operations.py
src/labcourt/pilot_cli.py
src/labcourt/contracts/pilot.py              # 仅在现有报告模型无法表达时新增
configs/pilot.yaml
scripts/run_pilot_smoke.py                    # 可选
```

不应新增第二套 Case repository、第二套 EvidencePack 或第二套模型响应存储。

### 3.3 进程边界

真实视觉依赖可能较重，初版推荐让检测器和跟踪器位于独立本地进程：

```text
LabCourt Python core
    ↕ bounded JSONL/stdin-stdout 或 localhost HTTP
Local Perception Worker
    ├─ detector
    ├─ tracker
    └─ optional pose
```

这样做的目的只是隔离模型依赖，不是建设微服务平台。

进程协议必须：

- 有明确版本；
- 每个请求绑定 `frame_id` 和像素哈希；
- 每个响应返回同一 `frame_id`；
- 有最大请求/响应字节；
- 有超时；
- worker 崩溃返回 typed failure；
- 不允许失败时悄悄返回空检测列表并标记成功；
- 不允许保存未授权原始帧副本。

如果现有环境中直接进程内加载模型更快完成，可以先采用进程内 adapter，但接口仍须保持可替换，且领域层不得 import 重模型包。

---

## 4. 分阶段实施计划

每个阶段都必须产生可观察结果和一个 Git 提交。Codex 一次只做一个阶段，不同时重构无关模块。

## 4.1 阶段 A0：Pilot 骨架和进度管理

### 目标

建立真实初版的唯一入口，但先不接真实模型。

### 实现

1. 新增 `configs/pilot.yaml` 示例。
2. 新增 `labcourt pilot` 命令组。
3. 新增：

```bash
labcourt pilot run
labcourt pilot perceive
labcourt pilot report
labcourt pilot review
```

4. `pilot run` 初始只完成参数、路径、配置和 run scope 校验。
5. 新增 `docs/progress/v0.2-pilot.md`。
6. 在进度文件中记录：
   - 当前分支；
   - 起始 commit SHA；
   - 当前阶段；
   - 已完成事项；
   - 下一步；
   - 执行过的测试命令；
   - 已知限制；
   - 需要人工提供的输入。

### 最小验证

- CLI help 测试；
- 配置加载测试；
- 非法视频路径 fail closed。

### 阶段提交

```text
chore(pilot): add v0.2 configuration and CLI skeleton
```

---

## 4.2 阶段 A1：真实人物与护目镜感知

### 目标

让真实 MP4 产生真实 `FrameBundle(frame, detections)`。

### 初始模型范围

必须输出：

```text
person
goggles
```

建议但不阻塞首个成功运行：

```text
person keypoints
```

为提高效率，第一版允许使用人体框上部推导头部区域，不必在第一轮同时接入 RTMPose。只有真实视频证明框上部回退明显不可用时，再增加姿态模型。

### 具体要求

1. 实现真实 `PerceptionProvider.detect()`。
2. 为每个 `person` 生成单视频内稳定的匿名 `track_ref`。
3. 检测输出必须映射到现有 `Detection` 契约。
4. `model_manifest_id` 必须来自真实模型 manifest，不得使用 Fake manifest。
5. 记录：
   - provider；
   - model；
   - revision；
   - 权重 SHA-256；
   - prompts；
   - 运行设备；
   - 关键阈值。
6. 输出一个可选的调试可视化：

```text
runs/<run_id>/debug/perception-preview.mp4
```

预览只用于人工确认，可不进入权威案件工件。

7. `labcourt pilot perceive` 应输出：

```text
frames_processed
detection_count
person_count
goggles_count
track_count
provider_failures
manifest_id
preview_path
```

### 人工配合点 1

项目负责人提供三段短视频即可，不启动大规模标注项目：

- 正常佩戴护目镜；
- 明显未佩戴护目镜；
- 遮挡或低头的歧义视频。

人工只需检查预览视频中的框和 track 是否基本合理，并在 `configs/pilot.yaml` 中确认区域多边形。

### 最小验证

- 一个 adapter contract test；
- 一个短视频 smoke test；
- worker 超时/崩溃测试；
- frame identity 不匹配测试。

不要在此阶段追求检测准确率指标或完整模型 benchmark。

### 阶段提交

```text
feat(perception): generate real detections from local video
```

---

## 4.3 阶段 A2：真实候选事件和证据包

### 目标

让真实 Detection 进入现有 L0、L1 和 L2。

### 具体要求

1. 将真实 `FrameBundle` 接入现有 `PerceptionPipeline`。
2. 复用现有 PPE 关联和 `AbsenceFSM`。
3. `STRICT_CAUSAL` 保持默认，不恢复旧的未来检出自动抹除逻辑。
4. L0 软提醒：
   - 进入高风险区后当前帧护目镜关联失败即可提醒；
   - 提醒冷却只存在内存；
   - 不建案；
   - 不进入审计链；
   - 不保存人员轨迹历史。
5. L1 候选事件：
   - 使用帧号计时；
   - 达到驻留阈值才产生问责候选；
   - 保留窗口确证和晚到反证机制。
6. 使用现有 EvidenceBuilder 建立：
   - panorama；
   - subject crop；
   - head/PPE focus crop；
   - temporal crops；
   - objective facts；
   - privacy receipt。
7. 云端允许的裁切必须来自现有 `PPE_PRESERVING_REDACTION`；完整 panorama 不得发给外部 VLM。
8. `pilot run` 在此阶段应能停在 `EVIDENCE_READY` 并输出报告。

### 人工配合点 2

人工打开生成的 3–10 张裁切，检查：

- 涉事人物是否正确；
- 头部区域是否包含护目镜判定所需像素；
- 无关脸部和背景是否被最小化；
- 是否存在明显错误的区域配置。

人工反馈只允许改：区域、阈值、头部外扩比例和选帧数量。不要因此启动新的 UI 或标注平台。

### 最小验证

- 一个真实 Detection → CandidateEvent 集成测试；
- 一个 CandidateEvent → EvidencePack 集成测试；
- 一个 L0 不落盘断言；
- 一个外部媒体策略拒绝测试。

### 阶段提交

```text
feat(pilot): build evidence packs from real perception
```

---

## 4.4 阶段 A3：真实 VLM 初审

### 目标

使用现有 VLM 请求、严格解析和存储机制调用真实 OpenAI-compatible endpoint。

### 新增 HTTP transport

实现 `OpenAICompatibleTransport` 的真实版本。它只负责一次网络请求，不负责重试策略、解析业务或案件状态。

必须满足：

- endpoint 由配置指定，但允许使用环境变量展开；
- API Key 只从环境变量读取；
- endpoint、Authorization header 和密钥不得出现在日志、异常、数据库或 manifest；
- TLS 校验默认开启；
- connect/read timeout 明确；
- 最大响应字节明确；
- 非 2xx、超时、网络不可用映射为现有 typed provider failure；
- transport 不做无限重试；
- 上游响应 envelope 不直接打印；
- 原始选中 content 继续由现有 response store 持久化。

### Provider 配置示例

`configs/pilot.yaml` 可扩展为：

```yaml
perception:
  provider: local-worker

providers:
  pilot-screening:
    provider: openai-compatible
    model: ${LABCOURT_SCREENING_MODEL}
    revision: ${LABCOURT_SCREENING_REVISION}
    execution_location: EXTERNAL
    transport: HTTP
    endpoint_env: LABCOURT_SCREENING_ENDPOINT
    api_key_env: LABCOURT_SCREENING_API_KEY
    timeout_seconds: 30
    cache_enabled: true

screening:
  provider_profile: pilot-screening
```

实际字段必须以现有 `AppConfig` 为准；只扩展缺失的 provider/transport 枚举，不复制整个配置系统。

### 组合根

新增 pilot 组合根，或把现有 M3 组合根改为 provider factory：

```text
open_pilot_operations_service(...)
```

必须复用：

- `ScreeningCoordinator`；
- Prompt catalog；
- rendered prompt registry；
- `OpenAICompatibleVLMClient`；
- response store；
- cache；
- strict parser；
- structure repair；
- backlog；
- procedural verifier。

真实路径与 Fake 路径只能在 adapter 选择上不同。

### 缺失型初审规则

对每张时序裁切输出：

```text
WORN
NOT_WORN
UNCLEAR
```

由确定性代码聚合：

```text
任一清晰帧为 WORN
  → NOT_ESTABLISHED

全部清晰帧为 NOT_WORN，且清晰帧数达到 K
  → ESTABLISHED

无清晰帧、清晰帧不足或结果冲突
  → ESCALATE / HUMAN_REVIEW
```

VLM 不得决定时长、人数、轨迹连续性和证据是否存在。

### 人工配合点 3

人工只需要：

1. 提供 endpoint、model 和 API Key 环境变量；
2. 审查一份真实渲染后的 screening prompt；
3. 查看前 10 个真实案件的初审结果；
4. 确认是否调整 `K`、概率阈值或提示词。

一次调整后形成版本化配置和 prompt，不反复手工改同一案件。

### 最小验证

- 使用注入 transport 的现有集成测试继续通过；
- 一个真实 endpoint 手工 smoke test；
- 一个真实响应严格解析成功；
- 一个无效 JSON 结构修复或 typed failure；
- 一个超时进入 backlog；
- 一个 cache hit 不再次调用 provider；
- 一个外部媒体越权请求被拒绝。

真实 endpoint 测试默认不进入普通 CI。

### 阶段提交

```text
feat(vlm): enable real OpenAI-compatible pilot screening
```

---

## 4.5 阶段 A4：结案、报告和人工复核

### 目标

把非灰区案件走到可读结果；灰区案件允许人工快速处理。

### 结案路径

必须复用现有：

- fast verdict；
- deterministic procedural review；
- M5 finalization；
- alert policy；
- appeal state machine；
- audit and artifact publication。

### 告警输出

初版新增一个低风险真实输出即可：

```text
LocalJsonAlertChannel
```

或：

```text
LocalWebhookAlertChannel
```

要求：

- 使用 `alert_id` 作为幂等键；
- 有 delivery receipt；
- 失败进入 outbox；
- 重跑不重复发送已确认告警；
- 不直接接生产纪律或处罚系统。

### 人工复核

不得新建复杂审核平台。复用现有人工复核/申诉能力，提供一个薄 CLI：

```bash
labcourt pilot review \
  --run-id pilot-001 \
  --case-id <case_id> \
  --decision ESTABLISHED|NOT_ESTABLISHED|INSUFFICIENT_EVIDENCE \
  --reason-file review.md
```

实现时应映射到现有 human review 或 appeal authority，不新增平行的人工判决数据模型。

### 报告

`labcourt pilot report` 生成：

```text
runs/<run_id>/report/index.html
runs/<run_id>/report/cases/<case_id>.html
runs/<run_id>/metrics.json
```

单案页至少展示：

- 违规类型；
- 视频帧区间；
- 匿名轨迹；
- 关键裁切；
- 检测和关联摘要；
- 初审结果；
- 程序审查结果；
- 最终结论；
- 告警级别；
- 人工复核/申诉状态；
- detector、VLM、prompt、rule 和 manifest 版本；
- “用于安全辅助与记录，不直接作为处罚依据”的声明。

真实报告不得再标记为：

```text
SYNTHETIC_PRECOMPUTED_FAKE
SIMULATED PERCEPTION
FAKE VLM
```

### 最小验证

- 一个成立案件；
- 一个不成立案件；
- 一个证据不足/人工复核案件；
- 一个告警幂等测试；
- 一个报告生成 E2E；
- 一个申诉改判 E2E。

### 阶段提交

```text
feat(report): close pilot cases and publish operator reports
```

---

## 4.6 阶段 A5：REPLAY_LOCKED 和恢复验收

### 目标

证明真实主链仍遵守现有可复现和恢复边界。

### 必须验证

1. 同一 run 使用保存的模型响应执行 `REPLAY_LOCKED`。
2. replay 期间 detector 和 VLM provider 调用计数为零，或明确复用已保存的感知输入。
3. 语义案件结果一致。
4. provider 超时留下的 backlog 可以恢复。
5. 重复执行 `pilot run --run-id ...` 不重复创建 Case。
6. 重复执行不重复发送 Alert。
7. 中断后可以从最近已提交阶段继续，不递归删除 run。

### 阶段提交

```text
test(pilot): verify replay and restart-safe pilot execution
```

---

## 4.7 阶段 B1：存在型规则

只有 A0–A5 全部完成后，才加入 `REAGENT_CONTAINER_OPEN`。

### 新增感知类别

```text
reagent_bottle
bottle_cap
```

### 实现要求

1. 接入现有 `PresenceFSM`。
2. 新增一个小型 `PresenceRuleEvaluator`，把检测关联结果转换为 `condition_met`。
3. 不把“瓶盖不存在”直接当最终违规，只产生候选事件。
4. 使用现有 presence evidence crop 和 screening prompt。
5. 复用同一真实 VLM、程序审查、告警和报告链路。

### 阶段提交

```text
feat(perception): add reagent-container presence rule to pilot
```

---

## 4.8 阶段 B2：真实三角色会审，可后置

真实会审是下一增强阶段，不阻塞初版基础交付。

开始条件：

- 真实感知主链稳定；
- 已收集至少一批真实 `ESCALATED` 案件；
- 初审错误和灰区原因已经可观察；
- 项目负责人确认真实三角色对当前问题有价值。

实现时复用现有 M4，不另建会审框架。初版可以由同一模型的三个独立 profile 扮演三个角色，但必须有独立 prompt、request identity、raw response 和预算。

第一批真实取证只做：

```text
GET_FRAME_RANGE
RECROP_REGION
REDETECT_HIGH_RES
```

不得先做多机位、向量数据库或复杂轨迹服务。

---

## 5. 最小契约变更

### 5.1 优先复用

以下现有模型继续作为唯一业务契约：

```text
FrameRef
FrameData
Detection
FrameBundle
CandidateEvent
Crop
EvidencePack
VLMRequest
VLMResponse
ScreeningResult
Verdict
ProceduralReview
AlertDecision
Case
RunManifest
ModelManifest
```

### 5.2 仅允许新增的 pilot 级报告

如果现有 command report 无法表达真实主链，可新增：

#### `PilotRunRequest`

```text
run_id
config_sha256
video_relative_path
video_sha256
selected_rules
resume
max_cases
```

#### `PilotStageOutcome`

```text
stage
status
input_ref
output_refs
failure_code
```

#### `PilotRunReport`

```text
run_id
manifest_id
video_sha256
perception_mode
model_mode
selected_rules
stage_outcomes
frames_processed
candidate_count
case_count
established_count
not_established_count
insufficient_evidence_count
human_review_count
provider_failure_count
report_index_path
metrics_path
```

这些报告不成为新的案件权威，只是命令边界的可观察结果。

### 5.3 数据库原则

- 优先使用现有 SQLite 表和 repository；
- 不为了 pilot 状态另建第二套案件表；
- 只有现有表无法保存真实 provider identity 或阶段回执时才加 migration；
- 每个 migration 必须小、单向、带一个真实集成测试；
- 不为未来可能需求预建表。

---

## 6. 配置策略

新增 `configs/pilot.yaml`，以当前 `configs/default.yaml` 为基础，仅修改真实 provider 和 pilot 输入所需项。

建议配置内容：

```yaml
run:
  mode: STANDARD
  reproducibility_mode: REPLAY_LOCKED
  workspace: runs

pilot:
  selected_rules:
    - PPE_GOGGLES_MISSING
  max_cases: 20
  write_debug_preview: true
  stop_after_stage: null

perception:
  provider: local-worker
  detector:
    model_id: ${LABCOURT_DETECTOR_MODEL}
    revision: ${LABCOURT_DETECTOR_REVISION}
    weights_path_env: LABCOURT_DETECTOR_WEIGHTS
    score_threshold: 0.35
    high_confidence_threshold: 0.50
    prompts:
      person: ["person"]
      goggles: ["safety goggles", "protective eyewear"]

providers:
  pilot-screening:
    provider: openai-compatible
    model: ${LABCOURT_SCREENING_MODEL}
    revision: ${LABCOURT_SCREENING_REVISION}
    execution_location: EXTERNAL
    transport: HTTP
    endpoint_env: LABCOURT_SCREENING_ENDPOINT
    api_key_env: LABCOURT_SCREENING_API_KEY
    timeout_seconds: 30
    cache_enabled: true

screening:
  provider_profile: pilot-screening
```

配置解析仍必须通过现有 Pydantic config，不使用任意字典绕过校验。

---

## 7. 人工配合方式

本阶段采用少量、高价值人工配合，不建设复杂人工流程。

### 7.1 人工必须提供

1. 三段短视频：正常佩戴、明显未佩戴、遮挡歧义。
2. 一个区域多边形和风险等级。
3. 可用的 VLM endpoint、模型名和 API Key 环境变量。
4. 对前 10 个案件进行一次结果复核。
5. 对初版发布候选进行一次 go/no-go 确认。

### 7.2 Codex 可以自行决定

在不违反现有公理的前提下，Codex 可以自行选择：

- worker 使用 JSONL 还是 localhost HTTP；
- HTTP 客户端库；
- debug preview 的具体实现；
- 模块内部函数拆分；
- 测试 fixture 命名；
- 最小必要的 config 扩展方式。

Codex 不应为了这些实现细节反复向人工提问。选择后记录在 `docs/progress/v0.2-pilot.md`；若选择改变系统公理或持久化权威，再写 ADR。

### 7.3 人工停止点

只有以下情况需要暂停并请求人工：

- 仓库存在无法安全归属的未提交修改；
- 需要覆盖或迁移真实用户数据；
- 需要新增外部付费服务；
- 模型许可证或数据授权不明确；
- 需要决定是否把真实图片发送到外部 provider；
- 真实视频中头部长期不可见，需要调整机位而不是继续调算法；
- 发布候选的真实案件结果存在明显业务争议。

其他问题由 Codex采用保守默认值继续，并记录限制。

---

## 8. Git 阶段管理规则

### 8.1 开始工作

Codex 开始前执行：

```bash
git status --short
git branch --show-current
git rev-parse HEAD
```

若工作区干净：

```bash
git switch -c codex/v0.2-pilot
```

若分支已存在：

```bash
git switch codex/v0.2-pilot
```

若工作区已有修改：

- 不得 reset、clean 或覆盖；
- 先判断修改是否属于当前任务；
- 无法判断时请求人工处理；
- 不把无关修改混入 pilot 提交。

### 8.2 每阶段提交

至少形成以下阶段提交：

```text
chore(pilot): add v0.2 configuration and CLI skeleton
feat(perception): generate real detections from local video
feat(pilot): build evidence packs from real perception
feat(vlm): enable real OpenAI-compatible pilot screening
feat(report): close pilot cases and publish operator reports
test(pilot): verify replay and restart-safe pilot execution
```

每个提交应：

- 对应一个可观察的工作阶段；
- 不夹带无关重构；
- 更新 `docs/progress/v0.2-pilot.md`；
- 在 commit message 正文简述：contract、state transition、scenario、manifest impact；
- 通过该阶段最小测试。

### 8.3 进度日志

`docs/progress/v0.2-pilot.md` 建议格式：

```markdown
# v0.2 Pilot Progress

## Baseline
- branch:
- starting_sha:
- config:

## Current Stage
- stage:
- status:

## Completed
- ...

## Commands Run
- ...

## Known Limitations
- ...

## Human Inputs Needed
- ...

## Next Commit
- ...
```

### 8.4 禁止事项

Codex 不得：

- 使用 `git reset --hard`；
- 使用 `git clean -fd`；
- 强制推送；
- 重写已有公共历史；
- 把 API Key、真实人员原图或本地模型权重提交到仓库；
- 一次提交整个项目的大规模格式化；
- 长时间保留跨多个阶段的未提交修改。

### 8.5 发布候选

准备发布时：

```bash
git status --short
git diff --check
git log --oneline --decorate -n 12
```

工作区必须干净。通过人工确认后，可以创建本地标签：

```bash
git tag -a v0.2.0-alpha1 -m "LabCourt v0.2 real-video pilot"
```

标签和推送由项目负责人决定。

---

## 9. 精简测试策略

### 9.1 原则

1. 不在每个小修改后运行全部测试。
2. 失败时先重跑最小失败节点，不直接反复跑整个仓库。
3. 未改变的阶段不重复验证。
4. 新代码只补能阻止真实回归的测试。
5. 不为 pilot 新增 100% coverage 要求。
6. 不降低或删除现有 M4/M5 质量门。
7. 全量 `make quality` 和 `make demo` 在合并前各运行一次即可。
8. 真实 GPU/外部 VLM 测试为手工发布门，不默认进入普通 PR CI。

### 9.2 每阶段最小测试

| 阶段 | 必须运行 |
|---|---|
| A0 | CLI/config 单元测试 |
| A1 | 感知 adapter contract + 一个短视频 smoke |
| A2 | real Detection → CandidateEvent → EvidencePack 集成测试 |
| A3 | VLM transport 单元测试 + 一个真实 provider smoke |
| A4 | 单案结案/报告 E2E + 人工改判 E2E |
| A5 | replay/provider trap + 幂等恢复 E2E |
| B1 | presence rule 单元测试 + 一条真实视频 E2E |

### 9.3 合并前一次性质量门

```bash
uv run --locked ruff format --check src tests scripts
uv run --locked ruff check src tests scripts
uv run --locked mypy
uv run --locked pytest <pilot-related-tests>
uv run --locked python scripts/export_schemas.py --check
```

在 pilot 相关测试稳定后，再运行一次：

```bash
make quality
make demo
```

若全量测试因与本阶段无关的既有问题失败，记录准确节点和证据，不要为了让全部绿色而绕路修改无关 M0–M6 模块。

### 9.4 外部模型测试回执

真实 provider smoke test 应生成隐私安全回执，至少包含：

```text
provider_profile
model
revision
request_id
response_id
input_image_count
input_pixel_count
latency_ms
input_tokens
output_tokens
estimated_cost
result
```

不得包含 endpoint、API Key、Authorization header 或未脱敏图片。

---

## 10. CLI 规格

### 10.1 完整运行

```bash
labcourt pilot run \
  --config configs/pilot.yaml \
  --video inputs/pilot-demo.mp4 \
  --run-id pilot-001
```

行为：

- 幂等创建或恢复 run；
- 从最近完成阶段继续；
- 输出 JSON 或人类可读摘要；
- 最后打印 `report_index_path`。

### 10.2 只运行感知

```bash
labcourt pilot perceive \
  --config configs/pilot.yaml \
  --video inputs/pilot-demo.mp4 \
  --run-id pilot-001
```

用于快速人工确认检测框和 track，不调用 VLM。

### 10.3 生成报告

```bash
labcourt pilot report \
  --config configs/pilot.yaml \
  --run-id pilot-001
```

不得重新调用 detector 或 VLM。

### 10.4 人工复核

```bash
labcourt pilot review \
  --config configs/pilot.yaml \
  --run-id pilot-001 \
  --case-id <case_id> \
  --decision NOT_ESTABLISHED \
  --reason-file review.md
```

### 10.5 稳定退出码

```text
0  命令成功完成
1  运行完成但存在 backlog、人工复核或未通过案件
2  配置、输入、权限或安全边界使运行无法形成可信结果
```

---

## 11. 运行工件

建议输出：

```text
runs/<run_id>/
├── labcourt.sqlite3
├── current.json
├── input/
│   └── video-manifest.json
├── perception/
│   ├── execution-manifest.json
│   ├── report.json
│   └── preview.mp4                 # 非权威调试工件
├── frames/
│   └── <content-addressed>.png
├── model-responses/
├── report/
│   ├── index.html
│   └── cases/
├── metrics.json
└── pilot-run-report.json
```

真实输入视频默认不复制进 `runs/`；保存受控相对路径、大小和 SHA-256 即可。含真实人员的视频、模型权重和 `.env` 必须在 `.gitignore` 中。

---

## 12. 初版验收场景

### 12.1 必须通过

#### 场景 1：正常佩戴

- 输入：人物进入高风险区并持续佩戴护目镜。
- 预期：不产生成立案件；允许无案件或 `NOT_ESTABLISHED`。

#### 场景 2：明显未佩戴

- 输入：人物在高风险区超过缺失驻留阈值，清晰帧均未佩戴。
- 预期：产生 CandidateEvent、EvidencePack、真实初审和 `ESTABLISHED` 或人工确认成立。

#### 场景 3：遮挡歧义

- 输入：头部长期低头或遮挡。
- 预期：不得在无足够清晰帧时自动输出高置信成立；进入 `ESCALATE`、`INSUFFICIENT_EVIDENCE` 或人工复核。

#### 场景 4：真实 VLM 超时

- 预期：案件进入 backlog；不丢 Case；恢复后复用原 Case；不重复建案。

#### 场景 5：伪造证据引用

- 输入：测试 transport 返回引用不存在 crop 的模型响应。
- 预期：严格解析或程序审查拒绝；不得告警。

#### 场景 6：人工改判

- 输入：对已结案案件提交人工复核/申诉。
- 预期：终局更新，保留原判历史，并产生相应高质量记录。

#### 场景 7：REPLAY_LOCKED

- 输入：复用同一 run 的保存响应。
- 预期：不调用 detector/VLM provider，语义结果一致。

### 12.2 第二条规则验收

#### 场景 8：试剂瓶正常关闭

- 预期：不成立。

#### 场景 9：试剂瓶持续敞口

- 预期：产生存在型候选并进入同一裁决主链。

---

## 13. 初版指标

`metrics.json` 只记录观察值，不设未经实测的强门槛。

至少记录：

```text
video_frames
processed_frames
person_detections
goggles_detections
track_count
l0_reminder_count
candidate_event_count
suppressed_candidate_count
evidence_pack_count
screening_call_count
screening_cache_hit_count
screening_failure_count
established_case_count
not_established_case_count
insufficient_evidence_case_count
human_review_count
alert_count
perception_elapsed_ms
screening_latency_p50_ms
screening_latency_p95_ms
input_tokens
output_tokens
estimated_cost
```

初版发布说明必须明确：

- 指标来自哪几段视频；
- 视频时长；
- 模型和权重版本；
- prompt 和规则版本；
- 是否包含人工干预；
- 结果不能代表生产实验室安全性能。

---

## 14. 完成门

v0.2 基础初版只有同时满足以下条件才算完成：

- [ ] 工作区由 Git 管理且阶段提交完整；
- [ ] 一个命令可以运行真实 MP4；
- [ ] Detection 不是预计算 fixture；
- [ ] 主链不再标记 `SIMULATED PERCEPTION`；
- [ ] L3 使用真实 provider，主链不再标记 `FAKE VLM`；
- [ ] `PPE_GOGGLES_MISSING` 从真实像素走到最终报告；
- [ ] L0 软提醒不落盘；
- [ ] EvidencePack 使用真实像素并通过隐私校验；
- [ ] 模型原始响应受控持久化；
- [ ] 伪造引用无法通过程序审查；
- [ ] 超时进入 backlog；
- [ ] 重跑不重复建案或重复告警；
- [ ] 人工能够维持或改判；
- [ ] `REPLAY_LOCKED` 不调用 provider；
- [ ] 报告中包含模型、规则、证据和终局；
- [ ] `metrics.json` 来自实际运行；
- [ ] pilot 相关测试通过；
- [ ] 合并前运行过一次现有全量质量门，并记录结果；
- [ ] 人工审核人完成一次发布确认。

`REAGENT_CONTAINER_OPEN` 和真实三角色会审可作为 `v0.2.0-alpha2` 或后续增量，不阻塞 `alpha1`。

---

## 15. Codex 执行顺序

Codex 应严格按以下顺序工作：

1. 建立或切换 `codex/v0.2-pilot` 分支。
2. 记录 baseline SHA 和当前测试状态。
3. 完成 A0 并提交。
4. 完成 A1，只证明真实 Detection 流，并提交。
5. 请求人工检查一次 perception preview。
6. 完成 A2，只证明真实 CandidateEvent 和 EvidencePack，并提交。
7. 请求人工检查一次裁切和区域。
8. 完成 A3，接真实 VLM，并提交。
9. 请求人工复核前 10 个案件，只调整一次配置/prompt 版本。
10. 完成 A4，生成报告和人工复核入口，并提交。
11. 完成 A5，验证 replay、backlog 和幂等，并提交。
12. 运行一次 pilot 验收场景。
13. 运行一次全量质量门。
14. 更新进度日志和 release notes。
15. 由人工决定是否进入 B1 和 B2。

Codex 不得在第 4 步之前开发 UI，不得在第 8 步之前接三角色会审，不得在第 12 步之前开展模型训练。

---

## 16. 明确停止绕路的规则

出现以下倾向时，应立即停止并回到当前阶段目标：

- 为真实模型复制一套新的 Case/Evidence/Verdict；
- 为一段 MP4 先建设 RTSP 服务；
- 为 10 个试用案件先建设完整审核后台；
- 为一个 detector adapter 引入分布式队列；
- 为尚未验证的需求预建数据库表；
- 为通过全量测试修改与 pilot 无关的成熟 M6 恢复模块；
- 在主链尚未运行前追求检测器训练；
- 在没有真实灰区样本前接大规模判例向量库；
- 因为模型输出偶有错误而绕过严格解析；
- 通过降低程序审查要求来让 demo “看起来成功”；
- 反复运行全部测试而没有新增信息。

判断优先级时，使用以下问题：

> 这项修改是否让“真实 MP4 → 真实检测 → 真实证据 → 真实 VLM → 真实报告”更接近可运行？

若答案是否定的，它不属于当前基础初版关键路径。

---

## 17. 发布结果

`v0.2.0-alpha1` 应交付：

1. 一条真实 PPE 缺失纵向链路；
2. 一个真实 provider 初审；
3. 一个可读、可复核、可申诉的案件报告；
4. 一个可重放、可恢复的本地运行目录；
5. 一份真实运行指标；
6. 一组阶段性 Git 提交；
7. 一份明确列出未完成能力和现场风险的 release note。

它不是生产级实验室安全系统，也不声称已完成所有 `request.md` 能力。它的价值是把现有离线可信内核变成第一个真实可用产品切片，为后续存在型规则、三角色会审、判例检索、RTSP 和训练闭环提供可信基础。

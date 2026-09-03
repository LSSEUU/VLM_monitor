# M8 会审平台 API（复用冻结 M4）

## 结论与范围

本接入是 M8 的增量平台边界，不是第二套会审实现。API 直接调用现有
`HearingCoordinator`，并从现有 M4 SQLite authority 读取 session、checkpoint、round、
role output、raw-response receipt、补证、Verdict、L5 review 与 backlog failure。

本切片没有修改 M0–M6 wire/authority contracts，也没有修改视觉母版
`docs/design-reference/labcourt-ops-ui/`。正式 `src/labcourt/m8_ui_web/` 案件详情页已经读取本 API。它不自动扫描或强迫案件进入会审，
不新增纪律处分权限，不暴露 raw model response 内容。

## 现有 M4 能力审计

| 能力 | 复用入口/authority | M8 投影 |
| --- | --- | --- |
| 控方、辩方、裁决方 | `hearing_request.py`、`hearing_role_call.py`、严格三角色 payload | `role_outputs`，固定 Prosecutor → Defender → Judge 顺序 |
| 先例注入 | `HearingPrecedentRetrievalService` 与 M5 bridge | 每轮 retrieval receipt、`cited_precedent_refs` |
| 主动补证 | `HearingAcquisitionService`、typed request/execution receipt | `acquisition_requests`、`tool_execution_receipts`，仍受每轮 1 次、总计 2 次限制 |
| L5 程序门控 | `DeterministicHearingProceduralReviewVerifier` | `procedural_reviews`、`l5_status`、`final_verdict` |
| 持久化与恢复 | migration 0008、checkpoint、raw-first response store、exact-role backlog | 终态和重启后通过只读 session locator 重建同一 view |
| 失败权限 | `HearingModelCallFailureAuthority` | `typed_failures`，保留 role、delivery certainty、backlog 与 request 绑定 |

冻结的 M4 上限保持不变：补证不超过 2 次，重审不超过 2 次，Judge 总轮次不超过 5 次；
primary 严格解析失败后最多一次无媒体 repair；角色失败不会由其他角色替代。

## HTTP 契约

两个路由都沿用现有 loopback bearer authentication：

```text
GET  /api/m8/runs/{run_id}/cases/{case_id}/hearing
POST /api/m8/runs/{run_id}/cases/{case_id}/hearing
```

只有当前持久化 authority 中处于 active 状态、具备 `REQUEST_CASE_EVIDENCE` capability、
且 scope 覆盖案件地点的 `SAFETY_OFFICER` 可以查询资格或启动。`LEADER` 仅在已有会审完成或
转人工复核后、具备 `VIEW_MAJOR_EVENTS` 时只读结果；学生和运维不读取会审 view。客户端不能提交 actor、role、
capability 或地点 authority；服务端从 bearer principal、M8 actor repository 和 M4 Case zone
映射重新解析。

POST 使用 `m8-hearing-start-request-v1`：

```json
{
  "schema_version": "m8-hearing-start-request-v1",
  "run_id": "run-2026-08-13-demo",
  "case_id": "case-content-addressed-id",
  "source_status": "ESCALATED",
  "source_screening_id": "<64-hex>",
  "source_evidence_pack_id": "<64-hex>",
  "source_evidence_pack_version": 1,
  "model_mode": "OFFLINE_FIXTURE",
  "explicit_start": true,
  "request_manifest_id": "<64-hex>"
}
```

`source_status` 只允许 `ESCALATED` 或 `REWORK_REQUIRED`。服务端还会原子前置核对当前
Case、最新 screening、当前 EvidencePack 和 RunManifest fence。`ESCALATED` 必须对应最新
`ScreeningDecision.ESCALATE`；明确 `ESTABLISHED`、`NOT_ESTABLISHED` 或其他清晰终态不能通过
伪造请求进入会审。已存在的同一 session 可以用原始 fence 重放观察，但不会创建第二个 session。

GET/POST 返回 `m8-hearing-view-v1`，包括：

- 当前资格与 Case 状态、revision、RunManifest fence、screening decision/conflicts 和 EvidencePack；
- 三个精确 provider/profile/model/manifest 选择；
- session、最新 checkpoint、所有完成 round 和三方结构化输出；
- raw response 的持久化 receipt（只含 ref/hash/usage，不含 raw 内容）与 typed failures；
- 引用的证据和先例、补证请求与执行 receipt；
- 最终 Verdict、完整 procedural review 历史和 L5 结果。

响应固定 `case_transition_permitted=false`、`raw_model_response_content_exposed=false`。

## 调用示例

PowerShell/curl 查询：

```powershell
curl.exe --fail-with-body `
  -H "Authorization: Bearer $env:LABCOURT_API_TOKEN" `
  "http://127.0.0.1:8765/api/m8/runs/run-2026-08-13-demo/cases/case-content-addressed-id/hearing"
```

显式启动（请求文件必须是上述 contract 的完整 JSON）：

```powershell
curl.exe --fail-with-body -X POST `
  -H "Authorization: Bearer $env:LABCOURT_API_TOKEN" `
  -H "Content-Type: application/json" `
  --data-binary "@m8-hearing-start.json" `
  "http://127.0.0.1:8765/api/m8/runs/run-2026-08-13-demo/cases/case-content-addressed-id/hearing"
```

正式平台将 `runtime_resolver` 注入现有同源 server。resolver 从持久化场景快照中的
`hearing_case_id`、真实 `run_id`、Pilot workspace 与 SQLite 路径重新打开 M4 runtime；服务重启
不依赖进程内字典。静态 runtime map 仍保留给受控测试和独立装配：

```python
from labcourt.contracts.m8_hearing_api import M8HearingModelMode
from labcourt.services.m8_hearing_api import M8HearingApiService
from labcourt.services.m8_hearing_runtime import open_m8_hearing_runtime

with open_m8_hearing_runtime(
    config=config,
    run_id=run_id,
    workspace_root=workspace_root,
    database_path=database_path,
    location_by_zone={"zone-chem-301": "room-chem-301"},
    model_mode=M8HearingModelMode.OFFLINE_FIXTURE,
    fixture_bundle=fixture_bundle,
) as runtime:
    hearing_service = M8HearingApiService(operations_repository, {run_id: runtime})
    server = build_m8_api_server(..., hearing_service=hearing_service)
```

## 离线与 Qwen 模式

默认 model mode 是 `OFFLINE_FIXTURE`。三个独立 hearing profile 必须都是
`fake + LOCAL + IN_PROCESS`，fixture 按 frozen request cache key 精确匹配；缺失 fixture 会形成
typed exact-role failure，不会改用其他 fixture 或真实模型。

平台 `DEMO_FIXTURE` run 使用明确标注的 `DEMO / SYNTHETIC HEARING INPUT` 类型化响应生成器；
它仍经过 raw-first response store、cache、usage、三角色严格解析、Verdict 与 L5，且只在调用者
点击“启动离线会审”后运行。打开页签没有状态副作用。

真实模式必须由调用者显式选择 `OPENAI_COMPATIBLE_QWEN`。三个独立 profile 必须满足：

```yaml
provider: openai-compatible
model: qwen2.5-vl-72b-instruct  # 模型名必须显式含 qwen
execution_location: EXTERNAL
transport: HTTP
endpoint_env: LABCOURT_QWEN_PROSECUTOR_ENDPOINT
api_key_env: LABCOURT_QWEN_PROSECUTOR_API_KEY
cache_enabled: true
```

Defender 和 Judge 使用各自独立的 profile 和 manifest component。
配置身份必须与当前 RunManifest 的 prosecutor/defender/judge ModelManifest 精确一致。
`open_m8_hearing_runtime` 只在这一模式下构造单次、有限 timeout 的 HTTPS transport；没有
`AUTO` 模式，也不会在配置、网络、provider、解析或预算失败时切换到 offline fixture。

## 失败、恢复与已知边界

- 能证明 `DEFINITELY_NOT_SENT` 的 provider/identity/prompt/media 失败，沿用 M4 原子写入
  `HearingModelCallFailureAuthority` 和 exact-role backlog，随后可从 API 查询。
- 已收到的成功 provider envelope 会先把选中的 raw content 写入私有 response store，再执行严格
  JSON 解析、一次 repair、cache 与 usage 提交。
- 传输层若只能证明 `UNKNOWN` delivery，冻结 M4 规则禁止把它伪造成可安全重试的
  `DEFINITELY_NOT_SENT` failure。该调用保持 recovery-required，绝不自动重发或回退；这是当前
  最小接入的显式边界。
- API 没有新增 backlog retry 命令；运维继续使用冻结 M4 exact-role recovery/worker 入口。
- 先例仍使用既有 M5 bridge；离线演示 embedding/retrieval 结果不代表真实检索准确率。
- Qwen 接入不把 VLM 输出变成客观计数、时长、身份、坐标或证据存在性 authority；也不支持
  人脸识别或跨相机 ReID。
- 真实 Qwen 的成功、延迟、成本或准确率只有在存在真实评测 artifact 时才能宣称。平台集成不重复
  调用 provider；展示验证复用 `m8-qwen-hearing-demo` 已有 attempt/provider receipt 与完成 view。

## Schema 与 manifest 影响

新增 Schema：

- `schemas/m8-hearing-start-request-v1.schema.json`
- `schemas/m8-hearing-provider-selection-v1.schema.json`
- `schemas/m8-hearing-view-v1.schema.json`

没有修改 RunManifest、M0–M6 schema 或 authority。M8 start request 绑定现有 `manifest_id`；
provider selections 绑定三个现有 ModelManifest ID；每个 M4 request/response/failure 继续绑定同一
manifest、prompt bundle、EvidencePack 与 session。API 本身不生成新的模型事实或 Case transition。
`m8-platform-scenario-run-v1` 只新增持久化 `hearing_case_id` 绑定，避免把 M8 运营 Case ID 错当成
冻结 M4 Case ID；`m8-hearing-view-v1.request_manifest_id` 让 UI 可以提交精确 fence，而不是猜测。

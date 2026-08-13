# M8 真实 Qwen 控辩裁决演示

## 范围

该演示只装配既有 M3/M4/M5/L5 能力，不重写会审，也不修改 M0–M6 wire/authority contract。
两张图片均为 AI 生成的无脸 3D 假人，receipt 固定声明 `synthetic=true`、
`machine_weak_label=true`、`ground_truth=false` 和 `real_person_depicted=false`。

离线 M3 fixture 给出 `0.50`，由既有路由自然产生 `ESCALATED`。明确风险或其他非
`ESCALATED/REWORK_REQUIRED` 案件仍会被既有 M8 start contract 拒绝，不会被强制送入会审。

## 准备与真实运行

准备命令无网络、无真实模型调用：

```powershell
uv run --locked labcourt hearing qwen-demo prepare `
  --output .labcourt-local/m8-qwen-hearing-demo
```

真实运行固定使用北京 Workspace 专属端点和 `qwen3.7-plus-2026-05-26`。三个独立 profile
都显式发送 `response_format={"type":"json_object"}` 与 `enable_thinking=false`。API key
只通过本机 SecureString 提示进入当前进程环境：

```powershell
.\scripts\windows\run-m8-qwen-hearing-demo.ps1 -WorkspaceId '<workspace-id>'
```

不要把 API key 粘贴到聊天、参数、配置、日志、manifest 或报告。运行器只允许一次正式
`POST /api/m8/runs/{run_id}/cases/{case_id}/hearing`；同一目录已有 attempt receipt 时只返回
既有结果。配置缺失或确定未发送的错误形成 typed failure；交付状态未知时保留
`RECOVERY_REQUIRED`，不在同一 run 自动重发，也不切换到 fixture。

## 产物与查询

产物均位于 Git 忽略目录：

- `preparation-receipt.json`：合成证据、灰区筛查、三 profile 与精确 start fence；
- `hearing-view.json`：M8 GET 的完整结构化投影；
- `provider-receipts.json`：provider envelope ID、LabCourt response ID、raw ref、hash、token、时延与估算 CNY；
- `attempt-receipt.json`：完成、可审计失败、配置失败或恢复必需；
- `hearing-record.md`：中文控辩裁决、引用、补证、最终裁决和 L5 结果，不嵌入 raw response。

无 API key 的只读复现：

```powershell
uv run --locked labcourt hearing qwen-demo serve-results --port 8878
```

`results-api-access.json` 给出 loopback GET 路径和本地 demo token；该服务的 POST 固定返回
`FORBIDDEN`，不会调用真实 provider。也可以直接读取 `hearing-view.json`，其 schema 是既有
`m8-hearing-view-v1`。

GET 示例：

```powershell
$access = Get-Content .labcourt-local/m8-qwen-hearing-demo/results-api-access.json | ConvertFrom-Json
curl.exe --fail-with-body `
  -H "Authorization: Bearer $($access.bearer_token)" `
  "$($access.base_url)$($access.hearing_path)"
```

## 补证、失败与已知边界

预封存补证适配器仅支持 M4 已有的 `RECROP` action，并把第二张合成图封装成受既有
EvidencePack closure 检查的本地补证。其他 action 返回 typed `TOOL_UNAVAILABLE`。这是演示
适配器，不是生产取证或第二视角真实性声明；配置最多允许一轮补证和一轮 rework。

供应商成功要求三方真实响应均形成 provider/LabCourt response ID 与 raw reference，并形成最终裁决和
L5 结果。L5 可以合法失败并转 `HUMAN_REVIEW`，这仍是平台链路的完整、可审计终态。
弱标签与真实模型意见都不是真值，不代表准确率评估或真实执法结论。

费用字段按准备时固定的每百万 input/output token 费率估算，不代表账单。超时或无法判断请求是否发送时，
同一 run 禁止自动重试；应只读展示现有 authority，并创建全新的准备目录后再进行人工决定。

## 合成图提示词

主证据提示词：

> Synthetic evidence image for a LabCourt demo: a clearly fictional, faceless 3D laboratory mannequin at a fume hood, wearing a lab coat and gloves; the eye area is partly hidden by a strong reflection and oblique angle so safety goggles cannot be determined. No text, logo, real person, injury, or enforcement implication.

预授权补充证据提示词：

> Pre-authorized synthetic supplementary evidence of the same fictional faceless 3D laboratory mannequin from a different close oblique angle; glare and hood-frame occlusion still make protective eyewear ambiguous. No text, logo, or real person.

## 参考

- [Qwen3.7 Plus](https://help.aliyun.com/zh/model-studio/qwen3-7-plus)
- [Workspace 模型端点](https://www.alibabacloud.com/help/en/model-studio/models)
- [结构化输出](https://www.alibabacloud.com/help/en/model-studio/qwen-structured-output)
- [模型价格](https://help.aliyun.com/zh/model-studio/model-pricing)

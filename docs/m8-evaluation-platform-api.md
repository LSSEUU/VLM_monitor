# M8 多视频全真评估台

本接口是 M8 校园运营平台的同源增量能力，不修改 M0–M6 冻结契约。评估运行复用既有录制视频 `FrameSource`、EvidencePack、M3、M4、L5、Alert Policy、outbox 和 M8 authority。

## 权限

- `OPERATIONS`：上传或从受控目录导入 MP4、创建并启动真实模型批次、查看结果。
- `SAFETY_OFFICER`：查看评估结果、发布版本化人工真值，并通过既有 Hearing API 显式启动符合条件的会审。
- `LEADER`：只读评估结果。
- `STUDENT`：不可访问评估 API 或页面。

上传和目录导入只接受可解码 MP4。资产按 SHA-256 去重，并记录探测参数与不可变媒体 manifest。人工未确认的标签只作为探索性样本，不进入准确率、漏检率或误报率统计。

## API

- `GET /api/m8/evaluation/dashboard`
- `GET /api/m8/evaluation/media`
- `POST /api/m8/evaluation/media/uploads`（有界 `multipart/form-data`，字段名 `file`）
- `POST /api/m8/evaluation/media/imports`
- `PUT /api/m8/evaluation/media/{asset_id}/ground-truth`
- `POST /api/m8/evaluation/ground-truth-imports`
- `GET|POST /api/m8/evaluation/campaigns`
- `POST /api/m8/evaluation/campaigns/{campaign_id}/start`
- `GET /api/m8/evaluation/campaigns/{campaign_id}`
- `GET /api/m8/evaluation/runs/{run_id}`

目录导入只允许相对 `inputs/` 或 `evaluation-import/` 的路径。部署时可用 `labcourt demo platform --project-root <root>` 显式锁定这两个受控目录的根；API 不接受任意绝对路径。

## 运行与恢复

批次启动为每个 `asset_id × repetition` 创建独立运行并进入持久化单 Worker FIFO。服务重启后，未完成的 `RUNNING` 运行会恢复为 `QUEUED`。每个 run 固定绑定：

- `asset_id`、`media_sha256` 和源 manifest；
- `config_hash` 与 `model_profile_hash`；
- run 专属的源引用 sidecar。

会审补帧和案件证据读取 run 专属源引用，不读取服务级“当前视频”指针。真实模型配置、网络、provider 或解析失败进入 `TECHNICAL_FAILURE`，不会回退 fixture。

安全阴性运行完整保留但不建案；清晰结论沿既有快速 Verdict → L5 → Alert Policy；灰区进入 `AWAITING_HEARING`，只允许安全负责人使用既有 Hearing API 显式启动。评估案件在正式列表标记 `EVALUATION / 全真模拟`，但状态和权限仍由正式 Case/M4 authority 驱动。

## 通知与 RTSP 边界

评估运行不会制造本地“已发送”通知。没有已激活的 Feishu sandbox/outbox authority 时，通知保持 `ACTIVATION_REQUIRED`；只有既有真实发送链路及 provider receipt 能证明投递。

当前增量包含 `M8LiveIngestSessionV1` 与 `M8CaptureSegmentV1` 契约和持久化表，但尚未在没有真实、人工激活 RTSP 源的情况下声明实时分析能力。只有 30 分钟 receipt 同时证明有效分析速率不低于 5 FPS、P95 不高于 2 秒、积压不持续增长并记录断流重连后，UI 才能显示实时指标已验证。

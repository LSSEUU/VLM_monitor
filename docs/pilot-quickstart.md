# LabCourt v0.2 Pilot 快速使用

当前 A1 命令只做本地视频解码、人物/护目镜检测和单视频匿名跟踪，不调用 VLM，
也不产生违规案件。A2 验收后才会把这些结果送入候选事件和证据链。

## 1. 准备三段视频

把已获授权的短 MP4 放入本项目的 `inputs/`，建议命名为：

```text
inputs/goggles-worn.mp4
inputs/goggles-missing.mp4
inputs/goggles-unclear.mp4
```

`inputs/`、`runs/`、模型权重和 `.env` 已被 Git 忽略。不要把 API Key 写入 YAML、
文件名或命令参数；A1 完全不需要 API Key。

## 2. 一次性准备真实模型

在项目根目录运行：

```powershell
.\scripts\setup_perception_worker.ps1
```

脚本会创建独立的 `.venv-perception/`，安装固定 CUDA/模型依赖，下载固定 revision
的 Grounding DINO Tiny，并核对权重 SHA-256。最终必须看到 JSON 中的
`"kind":"READY"`。脚本可重复运行，已下载内容会命中本地缓存。

## 3. 分别运行感知

```powershell
uv run labcourt pilot perceive `
  --config configs/pilot.yaml `
  --video inputs/goggles-worn.mp4 `
  --run-id goggles-worn-001 `
  --json
```

对另外两段视频更换 `--video` 和 `--run-id`。成功输出包含：

```text
frames_processed, detection_count, person_count, goggles_count,
track_count, provider_failures, manifest_id, preview_path
```

同一 `run-id` 和同一视频重复运行时，系统会先验证完成封印、全部 A1 工件及逐帧 raw
response，再读取已完成结果，不会再次调用 detector。任何已封印工件缺失或内容不一致都会
失败关闭，不能被误报为“运行完成”。

## 4. 只需人工检查三件事

打开输出中的 `preview_path`，检查：

1. 人物框是否大致覆盖现场人员；
2. 护目镜框是否大致落在眼部，不要把普通反光或背景物大量当成护目镜；
3. 同一个人在连续画面中的 `t=<匿名编号>` 是否基本保持一致。

然后告知项目维护者：视频分辨率、明显误检/漏检、track 跳变，以及真实高风险区域的
多边形顶点。无需逐帧标注，也不要把真人姓名写入反馈。

## 5. 工件位置

```text
runs/<run-id>/
├── input/video-manifest.json
├── perception/execution-manifest.json
├── perception/frame-bundles.jsonl
├── perception/frame-receipts.jsonl
├── perception/report.json
├── perception/completion-manifest.json
├── raw/perception/*.json
└── debug/perception-preview.mp4
```

预览是非权威调试文件，可能含真人画面；不得上传到未授权服务。权威感知数据通过
`frame_id`、像素 SHA-256、模型 manifest 和 raw response receipt 相互绑定；
`completion-manifest.json` 最后写入，并固定上述所有 A1 输出的路径、大小和 SHA-256。

## 6. 常见失败

- `VIDEO_MISSING`：相对路径下没有该文件。
- `VIDEO_PATH_INVALID`：必须使用项目内、以 `.mp4` 结尾的相对路径。
- `PERCEPTION_FAILED`：解码器、隔离 worker、权重、CUDA、模型推理、跟踪或工件完整性
  未形成可信结果。不要把它解释成“没有检测到人”。

若要重新测试已失败的运行，使用新的匿名 `run-id`；失败 raw response 会保留用于审计，
不会被静默覆盖。

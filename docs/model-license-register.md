# Model and Dataset License Register

v0.1 默认路径只使用预计算 fixture 与确定性 Fake VLM，不下载或分发任何真实模型权重。

| Component | Exact revision | Code license | Weight/data license | Commercial and distribution condition | Reviewer/date | Review status |
|---|---|---|---|---|---|---|
| Precomputed perception fixture | v1 | Project internal | Synthetic fixture only | Development validation only | Project baseline / 2026-07-27 | Reviewed |
| Deterministic Fake VLM | v1 | Project internal | No weights | Development validation only | Project baseline / 2026-07-27 | Reviewed |
| Grounding DINO Tiny via Transformers | `IDEA-Research/grounding-dino-tiny@a2bb814dd30d776dcf7e30523b00659f4f141c71`; `model.safetensors` SHA-256 `1a2412ef99bd74bcd3c2a246fa1e48581f8889a1300c9051974741314fc042f3` | Apache-2.0 | Apache-2.0 per model card | Commercial use is permitted under Apache-2.0 notice/license terms; weights are downloaded into the local cache and are not redistributed by this repository | Codex technical metadata check / 2026-08-07 | Business/legal approval pending before external distribution |
| Roboflow ByteTrackTracker | `trackers==2.5.0.post0`, source tag commit `a35a60d4f39ad1d7f8713eb60f1839a9792edf20` | Apache-2.0 | No weights | Commercial use is permitted under Apache-2.0 notice/license terms; preserve required notices when distributing | Codex technical metadata check / 2026-08-07 | Business/legal approval pending before external distribution |

任何真实检测器、跟踪器、姿态模型、VLM 或 embedding 模型在进入仓库前，必须新增一行，
记录精确 revision、代码与权重许可证、商业使用条件、修改/分发义务、审核人与审核日期。
CI 不自动下载模型权重。

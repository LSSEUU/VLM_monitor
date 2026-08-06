# Model and Dataset License Register

v0.1 默认路径只使用预计算 fixture 与确定性 Fake VLM，不下载或分发任何真实模型权重。

| Component | Version | Code license | Weight/data license | Commercial condition | Review status |
|---|---|---|---|---|---|
| Precomputed perception fixture | v1 | Project internal | Synthetic fixture only | Development validation only | Reviewed 2026-07-27 |
| Deterministic Fake VLM | v1 | Project internal | No weights | Development validation only | Reviewed 2026-07-27 |

任何真实检测器、跟踪器、姿态模型、VLM 或 embedding 模型在进入仓库前，必须新增一行，
记录精确 revision、代码与权重许可证、商业使用条件、修改/分发义务、审核人与审核日期。
CI 不自动下载模型权重。


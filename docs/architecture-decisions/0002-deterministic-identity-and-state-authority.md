# ADR 0002：确定性标识、时间与状态真实来源

- 状态：Accepted
- 日期：2026-07-27

## 决策

v0.1 只接受单摄像头、恒定帧率（CFR）流。业务时间只来自 `frame_index` 与有理数 FPS。
多机位/传感器对齐所需的 PTS、时钟原点和同步误差属于生产化规格。

所有确定性 ID 使用显式的 hashable projection：

- 投影排除对象自身 ID、墙钟字段、本机绝对路径和发送回执。
- `crop_id` 包含源帧内容 hash、bbox、裁切来源、隐私策略、变换版本与编码版本。
- `pack_id` 排除 `pack_id` 自身和 `local_path`，但包含所有媒体 hash 与语义引用。
- `manifest_id` 排除 `manifest_id` 自身。
- `event_id` 显式包含 camera、stream、违规类型、主体/对象引用、起始帧和规则版本。

SQLite 从 M2 起是唯一可变状态真实来源。JSONL、案件 JSON、schema 和 HTML 是可重建投影；
关闭案件与写入 alert outbox 必须在同一数据库事务内。

配置保留秒数，不在全局加载时换算成帧。M1 在获得每路 `FrameRef` 的有理数 FPS 后按
“不得短于配置时长”的向上取整规则换算。

工作区只接受相对 POSIX 路径；UNC、URI、绝对路径和路径穿越在配置边界拒绝。
`LOCAL_FILESYSTEM` 存储边界进入配置指纹与 RunManifest；manifest 不保存工作区路径或
机器绝对路径。

因此静态 `ViolationDefinition` 也保存默认秒数；M1 才生成带 `*_frames` 的流级已解析规则。

## 理由

原始公式若把对象自身 ID 或本机路径纳入 hash 会产生循环或跨机器不稳定。多路不同 FPS
也无法在读取配置时可靠地统一换算。

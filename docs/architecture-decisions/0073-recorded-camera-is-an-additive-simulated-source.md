# ADR 0073：预录摄像头是增量模拟来源

## 状态

Accepted for the offline personal Demo.

## 背景

个人 Demo 已有房间级模拟烟雾传感器，但运营地图没有摄像头来源。直接把不存在的视频伪装为实时画面会
违反来源真实性；改写初始 source catalog 又会破坏已经持久化的传感器、案件和 bootstrap receipt。

## 决策

新增独立 camera registration 命令，发布连续 source catalog revision 2，同时保留原烟雾传感器并加入一个
`RECORDED_VIDEO_SIMULATION` camera。camera 固定 `FRAME_INDEX`、显著模拟 badge、无消防资格且不启用生命
安全 authority。没有媒体文件时 receipt 必须声明 `media_attached=false`。

传感器 sample 与 catalog ID 强绑定，因此 catalog 换版后以连续 source sequence 2/3 生成同一确定性烟雾
状态的新样本，current projection 只消费 revision 2 的闭合 cut。初始 bootstrap projection 改为纯函数构造的
原始单传感器切片，后续 catalog、notification 或 Case revision 不得改变它的 receipt identity。

## 后果

运行时运营投影可展示一个模拟摄像头和一个模拟传感器，且不会跨 catalog 拼接样本。实际预录视频绑定、
帧引用和播放由后续独立切片处理，在此之前不得声称已有媒体或真实现场画面。

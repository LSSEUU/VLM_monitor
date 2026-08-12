# ADR 0030：M8 使用 additive 运营平面，并先冻结拓扑与来源真实性

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8 校园运营、地图、设备、摄像头、传感器、案件与通知的共同前置

## 背景

M0–M6 已验收并冻结，现有 authority 解决的是离线证据与案件裁决。校园运营需要空间层级、角色、
设备、实时信号和消息闭环，但把这些字段直接加入冻结 Case、SafetySignal 或 RunManifest 会破坏历史
schema、回放身份与审计语义。预录视频和模拟传感器又容易在演示界面中被误解为真实现场或认证
消防能力，因此来源真实性必须先于设备行为和 UI 固定为机器可校验的契约。

## 决策

1. M8 是 additive 运营平面；通过新 schema、新表、新投影和服务引用 M0–M6，不修改冻结 wire。
2. 第一个切片只定义校园拓扑与运营源目录，不实现数据库、API、采集或案件行为。
3. 空间层级固定为校园、楼宇、楼层、房间，目录必须完整、有序、内容寻址；所有 camera/sensor 源
   绑定房间。
4. 来源模式采用闭合枚举 `LIVE_CAMERA / RECORDED_VIDEO_SIMULATION / LIVE_SENSOR /
   SIMULATED_SENSOR`。`simulated`、显示 badge、source kind 和 life-safety eligibility 均由字段矩阵
   计算并校验，调用方不能自报。
5. 摄像头永不作为生命安全权威；模拟源永不具备生命安全资格；live sensor 只有绑定非空认证引用
   且配置明确允许时才可能具备资格。该资格仍不代表 LabCourt 自行完成消防认证。
6. 视频使用帧索引时间基准；live sensor 使用设备 UTC + source sequence；模拟 sensor 使用 simulation
   tick。领域逻辑不得自行读取墙钟补齐缺失时间。
7. 每个源绑定 adapter 与 manifest，并声明 raw reference 必需；具体 typed 样本和 adapter 在 M8.2
   单独契约化。

## 结果

- 地图、实时监控、传感器、告警和案件共享同一空间与真实性根，不各自发明设备语义。
- 演示数据无法在契约层伪装为真实现场或认证消防输入。
- M0–M6 的 schema、authority、回放和 manifest 字节保持不变。
- M8.1 之后可以在不返工拓扑身份的前提下增加 RBAC、状态流、持久化与通知。

## 未选择的方案

- **直接扩展 `SafetySignal` 和 `RunManifest`**：会改变冻结 wire 与历史身份。
- **只靠 UI 文案标记模拟**：导出、API 或其他客户端可丢失标签，无法审计。
- **首切片同时实现 RTSP、传感器和消息平台**：缺少稳定前置契约，无法形成一个可独立验收的增量。

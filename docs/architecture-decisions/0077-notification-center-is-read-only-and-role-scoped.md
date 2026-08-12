# ADR 0077：通知中心保持只读并按角色裁剪

## 状态

Accepted for the personal Demo API.

## 背景

运营投影包含通知，但通知 Agent/通知中心需要独立列表、详情与审计。让界面下载完整运营投影再自行筛选会
复制权限逻辑，也无法安全支持学生自己的消息或运维设备通知。

## 决策

新增独立 `M8NotificationApiService` 和三个 authenticated GET 路由。列表与详情从 current notification
authority 裁剪：安全负责人按 location scope，领导仅重大风险/领导 audience，学生仅自身 target，运维仅
自身设备响应 target。audit 进一步只允许可见范围内的安全负责人或领导。

接口只返回既有 typed commit/audit receipts，不提供 POST，不持有 dispatch、reply 或 Case capability。
actor、notification 缺失和 authority 漂移沿用现有 typed API failure。

## 后果

独立 UI 可实现通知中心和审计时间线而不解析全量运营投影。未来 Agent 的总结、催办与回复分类仍需独立
命令和权限；这些只读端点不能被解释为自动发送、定责或结案授权。

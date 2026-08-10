# ADR 0047：M8 运营投影是只读权威切面而不是新的业务事实

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.6 operations overview、map、source、Case、notification、audit projection

## 背景

运营总览和校园地图需要把拓扑、设备来源、传感器样本、案件、通知与审计组合到同一响应中。如果投影仅保存
可变计数或自报的“在线/健康”状态，页面会在换版、重启或并发时展示无法追溯的数据，也可能把只存在于目录
中的模拟摄像头伪装成真实实时画面。

## 决策

1. M8.6 投影完整嵌入 exact current topology/source catalog receipt、每个 catalog source 的最新持久化 sample
   receipt、current Case/notification receipts 及其完整 audit chains。
2. overview、校园层级 map nodes 和所有 inventory hash 均由上述 receipt cut 计算，序列化时拒绝客户端或缓存层
   伪造 computed 值。
3. source projection 使用闭合 observation state：摄像头只有 `SOURCE_CATALOG_ONLY`；传感器没有样本时是
   `NO_PERSISTED_SAMPLE`；只有 exact persisted sample 才能显示 live/simulated observation。
4. `display_badge` 与 `simulated` 直接继承 source authority。仅目录配置不得声称实时在线；模拟样本不得声称
   认证消防检测。只有组织认证且 emergency-enabled 的 live sensor 加上持久化 live sample，投影才允许保留
   已冻结的 certification claim。
5. current Case 必须属于 exact topology/source catalog；Case 和 notification audit 必须从序号 1 连续闭合到
   current receipt。投影不接受断链、跨目录或孤立通知。
6. 投影固定 `read_only=true`、`case_transition_permitted=false` 和
   `direct_disciplinary_action_permitted=false`，不写回任何 authority。

## 结果

- 总览、地图、来源、案件、通知和审计共享一个可内容寻址、可重放的读取切面。
- 页面可显著区分“仅配置”“已观察”“模拟观察”和“live 观察”，不会用 UI 文案提升来源真实性。
- 任何业务更新仍只通过原有 append-only repositories 与授权命令完成；投影删除或重建不改变业务事实。
- 后续 projection repository/API 可以只读 SQLite current cut 并按角色裁剪输出。

## 未选择的方案

- **独立可更新 dashboard 计数表**：会与 append-only authority 漂移并丢失来源链。
- **目录中存在即显示在线**：把配置事实错误提升为运行时观察事实。
- **投影直接执行案件动作**：绕过 M8.1/M8.3 的权限、人工确认和审计边界。
- **在投影中调用 VLM 总结**：引入默认网络/模型依赖和不可重放内容。

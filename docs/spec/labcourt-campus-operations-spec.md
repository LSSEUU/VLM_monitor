# LabCourt Campus Operations Productization Specification

**文档版本**：0.1.0

**日期**：2026-08-10

**状态**：M8 可执行规格；M0–M6 继续冻结

**上游规格**：`docs/request.md`、`docs/spec/labcourt-vibe-coding-spec.md`

## 1. 目标与权威边界

M8 把已经完成的离线案件核心扩展为“实验室先做深、全校园可扩展”的安全运营产品。M0–M6
继续负责证据、语义审查、程序守门、告警策略、申诉、判例和可复现发布；M8 只通过新增契约、
新增持久化和组合服务接入校园空间、设备、实时信号、权限、通知、知识和运营视图。

以下边界不可放宽：

- 不修改 M0–M6 已导出的 wire schema、确定性身份、SQLite authority、审计或回放语义。
- 默认演示路径无网络、无 GPU、无真实摄像头，使用预录视频和离线模拟传感器。
- 预录视频必须标为 `SIMULATED · RECORDED VIDEO`；模拟传感器必须标为
  `SIMULATED · SENSOR`，不得伪装为实时现场或认证消防检测。
- 禁止人脸识别、face embedding、跨摄像头 ReID；学生送达依赖外部授权身份映射，不从图像推断。
- VLM/Agent 只能总结、建议路由、催办和收集回复；确认、驳回、撤销、定责、结案等关键动作
  必须由具备权限的用户明确执行并写入审计。
- AI 输出是安全辅助信息，不直接作为纪律处分依据。领导只读全局与重大事件，不参与审批。
- 生命安全底线只能来自经过组织验证的可靠传感器、消防/PLC 系统或人工紧急按钮；VLM 和
  未验证视频算法只能补充，不得成为唯一依据。

## 2. 产品角色

| 角色 | 能力边界 |
|---|---|
| `LEADER` | 只读全局态势、趋势和重大事件；无案件审批能力 |
| `SAFETY_OFFICER` | 核实/驳回/补证/结案、配置规则、处理申诉；关键动作显式确认 |
| `STUDENT` | 查看被授权送达的消息卡片、提交说明和申诉；不能查看他人案件 |
| `OPERATIONS` | 管理设备、适配器和健康状态；不能作案件实体裁决 |

服务到服务身份与人员角色分离。任何权限判断都必须消费持久化 actor/capability authority，不能
相信客户端自报角色。M8.0 不实现账号体系；该边界由 M8.1 契约化。

## 3. 运营对象与状态

### 3.1 空间和设备

空间固定为：

```text
CAMPUS -> BUILDING -> FLOOR -> ROOM -> CAMERA | SENSOR | EVENT
```

设备和信号必须绑定房间、适配器、manifest、来源真实性与时间基准。跨校园聚合只能使用稳定
匿名引用，不得以人脸或跨机位轨迹作为连接键。

### 3.2 风险等级

M8 运营风险固定为 `REMINDER / GENERAL / SEVERE / EMERGENCY`。等级策略决定是否自动创建
`PENDING_VERIFICATION` 案件、通知对象、响应期限、升级和允许的本地联动。护目镜缺失演示默认为
`GENERAL`；经过明确模拟标注的消防信号演示为 `EMERGENCY`，但页面和工件必须同时声明它不是
认证消防检测结果。

### 3.3 运营案件

自动化最多创建“待核实案件”。建议状态主链：

```text
PENDING_VERIFICATION
  -> CONFIRMED | REJECTED | EVIDENCE_REQUESTED
EVIDENCE_REQUESTED -> PENDING_VERIFICATION
CONFIRMED -> RESOLVED
任一允许状态 -> APPEALED -> APPEAL_RESOLVED
```

每次迁移必须绑定 actor、capability、前后版本 hash、原因、证据/信号引用和审计序列。Agent 不拥有
关键迁移 capability。

## 4. 通知闭环

通知采用 adapter/outbox，不把飞书、企业微信或钉钉 SDK 引入领域层。闭环至少包含
`PLANNED -> QUEUED -> SENT -> DELIVERED | FAILED -> ACKNOWLEDGED | RESPONDED`，并记录模板版本、
目标引用、幂等键、通道回执和回复引用。默认离线 adapter 只写受控本地工件，不声称真实送达。

Agent 可以生成有来源的摘要、建议收件人、催办计划和回复分类；发送前是否需要人工确认由策略
决定，案件关键动作始终需要授权用户确认。

## 5. 摄像头与通用传感器

### 5.1 来源真实性

来源模式固定为：

- `LIVE_CAMERA`：真实摄像头流；不是生命安全权威。
- `RECORDED_VIDEO_SIMULATION`：预录视频模拟实时摄像头；必须显著标为模拟。
- `LIVE_SENSOR`：真实物理/系统信号；只有存在组织验证的 certification authority 才可能参与
  生命安全硬规则。
- `SIMULATED_SENSOR`：默认离线模拟信号；必须显著标为模拟，永不具备生命安全资格。

### 5.2 传感器范围

首个离线插件建议覆盖 `SMOKE / TEMPERATURE / COMBUSTIBLE_GAS / TOXIC_GAS / DOOR_CONTACT /
WATER_LEAK / EMERGENCY_BUTTON`。每条样本必须有严格 typed value、设备/来源/位置、source sequence、
时间基准、质量、完整性 hash、manifest 和原始信号引用。适配器不得用自由文本猜测类型或单位。

## 6. 知识库

知识类型为制度、SOP、历史判例、应急预案、设备资料和问答。检索回答必须带文档来源、版本、
生效日期和引用片段。普通文档不能静默成为裁决规则；规则发布需要独立、授权、可审计的配置流程。
默认离线实现使用本地 fixture 文档和确定性检索，不要求网络 embedding。

## 7. API、持久化与最小界面

- API 默认只监听 `127.0.0.1`；生产认证必须 fail closed，不能复用开发免认证模式。
- 新增 M8 SQLite migration/table，不修改冻结表语义；写模型使用版本号与乐观并发。
- 外部通知、真实设备、对象存储和身份提供方均通过端口；每个外部调用有 timeout、幂等、manifest、
  typed failure 和原始回执引用。
- 最小集成界面只验证运营总览、来源标记、地图层级和关键工作流；视觉稿由独立 UI 任务负责。

## 8. 有序实现切片

1. **M8.0 拓扑与来源真实性契约**：校园层级、运营源目录、模拟标记、时间基准、生命安全资格；
   Pydantic、schema 和 contract tests。除此之外不实现行为。
2. **M8.1 actor/capability 与运营案件状态契约**：四角色、关键动作矩阵、版本化命令、审计意图。
3. **M8.2 传感器端口与离线模拟插件**：typed 样本、raw ref、manifest、缓存/重放、风险评估；
   烟雾 fixture 形成显著模拟的 emergency 候选。
4. **M8.3 持久化与本地 API**：独立迁移、拓扑/设备/信号/案件仓库、loopback API、RBAC 拒绝测试。
5. **M8.4 通知闭环**：outbox、离线 fake channel、卡片回复和升级；真实平台 adapter 另行启用。
6. **M8.5 知识库**：版本/生效日期/来源契约、离线检索、规则与普通文档隔离。
7. **M8.6 运营投影与最小集成界面**：总览、地图、实时源、告警/案件、设备、审计只读投影；
   不覆盖独立 UI 视觉资产。
8. **M8.7 真实适配器与现场验证**：RTSP、物理传感器、OIDC、消息平台、监控/灾备；每项必须有
   许可证/安全评审、现场证据和可回退的离线 fake。

不得跳过前置切片。每个切片只在聚焦 contract/unit/integration 门通过后进入下一项；完成 M8
必须另行定义全量 e2e、迁移回滚、断网、权限、并发和灾备验收，不能继承 M6 demo 成绩冒充生产结果。

## 9. M8.0 完成门

- 新增 schema 不改变任何已冻结 schema 的字节。
- 拓扑只有一个校园根，父节点存在、层级相邻且父项先于子项；设备源只能绑定房间。
- 每个 source/device 唯一；目录顺序稳定且内容寻址。
- 预录视频和模拟传感器的 `simulated=true` 与显示 badge 不可由调用者伪造。
- 模拟源、摄像头和无认证 live sensor 均不能声明 `life_safety_eligible=true`。
- 所有新契约严格拒绝 extra、bool 冒充整数、开放字符串枚举和伪造 computed identity。
- `pytest` 聚焦门、schema check、Ruff、Mypy 与架构依赖检查通过。

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
相信客户端自报角色。M8.1 已冻结 actor authority 的角色、作用域、版本、active 状态与派生
capability；M8.3 必须从持久化 authority 解引用，不能接受客户端自报的嵌套 authority 作为事实。

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
CONFIRMED | RESOLVED -> APPEALED -> APPEAL_RESOLVED
```

每个迁移命令必须绑定 actor、capability、源版本及 authority hash、目标版本、原因和证据/信号引用；
M8.3 的提交回执还必须绑定结果版本、结果 authority hash 和审计序列。Agent 不拥有关键迁移
capability。自动化 create command 的唯一初态是 `PENDING_VERIFICATION`，并固定
`human_verification_required=true`、`direct_disciplinary_action_permitted=false`；所有迁移命令都固定
`explicit_human_confirmation=true` 和 `direct_disciplinary_action_permitted=false`。

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

M8.2 固定实现全部七类来源。布尔传感器只接受 strict boolean；数值传感器使用整数定点单位
`MILLI_CELSIUS / MILLI_PERCENT_LFL / MILLI_PPM`，禁止二进制浮点和自由文本单位。live sample 只接受
UTC device timestamp，模拟 sample 只接受 `simulation_tick`，不得用本机墙钟补齐。每个 sample 绑定
source catalog、完整 source authority、source sequence、quality、raw signal 相对引用及其字节 SHA-256、
adapter input authority 和 adapter manifest，并派生内容身份。

默认离线 adapter 不访问网络/GPU，不 sleep，按冻结 scenario 的 simulation tick 分页；相同 poll
request 返回相同缓存结果，并可按 request ID 重放和回读 raw JSON。风险策略是独立、版本化、typed
rule authority，普通知识文档不能进入该路径。风险评估最多建议建立 `PENDING_VERIFICATION` 案件；
M8.2 固定禁止生命安全联动、认证消防声明和直接纪律处分。

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
- M8.7 commissioning readiness 使用 authenticated loopback GET，只允许当前 active、in-scope
  `OPERATIONS` authority 读取。评估时点由服务端 UTC clock 注入；响应复用完整 typed readiness
  assessment，不返回 raw evidence bytes、secret 或 activation authority，并在读取期间 actor 换版时
  fail closed。

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

M8.7 首接消息平台选择飞书企业自建应用。发送边界固定使用应用身份 `tenant_access_token`、
`POST /open-apis/im/v1/messages?receive_id_type=open_id`、`msg_type=interactive` 和 provider `uuid`；
`uuid` 从 LabCourt notification ID 确定性派生且不超过 50 字符。首个子切片只生成厂商专用 preflight
authority 与显著模拟的离线 conformance response，不读取 app secret、不获取 token、不访问网络，且
不能生成可提交到通知状态机的真实发送结果。只有 provider-specific contract、commissioning、双人
activation、secret-store runtime binding 和真实沙箱证据全部通过后，才可增加实际 HTTP transport。

飞书首次 activation 只允许 `SANDBOX`：无密钥 runtime config 必须绑定 exact profile、canonical
bytes/hash/size 与 1–32 个 active 测试收件人 binding。配置本身不授权网络；append-only commit 必须重新
评估相同 evidence inventory，并重新解析与 intent 完全相同的当前 OPERATIONS/SAFETY_OFFICER 双人
authority。只有该 commit 可授权 allowlist 内的 sandbox call，生产发送、自动激活、生命安全联动和案件
动作继续禁止。调用时仍须从持久化 authority 解析当前未撤销状态，并从批准的 secret store 短暂解析
凭据与 open ID 后复核 hash；客户端不能提交或扩大激活状态。

飞书 sandbox activation 与 revocation 使用独立 append-only authority。每个 candidate 同时至多一个未
撤销 activation；kill switch 可由当前 in-scope OPERATIONS 或 SAFETY_OFFICER 单人显式提交，重新激活
仍需新的连续 revision 和双人 intent。任何调用前都必须在稳定 repository cut 中重算当前双人 authority、
当前测试收件人 target 与 latest commissioning readiness；显式撤销为 `REVOKED`，证据/人员/target 换版
为 `INVALIDATED`，两者均禁止外部调用。不得用历史回执、客户端 payload 或长生命周期缓存替代该检查。

飞书 live send 的 secret 与网络必须通过独立注入端口。secret lease 不可序列化、`repr` 脱敏并在关闭时
覆盖 mutable buffer；任何 HTTP 前复核 app ID/open ID hash 与 exact activation allowlist。token 原始明文
不落盘，receipt 只保留 hash、expiry、provider log ID 和脱敏 raw response；进程内 cache 使用到期安全
余量。token timeout 明确为消息未发，message timeout/transport failure 必须保持 unknown-delivery；数值
`code=0` 加 typed message ID 只确认 provider acceptance，不确认 delivery，也不能触发 Case 动作。

飞书 sandbox runtime 只允许显式的 credential/receive reference 到环境变量名映射；不得扫描前缀、猜测
变量名或在 authority 中保存 clear value。HTTP transport 固定 `open.feishu.cn:443`、系统 CA 与 hostname
verification、exact path、单次 `POST`、0 自动重试和 256 KiB response 上限。环境缺值、hash drift、TLS
失败、timeout 与超界 response 必须转换为 typed failure；默认应用 wiring 不得实例化该 live transport。

外部通知 runner 必须在调用前持久化 exact `QUEUED` version/attempt 的独占 claim，并在真正跨越调用边界
前追加 one-shot call fence。claim 到期不得自动接管；call fence 后缺少 completion 必须进入
`RECONCILIATION_REQUIRED`，禁止盲目重试。provider result、raw artifacts 与 notification `SENT`/`FAILED`
transition 必须原子提交；该流程不允许改变 Case 或形成纪律处分。

飞书 runner 的最终 receipt 必须逐项绑定 preflight request、source-version claim、one-shot call fence、调用时
current activation status 所引用的稳定 activation commit、provider send result 与 SQLite completion。
provider acceptance 只允许把通知推进
到 `SENT`，不得声明真实送达；unknown delivery 必须保留为 `FAILED` 且禁止自动 retry。

飞书学生回复必须先进入独立的 encrypted webhook evidence 边界。profile 只允许 `HTTPS_WEBHOOK`、事件
schema `2.0`、`im.message.receive_v1`、`p2p` user text，并固定 external ingress 未激活；入口 receipt 只绑定
原始密文 body/header/time，不能预先声明验签、解密或业务接受。验证 receipt 必须复核 Encrypt Key signature、
Verification Token、freshness、app、message shape，并以 provider `message_id` 防重放、`parent_id` 关联既有
outbound provider receipt；clear open ID 和自由文本只能通过 hash/raw reference 管理。验证成功本身仍不能
提交 notification reply、改变 Case 或形成纪律处分。

入站验证持久化必须以 provider `message_id` 为唯一 replay key；commit receipt 必须按 encrypted request、
decrypted event、text content 的固定顺序绑定 raw ref/hash/size inventory、commit/repository/storage manifests
与提交时点。exact retry 只能读回同一 receipt，任何不同 payload、event、parent 或 manifest 都必须冲突；
raw artifact 和验证记录必须 append-only。

签名必须在解析 encrypted envelope 前以 exact raw body 计算并 constant-time compare；freshness 必须在读取
secret 前拒绝。AES-256-CBC primitive 必须是显式注入端口，key 为 Encrypt Key 的 SHA-256，decoded payload
的前 16 bytes 为 IV；默认仓库不得自写或静默回退密码算法。strict parser 只接受已冻结的单聊 user text
shape，unknown field、bad base64/block、token/app drift、group 或非 text 均转换为 typed failure且不落库。

飞书 Request URL 的 `url_verification` challenge 必须使用独立入口契约，不得伪装为业务事件或复用业务
事件的签名已验证声明。配置 Encrypt Key 时只接受严格的 encrypted envelope；解密后必须核对 Verification
Token，并在收到后 1 秒内只返回原始 challenge 的 canonical JSON。可序列化 receipt 只保存 decrypted/response
hash、reference、size 与 manifest，不能嵌入 clear challenge，也不能激活公网入口、提交学生回复、改变 Case
或形成处分。默认 wiring 不监听公网；真实 Request URL 仍需独立的人审 activation 与租户验证证据。

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

## 10. M8.1 完成门

- 四类 actor 的 capability 必须由闭合角色矩阵派生，客户端不能提交或扩大 capability。
- `LEADER` 只能只读全局/重大事件/审计；`OPERATIONS` 只能管理设备和查看健康状态，二者均无
  运营案件迁移 capability。
- `SAFETY_OFFICER` 的案件动作受 active authority 与校园/地点作用域共同约束；`STUDENT` 只能为
  `subject_actor_id` 与本人 actor ID 一致的案件提交申诉。
- 案件动作、来源状态、目标状态、reason code、appeal resolution 和 required capability 使用闭合
  矩阵；错误状态、原因、角色、作用域或人工确认一律 fail closed。
- 自动化只产生待核实 create command；模拟来源从 source inventory 派生显著 badge，不能静默
  变成 live，也不能直接产生纪律处分。
- transition command 使用源版本与源 authority hash，并派生下一版本和内容寻址 ID；audit intent
  绑定动作、前后状态/版本、actor authority、supporting authority inventory 和 manifest，但自身
  不执行持久化写入。
- 新增 schema 不改变 M0–M6 既有 schema 字节；聚焦 contract、schema check、Ruff、Mypy 与架构门
  全部通过后才可进入 M8.2。

## 11. M8.2 完成门

- 七类 sensor 都有闭合 type/unit/value 矩阵，strict bool 与整数定点值不能互相冒充；模拟与 live
  时间字段互斥，来源真实性、manifest、source sequence 和 raw 引用不可伪造。
- sensor adapter capability 固定支持的 mode/type、batch/timeout 上限、网络要求、离线与确定性重放
  声明；poll request 必须与 source adapter/manifest 精确一致。
- poll result 绑定精确 request、稳定递增的 sample inventory 和内容 hash；raw signal bytes 可按引用
  回读并通过 SHA-256 验证。
- 默认离线 simulator 对七类 sensor 均可运行，同一 request 命中确定性内存缓存；未知 replay/raw、
  capability graft 和 source graft 转成 typed failure。
- 默认 smoke fixture 从 inactive 变为 active，active sample 产生显著标注的 `EMERGENCY` 运营候选，
  但只能建议待核实建案，且 `life_safety_action_permitted=false`、
  `certified_fire_detection_claim_permitted=false`、`direct_disciplinary_action_permitted=false`。
- 新增 schema 不改变 M0–M6 既有 schema 字节；聚焦 contract/unit/port、schema check、Ruff、Mypy 与
  架构门全部通过后才可进入 M8.3。

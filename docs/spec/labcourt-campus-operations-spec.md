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

默认 URL challenge HTTP adapter 只允许显式构建并手工启动 `127.0.0.1` listener，固定 POST path、
`application/json`、单一 canonical Content-Length 与 256 KiB 上限；禁止 transfer/content encoding。该 listener
只用于离线/本机集成验证，Host 必须为 loopback；出现任一业务事件签名头时必须返回 ingress inactive，不能
调用业务事件验证器。loopback profile 不得被解释为公网 Request URL、TLS 就绪或 external activation。

公网飞书 sandbox webhook runtime config 必须是无密钥 authority，绑定 exact inbound profile、callback URL
reference/hash、TLS configuration reference/hash、固定 path、本机 application bind 与反向代理 TLS termination；
配置本身保持 external ingress false。只有 current commissioning readiness、当前 OPERATIONS/SAFETY_OFFICER
双确认和 exact canonical config bytes 均未变化的 append-only activation commit 才可授权 sandbox challenge 与
business-event ingress；不得授权生产入口、listener autostart、notification reply commit、Case 动作或处分。
当前 ingress status 必须在请求时重算 current OPERATIONS/SAFETY_OFFICER 与 commissioning inventory；任一漂移
立即 `INVALIDATED`。当前 in-scope OPERATIONS 或 SAFETY_OFFICER 可单人显式提交 append-only kill switch，
状态变为 `REVOKED`，challenge 与 business event 同时禁用，且不得自动 reactivation。
ingress activation/revocation 必须独立 append-only 持久化：同一 activation intent exact retry 只返回原 receipt，
不同 config bytes 或 manifest 必须冲突；同一 candidate 未撤销时禁止第二个 activation，撤销后新 revision 必须
连续并精确引用 prior commit。进程重启不得丢失 authority，运行时不得用缓存状态替代当前数据库 cut。

activated webhook application backend 必须只绑定 runtime config 的 loopback host/port，由受审计的反向代理
提供公网 HTTPS 并重写 application Host。每个 POST 在读取 secret 或解密前必须重读 current ingress status，
且 running activation commit 必须仍为 latest exact commit。无 Lark 事件头只允许进入 challenge 路径；timestamp、
nonce、signature 必须三者完整才可构造业务 ingress。业务 HTTP 200 只确认 verified evidence 已 append-only
提交，不得自动提交 notification reply、改变 Case、形成处分或声明学生身份已经确定。
URL challenge 必须在写出 clear response 前提交 hash-only audit receipt；ledger 只保存 verification receipt、
encrypted/decrypted/response hashes、时间与 commit/repository manifests，不保存 clear challenge 或原始解密载荷。
exact verification retry 必须返回同一 commit，表与索引必须 append-only；该 audit 仍不是 ingress activation。

activated webhook 的产品运行时必须通过独立显式命令装配，不得挂入默认离线启动路径。装配时必须读取
既有 SQLite current activation，并按 activation 的 exact inbound profile 解析显式提供的环境变量名；不得
扫描环境变量前缀、接受 secret 明文命令行参数或创建新的 activation。运行时必须在开始服务前完成 secret
reference/hash 校验并关闭预检 lease，随后仅向 verification service 提供按请求取得的短生命周期 lease。
缺少可选密码依赖、数据库、current activation、精确 secret binding 或本机 bind 能力时必须 typed/fail-closed
退出。check mode 只允许构建、绑定、报告无密钥摘要并关闭 listener；正常 mode 才可阻塞服务。两种 mode
均不得管理公网 TLS、提交 notification reply、改变 Case、形成处分或声称真实飞书租户验证已经完成。

运维 activation boundary 只能消费已由外部人审流程生成的 typed `M8AdapterActivationIntentV1` 与 exact
canonical inbound runtime config；不得从零散 CLI 参数代填 operations/safety receipt 或静默补齐双人确认。
输入文件必须有界并在任何写入前完整通过 strict model/canonical bytes 校验。activation 命令只 append-only
提交 authority，不得启动 listener；status 命令必须从当前数据库 cut 重算而非读取进程缓存；revocation 命令
必须复用既有 current actor、closed reason 与 manifest gate，且只 append-only 提交 kill switch，不得直接
控制其他进程。CLI kill switch 必须显式接收稳定 UTC revocation time，使回执丢失后的 exact retry 不会因
隐式墙钟变化而冲突。运行中的 backend 通过逐请求重读观察撤销，因此下一次 challenge/business event 必须
fail closed。

outbound sandbox authority 必须通过与 inbound 分离的显式 operator boundary 提交和撤销。它只消费 typed
dual-human activation intent 与 exact canonical `M8FeishuSandboxRuntimeConfigV1`，不得把 webhook activation
解释为发送授权。status 必须重算 current actor、commissioning 与每个 allowlisted recipient target；任一 target
revision/active 漂移都必须撤销 external call permission。activation/status/revocation 命令本身不得读取
App Secret、取得 token 或发送消息；kill switch 必须使用稳定 UTC revocation time 支持 exact retry。

live sandbox outbox operator 只允许显式 one-shot command，不得默认启动 worker、扫描队列或批量发送。每次
必须绑定 exact current `QUEUED` notification、current outbound candidate、allowlisted recipient binding、
canonical workflow authority 与显式 manifest；App ID/App Secret/open_id/worker owner token 只能通过具名
环境变量引用解析，不得成为命令行值、日志或 receipt。任何 secret/reference/hash、activation、recipient 或
workflow 漂移必须在 claim/provider call 前 fail closed。transport 固定官方 HTTPS host、系统 CA、bounded timeout
与零自动重试；claim fence 后的 timeout/transport unknown 必须进入待对账，provider acceptance 仍不得声称
真实送达、改变 Case 或形成处分。
one-shot command 必须提供 check mode，复用 exact activation/notification/binding/workflow/secret-reference 校验，
但不得创建 dispatch claim、call fence、网络连接或通知状态迁移；check 结果只能输出无密钥摘要，并明确
`external_call_attempted=false`。check 成功不授权自动移除 check flag。

Windows 个人 Demo 可以增加显式的本机编排层，但不得改变上述 authority。唯一允许持久化明文测试
凭据的位置固定为仓库根目录下被 Git 精确忽略的 `.labcourt-local/feishu-secrets.json`；提交物只能包含
全空示例，首次写入必须先确认 ignore 生效并收紧当前 Windows 用户的目录 ACL。配置契约必须以
`SecretStr` 脱敏 repr/JSON 和隐藏输入的校验错误保证 CLI、日志与测试不出现凭据值。默认入口必须先运行
不 claim、不建 call fence、不联网的 exact webhook/outbox preflight；webhook 仅可在相应预检通过后监听
loopback，单条发送还必须在预检后取得操作者明确确认，且不提供批量、后台 worker 或静默确认参数。
本机脚本可消费既有 typed 双人 intent 并幂等提交 activation，但不得生成或代填两名确认人。它不管理
公网 HTTPS/TLS/反向代理，不证明真实租户已联调，也不扩大 reply、Case 或纪律处分权限。

为缩短企业自建应用首次联调，可增加与通知 authority 完全隔离的个人 Demo 连通性探针。探针只允许发送
一张固定且显著标注 `PERSONAL DEMO`/模拟事件的卡片，不接受 case/notification 输入，不读写 SQLite，
不生成 commissioning 或 activation 工件，不支持回复、队列、扫描或重试。它必须先提供无网络 check，
Windows live 入口还需操作者明确输入 `SEND`；token 响应只能保存脱敏摘要，message 响应与 typed receipt
仅落被忽略的本机目录。无论 provider 结果如何，回执必须固定禁止 notification/case/处分迁移且不得声称
真实送达。该探针不得作为正式 adapter、通知回执或 commissioning evidence，完整闭环仍必须回到既有
双人 activation-gated outbox/webhook 路径。

在同一隔离边界内可增加第二个固定的业务演示探针：它只能消费默认离线烟雾模拟器产生的 exact typed
poll result 与紧急 advisory assessment，卡片必须显示 `PERSONAL DEMO`、`SIMULATED`、非认证消防检测、
待核实案件“建议”与人工核实要求。它不得接受正式 case/notification authority，不得写 SQLite 或把建议
推进为案件状态；发送仍需先无网络 check，再由操作者输入 `SEND`，回执沿用单次调用和不确认真实送达语义。

产品演示装配必须与飞书连通探针分离。默认 bootstrap 可幂等提交固定的四层演示拓扑、四角色 authority、
离线烟雾 raw signal/poll cache、一个 `EMERGENCY` 的 `PENDING_VERIFICATION` 案件和稳定运营投影，并输出
content-addressed typed receipt。bootstrap 自身不得执行案件迁移、通知迁移、模型调用或网络调用；后续本机
API 必须从该 SQLite authority 解引用角色和案件，不能用 bootstrap 摘要替代持久化事实。

个人 Demo API runtime 可以使用固定的本机演示 token，但 authority/profile 只保存 SHA-256，明文只允许写入
被 Git 忽略的 local access 文件且不得打印。runtime 固定绑定 `127.0.0.1`，启动前必须支持 bind-and-close
check；领导的投影视图只含重大案件且不能迁移 Case，运维不得读取案件，学生不得读取运营投影，安全负责人
关键迁移仍需 `explicit_human_confirmation=true` 并由服务端解析 current actor authority。

个人 Demo 可提供 safety-officer 专用的 loopback 客户端，允许 `CONFIRM`、`REJECT`、`REQUEST_EVIDENCE`、
`RETURN_TO_VERIFICATION`、`RESOLVE` 五个既有动作。客户端必须先读取 current Case version/document hash，
使用既有 typed transition request，取得独立 `APPLY` 确认后只提交一次；不得提供领导/运维审批模式、自动重试
或客户端自报 actor authority。响应必须按 commit receipt 严格解析并写入 ignored 本机目录。

个人 Demo API 启动时应幂等装载固定六类知识文档，覆盖 POLICY、SOP、HISTORICAL_PRECEDENT、
EMERGENCY_PLAN、DEVICE_MANUAL、FAQ。问答必须走既有 deterministic offline retriever，citation 返回 exact
source/version/effective_at；profile/receipt 固定声明 `model_used=false`、`network_used=false` 和普通文档不能
定义案件规则。知识 catalog 冲突必须 fail closed，不能自动生成下一 revision 掩盖漂移。

个人 Demo 的通知必须通过独立显式路由入口创建，不能偷偷塞进基础 bootstrap。首个路由固定把原始模拟
`EMERGENCY` 待核实案件的 `CASE_ACTION_REQUIRED` 发送意图指向安全负责人，并只推进到离线 fake outbox 的
`QUEUED`。输出必须包含 typed route receipt 与显著模拟卡片；不得联网、读取飞书 secret、声称送达、迁移
案件或形成处分。安全负责人和领导可从角色裁剪的运营投影查看，运维不得看到案件通知。
后续离线 delivery 必须是另一个显式入口，只消费 exact route receipt，复用既有 fake channel 提交
`QUEUED -> SENT -> DELIVERED` 及 raw artifacts；中断在 `SENT` 时必须可确定性恢复。该 `DELIVERED` 仅表示
模拟通道完成，固定 `real_delivery_confirmed=false`，不得替代飞书 provider receipt。
离线 acknowledgement 必须由当前安全负责人 authority 显式确认，只允许
`DELIVERED -> ACKNOWLEDGED`，并固定 `case_transition_permitted=false`。确认通知不能解释为确认案件，重复命令
必须返回同一 commit，角色裁剪投影应把它计为已闭环通知。
预录视频模拟摄像头必须通过 source catalog 的连续增量 revision 注册，固定
`RECORDED_VIDEO_SIMULATION`、`FRAME_INDEX`、`SIMULATED · RECORDED VIDEO`，并保持
`live_camera_claim_permitted=false`、`life_safety_eligible=false`。未绑定媒体时 receipt 必须明确
`media_attached=false`；catalog 换版后传感器最新样本必须重新绑定当前 catalog cut，不能跨版本拼接投影。
媒体绑定必须是独立 additive receipt，至少固定 raw media ref、输入文件 SHA-256/字节数、播放副本
SHA-256/字节数、source catalog cut 与 manifest；默认路径只做 ISO-BMFF 签名检查和精确字节复制，
不转码、不修改原文件、不声称已完成解码验证，且仍保持模拟、非实时、非生命安全来源。
相机媒体 API 必须复核当前 actor authority、绑定 receipt、source catalog cut 和同一打开文件句柄的字节哈希；
仅安全负责人和运维可读取一般风险摄像头媒体。播放响应必须使用 `video/mp4`、`Accept-Ranges: bytes`，
支持单区间 `206`/`416`，并在输出中继续保留显著模拟来源元数据。
camera collection 必须从当前 source catalog 发现设备而非使用前端静态 inventory；安全负责人/运维可见，
领导/学生返回空集合。每个 typed camera view 必须固定 source catalog cut、source、模拟 badge、媒体绑定状态和
鉴权播放入口；未绑定媒体时设备仍可发现，但 binding 必须为 null 且 `media_attached=false`。
PPE 视频演示建案必须是独立显式切片，只消费已复核的 media binding 并使用 `VIDEO_EVENT` authority；候选类型
可以固定为 `GOGGLES_MISSING_CANDIDATE`，但必须声明没有验证输入媒体内容、没有把文件名当证据、机器弱标签不是
ground truth、没有模型调用，且只能创建 `GENERAL/PENDING_VERIFICATION`、`human_verification_required=true`、
`direct_disciplinary_action_permitted=false` 的学生案件。重复创建必须返回同一 commit。
安全负责人 Demo action client 可用闭合 target enum 选择初始烟雾案或 PPE 候选案；默认值必须保持初始烟雾案，
PPE 目标只能从 exact local PPE receipt 解引用 case ID。两种目标都必须读取 current Case authority、使用 safety
token 并要求独立显式确认；一键启动不得调用关键 transition。
学生 PPE 申诉客户端只能解引用 exact PPE receipt、使用 student token，并固定提交
`SUBMIT_APPEAL/SUBJECT_DISPUTE`；必须读取 current Case version/hash、要求独立显式确认并只允许状态矩阵接受的
`CONFIRMED|RESOLVED -> APPEALED`。申诉不得自动撤销、结案、改变通知或授予安全负责人权限。
确认后的 PPE 案件可通过独立离线入口创建 `CASE_UPDATED/CASE_SUBJECT` 学生通知；plan 必须绑定 current confirmed
Case version/hash、exact student target、GENERAL risk 与 fixed template/policy，并只推进到 `QUEUED`。卡片必须显著
标注模拟、允许 acknowledgement/explanation/appeal request，同时固定 case transition 和处分权限为 false。
基础 bootstrap receipt/projection 必须锚定初始切片，后续通知、案件和目录 revision 不得反向改变其 identity。
Windows 一键启动入口可以顺序编排上述已验证命令，但不得新增隐式 authority 或跳过 API bind preflight。
它只可覆盖由当前 authority 完全派生的本机 runtime profile/access/knowledge 摘要；bootstrap、catalog、Case、
notification 与 raw artifact receipt 继续 conflict closed。入口不得自动 acknowledgement、案件动作、飞书发送
或公网监听。
authenticated session discovery 必须从 bearer principal 重新解析当前 persisted actor receipt，返回现有 typed
actor authority，不接受客户端 role/scope/capability claim，也不得回显 bearer token。inactive、actor drift 或
缺失 authority 必须沿用 API 的 fail-closed 错误语义。
current Case collection 必须由服务端按当前 actor authority 裁剪：SAFETY_OFFICER 仅 scope 覆盖的 location，
LEADER 仅 SEVERE/EMERGENCY，STUDENT 仅 `subject_actor_id` 等于自身，OPERATIONS 返回空 inventory。collection
不得接受客户端 role 或无界 limit；单案与 audit 读取必须复用相同 location scope 判断，不能让列表和详情
产生权限分叉。
notification collection/detail 必须由独立 application service 从 current actor 与 current notification authority
裁剪：SAFETY_OFFICER 按 location scope，LEADER 仅重大风险或 leader audience，STUDENT 仅自身 target，
OPERATIONS 仅自身设备响应 target。audit 只允许可见范围内的 SAFETY_OFFICER/LEADER。所有读取均复用现有
typed notification receipts，不得授予 dispatch、reply、Case transition 或纪律处分 capability。

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

## 12. PPE 学生卡离线送达切片

确认后的 PPE 学生卡送达必须使用独立显式入口并只消费 exact typed route receipt。入口必须复核 current
Case、notification、target 与 source authority，复用默认离线 fake channel 顺序提交
`QUEUED -> SENT -> DELIVERED`；若中断在 `SENT`，必须从持久化 dispatch authority 与 raw card bytes
确定性恢复。`DELIVERED` 仅表示模拟通道完成，必须固定
`real_delivery_confirmed=false`、`case_transition_permitted=false`，不得替代飞书回执、迁移案件或形成处分。

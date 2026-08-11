# LabCourt

LabCourt 是一个本地优先、契约驱动、可离线复现的化学实验室违规案件系统。
它不会把“检测到目标”直接等同于“违规成立”，而是把候选事件组织成具备证据、
初审、控辩裁决、程序审查、告警、判例和申诉记录的可审计案件。

项目当前按
[`docs/spec/labcourt-vibe-coding-spec.md`](docs/spec/labcourt-vibe-coding-spec.md)
的 M0 → M6 顺序实施。默认开发与测试路径不需要 GPU、摄像头、云服务或真实人员图像。
M0 工程骨架、M1 确定性感知核心、M2 隐私证据包/可审计存储、M3
语义初审/确定性程序审查、M4 三角色会审与受限主动取证，以及 M5 生产判例、告警、申诉和
历史训练数据集闭环均已完成并冻结。M6 的 0014/V3 恢复链、CLOSED `REPLAY_LOCKED`
回归发布、隐私安全静态报告与 16 场景完整离线 demo 也已完成全量门禁并冻结。

M8 校园安全运营产品化现按
[`docs/spec/labcourt-campus-operations-spec.md`](docs/spec/labcourt-campus-operations-spec.md)
以 additive 方式推进，不修改上述冻结能力。M8.0–M8.5 的拓扑/来源、人员权限、案件状态流、
离线传感器、SQLite 权威记录、本机 API、通知闭环与版本化知识库已经完成；M8.6 的只读运营投影、
稳定读取、服务端角色裁剪和 authenticated loopback API 也已完成后端验收。M8.7a 已完成六类生产
adapter 的准入契约、append-only commissioning evidence、可重算 readiness 与双人 activation intent；
它只建立人工启用前的 fail-closed 边界，不会自动激活或发起外部调用。M8.7b 另以
`GET /api/m8/adapter-candidates/{candidate_authority_id}/readiness` 向当前运维角色提供服务端时点的
只读准入状态，不返回原始评审工件或凭据。M8.7c 已选择飞书企业自建应用并完成厂商专用卡片、
`open_id` binding、`uuid` 去重、typed failure/raw response 与 SQLite outbox 的全离线 preflight；模拟
provider 接受不会把通知推进到 `SENT`。M8.7d 进一步冻结了飞书 sandbox 的无密钥 runtime config 与
双人 activation commit：首次外部调用只可面向显式测试收件人 allowlist，生产发送仍禁止。M8.7d2 已
用 append-only SQLite 持久化 activation 与单人 kill switch；当前证据、双人权限或收件人 authority 变化
会动态变为 `INVALIDATED`，不再授权调用。M8.7e1 已实现可注入的 secret lease、token cache 与 sandbox
send core；默认只配内存 fake，token 明文不
进入 schema/SQLite/raw store，消息 timeout 保持 unknown-delivery。M8.7e2 已增加可选的显式环境引用
resolver 与固定 `open.feishu.cn`、系统 CA、单次 POST、0 自动重试的标准库 TLS transport；默认产品 wiring
仍不装配它，也尚无真实租户调用证据。M8.7e3a 已冻结通用 dispatch claim/call fence/completion：并发
worker 不得共享调用权，call fence 后崩溃必须待对账而不能自动重试；M8.7e3b 已用 migration 0008 和
SQLite repository 实现 source-version 唯一 claim、one-shot fence 及 completion/notification 原子提交。
M8.7e4a 进一步冻结 Feishu outbox run 组合回执，防止跨 preflight/activation/send/completion 拼接，同时保持
provider acceptance 不等于真实送达。M8.7e4b 已实现显式注入的单条 sandbox runner：claim 前与 call fence
前均重读 current activation，send core 再次核对 exact profile/测试收件人 allowlist；accepted 或 typed failure
会与 raw artifacts、`SENT`/`FAILED` 在 SQLite 原子提交，围栏后异常则进入待对账且不自动重试。默认产品
wiring 仍不装配 live secret/TLS adapter，仓库也尚无真实租户调用证据。M8.7f1 已开始补齐回复闭环：新增
encrypted webhook profile、未验证 ingress request 与 hash-only verified
`im.message.receive_v1` receipt；按 provider `message_id` 防重放、按 `parent_id` 关联 outbound message，且
验证回执本身不能提交 reply 或改变 Case。M8.7f2 已增加短生命周期可清零 secret lease、原始 body
SHA-256 签名/严格事件验证服务，以及 migration 0009 的 append-only encrypted/decrypted/content raw store；
provider `message_id` 在 SQLite 中唯一，异证据重放 fail closed。M8.7f3 已按当前 target/actor、连续通知历史与
exact outbound provider receipt 授权学生普通说明，并在同一 SQLite 事务中追加 `RESPONDED` 与 reply ledger；
它不会推断申诉、改变 Case 或形成处分。M8.7f4 增加了显式环境 secret resolver、可选且审计锁定的
`cryptography` AES-256-CBC adapter，以及独立的 encrypted URL challenge 验证边界。challenge 清文仅存在于
瞬时 JSON 响应，receipt 只保存 hash/reference；它不激活公网入口或业务事件。M8.7f5 增加了需显式启动的
`127.0.0.1` challenge-only HTTP listener：固定路径、有界 JSON、禁止压缩/分块传输，收到业务事件签名头时
明确返回入口未激活。仓库仍未开放公网 webhook、
保存真实学生自由文本或取得真实飞书租户验证证据。M8.7f6 已冻结 sandbox 公网回调配置与双人 activation
commit：精确绑定 callback URL/TLS/profile/commissioning/current actor，配置本身仍不开放入口，commit 也不允许
自动启动、生产入口、回复提交或案件动作；当前状态会重算人员与 commissioning authority，并支持当前运维或
安全负责人单人 kill switch，撤销后不得自动重启。独立 UI 任务
M8.7f7 已通过 migration 0011 将 ingress activation/revocation 做成 append-only SQLite authority：同一 intent
幂等、未撤销时禁止第二次启用、撤销后只允许连续 revision；进程重启后仍会重读当前 actor 与 commissioning
证据决定 `SANDBOX_INBOUND_ACTIVE` / `INVALIDATED` / `REVOKED`。仓库尚未把公网 HTTP listener 接到该状态。
M8.7f8 已增加显式构建的 activation-gated webhook backend：只监听 runtime config 的本机端口，逐请求重读
current ingress status；无事件头走 challenge，完整三件套签名头才走 `im.message.receive_v1` 验证/SQLite evidence
commit。任一缺头、坏签名、撤销或 authority 漂移均 fail closed；HTTP 200 仅表示入站证据已提交，不会自动
提交学生说明、改变案件或声称公网 TLS 已部署。
M8.7f9 已通过 migration 0012 将 URL challenge verification receipt 持久化为 hash-only append-only audit；
clear challenge 与原始解密载荷不落该 ledger，exact retry 幂等，审计提交仍不能激活入口或改变案件。
M8.7f10 已增加显式的 `labcourt feishu webhook-serve` 运行时装配：它只读取既有 SQLite activation，按
exact inbound profile 解析两个具名环境变量引用，装配可选 AES adapter、入站证据库和 challenge audit 后
绑定 activation 指定的 loopback 端口。`--check` 只完成校验、绑定与关闭；命令不会创建 activation、管理
公网 TLS、自动提交学生说明或执行案件动作。
M8.7f11 已把既有双人 activation 与单人 kill-switch 状态机接入显式运维命令：`webhook-activate` 只接受
已形成 typed intent 的两份当前人员确认和 canonical runtime config，`webhook-status` 从当前数据库 cut 重算，
`webhook-revoke` 只允许当前 in-scope 运维或安全负责人撤销。三者都不读取 secret、不自动启动 listener，
撤销由运行中的 backend 在下一次请求前观察并 fail closed。
M8.7f12 以独立的 `outbox-activate` / `outbox-status` / `outbox-revoke` 暴露同样严格的 sandbox 发送 authority：
发送 allowlist 还会重算当前收件人 target，activation 不会发送消息，稳定 UTC kill-switch 可精确重试；入站与
出站授权互不替代，真实联调必须分别满足各自的 current authority。
M8.7f13 已增加显式 `outbox-run-one`：一次只消费一条 current `QUEUED` 通知和一个 exact allowlisted binding，
从具名环境变量短暂解析 App ID/App Secret/open_id/worker token，使用固定 `open.feishu.cn`、系统 CA、零自动
重试 transport 完成 claim→call fence→send→SQLite completion。provider acceptance 只推进通知状态，仍明确
`real_delivery_confirmed=false`；围栏后的未知结果不得自动重试。`--check` 会验证同一输入但不 claim、不联网、
不发送，真实联调必须先通过该模式。
个人 Demo 产品装配已新增 `labcourt demo bootstrap`：它通过既有仓库幂等生成四层校园、四角色、模拟烟雾
raw signal、紧急待核实案件和运营投影，供后续本机 API 与独立 UI 任务消费；bootstrap 本身不执行案件迁移。
可直接消费
`GET /api/m8/campuses/{campus_id}/operations-projection` 的 typed view；仓库尚未声称真实摄像头、
消防系统、身份平台、外部消息平台或公网生产部署已经就绪。首个真实 adapter 的选择与输入要求见
[`docs/m8-production-adapter-intake.md`](docs/m8-production-adapter-intake.md)。

## 核心原则

- 安全底线不依赖 VLM。
- AI 负责语义提议，确定性代码验证客观事实与引用。
- 帧号是业务时间，墙钟不参与案件裁决。
- 存在型证据与缺失型证据使用不同的确证路径。
- L0 软提醒不建案、不落盘、不保存轨迹。
- 禁止人脸识别与跨摄像头 ReID。

## v0.2 图形演示入口

把已授权 MP4 放入 `inputs/` 后，在 Windows PowerShell 运行：

```powershell
.\.venv\Scripts\labcourt.exe pilot ui
```

浏览器会打开 `http://127.0.0.1:8876/`，集中展示视频选择、五阶段进度、视频预览、证据时间线、
案件详情和本地告警。界面只监听本机，浏览器不接触模型密钥；已有完整运行可直接回放，不会
再次调用 detector 或 VLM。详细说明见
[`docs/pilot-quickstart.md`](docs/pilot-quickstart.md)。

## 开发命令

完整校园运营 Demo 数据可先双击 `labcourt-demo-bootstrap.cmd`。它在被 Git 忽略的
`.labcourt-local/labcourt-demo/` 中幂等初始化 SQLite、校园四层拓扑、四角色、模拟烟雾原始信号、紧急
`PENDING_VERIFICATION` 案件及只读运营投影；不会联网、调用模型、发送消息或执行案件迁移。详见
[`docs/m8-personal-demo.md`](docs/m8-personal-demo.md)。
双击 `labcourt-demo-api.cmd` 会先绑定后关闭完成预检，再在 `127.0.0.1:8877` 启动现有 authenticated M8
API；四角色的本机演示 token 只写入同一 ignored 目录的 `api-access.json`，终端不显示明文。
API 装配还会幂等装载六类离线知识文档；问答返回来源、版本和生效时间，不使用模型或网络，也不把文档
静默转换为案件规则。
双击 `labcourt-demo-notification.cmd` 会把原始模拟紧急案件确定性路由给安全负责人，生成本地模拟卡片并
推进到 `QUEUED`；该入口不联网、不声称送达，也不改变案件。随后运营投影会显示该通知及审计链。
再双击 `labcourt-demo-notification-deliver.cmd`，现有离线 fake channel 会依次提交 `SENT` 和 `DELIVERED`；
结果始终标为模拟且 `real_delivery_confirmed=false`，不调用飞书。
双击 `labcourt-demo-notification-acknowledge.cmd` 并输入 `APPLY` 后，安全负责人可把通知闭环为
`ACKNOWLEDGED`；该动作不会确认、驳回或结案案件。
双击 `labcourt-demo-camera.cmd` 可增量注册一个 `RECORDED_VIDEO_SIMULATION` 摄像头，并把
`inputs/goggles-missing.mp4`（缺失时按文件名选择首个 MP4）按原始字节绑定到 ignored 本机播放目录；原文件不变，
绑定回执记录输入/播放副本哈希且显著显示 `SIMULATED · RECORDED VIDEO`，不伪装成实时画面。
日常演示可直接双击 `labcourt-demo-start.cmd`：它依次准备基础数据、摄像头、离线通知，完成 API bind-and-close
预检后在 `127.0.0.1:8877` 启动服务。已有回执会复用，派生的本机 API 访问文件会按当前 authority 刷新。
安全负责人或运维可用 authenticated `GET /api/m8/cameras/camera-recorded-demo-01/media-metadata`
读取绑定回执，并通过 `GET /api/m8/cameras/camera-recorded-demo-01/media` 获取 `video/mp4`；媒体接口支持标准
single-byte `Range` 与 `206 Partial Content`。领导和学生不自动获得一般风险摄像头媒体访问权。
设备页应先调用 authenticated `GET /api/m8/cameras`：安全负责人和运维会得到当前 catalog camera、媒体绑定
状态和上述播放入口；领导和学生得到空集合。未绑定媒体的 camera 仍会返回，但明确 `media_attached=false`。
双击 `labcourt-demo-ppe-case.cmd` 可把已绑定媒体作为 `VIDEO_EVENT` 创建一个 `GENERAL` 风险的学生 PPE
候选案件；它固定标注 `SIMULATED · MACHINE WEAK LABEL · PENDING VERIFICATION`，不验证视频内容、
不使用文件名作为证据、不把弱标签当 ground truth，也不能自动确认或处分。`labcourt-demo-start.cmd` 会幂等包含该步骤。
集成界面可先调用 authenticated `GET /api/m8/session` 获取当前 actor、role、scope 与 capability，无需在前端
根据 token 猜测角色；响应不包含 bearer token。
案件列表使用 `GET /api/m8/cases`：安全负责人只看辖区案件、领导只看重大事件、学生只看本人案件，运维
返回空列表；列表权限由服务端当前 authority 裁剪。
通知中心可使用 `GET /api/m8/notifications`、`GET /api/m8/notifications/{id}` 和 `/audit`；当前模拟紧急
通知仅对辖区安全负责人及重大事件领导可见，学生与运维无法读取。
API 运行时可双击 `labcourt-demo-case-action.cmd`，选择确认、驳回、请求补证、返回核实或结案，并输入
案件目标 `EMERGENCY_SMOKE` / `PPE_CANDIDATE` 后输入 `APPLY` 完成一次安全负责人显式动作；默认目标仍是
烟雾案件，脚本不提供领导或运维审批入口，也不会被一键启动自动调用。
PPE 案件经安全负责人明确确认后，学生可双击 `labcourt-demo-student-appeal.cmd`，填写争议理由并独立输入
`APPLY`；客户端只读取 exact PPE receipt、只使用 student token，并提交现有
`SUBMIT_APPEAL/SUBJECT_DISPUTE` transition。未确认的候选案会被状态机拒绝，申诉不会自动撤销或结案。
PPE 案件确认后可双击 `labcourt-demo-ppe-notification.cmd`：它向 `student-demo` 幂等路由一张默认离线的
`CASE_UPDATED/CASE_SUBJECT` 卡片并停在 `QUEUED`，学生通知中心可见；卡片允许确认、提交说明或请求申诉，
但回复和卡片本身均不能迁移案件。该入口不联网，也不在默认启动中自动执行。
随后双击 `labcourt-demo-ppe-notification-deliver.cmd`，可将 exact route receipt 通过离线 fake channel
显式推进到 `DELIVERED`；该状态固定不代表飞书或真实人员已收到，也不会迁移案件。
学生再双击 `labcourt-demo-ppe-notification-reply.cmd`，可明确选择 `EXPLANATION` 或 `APPEAL_REQUEST`、
填写内容并输入 `APPLY`。原始 UTF-8 回复会进入通知审计链，但只把通知推进到 `RESPONDED`；申诉案件仍须
单独执行 `labcourt-demo-student-appeal.cmd`，消息回复本身没有案件或处分权限。
案件进入 `APPEALED` 后，安全负责人可双击 `labcourt-demo-ppe-appeal-resolve.cmd`，选择
`UPHELD` 或 `OVERTURNED`、填写理由并输入 `APPLY`。该动作使用既有 `RESOLVE_APPEAL` 契约，最终
`APPEAL_RESOLVED` 即本申诉路径的结案状态；不会伪造一个状态矩阵不允许的二次 `RESOLVE`。
结案后可双击 `labcourt-demo-ppe-outcome-notification.cmd`，为学生创建一张独立、只读的离线结果卡；
它绑定 exact terminal Case 与 `UPHELD|OVERTURNED` 结果，停在 `QUEUED`，不会覆盖原说明/申诉审计。
再双击 `labcourt-demo-ppe-outcome-deliver.cmd` 可通过离线 fake channel 显式推进到 `DELIVERED`；该状态仍
固定 `real_delivery_confirmed=false`，不代表飞书送达，也不会改变已结案案件。
学生最后可双击 `labcourt-demo-ppe-outcome-acknowledge.cmd` 并输入 `APPLY`，将结果通知推进到
`ACKNOWLEDGED`。这只关闭通知闭环，案件继续保持终态 `APPEAL_RESOLVED`。
个人 Demo API 的 `GET /api/m8/users` 向领导和安全负责人返回当前 typed actor receipts，可直接展示
角色、scope、capabilities、active 与 revision；运维/学生无权读取全量清单，且该端点不提供权限变更。
`GET /api/m8/campuses/campus-demo/sensors` 与 `/device-health` 直接复用当前 role-scoped operations
projection：前者发现 typed sensor sources，后者返回全部 source、latest persisted sample 与
`observation_state`。领导/安全负责人/运维可读，学生禁止；模拟与非认证生命安全边界始终保留。
`GET /api/m8/rules` 向领导和安全负责人返回当前 typed smoke Demo risk policy，可展示阈值、风险等级、
自动待核实建案与响应期限。它不是从知识库文档解析出来的，本切片只读；后续写入须先增加持久化 revision。

Windows 个人 Demo 可先使用 `feishu-setup.cmd`、`feishu-demo-card.cmd` 和
`feishu-demo-emergency.cmd`，只配置企业自建应用的 App ID、App Secret 与测试 `open_id`，即可在明确
确认后尝试发送固定连通卡片，或演示“离线模拟烟雾 → 紧急候选 → 待核实案件建议”卡片。两者都不创建
正式案件或通知状态。完整闭环再使用
仓库根目录的 `feishu-preflight.cmd`、
`feishu-webhook.cmd` 和 `feishu-send-one.cmd`。真实测试凭据只保存在被 Git 强制忽略的
`.labcourt-local/feishu-secrets.json`；仓库中的示例保持全空。webhook 与单条发送入口都先执行无网络
预检，发送还要求人工输入 `SEND`。详细前置工件、飞书后台配置和安全边界见
[`docs/m8-feishu-windows-personal-demo.md`](docs/m8-feishu-windows-personal-demo.md)。

支持 Python 3.11–3.12；本仓库的 `.python-version` 按规格固定为 3.11。依赖与命令由
[uv](https://docs.astral.sh/uv/) 管理。

```bash
uv sync --all-groups --locked
make quality
make e2e
make m4-coverage
make demo
```

The audited AES provider for encrypted Feishu inbound events is an explicit optional install;
it does not enable a public webhook or change the default offline wiring:

```bash
uv sync --all-groups --extra feishu-inbound --locked
```

已有 current sandbox inbound activation 时，可先让获批的 secret loader 注入 Encrypt Key 与 Verification
Token，再以环境变量名（不是 secret 值）执行一次只读运行时预检：

```powershell
.\.venv\Scripts\labcourt.exe feishu webhook-serve `
  --database <activated-authority.db> `
  --candidate-authority-id <candidate-authority-id> `
  --encrypt-key-env LABCOURT_FEISHU_ENCRYPT_KEY `
  --verification-token-env LABCOURT_FEISHU_VERIFICATION_TOKEN `
  --runtime-manifest-id <lowercase-sha256> `
  --check --json
```

去掉 `--check` 才会阻塞运行本机 backend；公网 HTTPS、域名、证书、反向代理与飞书后台 Request URL
仍由外部受审计部署负责，且必须与 activation 中的引用和哈希一致。

首次 sandbox activation 必须消费外部双人确认流程生成的 typed intent 和 canonical runtime config，不能在
命令行内临时拼接权限：

```powershell
.\.venv\Scripts\labcourt.exe feishu webhook-activate `
  --database <commissioned-authority.db> `
  --activation-intent <dual-human-activation-intent.json> `
  --runtime-config <canonical-inbound-runtime-config.json> `
  --runtime-config-storage-manifest-id <lowercase-sha256> `
  --repository-manifest-id <lowercase-sha256> `
  --assessment-manifest-id <lowercase-sha256> `
  --json
```

当前状态可用 `webhook-status` 重算；紧急停用使用 `webhook-revoke` 并显式提供 current activation commit、
当前 revoker actor、closed reason、reason reference、稳定的 ISO-8601 UTC `revoked_at` 和 revocation manifest；
精确重试必须复用同一 `revoked_at`。kill-switch 不直接操作其他进程，但运行中的 backend 会逐请求重读
authority，因此撤销后 challenge 与业务事件立即拒绝。

outbound sandbox 使用同样的外部双人 intent 流程，但配置是包含测试收件人 allowlist 的
`M8FeishuSandboxRuntimeConfigV1`；以 `outbox-activate` 提交、`outbox-status` 重算、`outbox-revoke` 停用。
这三个命令不会读取 App Secret 或调用飞书，webhook activation 也不能替代 outbox activation。

发送一条已排队测试通知时，使用 `outbox-run-one` 并显式提供 notification/candidate/binding、canonical
`M8NotificationWorkflowManifestAuthorityV1`、四个环境变量名和三个 manifest ID。命令没有扫描/批量模式；
App ID/App Secret/open_id/worker token 的值只能由获批 secret loader 注入环境，不能作为命令行参数。先附加
`--check --json` 确认输出中的 `dispatch_claim_created=false` 与 `external_call_attempted=false`，人工确认后才可
去掉 `--check` 执行一次真实调用。

没有 `make` 的 Windows 环境可直接运行：

```powershell
uv run --locked pytest
uv run --locked python scripts/export_schemas.py --check
uv run --locked python scripts/run_m6_demo.py
```

本机若只有 `mingw32-make`，可用 `mingw32-make test` 代替 `make test`。

`make quality` 已包含 `m4-coverage` 与 `m5-coverage`：它们分别对 M4 状态机、预算策略、
五工具矩阵、重审路径，以及 M5 申诉、告警、判例冲突和训练质量门执行 branch coverage 100%
的独立门禁。

## M6 完整离线演示

执行：

```bash
make demo
```

命令会在隔离的 pytest 环境中指定 16 个精确 node ID，并核验一次性 JUnit 回执中的 16 个逐项
通过结果；只有完整回执成立，才会为每个场景生成 canonical 结果工件，并在同一 generation
中依次原子发布 CLOSED `regression.json`、隐私安全静态报告和 demo 站点。终端最后输出
`index_path`，用任意本地浏览器直接打开即可，无需后端或网络。

输出位于 `runs/m6-demo/generations/<demo-seal-id>/closed-report-candidate/`。其中：

- `demo/index.html` 是 demo 的最终 commit point；
- `demo/scenarios/<scenario>/result.json` 是 16 个逐场景、内容寻址的通过凭据；
- `index.html` 与 `regression.json` 分别是隐私安全报告和机器可读 CLOSED 回归结果；
- `demo/seal.json` 与内容寻址 manifest 可重算全部发布身份。

所有内容均明确标记为 `SYNTHETIC_PRECOMPUTED_FAKE`。它验证确定性流程、契约、恢复和发布
语义，不代表真实模型准确率、延迟、吞吐、成本或现实安全表现；默认路径不使用 GPU、网络、
真实摄像头或真实人员图像。

## 工件校验、恢复与 M3/M4 离线流程

对已存在的 run 执行只读工件校验：

```bash
labcourt artifacts validate --run-id <run_id>
```

校验器检查 audit chain/head、SQLite 文档、current closure、当前媒体、最终 raw response
库存与 `current.json` 指向的完整投影 generation；不重放原始帧、隐私变换或模型调用，也不把
staging/journal 当成最终权威。若 run 已有 M4 权威，同一命令还会校验 hearing、角色调用、backlog、
补证执行、相邻 EvidencePack 派生、Verdict 绑定和当前 Case 根的双向闭包，并重新读取和验证 M4
闭包引用的物理 PNG。M4 校验器只在完整 M4 权威能够证明某条旧 M2/M3 检查已被合法后继取代时
标记该条为 superseded；其余任何 M2/M3 缺陷仍会阻止通过。

数据库总字节、单文档字节、各类库存数量、raw response 总量和完整投影发布字节均有命令行预算。
私有快照的权威库存会与最终文件遍历逐项对账，孤立、缺失、跨 run、哈希不符或非法历史都会使
校验失败。权威 SQLite 不会被 SQLite 本身直接打开；主库及已存在的 WAL/SHM 被当作一个稳定
集合，通过已校验的只读 handle 复制到仅当前用户可访问的临时目录，后续只打开该私有副本。

对已存在的 run 执行有界的启动恢复：

```bash
labcourt maintenance recover --run-id <run_id>
```

恢复严格先处理 retention/PURGING，再扫描 orphan 和模型响应 publication journal。它可以在
不调用 provider、不解析模型输出、不推进案件的前提下，把已精确落盘的响应收敛到 SQLite/cache，
并幂等确认 journal。未引用的 staging 或 final media 移入受控隔离区，不对 run 或工作区做递归
删除；只有精确匹配、经验证且超过最小年龄的空 staging 操作目录才会非递归清理。

使用默认离线 Fake VLM 推进一批 `EVIDENCE_READY` 案件：

```bash
labcourt process \
  --run-id <run_id> \
  --fixture-bundle <fake-vlm-fixtures.json>
```

回收过期租约并最多重试一个 `SCREENING` backlog item：

```bash
labcourt backlog retry \
  --run-id <run_id> \
  --worker-id <stable_worker_id> \
  --fixture-bundle <fake-vlm-fixtures.json>
```

使用三份独立 Fake VLM 角色输入推进一个明确的 `ESCALATED | REWORK_REQUIRED` Case：

```bash
labcourt hearing process \
  --run-id <run_id> \
  --case-id <case_id> \
  --fixture-bundle <m4-fake-vlm-fixtures.json>
```

回收过期租约并最多重试一个精确角色的 `HEARING` backlog item：

```bash
labcourt hearing backlog retry \
  --run-id <run_id> \
  --worker-id <stable_worker_id> \
  --fixture-bundle <m4-fake-vlm-fixtures.json>
```

只收敛已落盘的 M4 模型响应 publication journal：

```bash
labcourt hearing recover-responses \
  --run-id <run_id> \
  --limit 10000
```

`recover-responses` 不调用 provider，不解析响应，不执行补证，不恢复角色编排，不推进 Case，也不
重置任何预算。业务重试只能通过持有精确 checkpoint 和 lease 的 `hearing backlog retry` 完成。
已证明 `DEFINITELY_NOT_SENT` 的 provider 重试失败以 exact call 的 `RETRY_FAILURE`
model-call authority 闭包；严格解析失败由 response、strict proof、typed outcome 和 completion
receipt 闭包，不能伪装成 provider 失败。过期 lease 回收则以 `WORKER_LEASE_EXPIRED` 绑定不可变
backlog stage input，不能伪称发生了 provider 失败或引用响应。

fixture bundle 是显式、严格、有界的离线输入；重复键、非规范超大数值、非有限数值、超预算响应或
未知请求都会 fail closed。M4 bundle 的 `fixtures` 绑定精确角色请求；可选的
`acquisition_fixtures`（最多 64 项）逐项绑定精确 `AcquisitionRequest` 和五种工具各自允许的
typed outputs。补证 fixture 必须按 request ID 稳定排序，条目数量既进入 bundle 内容地址，也进入
命令报告的 `acquisition_fixture_count`，因此不能在审计外增删。

只要 bundle 含补证 fixture，RunManifest 的 `software_components` 就必须精确包含：

```json
{
  "m4-controlled-fake-acquisition": {
    "component": "m4-controlled-fake-acquisition",
    "package": "labcourt",
    "version": "0.1.0",
    "license_id": "Proprietary"
  }
}
```

工具执行 manifest 绑定这份 canonical component 文档字节的 SHA-256；缺失或内容不一致会在创建
任何 M4 补证权威前以 `ACQUISITION_COMPONENT_UNPINNED` fail closed。

M3 与 M4 的离线模型命令都会显著输出 `SIMULATED PERCEPTION / FAKE VLM`；M4 还标明
`CONTROLLED FAKE`。仓库 fixture 只验证状态机、持久化与审计语义，不代表真实模型准确率。
权威事务一旦完成不会因投影重建失败而回滚；此时命令返回可重试的 `PENDING_REBUILD`，再次运行可
由 SQLite 重建同一内容寻址 generation。

校验与恢复命令使用稳定退出码：`0` 表示完成且通过，`1` 表示已产生可信报告但发现需处理问题，
`2` 表示配置、预算、数据库、run 或安全边界使得命令无法生成可信报告。可加 `--json` 获得稳定的机器可读输出。

SQLite writer 对缺失主库、非受控路径、link/reparse、异常 WAL/SHM 或任何 rollback journal 均
fail closed；只有 migration runner 能以 owner-only 的排他创建原语初始化数据库。这不是 custom SQLite
VFS，因此同权限攻击者在检查间完成完美 ABA 仍是已记录的残余边界。此外，从文件系统 unlink
不等于对 SSD 上的物理数据进行可证明擦除。

所有性能数字都只是待验证目标；仓库中的离线 fixture 不能代表真实实验室准确率。

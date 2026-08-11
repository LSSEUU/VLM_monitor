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
worker 不得共享调用权，call fence 后崩溃必须待对账而不能自动重试；SQLite 行为将在下一切片实现。独立 UI 任务
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

支持 Python 3.11–3.12；本仓库的 `.python-version` 按规格固定为 3.11。依赖与命令由
[uv](https://docs.astral.sh/uv/) 管理。

```bash
uv sync --all-groups --locked
make quality
make e2e
make m4-coverage
make demo
```

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

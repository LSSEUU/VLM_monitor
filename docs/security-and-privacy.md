# 安全与隐私边界

## 默认边界

系统默认离线运行，HTTP 服务默认只绑定 `127.0.0.1`。开发免认证模式不能直接复用为生产部署；生产 API 必须置于经过审查的认证网关后并 fail closed。真实网络、Feishu sandbox、webhook listener、模型服务和传感器只允许通过显式配置、preflight 和操作命令启用。

安全边界以 `docs/spec/labcourt-vibe-coding-spec.md` 第 22 节、`docs/spec/labcourt-campus-operations-spec.md` 第 1、4、7 节及 `docs/security-boundaries.md` 为准。

## 身份、权限与审计

- 服务端从持久化 actor/capability authority 解引用角色、作用域、版本和 active 状态；不信任客户端自报 role、scope 或 capability。
- M8 角色为 `LEADER`（只读）、`SAFETY_OFFICER`（案件动作）、`STUDENT`（本人消息/申诉）、`OPERATIONS`（设备与健康）。列表、详情、审计、通知和设备投影都必须执行相同的作用域检查。
- 案件迁移使用源版本、源 authority hash、当前 actor、capability、原因和 supporting evidence/signal 引用；写入 append-only audit/commit receipt。
- 自动化只能建议或创建 `PENDING_VERIFICATION` 案件，固定 `human_verification_required=true`、`explicit_human_confirmation=true`、`direct_disciplinary_action_permitted=false`。系统不直接实施纪律处分。
- 通知使用持久化 outbox 和幂等 key；发送失败必须变成可见的重试/运维状态，不能静默吞错。

## 数据最小化

- 只保存完成裁决、审计、回放和运维所需的媒体片段、证据引用、raw artifact hash、manifest 和 typed 结果。
- 日志、fixture、提交和报告不得包含 API key、bearer token、明文 secret 或未脱敏真实人员图像。
- 个人 Demo token 只能以 hash 形式进入 authority；明文仅允许存在于 Git 忽略的本机 access 文件，且不得打印。
- API 响应不返回 raw evidence bytes、secret、activation authority 或 bearer token；媒体读取必须同时校验 actor authority、绑定 receipt、source catalog cut 和同一打开句柄的字节 hash。
- 保留/删除由 retention policy 和审计要求决定，不得为了“清理”删除仍被 manifest、prompt hash、回放或审计引用的资源。

## 明确禁止事项

- 人脸识别、face embedding、跨摄像头 re-identification（ReID）。身份必须来自外部授权映射，不能从图像推断。
- 使用 VLM 作为客观计数、持续时间、身份、坐标或证据存在性的权威。
- 用 permissive free-text parser 猜测结构化模型输出，或在模型不可用时用另一个角色/模型偷偷替代。
- 用弱标签作为 ground truth，或让普通知识文档绕过 rule authority 进入裁决路径。
- 让未来合规抹除过去的 `STRICT_CAUSAL` 违规；让 Agent 直接获得关键案件迁移 capability。
- 默认启动后台 Feishu worker、批量发送、静默确认、公开 webhook 或任何未通过 activation/revocation authority 的外部调用。
- 在 domain 层引入 HTTP、数据库、OpenCV、Torch 或云 SDK。

## 外部适配器与恢复

每个模型、传感器和外部通知调用必须具备 fake/offline 实现、timeout、cache、manifest、raw response reference 和 typed failure。Feishu inbound/outbound activation 必须有独立、可撤销且可审计的 authority；secret 通过具名 secret store 短暂解析，不写入配置、schema、日志或 authority clear value。webhook 只允许显式 loopback 运行时，不能把 loopback challenge 误标为公网 TLS 或生产 URL 已就绪。

发生 provider、网络、权限、schema、证据或 SQLite 故障时，应返回 typed exit 或持久化 case/backlog 状态；不能吞异常或伪造成功。硬安全信号发送失败必须进入高优先级 outbox 重试并触发运维可见告警。

## 开发检查

变更应先更新 Pydantic contract、生成 schema 和 contract tests，再改业务行为；使用 `make schemas-check`、架构依赖检查、Ruff/Mypy 和相关测试验证边界。安全文档不得声称尚未产生的合规、准确率、延迟或成本结果。

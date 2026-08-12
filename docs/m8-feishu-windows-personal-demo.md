# 飞书 Windows 个人 Demo 一键运行

本方案只用于单机、单操作者、显式测试收件人的 sandbox 演示。它不会把本机服务伪装成公网服务，
不会把 provider 接受声明为真实送达，不会自动提交学生回复、改变案件状态或形成处分依据。

## 安全边界

- 唯一的本机明文凭据文件是 `.labcourt-local/feishu-secrets.json`。仓库用精确规则强制忽略它；
  首次配置还会在写入前收紧 `.labcourt-local` 的 Windows ACL。
- 仓库只提交字段为空的 `feishu-secrets.example.json`。空白示例故意不能通过运行时契约，避免误启动。
- 凭据用遮罩输入；CLI、脚本输出和错误只报告状态，不输出 App ID、App Secret、测试 `open_id`、
  Encrypt Key、Verification Token 或 worker token。
- 默认入口都先执行无网络 `--check`。`feishu-send-one.cmd` 还要求预检后现场输入 `SEND`，且一次
  只尝试一条 exact `QUEUED` 测试通知，没有批量或自动重试模式。
- 脚本只消费已经存在的 typed 双人 activation intent 与 canonical runtime config；它不会生成、代填或
  伪造 operations/safety 两份确认。个人 Demo 的存储方式被简化，授权语义没有被放宽。

## 最快可见 Demo

首次展示只需要企业自建应用的三个值，不需要先准备 LabCourt 数据库或双人 activation 工件：

1. 在飞书开发者后台为企业自建应用启用机器人能力，申请 `im:message:send_as_bot` 权限，发布一个
   对测试账号可用的版本。App ID 和 App Secret 位于“凭证与基础信息”。参考
   [飞书访问凭证说明](https://open.feishu.cn/document/ukTMukTMukTM/uMTNz4yM1MjLzUzM)和
   [机器人能力说明](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/bot-v3/bot-overview)。
2. 准备该应用作用域内测试账号的 `open_id`。不要使用真实学生资料。
3. 双击 `feishu-setup.cmd`，依次遮罩输入 App ID、App Secret、测试 `open_id`。默认只配置快速 Demo，
   不再询问 database、manifest、Encrypt Key 或 Verification Token，并自动完成无网络检查。
4. 双击 `feishu-demo-card.cmd`。本地检查通过后输入 `SEND`，程序只发送一张固定、显著标注模拟事件的
   LabCourt 卡片。运行回执与脱敏响应保存在 `.labcourt-local/feishu-demo-runs/`。
5. 业务链路展示可双击 `feishu-demo-emergency.cmd`。它先在本机确定性生成模拟烟雾原始信号、紧急风险
   评估和“建议建立待核实案件”，输入 `SEND` 后再发送一张红色飞书卡片。它不写 SQLite，也不创建
   正式案件或通知；回执保存在 `.labcourt-local/feishu-emergency-demo-runs/`。

该卡片只证明应用凭据、权限、可用范围和目标 `open_id` 能完成一次 API 调用，不属于案件通知，不证明
真实送达，也不能改变任何 LabCourt 状态。

## 完整通知闭环前置条件

1. 已在仓库根目录创建 `.venv` 并安装当前项目；`.venv\Scripts\labcourt.exe` 必须存在。
2. 飞书企业自建应用已建立，测试学生已在应用可用范围内；只使用测试人员的 `open_id`。
3. 已准备当前 SQLite authority、outbox/webhook 的 typed activation intent、canonical runtime config、
   notification workflow，以及对应 candidate、binding、notification 和 manifest ID。
4. 若要接收公网回调，需另行部署受控 HTTPS 反向代理，并让飞书后台 Request URL 与 inbound runtime
   config 完全一致。本仓库脚本只监听 activation 指定的 loopback 地址，不管理域名、证书、TLS 或隧道。

不要把真实学生自由文本、真实人员图片或生产租户凭据用于此个人 Demo。

## 六个入口

从资源管理器双击仓库根目录的命令文件，或在 PowerShell 中运行对应 `.ps1`：

1. `feishu-setup.cmd`：默认只遮罩采集 App ID、App Secret 和测试 `open_id`，原子写入后执行快速 Demo
   的无网络检查。完整 authority 配置使用
   `scripts\windows\feishu-setup.ps1 -FullAuthority`；只保存则附加 `-ConfigureOnly`。
2. `feishu-demo-card.cmd`：先做无网络检查，通过后要求输入 `SEND`，向测试账号尝试发送一张固定模拟卡片。
3. `feishu-demo-emergency.cmd`：确定性运行离线模拟烟雾传感器与 typed 风险策略；先检查、再确认发送一张
   “紧急候选/建议待核实案件”卡片。模拟信号不是认证消防检测，也没有正式案件 authority。
4. `feishu-preflight.cmd`：校验 Git ignore、配置契约、必需工件、双人 activation authority、secret 引用、
   exact notification/binding/workflow，并分别运行 webhook 与 outbox check mode。不会连接飞书。
5. `feishu-webhook.cmd`：先执行 webhook 预检，通过后才启动 loopback listener。终端需保持打开；
   `Ctrl+C` 停止。公网 HTTPS 仍由外部受审计设施负责。
6. `feishu-send-one.cmd`：先执行 outbox 预检，通过后要求输入 `SEND`，随后进行一次 sandbox 调用尝试。
   provider acceptance 仍显示 `real_delivery_confirmed=false`；超时或未知结果不得自动重试，应先对账。

脚本可以从任意当前目录启动，所有相对路径都以仓库根目录解析。`.cmd` 包装器会在退出时暂停，便于
双击运行后查看无密钥结果。

## 首次配置字段来源

- App ID、App Secret：快速 Demo 必填，来自该测试自建应用的飞书管理后台。
- Encrypt Key、Verification Token：只有 `-FullAuthority` 的 inbound webhook 闭环需要。
- 测试 `open_id`：必须与 outbound runtime config 中唯一 allowlisted recipient binding 对应。
- candidate/binding/notification/manifest ID：复制既有 LabCourt authority 工件中的 64 位小写 SHA-256 ID，
  不要临时编造。
- activation intent/runtime config：分别提供 outbound 与 inbound 的既有 canonical JSON 文件；两类授权
  彼此独立。

完整配置后可再次运行 `feishu-preflight.cmd`。只要工件、人员 authority、收件人 binding、secret reference 或
manifest 有漂移，预检就会 fail closed，不会进入监听或发送阶段。

## 本机清理

退出所有 LabCourt 进程后，可手工删除 `.labcourt-local/feishu-secrets.json` 以移除本机明文测试凭据。
删除后所有一键入口都会在预检阶段停止；Git 历史中没有该文件。若怀疑凭据曾外泄，还应立即在飞书后台
轮换或撤销对应凭据，仅删除本机文件并不能撤销平台侧凭据。

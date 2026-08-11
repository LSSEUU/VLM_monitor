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

## 前置条件

1. 已在仓库根目录创建 `.venv` 并安装当前项目；`.venv\Scripts\labcourt.exe` 必须存在。
2. 飞书企业自建应用已建立，测试学生已在应用可用范围内；只使用测试人员的 `open_id`。
3. 已准备当前 SQLite authority、outbox/webhook 的 typed activation intent、canonical runtime config、
   notification workflow，以及对应 candidate、binding、notification 和 manifest ID。
4. 若要接收公网回调，需另行部署受控 HTTPS 反向代理，并让飞书后台 Request URL 与 inbound runtime
   config 完全一致。本仓库脚本只监听 activation 指定的 loopback 地址，不管理域名、证书、TLS 或隧道。

不要把真实学生自由文本、真实人员图片或生产租户凭据用于此个人 Demo。

## 四个入口

从资源管理器双击仓库根目录的命令文件，或在 PowerShell 中运行对应 `.ps1`：

1. `feishu-setup.cmd`：遮罩采集凭据和本地 authority 引用，生成随机 worker token，原子写入本机配置，
   严格校验后默认执行完整预检。只想先保存配置时可直接运行
   `scripts\windows\feishu-setup.ps1 -ConfigureOnly`；这不会授权 webhook 或发送。
2. `feishu-preflight.cmd`：校验 Git ignore、配置契约、必需工件、双人 activation authority、secret 引用、
   exact notification/binding/workflow，并分别运行 webhook 与 outbox check mode。不会连接飞书。
3. `feishu-webhook.cmd`：先执行 webhook 预检，通过后才启动 loopback listener。终端需保持打开；
   `Ctrl+C` 停止。公网 HTTPS 仍由外部受审计设施负责。
4. `feishu-send-one.cmd`：先执行 outbox 预检，通过后要求输入 `SEND`，随后进行一次 sandbox 调用尝试。
   provider acceptance 仍显示 `real_delivery_confirmed=false`；超时或未知结果不得自动重试，应先对账。

脚本可以从任意当前目录启动，所有相对路径都以仓库根目录解析。`.cmd` 包装器会在退出时暂停，便于
双击运行后查看无密钥结果。

## 首次配置字段来源

- App ID、App Secret、Encrypt Key、Verification Token：来自该测试自建应用的飞书管理后台。
- 测试 `open_id`：必须与 outbound runtime config 中唯一 allowlisted recipient binding 对应。
- candidate/binding/notification/manifest ID：复制既有 LabCourt authority 工件中的 64 位小写 SHA-256 ID，
  不要临时编造。
- activation intent/runtime config：分别提供 outbound 与 inbound 的既有 canonical JSON 文件；两类授权
  彼此独立。

配置后可再次运行 `feishu-preflight.cmd`。只要工件、人员 authority、收件人 binding、secret reference 或
manifest 有漂移，预检就会 fail closed，不会进入监听或发送阶段。

## 本机清理

退出所有 LabCourt 进程后，可手工删除 `.labcourt-local/feishu-secrets.json` 以移除本机明文测试凭据。
删除后所有一键入口都会在预检阶段停止；Git 历史中没有该文件。若怀疑凭据曾外泄，还应立即在飞书后台
轮换或撤销对应凭据，仅删除本机文件并不能撤销平台侧凭据。

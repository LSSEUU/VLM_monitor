# ADR 0067：个人 Demo API 复用持久化角色与案件 authority

## 状态

Accepted for the loopback personal Demo.

## 背景

bootstrap 已生成可供产品消费的 SQLite authority，但直接让 UI 读取数据库会复制权限裁剪和乐观并发逻辑。
已有 M8 HTTP server、hash bearer authenticator、角色投影和案件迁移服务能够完成这些职责，缺少的是本机装配。

## 决策

个人 Demo runtime 直接装配既有 inventory/operations/sensor/notification/knowledge/commissioning repositories 与
API services，固定绑定 `127.0.0.1`。四角色使用固定的非生产演示 token；typed profile 只保存 token hash，
明文仅写入 `.labcourt-local/labcourt-demo/api-access.json`，终端和提交物不显示。

Windows 入口必须先运行 bind-and-close check，再启动阻塞式 server。领导只获得重大案件只读视图，运维只
获得设备视图，学生不能读取运营投影；安全负责人执行案件迁移仍必须提交显式人工确认和 supporting
authority，服务端从 SQLite 重读 current actor authority。

## 后果

独立 UI 可以通过稳定 HTTP 契约接入，无需理解 SQLite 布局或自行声明角色。固定 token 与 loopback 绑定只
适合个人 Demo，`production_ready=false`；后续 OIDC adapter 替换认证入口但不能扩大既有 capability 矩阵。

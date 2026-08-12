# ADR 0074：Windows 一键启动只编排既有 authority

## 状态

Accepted for the personal Demo.

## 背景

个人 Demo 已有多个可验证入口，但展示前逐个双击会增加操作成本。简单地把所有动作塞进一个新 bootstrap
会混淆基础数据、通知迁移、人工确认和外部平台边界。

## 决策

新增 Windows `labcourt-demo-start.cmd`，只顺序调用既有 bootstrap、camera registration、notification route、
offline delivery 和 API 命令。已有通知 receipt 时复用现有阶段，不自动执行 acknowledgement。API 必须先
bind-and-close check，再启动 loopback server；入口不调用飞书、不执行案件动作、不开放公网。

API profile、local access 和 knowledge receipt 是当前已验证 authority 的完全派生 runtime 文件，允许原子
刷新以跨 Demo 版本升级。基础 bootstrap、catalog、Case、notification 和 raw artifact receipts 仍使用 exact
write/conflict-closed 语义，编排层无权覆盖。

## 后果

Windows 用户可一次双击获得稳定后端，同时所有领域状态仍由原命令和 repository 约束。未来最小 UI 可直接
消费同一 loopback API，而无需复制初始化或权限逻辑。

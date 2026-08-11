# ADR 0071：离线 Demo 送达必须显式且保持模拟语义

## 状态

Accepted for the offline personal Demo.

## 背景

路由命令有意止于 `QUEUED`，但展示产品闭环还需要可见的发送与送达审计。如果基础启动或路由命令直接
写成 `DELIVERED`，用户无法区分发送意图、通道接受和送达，也容易把本地 fake 结果误解为飞书证据。

## 决策

增加独立的离线 delivery 命令。它必须读取并验证 exact typed route receipt，仅允许现有
`LOCAL_OFFLINE_FAKE` plan，通过既有通知服务依次提交 `RECORD_SENT` 与 `RECORD_DELIVERED`。卡片、发送
响应和送达响应继续按原始字节与 manifest 写入 SQLite。

若进程在 `SENT` 后中断，新进程从持久化 dispatch request、result 和 card bytes 重放同一个确定性 fake，
再提交唯一的 delivery；已经 `DELIVERED` 时精确重放返回现有 receipt。任何结果都固定不确认真实送达、
不调用网络、不执行案件动作。

## 后果

个人 Demo 可展示 `PLANNED -> QUEUED -> SENT -> DELIVERED` 的完整审计，同时不污染正式飞书 authority。
真实飞书仍使用独立 activation-gated outbox，provider acceptance 与真实送达继续分离。

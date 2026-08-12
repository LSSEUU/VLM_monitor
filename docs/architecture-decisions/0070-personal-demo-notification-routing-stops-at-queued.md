# ADR 0070：个人 Demo 通知路由止于 QUEUED

## 状态

Accepted for the offline personal Demo.

## 背景

通知状态机、SQLite outbox、离线通道和飞书 sandbox runner 已存在，但个人 Demo 的默认数据库没有通知，
运营投影无法展示从紧急案件到责任人的路由。把发送或送达硬塞进基础 bootstrap 会隐藏状态迁移，也会让
离线模拟和真实平台边界变得不清楚。

## 决策

新增独立的个人 Demo 通知路由命令。它只接受原始版本的模拟紧急待核实案件，发布安全负责人本地 fake
target，创建 `CASE_ACTION_REQUIRED` plan，并由确定性 system authority 推进一次 `PLANNED -> QUEUED`。
命令输出 content-addressed route receipt 和离线卡片，重复执行返回相同 authority。

该命令不装配外部 transport、不读取飞书凭据、不产生 dispatch/delivery receipt，也不执行案件动作。真实
飞书发送仍必须使用 activation-gated one-shot outbox；provider acceptance 也不能冒充真实送达。

## 后果

运营总览能够展示一条可审计的待发送通知，安全负责人和领导看到重大案件通知，运维仍只看到设备范围。
后续切片可在该 `QUEUED` 边界上增加显式离线 dispatch 或正式飞书绑定，而无需改写案件或 outbox 契约。

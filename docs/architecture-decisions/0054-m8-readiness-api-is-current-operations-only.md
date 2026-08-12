# ADR 0054：M8 readiness API 只信任当前运维权限与服务端时点

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.7 commissioning readiness API service、loopback HTTP route、RBAC integration

## 背景

M8.7a 已把 production adapter candidate 与 commissioning evidence 追加写入 SQLite，并可重算
readiness，但最小集成界面尚无安全读取边界。readiness 会受证据有效期与 actor 换版影响；若浏览器可
提交角色、authority 或历史评估时点，就可能隐藏已过期证据或在停权后继续读取生产接入资料。

## 决策

1. 新增 `GET /api/m8/adapter-candidates/{candidate_authority_id}/readiness`，沿用 loopback Host、bearer
   authentication、`no-store` 和现有安全响应头。
2. bearer credential 仍只解析 actor ID；服务端每次从 operations repository 读取当前 actor receipt，
   只允许 active、in-scope、具备 `MANAGE_DEVICES` 的 `OPERATIONS` actor。
3. API 不接受 `assessed_at` query；评估时点来自构造时显式注入的 UTC clock，非法 clock 输出转为
   typed internal failure。
4. readiness service 从 append-only repository 读取 exact candidate/evidence。API 在评估后再次读取
   当前 actor receipt；读取窗口内停用或换版返回 typed `CONCURRENT_MODIFICATION`。
5. 响应直接使用已注册的 `M8AdapterReadinessAssessmentV1` serialization contract，只返回每类确定性
   最新 evidence receipt；不返回 raw artifact bytes、credential material 或 activation authority。
6. GET 固定只读，不登记 candidate、不提交 evidence、不创建 activation intent、不调用外部 adapter，
   也不产生 Case、通知、纪律处分或生命安全动作。

## 结果

- 运维界面可以看到缺失、失败和过期项，但不能借读取 endpoint 越过 commissioning gate。
- 评估时点与权限均由服务端决定，历史回放需求必须另建有审计的接口，不能伪装成当前 readiness。
- 本切片无需厂商 SDK、网络、GPU、凭据或现场设备，默认离线测试路径保持成立。

## 未选择的方案

- **客户端传入 actor authority**：会让浏览器成为授权事实源。
- **客户端传入 assessed_at**：可选择证据尚未过期的历史时间误导当前状态。
- **安全负责人或领导共享设备管理读取权**：扩大既有闭合角色能力矩阵。
- **返回 raw evidence bytes**：增加敏感工件暴露面，且 readiness 只需内容寻址 receipt。
- **GET 顺便激活 adapter**：把只读评估与生产副作用合并，违反 ADR 0053。

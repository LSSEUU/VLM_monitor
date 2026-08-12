# ADR 0049：M8 运营投影视图按持久化角色裁剪且始终只读

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.6 projection view contract、纯裁剪 workflow、后续 authenticated projection API

## 背景

M8 内部运营投影是由拓扑、设备、传感器样本、案件、通知和完整审计组成的自洽读取切面。它适合作为服务内部事实源，但不能直接把同一份内容返回给领导、安全负责人、学生和运维。角色及其 capability 必须来自当前持久化 actor authority，客户端声明不能改变可见范围；只读总览也不能暗示可执行案件迁移或纪律处分。

## 决策

1. 新增内容寻址的 `M8OperationsProjectionViewV1`，同时绑定当前 actor authority receipt、完整源投影 ID 和裁剪后的可见投影。
2. 安全负责人获得完整运营读取切面；其具体案件动作仍由既有 Case command 的 capability、location scope、source fence 和显式人工确认独立约束。
3. 领导只保留严重或紧急案件，以及这些案件对应的完整案件审计、通知和通知审计；领导不获得审批或案件迁移能力。
4. 运维只保留拓扑、设备/摄像头、传感器来源及最新持久化观察；案件、案件审计、通知和通知审计必须全部为空。
5. 学生不能访问校园运营投影；学生仍通过既有本人案件和消息卡片边界参与说明与申诉。
6. 所有角色视图均固定 `projection_write_permitted=false`、`case_action_permitted=false`、`direct_disciplinary_action_permitted=false`。
7. 裁剪由纯 application workflow 完成，不写 dashboard 表、不修改源投影或任何业务 authority，也不调用网络、GPU 或模型。

## 结果

- 角色越权内容在构造 typed response 前即 fail closed，不能靠前端隐藏字段实现授权。
- 领导不会因总览访问获得审批能力，运维不会接触案件与通知内容，学生不会获得校园级运营数据。
- 视图保留源投影 ID 和当前 actor authority receipt，可审计其数据切面与授权版本。
- 后续 HTTP API 只需解析当前持久化 actor authority，再调用同一纯裁剪 workflow。

## 未选择的方案

- **返回完整投影后由前端隐藏字段**：敏感数据已经越过授权边界。
- **把 role/capability 放进客户端请求**：允许客户端伪造权限，破坏持久化 authority 语义。
- **为每个角色维护可更新 dashboard 表**：复制事实源并引入失效、漂移和额外写入状态。
- **允许投影携带 action endpoint 或处分标志**：混淆只读态势与人类确认的案件工作流。

# ADR 0057：飞书 sandbox 调用前必须从 append-only 状态重算当前授权

- 状态：Accepted
- 日期：2026-08-11
- 影响范围：M8.7 Feishu activation migration、repository、后续 sandbox transport

## 背景

一份激活回执只证明某个历史时点通过了 commissioning 与双人确认。激活后可能出现新的 FAILED/过期
证据、确认人停用或换版、测试收件人撤销等情况；如果 runtime runner 只缓存历史
`SANDBOX_ACTIVE`，就会在授权已失效后继续访问外部平台。另一方面，安全负责人或运维需要不依赖外部
网络的即时 kill switch，且撤销后重新激活必须形成新的连续审计 revision。

## 决策

1. migration 0007 只新增 activation 与 revocation 两类 append-only 表、稳定索引和 no
   update/delete/replace trigger，不修改 M0–M6 或现有 M8 表语义。
2. 激活 commit 在单个 `BEGIN IMMEDIATE` 事务中重新解析已登记 candidate、当前 OPERATIONS 与
   SAFETY_OFFICER、latest-per-kind commissioning evidence、当前通知 target，并验证 exact canonical
   runtime config bytes。任一对象与 intent/config 不一致即 fail closed。
3. 同一 candidate 同时只能有一个未撤销 activation。撤销由当前 OPERATIONS 或 SAFETY_OFFICER 单人
   显式确认即可立即提交；重新激活必须引用已撤销的 prior commit，并使用连续 revision 与新的双人 intent。
4. repository 读取 activation/revocation 时复核 canonical JSON、raw config bytes/hash/size、索引列、历史
   actor/evidence/target authority、repository/storage manifest 和 SQL layout；损坏或缺失整体 fail closed。
5. `get_current_status` 每次在一个稳定只读事务中重新解析当前双人 authority、当前收件人 target，并按
   调用时点重算 commissioning readiness。显式撤销返回 `REVOKED`；任一当前条件变化返回
   `INVALIDATED`；只有全部仍与 activation 精确一致时返回 `SANDBOX_ACTIVE` 和
   `sandbox_external_call_permitted=true`。
6. status 仍固定 `production_external_call_permitted=false`。本切片不读取 secret、不访问网络、不发送
   消息，也不改变 notification 或 Case 状态；未来 transport 必须读取 repository-derived current status，
   不得信任客户端对象或长生命周期缓存。

## 结果

- 历史激活不会覆盖后续安全证据、人员停用或收件人撤销；未显式撤销也能自动 fail closed。
- kill switch 是本地、单人、append-only 动作，不依赖飞书可达性；重新启用仍需要新的双人确认。
- 默认离线 fake 与现有通知状态机保持不变，尚未声称真实发送或送达。

## 未选择的方案

- **只在启动时读取一次 activation**：运行期间权限或证据变化无法生效。
- **撤销也要求双人确认**：会延迟紧急停止，扩大外部调用窗口。
- **直接更新 `active=false`**：破坏 append-only 历史与连续 revision。
- **新增证据后自动写撤销**：把证据提交隐式升级为关键动作；当前设计派生 `INVALIDATED`，但保留人工
  撤销审计。
- **在 activation 事务里发送测试消息**：把本地授权 commit 与不可回滚网络副作用混合。

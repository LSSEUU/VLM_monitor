# ADR 0031：M8 案件关键动作使用版本化人员 authority 与显式人工命令

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8 角色权限、自动建案、运营案件状态、申诉和审计

## 背景

校园运营需要自动把信号组织成待核实案件，也需要安全负责人核实、驳回、补证、结案和处理申诉。
与此同时，领导只看全局，运维只管设备，学生只能处理本人案件；Agent 和视觉模型不能定责或直接
形成处分。如果仅在 API handler 或 UI 中用字符串判断角色，离线工件、后续 adapter 和其他客户端
就可能绕过边界；如果把自动信号直接映射为已确认案件，又会把机器弱信号提升成人工事实。

## 决策

1. M8 新增独立的 `M8ActorAuthorityV1`，固定四角色、三类 scope、active 状态、authority revision、
   identity-provider 引用、匿名 subject binding 和 manifest。capability 完全由角色派生，调用方不能
   自报或扩大。
2. `LEADER` 只有全局、重大事件和审计只读 capability；`OPERATIONS` 只有设备管理与健康查看；
   二者均不能执行案件迁移。`SAFETY_OFFICER` 执行案件动作时必须 active 且覆盖案件地点。
3. `STUDENT` 只有本人案件查看、说明与申诉 capability；申诉命令必须同时证明 actor ID 等于案件
   `subject_actor_id`。图像、face embedding 或跨摄像头轨迹不得提供该绑定。
4. 自动 create command 的唯一初态为 `PENDING_VERIFICATION`，固定需要人工核实且禁止直接纪律
   处分。模拟 source inventory 派生 `SIMULATED INPUT · PENDING VERIFICATION`，不能由客户端改写。
5. 核实、驳回、补证、返回核实、结案、学生申诉和申诉处理采用闭合的 action/source/target/
   reason/capability 矩阵。所有迁移都要求 `explicit_human_confirmation=true`，并固定
   `direct_disciplinary_action_permitted=false`。
6. transition command 绑定源 Case 版本和 authority hash，派生下一版本与内容寻址 command ID。
   Pydantic 负责重算相对版本和 hash；JSON Schema 同时冻结可表达的动作矩阵与 literal 安全边界。
7. `M8OperationalCaseAuditIntentV1` 精确绑定迁移命令、前后状态/版本、actor authority、supporting
   authority inventory 和 audit manifest，但契约对象本身不执行写入。持久化、乐观并发与 actor
   authority 解引用留给 M8.3。

## 结果

- 机器信号最多创建待核实案件，不能静默升级为已确认事实或处分依据。
- 领导、运维、跨地点安全负责人和非案件本人学生在契约层 fail closed。
- API、离线 adapter 和未来消息平台可以消费同一动作矩阵，不需要各自解释自由文本角色。
- M0–M6 Case、Appeal、manifest、schema、审计和回放语义保持不变。

## 未选择的方案

- **让客户端提交 capability 列表**：角色与 capability 可发生 graft，无法形成稳定权限 authority。
- **只在 UI 隐藏按钮**：API、工件重放或其他客户端仍可提交越权动作。
- **让 Agent 自动确认或结案**：违反关键动作必须由有权限用户明确确认并审计的系统公理。
- **把 actor authority 内嵌文档当作仓库事实**：M8.1 仅冻结 wire；M8.3 必须从持久化 authority
  独立解引用并校验版本、active 状态和作用域。

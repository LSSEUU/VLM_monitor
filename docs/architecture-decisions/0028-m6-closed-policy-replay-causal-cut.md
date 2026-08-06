# ADR 0028：M6 CLOSED 策略重放使用独立的完整因果切片

- 状态：Accepted（contract-first authority 已实现，source producer 与执行接入进行中）
- 日期：2026-08-04
- 影响范围：生产 source catalog、alert policy replay、候选 CLOSED Case 与 regression report

## 背景

生产 regression source catalog 只接受带 `final_decision` 的 `CLOSED` baseline；ADR 0027 的 Fast/M4 路由只
重建到 Gate 后的 `READY_FOR_ALERT_POLICY`。手工拼装 catalog 的测试可以越过这条边界，但真实
source-catalog → evaluator-dataset → execution 链不能闭合。直接从 CLOSED Case 倒推 policy 还不充分：
cooldown 的“无历史”也是需要证明的因果事实，不能由 `None` 声明替代；当前 M5 layout 也没有可认证的
immediate-emergency signal root。

## 决策

1. 不修改冻结的 replay-input closure 与 source seal。新增独立
   `M6ReplayLockedAlertPolicyCausalCutAuthority`，把同一只读 snapshot 中的 READY predecessor、相邻 CLOSED
   successor、AlertPolicyAuthority、CASE_CLOSED audit、passing M5 report/root 与 closure 双身份精确绑定。
2. cooldown cut 必须包含 source run、close audit sequence/hash、key，以及 close 之前全部 eligible history 的
   contiguous revision、writer close sequence/hash、writer policy identity 和 canonical cooldown authority。
   count 与 inventory root 由条目重算。
3. `EMPTY_HISTORY` 只允许完整 eligible inventory 为空；`EXACT_PRIOR` 必须等于完整历史最后一项；无 track 的
   `UNTRACKED` 不得携带 key 或历史。只提交 `prior_cooldown=None` 不构成 absence proof。
4. `prior_emergency_delivery` 当前必须为 `None`，并显式记录
   `DISABLED_MISSING_CERTIFIED_SIGNAL_AUTHORITY`。在新增可验证 certified root 前，不开放 emergency 合并重放。
5. source producer 必须在同一个只读 snapshot identity 下解析所有 Case、alert、cooldown 与 audit row，并先验证
   M5 report 为 passing；caller 不能提交汇总 count/root 或用当前 cooldown head 代替 source close 时刻的 head。
6. CLOSED candidate route 必须 contract-first 新增 route/source/observation/write authority 和独立 append-only
   storage；不能复用 0017 的 pre-policy Case 形状，也不能把 policy 作为 0017 后的第二个隐藏 revision。
7. 只有真实 source catalog、evaluator dataset、CLOSED execution Seal 与 baseline/source snapshot 完整同源后，
   才允许组装 `M6RegressionReport`。报告 V1 已支持 `REPLAY_LOCKED`，无需伪造 upgrade inventory。

## 后果

- policy 结果可以由 locked config/manifest 与历史 causal head重新计算，而不是复制 source alert 输出。
- 空 cooldown 历史成为可审计承诺，恢复和重试不会跟随 candidate 运行时的新 cooldown 尾部。
- 当前 emergency 合并路径保持 fail closed；这是既有 M5 authority 能力边界，不是功能降级猜测。
- source producer、additive route 和 storage 尚未完成前，现有 M4 Seal 仍只能表述为 pre-policy 阶段成果。

## 被拒绝的方案

- Seal 后直接生成 report：生产 evaluator 的 CLOSED baseline 与 pre-policy candidate 不同源。
- 仅保存 `prior_cooldown=None`：无法区分真实空历史与漏读/伪造。
- 从当前 cooldown 表头重放：未来 close 会改变历史案件的因果输入。
- 把 replay execution Seal 塞进 upgrade publication V1：其文档种类和 candidate-run-cut 语义已经冻结。


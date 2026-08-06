# ADR 0019：M6 使用版本化语义投影、稳定样本身份与可重算回归门禁

- 状态：Accepted
- 日期：2026-08-03
- 影响范围：M6 replay、回归数据集、`regression.json` 与后续静态报告

## 背景

冻结的 `Case` wire contract 预留了可空 `semantic_case_hash`，但 M0–M5 从未把它作为持久化
权威，也没有定义完整的 Case 语义投影。直接对 `Case.model_dump()` 求 hash 不成立：其中包含
run ID、本机路径、provider latency、成本等运维数据；用递归黑名单删除若干字段又会在未来新增
字段时静默改变 hash 边界。

升级还可能改变 `rule_version`，进而改变 `event_id` 和 `case_id`。若仅按 Case ID 配对，真实的
候选漏检会从分母消失。申诉案件则存在另一种泄漏：若把改判后的当前 Case 同时用作机器 baseline
和 gold truth，candidate 实际上提前拿到了人工答案。

## 决策

1. 不修改 M0–M5 wire schema。M6 新增 `M6CaseReplaySnapshot` wrapper，并以版本化、白名单构造
   的六层语义根表示 Case：`PERCEPTION`、`SCREENING`、`RETRIEVAL`、`HEARING`、`GATE`、
   `POLICY`。
2. `semantic_case_hash` 只由投影版本、完整 manifest、六层语义根和终局语义摘要计算；source
   run/case revision、墙钟、路径、租约、发送回执、token、成本与延迟不参与。
3. baseline/candidate 按显式、匿名且稳定的 `sample_id` 配对，不按可能随升级变化的 Case ID。
   每个样本另绑定内容校验的输入 authority；候选缺失和候选新增都是显式逐样本结果。用于候选
   执行的 `M6RegressionExecutionDatasetSnapshot` 与 evaluator dataset 分离，前者不携带
   membership、baseline 或 gold truth，避免把答案送入候选执行路径。
4. evaluator dataset 同时绑定 source inventory cut、eligibility policy 与 selection inventory
   authority、文档计数和内容根；执行集与 evaluator 条目必须精确一一对应。数据集 membership
   可为 `GOLD + CHALLENGE` 或 `STABILITY + CHALLENGE`，但禁止 `STABILITY + GOLD`。
   完整 M6 数据集的三层均不得为空。
5. gold truth 只接受人工复核、申诉终局或预置金标 authority；机器弱标签没有可用枚举。申诉
   gold 必须把申诉前 `ClosedCaseAppealAuthority` 作为机器 baseline，并同时绑定终局 decision
   authority 与 resolution commit。
6. 每条候选执行必须产生 `M6ReplayExecutionReceipt`，精确绑定命令、盲化 entry、候选 run、
   manifest、候选快照以及 Detection、raw response、embedding 和 tool-result inventory。
   `REPLAY_LOCKED` 还必须记录零 provider 调用并绑定独立 provider trap authority；一次报告只
   接受一个完整、不同于 baseline 的候选 run，不能用复制的 baseline 根冒充重放。
7. `M6RegressionPolicyAuthority` 是命令内容的一部分；机器方向翻转上限在契约层不得高于 5%，
   gold accuracy drop 上限必须为零。5% 边界用整数计数与十进制交叉乘法判定，避免二进制浮点
   漂移；恰好等于阈值通过，严格大于才失败。
8. `regression.json` 嵌入命令、完整 evaluator dataset、逐样本 baseline/candidate snapshot、
   执行回执、结果和人工复核。flip count、gold correct count、首个分歧层、emergency 退化、
   reason code 与最终 disposition 全部重算；序列化的派生声明若与明细不符即拒绝解析。
   必需候选缺失或非终态属于硬失败，并优先于待人工复核状态。
9. baseline 为 emergency 而 candidate 降级时，发布默认阻断。只有绑定精确逐案结果、独立人工
   输入 authority 和 reviewer capability authority 的 approval 才能解除该阻断；拒绝或缺失复核
   均不得发布。
10. `REPLAY_LOCKED` 的任何语义差异均失败；仅 manifest 改变而六层与终局语义相同，必须显式
   分类为 `MANIFEST_ONLY_CHANGE`，不能伪造一个不存在的首个语义分歧层。`REINFER_PINNED` 只产生
   `DIAGNOSTIC_COMPLETE`，不把差异自动称为缺陷；`UPGRADE_REGRESSION` 执行 stability、gold
   与 emergency 三类门禁。
11. 候选执行的 replay input closure 与 evaluator 输出严格分层。closure 只绑定历史 Frame、
    Detection、模型调用、embedding、tool result 和逐会审周期的 retrieval authority：成功周期
    绑定 precedent exposure，降级周期绑定 M4 retrieval receipt 及其类型化原因。历史 application、
    alert、appeal resolution、gold truth 与训练标签不能由该契约表示。application 和 alert 必须
    由候选重新计算，appeal resolution 只在 evaluator 侧参与 gold 判定。
12. `M6ProviderTrapAuthority` 不只覆盖 provider、recovery 与 cache write，还显式统计对当前
    precedent tail 和 training-label tail 的查询。locked receipt 只有在所有计数均为零、且 trap
    的 command、candidate run 和执行组件 manifest 与本次执行精确一致时才成立。

## 后果

- 新 run ID、工作区路径和运维时钟可以变化而不影响 locked semantic hash。
- 首个不同的语义层根可直接定位分歧，不需要事后猜测。
- 候选漏掉整个 Case 仍留在 stability 分母；空 stability/gold 集不能伪装为 0% 通过。
- 候选执行看不到 membership、gold truth 或 baseline；门禁只在候选执行完成后由 evaluator
  dataset 计算。
- 六层根本身必须由下一切片从同一个只读 SQLite 快照及完整 authority closure 重算；调用方提供
  的 digest 不能直接成为可信权威。
- locked replay 必须显式绑定历史模型响应、embedding、tool result 和判例 exposure causal cut，
  不能依赖包含新 run/manifest 的普通 cache lookup，也不能查询当前判例尾部。
- exposure cut 使用 `(source run, source Case, hearing session, cycle index, cycle scope)` 的强类型
  逐周期绑定并保持从 1 开始的连续唯一顺序；repository 仍须在同一个只读快照中证明成功 exposure
  或降级 receipt 与 M4 retrieval cycle 是精确集合，而不是信任 closure 自述。
- 六层 root 不重复 hash `config_sha256`、组件 manifest ID、authority ID 等 opaque provenance；完整
  manifest 由 snapshot 顶层单独绑定。仅 provenance 改变而 policy 数值、embedding 向量、候选
  处置/评分/排序及输出均未改变时，必须保留相同六层 root，归入 manifest-only 变化。
- source cut、selection inventory、policy、gold decision、申诉 commit、artifact inventory、
  provider trap、人工输入与 reviewer capability 的引用都必须由 repository 层独立解引用验证；
  契约存在这些字段不等于引用内容已经可信。

## 被拒绝的方案

- 把冻结的 `Case.semantic_case_hash` 改成 required/computed：会破坏 M0–M5 wire 兼容性。
- 对完整 Case 做递归字段黑名单：未来字段可能被静默纳入或错误排除，无法审计投影边界。
- 按 `case_id` inner join baseline/candidate：会漏掉 ID 改变、候选缺失和新增 Case。
- 把 M5 COCO `GOLD_SET` 当作 M6 案件 gold set：训练裁切质量不等于案件人工真值。
- 用改判后的 Case 同时充当 appeal baseline 与 truth：形成答案泄漏和循环论证。
- 用预先填好的汇总数字生成报告：无法证明统计来自完整逐案 inventory。
- 把 emergency 退化仅写成 warning：不满足人工复核的 fail-closed 发布边界。

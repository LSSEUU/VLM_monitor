# ADR 0020：M6 升级回归使用先冻结、只追加、物理可解引用的执行账本

- 状态：Accepted
- 日期：2026-08-03
- 影响范围：`UPGRADE_REGRESSION` 候选执行、SQLite 审计链、物理工件引用与 `regression.json` 发布门禁

## 背景

`M6UpgradeCandidateOutputInventoryAuthority` 能证明候选输出、执行回执和逐样本工件清单在契约内彼此一致，但纯 JSON 一致性不能证明三件事：执行范围确实在首个样本前冻结；样本确实逐条追加而不是事后整体重写；调用方自报的 Frame、Detection、模型响应或工具结果确实存在于受信存储且字节摘要正确。

如果允许账本和候选输出共同伪造同一组摘要，终端 join 仍会通过。若只把 seal 外键指向 `runs` 的可变审计头，则 seal 又会意外阻止后续合法审计。旧 SQLite 触发器还只保证 run head 单调递增，不能阻止它指向不存在的 audit row。

## 决策

1. 每次升级回归使用独立、全新的 candidate run。`M6UpgradeExecutionScopeAuthority` 必须在审计 genesis 上持久化，并一次性冻结 blinded execution dataset、command、完整 candidate manifest、完整 AppConfig、执行组件及其 canonical 字节身份。scope 之后不可替换、更新或删除。
2. candidate manifest 的模型组件集合精确封闭为规范要求的九项。VLM 与 embedding 使用本地 in-process fake；detector、tracker 与 pose 使用 precomputed；隐藏的额外 provider、网络 provider 或 GPU provider全部拒绝。
3. 每个 blinded sample 使用一个 `BEGIN IMMEDIATE` 事务，按 physical refs → ordered links → sample record 的顺序写入。sample parent 最后写入；已存在 sample 后禁止补 link；seal 后禁止写入任何 scope/ref/link/sample。
4. 物理引用使用静态 source/kind、usage 和 container 矩阵。Detection 必须引用同一样本内的 Frame。SQLite 负责结构约束；受信 typed resolver 负责读取实际 M2–M5 authority、解析 canonical document、核对 raw/content SHA-256 与 size。没有 resolver 时默认失败，调用方自报摘要不能成为权威。
5. append 重试只接受逐字节完全相同的已持久化记录。禁止 `INSERT OR REPLACE`、`INSERT OR IGNORE` 和宽松合并。故障注入点必须证明 refs、links、sample 与 seal 在 crash 后要么完整提交，要么完整回滚。
6. seal 不接受调用方提供的对象，而是从持久化 scope、完整连续 sample prefix、links、refs、当前 Case 集和 seal 时的 run audit head 重建。seal 插入时验证 final head 是当前头并对应不可变 audit entry，但不建立会冻结 `runs` 后续合法推进的可变头外键。
7. migration 0010 在安装前验证已有 run/audit 链的数量、连续序列、前驱和当前 head；安装后要求新 run 从 genesis 创建、audit entry 精确扩展当前 head、run head 只能推进到刚写入的对应 entry。
8. terminal candidate inventory 必须 join 独立 run cut 与 sealed ledger，包括完整 Case 数、逐样本 record ID、物理工件 ID/字节、cache usage 和 final audit head。scope、ledger 与 terminal inventory 都按实际 canonical 字节执行 256 MiB fail-closed 上限。

## 后果

- 事后整体重建一个内部自洽的候选 JSON 不再等价于真实执行。
- candidate 执行看不到 evaluator membership、gold truth 或 baseline answer；evaluator 只能在 seal 后读取输出。
- 同一个不可变物理工件可以被多个样本消费，但同一物理键不能声明冲突字节。
- 旧 M0–M5 wire contract 和业务状态机不变；0010 只增加审计结构加固与 M6 专用 authority。
- 物理类型若在旧 schema 中没有可验证的 canonical/raw 字节来源，resolver 必须返回 typed failure，直到新增明确契约；不得用自由文本、近似字段或调用方摘要猜测。

## 被拒绝的方案

- 只比较 output inventory 与 ledger 中相同的自报摘要：两者可以共同伪造。
- 在报告阶段一次性写完整 ledger：无法证明 scope 先冻结或样本逐条执行。
- 允许从已有 candidate run 的非 genesis head 开始：无法无歧义地区分执行前 Case 与本次候选 Case。
- 把 seal 永久外键绑定到 `runs` 当前 head：会冻结 seal 后的合法审计。
- 用 polymorphic 普通外键替代 typed resolver：无法统一表达 raw 文件字节、canonical JSON、cache 与跨里程碑复合 authority。

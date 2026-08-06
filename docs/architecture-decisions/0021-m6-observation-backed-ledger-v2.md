# ADR 0021：M6 V2 使用受信观测、确定验证器与崩溃后精确承诺

- 状态：Accepted
- 日期：2026-08-03
- 影响范围：`UPGRADE_REGRESSION` 候选执行、物理工件闭包、SQLite 恢复、V2 ledger seal 与 terminal inventory

## 背景

ADR 0020 的 V1 ledger 要求调用者同时提交 sample record 和一个逐次传入的 artifact verifier。这个接口能验证一组引用，却不能证明 record 中的引用就是执行器真实消费或产生的完整集合：恶意或错误的调用者可以同时遗漏 observation、record 和 echo verifier 中的同一项。单个 `BEGIN IMMEDIATE` 事务也不能关闭另一个崩溃窗口：物理字节已经验证、record 已经构造，但事务尚未持久化时，恢复过程没有权威事实可证明应该重试哪一组精确 record bytes。

同时，M6 已经发布 V1 record、seal、inventory 和它们的 hash domain。修补 V1 的字段或哈希会把旧数据重新解释为一种从未承诺过的更强保证，因此必须使用独立版本完成升级。

## 决策

1. 保留 V1 wire schema、hash domain 和 SQLite 默认语义。新增 `M6UpgradeSampleExecutionRecordV2`、`M6UpgradeExecutionLedgerSealV2` 与 `M6UpgradeCandidateOutputInventoryAuthorityV2`；V2 record 的身份显式绑定 `observation_authority_id`，V1 与 V2 不得在同一个 run 中混用。SQLite 另存 append-only scope protocol marker，使空 scope、pending observation、pending commitment、已写 sample 和已 seal 的每个阶段都能在读取大 JSON 前确定走 V1 还是 V2；迁移遇到 observation 与 V1 sample/seal 混存时拒绝猜测版本。
2. 固定候选执行器在每个样本结束时生成完整、类型化的 `M6UpgradeSampleExecutionObservationAuthority`。它只记录运行期身份与使用事实，不允许携带或声明 digest、size、container 或物理引用。observation 使用独立事务先于 ledger 持久化，且每个 run 最多存在一个尚未写入 ledger 的 pending observation。
3. 非模型 observation 精确记录 `(source, kind, artifact_id, usage)`；模型 observation 精确记录 request、layer、role、attempt、result kind 与本次是否调用 provider。`provider_invoked` 和 `NO_CASE` 的 Frame/Detection 完整清单属于固定执行器 instrumentation 的受信事实，不允许由完成后的 cache 或自由文本反推。
4. whole-sample verifier 只能从 observation 中取得身份。digest、size、container、canonical document、raw response 和 pixel content 必须从 M2–M5 durable authority 及固定 Pixel/Raw verifier 独立解析。21 条合法 source/kind 路由使用精确集合，缺失、额外、重复、错误 usage 或同 physical key 冲突全部 fail closed。
5. 在第一次读取 Pixel 或 Raw bytes 前完成全样本两阶段 preflight。单样本最多 20,000 个物理引用，所有引用的物理字节总和最多 256 MiB；V2 record canonical document 最多 64 MiB。任何局部 resolver 的预算不得替代全样本预算。
6. 公开的 V2 appender 只接受 candidate run ID 与 execution scope ID。调用者不能提交 record、physical refs、hash、size、ordinal 或逐次 verifier。组合根在构造时固定注入 whole-sample verifier、Pixel verifier 与 M3/M4 Raw verifier；V1 `append_sample(record, verifier)` 仅保留兼容读取和历史测试，不进入 V2 候选执行路径。
7. 物理验证完成并构造 canonical V2 record 后，先用独立事务写入 `M6UpgradePendingSampleCommitmentAuthority`。commitment 完整内嵌 record，绑定 scope、entry、sequence、observation、record ID 以及 record canonical document SHA-256/size。首次成功 append 胜出；同 key 只有 byte-for-byte 相同的 canonical authority 可以幂等返回。首次写入前必须连同已提交 record 前缀验证累计 link 上限、physical key 与 artifact ref ID 一致性以及 candidate Case 全局唯一性；scope 加 record 前缀、observation inventory、commitment inventory 与 commitment 内嵌 record inventory 分别受 256 MiB 总预算约束。repository 与 SQLite trigger 都不得持久化一个已知永远无法写入 ledger 的 commitment。
8. commitment 的恢复保证从首次成功持久化后开始。持久化前崩溃没有可恢复的精确 record 承诺；持久化后重试必须重新解析 authority 与物理字节，并且只能把 commitment 中的同一 V2 record 写入 ledger。SQLite trigger 同时验证 observation、commitment、links 与 record 的一一对应，不能以逻辑等价但字节不同的 record 替换。observation、commitment 或 ledger 的任何幂等成功返回前，都必须重新验证有界、连续且互相闭合的完整 S/O/C 前缀；不能因为目标行字节相同而掩盖更早的缺失、篡改或链断裂。
9. ledger append 使用两个连接形成受控快照：A 先 `BEGIN IMMEDIATE`，再通过不可写、不可控制事务的窄 selector capability 确定唯一 pending 状态；selector 关闭后，B 才以 `mode=ro`、`query_only=ON`、`trusted_schema=OFF` 开启 read transaction，读取同一已提交 authority cut 并完成验证。B 关闭后才开放 A 的窄 writer capability 写 refs、links、V2 record；调用方拿不到原始 A connection/cursor connection，也不能执行 commit、rollback、savepoint、attach、DDL 或可写 PRAGMA，最终 commit/rollback 只属于 read-cut owner。cut、phase context、capability 与 cursor 都是不可复制且只直接持有 opaque token 的显式句柄，不使用会保留 owner locals 的 generator context manager。普通异常在私有 owner/broker bridge 返回闭合 failure outcome 后才由公开 facade 重新发布；capability 拒绝、存储异常、清理失败和遗弃 context 都是 sticky fail-closed，不能捕获后继续提交。live WAL 禁止使用 `immutable=1`。
10. V2 seal 只接受 observation、commitment 和 V2 sample 数量及顺序完全相等、没有 pending/orphan authority 的完整链。terminal V2 inventory 再把 observation、ledger record、candidate output、model-call runtime facts、artifact identity 与 usage 做双向精确 join；任一共同遗漏不能只靠自洽 JSON 通过。
11. SQLite 对所有已规范化的 scope/ref/link/sample/seal 列执行 fail-closed JSON 投影校验；谓词统一使用 `(projection) IS NOT TRUE`，不能让 JSON 缺键产生的 SQL `NULL` 绕过拒绝。0012 在安装新触发器前以相同矩阵检查既有 V1 行，异常历史使迁移原子失败。scope/ref/link 使用独立完整投影触发器，sample/seal 的公共投影位于 `(v1 OR v2)` 分支之外；合法的显式 `container_id: null` 与 `candidate_case: null` 仍保留原语义。

## 保证边界

- SQLite writer lock 不能锁住数据库外部的 Pixel/Raw 文件。当前保证是“验证时字节存在且匹配，并在 ledger commit 前再次验证”；若将来要求外部对象在验证至 commit 间原子存在，必须新增文件 lease、不可变对象存储或打开句柄 fence，不能把当前行为描述为该保证。
- `provider_invoked` 无法从调用结束后的 response/cache 表可靠反推；它必须由固定 executor instrumentation 记录，再由 cache usage 和完整模型闭包交叉验证。
- `NO_CASE` 没有可供事后枚举的 Case graph，其运行期 Frame/Detection 完整性依赖同一个固定 instrumentation。observation repository 只是 append-only storage，不是允许外部调用者自报事实的公开真相入口。
- commitment 不能恢复首次成功持久化之前丢失的内存状态，也不得声称能做到这一点。
- SQLite 触发器负责规范化列、协议状态和集合闭包，不在 SQL 中复制完整 Pydantic/LCJ-1 解释器或密码学身份计算。完整嵌套模型、canonical bytes、computed claims 与 SHA-256 仍由 repository codec 在写前和每次读取时验证；直接持有数据库文件并绕过 repository 的任意 SQL 写入不是受支持的公开写入接口。
- sealed read-cut 是 supported API、公开对象直接引用与 typed traceback locals 的进程内封装，不是同进程恶意 Python 的安全沙箱。主动读取模块私有全局 registry、附加调试器或任意遍历进程内存不在本 ADR 的保证内；若该威胁进入范围，必须把 SQLite authority owner 移入隔离进程。

## 后果

- V2 执行路径不再存在 echo verifier 注入点；record 的内容和顺序由数据库状态、pending observation 与固定 verifier 推导。
- observation、commitment 和 ledger 使用三个独立、可恢复的状态转换。每个阶段失败都保留一个明确的 durable restart point，不会留下半组 refs/links/sample。
- V1 数据可以原样升级并继续按 V1 读取；一旦某个 run 写入 V2 observation，该 run 不能回退为 V1 sample 或 V1 seal。
- 物理闭包验证的代价高于只检查摘要，但默认实现仍完全离线、无需 GPU 或网络，且有显式数量与字节上限。

## 被拒绝的方案

- 修改 V1 record 或 seal 的 hash 输入：破坏已经发布的身份语义。
- 继续让调用者提交 record 并逐次注入 verifier：允许 record 与 verifier 共同遗漏同一事实。
- 只保存 observation digest：恢复时无法证明完整 observation 内容或精确 runtime facts。
- 在验证后直接开启 ledger 事务而不写 commitment：崩溃后无法区分字节漂移与原 record。
- 只在首次构造 record 时读取外部字节：commitment 后的字节漂移可能在重试时被静默接受。
- 在 live WAL 上使用 `immutable=1`：可能忽略 WAL 中已经提交的 authority。

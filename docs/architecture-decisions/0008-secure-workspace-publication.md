# ADR 0008：安全工作区解析与两阶段工件发布

- 状态：Accepted
- 日期：2026-07-27

## 决策

M2 将配置、数据库或模型提供的相对路径视为不可信输入。威胁范围包括路径穿越、绝对路径、
UNC/URI、Windows 设备名和 ADS、symlink、junction、其他 reparse point、hardlink、非常规
文件，以及在检查和打开之间替换目录项的 TOCTOU。攻击者可以控制工作区中的目录项并与
进程并发操作，但不假设攻击者已取得当前进程权限、修改程序代码或控制操作系统内核。

所有工件操作通过唯一的 `SecureWorkspace` adapter；其他模块不得把 `local_path` 与
`workspace` 自行拼接后打开。配置和 contract 层先要求规范的相对 POSIX 路径并拒绝
`..`、反斜线、绝对路径、UNC、URI、控制字符、Windows 保留设备名、尾随点/空格和 ADS。
物理文件层仍必须执行以下检查，不能把 lexical 校验视为 containment 证明。

SQLite 是这一规则的受控例外：标准库 SQLite 必须接收数据库路径，不能消费
`SecureWorkspace` 已打开的普通文件 handle。因此可写主库统一通过专用
`SQLiteAuthorityGuard`，数据库名固定为 `labcourt.sqlite3`；它复用本 ADR 的父目录、
reparse、regular-file、single-link、identity 和最终路径原则，并在连接前后持有/复核锚点。
repository 使用 `mode=rw` 且永不创建缺失库；migration 先以 exclusive owner-only 文件创建
原语建立主库，再让 SQLite 打开。`-wal`、`-shm` 同样检查，rollback journal 存在时 fail
closed。它不能把路径式 SQLite 伪装成 handle/VFS 式 SQLite；同权限完美 ABA 的残余边界以
ADR 0005 为准。

工作区根目录在进程启动时解析并打开为信任锚。默认拒绝根本身为 symlink、junction 或
reparse point；需要使用此类部署路径时必须改用真实目标目录作为配置根。工作区下任何
segment 只要是 link/reparse point 就一律拒绝，即使它最终仍指向工作区内部。所有媒体和
状态文件必须是 regular file 且 link count 为 1；M2 不使用 hardlink 或 symlink 去重。

POSIX backend：

- 持有以 `O_DIRECTORY | O_CLOEXEC` 打开的根 directory fd；
- 逐 segment 使用相对 dir-fd 的 `openat` 和 `O_NOFOLLOW`；
- 目录以 `O_DIRECTORY` 打开，leaf 以需要的最小权限打开；
- 对已打开 handle 使用 `fstat` 核验类型、device/inode、link count 和大小；
- 后续读取、hash、解码和写入都使用同一 handle。

Windows backend 不依赖不存在的 `O_NOFOLLOW`，使用 Python 标准库 `ctypes` 调用 Win32：

- 逐 segment 用 `CreateFileW` 和 `FILE_FLAG_OPEN_REPARSE_POINT` 打开；目录同时使用
  `FILE_FLAG_BACKUP_SEMANTICS`；
- 用 handle 属性拒绝 `FILE_ATTRIBUTE_REPARSE_POINT` 和非常规文件；
- 用 `GetFinalPathNameByHandleW` 核验最终路径位于已打开根的同一 volume 和目录边界；
- 用 `BY_HANDLE_FILE_INFORMATION` 核验 volume/file identity 与 link count；
- 创建临时文件使用 `CREATE_NEW`，已存在目标从不被无条件覆盖。

在任一平台，如果当前运行环境无法建立上述 handle 级保证，操作必须以 typed
`PathBoundaryViolation` 失败，不得退化成 `Path.resolve()` 后继续。异常、API、日志和 audit
只记录受控相对引用和 reason code，不输出主机绝对路径。

读操作顺序固定为：安全打开 handle、核验最终目标与 identity、核验大小上限、从同一 handle
流式读取/hash、从同一 handle 解码，再比较预期 hash 与尺寸。检查后不得关闭并按路径重开。

EvidencePack 的文件到数据库发布采用以下两阶段协议：

1. 在目标 run 的同一文件系统下创建 `.staging/<opaque-operation-id>/`，目录与文件只允许
   当前进程身份访问；
2. 将隐私变换后的媒体与 JSON 写入 `CREATE_NEW` 临时文件，flush、fsync，并在原 handle 上
   校验类型、尺寸、pixel hash 与文件 hash；
3. 对 staging 映射执行完整 closure，计算内容寻址目标名；
4. 在再次核验父目录 handle 后把对象原子发布到最终位置；若目标已经存在，仅在安全打开后
   所有 hash 相等时视为幂等成功，任何不一致都失败且不覆盖；
5. 安全打开最终对象并再次核验 containment、identity 和 hash；
6. 最终文件全部就绪后，才在 SQLite 事务中写 media、pack、case version 与 audit；
7. 数据库提交后，从数据库生成 JSON/JSONL 投影。

发布前崩溃只留下 staging；文件发布后、数据库提交前崩溃可能留下内容寻址 orphan，但不会
产生数据库指向不存在文件的已提交记录。启动恢复必须严格先恢复 SQLite 中的 retention/PURGING
状态，该阶段成功返回后才进入 orphan 恢复。orphan 扫描只覆盖指定 run 的固定 `.staging` 与
内容寻址 `frames` 目录，两个区域分别使用有界预算；安全打开每个候选，检查数据库反向引用和
最小年龄后，将未引用的 staged/final media 移到受控隔离区，不采用或就地删除。

空 staging 清理是唯一个不经隔离的恢复特例：只允许精确匹配已知操作目录形状、安全复核为空且
修改时间早于最小年龄截止点的目录，并只对该精确目录执行非递归删除。年龄未到、形状未知、
非空或检查期间变化的对象必须保留或隔离并返回 typed reason。禁止对计算路径、workspace 根或
未验证目录执行递归删除。

retention 清除使用可恢复的三步状态机：

1. SQLite 事务检查案件、申诉、gold/challenge、训练与人工 legal hold，符合条件时把媒体
   标记为 `PURGING` 并写清除意图审计；
2. 安全打开并核验媒体，然后原子移动到同卷受控 `.trash/<opaque-id>`；
3. SQLite 事务把状态改为 `PURGED_BY_RETENTION`、将相对路径置为 null、保留不可逆 hash，
   并追加完成审计；随后删除 trash 中的已验证文件。

启动恢复按数据库状态与两个受控位置完成或回滚 `PURGING`。处于 `PURGING` 的媒体禁止提供
给裁决或模型。任何 active hold 或仍需像素的引用都阻止普通清除，并在 PurgeReport 中给出
typed retained reason。

retention 最后对 trash 中已验证文件执行 unlink，其安全承诺是该文件系统路径不再可达，而不是
物理介质擦除证明。SSD wear leveling/TRIM、文件系统与设备缓存、快照或备份都可能使底层字节在
未知时间内继续存在；需要可证明擦除的部署必须使用组织级加密销毁或介质销毁流程，超出 M2。

## 理由

字符串规范化和 `Path.resolve()` 只能发现部分静态逃逸，不能阻止 Windows junction、reparse
point、hardlink 或并发目录替换。使用 handle 作为读取与验证对象，并先发布可验证文件、后
提交数据库，可以在本地文件系统与 SQLite 无共同事务的前提下保持“已提交状态不主动引用
未发布文件”，同时让所有崩溃中间态可精确恢复。

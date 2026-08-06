# ADR 0012：整代原子投影与单调 current 指针

- 状态：Accepted
- 日期：2026-07-28
- 修订：取代 ADR 0005 中“逐个原子替换固定投影文件即可代表一次完整重建”的部分；
  SQLite 权威与提交后投影原则不变。

## 决策

JSON 投影不再把 `<run_id>/events.jsonl`、`audit.jsonl`、`cases/` 与 `packs/`
这组固定路径视为可信 current。一次重建生成以下不可变、内容寻址的完整代：

```text
<run_id>/projections/
├── .publish.lock
├── current.json
└── generations/<generation_id>/
    ├── events.jsonl
    ├── audit.jsonl
    ├── cases/<case_id>.json
    ├── packs/<pack_id>.json
    └── manifest-<manifest_bytes_sha256>.json
```

generation manifest 绑定 `run_id`、SQLite audit head sequence/hash，以及每个投影的受控类型、
语义 ID、代内相对路径、SHA-256 和大小。`generation_id` 是上述完整闭包的计算身份；manifest
文件名再绑定 manifest 的实际 canonical bytes。`current.json` 绑定同一 run/audit head、
generation ID、manifest 相对路径/hash/大小，并含不可伪造的计算 `pointer_id`。所有三个 contract
都只接受 LCJ-1 canonical JSON；本决策不改变既有 Case、EvidencePack、Verdict 或 M0-M3 schema
的 wire/hash。

projector 先在 current 之外 create-or-exact-verify 全部内容寻址文件和 manifest。重放同一代
逐字节幂等；同一路径出现不同内容、link/reparse/path swap 或额外代内成员时 fail closed。
所有已知 authority 大小的既有文件读取都以该精确大小为上限；`current.json` 使用独立的
4 KiB 固定上限。超长占位文件在 JSON 解析或完整物化前被拒绝，不能借全局投影上限放大内存消耗。
只有完整文件闭包、manifest 和双向 inventory 验证通过后，才可竞争发布 current。

`<run_id>/projections/.publish.lock` 是 generation 目录外的持久 owner-only、regular、single-link
锁文件，不进入 generation inventory。POSIX 使用 handle-anchored `flock`，Windows 使用经最终
路径、reparse、卷、link count 与 owner-only 检查的文件 handle 上的 `LockFileEx`。锁由内核
随 handle/进程终止自动释放。内容寻址文件在锁外物化；锁内重新验证完整代，重新读取 current，
执行单调 compare-and-swap 规则，再原子替换 current 并做提交后复核：

- 既有 current 的 audit sequence 更大时，旧候选不得发布；
- sequence 相同但 audit hash 不同时，视为完整性冲突；
- 同一 pointer 重放直接验证后成功；
- 较新的、完整的 audit head 可以替换较旧 current。

原子替换 current 是唯一提交点。提交点前的任何失败保留旧 current，首次失败不产生虚假
current。提交点后的普通“回执丢失”若重新读取到 exact pointer 与完整 generation，按成功
处理而不是错误报告 `PENDING_REBUILD`；`KeyboardInterrupt`/`SystemExit` 等进程控制异常不被
吞掉，后续重放通过 current 识别已经提交的代。

ArtifactValidator 只从 `current.json` 解析可信投影，验证 pointer → manifest → 文件闭包和
代内目录的双向 inventory，并与只读 SQLite snapshot 重新生成的期望 bytes 对比。目录 inventory
在正文读取前后各验证一次；读取期间出现的缺失、额外或不安全成员会使整代验证失败。旧固定布局
以及未被 current 引用的完整或半成品 generation 都不属于可信 current，不能让验证器误判；
它们可以由后续受控清理回收，但不在本里程碑自动删除。

## 理由

逐文件 `replace` 只能保证单个文件没有半行，不能保证 events、audit、cases 与 packs 同时来自
同一 authority head。内容寻址完整代把所有易变写入移出可见提交点，最后只原子替换一个小型
pointer，因而进程崩溃时可信消费者只会看到上一完整代或下一完整代。发布锁内的单调 CAS 还
阻止两个并发 snapshot 以“旧写者晚提交”的次序把 current 倒退。

## 剩余边界

未被 current 引用的半成品代可能占用磁盘；它们不是可信工件。清理必须在后续维护切片中按
current 引用、年龄、预算和 SecureWorkspace 规则实现，不能用递归删除猜测目标。与 SQLite
类似，同权限攻击者在验证检查之间实施完美 ABA 仍需 custom filesystem/VFS 或操作系统快照
才能彻底排除；实现与报告不宣称超出该边界。

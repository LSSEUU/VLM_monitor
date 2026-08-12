# ADR 0048：M8 运营投影使用有界乐观稳定读取

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.6 current Case/sample/notification scans、projection service、SQLite readers

## 背景

M8 的拓扑、来源目录、传感器样本、案件和通知分别由追加式仓库管理。若投影依次读取这些仓库而不设置一致性
栅栏，读取期间发生的目录换版、案件迁移或通知回复可能产生混合切面。为投影新增可更新 dashboard 表又会复制
业务事实并引入漂移。

## 决策

1. operations、sensor 和 notification repository 增加只读、有界、稳定排序的 current inventory 方法；查询使用
   latest-per-identity 语义并逐条执行原有 canonical receipt/index/raw 完整性校验。
2. 每个完整扫描查询 `limit + 1`。超出投影硬上限时抛 typed budget failure，不返回看似完整的截断清单。
3. projection service 第一次读取 current topology/catalog、Case、latest sample、notification 及所选对象完整 audit；
   完成后再次读取所有 current receipt inventories 作为 optimistic fence。
4. 只有前后 topology/catalog receipt 和 Case/sample/notification receipt inventories 完全相同时才构建投影；读取
   期间换版最多重试三次，仍不稳定则返回 typed concurrent modification。
5. catalog 换版后，Case 继续保留原创建目录证据；只要地点/来源仍存在即可进入新投影。旧 catalog 的 latest
   sample 不提升为当前目录观察，source 降级显示 `NO_PERSISTED_SAMPLE`，直到当前目录产生新样本。
6. reader 不写 projection table，不修改任何 Case/notification/sample，也不读取墙钟或调用网络/model。

## 结果

- 页面获得一个自洽的当前 receipt cut，而不是多个读取时点的拼接结果。
- 重启不需要恢复派生表；投影可随时从 authority repositories 重建。
- 数据量超界、raw 损坏、断链或连续并发更新均 fail closed，不静默截断或展示部分数据。
- 后续 RBAC API 可在同一完整内部投影上进行角色裁剪。

## 未选择的方案

- **跨仓库无栅栏读取**：可能组合互不兼容的 current authority。
- **可更新 dashboard cache 表**：成为第二套事实来源并需要复杂失效协议。
- **超过 limit 后截断**：会把不完整列表伪装成全局总览。
- **长时间全局写锁**：阻塞案件与通知工作流，不适合读取投影。

# ADR 0032：M8 传感器使用 typed additive authority 与确定性离线模拟端口

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8 传感器来源、样本、raw signal、风险候选、adapter 与后续持久化/API

## 背景

校园运营需要烟雾、温度、可燃/有毒气体、门磁、漏水和紧急按钮输入。M0 `SafetySignal` 是已经冻结
的案件核心 wire，不能加入设备、时间基准、raw signal 或 manifest 字段。直接使用自由文本
`type/unit/value` 会让 adapter 猜测单位；使用本机墙钟驱动模拟会破坏离线重放；只返回结构化 sample
而不保留 raw bytes 则无法证明输入完整性。模拟烟雾演示还容易被误解成真实消防检测或自动处置。

## 决策

1. 不修改 M0 `SafetySignal`。M8 新增 sensor sample、adapter capability、poll request/result、simulation
   scenario、risk policy 和 risk assessment authority，后续通过明确转换引用冻结核心。
2. 七类 sensor 使用闭合枚举。烟雾、门磁、漏水、紧急按钮使用 strict boolean；温度、可燃气体和
   有毒气体使用整数定点 `MILLI_CELSIUS / MILLI_PERCENT_LFL / MILLI_PPM`，不接受 float 或文本单位。
3. sample 嵌入完整 M8 source authority，并绑定 catalog、source sequence、互斥的 UTC device time 或
   simulation tick、quality、raw signal relative ref/byte hash、adapter input authority 和 manifest。
4. adapter capability 固定 source mode/type、batch/timeout、network/offline、raw reference 与 replay
   能力。poll request 必须与 capability、source adapter 和 manifest 精确一致；result 绑定稳定 sample
   inventory。未知 replay/raw 或 source/capability graft 产生 typed failure，不吞异常。
5. 默认 simulator 只消费冻结 scenario，不访问网络/GPU，不 sleep，不读取墙钟。相同 request ID 返回
   相同内存缓存结果；raw JSON 可回读并以普通字节 SHA-256 验证。持久化 cache/raw 留给 M8.3。
6. 风险规则是独立版本化 typed policy，不从知识库文档或自由文本解析。quality 非 `GOOD` 的 sample
   不匹配规则；无匹配时降为 `REMINDER`。
7. 默认 smoke demo 从 inactive 变为 active，active 匹配 `EMERGENCY` 演示规则，但 assessment 只能
   建议待核实案件，并固定需要人工核实、禁止生命安全联动、禁止认证消防声明和禁止直接纪律处分。

## 结果

- 真实 adapter、离线 simulator、持久化仓库和 API 可以共享同一 typed wire，不需要猜测单位。
- 离线演示与重放不依赖机器速度或当前时间；相同输入、manifest 和 request 得到相同 authority。
- 每个 sample 都能追到 raw bytes 引用及 hash，模拟来源标签不会在风险评估中丢失。
- M0–M6 schema、manifest、Case、SafetySignal、审计和回放身份保持不变。

## 未选择的方案

- **扩展 M0 `SafetySignal`**：会改变冻结 wire 和历史回放身份。
- **用 float 加自由文本单位**：存在单位误解、非有限值和跨实现序列化差异。
- **用真实时间 sleep 模拟实时流**：测试慢且不可重放；simulation tick 已能表达演示顺序。
- **模拟烟雾直接触发消防/处分动作**：模拟输入不具备认证与定责 authority。
- **本切片直接加入 SQLite/API**：会把尚未冻结的样本和端口语义固化到存储，扩大回滚风险。

# LabCourt Coding Agent Rules

项目基线是 `docs/request.md`。可执行规范是：

- `docs/spec/labcourt-vibe-coding-spec.md`：冻结的 M0–M6 核心。
- `docs/spec/labcourt-campus-operations-spec.md`：不改变 M0–M6 的增量 M8。

1. 开始工作前阅读适用规范、当前代码和相关测试；一次只实现一个可验证切片，不跳过前置里程碑。
2. 契约优先：先改 Pydantic models、生成 schemas 和 contract tests，再改业务行为、适配器、CLI 或 API。
3. `domain/` 只能依赖纯规则和契约，不导入数据库、HTTP、OpenCV、Torch 或云 SDK。
4. 默认路径必须离线、无 GPU、无真实外部账户；外部模型调用必须有 fake、timeout、cache、manifest 和 raw response reference。
5. 不用宽松自由文本解析猜测结构化输出；VLM 不是客观计数、时长、身份、坐标或证据存在性的 authority。
6. 保持 frame index、确定性 ID、evidence closure、manifest、`STRICT_CAUSAL` 和 SQLite authority 语义；未来合规不得抹去历史违规。
7. 角色、scope、capability 必须由服务端从持久化 authority 解引用；关键迁移需要版本/hash、审计和明确人工确认。
8. 禁止人脸识别、face embedding、跨摄像头 ReID；机器弱标签不是 ground truth；系统不得直接执行纪律处分。
9. 不吞异常：将失败转换为 typed exit、backlog 或 case state。不得在日志、fixture、提交中放 API key、secret、bearer token 或未脱敏真实人员图像。
10. 变更应说明 contract、状态迁移、场景覆盖和 manifest 影响；必要时记录 ADR。运行最小相关测试及质量门禁，不声称未经评估的准确率、延迟、成本或合规结果。

不要加载、调用或遵循名称以 `superpowers:` 开头的 skill。

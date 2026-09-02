# Changelog

本文件按 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 记录可证实的版本和工作区变更。未列出的能力不代表已交付。

## [Unreleased] — repository cleanup

### Changed

- 收束 README、Agent 规则和架构/契约/安全文档，统一指向当前 M0–M6 frozen core 与 additive M8 规范。
- 将历史 milestones、progress 和 superseded spec 归档到 `docs/archive/`；将设计参考集中到 `docs/design-reference/`。
- 增加统一 Windows `labcourt.cmd` 入口和文档导航；兼容性与行为影响仍以当前工作区验证为准。

### Not released

- 本节描述的是未发布的清理工作，不是新的产品版本，也不宣称新增模型准确率、生产部署或真实外部送达能力。

## [0.2.0-alpha1] — 2026-08-10

这是工程候选版本，来源为 `docs/archive/progress/v0.2-alpha1-release-notes.md`，不是生产或纪律处分发布。

### Added

- 受控本地 MP4 到静态运营报告的完整离线路径：本地感知、隐私检查证据、确定性程序审查、本地告警、追加式人工复核和可恢复回放。
- 严格结构化 screening、超时/缓存/manifest/raw response 记录，以及 M5 的告警、判例、申诉和投影闭环。
- `REPLAY_LOCKED` 重启恢复和一键 backlog recovery。

### Boundaries

- 样例视频为可见的 AI 生成素材，不是 ground truth；未建立准确率、现场误报率、吞吐或部署就绪度结论。
- 生产告警发送仍关闭，复核身份为本机未认证；不含人脸识别或跨摄像头 ReID。

## [pre-cleanup-v0.1.0] — 2026-09-02

`pre-cleanup-v0.1.0` 是清理前备份标签，指向 `dc09dedc4fbfb28ceecc102bcdd2470d9ae76b1d` 的 M8 集成代码快照。项目包元数据仍为 `0.1.0`；该标签不是额外的生产能力声明。

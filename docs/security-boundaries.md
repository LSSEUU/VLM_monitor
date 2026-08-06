# M0–M3 安全与隐私边界

## 权威校验器

JSON Schema 用于跨语言的结构、类型、枚举、范围和可表达条件校验。Python
`labcourt.contracts` 仍是工件的权威校验器，因为以下规则需要运行时或跨记录上下文：

- Windows 保留设备名、尾随点/空格等可移植路径规则；
- `case_id`、manifest、event、pack、verdict 等跨对象引用闭合；
- frame、track 与 camera 的归属一致性；
- 媒体文件的工作区 containment、实体存在性、SHA-256 与像素边界；
- SQLite 状态、outbox 与 append-only timeline 的事务一致性。

可由 Draft 2020-12 表达的安全规则必须同时存在于 Schema，并由一致性测试验证。
Schema 通过不等于工件已通过完整安全验证。当前 artifact validator 还会从 SQLite 私有
快照重建 M2/M3 权威，检查文件、链接、哈希、物理引用闭合、最终原始模型响应库存，以及
`current.json` 所指向的完整投影 generation。

## 本地存储

- 配置只接受工作区相对 POSIX 路径，拒绝绝对路径、UNC、URI、路径穿越和 Windows
  保留设备名。
- `storage_boundary=LOCAL_FILESYSTEM` 会进入配置指纹和 RunManifest。
- RunManifest 记录存储边界分类，不记录工作区路径或主机绝对路径；因此改变本机工作目录
  不会改变配置指纹或 manifest identity。
- M2 起，打开文件前还必须执行解析后的 containment 检查，并处理 symlink、junction、
  reparse point 与 TOCTOU。
- SQLite 主库及已存在的 WAL/SHM 作为一个 authority set 检查和复制；rollback journal、
  非 regular、reparse 或多链接对象均 fail closed。当前实现不是 custom SQLite VFS，
  不宣称排除同权限攻击者在检查间完成的完美 ABA。
- JSON/JSONL 只是不反写权威的可重建投影。可信消费者只跟随
  `<run_id>/projections/current.json`；旧固定布局、未引用 generation 和半成品 generation
  都不是 current。

## 模型与媒体

- 外部 VLM 请求不得包含全帧、panorama 或 `LOCAL_ONLY` 媒体。
- 每个媒体引用固定 crop ID、媒体 SHA-256、隐私策略和隐私变换版本。
- VLM cache key 由模型 revision、prompt/output-schema hash、有序媒体 hash、规范化文本输入
  和解码参数计算；不同隐私变换版本必然产生不同键。
- 原始 provider bytes 只位于 owner-only 的
  `<run_id>/model_responses/<response_id>.json`；数据库只保存受控 receipt、相对引用和内容
  hash，Verdict 不内嵌任意 provider JSON。
- 响应通过内容寻址 publication journal 两阶段发布。`artifacts validate` 只校验最终权威
  响应及物理库存；`.staging` 与 journal 属于 `maintenance recover` 的有界、provider-free
  恢复范围，不能借未完成发布成为裁决依据。
- 未知交付状态的过期 model-call claim 不会自动接管或再次外呼。维护路径只有“用已验证的
  journal/final 响应直接原子完成”能力，不会返回 owner token 或 `ACQUIRED` 权限；缺 journal
  时保留并要求人工关注。
- 默认路径只有预计算 fixture 和确定性 Fake，不访问网络、不下载模型、不包含真实人员图像。

## 匿名引用

camera、stream、zone、track epoch 与 local track ID 均为长度受限的 ASCII 匿名 token。
`track_ref` 必须使用 `camera_id:tracker_epoch:local_track_id`，并且不得跨摄像头复用。
该限制不能从技术上判断一个看似匿名的 token 是否由姓名生成；数据接入方仍有责任禁止把
姓名、邮箱、工号或其他直接身份标识编码进 token。

# ADR 0006：媒体像素规范、哈希与确定性编码

- 状态：Accepted
- 日期：2026-07-27

## 决策

M2 把“源文件字节”“解码像素”“变换后像素”和“编码文件字节”视为四个不同对象，禁止用
一个含糊的 media hash 代替它们。

所有进入领域与 FrameStore 的图像先规范化为连续、无行填充、row-major 的三通道
`RGB8`。宽、高必须位于无符号 32 位整数范围内，像素长度必须严格等于
`width * height * 3`。OpenCV 的 BGR 输出必须在 adapter 边界转换为 RGB8；Pydantic
工件和 domain 不保存或接收 ndarray。

规范像素 hash 采用以下固定字节前像：

```text
pixel_preimage =
    ASCII("LCPIX1") || 0x00 ||
    uint32_be(width) || uint32_be(height) ||
    ASCII("RGB8") || 0x00 ||
    contiguous_rgb_bytes

pixel_sha256 = SHA256(pixel_preimage)
```

据此定义：

- `input_file_sha256`：输入视频文件精确字节的 SHA-256；
- `source_media_sha256`：源帧规范 RGB8 像素的 `pixel_sha256`；
- `pixel_sha256`：裁切及隐私变换后规范 RGB8 像素的 `pixel_sha256`；
- `media_sha256`：最终 PNG 文件精确字节的 SHA-256。

字节流 hash 使用普通 SHA-256，不先套 LCJ-1。结构化 ID 与 document hash 才使用 LCJ-1
canonical JSON。文件 hash、解码和尺寸检查必须作用于同一个已安全打开的 handle，不能在
路径检查后重新按字符串路径打开文件。

`Crop` 必须保存源像素 hash、输出像素 hash、PNG 文件 hash、输出宽高、媒体类型、
`privacy_transform_version` 与 `encoding_version`。`crop_id` 继续按 ADR 0002 包含源像素
hash、bbox、输出宽高、crop source、隐私策略、变换版本和编码版本；输出宽高是身份的一部分，
防止同一源 bbox 的不同 panorama 缩放结果碰撞。`pack_id` 使用显式语义投影，
包含 crop ID、三个相关媒体 hash 和隐私回执，但排除 `local_path`、当前 availability、墙钟
和对象自身 ID。合法 retention 清除后相对路径可以变为 `null`，所有 hash 和语义 ID 保留。

最终 PNG 的规范 locator 使用 `frames/<media_sha256>.png`，与 `media_assets` 的内容寻址主键
一致。不同 `crop_id` 若产生完全相同的规范 PNG 字节，共享同一个普通单链接文件与 locator；
这不使用 hardlink 或 symlink，也不合并各 crop 独立保存的来源、隐私回执和语义身份。相同
`media_sha256` 却出现不同尺寸、像素 hash、编码版本或文件字节时必须按完整性冲突失败。

M2 默认 PNG encoder 位于 media adapter，使用固定版本的 Pillow 生成 RGB PNG：

```text
format=PNG
mode=RGB
optimize=false
compress_level=9
interlace=false
metadata/exif/icc/text/time chunks=none
```

输入图像由新建的 RGB image 构造，不继承源文件 metadata。`encoding_version` 标识上述参数
集合；Pillow 版本和许可证记录在 RunManifest 的 software component 中。改变库版本、编码
参数或输出字节规则必须改变 `encoding_version`，并更新 golden vectors。像素 hash 独立于
PNG 压缩结果，使审计者可以区分“像素变化”和“仅编码变化”。

隐私变换在任何持久化和 PNG 编码之前执行。`PPE_PRESERVING_REDACTION` 使用已经校验的
关键点/anchor 形成必要区域，区域外填充版本化的固定不透明 RGB 值：

- goggles 只保留双眼外接框扩张得到的 PPE 带；
- gloves 只保留腕部关键区；
- lab coat 只保留躯干关键区并完全遮蔽头部；
- 关键点不足时不得扩大到完整脸部，结果强制 `LOCAL_ONLY`；
- panorama 使用 `FULL_REDACTION` 且始终为 `LOCAL_ONLY`；
- `EPHEMERAL_RAW` 只能进入带 TTL 的 raw cache，不能进入 EvidencePack、报告或模型请求。

隐私结果保存 typed receipt，包含 policy、变换版本、输入关键点/anchor 引用、实际保留区、
填充值、access 结论和受控 reason code。`media_access` 是变换结果，不接受调用方自行声明。
M2 只声称规则按字节确定执行，不声称该处理实现匿名化。

OpenCV 只作为可选、headless 的本地视频解码 adapter：

- 包依赖置于 `video` extra，核心包导入和默认离线测试不得 import `cv2`；
- adapter 构造时 lazy import，未安装时返回 typed dependency failure；
- v0.1 只接受本地 CFR 文件，拒绝 URI、RTSP 与 UNC；
- 调用方或受信 sidecar 必须给出 `fps_num/fps_den`，不得从 `CAP_PROP_FPS` float 猜业务时间；
- `StreamManifest` 必须把 `timing_mode=CFR` 与
  `timing_authority=CALLER_ATTESTED|TRUSTED_SIDECAR` 一并固化，避免把“OpenCV 返回一个 FPS
  浮点数”误写成 CFR 证明；声明还必须绑定与 authority 匹配的
  `timing_evidence_type` 和 `timing_evidence_sha256`，M2 不接受未声明或声明为 VFR 的输入；
- OpenCV 报告的 FPS、宽高和帧数只做一致性核验，不匹配时拒绝输入；
- 只显式使用 `CAP_FFMPEG`，不允许 `CAP_ANY` 回退到图片序列、GStreamer pipeline 或其他
  字符串解释器；
- 顺序解码，不以随机 seek 作为确定性读取路径；任何帧可返回前先完整 preflight 全流，
  核验实际 EOF/尾帧并冻结逐帧 LCPIX1 hash，随后的按需解码必须逐帧匹配；
- 输入文件 hash、OpenCV 版本、backend、codec、RGB 转换和权威 FPS 写入 StreamManifest。

OpenCV/codec 在不同平台可能产生不同解码像素，因此 REPLAY_LOCKED 复用已保存的帧引用、
crop 和模型响应；需要重解码的运行必须核验 StreamManifest，并把任何 pixel hash 差异显式
报告为输入层分歧，不能悄悄复用旧 crop ID。

## 理由

视频文件相同不保证不同 decoder 产生相同像素，像素相同也不保证不同 PNG encoder 产生
相同文件字节。分离四种对象、冻结 RGB8 前像并记录软件版本，才能准确定位重放差异，并让
隐私变换和云端媒体缓存建立在真正被验证的字节上。

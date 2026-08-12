# LabCourt 前端设计方向 · 规划文档

> 状态：监控页(monitor.html) + 案件详情(case-file.html, v2 选项卡) 已交付并互通；`--alarm` 已调暗。进入范围扩展：监控页深度打磨(视频+识别标注+设备模块) + 登录/个人中心/设置等新页，分阶段，见 §11。本文件是路线图源头，供人编辑、供 agent 复用。
> 最后更新：2026-08-11

## 1. 意图摘要（一句话）

把 LabCourt 做成一个**真实可用的实验室安全网页**（识别 / 告警 / 通知 / 案件 / 地图 / 知识库 / Agent 全功能），用一套**"编辑刊物克制 → 电影化告警高潮"**的设计语言呈现，让 5–10 分钟的评委演示稳稳命中"哇"。**当前阶段只定设计规则与参考，不写最终代码。**

## 2. 三层模型（防止跑成线性 PPT）

| 层 | 是否真实 | 现阶段 |
|---|---|---|
| 产品层（功能） | 必须真实可用、可点、互联 | 已有 mock，后续接真接口 |
| 设计语言层（风格） | tokens / 字体 / 网格 / 动效 / 隐喻 | **现在锁定** |
| 引导演示层（可选叠加） | 真实产品里架"摄影机"的剧本导览 | 后做 |

红线：引导层只是叠加，**禁止**把产品做成固定流程的放映 PPT。

## 3. 已锁定方向（来自前几轮商榷）

- **主隐喻**：法庭 / 卷宗（与 LabCourt 名字、已有"控辩 / 裁决 / 程序守门"文案天然契合）。
- **体验脊**：编辑克制 → 电影高潮。**对比即设计**——平静是为了让风暴落地。
- **体验五幕**（用现有 mock 数据）：序章(楼是安静的) → 涟漪(T-07 异常) → 卷宗(立案审理，AI 之眼嵌在证据帧) → 高潮(烟雾+温度告警) → 尾声(盖章回归)。
- **伦理红线**（继承 README）：不做人脸识别、AI 不自动定责、引用必带来源；设计必须让人觉得"被守护"而非"被监视"。

## 4. 参考板（临摹目标 · 已核实可点开）

### A. 地基 —— 可直接采用的 DESIGN.md / 设计系统

- 元资源：[awesome-design-md](https://github.com/VoltAgent/awesome-design-md) —— 73 个真实网站的 DESIGN.md 合集（Google Stitch 格式，MIT）。重点候选：
  - **Runway** —— "editorial film-festival aesthetic: cinematic dark heroes, paper-white reading bands, single sans, pure black pill CTAs"。**几乎就是我们"编辑 × 电影"论点的双生子。** → https://getdesign.md/runwayml/design-md
  - **Sanity** —— "dark-first editorial; 112px display; IBM Plex Mono 技术眉标；**单一 coral-red 强调色只留给最高优先级 CTA**"。**= 我们"朱砂只留给告警"原则的最佳范例。** → https://getdesign.md/sanity/design-md
  - **Claude (Anthropic)** —— "warm terracotta accent, clean editorial layout"。可信、编辑型 AI 产品的气质锚。 → https://getdesign.md/claude/design-md
  - **WIRED** —— paper-white broadsheet density, custom serif, ink-blue links。纯刊物感。
  - **IBM (Carbon)** —— 结构化、严肃、蓝色；可作"认真工具 / 取证"组件地板。
- 开源严肃底座：[GOV.UK Design System](https://design-system.service.gov.uk/) —— 编辑 / 政府表格式的严肃、可达、排版导向，避免重新发明组件轮子。
- DESIGN.md 格式说明：[Google Stitch DESIGN.md](https://stitch.withgoogle.com/docs/design-md/overview/)

### B. 灵魂 —— mood / 隐喻 / 动效（看感觉，不抄代码）

- **Bear 71 (NFB, 2012)** —— 用真实监视影像 + 数据流做的互动纪录片，被评作"监视文化的寓言"。**双重价值**：方法上示范"用数据 / 镜头讲一个沉浸故事"；立场上它是**反面警示**——我们的产品绝不能变成它所讽的那个东西。([背景评析](https://tianvetter.com/my-blog/digital-story-critique-2-bear-71/))
- 编辑型数据叙事三件套：[The Pudding](https://pudding.cool) · [NYT Upshot](https://www.nytimes.com/international/section/upshot) · [Reuters Graphics](https://www.reuters.com/graphics/)
- 电影化 FUI：[Westworld UI 幕后 (Chris Kieffer)](http://chriskieffer.com/westworld-fui/) · [幕后访谈](https://vanschneider.com/blog/behind-the-scenes-of-the-westworld-ui/)
- 冷峻 / 对称 / 复古未来：[Severance UI 分析 (HUDS+GUIS)](https://www.hudsandguis.com/home/2022/severance) · [设计拆解](https://gatherit.co/blog/behind-the-design-apple-tvs-severance-zero-spoilers)
- 明暗对比(chiaroscuro) + 极简 + 单色：Ferrari / Bugatti 的 DESIGN.md（见 awesome-design-md）。
- 通用高端参考：[Awwwards Storytelling](https://www.awwwards.com/websites/storytelling/)

### C. 范式专项（按四幕各找）

- 空间俯瞰 · 活体建筑：[FeelPlace3D 数字孪生](https://www.feelplace.com/solutions/digital-twin/) · [Contexus 模板画廊](https://contexus.io/gallery) · [Kilo 楼宇孪生](https://kiloiot.io/product/digital-building-twin/)
- 法庭卷宗 · 证据板：[Detective Board](https://www.detectiveboard.io/) · [Cryptic Killers 案卷游戏](https://cryptickillers.com/) · [Creately 证据板](https://creately.com/lp/evidence-board-maker/)
- 时空回放 · 时间轴：[Shorthand 时间轴精选](https://shorthand.com/the-craft/best-visual-timeline-examples-on-the-web/index.html) · [Scrollytelling.ai 模板](https://scrollytelling.ai/templates/timeline/) · [Awwwards 时间轴灵感](https://www.awwwards.com/inspiration/interactive-timeline-menu)
- 电影化告警：见 B 的 Westworld / Severance。

## 5. 推荐主临摹目标（我的判断，待你拍板）

不要照搬任何单一系统。建议组合：
- **主 mood / tokens = Runway DESIGN.md**（编辑 × 电影双生子）+ **Sanity DESIGN.md**（单一保留强调色范例）。
- **伦理 / 气质锚 = Claude(Anthropic) DESIGN.md + Bear 71**（可信编辑型 AI ＋"用监视数据讲不监视的故事"）。
- **冷静组件地板 = GOV.UK 或 IBM Carbon**（认真、可达、不花哨的组件底座，省去重造轮子）。
- **法庭隐喻 + 编辑→电影动效** = 没有任何现成系统能给，**仍需我们自己设计**（这正是创新点）。

## 6. 设计 token 草案（待 #5 拍板后落死）

- 颜色：暖纸白底 + 近墨黑字；学术深色辅助（深绛 / 研究藏青）；**朱砂 / vermilion 仅留给告警高潮**。（具体 OKLch 值待定）
- 字体：中文思源宋体（正文 / 标题）+ 西文衬线（如 Source Serif）+ 等宽（IBM Plex Mono / JetBrains Mono，给案件号 / 帧号 / 时间——"取证"味）。
- 排版守则：CJK 标题行高 1.3–1.4、正文 1.7–1.8；中文不做负字距；ALL CAPS 才正字距 0.06em+。
- 动效：克制；一个"建筑呼吸"，一个高潮"AI 锁定"手势；提供 reduce-motion 兜底。

## 7. 已决（前几轮锁定）

- [x] **底色走向**：暖纸白 calm → 第四幕切影院墨 alarm（对比即设计）。
- [x] **主临摹目标**：Runway + Sanity + Claude + GOV.UK 组合（地基抄成熟系统，灵魂自己捏）。
- [x] **token 契约**：已写入 `DESIGN.md`（OKLch 双态 + 思源宋体/Source Serif 4 + IBM Plex Mono）。
- [x] **v1 原型**：案件卷宗屏 `case-file.html`（编辑卷宗 + 证据帧叠 AI 注意力 + 平静→告警切换）。

## 8. 路线图（下一步，待选）

> 评级"还可以"对以"哇"为目标的 pitch 是警讯；最可能元凶是三张**抽象占位证据帧**（本就约定艺术方向定了再生真图）。
> 依赖顺序：先把语言在一屏打磨到"哇"（A）→ 铺叙事需要的屏（B）→ 串成 5 幕导览（C）。

**A. 把这一屏打磨到"哇"**
- **A1 生图**：3 张匿名化实验室证据帧（真实风格），AI 注意力叠层照画 —— 治"还可以"的最大杠杆。
- **A2 生音频**：告警音 + 建筑低频心跳 —— 告警从"看见"变"听见"。
- **A3 动效**：calm"建筑呼吸"、告警"锁入"手势、切换节奏分层。

**B. 铺叙事需要的下一屏**（按 5 幕挑，不必全做）
- **B1 序章 · 活体建筑**：楼宇剖面 + 传感器脉搏 + 匿名光点 —— 五幕的"舞台"。
- B2 日常监控 · AI 之眼常态版 ｜ B3 校园地图 / 知识库 / 通知 Agent（按需）。

**C. 串成 pitch 正片**
- **C1 引导演示层**：按空格自动推进、随时暂停深挖的五幕导览。
- C2 轻量 `index.html` 把各屏串成可点 overview。

**推荐顺序**：A1 → A2 → B1 → C1。
- [x] A3 动效打磨已完成（建筑呼吸 / AI 锁入 / 分层切换）。
- [ ] A1 生图 / A2 生音频：用户暂缓，先不做。
- → 方向已据用户复盘修正，见 §9。

## 9. 方向修正（v1 复盘 · 2026-08-11）

用户反馈（成立）：

1. **告警全屏变暗"晃眼睛"，且不像真实产品。** 真实安全产品不会把整个工作区反转成暗色——那是 demo 噱头，评委也会觉得"像电影不像产品"。
   - 修正：**告警不再做全局 dark-mode 翻转**；页面始终保持编辑纸态。
   - 告警 = 一个**受控告警层**（朱砂横幅/toast，带"查看案件"跳转）+ **相关摄像头/证据帧上的朱砂锁定手势**（lock-on/scan 收敛到那一帧，不铺满屏）+ 可选的极轻页面边缘朱砂提示。
   - 你问"放监控页 还是 弹出容器？"——答案是**两者叠加，不是二选一**：告警层可在任意页（尤其监控页）弹出并跳案件详情；锁定手势只作用在相关那一路画面上。
   - 你问"调浅 还是 不全屏？"——答：**不全屏**（保留你喜欢的锁定/扫描手势，但收敛到帧 + 横幅，不再整页变暗、不再全屏闪）。
   - `DESIGN.md` 的"alarm = 暗色主题"需据此改为"**alarm = 受控朱砂层（页面留纸态）**"。
2. **案件页太像"风格展示"，有 AI 味/自我介绍。** 修正：**剥离 manifesto 内容**——删 pull-quote"AI 提议，代码守门，人，盖章"、"非隐藏思维链"之类元叙述 eyebrow、演示 toggle 的说辞、杂志式报头与诗意大标题、冗长的 PREVIEW 文案。
   - ⚠️ **重要界限（防过度纠正）**：保留**编辑刊物风格**（衬线 / 克制配色 / 发丝线 / 等宽取证眉标）——那是品牌与差异化；剥离的只是"自我介绍的元叙述"。功能模块（证据帧 / 会审 / 程序守门 / 裁决）是**产品特性**，保留，只去掉对它们的夸耀性注释。
3. **图片/声音暂缓**（A1/A2 搁置）。

**修订路线图**：
- **R1** 修订案件详情屏：去 manifesto、改成真实功能页（编辑风格保留、功能保留）。
- **R2** 重做告警为受控层（横幅/toast → 跳案件详情 + 帧级锁定手势），不再全屏翻暗；同步修订 `DESIGN.md` 告警态定义。
- **R3** 按 §5 同风格铺真实业务屏：监控/摄像头墙（日常运营首页 · AI 之眼常态版 · 告警发源地）→ 校园地图（活体建筑）→ 知识库 / 通知 Agent。
- **R4** 轻量 `index.html` 串成可点 overview；最后视情况做引导演示层。
- **推荐顺序**：R1 → R2 → R3（监控先）→ R4。
- [x] R1（去 manifesto）+ R2（告警改受控层）已落地。但告警层放错了位置，见 §10。

## 10. 案件详情页 v2 重构（用户复盘 · 2026-08-11 第 2 轮）

R1+R2 之后用户进一步反馈（成立，需重构）：

1. **告警层放错地方。** 告警弹出应在"主控制台/监控页"，不是案件详情页。→ 从 `case-file.html` 移除告警横幅 + "模拟告警"按钮；告警层迁到监控页（R3）再做并打磨（用户也说当前弹出"生硬"，到时结合真实界面再调）。
2. **页面太长、只是信息铺陈，不像能处理业务的工具。** → 改**选项卡 IA**（不破坏编辑风格：发丝下划线 tab + 等宽标签）。拟 4 个 tab：
   - **概览**（默认）：流程进度图 + 关键事实 + 状态 + 主操作。首屏即"哇 + 能动手"。
   - **证据**：3 帧证据 + AI 注意力 + 客观事实。
   - **会审**：初审/辩方/裁决 + 程序守门。
   - **处理**：操作按钮 + 处置说明输入框 + 补充证据上传框 + 时间线。
   - ⚠️ 取舍：tab 会藏内容（评委少看几屏）——所以"概览"必须自成高潮。
3. **加案件流程进度图（页面脊骨）。** 横向流程：检测触发 → 证据采集 → AI 初审 → 控辩会审 → 程序守门 → 人工确认 → 通知送达 → 结案归档；标 ✓完成 / ●当前 / ○待办。
4. **加真实操作控件（面向安全管理员）。** 处理 tab：主按钮（确认生成安全提醒）+ 次按钮（退回补证 / 升级）+ textarea（处置说明）+ 文件上传（补充证据）。
5. **红色太亮。** → `--alarm` 由 `oklch(0.62 0.20 30)` 调到 `oklch(0.50 0.15 28)`（更深、更可控的朱砂/oxblood，可读性↑、美感↑）。
6. **更多层级动效 + 出场编排 + 擦除**（用户自述不精准，交我判断）。动效词汇（克制，防 AI 味）：
   - 载入编排：顶栏落下 → 流程图从左到右"绘制"（节点 + 连线依次出现）→ 概览内容 stagger 浮入。
   - 单一动效母题：clip-path 擦除（标题/分隔从左揭开），全场只用这一种"擦除"。
   - 滚动触发：各区块进入视口时淡入上移（IntersectionObserver）。
   - `prefers-reduced-motion` 全关；幅度小、时长短（≤500ms/元素）。

**下一步**：按 §10 重构 `case-file.html`（v2，整页重做）。监控页（R3）随后，告警层在那里落地。
- [x] 已确认并落地（案件页 v2 选项卡 + 流程图 + 操作控件 + 告警迁出，均已交付）。

## 11. 范围扩展与分阶段（用户复盘 · 2026-08-11 第 3 轮）

### 11.1 立即生效的小改
- 位置更名："江北校区 · 理工实验楼 · 三层化学实验区" → **"海南大学 · 信通楼 · 开放预约实验室"**（与真实归属一致）。改 `monitor.html` / `case-file.html`。

### 11.2 监控页深度打磨（阶段 1 · 最高优先）
- **主画面用真实模拟视频**：把附件 mp4 拷为 `assets/lab-feed.mp4`，`<video autoplay muted loop playsinline>` 作主画面；其余机位暂留抽象场景（仅一段视频素材）。
- **识别信息标注（模拟 AI 之眼）**：在视频上叠——发丝边框 + 角括号（沿用 reticle 母题）+ mono 标签（`PPE·未佩戴·0.84` / `轨迹 T-07·匿名` / `区域·高风险`）+ 周期扫描线。**不跑真识别，纯外观**。保持编辑克制（不用霓虹亮色）。
- **多摄像头切换**：缩略图栏可点切换主画面（active 态 fg 描边）。诚实：仅一段视频，切换以标签/选态体现，不伪装多路真实视频。
- **设备/传感器小模块（device rail）**：每个 = 设备名(mono) + 实时值(大号) + 单位 + 迷你 sparkline（历史趋势，SVG 折线 + 填充，遵循数据可视化纪律）。示例：温度 T-02 24.1°C、烟雾 SMK-03 0.03、通风橱 FH-01 运行/风速 0.8m/s、门磁 D-03 CLOSED、湿度 H-01 42%。替换原来的简单 `<dl>`。

### 11.3 新增页面（分阶段）
- **阶段 2 · 登录 + 个人中心（角色感知）**：登录页（编辑卡片：邮箱 + 密码 + 角色选择 学生/教师领导/管理员）；个人中心按角色分流（学生: 我的预约/记录；领导: 管辖实验室/待办；管理员: 概览/快捷入口）。演示带角色切换器预览各视角。
- **阶段 3 · 设置（开发调试/管理）**：系统选项(toggles：启用AI识别/演示模式/减少动效/自动派单) + 模型与API(provider/key/model/置信阈值/超时) + 知识库管理(列表+增改，带来源/版本) + 通知通道 + 设备网关列表。
- **阶段 4 · 校园地图（活体建筑） + 知识库页 + 通知 Agent**。
- **阶段 5 · `index.html` 串屏 launcher + 引导演示层（可选）**。

### 11.4 角色模型（新增）
- 三类：学生 / 教师或实验室负责人 / 系统管理员；权限与可见面不同。先以**管理员**视角为主深做，其余角色做轻量预览。

### 11.5 取舍（防泛而浅）
- **英雄屏深做**：监控（含识别标注）、案件详情。其余（登录/设置/地图/知识库）做"够用且风格一致"，不追求等深度——demo 不需要每屏都满。
- [ ] 待用户确认：从阶段 1 起步？新增页面的深度取舍？

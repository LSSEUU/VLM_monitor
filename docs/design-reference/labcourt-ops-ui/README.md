# LabCourt 前端设计预览

本目录归档 `前端创意头脑风暴.zip` 的多页面静态设计，仅作设计参考，不接入项目后端、数据库、模型、权限或生产通知能力。正式界面位于 `src/labcourt/m8_ui_web/`。

## 启动

```powershell
python -m http.server 4173 --directory .
```

打开 `http://127.0.0.1:4173/docs/design-reference/labcourt-ops-ui/index.html` 查看原型总览。

## 页面

- `index.html`：原型总览
- `landing.html`：产品落地页
- `login.html`：登录页
- `monitor.html`：实时监控
- `case-file.html`：案件详情
- `knowledge.html`：知识库
- `map.html`：校园地图
- `profile.html`：个人中心
- `settings.html`：系统设置
- `agent.html`：通知 Agent 与高影响动作二次确认

共享导航位于 `assets/nav.css` 与 `assets/nav.js`。两段设计专用模拟视频位于 `assets/`；第三段复用仓库唯一的 `inputs/goggles-missing.mp4`。页面中的 `PREVIEW / SIMULATED`、无人脸识别、无跨摄像头 ReID、AI 不直接定责等边界均沿用设计稿。

三段视频均为项目随附、画面内明确标注的 AI 合成素材，仅用于本仓库演示，不构成 ground truth。项目未收到单独的再分发许可证；对外分发或替换前须取得所有者授权，并同步更新 manifest、内容 hash 和回归工件。

除将 `profile.html` 中失效的设计平台资源地址改为同内容的本地相对路径外，设计元素、文案、样式与交互均未改动。

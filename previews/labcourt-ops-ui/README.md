# LabCourt 前端设计预览

本目录完整保留 `前端创意头脑风暴.zip` 的多页面静态设计，不接入项目后端、数据库、模型、权限或生产通知能力。

## 启动

```powershell
python -m http.server 4173 --directory previews/labcourt-ops-ui
```

打开 `http://127.0.0.1:4173/index.html` 查看原型总览。

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

共享导航位于 `assets/nav.css` 与 `assets/nav.js`，三段模拟视频位于 `assets/`。页面中的 `PREVIEW / SIMULATED`、无人脸识别、无跨摄像头 ReID、AI 不直接定责等边界均沿用设计稿。

除将 `profile.html` 中失效的设计平台资源地址改为同内容的本地相对路径外，设计元素、文案、样式与交互均未改动。

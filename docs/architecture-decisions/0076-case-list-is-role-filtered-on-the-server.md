# ADR 0076：案件列表必须由服务端角色裁剪

## 状态

Accepted for the personal Demo API.

## 背景

界面首次加载不知道 Case ID，只能依赖运营投影或硬编码演示 ID。学生不能读取运营投影，运维也不应取得
案件；如果返回全量列表再让前端隐藏，会泄露超出角色 scope 的 authority。

## 决策

新增 authenticated `GET /api/m8/cases`，从 repository 读取有界 current inventory 后按当前 actor 过滤：
安全负责人仅 location scope 覆盖的案件，领导仅严重/紧急案件，学生仅 `subject_actor_id` 为自身的案件，
运维返回空列表。接口不接受客户端 role 或 limit。

单案和 audit 路径同步复用安全负责人的 location scope 判断。列表只返回现有 typed Case commit receipts，
不改变状态、不生成额外 authority。

## 后果

集成界面可从 session 后直接加载允许的案件清单，且无法通过前端参数扩大范围。当前烟雾案件没有学生主体，
因此个人 Demo 的 student list 正确为空，不会通过视觉推断或跨摄像头身份关联补齐主体。

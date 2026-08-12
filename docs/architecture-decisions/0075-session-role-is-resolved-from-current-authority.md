# ADR 0075：Session 角色必须解析自当前 authority

## 状态

Accepted for the personal Demo API.

## 背景

独立集成界面需要知道当前用户是领导、安全负责人、学生还是运维，以及可展示哪些功能。把 token 字符串或
本地配置映射复制到前端会产生第二套权限事实，并在 actor 停用或换版后继续展示过期 capability。

## 决策

新增 authenticated `GET /api/m8/session`，复用现有 bearer authenticator 得到 principal，再从 operations
repository 读取当前 actor commit receipt。响应直接使用已有 typed receipt；actor 必须 active 且 ID 与
principal 完全一致。请求不接受 role、scope 或 capability 参数，响应不包含 bearer token。

## 后果

界面可以先发现当前角色并按 capability 渲染导航，但服务端每个业务路由仍独立执行授权，session 结果不是
后续请求可提交的权限声明。actor authority 漂移会在下一次请求时重新解析并 fail closed。

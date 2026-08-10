# ADR 0046：M8 知识 API 只接收查询意图并解析当前权威

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.5 authenticated loopback knowledge catalog/query/answer API

## 背景

浏览器客户端需要查询知识库，但不能被允许自行声明 actor role/capability、actor authority、catalog authority、
query manifest 或 adapter manifest。否则客户端可以重放已停用权限、选择已过期目录或把任意组件身份嫁接到回答。
知识查询还必须保持默认离线，并且不得产生 Case transition。

## 决策

1. API request 只包含 query text、locale、as-of UTC、闭合 document-type scope 和 citation 上限；额外字段
   fail closed，并固定禁止客户端 actor/catalog authority 与直接 Case 决策。
2. catalog ID 位于本地路由。服务每次请求先用认证 principal 的 actor ID 读取当前持久化 actor revision，只有
   active actor 可以读取目录或查询。
3. 服务读取该 catalog ID 的当前最高 revision 及其 exact raw bytes，使用默认确定性离线 adapter 生成回答；
   query/adapter manifest 由服务端配置提供。
4. 回答提交再次由仓库校验当前 actor 与当前 catalog，关闭服务读取和持久化提交之间的换版竞态；冲突返回
   typed 409，且不写入部分结果。
5. `GET answer` 只允许当前认证 actor 回读自己 actor ID 下的回答。目录 metadata 可由任一当前 active 的四类
   产品角色读取。
6. API 仍固定监听 `127.0.0.1`，要求 bearer authenticator 和同源 POST；不增加公网、默认凭据、网络模型、
   embedding、Case transition 或纪律处分路径。

## 结果

- 客户端不能通过请求体控制权限、目录或运行组件 manifest。
- 相同当前 authority 与 query intent 得到确定性 query/answer ID，并可从追加式仓库重放。
- 权限停用、目录换版、raw 损坏或并发冲突均 fail closed；已提交的历史回答保持可审计。
- 回答继续逐字引用来源/version/effective date，普通文档不会静默成为规则。

## 未选择的方案

- **客户端提交完整 typed query**：其中包含可伪造的 actor/catalog authority 和 manifest。
- **跨用户读取所有回答**：会不必要地暴露其他用户的查询历史。
- **在线 RAG 作为默认 API**：破坏离线可运行性和确定性重放。
- **查询命中后自动建案或处分**：混淆知识证据与案件权威。

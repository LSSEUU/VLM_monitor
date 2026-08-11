# M8 首个生产适配器接入清单

本清单用于选择 M8.7 的第一个真实适配器，并把厂商特有语义转成可测试的 typed contract。填写清单
不等于批准生产激活；当前默认离线 fake 始终可回退，任何真实外部调用仍须通过完整 commissioning
evidence、readiness 和双人显式 activation gate。

## 1. 需要作出的最小决定

请只选择一个首接类别，并提供非敏感信息：

- 类别（六选一）：`RTSP_CAMERA`、`PHYSICAL_SENSOR`、`OIDC_IDENTITY`、
  `EXTERNAL_NOTIFICATION`、`OBSERVABILITY`、`DISASTER_RECOVERY`
- provider、product、版本或服务套餐
- 使用的正式协议及版本；例如 RTSP profile、传感器网关协议、OIDC discovery、消息平台 API
- 目标 campus 与 location scope
- 测试环境或沙箱是否可用，以及允许产生的真实副作用范围
- 组织批准的 secret 载入机制名称，例如部署平台 secret store 或仅在本机进程中设置的环境变量名

不要把 token、client secret、密码、私钥、摄像头口令或真实 webhook URL 写入本清单、Git、fixture、
日志或聊天。只记录不含秘密的 secret reference；实际值在运行时从批准的 secret store 注入。

## 2. 契约冻结前需要确认

- endpoint/config 的必填字段、允许的 scheme、证书与 TLS 要求
- timeout 上限、重试上限、rate limit 与 provider error taxonomy
- 幂等键的生成、作用域、有效期及 provider 是否原生支持
- 成功、拒绝、超时、限流、部分成功和重复请求的 typed receipt
- 原始 request/response 的最小保留内容、内容寻址引用、脱敏规则与保留期
- license/security/safety/site acceptance 的评审人和证据工件位置
- 断网、provider 故障和撤销凭据时的 fail-closed 行为及离线 fallback drill

普通文档、模型输出或“调用成功”的自由文本均不能替代这些契约或 commissioning evidence。

## 3. 推荐的首接顺序

若当前没有可用的物理设备，优先选择已有测试租户的 `EXTERNAL_NOTIFICATION`，因为它能验证通知闭环、
回执和回复，同时可把收件人严格限制为测试账号。若已有经过授权的实验室网关，则可优先
`PHYSICAL_SENSOR`，但首版仍不得宣称认证消防检测或生命安全联动。`RTSP_CAMERA` 只有在摄像头授权、
隐私评审和现场网络边界明确后再接；实现中继续禁止人脸识别和跨摄像头 ReID。

## 4. 接入后的验收边界

首个 adapter 只在以下条件全部满足后才可进入人工 activation commit：

1. 厂商特有 contract、schema 与 closed failure 测试先冻结；
2. fake、timeout、idempotency、manifest 与 raw receipt 引用完整；
3. 五类 commissioning evidence 当前、通过且可复核；
4. OPERATIONS 与 SAFETY_OFFICER 为两名不同人员并分别显式确认；
5. 凭据未进入任何持久化 authority；
6. 断网和撤销凭据场景 fail closed，离线 fallback drill 通过。

即使完成接入，AI/VLM 仍不能直接定责、处分、撤销或结案，真实传感器也只有在另行存在组织验证的
certification authority 时才可能参与生命安全硬规则。

## 5. 当前首接选择：飞书企业自建应用

首接类别已经确定为 `EXTERNAL_NOTIFICATION`，provider 为飞书企业自建应用；当前实现仅授权 `SANDBOX`
测试收件人与 sandbox webhook。仓库已具备离线 preflight、双人 activation、one-shot outbound、encrypted
URL challenge、`im.message.receive_v1` evidence、回复关联、逐请求 activation gate 与单人 kill switch。

进入真实租户现场验证前，仍需由部署方在仓库外准备：

- 飞书测试租户中的企业自建应用、测试用户 `open_id` 与获批的消息/事件权限；
- outbound App ID/App Secret，以及 inbound Encrypt Key/Verification Token 的获批 secret 注入；
- 公开可达的 HTTPS 域名、有效证书和受审计反向代理，只转发固定 callback path 到 activation 指定的
  `127.0.0.1` 端口；
- 不含 secret 的 callback URL/TLS reference 与 SHA-256、环境变量名、candidate/actor authority 和各类
  manifest ID；
- 由当前 OPERATIONS 与 SAFETY_OFFICER 分别确认后生成的 typed activation intent 与 canonical runtime config。

不要把上述 secret 值或真实学生消息粘贴到命令、清单、日志、fixture 或 Git。完成这些外部准备后，先执行
`labcourt feishu outbox-activate` 与 `webhook-activate`，再执行 `webhook-serve --check`；各自 status 均为
current、预检成功且反向代理审计证据齐全后，
才能在飞书后台配置 Request URL 并验证 challenge。provider 接受、HTTP 200 或 challenge 成功都不等于真实
送达、学生身份确认、案件责任或处分成立。

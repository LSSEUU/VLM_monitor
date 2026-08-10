# ADR 0043：M8 普通知识是版本化引用证据而不是案件规则

- 状态：Accepted
- 日期：2026-08-10
- 影响范围：M8.5 knowledge document/catalog/query/citation/answer authority

## 背景

校园知识库需要覆盖制度、SOP、历史判例、应急预案、设备资料和问答，但“制度文档”或“历史判例”被检索
到不代表它自动成为当前案件裁决规则。回答还必须展示来源、版本和生效日期，并在默认离线环境避免模型
幻觉、网络 embedding 与不可重放排名。

## 决策

1. knowledge document authority 只保存版本化 metadata、source/content reference、exact content hash/size、
   发布/生效/失效 UTC 和 manifest；正文由后续受控 raw store 保存。
2. document type 使用六值闭合枚举：`POLICY / SOP / HISTORICAL_PRECEDENT / EMERGENCY_PLAN /
   DEVICE_MANUAL / FAQ`。所有普通文档固定 `ordinary_document_can_define_case_rule=false` 与
   `direct_case_decision_permitted=false`，包括 `POLICY`。
3. catalog 完整内嵌稳定排序的 document versions，并禁止同一 logical document 的生效区间重叠。query
   绑定 exact catalog、requester actor authority、as-of UTC、闭合类型范围、citation 上限和 manifest。
4. citation 绑定 exact document authority、source/version/effective time、chunk 与字符区间、snippet hash 和
   lexical match count。answer 只接受 catalog 内、查询时有效、类型允许且稳定排序的 citations。
5. answer text 只能由 citation snippets 确定性拼接；无匹配返回固定 no-match 文本。answer 固定
   `network_used=false`、`model_used=false`、`ordinary_document_used_as_case_rule=false` 和
   `case_transition_permitted=false`。

## 结果

- 用户看到的每段回答都能回到 exact source/version/effective date 和内容 hash。
- 普通知识发布或检索不会静默修改 typed rule authority，也不会自动改变 Case。
- 默认离线 adapter 可使用受控 fixture bytes 和确定性 lexical chunk ranking，无需网络或 GPU。
- 真正规则发布仍须走后续独立、授权、可审计的 rule configuration path。

## 未选择的方案

- **把 Markdown/PDF 文档直接加载为规则**：绕过独立 rule authority、权限与审计。
- **生成式自由回答不强制 citation**：无法证明内容来源，可能混入幻觉。
- **只记录文档标题或最新版本**：历史查询无法按当时生效版本重放。
- **默认在线 embedding/LLM 检索**：引入网络、模型版本、成本和不可确定性。


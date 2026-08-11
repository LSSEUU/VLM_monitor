# ADR 0072：确认通知不等于确认案件

## 状态

Accepted for the offline personal Demo.

## 背景

离线通知达到 `DELIVERED` 后仍属于未闭环消息。安全负责人需要一个可演示的确认动作，但“已看到通知”与
“已核实案件”是两个不同权限和状态机；把两者合并会绕过案件的理由、证据和显式审批契约。

## 决策

增加独立 acknowledgement 命令，只消费 exact route authority 和当前 `DELIVERED` notification。命令必须
取得精确 `APPLY`，重新解析当前 `safety-officer-demo` authority，并通过既有 notification service 提交
`ACKNOWLEDGED`。没有显式确认、目标变化或状态不符时 fail closed。

acknowledgement receipt 固定 `case_transition_permitted=false`；命令不构造任何 Case transition request，
不改变案件版本、状态或处分语义。exact retry 返回同一 notification commit。

## 后果

运营投影可把该通知计为已闭环，同时原始案件继续保持 `PENDING_VERIFICATION`，仍需通过独立案件动作入口
由安全负责人确认、驳回、补证或结案。

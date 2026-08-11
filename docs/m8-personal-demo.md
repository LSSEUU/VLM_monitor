# LabCourt 校园运营个人 Demo

## 一键初始化

Windows 资源管理器中双击仓库根目录的 `labcourt-demo-bootstrap.cmd`。也可以在 PowerShell 执行：

```powershell
.\.venv\Scripts\labcourt.exe demo bootstrap --json
```

默认输出到被 Git 忽略的 `.labcourt-local/labcourt-demo/`：

- `labcourt.sqlite3`：追加式 M8 authority 数据库；
- `bootstrap-receipt.json`：内容寻址的初始化闭包摘要；
- `operations-projection.json`：供最小界面直接读取的当前运营投影。

命令可重复运行；相同 authority 返回同一回执，不追加重复案件。若已有工件与数据库 authority 冲突，命令
会停止而不会覆盖。需要全新演示环境时，应先退出后续 API 进程，再手工移走整个本机 Demo 目录。

## 固定场景

初始化内容为一个完全离线、确定性的演示校区：

- 校园 → 化学楼 → 三层 → 实验室 301；
- 领导、安全负责人、学生、运维四个 active 演示角色；
- 一个显著标注 `SIMULATED` 的烟雾传感器，保存 tick 0 未激活与 tick 5 激活的 typed 原始信号；
- typed 风险策略将激活信号评估为 `EMERGENCY` 候选；
- 自动化只建立一个 `PENDING_VERIFICATION` 案件，并记录原始信号 authority 与创建审计；
- 运营投影显示 4 个位置、1 个模拟源、1 个已观测传感器和 1 个待核实重大案件。

该数据集不是认证消防检测，不包含真实人员、真实摄像头或现实安全表现，也不允许 bootstrap 自动确认、
驳回、补证、结案或处分。下一阶段的本机 API 从同一 SQLite 数据库解引用角色 authority，由安全负责人
显式确认后才能执行关键案件迁移。

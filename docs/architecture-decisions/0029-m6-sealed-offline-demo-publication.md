# ADR 0029：M6 完整离线 demo 使用逐场景凭据、同根上游闭包与 HTML commit point

- 状态：Accepted
- 日期：2026-08-04
- 影响范围：M6 `make demo`、16 场景验收、CLOSED/静态报告组合发布与本地浏览

## 背景

M6 已分别具备 CLOSED `REPLAY_LOCKED` 回归发布和隐私安全静态 HTML 发布，但“两个页面存在”
不能证明完整 demo 已实际执行，也不能证明页面、场景结果与上游发布属于同一条权威链。若脚本在
部分场景失败后仍写出首页、复制一份脱离原始根的 HTML，或让 reader 只相信调用方传入的通过
列表，用户会把半成品误认成成功发布。

同时，M6 的离线 fixture 只验证确定性业务语义。它不能被包装成真实模型准确率、延迟、成本或
现实安全表现，也不能为了展示效果引入网络、GPU、真实人员媒体或隐藏推理。

## 决策

1. 完整 demo 固定为 M6 里程碑列出的 16 个稳定场景名。统一验收文件为
   `tests/e2e/test_m6_demo_scenarios.py`；每个名称对应一个无参数化后缀的精确 pytest function
   node，并复用已有 FSM、SQLite、会审、程序门、申诉、CLOSED replay 与 upgrade gate 路径。
2. `make demo` 必须显式指定这 16 个精确 node ID，而不是仅执行整个文件。子进程清除
   `PYTEST_ADDOPTS`/`PYTEST_PLUGINS`，关闭第三方插件自动发现，仅显式加载离线 socket guard；
   除零退出外，还必须从一次性 JUnit 回执核验 16 个有序 testcase 均真实通过且没有
   error/failure/skipped。缺节点、只收集、回执损坏或启动失败均类型化退出且不签发 `PASSED`。
3. 每个 result 使用 canonical JSON、SHA-256 与 size 双身份，固定发布到
   `demo/scenarios/<scenario_name>/result.json`。`M6OfflineDemoManifestAuthorityV1` 精确绑定 16 项
   有序库存、CLOSED report/seal 与静态报告 seal/index 身份，并固定
   `SYNTHETIC_PRECOMPUTED_FAKE`、无网络、无 GPU 与无外部 provider 的声明。
4. `M6OfflineDemoPublicationSealAuthorityV1` 另行绑定 demo manifest、landing HTML 与场景库存根。
   manifest 采用内容寻址路径，seal 固定为 `demo/seal.json`；`demo/index.html` 是唯一最后写入的
   commit point。scenario、manifest 与 seal 均先发布，任何 commit 前故障不得留下可被 reader
   认作成功的首页。
5. demo publisher 与 reader 都必须在自己的 `output_root` 内重新读取并验证 CLOSED 发布和静态
   报告，不能接受另一个目录中的上游。landing 只链接同 generation 的 `../regression.json` 与
   `../index.html`，不复制或重写上游正文。
6. publisher 使用每 run 的 demo 专用 handle-bound 文件锁、固定 `pending` staging slot 和
   partial-final compatibility preflight。不同 bundle 不能污染 exact retry；commit 前再次重建
   同根上游。reader 在读正文前执行 seal size 总预算，完成上游重建后第三次复读全部 demo
   snapshot 与库存，公开失败只暴露无载荷 reason code。
7. 默认输出按 demo publication seal ID 分 generation，位于
   `runs/m6-demo/generations/<seal-id>/`。同一内容精确重试得到同一路径和同一身份；内容改变产生
   新 generation，不覆盖旧结果。
8. landing 为纯静态、自包含、无脚本、无外部资源的 HTML；支持键盘焦点、响应式布局与
   `prefers-reduced-motion`。应用层使用标准库 `string.Template` 与逐值 `html.escape` 做确定性
   渲染，不放宽 application import 边界；静态报告仍只展示隐私处理后的证据或 retention 占位，
   不读取原始图像。

## 结果

- 首页存在不再是充分条件；完整 readback 必须重新闭合所有上游、16 个 result、manifest、seal
  与 landing 字节。
- demo 在断网环境中无需后端即可浏览，并能从人类可读页面进入机器可读结果和逐场景凭据。
- 开发演示依赖仓库内冻结的 synthetic/precomputed fixture factory；这是有意的 M6 开发路径，
  不进入生产运行时，也不替代 M7 的真实模型评估。
- 新增场景、改变顺序、verification node、模板或任一上游权威都会产生新的内容身份，不能静默
  继承旧 seal。

## 未选择的方案

- **仅生成一张 16/16 的静态页面**：页面无法证明场景实际执行，也不能逐项重算。
- **把静态报告复制到 `demo/index.html`**：会制造与原发布脱链的第二份正文，并破坏相对链接。
- **场景失败也写 result，再在页面标红**：`PASSED` authority 是成功凭据；失败必须以非零退出和
  无 commit 表达，不能混入同一成功 manifest。
- **用可变 `latest` 覆盖旧 demo**：会让本地路径替代内容身份。默认按 seal 分 generation 更适合
  审计与精确重试。

# LabCourt 故障排查

## 端口无法绑定

个人 Demo 和校园平台默认使用 `127.0.0.1:8877`。先执行只绑定、验证并关闭的预检：

```text
uv run --locked labcourt demo api --output .labcourt-local/labcourt-demo --port 8877 --check
```

如果端口已被占用，换一个合法端口，并在启动命令中保持相同端口：

```text
uv run --locked labcourt demo api --output .labcourt-local/labcourt-demo --port 8878 --check
uv run --locked labcourt demo api --output .labcourt-local/labcourt-demo --port 8878
```

结束服务使用 `Ctrl+C`。

## 依赖未安装

基础离线路径只需要锁定基础依赖和 dev group：

```text
uv sync --all-groups --locked
```

真实视频 smoke 缺少 `cv2` 时安装 `video` extra：

```text
uv sync --all-groups --extra video --locked
```

加密 Feishu inbound 缺少 `cryptography` 时安装 `feishu-inbound`；long connection 缺少
`lark-oapi` 时安装 `feishu-live`。不要为了离线 Demo 安装这些 optional extras。

## 配置错误

使用与命令匹配的样例配置检查：

```text
uv run --locked labcourt validate-config --config configs/default.yaml --json
uv run --locked labcourt validate-config --config configs/demo.yaml --json
uv run --locked labcourt validate-config --config configs/pilot.yaml --json
```

外部 HTTP provider 必须在 profile 中声明 endpoint 和 API key 的环境变量名；环境变量值
缺失时，配置解析或 provider 启动会 fail closed。默认 `default.yaml`/`demo.yaml` 的 fake
provider 不需要网络或密钥。

## Demo preflight 失败

个人 API 与校园平台都应先执行 `--check`：

```text
uv run --locked labcourt demo api --output .labcourt-local/labcourt-demo --port 8877 --check
uv run --locked labcourt demo platform --output .labcourt-local/labcourt-platform-demo --input inputs/goggles-missing.mp4 --port 8877 --check
```

预检失败时先确认输出目录、输入 MP4、端口和已生成 authority 工件；不要删除或覆盖冲突的
SQLite/receipt 文件来绕过检查。Feishu sandbox 则运行 `labcourt.cmd feishu preflight`。

## Pilot 的 typed failure

Pilot 失败会返回类型化失败状态或退出码，不应被当作成功运行。常见边界包括输入视频
不存在、运行工件缺失/哈希不一致、已有任务运行，以及 provider 不可用。

```text
uv run --locked labcourt pilot --help
uv run --locked labcourt pilot run --config configs/pilot.yaml --video inputs/goggles-missing.mp4 --run-id <new_run_id> --json
```

确认原运行不能恢复时，保留已有失败工件并使用新的匿名 `run-id`；不要把 provider failure
改写成空结果，也不要将 unknown delivery 自动重试为成功。

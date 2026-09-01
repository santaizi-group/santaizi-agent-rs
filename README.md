# santaizi-agent-rs

三太子（Santaizi）监控的 **Rust 探针**（可选实现；默认安装仍是 Go 探针 [`santaizi-agent`](https://github.com/santaizi-group/santaizi-agent)）。
与现网 [`santaizi-dashboard`](https://github.com/santaizi-group/santanzi-dashboard) 互通。

仓库：[`santaizi-group/santaizi-agent-rs`](https://github.com/santaizi-group/santaizi-agent-rs)。

线协议权威来源是 [`santaizi-agent/proto/santaizi.proto`](https://github.com/santaizi-group/santaizi-agent/blob/main/proto/santaizi.proto)。
本仓 `proto/santaizi.proto` 是 vendored 拷贝：单独 clone 即可编译；改协议后把权威文件拷进来，CI 会 `diff` 检查漂移。

## 构建与运行

需要 `protoc` 与较新的稳定版 Rust（edition 2024）。

```bash
cargo build --release
./target/release/santaizi-agent-rs -s panel.example.com:5555 -p <secret>            # v2（默认）
./target/release/santaizi-agent-rs -s panel.example.com:5555 -p <secret> --protocol v1
./target/release/santaizi-agent-rs -c /path/agent.yaml --tls
```

面板一键安装（Linux amd64 / arm64，需本仓已发布 `v*` Release）：

```bash
curl -fSL https://raw.githubusercontent.com/santaizi-group/santanzi-dashboard/main/script/install_agent_rs.sh | bash -s -- install_agent panel.example.com 5555 <secret> --clean-install --confirm-clean-install [--tls]
```

## 配置

键名与 Go 探针对齐的子集，见 [`config.example.yaml`](./config.example.yaml)。
环境变量 `SANTAIZI_SERVER` / `SANTAIZI_CLIENT_SECRET` 可覆盖。默认路径 `/etc/santaizi/agent.yaml`。

## 测试与发版

本地与 CI 相同：

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

`main` / `release/**` 的 push 与 PR 会跑上述检查，并比对 vendored proto 与 Go 探针仓。

Go 探针协议变更后同步：

```bash
cp ../santaizi-agent/proto/santaizi.proto proto/santaizi.proto
```

打 tag `vMAJOR.MINOR.PATCH`（允许 v0.x）会构建并发布 `linux/amd64`、`linux/arm64` zip。

## 当前能力

- **v2 通路（默认）**：Control（hello → 凭证/endpoint 指派，15s AgentRuntime，24h 刷新凭证）+ Ingest（hello → 1s 批量上送 → ack）。事件对齐 Go 探针：启动/退出 LIFECYCLE、HOST（10m + IP 变化）、STATE（5s）、HEARTBEAT（10s）；`event_id` = SHA256(node‖session‖seq) 前 16 字节。
- **v1 回退**（`--protocol v1`）：unary `ReportSystemInfo` + 周期 `ReportSystemState`。
- 认证：metadata `client_secret`；`tls: true` 时启动会 Enroll 设备证（`<data_dir>/pki/{client.key,client.crt,ca.crt}`），Control/Ingest 走 mTLS。仅当面板返回 `Unimplemented` 才回退密钥。提前 7 天 Renew。
- 可靠性：内存队列保留至 ack（上限 4096，满丢最旧），断流 10s 重连；**无 WAL**，重启丢未确认事件。
- 身份：16 字节 node UUID 持久化 `<data_dir>/identity`（0600），每进程新 session。
- 采集：CPU / 内存 / swap / 磁盘 / 网卡 / load / 进程 / Linux sockstat 连接数 / uptime。
- IP 与归属地自查（Cloudflare `/cdn-cgi/trace`）。
- 明文或 TLS（webpki 根证书；自签用 `tls_ca_file`）。

## 明确不做（相对 Go 探针）

| 能力 | 说明 |
| ---- | ---- |
| WAL 可靠重放 | 内存队列；断网超上限或重启会丢事件 |
| 服务探测 | HTTP / ICMP / TCP；收到 ProbeRequest 回「不支持」 |
| NAT 穿透 | 收到 NATOpenRequest 回拒绝 |
| 多 endpoint | 只连 primary，不下行到从端 |
| RealtimeSnapshot / Ping | 未实现 |
| insecure_tls | rustls 不支持跳过校验，用 `tls_ca_file` |
| Windows 服务 / `agent edit` / `service install` | 未实现 |

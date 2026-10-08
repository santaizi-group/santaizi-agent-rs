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
curl -fSL https://raw.githubusercontent.com/santaizi-group/santanzi-dashboard/main/script/install_agent_rs.sh | bash -s -- install_agent panel.example.com 5555 <secret> --clean-install --confirm-clean-install [--tls] [--server-ip <主端IP>]
```

能力开关、IP 上报和 `--server-ip` 与 Go 探针安装脚本相同，写入配置和拨号缓存；服务进程只带 `--config`。

本机升级（保留配置 / 身份；同一条命令会识别 Rust 并从本仓换包）：

```bash
curl -fSL https://raw.githubusercontent.com/santaizi-group/santanzi-dashboard/main/script/upgrade_agent.sh | bash
```

## 配置

键名与 Go 探针对齐的子集，见 [`config.example.yaml`](./config.example.yaml)。默认路径 `/etc/santaizi/agent.yaml`。

优先级：**默认 < yaml < 环境变量 < CLI**。环境变量覆盖全部标量键：`SANTAIZI_` + 大写下划线，嵌套键用 `_` 拼接（如 `SANTAIZI_SERVER`、`SANTAIZI_CAPABILITIES_HTTP_PROBE`、`SANTAIZI_TELEMETRY_STATE_INTERVAL`）；布尔接受 `true/false/1/0`，布尔/数字解析失败会拒绝启动。

Go 全量 yaml 中本实现不读的键（`dns`、`ip_report_interface`、`telemetry.wal` 等）静默忽略，可直接共用同一份配置。

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

- **v2 通路（默认）**：Control（hello → 凭证/endpoint 指派，15s AgentRuntime，24h 刷新凭证）+ 按指派对 **primary 与从端** 各开 Ingest（hello → 1s 批量上送 → ack；空闲时 RealtimeSnapshot 与 15s Ping）。事件对齐 Go 探针：启动/退出 LIFECYCLE、HOST（10m + IP 变化）、STATE（5s）、HEARTBEAT（10s）；`event_id` = SHA256(node‖session‖seq) 前 16 字节。
- **v1 回退**（`--protocol v1`）：unary `ReportSystemInfo` + 周期 `ReportSystemState`。
- 认证：metadata `client_secret`；`tls: true` 时启动会 Enroll 设备证（`<data_dir>/pki/{client.key,client.crt,ca.crt}`），Control/Ingest 走 mTLS。仅当面板返回 `Unimplemented` 才回退密钥。到期前 `telemetry.cert_renew_days`（默认 7）天 Renew。**Enrollment 仅 v2 通路生效**；`--protocol v1` 无设备证，`tls: true` 只做 CA/根证书校验。
- 可靠性：Segment WAL（`{data_dir}/wal`，帧格式与 Go 探针相同）。按 endpoint ack 后回收；压力到 85% 把 STATE 收成 1 分钟 rollup，顶满写 data-loss。重启重放未确认事件。新从端不回放本 session 更早的历史。
- 身份：16 字节 node UUID 持久化 `<data_dir>/identity`（0600），每进程新 session。
- 采集：CPU / 内存 / swap / 磁盘 / 网卡 / load / 进程 / Linux sockstat 连接数 / uptime / 虚拟化；温度需 `capabilities.temperature`。`capabilities.gpu` 时上报型号和第一张卡利用率（nvidia-smi，失败再 rocm-smi）。`nic_allowlist` / `hard_drive_partition_allowlist` 非空时只统计列表内项。`ip_report_interface` 非空时流量和公网 IP 自查只走该网卡。
- 服务探测：HTTP / ICMP / TCP。HTTP 使用 Chrome 系 ClientHello，并校验 Alt-Svc（`h3*` 走 HTTP/3）。ICMP 优先走 Linux ping socket（SOCK_DGRAM，受 `net.ipv4.ping_group_range` 限制）；不支持时回退 raw socket（需 root 或 `CAP_NET_RAW`）。
- NAT：`capabilities.nat` 默认开启。控制流下发后向目标 TCP 建连，再走 `SantaiziNATService/NATStream`。
- IP 与归属地自查：双栈并行查 Cloudflare `/cdn-cgi/trace`，合并为 `v4/v6`；`xx`/`t1` 忽略；`use_ipv6_countrycode: true` 时归属地取 v6；双栈均失败且周期大于 60 秒时 1 分钟快重试。
- 拨号：自定义 `dns`（空则轮换内置公共 DNS）。成功解析写入 `{data_dir}/endpoint-cache.json`，失败用缓存。`insecure_tls` / `-k` 跳过证书校验，仅测试。
- 明文或 TLS（webpki 根证书；自签用 `tls_ca_file` 或 Enrollment CA）。

## 明确不做（相对 Go 探针）

| 能力 | 说明 |
| ---- | ---- |
| 非 Linux | 只发 linux amd64 / arm64 |
| Windows 服务 / `agent edit` / `service install` | 安装仍走面板脚本 |
| v1 通路 | 保留 unary 回退，不补 Enrollment、WAL、探测 |
| ClientHello 字节级一致 | HTTP 探测是 Chrome 系指纹，不是 Go `HelloChrome_Auto` 的逐字节拷贝 |
| ICMP 只能 raw | 保留 ping socket 优先。无 `CAP_NET_RAW` 时 Go 会失败 |

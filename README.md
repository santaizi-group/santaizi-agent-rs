# santaizi-agent-rs

三太子（Santaizi）监控的 Rust 探针。与现网 Go 面板（`santaizi-dashboard`）互通。
线协议权威来源是 `santaizi-agent/proto/santaizi.proto`；本仓 `proto/santaizi.proto`
是 vendored 拷贝（改协议时需人工同步，CI 会 diff 检查漂移）。

## 当前能力

- **v2 通路（默认）**：Control 流（hello → 凭证/endpoint 指派，15s 一次 AgentRuntime，
  24h 断流刷新凭证）+ Ingest 流（hello → 1s 批量上送 → ack 推进）。事件模型对齐 Go 探针：
  启动/退出 LIFECYCLE、HOST（10m 周期 + IP 变化）、STATE（5s）、HEARTBEAT（10s），
  event_id = SHA256(node‖session‖seq) 前 16 字节。
- **v1 回退通路**（`--protocol v1`）：unary `ReportSystemInfo` + 周期 `ReportSystemState`。
- 认证：metadata `client_secret`（v2 Control 无证书时同样回退共享密钥）。
- 可靠性：内存队列保留至面板 ack（上限 4096 条，满丢最旧），断流重连 10s 固定间隔；
  **无 WAL**，进程重启丢未确认事件（新 session 序号重排，面板按 session 幂等去重）。
- 身份：16 字节 node UUID 持久化 `<data_dir>/identity`（0600），每进程新 session。
- 采集：CPU / 内存 / swap / 磁盘（fstype 白名单 + `/` 回退）/ 网卡流量与速率 /
  load / 进程数 / TCP/UDP 连接数（Linux `sockstat`）/ uptime / 启动时间。
- IP 与归属地自查（Cloudflare `/cdn-cgi/trace`）。
- 明文或 TLS（webpki 根证书，`tls_ca_file` 支持自签 CA）。

## 明确不做（与 Go 探针的差距，按优先级）

| 能力 | 说明 |
| ---- | ---- |
| WAL 可靠重放 | 现为内存队列；断网超队列上限或重启会丢事件（无 rollup/降采样/数据丢失事实） |
| 服务探测 | HTTP（uTLS 伪装）/ ICMP / TCP；收到 ProbeRequest 回「不支持」错误结果 |
| NAT 穿透 | 收到 NATOpenRequest 回拒绝 |
| Enrollment | mTLS 设备证书签发/续期（面板 `require_agent_mtls=true` 时不可用） |
| 多 endpoint | 只连 primary，不下行到 Collector |
| RealtimeSnapshot / Ping | 实时快照与 RTT 测量（batch 通路已够面板落库与在线判定） |
| GPU / 温度 | Go 探针同样默认关闭 |
| insecure_tls | tonic 0.14/rustls 不支持跳过证书校验，用 `tls_ca_file` 代替 |
| 非 Linux 连接数 | sockstat 之外的平台 tcp/udp_conn_count 报 0 |
| Windows 服务 / `agent edit` / `service install` | 安装与交互配置 |

## 构建与运行

```bash
cargo build --release   # 需要 protoc
./target/release/santaizi-agent-rs -s panel.example.com:5555 -p <secret>            # v2（默认）
./target/release/santaizi-agent-rs -s panel.example.com:5555 -p <secret> --protocol v1
./target/release/santaizi-agent-rs -c /path/agent.yaml --tls
```

## 配置（yaml，键名与 Go 探针对齐的子集）

见 `config.example.yaml`。环境变量 `SANTAIZI_SERVER` / `SANTAIZI_CLIENT_SECRET` 可覆盖。
默认路径 `/etc/santaizi/agent.yaml`。

## 测试

```bash
cargo test   # 采集单测 + v1/v2 mock 面板 wire 级集成测试
```

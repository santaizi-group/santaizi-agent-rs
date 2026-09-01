use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::path::Path;

/// 与 Go 探针对齐的配置键子集（santaizi-agent/model/model.go）。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// 面板 gRPC 地址 host:port
    pub server: String,
    /// 服务器接入密钥（面板创建主机时生成）
    pub client_secret: String,
    pub tls: bool,
    pub insecure_tls: bool,
    pub tls_ca_file: String,
    /// State 上报间隔秒数（沿用 Go 遗留键 report_delay）
    pub report_delay: u64,
    /// IP / 归属地刷新周期秒数
    pub ip_report_period: u64,
    /// 固定国家码，非空时覆盖自查结果
    pub country_code: String,
    pub debug: bool,
    /// 上报通路：v2（默认，Control+Ingest 流，对齐 Go 探针）或 v1（unary 回退）
    pub protocol: String,
    pub telemetry: TelemetryConfig,
}

/// v2 通路子配置，键对齐 Go 探针 telemetry.* 子集。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// 身份与后续 WAL 的数据目录
    pub data_dir: String,
    pub state_interval: u64,
    pub heartbeat_interval: u64,
    pub host_interval: u64,
    pub batch_size: usize,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            data_dir: "/var/lib/santaizi-agent".into(),
            state_interval: 5,
            heartbeat_interval: 10,
            host_interval: 600,
            batch_size: 256,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: "localhost:5555".into(),
            client_secret: String::new(),
            tls: false,
            insecure_tls: false,
            tls_ca_file: String::new(),
            report_delay: 5,
            ip_report_period: 1800,
            country_code: String::new(),
            debug: false,
            protocol: "v2".into(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_yaml::from_str(&text)
                .with_context(|| format!("解析配置 {} 失败", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("读取配置 {} 失败", path.display())),
        }
    }

    /// 只补最常用的两个键，其余走 yaml / CLI。
    pub fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("SANTAIZI_SERVER") {
            self.server = v;
        }
        if let Ok(v) = std::env::var("SANTAIZI_CLIENT_SECRET") {
            self.client_secret = v;
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.client_secret.is_empty() {
            bail!("缺少 client_secret（yaml 键 client_secret 或 CLI -p/--password）");
        }
        if !self.client_secret.chars().all(|c| c.is_ascii_graphic()) {
            bail!("client_secret 含非法字符（需为可见 ASCII）");
        }
        if !(1..=3600).contains(&self.report_delay) {
            bail!("report_delay 需在 1-3600 秒之间");
        }
        if self.insecure_tls {
            // tonic 0.14/rustls 不提供跳过证书校验；不是默认值错误，是能力边界。
            bail!("MVP 暂不支持 insecure_tls；自签证书请用 tls_ca_file 指定 CA");
        }
        if self.protocol != "v1" && self.protocol != "v2" {
            bail!("protocol 只能是 v1 或 v2");
        }
        if !(1..=3600).contains(&self.telemetry.state_interval) {
            bail!("telemetry.state_interval 需在 1-3600 秒之间");
        }
        if !(1..=1024).contains(&self.telemetry.batch_size) {
            bail!("telemetry.batch_size 需在 1-1024 之间");
        }
        if self.telemetry.data_dir.is_empty() {
            bail!("telemetry.data_dir 不能为空");
        }
        Ok(())
    }
}

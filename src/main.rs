use clap::{ArgAction, Parser};
use santaizi_agent_rs::config;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "santaizi-agent-rs",
    version,
    disable_version_flag = true,
    about = "三太子监控 Rust 探针（默认 v2 Control/Ingest）"
)]
struct Cli {
    /// 显示版本（缺密钥时也能打）
    #[arg(short = 'v', short_alias = 'V', long = "version", action = ArgAction::Version)]
    version: (),
    /// 配置文件路径
    #[arg(short, long, default_value = "/etc/santaizi/agent.yaml")]
    config: PathBuf,
    /// 面板 gRPC 地址 host:port
    #[arg(short, long)]
    server: Option<String>,
    /// 服务器接入密钥
    #[arg(short, long)]
    password: Option<String>,
    /// 启用 TLS（webpki 根证书，可用 tls_ca_file 指定 CA）
    #[arg(long)]
    tls: bool,
    /// 跳过证书校验（仅测试）
    #[arg(short = 'k', long)]
    insecure: bool,
    /// State 上报间隔秒数（1-3600，仅 v1 通路）
    #[arg(long)]
    report_delay: Option<u64>,
    /// 公网 IP 更新间隔（秒）
    #[arg(short = 'u', long)]
    ip_report_period: Option<u64>,
    /// 手填国家/区域识别码
    #[arg(long)]
    country_code: Option<String>,
    /// 优先使用 IPv6 位置信息
    #[arg(long)]
    use_ipv6_countrycode: bool,
    /// 公网 IP 探测与流量统计绑定的网卡名
    #[arg(long)]
    ip_report_interface: Option<String>,
    /// 可靠探测数据目录
    #[arg(long)]
    data_dir: Option<String>,
    /// 上报通路：v2（默认）或 v1
    #[arg(long)]
    protocol: Option<String>,
    /// debug 日志
    #[arg(short = 'd', long)]
    debug: bool,
    #[arg(long)]
    disable_cpu: bool,
    #[arg(long)]
    disable_memory: bool,
    #[arg(long)]
    disable_disk: bool,
    #[arg(long)]
    disable_network: bool,
    #[arg(long)]
    disable_connections: bool,
    #[arg(long)]
    disable_processes: bool,
    #[arg(long)]
    disable_host_info: bool,
    #[arg(long)]
    disable_ip_report: bool,
    #[arg(long)]
    disable_http_probe: bool,
    #[arg(long)]
    disable_icmp_probe: bool,
    #[arg(long)]
    disable_tcp_probe: bool,
    #[arg(long)]
    disable_nat: bool,
    /// 采集温度
    #[arg(long)]
    temperature: bool,
    /// 采集 GPU
    #[arg(long)]
    gpu: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // 分层：默认 < yaml < env < CLI（CLI 最高）。
    let mut cfg = config::Config::load(&cli.config)?;
    cfg.apply_env()?;
    if let Some(v) = cli.server {
        cfg.server = v;
    }
    if let Some(v) = cli.password {
        cfg.client_secret = v;
    }
    cfg.tls = cfg.tls || cli.tls;
    cfg.insecure_tls = cfg.insecure_tls || cli.insecure;
    if let Some(v) = cli.report_delay {
        cfg.report_delay = v;
    }
    if let Some(v) = cli.ip_report_period {
        cfg.ip_report_period = v;
    }
    if let Some(v) = cli.country_code {
        cfg.country_code = v;
    }
    if cli.use_ipv6_countrycode {
        cfg.use_ipv6_countrycode = true;
    }
    if let Some(v) = cli.ip_report_interface {
        cfg.ip_report_interface = v;
    }
    if let Some(v) = cli.data_dir {
        cfg.telemetry.data_dir = v;
    }
    if let Some(v) = cli.protocol {
        cfg.protocol = v;
    }
    cfg.debug = cfg.debug || cli.debug;
    if cli.disable_cpu {
        cfg.capabilities.cpu = false;
    }
    if cli.disable_memory {
        cfg.capabilities.memory = false;
    }
    if cli.disable_disk {
        cfg.capabilities.disk = false;
    }
    if cli.disable_network {
        cfg.capabilities.network = false;
    }
    if cli.disable_connections {
        cfg.capabilities.connections = false;
    }
    if cli.disable_processes {
        cfg.capabilities.processes = false;
    }
    if cli.disable_host_info {
        cfg.capabilities.host_info = false;
    }
    if cli.disable_ip_report {
        cfg.capabilities.ip_report = false;
    }
    if cli.disable_http_probe {
        cfg.capabilities.http_probe = false;
    }
    if cli.disable_icmp_probe {
        cfg.capabilities.icmp_probe = false;
    }
    if cli.disable_tcp_probe {
        cfg.capabilities.tcp_probe = false;
    }
    if cli.disable_nat {
        cfg.capabilities.nat = false;
    }
    if cli.temperature {
        cfg.capabilities.temperature = true;
    }
    if cli.gpu {
        cfg.capabilities.gpu = true;
    }
    cfg.normalize();
    cfg.validate()?;

    let filter = if cfg.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()),
        )
        .init();

    if cfg.insecure_tls {
        tracing::warn!("已跳过 TLS 证书校验（insecure_tls），仅用于测试");
    }

    let version = concat!(env!("CARGO_PKG_VERSION"), "-rs");
    tracing::info!(version, server = %cfg.server, tls = cfg.tls, protocol = %cfg.protocol, "santaizi-agent-rs 启动");
    match cfg.protocol.as_str() {
        "v1" => santaizi_agent_rs::report::run(cfg, version).await,
        _ => santaizi_agent_rs::v2::run(cfg, version).await,
    }
}

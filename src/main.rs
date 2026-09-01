use clap::Parser;
use santaizi_agent_rs::config;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "santaizi-agent-rs",
    version,
    about = "三太子监控 Rust 探针（默认 v2 Control/Ingest）"
)]
struct Cli {
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
    /// 跳过证书校验（MVP 暂不支持，启动会报错）
    #[arg(short = 'k', long)]
    insecure: bool,
    /// State 上报间隔秒数（1-3600，仅 v1 通路）
    #[arg(long)]
    report_delay: Option<u64>,
    /// 上报通路：v2（默认）或 v1
    #[arg(long)]
    protocol: Option<String>,
    /// debug 日志
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut cfg = config::Config::load(&cli.config)?;
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
    if let Some(v) = cli.protocol {
        cfg.protocol = v;
    }
    cfg.debug = cfg.debug || cli.debug;
    cfg.apply_env();
    cfg.validate()?;

    let filter = if cfg.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()),
        )
        .init();

    let version = env!("CARGO_PKG_VERSION");
    tracing::info!(version, server = %cfg.server, tls = cfg.tls, protocol = %cfg.protocol, "santaizi-agent-rs 启动");
    match cfg.protocol.as_str() {
        "v1" => santaizi_agent_rs::report::run(cfg, version).await,
        _ => santaizi_agent_rs::v2::run(cfg, version).await,
    }
}

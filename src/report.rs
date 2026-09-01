use crate::config::Config;
use crate::monitor::Monitor;
use crate::netip::{self, IpInfo};
use crate::pb::santaizi_service_client::SantaiziServiceClient;
use anyhow::{Context, Result};
use std::time::Duration;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, service::interceptor::InterceptedService};
use tracing::{info, warn};

const RPC_TIMEOUT: Duration = Duration::from_secs(10);
pub const IP_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// client_secret metadata 注入器，v1/v2 通路共用。
pub fn secret_interceptor(
    secret: &str,
) -> Result<impl Fn(Request<()>) -> std::result::Result<Request<()>, tonic::Status> + Clone> {
    let value = MetadataValue::try_from(secret.to_string()).context("client_secret 含非法字符")?;
    Ok(move |mut req: Request<()>| {
        req.metadata_mut().insert("client_secret", value.clone());
        Ok(req)
    })
}

pub fn build_channel(cfg: &Config) -> Result<Channel> {
    let scheme = if cfg.tls { "https" } else { "http" };
    let mut endpoint = Endpoint::from_shared(format!("{scheme}://{}", cfg.server))
        .context("server 地址无效，应为 host:port")?
        .connect_timeout(Duration::from_secs(5))
        .timeout(RPC_TIMEOUT);
    if cfg.tls {
        let mut tls = ClientTlsConfig::new().with_webpki_roots();
        if !cfg.tls_ca_file.is_empty() {
            let pem = std::fs::read(&cfg.tls_ca_file).context("读取 tls_ca_file 失败")?;
            tls = tls.ca_certificate(Certificate::from_pem(pem));
        }
        endpoint = endpoint.tls_config(tls).context("TLS 配置失败")?;
    }
    Ok(endpoint.connect_lazy())
}

pub async fn report_host<I: Interceptor>(
    client: &mut SantaiziServiceClient<InterceptedService<Channel, I>>,
    cfg: &Config,
    monitor: &mut Monitor,
    last: &mut IpInfo,
    version: &str,
) {
    let fetched = tokio::task::spawn_blocking(|| netip::fetch_ip_info(IP_FETCH_TIMEOUT)).await;
    match fetched {
        Ok(Ok(info)) => {
            if info != *last {
                *last = info;
            }
        }
        Ok(Err(e)) => {
            if last.ip.is_empty() {
                warn!(error = %e, "IP 自查失败，Host 暂不带 IP/归属地");
            }
        }
        Err(e) => warn!(error = %e, "IP 自查任务异常"),
    }

    let country = if cfg.country_code.is_empty() {
        last.country_code.clone()
    } else {
        cfg.country_code.clone()
    };
    let host = monitor.host(&last.ip, &country, version);
    match client.report_system_info(host).await {
        Ok(resp) => info!(proced = resp.get_ref().proced, "Host 已上报"),
        Err(e) => warn!(error = %e, "Host 上报失败"),
    }
}

pub async fn run(cfg: Config, version: &str) -> Result<()> {
    let channel = build_channel(&cfg)?;
    let mut client =
        SantaiziServiceClient::with_interceptor(channel, secret_interceptor(&cfg.client_secret)?);

    let mut monitor = Monitor::new();
    let mut last_ip = IpInfo::default();

    // 启动即报一次 Host；之后按 ip_report_period 刷新，IP 变化时重报。
    report_host(&mut client, &cfg, &mut monitor, &mut last_ip, version).await;

    let mut state_tick = tokio::time::interval(Duration::from_secs(cfg.report_delay.max(1)));
    let mut ip_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(cfg.ip_report_period.max(60)),
        Duration::from_secs(cfg.ip_report_period.max(60)),
    );

    loop {
        tokio::select! {
            _ = state_tick.tick() => {
                let state = monitor.collect_state();
                if let Err(e) = client.report_system_state(state).await {
                    // Channel 内部懒重连，下个周期自动恢复。
                    warn!(error = %e, "State 上报失败，下个周期重试");
                }
            }
            _ = ip_tick.tick() => {
                let before = last_ip.clone();
                report_host(&mut client, &cfg, &mut monitor, &mut last_ip, version).await;
                let _ = before;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("收到退出信号，停止上报");
                break;
            }
        }
    }
    Ok(())
}

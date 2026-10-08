use crate::config::Config;
use crate::monitor::Monitor;
use crate::netip::{self, IpInfo};
use crate::pb::santaizi_service_client::SantaiziServiceClient;
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
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

pub fn tls_server_name(server: &str) -> String {
    if let Some(rest) = server.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_string();
    }
    match server.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            host.to_string()
        }
        _ => server.to_string(),
    }
}

pub fn build_channel(cfg: &Config) -> Result<Channel> {
    build_channel_with_identity(cfg, None, false)
}

/// `streaming=true` 时不加整段 RPC timeout，避免 Control/Ingest 长连接被 10s 掐断。
pub fn build_channel_with_identity(
    cfg: &Config,
    identity: Option<&Identity>,
    streaming: bool,
) -> Result<Channel> {
    build_endpoint_channel(
        &cfg.server,
        cfg.tls,
        cfg.insecure_tls,
        &cfg.tls_ca_file,
        &[],
        identity,
        streaming,
    )
}

/// 按单个 endpoint 建连。`insecure_tls` 跳过服务端证书校验（仅测试，调用方须打 Warning）。
pub fn build_endpoint_channel(
    server: &str,
    tls: bool,
    insecure_tls: bool,
    tls_ca_file: &str,
    extra_ca_pem: &[u8],
    identity: Option<&Identity>,
    streaming: bool,
) -> Result<Channel> {
    let scheme = if tls { "https" } else { "http" };
    let mut endpoint = Endpoint::from_shared(format!("{scheme}://{server}"))
        .context("server 地址无效，应为 host:port")?
        .connect_timeout(Duration::from_secs(5))
        // 半开 TCP 检测：h2 keepalive ping + TCP keepalive 双保险
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(Duration::from_secs(60)));
    if !streaming {
        endpoint = endpoint.timeout(RPC_TIMEOUT);
    }
    if tls {
        let domain = tls_server_name(server);
        if insecure_tls {
            // 自定义 verifier 不能再配 CA / webpki roots，否则 tonic 直接报错。
            let mut tls_cfg = ClientTlsConfig::new().domain_name(domain);
            if let Some(identity) = identity {
                tls_cfg = tls_cfg.identity(identity.clone());
            }
            endpoint = endpoint
                .tls_config_with_verifier(tls_cfg, Arc::new(SkipServerVerify))
                .context("TLS 配置失败")?;
        } else {
            let mut tls_cfg = ClientTlsConfig::new()
                .domain_name(domain)
                .with_webpki_roots();
            let mut pem = Vec::new();
            if !tls_ca_file.is_empty() {
                pem.extend(std::fs::read(tls_ca_file).context("读取 tls_ca_file 失败")?);
            }
            if !extra_ca_pem.is_empty() {
                if !pem.is_empty() {
                    pem.push(b'\n');
                }
                pem.extend_from_slice(extra_ca_pem);
            }
            if !pem.is_empty() {
                tls_cfg = tls_cfg.ca_certificate(Certificate::from_pem(pem));
            }
            if let Some(identity) = identity {
                tls_cfg = tls_cfg.identity(identity.clone());
            }
            endpoint = endpoint.tls_config(tls_cfg).context("TLS 配置失败")?;
        }
    }
    Ok(endpoint.connect_lazy())
}

/// 拨到已解析地址，SNI / authority 用 `target.server_name`（不带端口）。
pub fn dial_target(
    cfg: &Config,
    target: &crate::dialcache::Target,
    extra_ca_pem: &[u8],
    identity: Option<&Identity>,
    streaming: bool,
) -> Result<Channel> {
    let scheme = if cfg.tls { "https" } else { "http" };
    let mut endpoint = Endpoint::from_shared(format!("{scheme}://{}", target.dial_addr))
        .map_err(|err| anyhow::anyhow!("server 地址无效，应为 host:port: {err}"))?
        .connect_timeout(Duration::from_secs(5))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(Duration::from_secs(60)));
    if !streaming {
        endpoint = endpoint.timeout(RPC_TIMEOUT);
    }
    let origin_host = if target.server_name.contains(':') && !target.server_name.starts_with('[') {
        format!("[{}]", target.server_name)
    } else {
        target.server_name.clone()
    };
    let origin: tonic::transport::Uri = format!("{scheme}://{origin_host}")
        .parse()
        .context("dial origin")?;
    endpoint = endpoint.origin(origin);
    if cfg.tls {
        let domain = target.server_name.clone();
        if cfg.insecure_tls {
            let mut tls_cfg = ClientTlsConfig::new().domain_name(domain);
            if let Some(identity) = identity {
                tls_cfg = tls_cfg.identity(identity.clone());
            }
            endpoint = endpoint
                .tls_config_with_verifier(tls_cfg, Arc::new(SkipServerVerify))
                .context("TLS 配置失败")?;
        } else {
            let mut tls_cfg = ClientTlsConfig::new()
                .domain_name(domain)
                .with_webpki_roots();
            let mut pem = Vec::new();
            if !cfg.tls_ca_file.is_empty() {
                pem.extend(std::fs::read(&cfg.tls_ca_file).context("读取 tls_ca_file 失败")?);
            }
            if !extra_ca_pem.is_empty() {
                if !pem.is_empty() {
                    pem.push(b'\n');
                }
                pem.extend_from_slice(extra_ca_pem);
            }
            if !pem.is_empty() {
                tls_cfg = tls_cfg.ca_certificate(Certificate::from_pem(pem));
            }
            if let Some(identity) = identity {
                tls_cfg = tls_cfg.identity(identity.clone());
            }
            endpoint = endpoint.tls_config(tls_cfg).context("TLS 配置失败")?;
        }
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
    let host = monitor.host(&last.ip, &country, version, &cfg.capabilities);
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
                let state = monitor.collect_state(&cfg.capabilities);
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

/// 对齐 Go `InsecureSkipVerify`：不校验证书链、主机名和握手签名。
#[derive(Debug)]
pub struct SkipServerVerify;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::{build_endpoint_channel, tls_server_name};

    #[tokio::test]
    async fn insecure_tls_builds_without_ca() {
        let channel = build_endpoint_channel("127.0.0.1:1", true, true, "", &[], None, true);
        assert!(channel.is_ok(), "{channel:?}");
    }

    #[test]
    fn tls_server_name_strips_port() {
        assert_eq!(tls_server_name("main.i18.in:18181"), "main.i18.in");
        assert_eq!(tls_server_name("[::1]:5555"), "::1");
        assert_eq!(tls_server_name("localhost"), "localhost");
    }
}

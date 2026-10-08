//! HTTP / ICMP / TCP 服务探测。对齐 Go `cmd/agent/probe.go` 的结果口径。
//! HTTP 使用 Chrome 系 ClientHello；`h3*` 的 Alt-Svc 走 HTTP/3。ICMP/TCP 不走自定义 DNS。

use crate::config::CapabilityConfig;
use crate::pb;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::timeout;

const HTTP_FALLBACK: Duration = Duration::from_secs(30);
const ICMP_FALLBACK: Duration = Duration::from_secs(20);
const TCP_FALLBACK: Duration = Duration::from_secs(10);
const USER_AGENT: &str = "Mozilla/5.0 Santaizi-Agent";

pub async fn execute(caps: &CapabilityConfig, request: pb::ProbeRequest) -> pb::ProbeResult {
    execute_with_dns(caps, &[], request).await
}

/// `dns` 只用于 HTTP 探测（含 Alt-Svc）。空列表轮换内置公共 DNS。
pub async fn execute_with_dns(
    caps: &CapabilityConfig,
    dns: &[String],
    request: pb::ProbeRequest,
) -> pb::ProbeResult {
    let mut result = pb::ProbeResult {
        probe_id: request.probe_id.clone(),
        ..Default::default()
    };
    if request.probe_id.is_empty() {
        result.error = "probe_id is required".into();
        result.completed_at_unix_nano = now_nanos();
        return result;
    }
    match request.target {
        Some(pb::probe_request::Target::Http(http)) => {
            result.kind = pb::ProbeKind::Http as i32;
            if !caps.http_probe {
                result.error = "HTTP probe capability is disabled".into();
            } else {
                http_probe(http, dns, &mut result).await;
            }
        }
        Some(pb::probe_request::Target::Icmp(icmp)) => {
            result.kind = pb::ProbeKind::Icmp as i32;
            if !caps.icmp_probe {
                result.error = "ICMP probe capability is disabled".into();
            } else {
                icmp_probe(icmp, &mut result).await;
            }
        }
        Some(pb::probe_request::Target::Tcp(tcp)) => {
            result.kind = pb::ProbeKind::Tcp as i32;
            if !caps.tcp_probe {
                result.error = "TCP probe capability is disabled".into();
            } else {
                tcp_probe(tcp, &mut result).await;
            }
        }
        None => {
            result.error = "unsupported probe kind".into();
        }
    }
    result.completed_at_unix_nano = now_nanos();
    result
}

pub fn bounded_timeout(milliseconds: u32, fallback: Duration) -> Duration {
    if milliseconds == 0 {
        return fallback;
    }
    let timeout = Duration::from_millis(milliseconds as u64);
    timeout.clamp(Duration::from_secs(1), Duration::from_secs(60))
}

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn join_host_port(host: &str, port: u32) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn lookup_ip(host_or_ip: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host_or_ip.parse::<IpAddr>() {
        return Ok(ip);
    }
    let mut addrs = tokio::net::lookup_host((host_or_ip, 0))
        .await
        .map_err(|e| e.to_string())?;
    addrs
        .next()
        .map(|a| a.ip())
        .ok_or_else(|| format!("cannot resolve {host_or_ip}"))
}

async fn http_probe(request: pb::HttpProbeRequest, dns: &[String], result: &mut pb::ProbeResult) {
    let parsed = match url::Url::parse(&request.url) {
        Ok(u) => u,
        Err(_) => {
            result.error = "HTTP probe requires an http or https URL".into();
            return;
        }
    };
    if (parsed.scheme() != "http" && parsed.scheme() != "https") || parsed.host_str().is_none() {
        result.error = "HTTP probe requires an http or https URL".into();
        return;
    }
    let timeout = bounded_timeout(request.timeout_ms, HTTP_FALLBACK);
    let host = parsed.host_str().unwrap_or_default().to_string();
    let Some(ip) = resolve_first(dns, &host).await else {
        result.error = format!("cannot resolve {host}");
        return;
    };
    let client = match http_client(timeout, &host, SocketAddr::new(ip, 0)) {
        Ok(c) => c,
        Err(e) => {
            result.error = e;
            return;
        }
    };
    let started = Instant::now();
    let response = match send_probe(&client, parsed.as_str(), &host).await {
        Ok(r) => r,
        Err(e) => {
            result.delay_ms = elapsed_ms(started);
            result.error = e;
            return;
        }
    };
    result.delay_ms = elapsed_ms(started);
    let alt = response
        .headers()
        .get(http::header::ALT_SVC)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    fill_http_result(&response, result);
    if let Err(err) = response.bytes().await {
        result.error = err.to_string();
        return;
    }
    if !result.error.is_empty() {
        return;
    }
    if let Some(alt) = alt.as_deref()
        && let Err(err) = validate_alt_svc(dns, &parsed, alt, timeout).await
    {
        result.successful = false;
        result.error = err;
        return;
    }
    result.successful = true;
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn http_client(timeout: Duration, host: &str, addr: SocketAddr) -> Result<wreq::Client, String> {
    wreq::Client::builder()
        .emulation(wreq_util::Emulation::Chrome144)
        .timeout(timeout)
        .connect_timeout(timeout)
        .tls_info(true)
        .resolve(host.to_string(), addr)
        .build()
        .map_err(|e| e.to_string())
}

fn probe_headers(req: wreq::RequestBuilder, host: &str) -> wreq::RequestBuilder {
    req.header(
        http::header::ACCEPT,
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    )
    .header(http::header::ACCEPT_LANGUAGE, "en-US,en;q=0.8")
    .header(http::header::USER_AGENT, USER_AGENT)
    .header(http::header::HOST, host)
}

async fn send_probe(
    client: &wreq::Client,
    url: &str,
    host: &str,
) -> Result<wreq::Response, String> {
    probe_headers(client.get(url), host)
        .send()
        .await
        .map_err(|e| e.to_string())
}

fn fill_http_result(response: &wreq::Response, result: &mut pb::ProbeResult) {
    let status = response.status();
    let code = status.as_u16() as u32;
    let mut detail = pb::HttpProbeResult {
        status_code: code,
        ..Default::default()
    };
    if let Some(info) = response.extensions().get::<wreq::tls::TlsInfo>()
        && let Some(der) = info.peer_certificate()
        && let Ok((_, cert)) = x509_parser::parse_x509_certificate(der)
    {
        detail.tls_issuer = cert
            .issuer()
            .iter_common_name()
            .next()
            .map_or_else(String::new, |cn| {
                cn.as_str().unwrap_or_default().to_string()
            });
        detail.tls_expires_at_unix = cert.validity().not_after.timestamp();
    }
    result.detail = Some(pb::probe_result::Detail::Http(detail));
    if !(200..400).contains(&status.as_u16()) {
        result.error = status_text(status);
    }
}

fn status_text(status: http::StatusCode) -> String {
    match status.canonical_reason() {
        Some(reason) => format!("{} {reason}", status.as_u16()),
        None => status.as_u16().to_string(),
    }
}

async fn resolve_first(dns: &[String], host: &str) -> Option<IpAddr> {
    let servers = dns.to_vec();
    let host = host.to_string();
    let looked = tokio::task::spawn_blocking(move || crate::dns::lookup_ips(&servers, &host)).await;
    looked
        .ok()
        .and_then(|r| r.ok())
        .and_then(|ips| ips.into_iter().next())
}

struct AltService {
    protocol: String,
    host: String,
    port: String,
}

fn parse_alt_svc(header: &str) -> Result<Vec<AltService>, String> {
    let mut out = Vec::new();
    for item in split_alt_items(header) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let Some((protocol, rest)) = item.split_once('=') else {
            return Err("alternative service: malformed Alt-Svc".into());
        };
        let rest = rest.trim();
        if !rest.starts_with('"') {
            return Err("alternative service: malformed Alt-Svc".into());
        }
        let Some(end) = rest[1..].find('"') else {
            return Err("alternative service: malformed Alt-Svc".into());
        };
        let authority = &rest[1..1 + end];
        let (host, port) = split_alt_authority(authority)?;
        out.push(AltService {
            protocol: protocol.trim().to_string(),
            host,
            port,
        });
    }
    Ok(out)
}

fn split_alt_items(header: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    for (i, ch) in header.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&header[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&header[start..]);
    out
}

fn split_alt_authority(authority: &str) -> Result<(String, String), String> {
    if let Some(port) = authority.strip_prefix(':') {
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err("alternative service: malformed Alt-Svc".into());
        }
        return Ok((String::new(), port.to_string()));
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err("alternative service: malformed Alt-Svc".into());
        };
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err("alternative service: malformed Alt-Svc".into());
        }
        return Ok((host.to_string(), port.to_string()));
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Err("alternative service: malformed Alt-Svc".into());
    };
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err("alternative service: malformed Alt-Svc".into());
    }
    Ok((host.to_string(), port.to_string()))
}

async fn validate_alt_svc(
    dns: &[String],
    original: &url::Url,
    header: &str,
    timeout: Duration,
) -> Result<(), String> {
    let services = parse_alt_svc(header)?;
    let original_host = original.host_str().unwrap_or_default();
    let original_port = original.port_or_known_default().unwrap_or(80).to_string();
    for service in services {
        if service.port.is_empty()
            || (service.host == original_host && service.port == original_port)
        {
            continue;
        }
        let host = if service.host.is_empty() {
            original_host.to_string()
        } else {
            service.host.clone()
        };
        let url = format!("https://{host}:{}/", service.port);
        if service.protocol.starts_with("h3") {
            let port: u16 = service
                .port
                .parse()
                .map_err(|_| "alternative service: bad port")?;
            http3_check(dns, &host, port, original_host, timeout).await?;
        } else {
            let Some(ip) = resolve_first(dns, &host).await else {
                return Err(format!("alternative service: cannot resolve {host}"));
            };
            let client = http_client(timeout, &host, SocketAddr::new(ip, 0))?;
            let response = send_probe(&client, &url, original_host)
                .await
                .map_err(|e| format!("alternative service: {e}"))?;
            let status = response.status();
            let body = response.bytes().await.map_err(|e| e.to_string())?;
            drop(body);
            if !(200..400).contains(&status.as_u16()) {
                return Err(status_text(status));
            }
        }
        break;
    }
    Ok(())
}

async fn http3_check(
    dns: &[String],
    connect_host: &str,
    port: u16,
    authority: &str,
    timeout: Duration,
) -> Result<(), String> {
    let Some(ip) = resolve_first(dns, connect_host).await else {
        return Err(format!(
            "alternative service: cannot resolve {connect_host}"
        ));
    };
    let addr = SocketAddr::new(ip, port);
    let check = async {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let quic =
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| e.to_string())?;
        let mut endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(|e| e.to_string())?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
        let connecting = endpoint
            .connect(addr, connect_host)
            .map_err(|e| format!("alternative service: {e}"))?;
        let conn = connecting
            .await
            .map_err(|e| format!("alternative service: {e}"))?;
        let h3_conn = h3_quinn::Connection::new(conn);
        let (mut driver, mut send) = h3::client::new(h3_conn)
            .await
            .map_err(|e| format!("alternative service: {e}"))?;
        let drive =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("https://{authority}/"))
            .body(())
            .map_err(|e| e.to_string())?;
        let mut stream = send
            .send_request(request)
            .await
            .map_err(|e| format!("alternative service: {e}"))?;
        stream
            .finish()
            .await
            .map_err(|e| format!("alternative service: {e}"))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|e| format!("alternative service: {e}"))?;
        while stream
            .recv_data()
            .await
            .map_err(|e| format!("alternative service: {e}"))?
            .is_some()
        {}
        drive.abort();
        let status = response.status();
        if !(200..400).contains(&status.as_u16()) {
            return Err(status_text(status));
        }
        Ok(())
    };
    match tokio::time::timeout(timeout, check).await {
        Ok(result) => result,
        Err(_) => Err("alternative service: HTTP/3 timed out".into()),
    }
}

async fn tcp_probe(request: pb::TcpProbeRequest, result: &mut pb::ProbeResult) {
    if request.host.trim().is_empty() || request.port == 0 || request.port > 65535 {
        result.error = "TCP probe requires a host and valid port".into();
        return;
    }
    let ip = match lookup_ip(request.host.trim()).await {
        Ok(ip) => ip,
        Err(e) => {
            result.error = e;
            return;
        }
    };
    result.detail = Some(pb::probe_result::Detail::Tcp(pb::TcpProbeResult {
        resolved_ip: ip.to_string(),
    }));
    let addr = join_host_port(&ip.to_string(), request.port);
    let timeout_d = bounded_timeout(request.timeout_ms, TCP_FALLBACK);
    let started = Instant::now();
    match timeout(timeout_d, TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            result.delay_ms = started.elapsed().as_secs_f64() * 1000.0;
            drop(stream);
            result.successful = true;
        }
        Ok(Err(e)) => {
            result.delay_ms = started.elapsed().as_secs_f64() * 1000.0;
            result.error = e.to_string();
        }
        Err(_) => {
            result.delay_ms = started.elapsed().as_secs_f64() * 1000.0;
            result.error = "tcp probe timed out".into();
        }
    }
}

async fn icmp_probe(request: pb::IcmpProbeRequest, result: &mut pb::ProbeResult) {
    if request.host.trim().is_empty() {
        result.error = "ICMP probe host is required".into();
        return;
    }
    let ip = match lookup_ip(request.host.trim()).await {
        Ok(ip) => ip,
        Err(e) => {
            result.error = e;
            return;
        }
    };
    let mut count = request.count;
    if count == 0 {
        count = 5;
    }
    if count > 10 {
        count = 10;
    }
    let timeout_d = bounded_timeout(request.timeout_ms, ICMP_FALLBACK);
    let started = Instant::now();
    match tokio::task::spawn_blocking(move || icmp_ping(ip, count, timeout_d)).await {
        Ok(Ok((sent, received, avg))) => {
            result.detail = Some(pb::probe_result::Detail::Icmp(pb::IcmpProbeResult {
                packets_sent: sent,
                packets_received: received,
            }));
            if received == 0 {
                result.delay_ms = started.elapsed().as_secs_f64() * 1000.0;
                result.error = "no ICMP reply received".into();
            } else {
                result.delay_ms = avg
                    .map(|d| d.as_secs_f64() * 1000.0)
                    .unwrap_or_else(|| started.elapsed().as_secs_f64() * 1000.0);
                result.successful = true;
            }
        }
        Ok(Err(e)) => {
            result.delay_ms = started.elapsed().as_secs_f64() * 1000.0;
            result.error = e;
        }
        Err(e) => {
            result.delay_ms = started.elapsed().as_secs_f64() * 1000.0;
            result.error = e.to_string();
        }
    }
}

// RFC 1071 16 位反码和。SOCK_RAW + IPPROTO_ICMP 内核不代算 ICMP checksum，
// 发送前需自行填充；ICMPv6 raw socket 由内核代算（默认 offset 2），DGRAM ping
// socket 整个头由内核重写，两条路径都不需要本函数。
#[cfg(unix)]
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (words, rem) = data.as_chunks::<2>();
    for w in words {
        sum += u32::from(u16::from_be_bytes(*w));
    }
    if let Some(&tail) = rem.first() {
        sum += u32::from(tail) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// 判断收到的包是否为本次探测的 echo reply。
// SOCK_RAW 的 IPv4 包自带 20 字节 IP 头；DGRAM 与 IPv6 收到的直接是 ICMP 报文。
// IPPROTO_ICMP raw socket 会收到所有 ICMP 流量，type/ident/seq 必须全部匹配。
#[cfg(unix)]
fn match_echo_reply(buf: &[u8], echo_reply: u8, ident: u16, seq: u16) -> bool {
    if buf.len() < 8 {
        return false;
    }
    let icmp = if buf[0] == echo_reply {
        buf
    } else if buf.len() >= 28 && buf[0] >> 4 == 4 {
        &buf[20..]
    } else {
        return false;
    };
    icmp[0] == echo_reply
        && u16::from_be_bytes([icmp[4], icmp[5]]) == ident
        && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
}

// Linux ping socket 内核把 echo id 覆盖为 socket 端口（net/ipv4/ping.c），
// 需从 getsockname 读回内核分配值；未 bind 时端口为 0，先 bind 到 0 触发分配。
#[cfg(unix)]
fn dgram_echo_ident(sock: &socket2::Socket, ip: IpAddr) -> Result<u16, String> {
    fn local_ident(sock: &socket2::Socket, v6: bool) -> Option<u16> {
        let local = sock.local_addr().ok()?;
        let port = if v6 {
            local.as_socket_ipv6()?.port()
        } else {
            local.as_socket_ipv4()?.port()
        };
        (port != 0).then_some(port)
    }
    let v6 = ip.is_ipv6();
    if let Some(ident) = local_ident(sock, v6) {
        return Ok(ident);
    }
    let any = if v6 {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    };
    sock.bind(&socket2::SockAddr::from(any))
        .map_err(|e| e.to_string())?;
    local_ident(sock, v6).ok_or_else(|| "cannot read echo id from ping socket".into())
}

// 优先 SOCK_DGRAM ping socket（无特权即可用，但受 net.ipv4.ping_group_range
// 限制），失败回退 SOCK_RAW（需 root/CAP_NET_RAW）。返回 (socket, echo ident,
// 是否 raw)。raw 路径上内核不覆盖 echo id，可用随机 ident。
#[cfg(unix)]
fn open_ping_socket(ip: IpAddr) -> Result<(socket2::Socket, u16, bool), String> {
    use socket2::{Domain, Protocol, Socket, Type};
    let (domain, proto) = match ip {
        IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
        IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
    };
    let dgram_err = match Socket::new(domain, Type::DGRAM, Some(proto)) {
        Ok(sock) => match dgram_echo_ident(&sock, ip) {
            Ok(ident) => return Ok((sock, ident, false)),
            Err(e) => e,
        },
        Err(e) => e.to_string(),
    };
    match Socket::new(domain, Type::RAW, Some(proto)) {
        Ok(sock) => Ok((sock, rand::random::<u16>(), true)),
        Err(e) => Err(format!(
            "cannot open ICMP socket (ping socket: {dgram_err}; raw socket: {e}); \
             需要内核 net.ipv4.ping_group_range 放开，或以 root/CAP_NET_RAW 运行"
        )),
    }
}

#[cfg(unix)]
fn icmp_ping(
    ip: IpAddr,
    count: u32,
    total: Duration,
) -> Result<(u32, u32, Option<Duration>), String> {
    use socket2::SockAddr;
    let (echo_req, echo_reply) = match ip {
        IpAddr::V4(_) => (8u8, 0u8),
        IpAddr::V6(_) => (128u8, 129u8),
    };
    let (sock, ident, raw) = open_ping_socket(ip)?;
    let dest = SockAddr::from(SocketAddr::new(ip, 0));
    let deadline = Instant::now() + total;
    let per = total / count.max(1);
    let mut sent = 0u32;
    let mut received = 0u32;
    let mut rtts = Vec::new();
    for seq in 0..count {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let wait = per.min(remaining).max(Duration::from_millis(50));
        sock.set_read_timeout(Some(wait))
            .map_err(|e| e.to_string())?;
        let mut pkt = [0u8; 16];
        pkt[0] = echo_req;
        pkt[4..6].copy_from_slice(&ident.to_be_bytes());
        pkt[6..8].copy_from_slice(&(seq as u16).to_be_bytes());
        if raw && ip.is_ipv4() {
            let sum = icmp_checksum(&pkt);
            pkt[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        let t0 = Instant::now();
        if sock.send_to(&pkt, &dest).is_err() {
            sent += 1;
            continue;
        }
        sent += 1;
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 256];
        while let Ok((n, _)) = sock.recv_from(&mut buf) {
            let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
            if match_echo_reply(bytes, echo_reply, ident, seq as u16) {
                received += 1;
                rtts.push(t0.elapsed());
                break;
            }
        }
    }
    let avg = if rtts.is_empty() {
        None
    } else {
        Some(rtts.iter().sum::<Duration>() / rtts.len() as u32)
    };
    Ok((sent, received, avg))
}

#[cfg(not(unix))]
fn icmp_ping(
    _ip: IpAddr,
    _count: u32,
    _total: Duration,
) -> Result<(u32, u32, Option<Duration>), String> {
    Err("ICMP probe is only supported on Unix".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CapabilityConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn bounded_timeout_clamps() {
        assert_eq!(bounded_timeout(0, HTTP_FALLBACK), HTTP_FALLBACK);
        assert_eq!(bounded_timeout(100, HTTP_FALLBACK), Duration::from_secs(1));
        assert_eq!(
            bounded_timeout(120_000, HTTP_FALLBACK),
            Duration::from_secs(60)
        );
        assert_eq!(
            bounded_timeout(5_000, HTTP_FALLBACK),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn alt_svc_skips_same_endpoint_and_keeps_first_other() {
        let same = parse_alt_svc(r#"h2=":443""#).unwrap();
        assert_eq!(same.len(), 1);
        assert!(same[0].host.is_empty());
        assert_eq!(same[0].port, "443");
        let mixed = parse_alt_svc(r#"h3=":443", h2="alt.example:8443""#).unwrap();
        assert_eq!(mixed[0].protocol, "h3");
        assert_eq!(mixed[1].host, "alt.example");
        assert_eq!(mixed[1].port, "8443");
        assert!(parse_alt_svc("not-a-header").is_err());
    }

    #[tokio::test]
    async fn tcp_probe_localhost() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            drop(s);
        });
        let result = execute(
            &CapabilityConfig::default(),
            pb::ProbeRequest {
                probe_id: "t1".into(),
                target: Some(pb::probe_request::Target::Tcp(pb::TcpProbeRequest {
                    host: "127.0.0.1".into(),
                    port: addr.port() as u32,
                    timeout_ms: 3000,
                })),
            },
        )
        .await;
        accept.await.unwrap();
        assert!(result.successful, "error={}", result.error);
        assert_eq!(result.kind, pb::ProbeKind::Tcp as i32);
        assert!(
            matches!(result.detail, Some(pb::probe_result::Detail::Tcp(t)) if t.resolved_ip == "127.0.0.1")
        );
    }

    #[tokio::test]
    async fn http_probe_localhost_200() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let _ = s.read(&mut buf).await;
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
        });
        let result = execute(
            &CapabilityConfig::default(),
            pb::ProbeRequest {
                probe_id: "h1".into(),
                target: Some(pb::probe_request::Target::Http(pb::HttpProbeRequest {
                    url: format!("http://127.0.0.1:{}", addr.port()),
                    timeout_ms: 3000,
                })),
            },
        )
        .await;
        server.await.unwrap();
        assert!(result.successful, "error={}", result.error);
        assert!(
            matches!(result.detail, Some(pb::probe_result::Detail::Http(h)) if h.status_code == 200)
        );
    }

    #[tokio::test]
    async fn http_probe_disabled() {
        let caps = CapabilityConfig {
            http_probe: false,
            ..CapabilityConfig::default()
        };
        let result = execute(
            &caps,
            pb::ProbeRequest {
                probe_id: "h2".into(),
                target: Some(pb::probe_request::Target::Http(pb::HttpProbeRequest {
                    url: "http://example.com/".into(),
                    timeout_ms: 1000,
                })),
            },
        )
        .await;
        assert!(!result.successful);
        assert!(result.error.contains("disabled"));
    }

    #[tokio::test]
    async fn icmp_empty_host() {
        let result = execute(
            &CapabilityConfig::default(),
            pb::ProbeRequest {
                probe_id: "i1".into(),
                target: Some(pb::probe_request::Target::Icmp(pb::IcmpProbeRequest {
                    host: "  ".into(),
                    count: 1,
                    timeout_ms: 1000,
                })),
            },
        )
        .await;
        assert!(!result.successful);
        assert!(result.error.contains("host"));
    }

    #[tokio::test]
    async fn missing_probe_id() {
        let result = execute(
            &CapabilityConfig::default(),
            pb::ProbeRequest {
                probe_id: String::new(),
                target: Some(pb::probe_request::Target::Tcp(pb::TcpProbeRequest {
                    host: "127.0.0.1".into(),
                    port: 1,
                    timeout_ms: 1000,
                })),
            },
        )
        .await;
        assert_eq!(result.error, "probe_id is required");
    }

    #[cfg(unix)]
    #[test]
    fn icmp_checksum_known_vector() {
        // RFC 1071 §3 数值示例
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(icmp_checksum(&data), 0x220d);
        assert_eq!(icmp_checksum(&[]), 0xffff);
        // 奇数长度末尾补零
        assert_eq!(icmp_checksum(&[0x01]), 0xfeff);
    }

    #[cfg(unix)]
    #[test]
    fn icmp_checksum_verifies_to_zero() {
        let mut pkt = [0u8; 16];
        pkt[0] = 8;
        pkt[4..6].copy_from_slice(&0xABCDu16.to_be_bytes());
        pkt[6..8].copy_from_slice(&9u16.to_be_bytes());
        pkt[8..].copy_from_slice(b"12345678");
        let sum = icmp_checksum(&pkt);
        assert_ne!(sum, 0);
        pkt[2..4].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(icmp_checksum(&pkt), 0);
    }

    #[cfg(unix)]
    #[test]
    fn echo_reply_matching() {
        let mut reply = [0u8; 16];
        reply[0] = 0;
        reply[4..6].copy_from_slice(&0xBEEFu16.to_be_bytes());
        reply[6..8].copy_from_slice(&3u16.to_be_bytes());
        assert!(match_echo_reply(&reply, 0, 0xBEEF, 3));
        assert!(!match_echo_reply(&reply, 0, 0xBEEF, 2));
        assert!(!match_echo_reply(&reply, 0, 0xBE00, 3));
        assert!(!match_echo_reply(&reply, 129, 0xBEEF, 3));
        // echo request（type=8）不匹配
        let mut req = reply;
        req[0] = 8;
        assert!(!match_echo_reply(&req, 0, 0xBEEF, 3));
        // 过短的包不匹配
        assert!(!match_echo_reply(&reply[..7], 0, 0xBEEF, 3));
        // SOCK_RAW v4 收到的包带 20 字节 IP 头
        let mut with_ip = [0u8; 36];
        with_ip[0] = 0x45;
        with_ip[20..].copy_from_slice(&reply);
        assert!(match_echo_reply(&with_ip, 0, 0xBEEF, 3));
        assert!(!match_echo_reply(&with_ip, 0, 0xBEEF, 4));
    }

    #[cfg(unix)]
    #[test]
    fn icmp_ping_localhost() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        match icmp_ping(ip, 3, Duration::from_secs(3)) {
            Ok((sent, received, avg)) => {
                assert_eq!(sent, 3);
                assert!(received > 0, "sent {sent} echo requests, got no reply");
                assert!(avg.is_some());
            }
            // 非 root 且 ping_group_range 未放开时两条 socket 路径都不可用，跳过
            Err(e) => eprintln!("icmp_ping_localhost skipped: {e}"),
        }
    }
}

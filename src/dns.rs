//! 拨号用 DNS。空列表轮换 Go `DNSServersAll`，不走系统解析器。

use anyhow::{Context, Result, anyhow, bail};
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 与 Go `util.DNSServersAll` 顺序一致。
pub const DNS_SERVERS_ALL: &[&str] = &[
    "8.8.4.4:53",
    "223.5.5.5:53",
    "94.140.14.140:53",
    "119.29.29.29:53",
    "[2001:4860:4860::8844]:53",
    "[2400:3200::1]:53",
    "[2a10:50c0::1:ff]:53",
    "[2402:4e00::]:53",
];

const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// `servers` 为空时用 [`DNS_SERVERS_ALL`]。字面 IP 不发查询。
/// 非空则只用这些 `host:port`，按当前秒轮换起点，失败再试下一个。
pub fn lookup_ips(servers: &[String], host: &str) -> Result<Vec<IpAddr>> {
    let host = host.trim();
    if host.is_empty() {
        bail!("dns host is empty");
    }
    if let Some(ip) = parse_literal(host) {
        return Ok(vec![ip]);
    }
    let owned: Vec<String> = if servers.is_empty() {
        DNS_SERVERS_ALL.iter().map(|s| (*s).to_string()).collect()
    } else {
        servers.to_vec()
    };
    if owned.is_empty() {
        bail!("dns server list is empty");
    }
    let host = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("santaizi-dns".into())
        .spawn(move || {
            let result = (|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("dns runtime")?;
                runtime.block_on(lookup_rotated(&owned, &host))
            })();
            let _ = tx.send(result);
        })
        .context("spawn dns lookup")?;
    rx.recv().map_err(|_| anyhow!("dns lookup thread exited"))?
}

fn parse_literal(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse() {
        return Some(ip);
    }
    let bare = host.strip_prefix('[')?.strip_suffix(']')?;
    bare.parse().ok()
}

fn rotate_start(len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs as usize) % len
}

async fn lookup_rotated(servers: &[String], host: &str) -> Result<Vec<IpAddr>> {
    let start = rotate_start(servers.len());
    let mut last = None;
    for offset in 0..servers.len() {
        let server = &servers[(start + offset) % servers.len()];
        match query_one(server, host).await {
            Ok(ips) if !ips.is_empty() => return Ok(ips),
            Ok(_) => last = Some(anyhow!("cannot resolve {host}")),
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("cannot resolve {host}")))
}

async fn query_one(server: &str, host: &str) -> Result<Vec<IpAddr>> {
    let addr: SocketAddr = server
        .trim()
        .parse()
        .with_context(|| format!("invalid DNS server {server:?}"))?;
    let mut connection = ConnectionConfig::udp();
    connection.port = addr.port();
    let name_server = NameServerConfig::new(addr.ip(), false, vec![connection]);
    let config = ResolverConfig::from_name_servers(vec![name_server]);
    let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    {
        let opts: &mut ResolverOpts = builder.options_mut();
        opts.timeout = QUERY_TIMEOUT;
        opts.attempts = 1;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.num_concurrent_reqs = 1;
    }
    let resolver = builder.build().context("build dns resolver")?;
    let query = if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{host}.")
    };
    let lookup = resolver
        .lookup_ip(query)
        .await
        .with_context(|| format!("query {host} via {server}"))?;
    Ok(lookup.iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn literal_ipv4_does_not_query() {
        let ips = lookup_ips(&["127.0.0.1:1".into()], "127.0.0.1").unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    }

    #[test]
    fn literal_ipv6_brackets_do_not_query() {
        let ips = lookup_ips(&[":::".into()], "[2001:db8::10]").unwrap();
        assert_eq!(ips, vec!["2001:db8::10".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn invalid_server_does_not_panic() {
        let err = lookup_ips(&["not a server".into()], "example.com").unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("not a server") || text.contains("invalid"),
            "{text}"
        );
        assert!(lookup_ips(&[String::new()], "example.com").is_err());
        assert!(lookup_ips(&["256.1.1.1:53".into()], "example.com").is_err());
        assert!(lookup_ips(&["8.8.8.8".into()], "").is_err());
    }
}

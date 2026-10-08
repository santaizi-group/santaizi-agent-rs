//! 自查公网 IP 与归属地：双栈并行查 Cloudflare `/cdn-cgi/trace`，
//! 对齐 Go `pkg/monitor/myip.go`（不调面板 LookupGeoIP）。

use anyhow::{Context, Result};
use std::net::IpAddr;
use std::time::Duration;

/// 对齐 Go myip.go `cfList`，每栈按序尝试，首个拿到本栈地址的胜出。
const TRACE_URLS: &[&str] = &[
    "https://blog.cloudflare.com/cdn-cgi/trace",
    "https://dash.cloudflare.com/cdn-cgi/trace",
    "https://developers.cloudflare.com/cdn-cgi/trace",
];

/// 对齐 Go util.MacOSChromeUA：部分端点对非浏览器 UA 不友好。
const TRACE_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IpInfo {
    pub ip: String,
    pub country_code: String,
}

/// 单栈自查结果；ip 为空表示该栈不可用。
#[derive(Debug, Clone, Default, PartialEq)]
struct StackInfo {
    ip: String,
    loc: String,
}

/// trace 文本 → (ip, loc)。对齐 Go parseCloudflareTrace：原样取值，不过滤。
fn parse_trace(body: &str) -> StackInfo {
    let mut out = StackInfo::default();
    for line in body.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("ip=") {
            out.ip = v.to_string();
        } else if let Some(v) = line.strip_prefix("loc=") {
            out.loc = v.to_string();
        }
    }
    out
}

/// 对齐 Go normalizeTraceLoc：恰两位小写字母，xx/t1 视为无效。
fn normalize_loc(loc: &str) -> Option<String> {
    let code = loc.trim().to_lowercase();
    if code.len() != 2
        || code == "xx"
        || code == "t1"
        || !code.bytes().all(|b| b.is_ascii_lowercase())
    {
        return None;
    }
    Some(code)
}

/// 对齐 Go applyPublicAddresses：双栈合并为 "v4/v6"，单栈即单边 IP；
/// 国家码在 v6 可用且（要求 v6 口径或 v4 缺席）时取 v6 loc，否则取 v4。
/// 双栈均空返回 None，由调用方决定报错或保留缓存。
fn merge_stacks(v4: &StackInfo, v6: &StackInfo, use_ipv6_countrycode: bool) -> Option<IpInfo> {
    if v4.ip.is_empty() && v6.ip.is_empty() {
        return None;
    }
    let ip = if v4.ip.is_empty() || v6.ip.is_empty() {
        format!("{}{}", v4.ip, v6.ip)
    } else {
        format!("{}/{}", v4.ip, v6.ip)
    };
    let loc = if !v6.ip.is_empty() && (use_ipv6_countrycode || v4.ip.is_empty()) {
        &v6.loc
    } else {
        &v4.loc
    };
    Some(IpInfo {
        ip,
        country_code: normalize_loc(loc).unwrap_or_default(),
    })
}

/// 逐域名解析出 v4/v6 地址并分别钉进两个 client，强制各栈走各自协议族；
/// 某个域名解析失败仅跳过该域名的钉扎（回退系统解析，栈归属仍由响应 ip 字段校验兜底）。
fn bindable(ip: IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// 网卡上的全球单播地址。空名字返回 (None, None)。
pub fn interface_locals(name: &str) -> (Option<IpAddr>, Option<IpAddr>) {
    let name = name.trim();
    if name.is_empty() {
        return (None, None);
    }
    let Ok(list) = if_addrs::get_if_addrs() else {
        return (None, None);
    };
    let mut v4 = None;
    let mut v6 = None;
    for iface in list {
        if iface.name != name {
            continue;
        }
        let ip = iface.ip();
        if !bindable(ip) {
            continue;
        }
        match ip {
            IpAddr::V4(_) if v4.is_none() => v4 = Some(ip),
            IpAddr::V6(_) if v6.is_none() => v6 = Some(ip),
            _ => {}
        }
    }
    (v4, v6)
}

async fn build_stack_clients(
    timeout: Duration,
    iface: &str,
) -> Result<(reqwest::Client, reqwest::Client)> {
    let (local_v4, local_v6) = interface_locals(iface);
    let mut b4 = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(TRACE_UA);
    let mut b6 = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(TRACE_UA);
    if let Some(ip) = local_v4 {
        b4 = b4.local_address(ip);
    }
    if let Some(ip) = local_v6 {
        b6 = b6.local_address(ip);
    }
    for url in TRACE_URLS {
        let host = reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .with_context(|| format!("trace URL 非法: {url}"))?;
        let Ok(addrs) = tokio::net::lookup_host((host.as_str(), 443)).await else {
            continue;
        };
        let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = addrs.map(|a| a.ip()).partition(IpAddr::is_ipv4);
        // 端口恒被 URL 覆盖，钉 0 即可（reqwest resolve 语义）
        let pin = |ips: &[IpAddr]| -> Vec<std::net::SocketAddr> {
            ips.iter()
                .map(|ip| std::net::SocketAddr::new(*ip, 0))
                .collect()
        };
        if !v4.is_empty() {
            b4 = b4.resolve_to_addrs(&host, &pin(&v4));
        }
        if !v6.is_empty() {
            b6 = b6.resolve_to_addrs(&host, &pin(&v6));
        }
    }
    Ok((
        b4.build().context("构建 v4 client 失败")?,
        b6.build().context("构建 v6 client 失败")?,
    ))
}

/// 对齐 Go fetchIP：按序尝试各端点，拿到的 ip 必须匹配本栈协议族
/// （v6 含冒号、v4 含点），否则换下一个；全落空返回空。
async fn fetch_stack(client: &reqwest::Client, v6: bool) -> StackInfo {
    for url in TRACE_URLS {
        let Ok(resp) = client.get(*url).send().await else {
            continue;
        };
        let Ok(body) = resp.text().await else {
            continue;
        };
        let found = parse_trace(&body);
        let matches = if v6 {
            found.ip.contains(':')
        } else {
            found.ip.contains('.')
        };
        if matches {
            return found;
        }
    }
    StackInfo::default()
}

async fn fetch_dual(timeout: Duration, use_ipv6_countrycode: bool, iface: &str) -> Result<IpInfo> {
    let (c4, c6) = build_stack_clients(timeout, iface).await?;
    let (v4, v6) = tokio::join!(fetch_stack(&c4, false), fetch_stack(&c6, true));
    merge_stacks(&v4, &v6, use_ipv6_countrycode)
        .ok_or_else(|| anyhow::anyhow!("v4/v6 双栈自查均失败"))
}

/// v1 通路（report.rs）入口：双栈合并 IP，国家码固定取 v4 口径（Go 默认）。
pub fn fetch_ip_info(timeout: Duration) -> Result<IpInfo> {
    fetch_ip_info_with(timeout, false, "")
}

/// `use_ipv6_countrycode=true` 时国家码取 v6 查询的 loc。
/// `iface` 非空时用该网卡的全球单播地址做本地地址。
/// 调用方经 spawn_blocking 进入；独立线程跑临时运行时，避免嵌套 block_on。
pub fn fetch_ip_info_with(
    timeout: Duration,
    use_ipv6_countrycode: bool,
    iface: &str,
) -> Result<IpInfo> {
    let iface = iface.to_string();
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("创建 IP 自查运行时失败")?
                .block_on(fetch_dual(timeout, use_ipv6_countrycode, &iface))
        })
        .join()
        .map_err(|_| anyhow::anyhow!("IP 自查线程异常退出"))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE_SAMPLE: &str = "fl=31f4\nh=blog.cloudflare.com\nip=203.0.113.7\nts=1690000000.1\nvisit_scheme=https\nuag=Mozilla/5.0\ncolo=SJC\nsliver=none\nhttp=http/2\nloc=CN\ntls=TLSv1.3\nsni=plaintext\nwarp=off\ngateway=off\nrbi=off\nkex=X25519\n";

    #[test]
    fn parse_trace_extracts_ip_and_loc() {
        let got = parse_trace(TRACE_SAMPLE);
        assert_eq!(got.ip, "203.0.113.7");
        assert_eq!(got.loc, "CN");
        // 缺字段给空串
        assert_eq!(parse_trace("loc=JP\n").ip, "");
        assert_eq!(parse_trace("").loc, "");
    }

    #[test]
    fn normalize_loc_rules() {
        assert_eq!(normalize_loc("CN"), Some("cn".into()));
        assert_eq!(normalize_loc(" jp "), Some("jp".into()));
        // xx / t1 忽略
        assert_eq!(normalize_loc("XX"), None);
        assert_eq!(normalize_loc("t1"), None);
        // 非两位、非纯字母都无效
        assert_eq!(normalize_loc("USA"), None);
        assert_eq!(normalize_loc("c1"), None);
        assert_eq!(normalize_loc(""), None);
    }

    #[test]
    fn merge_dual_stack_format() {
        let v4 = StackInfo {
            ip: "203.0.113.7".into(),
            loc: "CN".into(),
        };
        let v6 = StackInfo {
            ip: "2001:db8::1".into(),
            loc: "JP".into(),
        };
        // 双栈合并为 v4/v6
        let m = merge_stacks(&v4, &v6, false).unwrap();
        assert_eq!(m.ip, "203.0.113.7/2001:db8::1");
        assert_eq!(m.country_code, "cn");
        // use_ipv6_countrycode 选 v6 栈
        let m = merge_stacks(&v4, &v6, true).unwrap();
        assert_eq!(m.country_code, "jp");
    }

    #[test]
    fn merge_single_stack() {
        let v4 = StackInfo {
            ip: "203.0.113.7".into(),
            loc: "CN".into(),
        };
        let v6 = StackInfo {
            ip: "2001:db8::1".into(),
            loc: "JP".into(),
        };
        let empty = StackInfo::default();
        // 单栈即单边 IP，无斜杠
        let m = merge_stacks(&v4, &empty, false).unwrap();
        assert_eq!(m.ip, "203.0.113.7");
        assert_eq!(m.country_code, "cn");
        // v4 缺席时即使未开 v6 口径也取 v6 loc（对齐 Go）
        let m = merge_stacks(&empty, &v6, false).unwrap();
        assert_eq!(m.ip, "2001:db8::1");
        assert_eq!(m.country_code, "jp");
        // 双栈皆空 → None（调用方报错、不覆盖缓存）
        assert!(merge_stacks(&empty, &empty, false).is_none());
    }

    #[test]
    fn merge_ignores_xx_t1_country() {
        let v4 = StackInfo {
            ip: "203.0.113.7".into(),
            loc: "XX".into(),
        };
        let v6 = StackInfo {
            ip: "2001:db8::1".into(),
            loc: "T1".into(),
        };
        let m = merge_stacks(&v4, &v6, false).unwrap();
        assert_eq!(m.country_code, "");
        let m = merge_stacks(&v4, &v6, true).unwrap();
        assert_eq!(m.country_code, "");
    }
}

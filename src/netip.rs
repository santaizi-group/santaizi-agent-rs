use anyhow::{Context, Result, bail};
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IpInfo {
    pub ip: String,
    pub country_code: String,
}

/// 与 Go 探针一致：探针自查 Cloudflare /cdn-cgi/trace，不调面板 LookupGeoIP。
pub fn fetch_ip_info(timeout: Duration) -> Result<IpInfo> {
    let agent = ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(timeout))
            .build(),
    );
    let mut resp = agent
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .call()
        .context("cloudflare trace 请求失败")?;
    let body = resp
        .body_mut()
        .read_to_string()
        .context("读取 trace 响应失败")?;
    let mut info = IpInfo::default();
    for line in body.lines() {
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "ip" => info.ip = v.trim().to_string(),
                "loc" => info.country_code = v.trim().to_lowercase(),
                _ => {}
            }
        }
    }
    if info.ip.is_empty() {
        bail!("trace 响应缺少 ip 字段");
    }
    Ok(info)
}

//! 与 Go 探针共用的配置键（santaizi-agent/model/model.go）。
//!
//! 有意不加 `deny_unknown_fields`：未知键静默跳过，避免以后 Go 加键时这边起不来。
//! 间隔同时接受裸秒数和 Go 的 duration 字符串（`5s`、`10m`）。

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};
use std::fmt;
use std::path::Path;
use std::time::Duration;

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
    /// IP / 归属地刷新周期秒数。0 视为默认 1800；小于 60 允许（对齐 Go）。
    pub ip_report_period: u64,
    /// 公网 IP 自查与流量统计绑定的网卡名。非空时网卡统计只留这一张。
    pub ip_report_interface: String,
    /// 固定国家码，非空时覆盖自查结果
    pub country_code: String,
    /// 自定义 DNS（`host:port`）。空则拨号与 HTTP 探测轮换内置公共 DNS。
    pub dns: Vec<String>,
    /// true 时归属地国家码取 IPv6 自查结果；false 取 IPv4（v6 缺席时仍回退 v4）
    pub use_ipv6_countrycode: bool,
    /// 非空时只统计列表内网卡（精确匹配接口名），并取代内置前缀排除。
    /// 容忍 Go 的 map 写法（`nic_allowlist: {eth0: true}`），只取值为 true 的键。
    #[serde(deserialize_with = "de_nic_allowlist")]
    pub nic_allowlist: Vec<String>,
    /// 非空时只统计列表内磁盘分区（精确匹配挂载点），并取代内置文件系统白名单
    pub hard_drive_partition_allowlist: Vec<String>,
    pub debug: bool,
    /// 上报通路：v2（默认，Control+Ingest 流，对齐 Go 探针）或 v1（unary 回退）
    pub protocol: String,
    pub capabilities: CapabilityConfig,
    pub telemetry: TelemetryConfig,
}

/// 网卡白名单兼容 Go 两种形态：列表 `["eth0"]` 或 map `{eth0: true}`。
fn de_nic_allowlist<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        List(Vec<String>),
        Map(std::collections::HashMap<String, bool>),
    }
    Ok(match Repr::deserialize(deserializer)? {
        Repr::List(v) => v,
        Repr::Map(m) => {
            let mut names: Vec<String> = m
                .into_iter()
                .filter(|(_, on)| *on)
                .map(|(k, _)| k)
                .collect();
            names.sort();
            names
        }
    })
}

/// 能力开关。采集项缺省与 Go `DefaultCapabilities` 对齐。
/// `nat` 默认开启；配置或 `--disable-nat` 可关。
#[derive(Debug, Clone, Deserialize)]
pub struct CapabilityConfig {
    #[serde(default = "default_true")]
    pub cpu: bool,
    #[serde(default = "default_true")]
    pub memory: bool,
    #[serde(default = "default_true")]
    pub disk: bool,
    #[serde(default = "default_true")]
    pub network: bool,
    #[serde(default = "default_true")]
    pub connections: bool,
    #[serde(default = "default_true")]
    pub processes: bool,
    #[serde(default)]
    pub temperature: bool,
    #[serde(default)]
    pub gpu: bool,
    #[serde(default = "default_true")]
    pub host_info: bool,
    #[serde(default = "default_true")]
    pub ip_report: bool,
    #[serde(default = "default_true")]
    pub http_probe: bool,
    #[serde(default = "default_true")]
    pub icmp_probe: bool,
    #[serde(default = "default_true")]
    pub tcp_probe: bool,
    #[serde(default = "default_true")]
    pub nat: bool,
}

fn default_true() -> bool {
    true
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            cpu: true,
            memory: true,
            disk: true,
            network: true,
            connections: true,
            processes: true,
            temperature: false,
            gpu: false,
            host_info: true,
            ip_report: true,
            http_probe: true,
            icmp_probe: true,
            tcp_probe: true,
            nat: true,
        }
    }
}

/// yaml `telemetry.collectors`：按 endpoint id 覆盖从端地址，不能私自加未分配观测点。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct CollectorOverride {
    pub id: String,
    pub address: String,
    pub tls: bool,
    pub insecure_tls: bool,
}

/// v2 通路子配置，键对齐 Go 探针 telemetry.*。
#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    /// 身份、WAL、拨号缓存的数据目录
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_state_interval", deserialize_with = "de_secs")]
    pub state_interval: u64,
    #[serde(default = "default_heartbeat_interval", deserialize_with = "de_secs")]
    pub heartbeat_interval: u64,
    #[serde(default = "default_host_interval", deserialize_with = "de_secs")]
    pub host_interval: u64,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// 设备证续期窗口天数：到期前 N 天触发 Renew（0 视为 7，对齐 Go ApplyDefaults）
    #[serde(default = "default_cert_renew_days")]
    pub cert_renew_days: u32,
    #[serde(default)]
    pub disabled_remote_ids: Vec<String>,
    #[serde(default)]
    pub collectors: Vec<CollectorOverride>,
    #[serde(default)]
    pub wal: WalConfig,
}

/// Segment WAL。默认与 Go `ApplyDefaults` 相同。
#[derive(Debug, Clone, Deserialize)]
pub struct WalConfig {
    #[serde(default = "default_segment_size")]
    pub segment_size_bytes: u64,
    #[serde(default = "default_wal_max")]
    pub max_size_bytes: u64,
    #[serde(default = "default_wal_reserve")]
    pub reserve_bytes: u64,
    #[serde(default = "default_fsync_interval", deserialize_with = "de_duration")]
    pub fsync_interval: Duration,
    #[serde(default = "default_fsync_records")]
    pub fsync_records: usize,
}

fn default_data_dir() -> String {
    "/var/lib/santaizi-agent".into()
}
fn default_state_interval() -> u64 {
    5
}
fn default_heartbeat_interval() -> u64 {
    10
}
fn default_host_interval() -> u64 {
    600
}
fn default_batch_size() -> usize {
    256
}
fn default_cert_renew_days() -> u32 {
    7
}
fn default_segment_size() -> u64 {
    8 << 20
}
fn default_wal_max() -> u64 {
    256 << 20
}
fn default_wal_reserve() -> u64 {
    1 << 20
}
fn default_fsync_interval() -> Duration {
    Duration::from_secs(1)
}
fn default_fsync_records() -> usize {
    64
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            segment_size_bytes: default_segment_size(),
            max_size_bytes: default_wal_max(),
            reserve_bytes: default_wal_reserve(),
            fsync_interval: default_fsync_interval(),
            fsync_records: default_fsync_records(),
        }
    }
}

/// 裸秒数或 Go duration（`5s`、`10m`、`500ms`）解析成秒。不足 1 秒且非 0 时进位为 1。
pub fn parse_secs(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if let Ok(n) = trimmed.parse::<u64>() {
        return Ok(n);
    }
    let d = parse_go_duration(trimmed)?;
    Ok(duration_to_secs(d))
}

pub fn parse_go_duration(raw: &str) -> Result<Duration> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("duration 为空");
    }
    let mut total = Duration::ZERO;
    let bytes = trimmed.as_bytes();
    let mut i = 0;
    let mut saw = false;
    while i < bytes.len() {
        let start = i;
        if bytes[i] == b'-' {
            bail!("duration 不接受负数：{trimmed}");
        }
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        if i == start {
            bail!("duration 无效：{trimmed}");
        }
        let num: f64 = trimmed[start..i]
            .parse()
            .map_err(|_| anyhow::anyhow!("duration 数值无效：{trimmed}"))?;
        if !num.is_finite() || num < 0.0 {
            bail!("duration 数值无效：{trimmed}");
        }
        let unit_start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        if unit_start == i {
            bail!("duration 缺少单位：{trimmed}");
        }
        let unit = &trimmed[unit_start..i];
        let scale = match unit {
            "ns" => 1e-9,
            "us" | "µs" | "μs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => bail!("duration 单位无效：{unit}"),
        };
        total += Duration::from_secs_f64(num * scale);
        saw = true;
    }
    if !saw {
        bail!("duration 无效：{trimmed}");
    }
    Ok(total)
}

fn duration_to_secs(d: Duration) -> u64 {
    let secs = d.as_secs();
    if secs == 0 && !d.is_zero() { 1 } else { secs }
}

fn de_secs<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    struct V;
    impl Visitor<'_> for V {
        type Value = u64;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("秒数或 Go duration 字符串")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
            u64::try_from(v).map_err(E::custom)
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<u64, E> {
            if v < 0.0 || !v.is_finite() {
                return Err(E::custom("秒数无效"));
            }
            Ok(v as u64)
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
            parse_secs(v).map_err(E::custom)
        }
    }
    deserializer.deserialize_any(V)
}

fn de_duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let secs = de_secs(deserializer)?;
    Ok(Duration::from_secs(secs))
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            state_interval: default_state_interval(),
            heartbeat_interval: default_heartbeat_interval(),
            host_interval: default_host_interval(),
            batch_size: default_batch_size(),
            cert_renew_days: default_cert_renew_days(),
            disabled_remote_ids: Vec::new(),
            collectors: Vec::new(),
            wal: WalConfig::default(),
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
            ip_report_interface: String::new(),
            country_code: String::new(),
            dns: Vec::new(),
            use_ipv6_countrycode: false,
            nic_allowlist: Vec::new(),
            hard_drive_partition_allowlist: Vec::new(),
            debug: false,
            protocol: "v2".into(),
            capabilities: CapabilityConfig::default(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

fn parse_env_bool(key: &str, raw: &str) -> Result<bool> {
    match raw.to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => bail!("环境变量 {key} 布尔值无效：{raw:?}（接受 true/false/1/0）"),
    }
}

fn set_env_str(get: &impl Fn(&str) -> Option<String>, key: &str, dst: &mut String) {
    if let Some(v) = get(key) {
        *dst = v;
    }
}

fn set_env_bool(get: &impl Fn(&str) -> Option<String>, key: &str, dst: &mut bool) -> Result<()> {
    if let Some(v) = get(key) {
        *dst = parse_env_bool(key, &v)?;
    }
    Ok(())
}

fn set_env_num<T: std::str::FromStr>(
    get: &impl Fn(&str) -> Option<String>,
    key: &str,
    dst: &mut T,
) -> Result<()> {
    if let Some(v) = get(key) {
        *dst = v
            .parse()
            .map_err(|_| anyhow::anyhow!("环境变量 {key} 数值无效：{v:?}"))?;
    }
    Ok(())
}

fn set_env_secs(get: &impl Fn(&str) -> Option<String>, key: &str, dst: &mut u64) -> Result<()> {
    if let Some(v) = get(key) {
        *dst = parse_secs(&v).map_err(|e| anyhow::anyhow!("环境变量 {key}：{e:#}"))?;
    }
    Ok(())
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

    /// 环境变量覆盖，对齐 Go viper `SANTAIZI_` AutomaticEnv 的标量键
    /// （嵌套键用 `_` 拼接，如 `SANTAIZI_TELEMETRY_STATE_INTERVAL`）。
    /// 布尔/数字解析失败即报错，不静默忽略。优先级：默认 < yaml < env < CLI。
    pub fn apply_env(&mut self) -> Result<()> {
        self.apply_env_from(|k| std::env::var(k).ok())
    }

    fn apply_env_from(&mut self, get: impl Fn(&str) -> Option<String>) -> Result<()> {
        set_env_str(&get, "SANTAIZI_SERVER", &mut self.server);
        set_env_str(&get, "SANTAIZI_CLIENT_SECRET", &mut self.client_secret);
        set_env_bool(&get, "SANTAIZI_TLS", &mut self.tls)?;
        set_env_bool(&get, "SANTAIZI_INSECURE_TLS", &mut self.insecure_tls)?;
        set_env_str(&get, "SANTAIZI_TLS_CA_FILE", &mut self.tls_ca_file);
        set_env_num(&get, "SANTAIZI_REPORT_DELAY", &mut self.report_delay)?;
        set_env_secs(
            &get,
            "SANTAIZI_IP_REPORT_PERIOD",
            &mut self.ip_report_period,
        )?;
        set_env_str(
            &get,
            "SANTAIZI_IP_REPORT_INTERFACE",
            &mut self.ip_report_interface,
        );
        set_env_str(&get, "SANTAIZI_COUNTRY_CODE", &mut self.country_code);
        if let Some(v) = get("SANTAIZI_DNS") {
            self.dns = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        set_env_bool(
            &get,
            "SANTAIZI_USE_IPV6_COUNTRYCODE",
            &mut self.use_ipv6_countrycode,
        )?;
        set_env_bool(&get, "SANTAIZI_DEBUG", &mut self.debug)?;
        set_env_str(&get, "SANTAIZI_PROTOCOL", &mut self.protocol);
        {
            let caps = &mut self.capabilities;
            let table: [(&str, &mut bool); 14] = [
                ("SANTAIZI_CAPABILITIES_CPU", &mut caps.cpu),
                ("SANTAIZI_CAPABILITIES_MEMORY", &mut caps.memory),
                ("SANTAIZI_CAPABILITIES_DISK", &mut caps.disk),
                ("SANTAIZI_CAPABILITIES_NETWORK", &mut caps.network),
                ("SANTAIZI_CAPABILITIES_CONNECTIONS", &mut caps.connections),
                ("SANTAIZI_CAPABILITIES_PROCESSES", &mut caps.processes),
                ("SANTAIZI_CAPABILITIES_TEMPERATURE", &mut caps.temperature),
                ("SANTAIZI_CAPABILITIES_GPU", &mut caps.gpu),
                ("SANTAIZI_CAPABILITIES_HOST_INFO", &mut caps.host_info),
                ("SANTAIZI_CAPABILITIES_IP_REPORT", &mut caps.ip_report),
                ("SANTAIZI_CAPABILITIES_HTTP_PROBE", &mut caps.http_probe),
                ("SANTAIZI_CAPABILITIES_ICMP_PROBE", &mut caps.icmp_probe),
                ("SANTAIZI_CAPABILITIES_TCP_PROBE", &mut caps.tcp_probe),
                ("SANTAIZI_CAPABILITIES_NAT", &mut caps.nat),
            ];
            for (key, dst) in table {
                if let Some(v) = get(key) {
                    *dst = parse_env_bool(key, &v)?;
                }
            }
        }
        set_env_str(
            &get,
            "SANTAIZI_TELEMETRY_DATA_DIR",
            &mut self.telemetry.data_dir,
        );
        set_env_secs(
            &get,
            "SANTAIZI_TELEMETRY_STATE_INTERVAL",
            &mut self.telemetry.state_interval,
        )?;
        set_env_secs(
            &get,
            "SANTAIZI_TELEMETRY_HEARTBEAT_INTERVAL",
            &mut self.telemetry.heartbeat_interval,
        )?;
        set_env_secs(
            &get,
            "SANTAIZI_TELEMETRY_HOST_INTERVAL",
            &mut self.telemetry.host_interval,
        )?;
        set_env_num(
            &get,
            "SANTAIZI_TELEMETRY_BATCH_SIZE",
            &mut self.telemetry.batch_size,
        )?;
        set_env_num(
            &get,
            "SANTAIZI_TELEMETRY_CERT_RENEW_DAYS",
            &mut self.telemetry.cert_renew_days,
        )?;
        set_env_num(
            &get,
            "SANTAIZI_TELEMETRY_WAL_SEGMENT_SIZE_BYTES",
            &mut self.telemetry.wal.segment_size_bytes,
        )?;
        set_env_num(
            &get,
            "SANTAIZI_TELEMETRY_WAL_MAX_SIZE_BYTES",
            &mut self.telemetry.wal.max_size_bytes,
        )?;
        set_env_num(
            &get,
            "SANTAIZI_TELEMETRY_WAL_RESERVE_BYTES",
            &mut self.telemetry.wal.reserve_bytes,
        )?;
        set_env_num(
            &get,
            "SANTAIZI_TELEMETRY_WAL_FSYNC_RECORDS",
            &mut self.telemetry.wal.fsync_records,
        )?;
        if let Some(v) = get("SANTAIZI_TELEMETRY_WAL_FSYNC_INTERVAL") {
            self.telemetry.wal.fsync_interval = Duration::from_secs(parse_secs(&v)?);
        }
        Ok(())
    }

    /// 对齐 Go `ApplyDefaults` 里「0 即默认」的项。CLI 覆盖之后调用。
    pub fn normalize(&mut self) {
        if self.ip_report_period == 0 {
            self.ip_report_period = 1800;
        }
        if self.telemetry.wal.segment_size_bytes == 0 {
            self.telemetry.wal.segment_size_bytes = default_segment_size();
        }
        if self.telemetry.wal.max_size_bytes == 0 {
            self.telemetry.wal.max_size_bytes = default_wal_max();
        }
        if self.telemetry.wal.reserve_bytes == 0 {
            self.telemetry.wal.reserve_bytes = default_wal_reserve();
        }
        if self.telemetry.wal.fsync_interval.is_zero() {
            self.telemetry.wal.fsync_interval = default_fsync_interval();
        }
        if self.telemetry.wal.fsync_records == 0 {
            self.telemetry.wal.fsync_records = default_fsync_records();
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
        if self.protocol != "v1" && self.protocol != "v2" {
            bail!("protocol 只能是 v1 或 v2");
        }
        if !(1..=3600).contains(&self.telemetry.state_interval) {
            bail!("telemetry.state_interval 需在 1-3600 秒之间");
        }
        if !(1..=3600).contains(&self.telemetry.heartbeat_interval) {
            bail!("telemetry.heartbeat_interval 需在 1-3600 秒之间");
        }
        if !(1..=1024).contains(&self.telemetry.batch_size) {
            bail!("telemetry.batch_size 需在 1-1024 之间");
        }
        if self.telemetry.data_dir.is_empty() {
            bail!("telemetry.data_dir 不能为空");
        }
        for c in &self.telemetry.collectors {
            if c.id.is_empty() {
                bail!("telemetry.collectors[].id 不能为空");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn capabilities_partial_yaml_keeps_probe_defaults() {
        let cfg: Config = serde_yaml::from_str(
            r#"
client_secret: "s"
capabilities:
  http_probe: false
  temperature: true
"#,
        )
        .unwrap();
        assert!(!cfg.capabilities.http_probe);
        assert!(cfg.capabilities.tcp_probe);
        assert!(cfg.capabilities.icmp_probe);
        assert!(cfg.capabilities.cpu);
        assert!(cfg.capabilities.temperature);
        assert!(!cfg.capabilities.gpu);
        assert!(cfg.capabilities.nat);
    }

    #[test]
    fn telemetry_partial_yaml_keeps_intervals() {
        let cfg: Config = serde_yaml::from_str(
            r#"
client_secret: "s"
telemetry:
  data_dir: "/tmp/x"
  collectors:
    - id: "c1"
      address: "obs.example:5555"
      tls: true
  disabled_remote_ids: ["skip-me"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.telemetry.state_interval, 5);
        assert_eq!(cfg.telemetry.heartbeat_interval, 10);
        assert_eq!(cfg.telemetry.batch_size, 256);
        assert_eq!(cfg.telemetry.cert_renew_days, 7);
        assert_eq!(cfg.telemetry.collectors.len(), 1);
        assert_eq!(cfg.telemetry.collectors[0].id, "c1");
        assert!(cfg.telemetry.collectors[0].tls);
        assert_eq!(cfg.telemetry.disabled_remote_ids, ["skip-me"]);
    }

    #[test]
    fn new_keys_default_and_parse() {
        let cfg: Config = serde_yaml::from_str("client_secret: s\n").unwrap();
        assert!(!cfg.use_ipv6_countrycode);
        assert!(cfg.nic_allowlist.is_empty());
        assert!(cfg.hard_drive_partition_allowlist.is_empty());
        let cfg: Config = serde_yaml::from_str(
            r#"
client_secret: "s"
use_ipv6_countrycode: true
nic_allowlist: ["eth0", "ens3"]
hard_drive_partition_allowlist: ["/", "/data"]
telemetry:
  cert_renew_days: 14
"#,
        )
        .unwrap();
        assert!(cfg.use_ipv6_countrycode);
        assert_eq!(cfg.nic_allowlist, ["eth0", "ens3"]);
        assert_eq!(cfg.hard_drive_partition_allowlist, ["/", "/data"]);
        assert_eq!(cfg.telemetry.cert_renew_days, 14);
    }

    /// Go 的 nic_allowlist 是 map 形态，共用 yaml 时必须容忍（只取 true 的键）。
    #[test]
    fn nic_allowlist_accepts_go_map_form() {
        let cfg: Config = serde_yaml::from_str(
            r#"
client_secret: "s"
nic_allowlist:
  eth0: true
  docker0: false
"#,
        )
        .unwrap();
        assert_eq!(cfg.nic_allowlist, ["eth0"]);
    }

    /// Go 全量 yaml 里本实现不读的键必须静默跳过（无 deny_unknown_fields）。
    #[test]
    fn go_yaml_duration_dns_and_wal() {
        let cfg: Config = serde_yaml::from_str(
            r#"
client_secret: "s"
dns: ["1.1.1.1:53"]
ip_report_interface: "eth0"
insecure_tls: true
telemetry:
  state_interval: 5s
  heartbeat_interval: 10s
  host_interval: 10m
  wal:
    segment_size_bytes: 8388608
    fsync_interval: 1s
    fsync_records: 64
"#,
        )
        .unwrap();
        assert_eq!(cfg.dns, ["1.1.1.1:53"]);
        assert_eq!(cfg.ip_report_interface, "eth0");
        assert!(cfg.insecure_tls);
        assert_eq!(cfg.telemetry.state_interval, 5);
        assert_eq!(cfg.telemetry.heartbeat_interval, 10);
        assert_eq!(cfg.telemetry.host_interval, 600);
        assert_eq!(cfg.telemetry.wal.segment_size_bytes, 8 << 20);
        assert_eq!(
            cfg.telemetry.wal.fsync_interval,
            std::time::Duration::from_secs(1)
        );
        assert_eq!(cfg.telemetry.wal.fsync_records, 64);
        assert!(cfg.validate().is_ok());
    }

    fn env_cfg(vars: &[(&str, &str)]) -> Config {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut cfg = Config::default();
        cfg.apply_env_from(|k| map.get(k).cloned()).unwrap();
        cfg
    }

    #[test]
    fn env_overrides_scalars() {
        let cfg = env_cfg(&[
            ("SANTAIZI_SERVER", "panel.example:5555"),
            ("SANTAIZI_CLIENT_SECRET", "env-secret"),
            ("SANTAIZI_TLS", "true"),
            ("SANTAIZI_TLS_CA_FILE", "/etc/santaizi/ca.pem"),
            ("SANTAIZI_REPORT_DELAY", "15"),
            ("SANTAIZI_IP_REPORT_PERIOD", "600"),
            ("SANTAIZI_COUNTRY_CODE", "hk"),
            ("SANTAIZI_USE_IPV6_COUNTRYCODE", "1"),
            ("SANTAIZI_DEBUG", "false"),
            ("SANTAIZI_PROTOCOL", "v1"),
        ]);
        assert_eq!(cfg.server, "panel.example:5555");
        assert_eq!(cfg.client_secret, "env-secret");
        assert!(cfg.tls);
        assert_eq!(cfg.tls_ca_file, "/etc/santaizi/ca.pem");
        assert_eq!(cfg.report_delay, 15);
        assert_eq!(cfg.ip_report_period, 600);
        assert_eq!(cfg.country_code, "hk");
        assert!(cfg.use_ipv6_countrycode);
        assert!(!cfg.debug);
        assert_eq!(cfg.protocol, "v1");
    }

    #[test]
    fn env_overrides_capabilities_and_telemetry() {
        let cfg = env_cfg(&[
            ("SANTAIZI_CAPABILITIES_HTTP_PROBE", "0"),
            ("SANTAIZI_CAPABILITIES_TEMPERATURE", "true"),
            ("SANTAIZI_TELEMETRY_DATA_DIR", "/tmp/agent"),
            ("SANTAIZI_TELEMETRY_STATE_INTERVAL", "20"),
            ("SANTAIZI_TELEMETRY_HEARTBEAT_INTERVAL", "30"),
            ("SANTAIZI_TELEMETRY_HOST_INTERVAL", "1200"),
            ("SANTAIZI_TELEMETRY_BATCH_SIZE", "64"),
            ("SANTAIZI_TELEMETRY_CERT_RENEW_DAYS", "30"),
        ]);
        assert!(!cfg.capabilities.http_probe);
        assert!(cfg.capabilities.temperature);
        // 未设置的键保持默认
        assert!(cfg.capabilities.tcp_probe);
        assert_eq!(cfg.telemetry.data_dir, "/tmp/agent");
        assert_eq!(cfg.telemetry.state_interval, 20);
        assert_eq!(cfg.telemetry.heartbeat_interval, 30);
        assert_eq!(cfg.telemetry.host_interval, 1200);
        assert_eq!(cfg.telemetry.batch_size, 64);
        assert_eq!(cfg.telemetry.cert_renew_days, 30);
    }

    #[test]
    fn env_invalid_bool_is_error() {
        let map: HashMap<String, String> = [("SANTAIZI_TLS".to_string(), "yes".to_string())]
            .into_iter()
            .collect();
        let mut cfg = Config::default();
        let err = cfg.apply_env_from(|k| map.get(k).cloned()).unwrap_err();
        assert!(format!("{err:#}").contains("SANTAIZI_TLS"), "{err:#}");
    }

    #[test]
    fn env_invalid_number_is_error() {
        let map: HashMap<String, String> =
            [("SANTAIZI_IP_REPORT_PERIOD".to_string(), "abc".to_string())]
                .into_iter()
                .collect();
        let mut cfg = Config::default();
        let err = cfg.apply_env_from(|k| map.get(k).cloned()).unwrap_err();
        assert!(
            format!("{err:#}").contains("SANTAIZI_IP_REPORT_PERIOD"),
            "{err:#}"
        );
    }

    #[test]
    fn short_ip_report_period_is_allowed() {
        let mut cfg = Config {
            client_secret: "s".into(),
            ..Config::default()
        };
        cfg.ip_report_period = 30;
        assert!(cfg.validate().is_ok());
        cfg.ip_report_period = 0;
        cfg.normalize();
        assert_eq!(cfg.ip_report_period, 1800);
    }
}

//! 拨号终点缓存，对齐 Go `pkg/dialcache`。
//!
//! 不在这里做 DNS。`plan` 的 lookup 由调用方注入。

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const FILE_NAME: &str = "endpoint-cache.json";
pub const PRIMARY_KEY: &str = "primary";

const VERSION: i64 = 1;

/// `collector:<id>`，id 去掉首尾空白。对齐 Go `CollectorKey`。
pub fn collector_key(endpoint_id: &str) -> String {
    format!("collector:{}", endpoint_id.trim())
}

/// 一次拨号候选。`authority` 与 `server_name` 都不含端口，给 gRPC authority 和 TLS ServerName 用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub dial_addr: String,
    pub authority: String,
    pub server_name: String,
    pub host: String,
    pub port: String,
    pub ip: String,
    pub from_dns: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct CacheFile {
    #[serde(default)]
    version: i64,
    #[serde(default)]
    endpoints: Option<BTreeMap<String, WireEntry>>,
}

#[derive(Debug, Clone, Deserialize)]
struct WireEntry {
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    ips: Option<Vec<String>>,
    #[serde(default)]
    updated_at_unix: i64,
}

#[derive(Debug, Clone)]
struct Entry {
    host: String,
    port: String,
    ips: Vec<String>,
    updated_at_unix: i64,
}

impl From<WireEntry> for Entry {
    fn from(raw: WireEntry) -> Self {
        Self {
            host: raw.host,
            port: raw.port,
            ips: raw.ips.unwrap_or_default(),
            updated_at_unix: raw.updated_at_unix,
        }
    }
}

struct State {
    version: i64,
    endpoints: BTreeMap<String, Entry>,
}

impl State {
    fn empty() -> Self {
        Self {
            version: VERSION,
            endpoints: BTreeMap::new(),
        }
    }
}

pub struct Store {
    path: PathBuf,
    inner: Mutex<State>,
}

impl Store {
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let data_dir = data_dir.as_ref();
        if data_dir.as_os_str().is_empty() || data_dir.to_string_lossy().trim().is_empty() {
            bail!("dial cache data directory is empty");
        }
        ensure_dir(data_dir)
            .with_context(|| format!("create dial cache directory {}", data_dir.display()))?;
        let path = data_dir.join(FILE_NAME);
        let state = match fs::read(&path) {
            Ok(raw) => load_state(&raw),
            Err(err) if err.kind() == io::ErrorKind::NotFound => State::empty(),
            Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
        };
        Ok(Self {
            path,
            inner: Mutex::new(state),
        })
    }

    /// host 大小写不敏感，port 必须完全相等，否则空。
    pub fn get(&self, key: &str, host: &str, port: &str) -> Vec<String> {
        let state = self.lock();
        let Some(entry) = state.endpoints.get(key) else {
            return Vec::new();
        };
        if !same_endpoint(&entry.host, &entry.port, host, port) {
            return Vec::new();
        }
        entry.ips.clone()
    }

    pub fn put<I, S>(&self, key: &str, host: &str, port: &str, ips: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let normalized = normalize_ips(ips)?;
        if normalized.is_empty() {
            bail!("dial cache IPs are required");
        }
        let mut state = self.lock();
        state.version = VERSION;
        state.endpoints.insert(
            key.to_string(),
            Entry {
                host: host.to_string(),
                port: port.to_string(),
                ips: normalized,
                updated_at_unix: now_unix(),
            },
        );
        write_atomic(&self.path, &encode_state(&state))
    }

    /// 已有同 host+port 的记录则不覆盖。
    pub fn seed<I, S>(&self, key: &str, host: &str, port: &str, ips: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if !self.get(key, host, port).is_empty() {
            return Ok(());
        }
        self.put(key, host, port, ips)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }
}

/// 地址必须带端口。字面 IP 不调用 lookup、不读缓存。
///
/// lookup 成功时，每个可用 IP 的 `from_dns=true`，再把缓存里 host+port 匹配且 DNS 没有的 IP 接在后面。
/// lookup 失败则留下该错误，同样接上缓存。一个候选都没有才返回错误：lookup 错误优先，否则 `cannot resolve {host}`。
pub fn plan<F, E>(store: Option<&Store>, key: &str, address: &str, lookup: F) -> Result<Vec<Target>>
where
    F: FnOnce(&str) -> std::result::Result<Vec<IpAddr>, E>,
    E: Into<anyhow::Error>,
{
    let (host, port) = split_host_port(address)?;
    if let Some(ip) = parse_ip(host) {
        let ip = canonical_ip_string(ip);
        return Ok(vec![Target {
            dial_addr: join_host_port(&ip, port),
            authority: host.to_string(),
            server_name: host.to_string(),
            host: host.to_string(),
            port: port.to_string(),
            ip,
            from_dns: false,
        }]);
    }

    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    let mut lookup_err = None;
    match lookup(host) {
        Ok(addrs) => {
            let ips = normalize_addrs(&addrs);
            if ips.is_empty() {
                lookup_err = Some(anyhow!("cannot resolve {host}"));
            } else {
                for ip in ips {
                    if seen.insert(ip.clone()) {
                        targets.push(make_target(host, port, ip, true));
                    }
                }
            }
        }
        Err(err) => lookup_err = Some(err.into()),
    }
    for ip in cached_ips(store, key, host, port) {
        if seen.insert(ip.clone()) {
            targets.push(make_target(host, port, ip, false));
        }
    }
    if targets.is_empty() {
        if let Some(err) = lookup_err {
            return Err(err);
        }
        bail!("cannot resolve {host}");
    }
    Ok(targets)
}

/// 对齐 `net.SplitHostPort`，并拒绝空 host 或空 port。返回值借用 `address`。
pub fn split_host_port(address: &str) -> Result<(&str, &str)> {
    let trimmed = address.trim();
    let (host, port) =
        split_host_port_raw(trimmed).map_err(|why| anyhow!("dial address {address:?}: {why}"))?;
    if host.is_empty() || port.is_empty() {
        bail!("dial address {address:?} is missing host or port");
    }
    Ok((host, port))
}

fn cached_ips(store: Option<&Store>, key: &str, host: &str, port: &str) -> Vec<String> {
    store
        .map(|store| store.get(key, host, port))
        .unwrap_or_default()
}

fn make_target(host: &str, port: &str, ip: String, from_dns: bool) -> Target {
    Target {
        dial_addr: join_host_port(&ip, port),
        authority: host.to_string(),
        server_name: host.to_string(),
        host: host.to_string(),
        port: port.to_string(),
        ip,
        from_dns,
    }
}

fn split_host_port_raw(hostport: &str) -> std::result::Result<(&str, &str), &'static str> {
    const MISSING_PORT: &str = "missing port in address";
    const TOO_MANY_COLONS: &str = "too many colons in address";
    let bytes = hostport.as_bytes();
    let Some(i) = bytes.iter().rposition(|b| *b == b':') else {
        return Err(MISSING_PORT);
    };
    let (host, bracket_from, bracket_to) = if bytes.first() == Some(&b'[') {
        let Some(end) = bytes.iter().position(|b| *b == b']') else {
            return Err("missing ']' in address");
        };
        match end + 1 {
            n if n == bytes.len() => return Err(MISSING_PORT),
            n if n == i => {}
            _ => {
                if bytes.get(end + 1) == Some(&b':') {
                    return Err(TOO_MANY_COLONS);
                }
                return Err(MISSING_PORT);
            }
        }
        (&hostport[1..end], 1, end + 1)
    } else {
        let host = &hostport[..i];
        if host.as_bytes().contains(&b':') {
            return Err(TOO_MANY_COLONS);
        }
        (host, 0, 0)
    };
    if hostport.as_bytes()[bracket_from..].contains(&b'[') {
        return Err("unexpected '[' in address");
    }
    if hostport.as_bytes()[bracket_to..].contains(&b']') {
        return Err("unexpected ']' in address");
    }
    Ok((host, &hostport[i + 1..]))
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.as_bytes().contains(&b':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn same_endpoint(cached_host: &str, cached_port: &str, host: &str, port: &str) -> bool {
    cached_port == port && cached_host.eq_ignore_ascii_case(host)
}

fn normalize_ips<I, S>(ips: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for raw in ips {
        let raw = raw.as_ref();
        let Some(ip) = parse_ip(raw.trim()) else {
            bail!("invalid IP {raw:?}");
        };
        push_usable(&mut seen, &mut out, ip);
    }
    Ok(out)
}

fn normalize_addrs(addrs: &[IpAddr]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for ip in addrs {
        push_usable(&mut seen, &mut out, *ip);
    }
    out
}

fn push_usable(seen: &mut HashSet<String>, out: &mut Vec<String>, ip: IpAddr) {
    if !usable_ip(ip) {
        return;
    }
    let value = canonical_ip_string(ip);
    if seen.insert(value.clone()) {
        out.push(value);
    }
}

fn parse_ip(raw: &str) -> Option<IpAddr> {
    raw.parse().ok()
}

/// Go `net.IP.String` 把 IPv4-mapped IPv6 收成点分 IPv4；可用性也按这个形态判断。
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn canonical_ip_string(ip: IpAddr) -> String {
    canonical_ip(ip).to_string()
}

fn usable_ip(ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    !ip.is_unspecified() && !ip.is_multicast()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn load_state(raw: &[u8]) -> State {
    let Ok(text) = std::str::from_utf8(raw) else {
        return State::empty();
    };
    let Ok(file) = serde_yaml::from_str::<CacheFile>(text) else {
        return State::empty();
    };
    let Some(endpoints) = file.endpoints else {
        return State::empty();
    };
    let version = if file.version == 0 {
        VERSION
    } else {
        file.version
    };
    State {
        version,
        endpoints: endpoints.into_iter().map(|(k, v)| (k, v.into())).collect(),
    }
}

fn encode_state(state: &State) -> String {
    let mut out = String::from("{\"version\":");
    out.push_str(&state.version.to_string());
    out.push_str(",\"endpoints\":{");
    for (i, (key, entry)) in state.endpoints.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_string(&mut out, key);
        out.push(':');
        out.push('{');
        out.push_str("\"host\":");
        push_json_string(&mut out, &entry.host);
        out.push_str(",\"port\":");
        push_json_string(&mut out, &entry.port);
        out.push_str(",\"ips\":[");
        for (j, ip) in entry.ips.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            push_json_string(&mut out, ip);
        }
        out.push_str("],\"updated_at_unix\":");
        out.push_str(&entry.updated_at_unix.to_string());
        out.push('}');
    }
    out.push_str("}}");
    out
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                let b = c as u8;
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push_str("\\u00");
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn ensure_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

fn create_temp(dir: &Path) -> Result<(PathBuf, File)> {
    for _ in 0..32 {
        let n: u64 = rand::random();
        let path = dir.join(format!(".endpoint-cache-{n:016x}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err).context("create dial cache temp file"),
        }
    }
    bail!("create dial cache temp file")
}

fn write_atomic(path: &Path, payload: &str) -> Result<()> {
    let dir = path.parent().context("dial cache path has no parent")?;
    let (tmp_path, mut tmp) = create_temp(dir)?;
    let wrote = (|| -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        tmp.write_all(payload.as_bytes())?;
        tmp.flush()?;
        tmp.sync_all()?;
        Ok(())
    })();
    if let Err(err) = wrote {
        drop(tmp);
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    drop(tmp);
    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err).context("install dial cache file");
    }
    File::open(dir)
        .and_then(|dir_file| dir_file.sync_all())
        .context("sync dial cache directory")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let extra: u64 = rand::random();
            let path = std::env::temp_dir().join(format!(
                "santaizi-dialcache-{}-{n}-{extra}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn open_store() -> (TempDir, Store) {
        let dir = TempDir::new();
        let store = Store::open(&dir.path).unwrap();
        (dir, store)
    }

    fn boom(_: &str) -> io::Result<Vec<IpAddr>> {
        panic!("lookup must not be called");
    }

    #[test]
    fn put_get_seed_roundtrip_port_and_case() {
        let (dir, store) = open_store();
        assert!(
            !dir.path.join(FILE_NAME).exists(),
            "open must not create the cache file"
        );
        assert!(
            store
                .get(PRIMARY_KEY, "grpc.example.invalid", "5555")
                .is_empty()
        );

        store
            .put(
                PRIMARY_KEY,
                "grpc.example.invalid",
                "5555",
                [
                    " 192.0.2.10 ",
                    "192.0.2.10",
                    "::ffff:192.0.2.10",
                    "2001:0db8::2",
                    "0.0.0.0",
                    "::",
                    "::ffff:0.0.0.0",
                    "224.0.0.1",
                    "::ffff:224.0.0.1",
                    "ff02::1",
                ],
            )
            .unwrap();
        assert_eq!(
            store.get(PRIMARY_KEY, "grpc.example.invalid", "5555"),
            vec!["192.0.2.10".to_string(), "2001:db8::2".to_string()]
        );
        assert!(
            store
                .get(PRIMARY_KEY, "grpc.example.invalid", "443")
                .is_empty()
        );
        assert!(
            store
                .get(PRIMARY_KEY, "other.example.invalid", "5555")
                .is_empty()
        );

        let raw = fs::read_to_string(dir.path.join(FILE_NAME)).unwrap();
        assert!(raw.starts_with("{\"version\":1,\"endpoints\":{"), "{raw}");
        assert!(raw.contains("\"port\":\"5555\""), "{raw}");
        assert!(!raw.contains('\n'), "{raw}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path.join(FILE_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "mode {mode:o}");
        }

        let reloaded = Store::open(&dir.path).unwrap();
        assert_eq!(
            reloaded.get(PRIMARY_KEY, "GRPC.example.invalid", "5555"),
            vec!["192.0.2.10".to_string(), "2001:db8::2".to_string()]
        );

        reloaded
            .seed(
                PRIMARY_KEY,
                "grpc.example.invalid",
                "5555",
                ["198.51.100.4", "not-an-ip"],
            )
            .unwrap();
        assert_eq!(
            reloaded.get(PRIMARY_KEY, "grpc.example.invalid", "5555"),
            vec!["192.0.2.10".to_string(), "2001:db8::2".to_string()]
        );
        reloaded
            .seed(PRIMARY_KEY, "new.example.invalid", "5555", ["198.51.100.4"])
            .unwrap();
        assert_eq!(
            reloaded.get(PRIMARY_KEY, "new.example.invalid", "5555"),
            vec!["198.51.100.4".to_string()]
        );
        assert!(
            reloaded
                .get(PRIMARY_KEY, "grpc.example.invalid", "5555")
                .is_empty()
        );

        let err = reloaded
            .put(PRIMARY_KEY, "new.example.invalid", "5555", ["not-an-ip"])
            .unwrap_err();
        assert!(err.to_string().contains("not-an-ip"), "{err}");
        assert_eq!(
            reloaded.get(PRIMARY_KEY, "new.example.invalid", "5555"),
            vec!["198.51.100.4".to_string()]
        );
        assert!(
            reloaded
                .put(
                    PRIMARY_KEY,
                    "empty.example.invalid",
                    "5555",
                    ["0.0.0.0", "ff02::1"],
                )
                .is_err()
        );

        assert_eq!(collector_key(" abc "), "collector:abc");
        reloaded
            .put(&collector_key(" abc "), "c.example", "9", ["192.0.2.9"])
            .unwrap();
        let raw = fs::read_to_string(dir.path.join(FILE_NAME)).unwrap();
        let collector_at = raw.find("collector:abc").unwrap();
        let primary_at = raw.find("\"primary\"").unwrap();
        assert!(collector_at < primary_at, "{raw}");
        assert!(Store::open("").is_err());
        assert!(Store::open("   ").is_err());
    }

    #[test]
    fn bad_json_or_missing_endpoints_is_empty() {
        let dir = TempDir::new();
        fs::write(dir.path.join(FILE_NAME), b"{").unwrap();
        let store = Store::open(&dir.path).unwrap();
        assert!(
            store
                .get(PRIMARY_KEY, "grpc.example.invalid", "5555")
                .is_empty()
        );
        store
            .put(PRIMARY_KEY, "grpc.example.invalid", "5555", ["192.0.2.10"])
            .unwrap();
        assert_eq!(
            Store::open(&dir.path)
                .unwrap()
                .get(PRIMARY_KEY, "grpc.example.invalid", "5555"),
            vec!["192.0.2.10".to_string()]
        );

        fs::write(dir.path.join(FILE_NAME), br#"{"version":1}"#).unwrap();
        let store = Store::open(&dir.path).unwrap();
        assert!(store.get(PRIMARY_KEY, "h.example", "1").is_empty());

        fs::write(
            dir.path.join(FILE_NAME),
            br#"{"version":1,"endpoints":null}"#,
        )
        .unwrap();
        assert!(
            Store::open(&dir.path)
                .unwrap()
                .get(PRIMARY_KEY, "h.example", "1")
                .is_empty()
        );

        let raw = r#"{"version":0,"endpoints":{"primary":{"host":"Example.COM","port":"5555","ips":["1.2.3.4","2001:db8::8"],"updated_at_unix":1710000000}}}"#;
        fs::write(dir.path.join(FILE_NAME), raw).unwrap();
        let store = Store::open(&dir.path).unwrap();
        assert_eq!(
            store.get(PRIMARY_KEY, "example.com", "5555"),
            vec!["1.2.3.4".to_string(), "2001:db8::8".to_string()]
        );
        assert!(store.get(PRIMARY_KEY, "example.com", "5556").is_empty());
    }

    #[test]
    fn plan_lookup_success_covers_failure_uses_cache_literal_skips_lookup() {
        let (_dir, store) = open_store();
        store
            .put(
                PRIMARY_KEY,
                "Grpc.Example.Invalid",
                "5555",
                ["198.51.100.4", "192.0.2.20"],
            )
            .unwrap();

        let targets = plan(
            Some(&store),
            PRIMARY_KEY,
            "grpc.example.invalid:5555",
            |host| {
                assert_eq!(host, "grpc.example.invalid");
                Ok::<_, io::Error>(vec![
                    "192.0.2.20".parse().unwrap(),
                    "2001:db8::5".parse().unwrap(),
                    "0.0.0.0".parse().unwrap(),
                    "224.0.0.1".parse().unwrap(),
                    "::ffff:192.0.2.20".parse().unwrap(),
                ])
            },
        )
        .unwrap();
        assert_eq!(targets.len(), 3, "{targets:?}");
        assert!(targets[0].from_dns);
        assert_eq!(targets[0].ip, "192.0.2.20");
        assert_eq!(targets[0].dial_addr, "192.0.2.20:5555");
        assert!(targets[1].from_dns);
        assert_eq!(targets[1].ip, "2001:db8::5");
        assert_eq!(targets[1].dial_addr, "[2001:db8::5]:5555");
        assert!(!targets[2].from_dns);
        assert_eq!(targets[2].ip, "198.51.100.4");
        for target in &targets {
            assert_eq!(target.authority, "grpc.example.invalid");
            assert_eq!(target.server_name, "grpc.example.invalid");
            assert_eq!(target.host, "grpc.example.invalid");
            assert_eq!(target.port, "5555");
        }

        let targets = plan(
            Some(&store),
            PRIMARY_KEY,
            "grpc.example.invalid:5555",
            |_| Err(io::Error::other("dig failed")),
        )
        .unwrap();
        assert_eq!(targets.len(), 2, "{targets:?}");
        assert!(!targets[0].from_dns && targets[0].ip == "198.51.100.4");
        assert!(!targets[1].from_dns && targets[1].ip == "192.0.2.20");

        let err = plan(
            Some(&store),
            PRIMARY_KEY,
            "missing.example.invalid:5555",
            |_| Err(io::Error::other("dig failed")),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "dig failed");

        let err = plan(
            Some(&store),
            PRIMARY_KEY,
            "missing.example.invalid:5555",
            |_| Ok::<_, io::Error>(vec!["0.0.0.0".parse().unwrap()]),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "cannot resolve missing.example.invalid");

        store
            .put(PRIMARY_KEY, "192.0.2.10", "5555", ["198.51.100.9"])
            .unwrap();
        let targets = plan(Some(&store), PRIMARY_KEY, "192.0.2.10:5555", boom).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(!targets[0].from_dns);
        assert_eq!(targets[0].ip, "192.0.2.10");
        assert_eq!(targets[0].dial_addr, "192.0.2.10:5555");
        assert_eq!(targets[0].authority, "192.0.2.10");
        assert_eq!(targets[0].server_name, "192.0.2.10");

        let err = plan(None, PRIMARY_KEY, "grpc.example.invalid", boom).unwrap_err();
        assert!(err.to_string().contains("grpc.example.invalid"), "{err}");
    }

    #[test]
    fn plan_ipv6_literal_dial_addr_brackets_server_name_bare() {
        let targets = plan(None, PRIMARY_KEY, "[2001:db8::10]:5555", boom).unwrap();
        assert_eq!(targets.len(), 1);
        let target = &targets[0];
        assert_eq!(target.dial_addr, "[2001:db8::10]:5555");
        assert_eq!(target.server_name, "2001:db8::10");
        assert_eq!(target.authority, "2001:db8::10");
        assert!(!target.server_name.contains('['));
        assert!(!target.server_name.contains(']'));
        assert!(!target.server_name.contains("5555"));
        assert!(!target.from_dns);
        assert_eq!(target.ip, "2001:db8::10");
        assert_eq!(target.host, "2001:db8::10");
        assert_eq!(target.port, "5555");
    }

    #[test]
    fn split_host_port_requires_port() {
        assert_eq!(
            split_host_port("grpc.example.invalid:5555").unwrap(),
            ("grpc.example.invalid", "5555")
        );
        assert_eq!(
            split_host_port("  [2001:db8::10]:5555 ").unwrap(),
            ("2001:db8::10", "5555")
        );
        assert!(split_host_port("grpc.example.invalid").is_err());
        assert!(split_host_port("2001:db8::10:5555").is_err());
        assert!(split_host_port(":5555").is_err());
        assert!(split_host_port("host:").is_err());
    }
}

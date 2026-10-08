//! 设备证书：Ed25519 CSR + Enroll/Renew，对齐 Go pkg/pki。
//! 面板 `grpc_tls.require_agent_mtls=true` 时 Control/Ingest 必须出示此证。

use crate::config::Config;
use crate::dialcache::{self, Store};
use crate::pb;
use crate::report::{dial_target, secret_interceptor};
use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519, SanType};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tonic::transport::Identity;
use tracing::{info, warn};

/// 登记/续期失败后退避。从 1s 翻倍，封顶 10s；续期或登记成功清零。
struct CredentialBackoff {
    delay: Duration,
    next_renew: Option<Instant>,
}

static CREDENTIAL_BACKOFF: Mutex<CredentialBackoff> = Mutex::new(CredentialBackoff {
    delay: Duration::ZERO,
    next_renew: None,
});

fn backoff_step(current: Duration) -> Duration {
    if current.is_zero() {
        Duration::from_secs(1)
    } else {
        current.saturating_mul(2).min(Duration::from_secs(10))
    }
}

/// 记录一次失败并返回本次应等待的时长。
pub fn note_credential_failure() -> Duration {
    let mut gate = CREDENTIAL_BACKOFF
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    gate.delay = backoff_step(gate.delay);
    gate.next_renew = Some(Instant::now() + gate.delay);
    gate.delay
}

pub fn clear_credential_backoff() {
    let mut gate = CREDENTIAL_BACKOFF
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    gate.delay = Duration::ZERO;
    gate.next_renew = None;
}

fn renew_due() -> bool {
    let gate = CREDENTIAL_BACKOFF
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    gate.next_renew.is_none_or(|at| Instant::now() >= at)
}

const CLIENT_KEY: &str = "client.key";
const CLIENT_CERT: &str = "client.crt";
const CLIENT_CA: &str = "ca.crt";

#[derive(Debug)]
pub struct Bundle {
    pub key_pem: Vec<u8>,
    pub cert_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}

#[derive(Clone)]
pub struct DeviceCredentials {
    pub identity: Identity,
    pub ca_pem: Vec<u8>,
}

impl Bundle {
    /// 解析失败必须上抛走重登记，不能让损坏 PEM 把进程打进崩溃循环。
    pub fn identity(&self) -> Result<Identity> {
        validate_pair(&self.key_pem, &self.cert_pem)?;
        Ok(Identity::from_pem(&self.cert_pem, &self.key_pem))
    }

    pub fn credentials(&self) -> Result<DeviceCredentials> {
        Ok(DeviceCredentials {
            identity: self.identity()?,
            ca_pem: self.ca_pem.clone(),
        })
    }

    fn not_after_unix(&self) -> Result<i64> {
        cert_not_after(&self.cert_pem)
    }

    fn expired(&self) -> bool {
        match self.not_after_unix() {
            Ok(ts) => now_unix() >= ts,
            Err(_) => true,
        }
    }

    /// `renew_days` 来自 `telemetry.cert_renew_days`；0 视为 7（对齐 Go ApplyDefaults）。
    fn needs_renew(&self, renew_days: u32) -> bool {
        let days = if renew_days == 0 { 7 } else { renew_days };
        let window_secs = i64::from(days) * 24 * 3600;
        match self.not_after_unix() {
            Ok(ts) => now_unix() >= ts.saturating_sub(window_secs),
            Err(_) => true,
        }
    }
}

pub fn agent_uri(node_uuid: &[u8; 16]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(19 + 32);
    s.push_str("urn:santaizi:agent:");
    for b in node_uuid {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn generate_key_and_csr(node_uuid: &[u8; 16]) -> Result<(Vec<u8>, Vec<u8>)> {
    let uri = agent_uri(node_uuid);
    let key_pair = KeyPair::generate_for(&PKCS_ED25519).context("生成 Ed25519 密钥失败")?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &uri);
    params.distinguished_name = dn;
    let ia5 = rcgen::Ia5String::try_from(uri.as_str())
        .map_err(|e| anyhow::anyhow!("URI SAN 非法: {e}"))?;
    params.subject_alt_names = vec![SanType::URI(ia5)];
    let csr = params
        .serialize_request(&key_pair)
        .context("序列化 CSR 失败")?;
    Ok((key_pair.serialize_pem().into_bytes(), csr.der().to_vec()))
}

fn pki_dir(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("pki")
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn cert_not_after(pem: &[u8]) -> Result<i64> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem).context("解析证书 PEM 失败")?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&parsed.contents).context("解析证书 DER 失败")?;
    Ok(cert.validity().not_after.timestamp())
}

/// key/cert 配对校验：崩溃半截留下的不匹配 bundle 若直接使用会造成永久 TLS 失败。
fn validate_pair(key_pem: &[u8], cert_pem: &[u8]) -> Result<()> {
    let key_str = std::str::from_utf8(key_pem).context("私钥不是合法 UTF-8 PEM")?;
    let key = KeyPair::from_pem(key_str).context("解析私钥 PEM 失败")?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem).context("解析证书 PEM 失败")?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&pem.contents).context("解析证书 DER 失败")?;
    if cert.public_key().raw != key.public_key_der() {
        bail!("证书与私钥不匹配");
    }
    Ok(())
}

/// 先写 `path.tmp`（创建即带目标权限，不留 umask 窗口），由调用方统一 rename。
fn write_tmp(path: &Path, bytes: &[u8], mode: u32) -> Result<PathBuf> {
    let tmp = {
        let mut p = path.as_os_str().to_os_string();
        p.push(".tmp");
        PathBuf::from(p)
    };
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // 崩溃残留的 tmp 权限可能不对，先删再以目标权限重建
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("写入 {} 失败", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("写入 {} 失败", tmp.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::write(&tmp, bytes).with_context(|| format!("写入 {} 失败", tmp.display()))?;
    Ok(tmp)
}

fn rename_tmp(tmp: &Path, path: &Path) -> Result<()> {
    std::fs::rename(tmp, path).with_context(|| format!("落盘 {} 失败", path.display()))
}

pub fn save_bundle(data_dir: &str, bundle: &Bundle) -> Result<()> {
    let dir = pki_dir(data_dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("创建 {} 失败", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    // key+cert 作为一个写入单元：全部 tmp 写好才逐个 rename；
    // 中途崩溃只会留下完整旧 pair，残留 .tmp 由下次写入覆盖。
    let key_tmp = write_tmp(&dir.join(CLIENT_KEY), &bundle.key_pem, 0o600)?;
    let cert_tmp = write_tmp(&dir.join(CLIENT_CERT), &bundle.cert_pem, 0o644)?;
    let ca_tmp = if bundle.ca_pem.is_empty() {
        None
    } else {
        Some(write_tmp(&dir.join(CLIENT_CA), &bundle.ca_pem, 0o644)?)
    };
    rename_tmp(&key_tmp, &dir.join(CLIENT_KEY))?;
    rename_tmp(&cert_tmp, &dir.join(CLIENT_CERT))?;
    if let Some(tmp) = ca_tmp {
        rename_tmp(&tmp, &dir.join(CLIENT_CA))?;
    }
    Ok(())
}

pub fn load_bundle(data_dir: &str) -> Result<Option<Bundle>> {
    let dir = pki_dir(data_dir);
    let key_path = dir.join(CLIENT_KEY);
    let cert_path = dir.join(CLIENT_CERT);
    match (std::fs::read(&key_path), std::fs::read(&cert_path)) {
        (Ok(key_pem), Ok(cert_pem)) => {
            let ca_pem = std::fs::read(dir.join(CLIENT_CA)).unwrap_or_default();
            let bundle = Bundle {
                key_pem,
                cert_pem,
                ca_pem,
            };
            // 损坏/不配对的 bundle 视为无 bundle，走重登记
            match validate_pair(&bundle.key_pem, &bundle.cert_pem) {
                Ok(()) => Ok(Some(bundle)),
                Err(e) => {
                    warn!(error = %format!("{e:#}"), "设备凭证 bundle 无效，将重新登记");
                    Ok(None)
                }
            }
        }
        (Err(e), _) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        (_, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        (Err(e), _) => Err(e).with_context(|| format!("读取 {} 失败", key_path.display())),
        (_, Err(e)) => Err(e).with_context(|| format!("读取 {} 失败", cert_path.display())),
    }
}

fn is_unimplemented(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<tonic::Status>()
            .is_some_and(|s| s.code() == tonic::Code::Unimplemented)
    })
}

fn bundle_from_response(key_pem: Vec<u8>, resp: pb::AgentEnrollResponse) -> Result<Bundle> {
    if resp.certificate_pem.is_empty() {
        bail!("Enrollment 响应缺少证书");
    }
    Ok(Bundle {
        key_pem,
        cert_pem: resp.certificate_pem.into_bytes(),
        ca_pem: resp.ca_certificate_pem.into_bytes(),
    })
}

fn primary_targets(cfg: &Config) -> Result<(Store, Vec<dialcache::Target>)> {
    let store = Store::open(&cfg.telemetry.data_dir)?;
    let dns = cfg.dns.clone();
    let targets = dialcache::plan(Some(&store), dialcache::PRIMARY_KEY, &cfg.server, |host| {
        crate::dns::lookup_ips(&dns, host)
    })?;
    Ok((store, targets))
}

fn remember_primary(store: &Store, target: &dialcache::Target) {
    if !target.from_dns {
        return;
    }
    if let Err(err) = store.put(
        dialcache::PRIMARY_KEY,
        &target.host,
        &target.port,
        [target.ip.as_str()],
    ) {
        warn!(error = %err, "写入拨号缓存失败");
    }
}

async fn enroll_once(cfg: &Config, node_uuid: [u8; 16], version: &str) -> Result<Bundle> {
    let (key_pem, csr_der) = generate_key_and_csr(&node_uuid)?;
    let (store, targets) = primary_targets(cfg)?;
    let auth = secret_interceptor(&cfg.client_secret)?;
    let mut last = None;
    for target in &targets {
        let channel = dial_target(cfg, target, &[], None, false)?;
        let mut client = pb::santaizi_enrollment_service_client::SantaiziEnrollmentServiceClient::with_interceptor(
            channel,
            auth.clone(),
        );
        match client
            .enroll(pb::AgentEnrollRequest {
                node_uuid: node_uuid.to_vec(),
                csr_der: csr_der.clone(),
                agent_version: version.to_string(),
            })
            .await
        {
            Ok(resp) => {
                remember_primary(&store, target);
                return bundle_from_response(key_pem, resp.into_inner());
            }
            Err(err) => last = Some(err),
        }
    }
    Err(last
        .map(|err| err.into())
        .unwrap_or_else(|| anyhow::anyhow!("no dial target")))
    .context("Enroll RPC 失败")
}

async fn renew_once(
    cfg: &Config,
    node_uuid: [u8; 16],
    version: &str,
    current: &Bundle,
) -> Result<Bundle> {
    let (key_pem, csr_der) = generate_key_and_csr(&node_uuid)?;
    let identity = current.identity()?;
    let (store, targets) = primary_targets(cfg)?;
    let mut last = None;
    for target in &targets {
        let channel = dial_target(cfg, target, &[], Some(&identity), false)?;
        let mut client =
            pb::santaizi_enrollment_service_client::SantaiziEnrollmentServiceClient::new(channel);
        match client
            .renew(pb::AgentRenewRequest {
                node_uuid: node_uuid.to_vec(),
                csr_der: csr_der.clone(),
                agent_version: version.to_string(),
            })
            .await
        {
            Ok(resp) => {
                remember_primary(&store, target);
                return bundle_from_response(key_pem, resp.into_inner());
            }
            Err(err) => last = Some(err),
        }
    }
    Err(last
        .map(|err| err.into())
        .unwrap_or_else(|| anyhow::anyhow!("no dial target")))
    .context("Renew RPC 失败")
}

/// TLS 开启时登记/续期设备证。仅当面板返回 Unimplemented 才回退密钥认证。
pub async fn ensure_device_credentials(
    cfg: &Config,
    node_uuid: [u8; 16],
    version: &str,
) -> Result<Option<DeviceCredentials>> {
    if !cfg.tls {
        return Ok(None);
    }
    if let Some(bundle) = load_bundle(&cfg.telemetry.data_dir)?
        && !bundle.expired()
    {
        if bundle.needs_renew(cfg.telemetry.cert_renew_days) && renew_due() {
            match renew_once(cfg, node_uuid, version, &bundle).await {
                Ok(renewed) => {
                    clear_credential_backoff();
                    save_bundle(&cfg.telemetry.data_dir, &renewed)?;
                    info!("设备证书已续期");
                    return Ok(Some(renewed.credentials()?));
                }
                Err(e) => {
                    let delay = note_credential_failure();
                    warn!(
                        error = %format!("{e:#}"),
                        delay_secs = delay.as_secs(),
                        "设备证书续期失败，继续使用现有证书"
                    );
                }
            }
        }
        return Ok(Some(bundle.credentials()?));
    }
    match enroll_once(cfg, node_uuid, version).await {
        Ok(bundle) => {
            clear_credential_backoff();
            save_bundle(&cfg.telemetry.data_dir, &bundle)?;
            info!("已登记设备证书");
            Ok(Some(bundle.credentials()?))
        }
        Err(e) if is_unimplemented(&e) => {
            warn!("面板不支持 Enrollment，回退到密钥认证");
            Ok(None)
        }
        Err(e) => Err(e).context("Enrollment 失败（require_agent_mtls 的面板必须成功登记）"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::pb;

    #[test]
    fn agent_uri_is_hex_without_dashes() {
        let id = [0x0a, 0x0b, 0x0c, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            agent_uri(&id),
            "urn:santaizi:agent:0a0b0c0d000000000000000000000001"
        );
    }

    #[test]
    fn csr_carries_uri_cn_and_san() {
        let id = [7u8; 16];
        let (key_pem, csr_der) = generate_key_and_csr(&id).expect("csr");
        assert!(
            String::from_utf8_lossy(&key_pem).contains("PRIVATE KEY"),
            "密钥应为 PKCS8 PEM"
        );
        use x509_parser::prelude::FromDer;
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&csr_der)
                .expect("parse csr");
        let uri = agent_uri(&id);
        let subject = csr.certification_request_info.subject.to_string();
        assert!(
            subject.contains(&uri),
            "CSR CN 应是设备 URI，实际: {subject}"
        );
    }

    /// 自签 bundle：仅用于落盘/配对校验测试。`not_after_year` 控制有效期。
    fn self_signed_bundle(not_after_year: i32) -> Bundle {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519).expect("keygen");
        let mut params = CertificateParams::new(vec!["test.local".to_string()]).expect("params");
        params.not_after = rcgen::date_time_ymd(not_after_year, 1, 1);
        let cert = params.self_signed(&key_pair).expect("self-signed");
        Bundle {
            key_pem: key_pair.serialize_pem().into_bytes(),
            cert_pem: cert.pem().into_bytes(),
            ca_pem: b"CA".to_vec(),
        }
    }

    fn test_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("santaizi-pki-{tag}-{}", std::process::id()))
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = test_dir("roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let bundle = self_signed_bundle(2050);
        let data_dir = dir.to_string_lossy().to_string();
        save_bundle(&data_dir, &bundle).unwrap();
        let loaded = load_bundle(&data_dir).unwrap().expect("loaded");
        assert_eq!(loaded.key_pem, bundle.key_pem);
        assert_eq!(loaded.cert_pem, bundle.cert_pem);
        assert_eq!(loaded.ca_pem, b"CA");
        // key 文件必须 0600（创建即带权限，无 umask 窗口）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("pki").join(CLIENT_KEY))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_mismatched_pair() {
        let dir = test_dir("mismatch");
        let _ = std::fs::remove_dir_all(&dir);
        let a = self_signed_bundle(2050);
        let b = self_signed_bundle(2050);
        let mixed = Bundle {
            key_pem: b.key_pem,
            cert_pem: a.cert_pem,
            ca_pem: a.ca_pem,
        };
        let data_dir = dir.to_string_lossy().to_string();
        save_bundle(&data_dir, &mixed).unwrap();
        assert!(
            load_bundle(&data_dir).unwrap().is_none(),
            "key/cert 不匹配的 bundle 必须视为无效，走重登记"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_corrupt_pem() {
        let dir = test_dir("corrupt");
        let _ = std::fs::remove_dir_all(&dir);
        let bundle = Bundle {
            key_pem: b"KEY".to_vec(),
            cert_pem: b"CERT".to_vec(),
            ca_pem: vec![],
        };
        let data_dir = dir.to_string_lossy().to_string();
        save_bundle(&data_dir, &bundle).unwrap();
        assert!(
            load_bundle(&data_dir).unwrap().is_none(),
            "损坏 PEM 必须视为无效 bundle 而不是 panic"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_errs_on_corrupt_pem() {
        let bundle = Bundle {
            key_pem: b"garbage".to_vec(),
            cert_pem: b"garbage".to_vec(),
            ca_pem: vec![],
        };
        assert!(bundle.identity().is_err());
    }

    #[test]
    fn expired_bundle_detected() {
        let bundle = self_signed_bundle(2020);
        assert!(bundle.expired());
        assert!(bundle.needs_renew(7));
        let fresh = self_signed_bundle(2050);
        assert!(!fresh.expired());
        assert!(!fresh.needs_renew(7));
        // 续期窗口可配置：窗口大于有效期时必须判定为待续期
        assert!(fresh.needs_renew(9000));
        // 0 回落默认 7 天（对齐 Go ApplyDefaults）
        assert!(!fresh.needs_renew(0));
    }

    struct MockEnroll {
        unimplemented: bool,
        secret: std::sync::Mutex<Option<String>>,
        csr_len: std::sync::Mutex<usize>,
    }

    #[tonic::async_trait]
    impl pb::santaizi_enrollment_service_server::SantaiziEnrollmentService for MockEnroll {
        async fn enroll(
            &self,
            request: tonic::Request<pb::AgentEnrollRequest>,
        ) -> std::result::Result<tonic::Response<pb::AgentEnrollResponse>, tonic::Status> {
            if self.unimplemented {
                return Err(tonic::Status::unimplemented("no enroll"));
            }
            *self.secret.lock().unwrap() = request
                .metadata()
                .get("client_secret")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let req = request.into_inner();
            *self.csr_len.lock().unwrap() = req.csr_der.len();
            if req.node_uuid.len() != 16 {
                return Err(tonic::Status::invalid_argument("node uuid"));
            }
            Ok(tonic::Response::new(pb::AgentEnrollResponse {
                certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                    .into(),
                ca_certificate_pem: "CA".into(),
                not_before_unix: 0,
                expires_at_unix: 0,
            }))
        }

        async fn renew(
            &self,
            _request: tonic::Request<pb::AgentRenewRequest>,
        ) -> std::result::Result<tonic::Response<pb::AgentEnrollResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("no renew"))
        }
    }

    fn free_addr() -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn enroll_once_sends_csr_and_secret() {
        use pb::santaizi_enrollment_service_server::SantaiziEnrollmentServiceServer;
        use std::sync::Arc;
        let mock = Arc::new(MockEnroll {
            unimplemented: false,
            secret: std::sync::Mutex::new(None),
            csr_len: std::sync::Mutex::new(0),
        });
        let addr = free_addr();
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(SantaiziEnrollmentServiceServer::from_arc(mock.clone()))
                .serve(addr),
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let cfg = Config {
            server: addr.to_string(),
            client_secret: "enroll-secret".into(),
            tls: false,
            ..Config::default()
        };
        let bundle = enroll_once(&cfg, [9u8; 16], "0.1.0-test")
            .await
            .expect("enroll");
        assert!(String::from_utf8_lossy(&bundle.cert_pem).contains("BEGIN CERTIFICATE"));
        assert_eq!(
            mock.secret.lock().unwrap().as_deref(),
            Some("enroll-secret")
        );
        assert!(*mock.csr_len.lock().unwrap() > 0);
        server.abort();
    }

    #[tokio::test]
    async fn enroll_unimplemented_is_detected() {
        use pb::santaizi_enrollment_service_server::SantaiziEnrollmentServiceServer;
        let mock = MockEnroll {
            unimplemented: true,
            secret: std::sync::Mutex::new(None),
            csr_len: std::sync::Mutex::new(0),
        };
        let addr = free_addr();
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(SantaiziEnrollmentServiceServer::new(mock))
                .serve(addr),
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let cfg = Config {
            server: addr.to_string(),
            client_secret: "x".into(),
            tls: false,
            ..Config::default()
        };
        let err = enroll_once(&cfg, [1u8; 16], "test").await.unwrap_err();
        assert!(is_unimplemented(&err), "{err:#}");
        server.abort();
    }
}

//! 设备证书：Ed25519 CSR + Enroll/Renew，对齐 Go pkg/pki。
//! 面板 `grpc_tls.require_agent_mtls=true` 时 Control/Ingest 必须出示此证。

use crate::config::Config;
use crate::pb;
use crate::report::{build_channel_with_identity, secret_interceptor};
use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519, SanType};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::transport::Identity;
use tracing::{info, warn};

const CLIENT_KEY: &str = "client.key";
const CLIENT_CERT: &str = "client.crt";
const CLIENT_CA: &str = "ca.crt";
const RENEW_WINDOW_SECS: i64 = 7 * 24 * 3600;

#[derive(Debug)]
pub struct Bundle {
    pub key_pem: Vec<u8>,
    pub cert_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}

impl Bundle {
    pub fn identity(&self) -> Identity {
        Identity::from_pem(&self.cert_pem, &self.key_pem)
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

    fn needs_renew(&self) -> bool {
        match self.not_after_unix() {
            Ok(ts) => now_unix() >= ts.saturating_sub(RENEW_WINDOW_SECS),
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

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let tmp = {
        let mut p = path.as_os_str().to_os_string();
        p.push(".tmp");
        PathBuf::from(p)
    };
    std::fs::write(&tmp, bytes).with_context(|| format!("写入 {} 失败", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("落盘 {} 失败", path.display()))?;
    Ok(())
}

pub fn save_bundle(data_dir: &str, bundle: &Bundle) -> Result<()> {
    let dir = pki_dir(data_dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("创建 {} 失败", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    write_atomic(&dir.join(CLIENT_KEY), &bundle.key_pem, 0o600)?;
    write_atomic(&dir.join(CLIENT_CERT), &bundle.cert_pem, 0o644)?;
    if !bundle.ca_pem.is_empty() {
        write_atomic(&dir.join(CLIENT_CA), &bundle.ca_pem, 0o644)?;
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
            Ok(Some(Bundle {
                key_pem,
                cert_pem,
                ca_pem,
            }))
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

async fn enroll_once(cfg: &Config, node_uuid: [u8; 16], version: &str) -> Result<Bundle> {
    let (key_pem, csr_der) = generate_key_and_csr(&node_uuid)?;
    let channel = build_channel_with_identity(cfg, None, false)?;
    let mut client =
        pb::santaizi_enrollment_service_client::SantaiziEnrollmentServiceClient::with_interceptor(
            channel,
            secret_interceptor(&cfg.client_secret)?,
        );
    let resp = client
        .enroll(pb::AgentEnrollRequest {
            node_uuid: node_uuid.to_vec(),
            csr_der,
            agent_version: version.to_string(),
        })
        .await
        .context("Enroll RPC 失败")?
        .into_inner();
    bundle_from_response(key_pem, resp)
}

async fn renew_once(
    cfg: &Config,
    node_uuid: [u8; 16],
    version: &str,
    current: &Bundle,
) -> Result<Bundle> {
    let (key_pem, csr_der) = generate_key_and_csr(&node_uuid)?;
    let identity = current.identity();
    let channel = build_channel_with_identity(cfg, Some(&identity), false)?;
    let mut client =
        pb::santaizi_enrollment_service_client::SantaiziEnrollmentServiceClient::new(channel);
    let resp = client
        .renew(pb::AgentRenewRequest {
            node_uuid: node_uuid.to_vec(),
            csr_der,
            agent_version: version.to_string(),
        })
        .await
        .context("Renew RPC 失败")?
        .into_inner();
    bundle_from_response(key_pem, resp)
}

/// TLS 开启时登记/续期设备证。仅当面板返回 Unimplemented 才回退密钥认证。
pub async fn ensure_device_credentials(
    cfg: &Config,
    node_uuid: [u8; 16],
    version: &str,
) -> Result<Option<Identity>> {
    if !cfg.tls {
        return Ok(None);
    }
    if let Some(bundle) = load_bundle(&cfg.telemetry.data_dir)?
        && !bundle.expired()
    {
        if bundle.needs_renew() {
            match renew_once(cfg, node_uuid, version, &bundle).await {
                Ok(renewed) => {
                    save_bundle(&cfg.telemetry.data_dir, &renewed)?;
                    info!("设备证书已续期");
                    return Ok(Some(renewed.identity()));
                }
                Err(e) => {
                    warn!(error = %format!("{e:#}"), "设备证书续期失败，继续使用现有证书");
                }
            }
        }
        return Ok(Some(bundle.identity()));
    }
    match enroll_once(cfg, node_uuid, version).await {
        Ok(bundle) => {
            save_bundle(&cfg.telemetry.data_dir, &bundle)?;
            info!("已登记设备证书");
            Ok(Some(bundle.identity()))
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

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("santaizi-pki-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let bundle = Bundle {
            key_pem: b"KEY".to_vec(),
            cert_pem: b"CERT".to_vec(),
            ca_pem: b"CA".to_vec(),
        };
        let data_dir = dir.to_string_lossy().to_string();
        save_bundle(&data_dir, &bundle).unwrap();
        let loaded = load_bundle(&data_dir).unwrap().expect("loaded");
        assert_eq!(loaded.key_pem, b"KEY");
        assert_eq!(loaded.cert_pem, b"CERT");
        assert_eq!(loaded.ca_pem, b"CA");
        let _ = std::fs::remove_dir_all(&dir);
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

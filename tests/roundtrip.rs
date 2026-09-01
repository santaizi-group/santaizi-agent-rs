//! 进程内 mock 面板：验证 v1 unary 通路的 wire 行为
//! （client_secret metadata、Host/State 序列化、Receipt 回包）。

use santaizi_agent_rs::config::Config;
use santaizi_agent_rs::monitor::Monitor;
use santaizi_agent_rs::netip::IpInfo;
use santaizi_agent_rs::pb::santaizi_service_client::SantaiziServiceClient;
use santaizi_agent_rs::pb::santaizi_service_server::{SantaiziService, SantaiziServiceServer};
use santaizi_agent_rs::pb::{GeoIp, Host, Receipt, State};
use santaizi_agent_rs::report;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tonic::metadata::MetadataValue;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

#[derive(Clone, Default)]
struct MockPanel {
    seen_secret: Arc<Mutex<Option<String>>>,
    seen_host: Arc<Mutex<Option<Host>>>,
    seen_state: Arc<Mutex<Option<State>>>,
}

#[tonic::async_trait]
impl SantaiziService for MockPanel {
    async fn report_system_state(
        &self,
        request: Request<State>,
    ) -> Result<Response<Receipt>, Status> {
        *self.seen_secret.lock().unwrap() = request
            .metadata()
            .get("client_secret")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        *self.seen_state.lock().unwrap() = Some(request.into_inner());
        Ok(Response::new(Receipt { proced: true }))
    }

    async fn report_system_info(
        &self,
        request: Request<Host>,
    ) -> Result<Response<Receipt>, Status> {
        *self.seen_host.lock().unwrap() = Some(request.into_inner());
        Ok(Response::new(Receipt { proced: true }))
    }

    async fn lookup_geo_ip(&self, request: Request<GeoIp>) -> Result<Response<GeoIp>, Status> {
        Ok(Response::new(request.into_inner()))
    }
}

fn free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

#[tokio::test]
async fn v1_unary_roundtrip() {
    let mock = MockPanel::default();
    let addr = free_addr();
    let server = tokio::spawn(
        Server::builder()
            .add_service(SantaiziServiceServer::new(mock.clone()))
            .serve(addr),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;

    let cfg = Config {
        server: addr.to_string(),
        client_secret: "test-secret".into(),
        ..Config::default()
    };
    let channel = report::build_channel(&cfg).unwrap();
    let secret = MetadataValue::try_from(cfg.client_secret.as_str()).unwrap();
    let mut client =
        SantaiziServiceClient::with_interceptor(channel, move |mut req: Request<()>| {
            req.metadata_mut().insert("client_secret", secret.clone());
            Ok(req)
        });

    let mut monitor = Monitor::new();
    let mut last_ip = IpInfo::default();
    report::report_host(&mut client, &cfg, &mut monitor, &mut last_ip, "0.1.0-test").await;
    let state = monitor.collect_state();
    client.report_system_state(state).await.unwrap();
    server.abort();

    assert_eq!(
        mock.seen_secret.lock().unwrap().as_deref(),
        Some("test-secret"),
        "面板应收到 client_secret metadata"
    );
    let host = mock
        .seen_host
        .lock()
        .unwrap()
        .clone()
        .expect("面板应收到 Host");
    assert_eq!(host.version, "0.1.0-test");
    assert!(!host.platform.is_empty());
    assert!(host.mem_total > 0);
    let state = mock
        .seen_state
        .lock()
        .unwrap()
        .clone()
        .expect("面板应收到 State");
    assert!(state.uptime > 0);
    assert!(state.mem_used > 0);
}

//! mock v2 面板：验证 Control（hello→凭证/指派）+ Ingest（hello→batch→ack）全链路。

use santaizi_agent_rs::config::{Config, TelemetryConfig};
use santaizi_agent_rs::pb;
use santaizi_agent_rs::pb::santaizi_control_service_server::{
    SantaiziControlService, SantaiziControlServiceServer,
};
use santaizi_agent_rs::pb::santaizi_telemetry_service_server::{
    SantaiziTelemetryService, SantaiziTelemetryServiceServer,
};
use santaizi_agent_rs::v2;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

#[derive(Default)]
struct Seen {
    control_secret: Mutex<Option<String>>,
    control_hello: Mutex<Option<pb::AgentControlHello>>,
    telemetry_secret: Mutex<Option<String>>,
    telemetry_hello: Mutex<Option<pb::TelemetryHello>>,
    events: Mutex<Vec<pb::TelemetryEvent>>,
    runtimes: Mutex<u32>,
}

type Mock = Arc<Seen>;

fn metadata_secret<T>(req: &Request<T>) -> Option<String> {
    req.metadata()
        .get("client_secret")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

struct MockControl {
    seen: Mock,
}

#[tonic::async_trait]
impl SantaiziControlService for MockControl {
    type ControlStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<pb::PrimaryControlResponse, Status>> + Send>,
    >;

    async fn control(
        &self,
        request: Request<Streaming<pb::AgentControlRequest>>,
    ) -> Result<Response<Self::ControlStream>, Status> {
        *self.seen.control_secret.lock().unwrap() = metadata_secret(&request);
        let mut inbound = request.into_inner();
        let seen = self.seen.clone();
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let Some(Ok(first)) = inbound.message().await.transpose() else {
                return;
            };
            let Some(pb::agent_control_request::Body::Hello(hello)) = first.body else {
                return;
            };
            *seen.control_hello.lock().unwrap() = Some(hello.clone());
            // 对齐真面板顺序：先凭证，后指派。
            let credential = pb::SignedAgentCredential {
                claims: b"claims".to_vec(),
                signature: b"sig".to_vec(),
                key_id: b"key1".to_vec(),
            };
            if out_tx
                .send(pb::PrimaryControlResponse {
                    body: Some(pb::primary_control_response::Body::Credential(credential)),
                })
                .await
                .is_err()
            {
                return;
            }
            let assignment = pb::EndpointAssignment {
                config_version: 1,
                endpoints: vec![pb::TelemetryEndpoint {
                    endpoint_id: "primary".into(),
                    kind: pb::EndpointKind::Primary as i32,
                    address: String::new(),
                    reliable: true,
                    tls: false,
                    insecure_tls: false,
                    generation: 7,
                    activation_session_id: vec![],
                    activation_sequence: 0,
                }],
            };
            if out_tx
                .send(pb::PrimaryControlResponse {
                    body: Some(pb::primary_control_response::Body::Assignment(assignment)),
                })
                .await
                .is_err()
            {
                return;
            }
            loop {
                match inbound.message().await {
                    Ok(Some(req)) => {
                        if matches!(req.body, Some(pb::agent_control_request::Body::Runtime(_))) {
                            *seen.runtimes.lock().unwrap() += 1;
                        }
                    }
                    _ => return,
                }
            }
        });
        Ok(Response::new(Box::pin(tokio_stream::StreamExt::map(
            ReceiverStream::new(out_rx),
            Ok,
        ))))
    }
}

struct MockTelemetry {
    seen: Mock,
}

#[tonic::async_trait]
impl SantaiziTelemetryService for MockTelemetry {
    type IngestStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<pb::TelemetryResponse, Status>> + Send>,
    >;

    async fn ingest(
        &self,
        request: Request<Streaming<pb::TelemetryRequest>>,
    ) -> Result<Response<Self::IngestStream>, Status> {
        *self.seen.telemetry_secret.lock().unwrap() = metadata_secret(&request);
        let mut inbound = request.into_inner();
        let seen = self.seen.clone();
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            let Some(Ok(first)) = inbound.message().await.transpose() else {
                return;
            };
            let Some(pb::telemetry_request::Body::Hello(hello)) = first.body else {
                return;
            };
            *seen.telemetry_hello.lock().unwrap() = Some(hello);
            loop {
                match inbound.message().await {
                    Ok(Some(pb::TelemetryRequest {
                        body: Some(pb::telemetry_request::Body::Batch(batch)),
                    })) => {
                        let mut max_seq = 0u64;
                        let mut session = vec![];
                        for record in &batch.records {
                            if let Some(pb::telemetry_record::Record::Event(event)) = &record.record
                            {
                                max_seq = max_seq.max(event.sequence);
                                session = event.session_id.clone();
                                seen.events.lock().unwrap().push(event.clone());
                            }
                        }
                        if max_seq > 0
                            && out_tx
                                .send(pb::TelemetryResponse {
                                    acks: vec![pb::SessionAck {
                                        node_uuid: vec![],
                                        session_id: session,
                                        ack_through: max_seq,
                                    }],
                                    accepted_gap_ids: vec![],
                                    error: String::new(),
                                    pong: None,
                                })
                                .await
                                .is_err()
                        {
                            return;
                        }
                    }
                    Ok(Some(_)) => {}
                    _ => return,
                }
            }
        });
        Ok(Response::new(Box::pin(tokio_stream::StreamExt::map(
            ReceiverStream::new(out_rx),
            Ok,
        ))))
    }
}

fn free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

#[tokio::test]
async fn v2_control_ingest_roundtrip() {
    let seen = Mock::default();
    let addr = free_addr();
    let server = tokio::spawn(
        Server::builder()
            .add_service(SantaiziControlServiceServer::new(MockControl {
                seen: seen.clone(),
            }))
            .add_service(SantaiziTelemetryServiceServer::new(MockTelemetry {
                seen: seen.clone(),
            }))
            .serve(addr),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;

    let data_dir = std::env::temp_dir().join(format!("santaizi-rs-test-{}", std::process::id()));
    let cfg = Config {
        server: addr.to_string(),
        client_secret: "test-secret".into(),
        protocol: "v2".into(),
        telemetry: TelemetryConfig {
            data_dir: data_dir.to_string_lossy().into(),
            state_interval: 1,
            heartbeat_interval: 1,
            host_interval: 3600,
            batch_size: 256,
        },
        ip_report_period: 3600,
        ..Config::default()
    };
    cfg.validate().unwrap();

    v2::run_with_shutdown(cfg, "0.2.0-test", async {
        tokio::time::sleep(Duration::from_secs(6)).await;
    })
    .await
    .unwrap();
    server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);

    // Control：hello 合法、带密钥。
    assert_eq!(
        seen.control_secret.lock().unwrap().as_deref(),
        Some("test-secret")
    );
    let hello = seen
        .control_hello
        .lock()
        .unwrap()
        .clone()
        .expect("应收到 control hello");
    assert_eq!(hello.node_uuid.len(), 16);
    assert_eq!(hello.session_id.len(), 16);
    assert_eq!(hello.agent_version, "0.2.0-test");
    assert!(hello.host.is_some());

    // Ingest：hello 走 primary、带上指派 generation 与凭证。
    assert_eq!(
        seen.telemetry_secret.lock().unwrap().as_deref(),
        Some("test-secret")
    );
    let hello = seen
        .telemetry_hello
        .lock()
        .unwrap()
        .clone()
        .expect("应收到 ingest hello");
    assert_eq!(hello.endpoint_id, "primary");
    assert_eq!(hello.assignment_generation, 7);
    assert_eq!(
        hello.credential.as_ref().map(|c| c.key_id.as_slice()),
        Some(b"key1".as_slice())
    );
    assert_eq!(hello.protocol_version, "2");

    // 事件：lifecycle(started+stopped) / host / state / heartbeat 四类齐备。
    let events = seen.events.lock().unwrap();
    let has = |t: pb::TelemetryEventType| events.iter().any(|e| e.event_type == t as i32);
    assert!(has(pb::TelemetryEventType::Lifecycle), "缺 lifecycle");
    assert!(has(pb::TelemetryEventType::Host), "缺 host");
    assert!(has(pb::TelemetryEventType::State), "缺 state");
    assert!(has(pb::TelemetryEventType::Heartbeat), "缺 heartbeat");
    let stopped = events.iter().any(|e| {
        e.event_type == pb::TelemetryEventType::Lifecycle as i32
            && matches!(&e.payload, Some(pb::telemetry_event::Payload::Lifecycle(l)) if l.kind == pb::LifecycleKind::AgentStopped as i32)
    });
    assert!(stopped, "退出前应上送 AGENT_STOPPED");
    // 序号从 1 递增且 event_id 为 16 字节。
    assert!(
        events
            .iter()
            .all(|e| e.sequence >= 1 && e.event_id.len() == 16)
    );
    // control 上至少收到一次 AgentRuntime。
    assert!(*seen.runtimes.lock().unwrap() >= 1);
}

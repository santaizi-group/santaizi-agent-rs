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
    telemetry_hellos: Mutex<Vec<pb::TelemetryHello>>,
    events: Mutex<Vec<pb::TelemetryEvent>>,
    runtimes: Mutex<u32>,
    probe_results: Mutex<Vec<pb::ProbeResult>>,
    pings: Mutex<u32>,
    snapshots: Mutex<u32>,
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
    extra_endpoints: Vec<pb::TelemetryEndpoint>,
    probes: Vec<pb::ProbeRequest>,
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
        let extra_endpoints = self.extra_endpoints.clone();
        let probes = self.probes.clone();
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
            let mut endpoints = vec![pb::TelemetryEndpoint {
                endpoint_id: "primary".into(),
                kind: pb::EndpointKind::Primary as i32,
                address: String::new(),
                reliable: true,
                tls: false,
                insecure_tls: false,
                generation: 7,
                activation_session_id: vec![],
                activation_sequence: 0,
            }];
            endpoints.extend(extra_endpoints);
            let assignment = pb::EndpointAssignment {
                config_version: 1,
                endpoints,
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
            for probe in probes {
                if out_tx
                    .send(pb::PrimaryControlResponse {
                        body: Some(pb::primary_control_response::Body::ProbeRequest(probe)),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            loop {
                match inbound.message().await {
                    Ok(Some(req)) => match req.body {
                        Some(pb::agent_control_request::Body::Runtime(_)) => {
                            *seen.runtimes.lock().unwrap() += 1;
                        }
                        Some(pb::agent_control_request::Body::ProbeResult(result)) => {
                            seen.probe_results.lock().unwrap().push(result);
                        }
                        _ => {}
                    },
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
    /// 对齐 grpc-go：Recv hello 后不立刻回 Response，直到再收到一条消息。
    hold_headers_until_second: bool,
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
        if self.hold_headers_until_second {
            let Some(Ok(first)) = inbound.message().await.transpose() else {
                return Err(Status::invalid_argument("ingest hello required"));
            };
            record_ingest_hello(&seen, first);
            let Some(Ok(second)) = inbound.message().await.transpose() else {
                return Err(Status::aborted("held headers until second message"));
            };
            apply_ingest_message(&seen, &out_tx, second).await;
            tokio::spawn(async move {
                loop {
                    match inbound.message().await {
                        Ok(Some(msg)) => apply_ingest_message(&seen, &out_tx, msg).await,
                        _ => return,
                    }
                }
            });
            return Ok(Response::new(Box::pin(tokio_stream::StreamExt::map(
                ReceiverStream::new(out_rx),
                Ok,
            ))));
        }
        tokio::spawn(async move {
            let Some(Ok(first)) = inbound.message().await.transpose() else {
                return;
            };
            record_ingest_hello(&seen, first);
            loop {
                match inbound.message().await {
                    Ok(Some(msg)) => apply_ingest_message(&seen, &out_tx, msg).await,
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

fn record_ingest_hello(seen: &Mock, first: pb::TelemetryRequest) {
    let Some(pb::telemetry_request::Body::Hello(hello)) = first.body else {
        return;
    };
    *seen.telemetry_hello.lock().unwrap() = Some(hello.clone());
    seen.telemetry_hellos.lock().unwrap().push(hello);
}

async fn apply_ingest_message(
    seen: &Mock,
    out_tx: &tokio::sync::mpsc::Sender<pb::TelemetryResponse>,
    msg: pb::TelemetryRequest,
) {
    match msg.body {
        Some(pb::telemetry_request::Body::Ping(_)) => {
            *seen.pings.lock().unwrap() += 1;
            let _ = out_tx
                .send(pb::TelemetryResponse {
                    acks: vec![],
                    accepted_gap_ids: vec![],
                    error: String::new(),
                    pong: Some(pb::TelemetryPong {}),
                })
                .await;
        }
        Some(pb::telemetry_request::Body::RealtimeSnapshot(_)) => {
            *seen.snapshots.lock().unwrap() += 1;
        }
        Some(pb::telemetry_request::Body::Batch(batch)) => {
            let mut max_seq = 0u64;
            let mut session = vec![];
            for record in &batch.records {
                if let Some(pb::telemetry_record::Record::Event(event)) = &record.record {
                    max_seq = max_seq.max(event.sequence);
                    session = event.session_id.clone();
                    seen.events.lock().unwrap().push(event.clone());
                }
            }
            if max_seq > 0 {
                let _ = out_tx
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
                    .await;
            }
        }
        _ => {}
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
                extra_endpoints: vec![],
                probes: vec![],
            }))
            .add_service(SantaiziTelemetryServiceServer::new(MockTelemetry {
                seen: seen.clone(),
                hold_headers_until_second: false,
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
            ..TelemetryConfig::default()
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
    let enabled = hello
        .capabilities
        .as_ref()
        .map(|c| c.enabled.clone())
        .unwrap_or_default();
    assert!(enabled.contains(&(pb::AgentCapability::ProbeHttp as i32)));
    assert!(enabled.contains(&(pb::AgentCapability::ProbeTcp as i32)));
    assert!(enabled.contains(&(pb::AgentCapability::ProbeIcmp as i32)));
    assert!(!enabled.contains(&(pb::AgentCapability::Nat as i32)));

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

/// grpc-go Ingest 要等第一次 Send 才回响应头。hello 之后若客户端停送，双方互等。
#[tokio::test]
async fn v2_ingest_unblocks_when_server_holds_headers() {
    let seen = Mock::default();
    let addr = free_addr();
    let server = tokio::spawn(
        Server::builder()
            .add_service(SantaiziControlServiceServer::new(MockControl {
                seen: seen.clone(),
                extra_endpoints: vec![],
                probes: vec![],
            }))
            .add_service(SantaiziTelemetryServiceServer::new(MockTelemetry {
                seen: seen.clone(),
                hold_headers_until_second: true,
            }))
            .serve(addr),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;

    let data_dir = std::env::temp_dir().join(format!(
        "santaizi-rs-test-{}-hold-headers",
        std::process::id()
    ));
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
            ..TelemetryConfig::default()
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

    assert!(
        seen.telemetry_hello.lock().unwrap().is_some(),
        "应收到 ingest hello"
    );
    let events = seen.events.lock().unwrap();
    assert!(
        !events.is_empty(),
        "hold-headers 时仍应上送事件，否则 tonic 会卡在 ingest().await"
    );
}

#[tokio::test]
async fn v2_collector_ingest_and_tcp_probe() {
    use tokio::net::TcpListener;

    let seen = Mock::default();
    let primary = free_addr();
    let collector = free_addr();
    let probe_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let probe_addr = probe_listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let (s, _) = probe_listener.accept().await.unwrap();
        drop(s);
    });

    let extra = vec![pb::TelemetryEndpoint {
        endpoint_id: "c1".into(),
        kind: pb::EndpointKind::Collector as i32,
        address: collector.to_string(),
        reliable: true,
        tls: false,
        insecure_tls: false,
        generation: 4,
        activation_session_id: vec![],
        activation_sequence: 0,
    }];
    let probe = pb::ProbeRequest {
        probe_id: "tcp-e2e".into(),
        target: Some(pb::probe_request::Target::Tcp(pb::TcpProbeRequest {
            host: "127.0.0.1".into(),
            port: probe_addr.port() as u32,
            timeout_ms: 3000,
        })),
    };

    let primary_server = tokio::spawn(
        Server::builder()
            .add_service(SantaiziControlServiceServer::new(MockControl {
                seen: seen.clone(),
                extra_endpoints: extra,
                probes: vec![probe],
            }))
            .add_service(SantaiziTelemetryServiceServer::new(MockTelemetry {
                seen: seen.clone(),
                hold_headers_until_second: false,
            }))
            .serve(primary),
    );
    let collector_server = tokio::spawn(
        Server::builder()
            .add_service(SantaiziTelemetryServiceServer::new(MockTelemetry {
                seen: seen.clone(),
                hold_headers_until_second: false,
            }))
            .serve(collector),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;

    let data_dir =
        std::env::temp_dir().join(format!("santaizi-rs-test-{}-multi", std::process::id()));
    let cfg = Config {
        server: primary.to_string(),
        client_secret: "test-secret".into(),
        protocol: "v2".into(),
        telemetry: TelemetryConfig {
            data_dir: data_dir.to_string_lossy().into(),
            state_interval: 1,
            heartbeat_interval: 1,
            host_interval: 3600,
            batch_size: 256,
            ..TelemetryConfig::default()
        },
        ip_report_period: 3600,
        ..Config::default()
    };
    cfg.validate().unwrap();

    v2::run_with_shutdown(cfg, "0.2.0-test", async {
        tokio::time::sleep(Duration::from_secs(7)).await;
    })
    .await
    .unwrap();
    primary_server.abort();
    collector_server.abort();
    let _ = accept.await;
    let _ = std::fs::remove_dir_all(&data_dir);

    let ids: std::collections::HashSet<_> = seen
        .telemetry_hellos
        .lock()
        .unwrap()
        .iter()
        .map(|h| h.endpoint_id.clone())
        .collect();
    assert!(ids.contains("primary"), "缺 primary ingest: {ids:?}");
    assert!(ids.contains("c1"), "缺 collector ingest: {ids:?}");

    let results = seen.probe_results.lock().unwrap();
    assert_eq!(results.len(), 1, "应回一条探测结果");
    assert!(
        results[0].successful,
        "tcp probe error={}",
        results[0].error
    );
    assert_eq!(results[0].probe_id, "tcp-e2e");
}

/// 并发上限 32：慢目标占满许可后，超出的 probe 必须立即回失败结果而不是排队。
#[tokio::test]
async fn v2_probe_concurrency_limit() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    let http_server = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = http_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = s.read(&mut buf).await;
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await;
            });
        }
    });

    const PROBE_COUNT: usize = 40;
    let probes: Vec<pb::ProbeRequest> = (0..PROBE_COUNT)
        .map(|i| pb::ProbeRequest {
            probe_id: format!("http-{i}"),
            target: Some(pb::probe_request::Target::Http(pb::HttpProbeRequest {
                url: format!("http://127.0.0.1:{http_port}"),
                timeout_ms: 8000,
            })),
        })
        .collect();

    let seen = Mock::default();
    let addr = free_addr();
    let server = tokio::spawn(
        Server::builder()
            .add_service(SantaiziControlServiceServer::new(MockControl {
                seen: seen.clone(),
                extra_endpoints: vec![],
                probes,
            }))
            .add_service(SantaiziTelemetryServiceServer::new(MockTelemetry {
                seen: seen.clone(),
                hold_headers_until_second: false,
            }))
            .serve(addr),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;

    let data_dir =
        std::env::temp_dir().join(format!("santaizi-rs-test-{}-probe", std::process::id()));
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
            ..TelemetryConfig::default()
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
    http_server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);

    let results = seen.probe_results.lock().unwrap();
    assert_eq!(results.len(), PROBE_COUNT, "每个 probe 都必须有结果");
    let rejected = results
        .iter()
        .filter(|r| r.error.contains("concurrency limit"))
        .count();
    let ok = results.iter().filter(|r| r.successful).count();
    assert_eq!(rejected, PROBE_COUNT - 32, "超过上限的必须立即拒绝");
    assert_eq!(ok, 32, "上限内的必须执行成功");
}

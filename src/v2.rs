//! v2 通路：Control（认证/凭证/指派）+ Ingest（事件批量上送）双向流。
//! 对齐 Go 探针 telemetry_v2.go 的最小集：内存队列代替 WAL（重启丢未确认事件，
//! 新会话序号重排，面板按 session 幂等去重，不会混淆）。

use crate::config::Config;
use crate::monitor::Monitor;
use crate::netip::{self, IpInfo};
use crate::pb;
use crate::report::{IP_FETCH_TIMEOUT, secret_interceptor};
use anyhow::{Context, Result, bail};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, mpsc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tracing::{debug, info, warn};

pub const PROTOCOL_VERSION: &str = "2";
const RECONNECT_DELAY: Duration = Duration::from_secs(10);
/// 面板 ingest 队列上限同值；内存队列满则丢最旧（代替 WAL 的数据丢失事实）。
const QUEUE_CAP: usize = 4096;
const RUNTIME_INTERVAL: Duration = Duration::from_secs(15);
/// 对齐 Go：每 24h 主动断流刷新凭证。
const CREDENTIAL_REFRESH: Duration = Duration::from_secs(24 * 3600);
/// 退出前留给 ingest 冲刷 STOPPED 事件的窗口。
const SHUTDOWN_FLUSH: Duration = Duration::from_secs(2);

pub struct Shared {
    pub node_uuid: [u8; 16],
    pub session_id: [u8; 16],
    started: Instant,
    seq: AtomicU64,
    queue: Mutex<VecDeque<pb::TelemetryEvent>>,
    credential: Mutex<Option<pb::SignedAgentCredential>>,
    endpoint: Mutex<Option<pb::TelemetryEndpoint>>,
    ready: Notify,
}

impl Shared {
    pub fn new(node_uuid: [u8; 16], session_id: [u8; 16]) -> Self {
        Self {
            node_uuid,
            session_id,
            started: Instant::now(),
            seq: AtomicU64::new(0),
            queue: Mutex::new(VecDeque::new()),
            credential: Mutex::new(None),
            endpoint: Mutex::new(None),
            ready: Notify::new(),
        }
    }

    fn append(
        &self,
        event_type: pb::TelemetryEventType,
        priority: pb::TelemetryPriority,
        payload: pb::telemetry_event::Payload,
    ) {
        let sequence = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let now = now_nanos();
        let elapsed = self.started.elapsed().as_nanos() as u64;
        // 对齐 Go：state 事件的 agent_uptime 用主机 uptime，其余用进程存活时长。
        let uptime_nano = match &payload {
            pb::telemetry_event::Payload::State(s) => s.uptime.saturating_mul(1_000_000_000),
            _ => elapsed,
        };
        let event = pb::TelemetryEvent {
            event_id: crate::identity::event_id(&self.node_uuid, &self.session_id, sequence)
                .to_vec(),
            node_uuid: self.node_uuid.to_vec(),
            session_id: self.session_id.to_vec(),
            sequence,
            event_type: event_type as i32,
            priority: priority as i32,
            collected_at_unix_nano: now,
            agent_uptime_nano: uptime_nano,
            session_elapsed_nano: elapsed,
            protocol_version: 2,
            source_protocol: pb::SourceProtocol::SantaiziV2 as i32,
            reliability: pb::Reliability::ReliableReplay as i32,
            payload: Some(payload),
        };
        let mut q = self.queue.lock().unwrap();
        if q.len() >= QUEUE_CAP {
            q.pop_front();
            warn!("事件内存队列满（{}），丢弃最旧事件", QUEUE_CAP);
        }
        q.push_back(event);
    }

    fn peek_batch(&self, max: usize) -> Vec<pb::TelemetryRecord> {
        self.queue
            .lock()
            .unwrap()
            .iter()
            .take(max)
            .map(|e| pb::TelemetryRecord {
                record: Some(pb::telemetry_record::Record::Event(e.clone())),
            })
            .collect()
    }

    fn ack_through(&self, session_id: &[u8], through: u64) {
        if session_id != self.session_id {
            return; // 旧会话的 ack，忽略
        }
        let mut q = self.queue.lock().unwrap();
        while q.front().is_some_and(|e| e.sequence <= through) {
            q.pop_front();
        }
    }

    fn pending(&self) -> u64 {
        self.queue.lock().unwrap().len() as u64
    }

    fn oldest_pending(&self) -> i64 {
        self.queue
            .lock()
            .unwrap()
            .front()
            .map(|e| e.collected_at_unix_nano)
            .unwrap_or(0)
    }

    fn set_credential(&self, credential: pb::SignedAgentCredential) {
        *self.credential.lock().unwrap() = Some(credential);
        self.ready.notify_waiters();
    }

    fn set_assignment(&self, assignment: pb::EndpointAssignment) {
        let primary = assignment
            .endpoints
            .into_iter()
            .find(|e| e.kind == pb::EndpointKind::Primary as i32 || e.endpoint_id == "primary");
        if let Some(endpoint) = primary {
            *self.endpoint.lock().unwrap() = Some(endpoint);
            self.ready.notify_waiters();
        }
    }

    async fn wait_ready(&self) -> (pb::SignedAgentCredential, pb::TelemetryEndpoint) {
        loop {
            let pair = {
                let c = self.credential.lock().unwrap().clone();
                let e = self.endpoint.lock().unwrap().clone();
                c.zip(e)
            };
            if let Some(pair) = pair {
                return pair;
            }
            self.ready.notified().await;
        }
    }

    fn runtime(&self) -> pb::AgentRuntime {
        pb::AgentRuntime {
            wal_pressure: pb::WalPressure::Healthy as i32,
            wal_bytes: 0,
            pending_events: self.pending(),
            oldest_pending_unix_nano: self.oldest_pending(),
            sinks: vec![],
            clock_untrusted: false,
            protocol_version: PROTOCOL_VERSION.into(),
            capabilities: Some(capabilities()),
        }
    }
}

/// MVP 实际具备的能力；温度/GPU/探测/NAT 不上报。
pub fn capabilities() -> pb::AgentCapabilities {
    use pb::AgentCapability as C;
    pb::AgentCapabilities {
        enabled: [
            C::MetricCpu,
            C::MetricMemory,
            C::MetricDisk,
            C::MetricNetwork,
            C::MetricConnections,
            C::MetricProcesses,
            C::HostInfo,
            C::IpReport,
        ]
        .iter()
        .map(|c| *c as i32)
        .collect(),
    }
}

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn effective_endpoint_id(endpoint: &pb::TelemetryEndpoint) -> String {
    if endpoint.endpoint_id.is_empty() {
        "primary".into()
    } else {
        endpoint.endpoint_id.clone()
    }
}

async fn control_loop(
    cfg: Config,
    channel: Channel,
    shared: Arc<Shared>,
    host: pb::Host,
    version: String,
) {
    loop {
        if let Err(e) = control_once(&cfg, channel.clone(), &shared, &host, &version).await {
            warn!(error = %format!("{e:#}"), "control 流断开，{}s 后重连", RECONNECT_DELAY.as_secs());
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

async fn control_once(
    cfg: &Config,
    channel: Channel,
    shared: &Arc<Shared>,
    host: &pb::Host,
    version: &str,
) -> Result<()> {
    let mut client =
        pb::santaizi_control_service_client::SantaiziControlServiceClient::with_interceptor(
            channel,
            secret_interceptor(&cfg.client_secret)?,
        );
    let (tx, rx) = mpsc::channel::<pb::AgentControlRequest>(32);
    // grpc-go 在 Recv hello 之前不回响应头；hello 必须在 control().await 前入队。
    tx.send(pb::AgentControlRequest {
        body: Some(pb::agent_control_request::Body::Hello(
            pb::AgentControlHello {
                node_uuid: shared.node_uuid.to_vec(),
                session_id: shared.session_id.to_vec(),
                current_config_version: 0,
                agent_version: version.to_string(),
                host: Some(host.clone()),
                capabilities: Some(capabilities()),
            },
        )),
    })
    .await
    .context("control hello 入队失败")?;
    let mut stream = client
        .control(ReceiverStream::new(rx))
        .await
        .context("control 建流失败")?
        .into_inner();
    info!("control 流已建立");

    let mut runtime_tick = tokio::time::interval(RUNTIME_INTERVAL);
    let mut refresh_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + CREDENTIAL_REFRESH,
        CREDENTIAL_REFRESH,
    );
    loop {
        tokio::select! {
            msg = stream.next() => {
                let resp = match msg {
                    Some(Ok(r)) => r,
                    Some(Err(e)) => return Err(e.into()),
                    None => bail!("面板关闭了 control 流"),
                };
                match resp.body {
                    Some(pb::primary_control_response::Body::Credential(credential)) => {
                        debug!("收到新凭证");
                        shared.set_credential(credential);
                    }
                    Some(pb::primary_control_response::Body::Assignment(assignment)) => {
                        debug!(config_version = assignment.config_version, "收到 endpoint 指派");
                        shared.set_assignment(assignment);
                    }
                    Some(pb::primary_control_response::Body::ProbeRequest(req)) => {
                        let kind = match &req.target {
                            Some(pb::probe_request::Target::Http(_)) => pb::ProbeKind::Http,
                            Some(pb::probe_request::Target::Icmp(_)) => pb::ProbeKind::Icmp,
                            Some(pb::probe_request::Target::Tcp(_)) => pb::ProbeKind::Tcp,
                            None => pb::ProbeKind::Unspecified,
                        };
                        let result = pb::ProbeResult {
                            probe_id: req.probe_id,
                            kind: kind as i32,
                            successful: false,
                            delay_ms: 0.0,
                            error: "santaizi-agent-rs 尚不支持服务探测".into(),
                            completed_at_unix_nano: now_nanos(),
                            detail: None,
                        };
                        let _ = tx.send(pb::AgentControlRequest {
                            body: Some(pb::agent_control_request::Body::ProbeResult(result)),
                        }).await;
                    }
                    Some(pb::primary_control_response::Body::NatOpenRequest(req)) => {
                        let _ = tx.send(pb::AgentControlRequest {
                            body: Some(pb::agent_control_request::Body::NatOpenResult(pb::NatOpenResult {
                                stream_id: req.stream_id,
                                accepted: false,
                                error: "santaizi-agent-rs 尚不支持 NAT".into(),
                            })),
                        }).await;
                    }
                    None => {}
                }
            }
            _ = runtime_tick.tick() => {
                tx.send(pb::AgentControlRequest {
                    body: Some(pb::agent_control_request::Body::Runtime(shared.runtime())),
                }).await.context("runtime 发送失败")?;
            }
            _ = refresh_tick.tick() => {
                info!("到达凭证刷新周期，重建 control 流");
                return Ok(());
            }
        }
    }
}

async fn ingest_loop(cfg: Config, channel: Channel, shared: Arc<Shared>) {
    loop {
        if let Err(e) = ingest_once(&cfg, channel.clone(), &shared).await {
            warn!(error = %format!("{e:#}"), "ingest 流断开，{}s 后重连", RECONNECT_DELAY.as_secs());
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

async fn ingest_once(cfg: &Config, channel: Channel, shared: &Arc<Shared>) -> Result<()> {
    let (credential, endpoint) = shared.wait_ready().await;
    let mut client =
        pb::santaizi_telemetry_service_client::SantaiziTelemetryServiceClient::with_interceptor(
            channel,
            secret_interceptor(&cfg.client_secret)?,
        );
    let (tx, rx) = mpsc::channel::<pb::TelemetryRequest>(64);
    tx.send(pb::TelemetryRequest {
        body: Some(pb::telemetry_request::Body::Hello(pb::TelemetryHello {
            node_uuid: shared.node_uuid.to_vec(),
            endpoint_id: effective_endpoint_id(&endpoint),
            assignment_generation: endpoint.generation,
            credential: Some(credential),
            protocol_version: PROTOCOL_VERSION.into(),
            agent_runtime: Some(shared.runtime()),
        })),
    })
    .await
    .context("ingest hello 入队失败")?;
    let mut stream = client
        .ingest(ReceiverStream::new(rx))
        .await
        .context("ingest 建流失败")?
        .into_inner();
    info!(generation = endpoint.generation, "ingest 流已建立");

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let records = shared.peek_batch(cfg.telemetry.batch_size);
                if !records.is_empty() {
                    tx.send(pb::TelemetryRequest {
                        body: Some(pb::telemetry_request::Body::Batch(pb::TelemetryBatch { records })),
                    }).await.context("batch 发送失败")?;
                }
            }
            msg = stream.next() => {
                match msg {
                    Some(Ok(resp)) => {
                        if !resp.error.is_empty() {
                            warn!(error = %resp.error, "面板 ingest 报错");
                        }
                        for ack in resp.acks {
                            shared.ack_through(&ack.session_id, ack.ack_through);
                        }
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => bail!("面板关闭了 ingest 流"),
                }
            }
        }
    }
}

struct CollectContext {
    cfg: Config,
    shared: Arc<Shared>,
    monitor: Monitor,
    last_ip: IpInfo,
    boot_time: u64,
    version: String,
}

impl CollectContext {
    fn country(&self) -> String {
        if self.cfg.country_code.is_empty() {
            self.last_ip.country_code.clone()
        } else {
            self.cfg.country_code.clone()
        }
    }

    fn append_host(&mut self) {
        let host = self
            .monitor
            .host(&self.last_ip.ip, &self.country(), &self.version);
        self.shared.append(
            pb::TelemetryEventType::Host,
            pb::TelemetryPriority::P1Important,
            pb::telemetry_event::Payload::Host(host),
        );
    }
}

async fn collect_loop<F: Future<Output = ()>>(mut cx: CollectContext, shutdown: F) {
    cx.shared.append(
        pb::TelemetryEventType::Lifecycle,
        pb::TelemetryPriority::P0Critical,
        pb::telemetry_event::Payload::Lifecycle(pb::LifecyclePayload {
            kind: pb::LifecycleKind::AgentStarted as i32,
            reason: "agent started".into(),
            previous_node_uuid: vec![],
        }),
    );
    cx.append_host();

    let mut state_tick =
        tokio::time::interval(Duration::from_secs(cx.cfg.telemetry.state_interval.max(1)));
    let mut heartbeat_tick = tokio::time::interval(Duration::from_secs(
        cx.cfg.telemetry.heartbeat_interval.max(1),
    ));
    let host_interval = Duration::from_secs(cx.cfg.telemetry.host_interval.max(60));
    let ip_interval = Duration::from_secs(cx.cfg.ip_report_period.max(60));
    let mut host_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + host_interval, host_interval);
    let mut ip_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + ip_interval, ip_interval);
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            _ = state_tick.tick() => {
                let state = cx.monitor.collect_state();
                cx.shared.append(
                    pb::TelemetryEventType::State,
                    pb::TelemetryPriority::P2Normal,
                    pb::telemetry_event::Payload::State(state),
                );
            }
            _ = heartbeat_tick.tick() => {
                cx.shared.append(
                    pb::TelemetryEventType::Heartbeat,
                    pb::TelemetryPriority::P0Critical,
                    pb::telemetry_event::Payload::Heartbeat(pb::HeartbeatPayload {
                        boot_time_unix: cx.boot_time,
                    }),
                );
            }
            _ = host_tick.tick() => {
                cx.append_host();
            }
            _ = ip_tick.tick() => {
                if let Ok(Ok(info)) = tokio::task::spawn_blocking(|| netip::fetch_ip_info(IP_FETCH_TIMEOUT)).await
                    && info != cx.last_ip
                {
                    cx.last_ip = info;
                    cx.append_host();
                }
            }
            _ = &mut shutdown => {
                cx.shared.append(
                    pb::TelemetryEventType::Lifecycle,
                    pb::TelemetryPriority::P0Critical,
                    pb::telemetry_event::Payload::Lifecycle(pb::LifecyclePayload {
                        kind: pb::LifecycleKind::AgentStopped as i32,
                        reason: "agent stopped".into(),
                        previous_node_uuid: vec![],
                    }),
                );
                info!("收到退出信号，等待事件冲刷");
                tokio::time::sleep(SHUTDOWN_FLUSH).await;
                break;
            }
        }
    }
}

pub async fn run(cfg: Config, version: &str) -> Result<()> {
    run_with_shutdown(cfg, version, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

pub async fn run_with_shutdown<F: Future<Output = ()>>(
    cfg: Config,
    version: &str,
    shutdown: F,
) -> Result<()> {
    let node_uuid = crate::identity::load_or_create(&cfg.telemetry.data_dir)?;
    let session_id = crate::identity::new_session_id();
    let device = crate::pki::ensure_device_credentials(&cfg, node_uuid, version).await?;
    let shared = Arc::new(Shared::new(node_uuid, session_id));

    let mut monitor = Monitor::new();
    let last_ip = match tokio::task::spawn_blocking(|| netip::fetch_ip_info(IP_FETCH_TIMEOUT)).await
    {
        Ok(Ok(info)) => info,
        Ok(Err(e)) => {
            warn!(error = %e, "IP 自查失败，Host 暂不带 IP/归属地");
            IpInfo::default()
        }
        Err(e) => {
            warn!(error = %e, "IP 自查任务异常");
            IpInfo::default()
        }
    };
    let country = if cfg.country_code.is_empty() {
        last_ip.country_code.clone()
    } else {
        cfg.country_code.clone()
    };
    let host = monitor.host(&last_ip.ip, &country, version);
    let boot_time = monitor.boot_time();

    let channel = crate::report::build_channel_with_identity(&cfg, device.as_ref(), true)?;
    let control = tokio::spawn(control_loop(
        cfg.clone(),
        channel.clone(),
        shared.clone(),
        host,
        version.to_string(),
    ));
    let ingest = tokio::spawn(ingest_loop(cfg.clone(), channel, shared.clone()));

    let cx = CollectContext {
        cfg,
        shared,
        monitor,
        last_ip,
        boot_time,
        version: version.to_string(),
    };
    collect_loop(cx, shutdown).await;

    control.abort();
    ingest.abort();
    Ok(())
}

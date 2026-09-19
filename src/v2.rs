//! v2 通路：Control + 多 endpoint Ingest。内存队列代替 WAL（重启丢未确认事件）。

use crate::config::Config;
use crate::monitor::Monitor;
use crate::netip::{self, IpInfo};
use crate::pb;
use crate::pki::DeviceCredentials;
use crate::report::{self, IP_FETCH_TIMEOUT, secret_interceptor};
use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};

pub const PROTOCOL_VERSION: &str = "2";
const RECONNECT_DELAY: Duration = Duration::from_secs(10);
/// 面板 ingest 队列上限同值；内存队列满则丢最旧（代替 WAL 的数据丢失事实）。
const QUEUE_CAP: usize = 4096;
/// 队列满时每 tick 都在丢，warn 节流避免刷屏。
const QUEUE_FULL_WARN_INTERVAL: Duration = Duration::from_secs(30);
const RUNTIME_INTERVAL: Duration = Duration::from_secs(15);
const SINK_RTT_INTERVAL: Duration = Duration::from_secs(15);
/// 对齐 Go：每 24h 主动断流刷新凭证。
const CREDENTIAL_REFRESH: Duration = Duration::from_secs(24 * 3600);
/// 退出前留给 ingest 冲刷 STOPPED 事件的窗口。
const SHUTDOWN_FLUSH: Duration = Duration::from_secs(2);
/// 单次入队上限：mpsc 满意味着对端停读（半开连接），超时判连接死亡。
/// 只包单次 send；流式 RPC 整体禁止套 timeout。
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// ProbeRequest 并发上限；超出立即回失败结果（口径同 NatOpenResult 的 accepted:false）。
const MAX_CONCURRENT_PROBES: usize = 32;
/// ping 节拍固定 SINK_RTT_INTERVAL；连续丢失这么多个 pong 判定 ingest 连接死亡。
const PING_MISS_LIMIT: u32 = 3;
/// IP 自查失败后的快重试间隔（对齐 Go myip.go UpdateIP：双栈都失败 1 分钟后重试）。
const IP_RETRY_DELAY: Duration = Duration::from_secs(60);

struct Inner {
    queue: VecDeque<pb::TelemetryEvent>,
    credential: Option<pb::SignedAgentCredential>,
    endpoints: HashMap<String, pb::TelemetryEndpoint>,
    acks: HashMap<String, u64>,
    sinks: HashMap<String, pb::SinkRuntime>,
    latest_host: Option<pb::Host>,
    latest_state: Option<pb::State>,
    latest_seq: u64,
    latest_at: i64,
    queue_full_warned_at: Option<Instant>,
}

pub struct Shared {
    pub node_uuid: [u8; 16],
    pub session_id: [u8; 16],
    started: Instant,
    seq: AtomicU64,
    /// 最近一次应用的指派 config_version，control hello 回传。
    config_version: AtomicU64,
    inner: Mutex<Inner>,
    // watch 代替 Notify：notify_waiters 不存 permit，check-then-wait 之间会丢唤醒
    ready: watch::Sender<bool>,
    assignment_changed: watch::Sender<u64>,
}

impl Shared {
    pub fn new(node_uuid: [u8; 16], session_id: [u8; 16]) -> Self {
        Self {
            node_uuid,
            session_id,
            started: Instant::now(),
            seq: AtomicU64::new(0),
            config_version: AtomicU64::new(0),
            inner: Mutex::new(Inner {
                queue: VecDeque::new(),
                credential: None,
                endpoints: HashMap::new(),
                acks: HashMap::new(),
                sinks: HashMap::new(),
                latest_host: None,
                latest_state: None,
                latest_seq: 0,
                latest_at: 0,
                queue_full_warned_at: None,
            }),
            ready: watch::channel(false).0,
            assignment_changed: watch::channel(0).0,
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
        let mut inner = self.inner.lock().unwrap();
        match &event.payload {
            Some(pb::telemetry_event::Payload::State(s)) => {
                inner.latest_state = Some(s.clone());
            }
            Some(pb::telemetry_event::Payload::Host(h)) => {
                inner.latest_host = Some(h.clone());
            }
            _ => {}
        }
        inner.latest_seq = sequence;
        inner.latest_at = now;
        if inner.queue.len() >= QUEUE_CAP {
            inner.queue.pop_front();
            let now = Instant::now();
            if inner
                .queue_full_warned_at
                .is_none_or(|t| now.duration_since(t) >= QUEUE_FULL_WARN_INTERVAL)
            {
                warn!("事件内存队列满（{}），丢弃最旧事件", QUEUE_CAP);
                inner.queue_full_warned_at = Some(now);
            }
        }
        inner.queue.push_back(event);
    }

    fn peek_batch(&self, endpoint_id: &str, max: usize) -> Vec<pb::TelemetryRecord> {
        let inner = self.inner.lock().unwrap();
        let activation = inner
            .endpoints
            .get(endpoint_id)
            .map(|e| e.activation_sequence.max(1))
            .unwrap_or(1);
        let ack = inner.acks.get(endpoint_id).copied().unwrap_or(0);
        inner
            .queue
            .iter()
            .filter(|e| e.sequence >= activation && e.sequence > ack)
            .take(max)
            .map(|e| pb::TelemetryRecord {
                record: Some(pb::telemetry_record::Record::Event(e.clone())),
            })
            .collect()
    }

    fn ack_through(&self, endpoint_id: &str, session_id: &[u8], through: u64) {
        if session_id != self.session_id {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let ack = inner.acks.entry(endpoint_id.to_string()).or_insert(0);
        if through > *ack {
            *ack = through;
        }
        if let Some(sink) = inner.sinks.get_mut(endpoint_id)
            && through > sink.ack_through
        {
            sink.ack_through = through;
        }
        gc_queue(&mut inner);
    }

    fn set_credential(&self, credential: pb::SignedAgentCredential) {
        let mut inner = self.inner.lock().unwrap();
        inner.credential = Some(credential);
        let ready = !inner.endpoints.is_empty();
        drop(inner);
        let _ = self.ready.send(ready);
    }

    fn apply_assignment(&self, cfg: &Config, assignment: pb::EndpointAssignment) {
        self.config_version
            .store(assignment.config_version, Ordering::SeqCst);
        let desired = desired_endpoints(cfg, assignment);
        let mut inner = self.inner.lock().unwrap();
        let new_ids: HashSet<String> = desired.iter().map(|e| e.endpoint_id.clone()).collect();
        inner.acks.retain(|id, _| new_ids.contains(id));
        inner.sinks.retain(|id, _| new_ids.contains(id));
        let mut map = HashMap::new();
        for ep in desired {
            match inner.sinks.get_mut(&ep.endpoint_id) {
                Some(sink) if sink.generation != ep.generation => {
                    *sink = pb::SinkRuntime {
                        endpoint_id: ep.endpoint_id.clone(),
                        generation: ep.generation,
                        ..Default::default()
                    };
                    inner.acks.remove(&ep.endpoint_id);
                }
                Some(_) => {}
                None => {
                    inner.sinks.insert(
                        ep.endpoint_id.clone(),
                        pb::SinkRuntime {
                            endpoint_id: ep.endpoint_id.clone(),
                            generation: ep.generation,
                            ..Default::default()
                        },
                    );
                }
            }
            map.insert(ep.endpoint_id.clone(), ep);
        }
        inner.endpoints = map;
        let ready = inner.credential.is_some() && !inner.endpoints.is_empty();
        drop(inner);
        let _ = self.ready.send(ready);
        self.assignment_changed.send_modify(|g| *g += 1);
    }

    fn assignment_gen(&self) -> u64 {
        *self.assignment_changed.borrow()
    }

    fn config_version(&self) -> u64 {
        self.config_version.load(Ordering::SeqCst)
    }

    async fn wait_ready(&self) -> pb::SignedAgentCredential {
        // subscribe 必须先于首次状态检查：等待期间的变更必然经 send 被 changed 观察到
        let mut rx = self.ready.subscribe();
        loop {
            {
                let inner = self.inner.lock().unwrap();
                if !inner.endpoints.is_empty()
                    && let Some(c) = &inner.credential
                {
                    return c.clone();
                }
            }
            if rx.changed().await.is_err() {
                // Sender 与 Shared 同寿，走到这说明进程正在退出
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    }

    async fn wait_assignment_change(&self, seen: u64) {
        let mut rx = self.assignment_changed.subscribe();
        while *rx.borrow_and_update() == seen {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    fn credential(&self) -> Option<pb::SignedAgentCredential> {
        self.inner.lock().unwrap().credential.clone()
    }

    fn endpoints(&self) -> Vec<pb::TelemetryEndpoint> {
        self.inner
            .lock()
            .unwrap()
            .endpoints
            .values()
            .cloned()
            .collect()
    }

    fn latest_sequence(&self) -> u64 {
        self.inner.lock().unwrap().latest_seq
    }

    fn set_sink_connected(&self, endpoint_id: &str, generation: u64, connected: bool) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(sink) = inner.sinks.get_mut(endpoint_id)
            && sink.generation == generation
        {
            sink.connected = connected;
            if connected {
                sink.last_error.clear();
            } else {
                sink.last_rtt_ms = 0.0;
                sink.rtt_sampled_at_unix_nano = 0;
            }
        }
    }

    fn set_sink_rtt(&self, endpoint_id: &str, generation: u64, rtt: Duration) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(sink) = inner.sinks.get_mut(endpoint_id)
            && sink.generation == generation
        {
            sink.connected = true;
            sink.last_error.clear();
            sink.last_rtt_ms = rtt.as_secs_f64() * 1000.0;
            sink.rtt_sampled_at_unix_nano = now_nanos();
        }
    }

    fn set_sink_error(&self, endpoint_id: &str, err: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(sink) = inner.sinks.get_mut(endpoint_id) {
            sink.connected = false;
            sink.last_error = err.to_string();
            sink.last_rtt_ms = 0.0;
            sink.rtt_sampled_at_unix_nano = 0;
        }
    }

    fn runtime(&self) -> pb::AgentRuntime {
        let inner = self.inner.lock().unwrap();
        let mut sinks: Vec<_> = inner
            .sinks
            .values()
            .map(|s| {
                let mut s = s.clone();
                let activation = inner
                    .endpoints
                    .get(&s.endpoint_id)
                    .map(|e| e.activation_sequence.max(1))
                    .unwrap_or(1);
                let ack = inner.acks.get(&s.endpoint_id).copied().unwrap_or(0);
                let mut pending = 0u64;
                let mut oldest = 0i64;
                for e in &inner.queue {
                    if e.sequence >= activation && e.sequence > ack {
                        pending += 1;
                        if oldest == 0 {
                            oldest = e.collected_at_unix_nano;
                        }
                    }
                }
                s.pending_events = pending;
                s.oldest_pending_unix_nano = oldest;
                s
            })
            .collect();
        sinks.sort_by(|a, b| a.endpoint_id.cmp(&b.endpoint_id));
        pb::AgentRuntime {
            wal_pressure: pb::WalPressure::Healthy as i32,
            wal_bytes: 0,
            pending_events: inner.queue.len() as u64,
            oldest_pending_unix_nano: inner
                .queue
                .front()
                .map(|e| e.collected_at_unix_nano)
                .unwrap_or(0),
            sinks,
            clock_untrusted: false,
            protocol_version: PROTOCOL_VERSION.into(),
            capabilities: None, // filled by caller with config
        }
    }

    fn realtime_snapshot(&self, caps: pb::AgentCapabilities) -> Option<pb::RealtimeSnapshot> {
        let inner = self.inner.lock().unwrap();
        if inner.latest_at == 0 {
            return None;
        }
        let mut runtime = {
            drop(inner);
            self.runtime()
        };
        runtime.capabilities = Some(caps);
        let inner = self.inner.lock().unwrap();
        Some(pb::RealtimeSnapshot {
            node_uuid: self.node_uuid.to_vec(),
            session_id: self.session_id.to_vec(),
            latest_sequence: inner.latest_seq,
            collected_at_unix_nano: inner.latest_at,
            agent_uptime_nano: self.started.elapsed().as_nanos() as u64,
            host: inner.latest_host.clone(),
            state: inner.latest_state.clone(),
            agent_runtime: Some(runtime),
        })
    }
}

/// 单次入队包超时：超时视为连接死亡，返回错误走正常重连。
async fn send_with_timeout<T>(
    tx: &mpsc::Sender<T>,
    msg: T,
    timeout: Duration,
    what: &str,
) -> Result<()> {
    match tokio::time::timeout(timeout, tx.send(msg)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => bail!("{what} 发送失败（对端已关闭）"),
        Err(_) => bail!("{what} 发送超时，判定连接死亡"),
    }
}

/// 并发满的拒绝口径：立即回失败结果，不排队。
fn probe_rejected(req: &pb::ProbeRequest) -> pb::ProbeResult {
    let kind = match &req.target {
        Some(pb::probe_request::Target::Http(_)) => pb::ProbeKind::Http,
        Some(pb::probe_request::Target::Icmp(_)) => pb::ProbeKind::Icmp,
        Some(pb::probe_request::Target::Tcp(_)) => pb::ProbeKind::Tcp,
        None => pb::ProbeKind::Unspecified,
    };
    pb::ProbeResult {
        probe_id: req.probe_id.clone(),
        kind: kind as i32,
        successful: false,
        error: "agent probe concurrency limit reached".into(),
        completed_at_unix_nano: now_nanos(),
        ..Default::default()
    }
}

fn gc_queue(inner: &mut Inner) {
    if inner.endpoints.is_empty() {
        return;
    }
    let mut min_keep = u64::MAX;
    for (id, ep) in &inner.endpoints {
        let activation = ep.activation_sequence.max(1);
        let ack = inner.acks.get(id).copied().unwrap_or(0);
        let keep_from = ack.max(activation.saturating_sub(1));
        min_keep = min_keep.min(keep_from);
    }
    if min_keep == u64::MAX {
        return;
    }
    while inner.queue.front().is_some_and(|e| e.sequence <= min_keep) {
        inner.queue.pop_front();
    }
}

/// MVP 实际具备的能力；GPU / NAT 不上报。
pub fn capabilities(cfg: &Config) -> pb::AgentCapabilities {
    use pb::AgentCapability as C;
    let caps = &cfg.capabilities;
    let flags = [
        (caps.cpu, C::MetricCpu),
        (caps.memory, C::MetricMemory),
        (caps.disk, C::MetricDisk),
        (caps.network, C::MetricNetwork),
        (caps.connections, C::MetricConnections),
        (caps.processes, C::MetricProcesses),
        (caps.temperature, C::MetricTemperature),
        (caps.host_info, C::HostInfo),
        (caps.ip_report, C::IpReport),
        (caps.http_probe, C::ProbeHttp),
        (caps.icmp_probe, C::ProbeIcmp),
        (caps.tcp_probe, C::ProbeTcp),
    ];
    pb::AgentCapabilities {
        enabled: flags
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, c)| *c as i32)
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

pub(crate) fn desired_endpoints(
    cfg: &Config,
    assignment: pb::EndpointAssignment,
) -> Vec<pb::TelemetryEndpoint> {
    let disabled: HashSet<&str> = cfg
        .telemetry
        .disabled_remote_ids
        .iter()
        .map(String::as_str)
        .collect();
    let overrides: HashMap<&str, &crate::config::CollectorOverride> = cfg
        .telemetry
        .collectors
        .iter()
        .map(|c| (c.id.as_str(), c))
        .collect();
    let mut out = Vec::new();
    for mut ep in assignment.endpoints {
        let id = effective_endpoint_id(&ep);
        ep.endpoint_id = id.clone();
        if disabled.contains(id.as_str()) {
            continue;
        }
        if ep.kind == pb::EndpointKind::Primary as i32 || id == "primary" {
            ep.address = cfg.server.clone();
            ep.tls = cfg.tls;
            ep.insecure_tls = cfg.insecure_tls;
        } else if let Some(ov) = overrides.get(id.as_str()) {
            ep.address = ov.address.clone();
            ep.tls = ov.tls;
            ep.insecure_tls = ov.insecure_tls;
        }
        if ep.address.is_empty() {
            continue;
        }
        if ep.activation_sequence == 0 {
            ep.activation_sequence = 1;
        }
        out.push(ep);
    }
    out
}

#[derive(Clone, PartialEq, Eq)]
struct EndpointKey {
    id: String,
    generation: u64,
    address: String,
    tls: bool,
    insecure_tls: bool,
}

fn endpoint_key(ep: &pb::TelemetryEndpoint) -> EndpointKey {
    EndpointKey {
        id: ep.endpoint_id.clone(),
        generation: ep.generation,
        address: ep.address.clone(),
        tls: ep.tls,
        insecure_tls: ep.insecure_tls,
    }
}

struct WorkerSet {
    handles: HashMap<String, (EndpointKey, tokio::task::JoinHandle<()>)>,
}

impl Drop for WorkerSet {
    fn drop(&mut self) {
        for (_, (_, h)) in self.handles.drain() {
            h.abort();
        }
    }
}

async fn control_loop(
    cfg: Config,
    device: Arc<Mutex<Option<DeviceCredentials>>>,
    shared: Arc<Shared>,
    host: pb::Host,
    version: String,
) {
    let probe_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES));
    loop {
        // 对齐 Go：每轮重连都做登记/续期检查（未临期是纯本地幂等操作）。
        // 失败走退避上抛，避免 mTLS 失效时无退避刷 Enroll；enroll/renew 走非流式
        // channel，自带 connect/RPC 超时。
        match crate::pki::ensure_device_credentials(&cfg, shared.node_uuid, &version).await {
            Ok(creds) => *device.lock().unwrap() = creds,
            Err(e) => {
                warn!(error = %format!("{e:#}"), "设备凭证登记/续期失败，{}s 后重试", RECONNECT_DELAY.as_secs());
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        }
        // channel 每轮重建：续期后的新身份要经新的 TLS 配置才生效
        let channel = {
            let guard = device.lock().unwrap();
            report::build_endpoint_channel(
                &cfg.server,
                cfg.tls,
                &cfg.tls_ca_file,
                guard.as_ref().map(|d| d.ca_pem.as_slice()).unwrap_or(&[]),
                guard.as_ref().map(|d| &d.identity),
                true,
            )
        };
        let channel = match channel {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %format!("{e:#}"), "control channel 构建失败，{}s 后重试", RECONNECT_DELAY.as_secs());
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };
        match control_once(
            &cfg,
            channel,
            &shared,
            &host,
            &version,
            probe_permits.clone(),
        )
        .await
        {
            // 计划刷新（24h 凭证周期）不是故障：跳过错误退避，立即重建
            Ok(()) => info!("control 流计划刷新，立即重建"),
            Err(e) => {
                warn!(error = %format!("{e:#}"), "control 流断开，{}s 后重连", RECONNECT_DELAY.as_secs());
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    }
}

async fn control_once(
    cfg: &Config,
    channel: tonic::transport::Channel,
    shared: &Arc<Shared>,
    host: &pb::Host,
    version: &str,
    probe_permits: Arc<Semaphore>,
) -> Result<()> {
    let mut client =
        pb::santaizi_control_service_client::SantaiziControlServiceClient::with_interceptor(
            channel,
            secret_interceptor(&cfg.client_secret)?,
        );
    let (tx, rx) = mpsc::channel::<pb::AgentControlRequest>(32);
    send_with_timeout(
        &tx,
        pb::AgentControlRequest {
            body: Some(pb::agent_control_request::Body::Hello(
                pb::AgentControlHello {
                    node_uuid: shared.node_uuid.to_vec(),
                    session_id: shared.session_id.to_vec(),
                    current_config_version: shared.config_version(),
                    agent_version: version.to_string(),
                    host: Some(host.clone()),
                    capabilities: Some(capabilities(cfg)),
                },
            )),
        },
        SEND_TIMEOUT,
        "control hello",
    )
    .await?;
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
                        shared.apply_assignment(cfg, assignment);
                    }
                    Some(pb::primary_control_response::Body::ProbeRequest(req)) => {
                        match probe_permits.clone().try_acquire_owned() {
                            Ok(permit) => {
                                let caps = cfg.capabilities.clone();
                                let tx = tx.clone();
                                tokio::spawn(async move {
                                    let result = crate::probe::execute(&caps, req).await;
                                    // 结果发不出去仅丢弃；主循环的定期 send 会发现死连接。
                                    // permit 随任务结束释放。
                                    let _ = send_with_timeout(&tx, pb::AgentControlRequest {
                                        body: Some(pb::agent_control_request::Body::ProbeResult(result)),
                                    }, SEND_TIMEOUT, "probe result").await;
                                    drop(permit);
                                });
                            }
                            Err(_) => {
                                send_with_timeout(&tx, pb::AgentControlRequest {
                                    body: Some(pb::agent_control_request::Body::ProbeResult(probe_rejected(&req))),
                                }, SEND_TIMEOUT, "probe 拒绝").await?;
                            }
                        }
                    }
                    Some(pb::primary_control_response::Body::NatOpenRequest(req)) => {
                        send_with_timeout(&tx, pb::AgentControlRequest {
                            body: Some(pb::agent_control_request::Body::NatOpenResult(pb::NatOpenResult {
                                stream_id: req.stream_id,
                                accepted: false,
                                error: "santaizi-agent-rs 尚不支持 NAT".into(),
                            })),
                        }, SEND_TIMEOUT, "NAT 拒绝").await?;
                    }
                    None => {}
                }
            }
            _ = runtime_tick.tick() => {
                let mut runtime = shared.runtime();
                runtime.capabilities = Some(capabilities(cfg));
                send_with_timeout(&tx, pb::AgentControlRequest {
                    body: Some(pb::agent_control_request::Body::Runtime(runtime)),
                }, SEND_TIMEOUT, "runtime").await?;
            }
            _ = refresh_tick.tick() => {
                info!("到达凭证刷新周期，重建 control 流");
                return Ok(());
            }
        }
    }
}

async fn ingest_supervisor(
    cfg: Config,
    shared: Arc<Shared>,
    device: Arc<Mutex<Option<DeviceCredentials>>>,
) {
    let mut workers = WorkerSet {
        handles: HashMap::new(),
    };
    loop {
        shared.wait_ready().await;
        let seen_gen = shared.assignment_gen();
        let desired = shared.endpoints();
        let desired_keys: HashMap<String, EndpointKey> = desired
            .iter()
            .map(|e| (e.endpoint_id.clone(), endpoint_key(e)))
            .collect();
        workers.handles.retain(|id, (key, handle)| {
            if desired_keys.get(id) == Some(key) {
                true
            } else {
                handle.abort();
                false
            }
        });
        for ep in desired {
            if workers.handles.contains_key(&ep.endpoint_id) {
                continue;
            }
            if ep.insecure_tls {
                warn!(
                    endpoint = %ep.endpoint_id,
                    "insecure_tls 被忽略（rustls 不支持跳过校验），请用 tls_ca_file 或 Enrollment CA"
                );
            }
            let key = endpoint_key(&ep);
            let handle = tokio::spawn(sink_loop(cfg.clone(), shared.clone(), ep, device.clone()));
            workers.handles.insert(key.id.clone(), (key, handle));
        }
        shared.wait_assignment_change(seen_gen).await;
    }
}

async fn sink_loop(
    cfg: Config,
    shared: Arc<Shared>,
    endpoint: pb::TelemetryEndpoint,
    device: Arc<Mutex<Option<DeviceCredentials>>>,
) {
    let mut ping_disabled = false;
    let mut last_snapshot_seq = 0u64;
    loop {
        // 每轮重连取最新凭证：control 侧续期后 sink 重连即生效
        let creds = device.lock().unwrap().clone();
        if let Err(e) = ingest_once(
            &cfg,
            &shared,
            &endpoint,
            creds.as_ref(),
            &mut ping_disabled,
            &mut last_snapshot_seq,
        )
        .await
        {
            shared.set_sink_error(&endpoint.endpoint_id, &format!("{e:#}"));
            warn!(
                endpoint = %endpoint.endpoint_id,
                error = %format!("{e:#}"),
                "ingest 流断开，{}s 后重连",
                RECONNECT_DELAY.as_secs()
            );
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

fn ping_unsupported(err: &tonic::Status) -> bool {
    matches!(
        err.code(),
        tonic::Code::Unimplemented | tonic::Code::InvalidArgument
    )
}

async fn ingest_once(
    cfg: &Config,
    shared: &Arc<Shared>,
    endpoint: &pb::TelemetryEndpoint,
    device: Option<&DeviceCredentials>,
    ping_disabled: &mut bool,
    last_snapshot_seq: &mut u64,
) -> Result<()> {
    let credential = shared
        .credential()
        .ok_or_else(|| anyhow::anyhow!("尚无凭证"))?;
    let identity = if endpoint.tls {
        device.map(|d| &d.identity)
    } else {
        None
    };
    let extra_ca = if endpoint.tls {
        device.map(|d| d.ca_pem.as_slice()).unwrap_or(&[])
    } else {
        &[]
    };
    let channel = report::build_endpoint_channel(
        &endpoint.address,
        endpoint.tls,
        &cfg.tls_ca_file,
        extra_ca,
        identity,
        true,
    )?;
    let mut client =
        pb::santaizi_telemetry_service_client::SantaiziTelemetryServiceClient::with_interceptor(
            channel,
            secret_interceptor(&cfg.client_secret)?,
        );
    let (tx, rx) = mpsc::channel::<pb::TelemetryRequest>(64);
    let mut runtime = shared.runtime();
    runtime.capabilities = Some(capabilities(cfg));
    send_with_timeout(
        &tx,
        pb::TelemetryRequest {
            body: Some(pb::telemetry_request::Body::Hello(pb::TelemetryHello {
                node_uuid: shared.node_uuid.to_vec(),
                endpoint_id: effective_endpoint_id(endpoint),
                assignment_generation: endpoint.generation,
                credential: Some(credential),
                protocol_version: PROTOCOL_VERSION.into(),
                agent_runtime: Some(runtime),
            })),
        },
        SEND_TIMEOUT,
        "ingest hello",
    )
    .await?;
    let mut stream = client
        .ingest(ReceiverStream::new(rx))
        .await
        .context("ingest 建流失败")?
        .into_inner();
    info!(
        endpoint = %endpoint.endpoint_id,
        generation = endpoint.generation,
        "ingest 流已建立"
    );
    shared.set_sink_connected(&endpoint.endpoint_id, endpoint.generation, true);

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut last_ping_at = Instant::now();
    let mut ping_sent: Option<Instant> = None;
    let mut missed_pongs = 0u32;
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let records = shared.peek_batch(&endpoint.endpoint_id, cfg.telemetry.batch_size);
                if !records.is_empty() {
                    send_with_timeout(&tx, pb::TelemetryRequest {
                        body: Some(pb::telemetry_request::Body::Batch(pb::TelemetryBatch { records })),
                    }, SEND_TIMEOUT, "batch").await?;
                    continue;
                }
                let seq = shared.latest_sequence();
                if seq != 0
                    && seq != *last_snapshot_seq
                    && let Some(snapshot) = shared.realtime_snapshot(capabilities(cfg))
                {
                    send_with_timeout(&tx, pb::TelemetryRequest {
                        body: Some(pb::telemetry_request::Body::RealtimeSnapshot(snapshot)),
                    }, SEND_TIMEOUT, "snapshot").await?;
                    *last_snapshot_seq = seq;
                }
                // 发送节拍固定：pong 丢失不再加快 ping，连续丢失判连接死亡
                if !*ping_disabled && last_ping_at.elapsed() >= SINK_RTT_INTERVAL {
                    if ping_sent.is_some() {
                        missed_pongs += 1;
                        if missed_pongs >= PING_MISS_LIMIT {
                            bail!("连续 {PING_MISS_LIMIT} 次 ping 未收到 pong，判定连接死亡");
                        }
                    }
                    last_ping_at = Instant::now();
                    ping_sent = Some(Instant::now());
                    send_with_timeout(&tx, pb::TelemetryRequest {
                        body: Some(pb::telemetry_request::Body::Ping(pb::TelemetryPing {})),
                    }, SEND_TIMEOUT, "ping").await?;
                }
            }
            msg = stream.next() => {
                match msg {
                    Some(Ok(resp)) => {
                        if !resp.error.is_empty() {
                            warn!(endpoint = %endpoint.endpoint_id, error = %resp.error, "面板 ingest 报错");
                        }
                        if resp.pong.is_some()
                            && let Some(sent) = ping_sent.take()
                        {
                            missed_pongs = 0;
                            shared.set_sink_rtt(&endpoint.endpoint_id, endpoint.generation, sent.elapsed());
                        }
                        for ack in resp.acks {
                            shared.ack_through(&endpoint.endpoint_id, &ack.session_id, ack.ack_through);
                        }
                    }
                    Some(Err(e)) => {
                        if ping_sent.take().is_some() && ping_unsupported(&e) {
                            *ping_disabled = true;
                            warn!(endpoint = %endpoint.endpoint_id, "面板不支持 TelemetryPing，已关闭");
                        }
                        shared.set_sink_connected(&endpoint.endpoint_id, endpoint.generation, false);
                        return Err(e.into());
                    }
                    None => {
                        shared.set_sink_connected(&endpoint.endpoint_id, endpoint.generation, false);
                        bail!("面板关闭了 ingest 流");
                    }
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
        let host = self.monitor.host(
            &self.last_ip.ip,
            &self.country(),
            &self.version,
            &self.cfg.capabilities,
        );
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
    let ip_period = Duration::from_secs(cx.cfg.ip_report_period.max(60));
    // 对齐 Go UpdateIP（myip.go:72-81）：双栈都失败时 IP_RETRY_DELAY 快重试，
    // 成功回到 ip_report_period；启动首查已失败（last_ip 为空）首轮也走快重试。
    let first_ip_wait = if cx.last_ip.ip.is_empty() {
        IP_RETRY_DELAY
    } else {
        ip_period
    };
    let mut ip_sleep = std::pin::pin!(tokio::time::sleep(first_ip_wait));
    let mut host_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + host_interval, host_interval);
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            _ = state_tick.tick() => {
                let state = cx.monitor.collect_state(&cx.cfg.capabilities);
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
            _ = &mut ip_sleep => {
                let use_v6_cc = cx.cfg.use_ipv6_countrycode;
                let fetched = tokio::task::spawn_blocking(move || {
                    netip::fetch_ip_info_with(IP_FETCH_TIMEOUT, use_v6_cc)
                })
                .await;
                let mut fetched_ok = false;
                if let Ok(Ok(mut info)) = fetched
                    && !info.ip.is_empty()
                {
                    // loc 缺席/xx/t1 时 netip 返回空国家码：保留旧值，对齐 Go「忽略」语义。
                    if info.country_code.is_empty() {
                        info.country_code.clone_from(&cx.last_ip.country_code);
                    }
                    if info != cx.last_ip {
                        cx.last_ip = info;
                        cx.append_host();
                    }
                    fetched_ok = true;
                }
                if !fetched_ok {
                    debug!("IP 自查失败，{}s 后快重试", IP_RETRY_DELAY.as_secs());
                }
                let wait = if fetched_ok { ip_period } else { IP_RETRY_DELAY };
                ip_sleep.as_mut().reset(tokio::time::Instant::now() + wait);
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
    // 启动期登记失败直接退出（require_agent_mtls 的面板必须成功登记）；
    // 之后的续期检查由 control 重连循环每轮幂等执行。
    let device = crate::pki::ensure_device_credentials(&cfg, node_uuid, version).await?;
    let device = Arc::new(Mutex::new(device));
    let shared = Arc::new(Shared::new(node_uuid, session_id));

    let mut monitor = Monitor::with_allowlists(
        cfg.nic_allowlist.clone(),
        cfg.hard_drive_partition_allowlist.clone(),
    );
    let use_v6_cc = cfg.use_ipv6_countrycode;
    let last_ip = match tokio::task::spawn_blocking(move || {
        netip::fetch_ip_info_with(IP_FETCH_TIMEOUT, use_v6_cc)
    })
    .await
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
    let host = monitor.host(&last_ip.ip, &country, version, &cfg.capabilities);
    let boot_time = monitor.boot_time();

    let control = tokio::spawn(control_loop(
        cfg.clone(),
        device.clone(),
        shared.clone(),
        host,
        version.to_string(),
    ));
    let ingest = tokio::spawn(ingest_supervisor(cfg.clone(), shared.clone(), device));

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CollectorOverride, Config, TelemetryConfig};

    fn assignment(endpoints: Vec<pb::TelemetryEndpoint>) -> pb::EndpointAssignment {
        pb::EndpointAssignment {
            config_version: 1,
            endpoints,
        }
    }

    #[test]
    fn desired_fills_primary_from_cfg() {
        let cfg = Config {
            server: "panel.example:5555".into(),
            tls: true,
            client_secret: "s".into(),
            ..Config::default()
        };
        let out = desired_endpoints(
            &cfg,
            assignment(vec![pb::TelemetryEndpoint {
                endpoint_id: "primary".into(),
                kind: pb::EndpointKind::Primary as i32,
                address: String::new(),
                reliable: true,
                generation: 3,
                ..Default::default()
            }]),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].address, "panel.example:5555");
        assert!(out[0].tls);
        assert_eq!(out[0].activation_sequence, 1);
    }

    #[test]
    fn desired_overrides_collector_and_skips_disabled() {
        let cfg = Config {
            server: "panel.example:5555".into(),
            client_secret: "s".into(),
            telemetry: TelemetryConfig {
                collectors: vec![CollectorOverride {
                    id: "c1".into(),
                    address: "obs.local:5555".into(),
                    tls: true,
                    insecure_tls: false,
                }],
                disabled_remote_ids: vec!["c2".into()],
                ..TelemetryConfig::default()
            },
            ..Config::default()
        };
        let out = desired_endpoints(
            &cfg,
            assignment(vec![
                pb::TelemetryEndpoint {
                    endpoint_id: "primary".into(),
                    kind: pb::EndpointKind::Primary as i32,
                    ..Default::default()
                },
                pb::TelemetryEndpoint {
                    endpoint_id: "c1".into(),
                    kind: pb::EndpointKind::Collector as i32,
                    address: "old:1".into(),
                    generation: 9,
                    activation_sequence: 40,
                    ..Default::default()
                },
                pb::TelemetryEndpoint {
                    endpoint_id: "c2".into(),
                    kind: pb::EndpointKind::Collector as i32,
                    address: "skip:1".into(),
                    ..Default::default()
                },
                pb::TelemetryEndpoint {
                    endpoint_id: "c3".into(),
                    kind: pb::EndpointKind::Collector as i32,
                    address: String::new(),
                    ..Default::default()
                },
            ]),
        );
        let ids: Vec<_> = out.iter().map(|e| e.endpoint_id.as_str()).collect();
        assert_eq!(ids, ["primary", "c1"]);
        let c1 = out.iter().find(|e| e.endpoint_id == "c1").unwrap();
        assert_eq!(c1.address, "obs.local:5555");
        assert!(c1.tls);
        assert_eq!(c1.activation_sequence, 40);
    }

    #[test]
    fn ack_is_per_endpoint() {
        let shared = Shared::new([1u8; 16], [2u8; 16]);
        let cfg = Config {
            server: "127.0.0.1:1".into(),
            client_secret: "s".into(),
            ..Config::default()
        };
        shared.apply_assignment(
            &cfg,
            assignment(vec![
                pb::TelemetryEndpoint {
                    endpoint_id: "primary".into(),
                    kind: pb::EndpointKind::Primary as i32,
                    ..Default::default()
                },
                pb::TelemetryEndpoint {
                    endpoint_id: "c1".into(),
                    kind: pb::EndpointKind::Collector as i32,
                    address: "127.0.0.1:2".into(),
                    ..Default::default()
                },
            ]),
        );
        for _ in 0..3 {
            shared.append(
                pb::TelemetryEventType::Heartbeat,
                pb::TelemetryPriority::P0Critical,
                pb::telemetry_event::Payload::Heartbeat(pb::HeartbeatPayload { boot_time_unix: 1 }),
            );
        }
        assert_eq!(shared.peek_batch("primary", 10).len(), 3);
        shared.ack_through("primary", &[2u8; 16], 2);
        assert_eq!(shared.peek_batch("primary", 10).len(), 1);
        assert_eq!(shared.peek_batch("c1", 10).len(), 3);
        shared.ack_through("c1", &[2u8; 16], 3);
        assert!(shared.peek_batch("c1", 10).is_empty());
        assert_eq!(shared.peek_batch("primary", 10).len(), 1);
    }

    fn test_cfg() -> Config {
        Config {
            server: "127.0.0.1:1".into(),
            client_secret: "s".into(),
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn send_with_timeout_times_out_when_queue_full() {
        let (tx, _rx) = mpsc::channel::<u8>(1);
        tx.send(1).await.unwrap();
        let err = send_with_timeout(&tx, 2, Duration::from_millis(50), "test")
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("超时"), "{err:#}");
    }

    #[tokio::test]
    async fn send_with_timeout_ok_when_drained() {
        let (tx, mut rx) = mpsc::channel::<u8>(1);
        tx.send(1).await.unwrap();
        let drain = tokio::spawn(async move {
            rx.recv().await; // 腾出容量
            rx.recv().await
        });
        send_with_timeout(&tx, 2, Duration::from_secs(5), "test")
            .await
            .unwrap();
        assert_eq!(drain.await.unwrap(), Some(2));
    }

    #[test]
    fn probe_rejected_carries_id_and_kind() {
        let req = pb::ProbeRequest {
            probe_id: "p1".into(),
            target: Some(pb::probe_request::Target::Tcp(pb::TcpProbeRequest {
                host: "127.0.0.1".into(),
                port: 80,
                timeout_ms: 1000,
            })),
        };
        let r = probe_rejected(&req);
        assert_eq!(r.probe_id, "p1");
        assert_eq!(r.kind, pb::ProbeKind::Tcp as i32);
        assert!(!r.successful);
        assert!(!r.error.is_empty());
        let req = pb::ProbeRequest {
            probe_id: "p2".into(),
            target: None,
        };
        assert_eq!(probe_rejected(&req).kind, pb::ProbeKind::Unspecified as i32);
    }

    #[test]
    fn apply_assignment_records_config_version() {
        let shared = Shared::new([1u8; 16], [2u8; 16]);
        assert_eq!(shared.config_version(), 0);
        shared.apply_assignment(
            &test_cfg(),
            pb::EndpointAssignment {
                config_version: 42,
                endpoints: vec![],
            },
        );
        assert_eq!(shared.config_version(), 42);
    }

    #[tokio::test]
    async fn wait_ready_observes_update_during_wait() {
        let shared = Arc::new(Shared::new([1u8; 16], [2u8; 16]));
        let waiter = {
            let shared = shared.clone();
            tokio::spawn(async move { shared.wait_ready().await })
        };
        // 让 waiter 先完成首次检查进入等待，再在等待期间变更
        tokio::task::yield_now().await;
        shared.set_credential(pb::SignedAgentCredential {
            claims: b"c".to_vec(),
            signature: b"s".to_vec(),
            key_id: b"k".to_vec(),
        });
        shared.apply_assignment(
            &test_cfg(),
            assignment(vec![pb::TelemetryEndpoint {
                endpoint_id: "primary".into(),
                kind: pb::EndpointKind::Primary as i32,
                ..Default::default()
            }]),
        );
        let cred = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("等待期间的变更必须被观察到")
            .unwrap();
        assert_eq!(cred.key_id, b"k");
    }

    #[tokio::test]
    async fn wait_assignment_change_observes_bump() {
        let shared = Arc::new(Shared::new([1u8; 16], [2u8; 16]));
        let seen = shared.assignment_gen();
        let waiter = {
            let shared = shared.clone();
            tokio::spawn(async move { shared.wait_assignment_change(seen).await })
        };
        tokio::task::yield_now().await;
        shared.apply_assignment(&test_cfg(), assignment(vec![]));
        tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("gen 变化必须被观察到")
            .unwrap();
    }
}

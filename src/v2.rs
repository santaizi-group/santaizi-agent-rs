//! v2 通路：Control + 多 endpoint Ingest。事件进 Segment WAL，拨号走缓存。

use crate::config::Config;
use crate::dialcache::{self, Store, Target};
use crate::monitor::Monitor;
use crate::netip::{self, IpInfo};
use crate::pb;
use crate::pki::DeviceCredentials;
use crate::report::{self, IP_FETCH_TIMEOUT};
use crate::wal::{self, AppendError, EndpointState, Pressure, StateStore, Wal};
use anyhow::{Context, Result, bail};
use prost::Message;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tracing::{debug, info, warn};

pub const PROTOCOL_VERSION: &str = "2";
const RECONNECT_DELAY: Duration = Duration::from_secs(10);
const RUNTIME_INTERVAL: Duration = Duration::from_secs(15);
const SINK_RTT_INTERVAL: Duration = Duration::from_secs(15);
/// 对齐 Go：每 24h 主动断流刷新凭证。
const CREDENTIAL_REFRESH: Duration = Duration::from_secs(24 * 3600);
/// 退出前留给 ingest 冲刷 STOPPED 事件的窗口。
const SHUTDOWN_FLUSH: Duration = Duration::from_secs(2);
/// 单次入队上限：mpsc 满意味着对端停读（半开连接），超时判连接死亡。
/// 只包单次 send；流式 RPC 整体禁止套 timeout。
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// 探测与 NAT 共用的并发槽。满了立即拒绝，不排队。
const MAX_CONCURRENT_CONTROL_JOBS: usize = 16;
/// ping 节拍固定 SINK_RTT_INTERVAL；连续丢失这么多个 pong 判定 ingest 连接死亡。
const PING_MISS_LIMIT: u32 = 3;
/// IP 自查失败后的快重试间隔（对齐 Go myip.go UpdateIP：双栈都失败 1 分钟后重试）。
const IP_RETRY_DELAY: Duration = Duration::from_secs(60);

struct Inner {
    credential: Option<pb::SignedAgentCredential>,
    endpoints: HashMap<String, pb::TelemetryEndpoint>,
    sinks: HashMap<String, pb::SinkRuntime>,
    latest_host: Option<pb::Host>,
    latest_state: Option<pb::State>,
    latest_seq: u64,
    latest_at: i64,
}

struct PressureRollup {
    window_start: i64,
    count: u32,
    minimum: pb::State,
    average: pb::State,
    maximum: pb::State,
    previous: pb::State,
    net_in: u64,
    net_out: u64,
}

pub struct Shared {
    pub node_uuid: [u8; 16],
    pub session_id: [u8; 16],
    started: Instant,
    seq: AtomicU64,
    /// 最近一次应用的指派 config_version，control hello 回传。
    config_version: AtomicU64,
    inner: Mutex<Inner>,
    wal: Wal,
    state: StateStore,
    dial: Store,
    credential_path: PathBuf,
    rollup: Mutex<Option<PressureRollup>>,
    /// HardLimit 替换写入期间为真，避免 DATA_LOSS 再触发 DATA_LOSS。
    loss_guard: AtomicBool,
    // watch 代替 Notify：notify_waiters 不存 permit，check-then-wait 之间会丢唤醒
    ready: watch::Sender<bool>,
    assignment_changed: watch::Sender<u64>,
}

impl Shared {
    pub fn open(
        data_dir: &Path,
        node_uuid: [u8; 16],
        session_id: [u8; 16],
        wal_cfg: &crate::config::WalConfig,
    ) -> Result<Self> {
        let wal_dir = data_dir.join("wal");
        let wal = Wal::open(wal::WalConfig {
            dir: wal_dir.clone(),
            segment_size: wal_cfg.segment_size_bytes,
            max_size: wal_cfg.max_size_bytes,
            fsync_interval: wal_cfg.fsync_interval,
            fsync_records: wal_cfg.fsync_records,
            reserve_bytes: wal_cfg.reserve_bytes,
        })?;
        let state = StateStore::open(&wal_dir)?;
        let dial = Store::open(data_dir)?;
        let shared = Self {
            node_uuid,
            session_id,
            started: Instant::now(),
            seq: AtomicU64::new(0),
            config_version: AtomicU64::new(0),
            inner: Mutex::new(Inner {
                credential: None,
                endpoints: HashMap::new(),
                sinks: HashMap::new(),
                latest_host: None,
                latest_state: None,
                latest_seq: 0,
                latest_at: 0,
            }),
            wal,
            state,
            dial,
            credential_path: data_dir.join("credential.pb"),
            rollup: Mutex::new(None),
            loss_guard: AtomicBool::new(false),
            ready: watch::channel(false).0,
            assignment_changed: watch::channel(0).0,
        };
        if let Some(credential) = read_credential(&shared.credential_path)? {
            shared.install_credential(credential);
        }
        Ok(shared)
    }

    fn alloc_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn append(
        &self,
        event_type: pb::TelemetryEventType,
        priority: pb::TelemetryPriority,
        payload: pb::telemetry_event::Payload,
    ) {
        let _ = self.append_event(event_type, priority, payload);
    }

    fn append_event(
        &self,
        event_type: pb::TelemetryEventType,
        priority: pb::TelemetryPriority,
        payload: pb::telemetry_event::Payload,
    ) -> std::result::Result<pb::TelemetryEvent, AppendError> {
        if event_type == pb::TelemetryEventType::State {
            self.flush_completed_rollup();
        }
        let sequence = self.alloc_seq();
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
        if let Some(pb::telemetry_event::Payload::State(state)) = &event.payload {
            self.inner.lock().unwrap().latest_state = Some(state.clone());
        }
        if let Some(pb::telemetry_event::Payload::Host(host)) = &event.payload {
            self.inner.lock().unwrap().latest_host = Some(host.clone());
        }
        let record = pb::TelemetryRecord {
            record: Some(pb::telemetry_record::Record::Event(event.clone())),
        };
        match self.wal.append(&record, priority as i32) {
            Ok(()) => {
                let mut inner = self.inner.lock().unwrap();
                inner.latest_seq = sequence;
                inner.latest_at = now;
                Ok(event)
            }
            Err(AppendError::NeedsRollup) => {
                if let Some(pb::telemetry_event::Payload::State(state)) = &event.payload {
                    self.note_rollup(state, sequence);
                }
                Err(AppendError::NeedsRollup)
            }
            Err(AppendError::Downsampled) => Err(AppendError::Downsampled),
            Err(AppendError::HardLimit) => {
                if !self.loss_guard.swap(true, Ordering::SeqCst) {
                    self.note_hard_limit(sequence, hard_limit_detail(event_type));
                    self.loss_guard.store(false, Ordering::SeqCst);
                }
                Err(AppendError::HardLimit)
            }
            Err(err) => {
                warn!(error = %err, "追加探测失败");
                Err(err)
            }
        }
    }

    fn peek_batch(&self, endpoint_id: &str, max: usize) -> Vec<pb::TelemetryRecord> {
        if max == 0 {
            return Vec::new();
        }
        let Some(endpoint) = self.state.endpoint(endpoint_id) else {
            return Vec::new();
        };
        if !endpoint.reliable {
            return Vec::new();
        }
        self.wal.collect_pending(
            |session, start, end| record_visible(&endpoint, session, start, end),
            max,
        )
    }

    fn ack_through(&self, endpoint_id: &str, node_uuid: &[u8], session_id: &[u8], through: u64) {
        if node_uuid != self.node_uuid {
            return;
        }
        let generation = self
            .inner
            .lock()
            .unwrap()
            .endpoints
            .get(endpoint_id)
            .map(|endpoint| endpoint.generation)
            .or_else(|| {
                self.state
                    .endpoint(endpoint_id)
                    .map(|endpoint| endpoint.generation)
            });
        let Some(generation) = generation else {
            return;
        };
        match self
            .state
            .update_ack(endpoint_id, generation, session_id, through)
        {
            Ok(()) => {}
            Err(wal::StateError::Generation { .. }) => return,
            Err(err) => {
                warn!(endpoint = %endpoint_id, error = %err, "更新探测游标失败");
                return;
            }
        }
        let mut inner = self.inner.lock().unwrap();
        if let Some(sink) = inner.sinks.get_mut(endpoint_id)
            && through > sink.ack_through
        {
            sink.ack_through = through;
        }
        drop(inner);
        self.reclaim_wal();
    }

    fn install_credential(&self, credential: pb::SignedAgentCredential) {
        let mut inner = self.inner.lock().unwrap();
        inner.credential = Some(credential);
        let ready = !inner.endpoints.is_empty();
        drop(inner);
        let _ = self.ready.send(ready);
    }

    fn set_credential(&self, credential: pb::SignedAgentCredential) -> Result<()> {
        write_credential(&self.credential_path, &credential)?;
        self.install_credential(credential);
        Ok(())
    }

    fn apply_assignment(&self, cfg: &Config, assignment: pb::EndpointAssignment) {
        self.config_version
            .store(assignment.config_version, Ordering::SeqCst);
        if let Err(err) = self.state.set_config_version(assignment.config_version) {
            warn!(error = %err, "写入 config_version 失败");
        }
        let desired = desired_endpoints(cfg, assignment);
        let new_ids: HashSet<String> = desired.iter().map(|e| e.endpoint_id.clone()).collect();
        let stale: Vec<String> = self
            .state
            .snapshot()
            .endpoints
            .keys()
            .filter(|id| !new_ids.contains(*id))
            .cloned()
            .collect();
        for id in stale {
            if let Err(err) = self.state.remove_endpoint(&id) {
                warn!(endpoint = %id, error = %err, "移除探测游标失败");
            }
        }
        for ep in &desired {
            let activation_raw = if ep.activation_session_id.is_empty() {
                self.session_id.to_vec()
            } else {
                ep.activation_session_id.clone()
            };
            let activation = if ep.activation_sequence == 0 {
                1
            } else {
                ep.activation_sequence
            };
            if let Err(err) = self.state.upsert_endpoint(EndpointState {
                endpoint_id: ep.endpoint_id.clone(),
                generation: ep.generation,
                reliable: ep.reliable,
                activation_session: hex_encode(&activation_raw),
                activation_sequence: activation,
                cursors: None,
                activations: None,
            }) {
                warn!(endpoint = %ep.endpoint_id, error = %err, "写入 endpoint 游标失败");
            }
        }
        let mut inner = self.inner.lock().unwrap();
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
        let mut sinks: Vec<_> = inner.sinks.values().cloned().collect();
        drop(inner);
        sinks.sort_by(|a, b| a.endpoint_id.cmp(&b.endpoint_id));
        pb::AgentRuntime {
            wal_pressure: pressure_pb(self.wal.pressure()) as i32,
            wal_bytes: self.wal.size(),
            pending_events: 0,
            oldest_pending_unix_nano: 0,
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

/// 并发满的拒绝口径：立即回失败结果，不排队。kind 固定 0。
fn probe_rejected(req: &pb::ProbeRequest) -> pb::ProbeResult {
    pb::ProbeResult {
        probe_id: req.probe_id.clone(),
        kind: 0,
        successful: false,
        error: "too many concurrent probes".into(),
        completed_at_unix_nano: now_nanos(),
        ..Default::default()
    }
}

/// 实际上报的能力。顺序对齐 Go `capabilitiesPB`。
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
        (caps.gpu, C::MetricGpu),
        (caps.host_info, C::HostInfo),
        (caps.ip_report, C::IpReport),
        (caps.http_probe, C::ProbeHttp),
        (caps.icmp_probe, C::ProbeIcmp),
        (caps.tcp_probe, C::ProbeTcp),
        (caps.nat, C::Nat),
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
    let jobs = Arc::new(Semaphore::new(MAX_CONCURRENT_CONTROL_JOBS));
    loop {
        // 对齐 Go：每轮重连都做登记/续期检查（未临期是纯本地幂等操作）。
        // 登记失败从 1s 翻倍，封顶 10s；续期失败在 pki 内记退避，不打断现有证书。
        match crate::pki::ensure_device_credentials(&cfg, shared.node_uuid, &version).await {
            Ok(creds) => *device.lock().unwrap() = creds,
            Err(e) => {
                let delay = crate::pki::note_credential_failure();
                warn!(error = %format!("{e:#}"), "设备凭证登记/续期失败，{}s 后重试", delay.as_secs());
                tokio::time::sleep(delay).await;
                continue;
            }
        }
        let targets = match dial_targets(
            &shared.dial,
            dialcache::PRIMARY_KEY,
            &cfg.server,
            &cfg.dns,
        ) {
            Ok(targets) => targets,
            Err(e) => {
                warn!(error = %format!("{e:#}"), "control 拨号计划失败，{}s 后重试", RECONNECT_DELAY.as_secs());
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };
        let mut last_err: Option<anyhow::Error> = None;
        let mut settled = false;
        for target in targets {
            let (legacy, identity, extra_ca) = {
                let guard = device.lock().unwrap();
                (
                    guard.is_none(),
                    guard.as_ref().map(|d| d.identity.clone()),
                    guard.as_ref().map(|d| d.ca_pem.clone()).unwrap_or_default(),
                )
            };
            let channel = match dial_channel(&DialArgs {
                target: &target,
                tls: cfg.tls,
                insecure_tls: cfg.insecure_tls,
                tls_ca_file: &cfg.tls_ca_file,
                extra_ca_pem: &extra_ca,
                identity: identity.as_ref(),
                streaming: true,
            }) {
                Ok(channel) => channel,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            let mut established = false;
            match control_once(
                &cfg,
                channel,
                &shared,
                &host,
                &version,
                jobs.clone(),
                device.clone(),
                legacy,
                &target,
                &mut established,
            )
            .await
            {
                Ok(()) => {
                    info!("control 流计划刷新，立即重建");
                    settled = true;
                    break;
                }
                Err(e) if established => {
                    warn!(error = %format!("{e:#}"), "control 流断开，{}s 后重连", RECONNECT_DELAY.as_secs());
                    tokio::time::sleep(RECONNECT_DELAY).await;
                    settled = true;
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        if !settled {
            warn!(
                error = %last_err.map(|e| format!("{e:#}")).unwrap_or_else(|| "no dial target".into()),
                "control 建连失败，{}s 后重试",
                RECONNECT_DELAY.as_secs()
            );
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn control_once(
    cfg: &Config,
    channel: Channel,
    shared: &Arc<Shared>,
    host: &pb::Host,
    version: &str,
    jobs: Arc<Semaphore>,
    device: Arc<Mutex<Option<DeviceCredentials>>>,
    legacy: bool,
    target: &Target,
    established: &mut bool,
) -> Result<()> {
    let mut client =
        pb::santaizi_control_service_client::SantaiziControlServiceClient::with_interceptor(
            channel,
            auth_interceptor(&cfg.client_secret, legacy)?,
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
    *established = true;
    remember_dns(&shared.dial, dialcache::PRIMARY_KEY, target);
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
                        shared.set_credential(credential)?;
                    }
                    Some(pb::primary_control_response::Body::Assignment(assignment)) => {
                        debug!(config_version = assignment.config_version, "收到 endpoint 指派");
                        shared.apply_assignment(cfg, assignment);
                    }
                    Some(pb::primary_control_response::Body::ProbeRequest(req)) => {
                        match jobs.clone().try_acquire_owned() {
                            Ok(permit) => {
                                let caps = cfg.capabilities.clone();
                                let dns = cfg.dns.clone();
                                let tx = tx.clone();
                                tokio::spawn(async move {
                                    let result = crate::probe::execute_with_dns(&caps, &dns, req).await;
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
                        match jobs.clone().try_acquire_owned() {
                            Ok(permit) => {
                                let tx = tx.clone();
                                let cfg = cfg.clone();
                                let shared = shared.clone();
                                let device = device.clone();
                                tokio::spawn(async move {
                                    let creds = device.lock().unwrap().clone();
                                    let legacy = creds.is_none();
                                    let stream_id = req.stream_id.clone();
                                    let result = match open_nat(&cfg, &shared, creds.as_ref(), legacy, &req).await {
                                        Ok(()) => pb::NatOpenResult {
                                            stream_id,
                                            accepted: true,
                                            error: String::new(),
                                        },
                                        Err(err) => pb::NatOpenResult {
                                            stream_id,
                                            accepted: false,
                                            error: err.to_string(),
                                        },
                                    };
                                    let _ = send_with_timeout(&tx, pb::AgentControlRequest {
                                        body: Some(pb::agent_control_request::Body::NatOpenResult(result)),
                                    }, SEND_TIMEOUT, "NAT 结果").await;
                                    drop(permit);
                                });
                            }
                            Err(_) => {
                                send_with_timeout(&tx, pb::AgentControlRequest {
                                    body: Some(pb::agent_control_request::Body::NatOpenResult(pb::NatOpenResult {
                                        stream_id: req.stream_id,
                                        accepted: false,
                                        error: "too many concurrent NAT streams".into(),
                                    })),
                                }, SEND_TIMEOUT, "NAT 拒绝").await?;
                            }
                        }
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
                address = %endpoint.address,
                tls = endpoint.tls,
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

struct IngestSendState {
    ping_disabled: bool,
    last_snapshot_seq: u64,
    last_ping_at: Instant,
    ping_sent: Option<Instant>,
    missed_pongs: u32,
}

/// 一条 outbound：有待确认事件就发 batch，否则快照，再否则按节拍 ping。
/// `force_ping` 用于建流：grpc-go 要等第一次 Send 才回响应头，tonic 的 ingest().await
/// 会卡在等头；hello 后再立刻塞 ping/batch，避免双方互等最后 broken pipe。
async fn drive_ingest_send(
    tx: &mpsc::Sender<pb::TelemetryRequest>,
    cfg: &Config,
    shared: &Shared,
    endpoint: &pb::TelemetryEndpoint,
    state: &mut IngestSendState,
    force_ping: bool,
) -> Result<()> {
    let records = shared.peek_batch(&endpoint.endpoint_id, cfg.telemetry.batch_size);
    if !records.is_empty() {
        send_with_timeout(
            tx,
            pb::TelemetryRequest {
                body: Some(pb::telemetry_request::Body::Batch(pb::TelemetryBatch {
                    records,
                })),
            },
            SEND_TIMEOUT,
            "batch",
        )
        .await?;
        return Ok(());
    }
    let seq = shared.latest_sequence();
    if seq != 0
        && seq != state.last_snapshot_seq
        && let Some(snapshot) = shared.realtime_snapshot(capabilities(cfg))
    {
        send_with_timeout(
            tx,
            pb::TelemetryRequest {
                body: Some(pb::telemetry_request::Body::RealtimeSnapshot(snapshot)),
            },
            SEND_TIMEOUT,
            "snapshot",
        )
        .await?;
        state.last_snapshot_seq = seq;
        return Ok(());
    }
    if !state.ping_disabled && (force_ping || state.last_ping_at.elapsed() >= SINK_RTT_INTERVAL) {
        if !force_ping && state.ping_sent.is_some() {
            state.missed_pongs += 1;
            if state.missed_pongs >= PING_MISS_LIMIT {
                bail!("连续 {PING_MISS_LIMIT} 次 ping 未收到 pong，判定连接死亡");
            }
        }
        state.last_ping_at = Instant::now();
        state.ping_sent = Some(Instant::now());
        send_with_timeout(
            tx,
            pb::TelemetryRequest {
                body: Some(pb::telemetry_request::Body::Ping(pb::TelemetryPing {})),
            },
            SEND_TIMEOUT,
            "ping",
        )
        .await?;
    }
    Ok(())
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
    let key = dial_key(endpoint);
    let targets = dial_targets(&shared.dial, &key, &endpoint.address, &cfg.dns)?;
    let legacy = device.is_none();
    let mut last_err = None;
    for target in targets {
        let mut established = false;
        match ingest_on_target(
            cfg,
            shared,
            endpoint,
            device,
            ping_disabled,
            last_snapshot_seq,
            &credential,
            &target,
            &key,
            legacy,
            &mut established,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(err) if established => return Err(err),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no dial target")))
}

#[allow(clippy::too_many_arguments)]
async fn ingest_on_target(
    cfg: &Config,
    shared: &Arc<Shared>,
    endpoint: &pb::TelemetryEndpoint,
    device: Option<&DeviceCredentials>,
    ping_disabled: &mut bool,
    last_snapshot_seq: &mut u64,
    credential: &pb::SignedAgentCredential,
    target: &Target,
    dial_key_name: &str,
    legacy: bool,
    established: &mut bool,
) -> Result<()> {
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
    let channel = dial_channel(&DialArgs {
        target,
        tls: endpoint.tls,
        insecure_tls: endpoint.insecure_tls,
        tls_ca_file: &cfg.tls_ca_file,
        extra_ca_pem: extra_ca,
        identity,
        streaming: true,
    })?;
    let mut client =
        pb::santaizi_telemetry_service_client::SantaiziTelemetryServiceClient::with_interceptor(
            channel,
            auth_interceptor(&cfg.client_secret, legacy)?,
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
                credential: Some(credential.clone()),
                protocol_version: PROTOCOL_VERSION.into(),
                agent_runtime: Some(runtime),
            })),
        },
        SEND_TIMEOUT,
        "ingest hello",
    )
    .await?;
    let mut send = IngestSendState {
        ping_disabled: *ping_disabled,
        last_snapshot_seq: *last_snapshot_seq,
        last_ping_at: Instant::now(),
        ping_sent: None,
        missed_pongs: 0,
    };
    drive_ingest_send(&tx, cfg, shared, endpoint, &mut send, true).await?;

    let ingest_fut = client.ingest(ReceiverStream::new(rx));
    tokio::pin!(ingest_fut);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut stream = loop {
        tokio::select! {
            result = &mut ingest_fut => {
                break result.context("ingest 建流失败")?.into_inner();
            }
            _ = tick.tick() => {
                drive_ingest_send(&tx, cfg, shared, endpoint, &mut send, false).await?;
            }
        }
    };
    *established = true;
    remember_dns(&shared.dial, dial_key_name, target);
    info!(
        endpoint = %endpoint.endpoint_id,
        address = %endpoint.address,
        generation = endpoint.generation,
        "ingest 流已建立"
    );
    shared.set_sink_connected(&endpoint.endpoint_id, endpoint.generation, true);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                drive_ingest_send(&tx, cfg, shared, endpoint, &mut send, false).await?;
            }
            msg = stream.next() => {
                match msg {
                    Some(Ok(resp)) => {
                        if !resp.error.is_empty() {
                            *ping_disabled = send.ping_disabled;
                            *last_snapshot_seq = send.last_snapshot_seq;
                            shared.set_sink_connected(&endpoint.endpoint_id, endpoint.generation, false);
                            bail!("{}", resp.error);
                        }
                        if resp.pong.is_some()
                            && let Some(sent) = send.ping_sent.take()
                        {
                            send.missed_pongs = 0;
                            shared.set_sink_rtt(&endpoint.endpoint_id, endpoint.generation, sent.elapsed());
                        }
                        for ack in resp.acks {
                            shared.ack_through(
                                &endpoint.endpoint_id,
                                &ack.node_uuid,
                                &ack.session_id,
                                ack.ack_through,
                            );
                        }
                    }
                    Some(Err(e)) => {
                        if send.ping_sent.take().is_some() && ping_unsupported(&e) {
                            send.ping_disabled = true;
                            warn!(endpoint = %endpoint.endpoint_id, "面板不支持 TelemetryPing，已关闭");
                        }
                        *ping_disabled = send.ping_disabled;
                        *last_snapshot_seq = send.last_snapshot_seq;
                        shared.set_sink_connected(&endpoint.endpoint_id, endpoint.generation, false);
                        return Err(e.into());
                    }
                    None => {
                        *ping_disabled = send.ping_disabled;
                        *last_snapshot_seq = send.last_snapshot_seq;
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
    cx.shared.record_recovery();

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
    let fsync_every = cx
        .cfg
        .telemetry
        .wal
        .fsync_interval
        .max(Duration::from_secs(1));
    let mut fsync_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + fsync_every, fsync_every);
    let mut gc_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(60),
        Duration::from_secs(60),
    );
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
            _ = fsync_tick.tick() => {
                if let Err(err) = cx.shared.wal.sync() {
                    warn!(error = %err, "探测 WAL sync 失败");
                }
            }
            _ = gc_tick.tick() => {
                cx.shared.reclaim_and_prune();
            }
            _ = &mut ip_sleep => {
                let use_v6_cc = cx.cfg.use_ipv6_countrycode;
                let iface = cx.cfg.ip_report_interface.clone();
                let fetched = tokio::task::spawn_blocking(move || {
                    netip::fetch_ip_info_with(IP_FETCH_TIMEOUT, use_v6_cc, &iface)
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
                cx.shared.flush_rollup_force();
                if let Err(err) = cx.shared.wal.sync() {
                    warn!(error = %err, "退出前 WAL sync 失败");
                }
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
    let data_dir = PathBuf::from(&cfg.telemetry.data_dir);
    let shared = Arc::new(Shared::open(
        &data_dir,
        node_uuid,
        session_id,
        &cfg.telemetry.wal,
    )?);

    let nics = if cfg.ip_report_interface.is_empty() {
        cfg.nic_allowlist.clone()
    } else {
        vec![cfg.ip_report_interface.clone()]
    };
    let mut monitor = Monitor::with_allowlists(nics, cfg.hard_drive_partition_allowlist.clone());
    let use_v6_cc = cfg.use_ipv6_countrycode;
    let iface = cfg.ip_report_interface.clone();
    let last_ip = match tokio::task::spawn_blocking(move || {
        netip::fetch_ip_info_with(IP_FETCH_TIMEOUT, use_v6_cc, &iface)
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

impl Shared {
    fn record_recovery(&self) {
        for issue in self.wal.recovery_issues() {
            let detail = format!("{}: {}", issue.segment, issue.reason);
            let mut lost = 0u64;
            for range in &issue.ranges {
                lost = lost.saturating_add(
                    range
                        .end_sequence
                        .saturating_sub(range.start_sequence)
                        .saturating_add(1),
                );
            }
            let intentional = if issue.ranges.is_empty() {
                lost = 1;
                Some(self.alloc_seq())
            } else {
                None
            };
            let event = self.append_event(
                pb::TelemetryEventType::DataLoss,
                pb::TelemetryPriority::P0Critical,
                pb::telemetry_event::Payload::DataLoss(pb::DataLossPayload {
                    reason: pb::GapReason::Corruption as i32,
                    component: "agent_wal".into(),
                    detail,
                    lost_records: lost,
                }),
            );
            let Ok(event) = event else {
                warn!(segment = %issue.segment, "追加 WAL 损坏事实失败");
                continue;
            };
            if let Some(seq) = intentional {
                self.append_gap(
                    &self.node_uuid,
                    &self.session_id,
                    seq,
                    seq,
                    pb::GapReason::Corruption,
                    &event.event_id,
                );
            }
            for range in &issue.ranges {
                self.append_gap(
                    &range.node_uuid,
                    &range.session_id,
                    range.start_sequence,
                    range.end_sequence,
                    pb::GapReason::Corruption,
                    &event.event_id,
                );
            }
        }
    }

    fn reclaim_wal(&self) {
        let snapshot = self.state.snapshot();
        if let Err(err) = self
            .wal
            .reclaim(|session, start, end| record_acked_by(&snapshot, session, start, end))
        {
            warn!(error = %err, "回收探测 WAL 失败");
        }
    }

    fn reclaim_and_prune(&self) {
        self.reclaim_wal();
        let mut keep = HashSet::new();
        for session in self.wal.durable_heads().keys() {
            keep.insert(session.clone());
        }
        keep.insert(hex_encode(&self.session_id));
        if let Err(err) = self.state.prune_sessions(&keep) {
            warn!(error = %err, "裁剪探测游标失败");
        }
    }

    fn note_rollup(&self, state: &pb::State, skipped: u64) {
        let window = minute_floor(now_nanos());
        let previous = {
            let mut guard = self.rollup.lock().unwrap();
            if guard
                .as_ref()
                .is_some_and(|rollup| rollup.window_start != window)
            {
                guard.take()
            } else {
                None
            }
        };
        if let Some(old) = previous {
            self.emit_rollup(old, now_nanos());
        }
        {
            let mut guard = self.rollup.lock().unwrap();
            let rollup = guard.get_or_insert_with(|| PressureRollup::new(window));
            rollup.add(state);
        }
        self.append_gap(
            &self.node_uuid,
            &self.session_id,
            skipped,
            skipped,
            pb::GapReason::Compacted,
            &[],
        );
    }

    fn flush_completed_rollup(&self) {
        let window = minute_floor(now_nanos());
        let old = {
            let mut guard = self.rollup.lock().unwrap();
            if guard
                .as_ref()
                .is_some_and(|rollup| rollup.window_start != window)
            {
                guard.take()
            } else {
                None
            }
        };
        if let Some(old) = old {
            let end = old.window_start.saturating_add(60 * 1_000_000_000);
            self.emit_rollup(old, end);
        }
    }

    fn flush_rollup_force(&self) {
        if let Some(old) = self.rollup.lock().unwrap().take() {
            self.emit_rollup(old, now_nanos());
        }
    }

    fn emit_rollup(&self, rollup: PressureRollup, mut end: i64) {
        if rollup.count == 0 {
            return;
        }
        let cap = rollup.window_start.saturating_add(60 * 1_000_000_000);
        if end > cap {
            end = cap;
        }
        if end < rollup.window_start {
            end = rollup.window_start;
        }
        let _ = self.append_event(
            pb::TelemetryEventType::StateRollup,
            pb::TelemetryPriority::P1Important,
            pb::telemetry_event::Payload::StateRollup(rollup.payload(end)),
        );
    }

    fn note_hard_limit(&self, skipped: u64, detail: &str) {
        match self.append_event(
            pb::TelemetryEventType::DataLoss,
            pb::TelemetryPriority::P0Critical,
            pb::telemetry_event::Payload::DataLoss(pb::DataLossPayload {
                reason: pb::GapReason::HardLimitDataLoss as i32,
                component: "agent_wal".into(),
                detail: detail.to_string(),
                lost_records: 1,
            }),
        ) {
            Ok(event) => self.append_gap(
                &self.node_uuid,
                &self.session_id,
                skipped,
                skipped,
                pb::GapReason::HardLimitDataLoss,
                &event.event_id,
            ),
            Err(_) => {
                let end = skipped.max(self.seq.load(Ordering::SeqCst));
                self.append_gap(
                    &self.node_uuid,
                    &self.session_id,
                    skipped,
                    end,
                    pb::GapReason::HardLimitDataLoss,
                    &[],
                );
            }
        }
    }

    fn append_gap(
        &self,
        node: &[u8],
        session: &[u8],
        start: u64,
        end: u64,
        reason: pb::GapReason,
        replacement: &[u8],
    ) {
        if start == 0 || end < start {
            return;
        }
        let gap_id: [u8; 16] = rand::random();
        let record = pb::TelemetryRecord {
            record: Some(pb::telemetry_record::Record::Gap(pb::SequenceGap {
                gap_id: gap_id.to_vec(),
                node_uuid: node.to_vec(),
                session_id: session.to_vec(),
                start_sequence: start,
                end_sequence: end,
                reason: reason as i32,
                replacement_event_id: replacement.to_vec(),
                created_at_unix_nano: now_nanos().max(1),
            })),
        };
        if let Err(err) = self
            .wal
            .append(&record, pb::TelemetryPriority::P0Critical as i32)
        {
            warn!(error = %err, "追加探测缺口事实失败");
        }
    }
}

impl PressureRollup {
    fn new(window_start: i64) -> Self {
        Self {
            window_start,
            count: 0,
            minimum: pb::State::default(),
            average: pb::State::default(),
            maximum: pb::State::default(),
            previous: pb::State::default(),
            net_in: 0,
            net_out: 0,
        }
    }

    fn add(&mut self, state: &pb::State) {
        if self.count == 0 {
            self.minimum = scrub_state(state);
            self.average = scrub_state(state);
            self.maximum = scrub_state(state);
        } else {
            update_state_min(&mut self.minimum, state);
            update_state_max(&mut self.maximum, state);
            update_state_avg(&mut self.average, state, u64::from(self.count) + 1);
            let continuous = state.uptime >= self.previous.uptime;
            self.net_in += counter_delta(
                self.previous.net_in_transfer,
                state.net_in_transfer,
                continuous,
            );
            self.net_out += counter_delta(
                self.previous.net_out_transfer,
                state.net_out_transfer,
                continuous,
            );
        }
        self.previous = state.clone();
        self.count += 1;
    }

    fn payload(&self, end: i64) -> pb::StateRollupPayload {
        pb::StateRollupPayload {
            window_start_unix_nano: self.window_start,
            window_end_unix_nano: end,
            sample_count: self.count,
            minimum: Some(self.minimum.clone()),
            average: Some(self.average.clone()),
            maximum: Some(self.maximum.clone()),
            net_in_total: self.net_in,
            net_out_total: self.net_out,
        }
    }
}

fn scrub_state(state: &pb::State) -> pb::State {
    let mut out = state.clone();
    out.net_in_speed = 0;
    out.net_out_speed = 0;
    out.gpu = 0.0;
    out.temperatures.clear();
    out
}

fn update_state_min(target: &mut pb::State, sample: &pb::State) {
    target.cpu = target.cpu.min(sample.cpu);
    target.mem_used = target.mem_used.min(sample.mem_used);
    target.swap_used = target.swap_used.min(sample.swap_used);
    target.disk_used = target.disk_used.min(sample.disk_used);
    target.load1 = target.load1.min(sample.load1);
    target.load5 = target.load5.min(sample.load5);
    target.load15 = target.load15.min(sample.load15);
    target.tcp_conn_count = target.tcp_conn_count.min(sample.tcp_conn_count);
    target.udp_conn_count = target.udp_conn_count.min(sample.udp_conn_count);
    target.process_count = target.process_count.min(sample.process_count);
}

fn update_state_max(target: &mut pb::State, sample: &pb::State) {
    target.cpu = target.cpu.max(sample.cpu);
    target.mem_used = target.mem_used.max(sample.mem_used);
    target.swap_used = target.swap_used.max(sample.swap_used);
    target.disk_used = target.disk_used.max(sample.disk_used);
    target.load1 = target.load1.max(sample.load1);
    target.load5 = target.load5.max(sample.load5);
    target.load15 = target.load15.max(sample.load15);
    target.tcp_conn_count = target.tcp_conn_count.max(sample.tcp_conn_count);
    target.udp_conn_count = target.udp_conn_count.max(sample.udp_conn_count);
    target.process_count = target.process_count.max(sample.process_count);
}

fn update_state_avg(target: &mut pb::State, sample: &pb::State, count: u64) {
    let previous = count - 1;
    let blend = |left: f64, right: f64| (left * previous as f64 + right) / count as f64;
    let blend_u =
        |left: u64, right: u64| (left.saturating_mul(previous).saturating_add(right)) / count;
    target.cpu = blend(target.cpu, sample.cpu);
    target.mem_used = blend_u(target.mem_used, sample.mem_used);
    target.swap_used = blend_u(target.swap_used, sample.swap_used);
    target.disk_used = blend_u(target.disk_used, sample.disk_used);
    target.load1 = blend(target.load1, sample.load1);
    target.load5 = blend(target.load5, sample.load5);
    target.load15 = blend(target.load15, sample.load15);
    target.tcp_conn_count = blend_u(target.tcp_conn_count, sample.tcp_conn_count);
    target.udp_conn_count = blend_u(target.udp_conn_count, sample.udp_conn_count);
    target.process_count = blend_u(target.process_count, sample.process_count);
}

fn counter_delta(previous: u64, current: u64, continuous_boot: bool) -> u64 {
    const MAX_DELTA: u64 = 1 << 50;
    if !continuous_boot {
        return 0;
    }
    if current >= previous {
        let delta = current - previous;
        if delta <= MAX_DELTA { delta } else { 0 }
    } else if previous > u64::MAX - (1 << 32) {
        let delta = u64::MAX - previous + current + 1;
        if delta <= MAX_DELTA { delta } else { 0 }
    } else {
        0
    }
}

fn minute_floor(nanos: i64) -> i64 {
    let secs = nanos.div_euclid(1_000_000_000);
    secs.div_euclid(60) * 60 * 1_000_000_000
}

fn hard_limit_detail(event_type: pb::TelemetryEventType) -> &'static str {
    match event_type {
        pb::TelemetryEventType::State => "state sample rejected at hard limit",
        pb::TelemetryEventType::Heartbeat => "heartbeat WAL append failed",
        pb::TelemetryEventType::Host => "host WAL append failed",
        pb::TelemetryEventType::StateRollup => "one-minute pressure rollup WAL append failed",
        pb::TelemetryEventType::Lifecycle => "lifecycle WAL append failed",
        _ => "telemetry WAL append failed",
    }
}

fn pressure_pb(pressure: Pressure) -> pb::WalPressure {
    match pressure {
        Pressure::Healthy => pb::WalPressure::Healthy,
        Pressure::Downsample => pb::WalPressure::P3Downsampled,
        Pressure::Rollup => pb::WalPressure::Rollup,
        Pressure::Critical => pb::WalPressure::Critical,
        Pressure::HardLimit => pb::WalPressure::DataLoss,
    }
}

fn record_visible(endpoint: &EndpointState, session: &str, start: u64, end: u64) -> bool {
    if !endpoint.reliable || session.is_empty() || start > end {
        return false;
    }
    let (activation, obligated) = if let Some(activation) = endpoint
        .activations
        .as_ref()
        .and_then(|map| map.get(session))
    {
        (*activation, true)
    } else if endpoint
        .cursors
        .as_ref()
        .is_some_and(|cursors| cursors.contains_key(session))
    {
        (1, true)
    } else {
        (0, false)
    };
    if !obligated {
        return false;
    }
    let cursor = endpoint
        .cursors
        .as_ref()
        .and_then(|cursors| cursors.get(session))
        .copied()
        .unwrap_or(0);
    end >= activation && end > cursor
}

fn record_acked_by(snapshot: &wal::CursorState, session: &str, start: u64, end: u64) -> bool {
    if session.is_empty() || start > end {
        return false;
    }
    let mut obligated = false;
    for endpoint in snapshot.endpoints.values() {
        if !endpoint.reliable {
            continue;
        }
        let (activation, active) = if let Some(activation) = endpoint
            .activations
            .as_ref()
            .and_then(|map| map.get(session))
        {
            (*activation, true)
        } else if endpoint
            .cursors
            .as_ref()
            .is_some_and(|cursors| cursors.contains_key(session))
        {
            (1, true)
        } else {
            (0, false)
        };
        if !active || end < activation {
            continue;
        }
        obligated = true;
        let cursor = endpoint
            .cursors
            .as_ref()
            .and_then(|cursors| cursors.get(session))
            .copied()
            .unwrap_or(0);
        if cursor < end {
            return false;
        }
    }
    obligated
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn dial_key(endpoint: &pb::TelemetryEndpoint) -> String {
    if endpoint.kind == pb::EndpointKind::Primary as i32 {
        dialcache::PRIMARY_KEY.to_string()
    } else {
        dialcache::collector_key(&endpoint.endpoint_id)
    }
}

fn dial_targets(store: &Store, key: &str, address: &str, dns: &[String]) -> Result<Vec<Target>> {
    dialcache::plan(Some(store), key, address, |host| {
        crate::dns::lookup_ips(dns, host)
    })
}

fn remember_dns(store: &Store, key: &str, target: &Target) {
    if !target.from_dns {
        return;
    }
    if let Err(err) = store.put(key, &target.host, &target.port, [target.ip.as_str()]) {
        warn!(error = %err, "写入拨号缓存失败");
    }
}

struct DialArgs<'a> {
    target: &'a Target,
    tls: bool,
    insecure_tls: bool,
    tls_ca_file: &'a str,
    extra_ca_pem: &'a [u8],
    identity: Option<&'a tonic::transport::Identity>,
    streaming: bool,
}

fn dial_channel(args: &DialArgs<'_>) -> Result<Channel> {
    let scheme = if args.tls { "https" } else { "http" };
    let mut endpoint = Endpoint::from_shared(format!("{scheme}://{}", args.target.dial_addr))
        .map_err(|err| anyhow::anyhow!("server 地址无效，应为 host:port: {err}"))?
        .connect_timeout(Duration::from_secs(5))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(Duration::from_secs(60)));
    if !args.streaming {
        endpoint = endpoint.timeout(Duration::from_secs(10));
    }
    let origin_host =
        if args.target.server_name.contains(':') && !args.target.server_name.starts_with('[') {
            format!("[{}]", args.target.server_name)
        } else {
            args.target.server_name.clone()
        };
    let origin: tonic::transport::Uri = format!("{scheme}://{origin_host}")
        .parse()
        .context("dial origin")?;
    endpoint = endpoint.origin(origin);
    if args.tls {
        let domain = args.target.server_name.clone();
        if args.insecure_tls {
            let mut tls_cfg = ClientTlsConfig::new().domain_name(domain);
            if let Some(identity) = args.identity {
                tls_cfg = tls_cfg.identity(identity.clone());
            }
            endpoint = endpoint
                .tls_config_with_verifier(tls_cfg, Arc::new(report::SkipServerVerify))
                .context("TLS 配置失败")?;
        } else {
            let mut tls_cfg = ClientTlsConfig::new()
                .domain_name(domain)
                .with_webpki_roots();
            let mut pem = Vec::new();
            if !args.tls_ca_file.is_empty() {
                pem.extend(fs::read(args.tls_ca_file).context("读取 tls_ca_file 失败")?);
            }
            if !args.extra_ca_pem.is_empty() {
                if !pem.is_empty() {
                    pem.push(b'\n');
                }
                pem.extend_from_slice(args.extra_ca_pem);
            }
            if !pem.is_empty() {
                tls_cfg = tls_cfg.ca_certificate(Certificate::from_pem(pem));
            }
            if let Some(identity) = args.identity {
                tls_cfg = tls_cfg.identity(identity.clone());
            }
            endpoint = endpoint.tls_config(tls_cfg).context("TLS 配置失败")?;
        }
    }
    Ok(endpoint.connect_lazy())
}

fn auth_interceptor(
    secret: &str,
    legacy: bool,
) -> Result<impl Fn(Request<()>) -> std::result::Result<Request<()>, tonic::Status> + Clone> {
    let value = if legacy {
        Some(MetadataValue::try_from(secret.to_string()).context("client_secret 含非法字符")?)
    } else {
        None
    };
    Ok(move |mut req: Request<()>| {
        if let Some(value) = &value {
            req.metadata_mut().insert("client_secret", value.clone());
        }
        Ok(req)
    })
}

async fn open_nat(
    cfg: &Config,
    shared: &Shared,
    device: Option<&DeviceCredentials>,
    legacy: bool,
    req: &pb::NatOpenRequest,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Some(reason) = crate::nat::rejection(cfg.capabilities.nat, req, now) {
        bail!(reason);
    }
    let mut tcp = Some(crate::nat::dial_target(&req.target_host, req.target_port).await?);
    let targets = dial_targets(&shared.dial, dialcache::PRIMARY_KEY, &cfg.server, &cfg.dns)?;
    let mut last = None;
    for target in targets {
        match attach_nat(cfg, shared, device, legacy, req, &target, &mut tcp).await {
            Ok(()) => return Ok(()),
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no dial target")))
}

async fn attach_nat(
    cfg: &Config,
    shared: &Shared,
    device: Option<&DeviceCredentials>,
    legacy: bool,
    req: &pb::NatOpenRequest,
    target: &Target,
    tcp: &mut Option<tokio::net::TcpStream>,
) -> Result<()> {
    if tcp.is_none() {
        bail!("NAT target already handed off");
    }
    let identity = if cfg.tls {
        device.map(|creds| &creds.identity)
    } else {
        None
    };
    let extra_ca = if cfg.tls {
        device.map(|creds| creds.ca_pem.as_slice()).unwrap_or(&[])
    } else {
        &[]
    };
    let channel = dial_channel(&DialArgs {
        target,
        tls: cfg.tls,
        insecure_tls: cfg.insecure_tls,
        tls_ca_file: &cfg.tls_ca_file,
        extra_ca_pem: extra_ca,
        identity,
        streaming: true,
    })?;
    let mut client = pb::santaizi_nat_service_client::SantaiziNatServiceClient::with_interceptor(
        channel,
        auth_interceptor(&cfg.client_secret, legacy)?,
    );
    let (tx, rx) = mpsc::channel(32);
    let inbound = client
        .nat_stream(ReceiverStream::new(rx))
        .await
        .context("NAT 建流失败")?
        .into_inner();
    tx.send(crate::nat::open_frame(&req.stream_id))
        .await
        .context("NAT OPEN")?;
    remember_dns(&shared.dial, dialcache::PRIMARY_KEY, target);
    let stream = tcp.take().context("NAT target already handed off")?;
    let (read, write) = stream.into_split();
    let stream_id = req.stream_id.clone();
    let frames = inbound.map(|item| item.map_err(|err| err.to_string()));
    tokio::spawn(async move {
        if let Err(err) = crate::nat::relay(&stream_id, read, write, tx, frames).await {
            let text = err.to_string();
            if !text.is_empty() && text != "NAT stream closed" {
                warn!(stream_id = %stream_id, error = %text, "NAT 流结束");
            }
        }
    });
    Ok(())
}

fn read_credential(path: &Path) -> Result<Option<pb::SignedAgentCredential>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(
            pb::SignedAgentCredential::decode(bytes.as_slice())
                .context("decode telemetry credential")?,
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("读取 {} 失败", path.display())),
    }
}

fn write_credential(path: &Path, credential: &pb::SignedAgentCredential) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("创建 {} 失败", dir.display()))?;
    }
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("credential path has no parent"))?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(".credential-{}-{nanos}.tmp", std::process::id()));
    let data = credential.encode_to_vec();
    let write_result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&data)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err).context("安装 credential.pb 失败");
    }
    let _ = File::open(dir).and_then(|dir_file| dir_file.sync_all());
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

    struct TmpShared {
        dir: PathBuf,
        shared: Option<Shared>,
    }

    impl TmpShared {
        fn new() -> Self {
            Self::with_wal(crate::config::WalConfig::default())
        }

        fn with_wal(wal: crate::config::WalConfig) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "santaizi-v2-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                rand::random::<u32>()
            ));
            fs::create_dir_all(&dir).unwrap();
            let shared = Shared::open(&dir, [1u8; 16], [2u8; 16], &wal).unwrap();
            Self {
                dir,
                shared: Some(shared),
            }
        }

        fn shared(&self) -> &Shared {
            self.shared.as_ref().unwrap()
        }
    }

    impl Drop for TmpShared {
        fn drop(&mut self) {
            self.shared.take();
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn reliable(id: &str, address: &str) -> pb::TelemetryEndpoint {
        pb::TelemetryEndpoint {
            endpoint_id: id.into(),
            kind: if id == "primary" {
                pb::EndpointKind::Primary as i32
            } else {
                pb::EndpointKind::Collector as i32
            },
            address: address.into(),
            reliable: true,
            ..Default::default()
        }
    }

    #[test]
    fn ack_is_per_endpoint() {
        let fix = TmpShared::new();
        let shared = fix.shared();
        shared.apply_assignment(
            &test_cfg(),
            assignment(vec![reliable("primary", ""), reliable("c1", "127.0.0.1:2")]),
        );
        for _ in 0..3 {
            shared.append(
                pb::TelemetryEventType::Heartbeat,
                pb::TelemetryPriority::P0Critical,
                pb::telemetry_event::Payload::Heartbeat(pb::HeartbeatPayload { boot_time_unix: 1 }),
            );
        }
        shared.wal.sync().unwrap();
        assert_eq!(shared.peek_batch("primary", 10).len(), 3);
        shared.ack_through("primary", &[1u8; 16], &[2u8; 16], 2);
        assert_eq!(shared.peek_batch("primary", 10).len(), 1);
        assert_eq!(shared.peek_batch("c1", 10).len(), 3);
        shared.ack_through("c1", &[1u8; 16], &[2u8; 16], 3);
        assert!(shared.peek_batch("c1", 10).is_empty());
        assert_eq!(shared.peek_batch("primary", 10).len(), 1);
        assert!(shared.peek_batch("unreliable", 10).is_empty());
    }

    #[test]
    fn unreliable_endpoint_skips_wal_batch() {
        let fix = TmpShared::new();
        let shared = fix.shared();
        shared.apply_assignment(
            &test_cfg(),
            assignment(vec![pb::TelemetryEndpoint {
                endpoint_id: "primary".into(),
                kind: pb::EndpointKind::Primary as i32,
                reliable: false,
                ..Default::default()
            }]),
        );
        shared.append(
            pb::TelemetryEventType::Heartbeat,
            pb::TelemetryPriority::P0Critical,
            pb::telemetry_event::Payload::Heartbeat(pb::HeartbeatPayload { boot_time_unix: 1 }),
        );
        assert!(shared.peek_batch("primary", 10).is_empty());
        assert_eq!(shared.runtime().pending_events, 0);
        assert_eq!(shared.runtime().oldest_pending_unix_nano, 0);
    }

    #[test]
    fn state_under_rollup_pressure_writes_compacted_gap() {
        let fix = TmpShared::with_wal(crate::config::WalConfig {
            segment_size_bytes: 1 << 20,
            max_size_bytes: 8192,
            reserve_bytes: 64,
            fsync_interval: Duration::from_secs(3600),
            fsync_records: 10_000,
        });
        let shared = fix.shared();
        shared.apply_assignment(&test_cfg(), assignment(vec![reliable("primary", "")]));
        let mut n = 0;
        while shared.runtime().wal_pressure < pb::WalPressure::Rollup as i32 {
            shared.append(
                pb::TelemetryEventType::Heartbeat,
                pb::TelemetryPriority::P0Critical,
                pb::telemetry_event::Payload::Heartbeat(pb::HeartbeatPayload { boot_time_unix: 1 }),
            );
            n += 1;
            assert!(n < 10_000, "never reached rollup");
        }
        shared.append(
            pb::TelemetryEventType::State,
            pb::TelemetryPriority::P2Normal,
            pb::telemetry_event::Payload::State(pb::State {
                cpu: 1.5,
                mem_used: 10,
                ..Default::default()
            }),
        );
        shared.wal.sync().unwrap();
        let batch = shared.peek_batch("primary", 256);
        let gap = batch.iter().find_map(|record| match &record.record {
            Some(pb::telemetry_record::Record::Gap(gap)) => Some(gap),
            _ => None,
        });
        let gap = gap.expect("压力下的 STATE 应留下 COMPACTED gap");
        assert_eq!(gap.reason, pb::GapReason::Compacted as i32);
        assert_eq!(gap.gap_id.len(), 16);
        assert!(gap.created_at_unix_nano > 0);
    }

    #[test]
    fn rollup_tracks_min_avg_max_without_speed() {
        let mut rollup = PressureRollup::new(0);
        rollup.add(&pb::State {
            cpu: 1.0,
            mem_used: 10,
            net_in_speed: 9,
            net_in_transfer: 100,
            gpu: 3.0,
            uptime: 10,
            ..Default::default()
        });
        rollup.add(&pb::State {
            cpu: 3.0,
            mem_used: 30,
            net_in_speed: 99,
            net_in_transfer: 150,
            gpu: 8.0,
            uptime: 11,
            ..Default::default()
        });
        let payload = rollup.payload(60_000_000_000);
        assert_eq!(payload.sample_count, 2);
        let min = payload.minimum.unwrap();
        let avg = payload.average.unwrap();
        let max = payload.maximum.unwrap();
        assert_eq!(min.mem_used, 10);
        assert_eq!(max.mem_used, 30);
        assert_eq!(avg.mem_used, 20);
        assert_eq!(avg.cpu, 2.0);
        assert_eq!(min.net_in_speed, 0);
        assert_eq!(max.gpu, 0.0);
        assert!(min.temperatures.is_empty());
        assert_eq!(payload.net_in_total, 50);
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
        assert_eq!(r.kind, 0);
        assert!(!r.successful);
        assert_eq!(r.error, "too many concurrent probes");
        let req = pb::ProbeRequest {
            probe_id: "p2".into(),
            target: None,
        };
        assert_eq!(probe_rejected(&req).kind, 0);
    }

    #[test]
    fn apply_assignment_records_config_version() {
        let fix = TmpShared::new();
        let shared = fix.shared();
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
        let mut fix = TmpShared::new();
        let shared = Arc::new(fix.shared.take().unwrap());
        let waiter = {
            let shared = shared.clone();
            tokio::spawn(async move { shared.wait_ready().await })
        };
        // 让 waiter 先完成首次检查进入等待，再在等待期间变更
        tokio::task::yield_now().await;
        shared
            .set_credential(pb::SignedAgentCredential {
                claims: b"c".to_vec(),
                signature: b"s".to_vec(),
                key_id: b"k".to_vec(),
            })
            .unwrap();
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
        let mut fix = TmpShared::new();
        let shared = Arc::new(fix.shared.take().unwrap());
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

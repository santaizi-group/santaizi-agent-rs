//! Segment WAL，帧布局与 `santaizi-agent/pkg/wal` 字节兼容。
//!
//! 不在模块内起 fsync 定时器：写满 `fsync_records` 会立刻 `sync`，其余由调用方定时调用 [`Wal::sync`]。

use crate::pb;
use prost::Message;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FRAME_MAGIC: u32 = 0x5354_5a32; // STZ2
const FRAME_VERSION: u16 = 1;
const FRAME_HEADER_SIZE: usize = 16;
const DEFAULT_SEGMENT_SIZE: u64 = 8 << 20;
const DEFAULT_MAX_SIZE: u64 = 256 << 20;
const DEFAULT_RESERVE: u64 = 1 << 20;
const FRAME_KIND_EVENT: u8 = 1;
const FRAME_KIND_GAP: u8 = 2;
const MAX_PENDING_CAP: usize = 1024;
/// Go `hash/crc32` Castagnoli（反射多项式）。
const CASTAGNOLI_POLY: u32 = 0x82f6_3b78;
const CRC_TABLE: [u32; 256] = castagnoli_table();

const fn castagnoli_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ CASTAGNOLI_POLY;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

fn crc32_castagnoli(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc = CRC_TABLE[((crc as u8) ^ byte) as usize] ^ (crc >> 8);
    }
    !crc
}

fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

fn b64_value(byte: u8) -> Result<u8, String> {
    Ok(match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return Err("bad base64".into()),
    })
}

fn b64_decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("bad base64 length".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let (b2, b3) = (bytes[i + 2], bytes[i + 3]);
        if b2 == b'=' && b3 != b'=' {
            return Err("bad base64 padding".into());
        }
        let pad = usize::from(b2 == b'=') + usize::from(b3 == b'=');
        let n0 = b64_value(bytes[i])?;
        let n1 = b64_value(bytes[i + 1])?;
        let n2 = if b2 == b'=' { 0 } else { b64_value(b2)? };
        let n3 = if b3 == b'=' { 0 } else { b64_value(b3)? };
        let n = ((n0 as u32) << 18) | ((n1 as u32) << 12) | ((n2 as u32) << 6) | (n3 as u32);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
        i += 4;
    }
    Ok(out)
}

/// 与 Go `Pressure` 的 iota 顺序一致，可直接比较。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pressure {
    Healthy = 0,
    Downsample = 1,
    Rollup = 2,
    Critical = 3,
    HardLimit = 4,
}

#[derive(Debug)]
pub enum AppendError {
    HardLimit,
    NeedsRollup,
    Downsampled,
    Io(io::Error),
    Other(String),
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppendError::HardLimit => write!(f, "wal hard limit reached"),
            AppendError::NeedsRollup => write!(f, "wal pressure requires telemetry rollup"),
            AppendError::Downsampled => {
                write!(f, "wal pressure requires optional telemetry downsampling")
            }
            AppendError::Io(err) => write!(f, "{err}"),
            AppendError::Other(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for AppendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppendError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for AppendError {
    fn from(err: io::Error) -> Self {
        AppendError::Io(err)
    }
}

#[derive(Debug, Clone)]
pub struct WalConfig {
    pub dir: PathBuf,
    pub segment_size: u64,
    pub max_size: u64,
    pub fsync_interval: Duration,
    pub fsync_records: usize,
    pub reserve_bytes: u64,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::new(),
            segment_size: 0,
            max_size: 0,
            fsync_interval: Duration::ZERO,
            fsync_records: 0,
            reserve_bytes: 0,
        }
    }
}

impl WalConfig {
    pub fn normalize(&mut self) {
        if self.segment_size == 0 {
            self.segment_size = DEFAULT_SEGMENT_SIZE;
        }
        if self.max_size == 0 {
            self.max_size = DEFAULT_MAX_SIZE;
        }
        if self.fsync_interval.is_zero() {
            self.fsync_interval = Duration::from_secs(1);
        }
        if self.fsync_records == 0 {
            self.fsync_records = 64;
        }
        if self.reserve_bytes == 0 {
            self.reserve_bytes = DEFAULT_RESERVE;
        }
        if self.reserve_bytes >= self.max_size {
            self.reserve_bytes = self.max_size / 100;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceRange {
    pub node_uuid: Vec<u8>,
    pub session_id: Vec<u8>,
    pub start_sequence: u64,
    pub end_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryIssue {
    pub segment: String,
    pub reason: String,
    pub ranges: Vec<SequenceRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalStats {
    pub bytes: u64,
    pub frames: usize,
    pub sessions: usize,
}

struct FrameRef {
    offset: u64,
    length: u32,
    session: u16,
    /// 与 Go frame index 一致：event=1，gap=2。读路径按字节区间回放，不看 kind。
    #[allow(dead_code)]
    kind: u8,
    start: u64,
    end: u64,
}

struct PendingWrite {
    offset: u64,
    length: u32,
    session: String,
    kind: u8,
    start: u64,
    end: u64,
}

struct Segment {
    id: u64,
    path: PathBuf,
    size: u64,
    ranges: BTreeMap<String, SequenceRange>,
    sessions: Vec<String>,
    frames: Vec<FrameRef>,
    reader: Option<File>,
}

impl Segment {
    fn new(id: u64, path: PathBuf) -> Self {
        Self {
            id,
            path,
            size: 0,
            ranges: BTreeMap::new(),
            sessions: Vec::new(),
            frames: Vec::new(),
            reader: None,
        }
    }

    fn intern_session(&mut self, session: &str) -> u16 {
        if let Some(index) = self
            .sessions
            .iter()
            .position(|existing| existing == session)
        {
            return index as u16;
        }
        self.sessions.push(session.to_string());
        (self.sessions.len() - 1) as u16
    }

    fn session_of(&self, index: u16) -> &str {
        self.sessions
            .get(index as usize)
            .map(String::as_str)
            .unwrap_or("")
    }

    fn open_reader(&mut self) -> io::Result<()> {
        if self.reader.is_some() {
            return Ok(());
        }
        self.reader = Some(File::open(&self.path)?);
        Ok(())
    }

    fn read_record(
        &mut self,
        offset: u64,
        length: u32,
    ) -> Result<pb::TelemetryRecord, AppendError> {
        self.open_reader()?;
        let mut payload = vec![0u8; length as usize];
        self.reader
            .as_ref()
            .unwrap()
            .read_exact_at(&mut payload, offset + FRAME_HEADER_SIZE as u64)?;
        pb::TelemetryRecord::decode(payload.as_slice())
            .map_err(|err| AppendError::Other(err.to_string()))
    }
}

struct RecordSpan {
    node: Vec<u8>,
    session: Vec<u8>,
    start: u64,
    end: u64,
    kind: u8,
}

fn record_span(record: &pb::TelemetryRecord) -> RecordSpan {
    match &record.record {
        Some(pb::telemetry_record::Record::Event(event)) => RecordSpan {
            node: event.node_uuid.clone(),
            session: event.session_id.clone(),
            start: event.sequence,
            end: event.sequence,
            kind: FRAME_KIND_EVENT,
        },
        Some(pb::telemetry_record::Record::Gap(gap)) => RecordSpan {
            node: gap.node_uuid.clone(),
            session: gap.session_id.clone(),
            start: gap.start_sequence,
            end: gap.end_sequence,
            kind: FRAME_KIND_GAP,
        },
        None => RecordSpan {
            node: Vec::new(),
            session: Vec::new(),
            start: 0,
            end: 0,
            kind: FRAME_KIND_EVENT,
        },
    }
}

fn add_raw_range(
    ranges: &mut BTreeMap<String, SequenceRange>,
    node: &[u8],
    session: &[u8],
    start: u64,
    end: u64,
) {
    if node.len() != 16 || session.len() != 16 || start == 0 || end < start {
        return;
    }
    let key = format!("{}/{}", hex_encode(node), hex_encode(session));
    match ranges.get_mut(&key) {
        Some(current) => {
            if start < current.start_sequence {
                current.start_sequence = start;
            }
            if end > current.end_sequence {
                current.end_sequence = end;
            }
        }
        None => {
            ranges.insert(
                key,
                SequenceRange {
                    node_uuid: node.to_vec(),
                    session_id: session.to_vec(),
                    start_sequence: start,
                    end_sequence: end,
                },
            );
        }
    }
}

fn note_durable(heads: &mut BTreeMap<String, u64>, session: &str, end: u64) {
    if session.is_empty() {
        return;
    }
    match heads.get_mut(session) {
        Some(current) if end > *current => *current = end,
        Some(_) => {}
        None if end > 0 => {
            heads.insert(session.to_string(), end);
        }
        None => {}
    }
}

fn rebuild_heads(segments: &[Segment]) -> BTreeMap<String, u64> {
    let mut heads = BTreeMap::new();
    for segment in segments {
        for frame in &segment.frames {
            note_durable(&mut heads, segment.session_of(frame.session), frame.end);
        }
    }
    heads
}

fn pressure_for(size: u64, max: u64) -> Pressure {
    if max == 0 || size >= max {
        return Pressure::HardLimit;
    }
    let ratio = size as f64 / max as f64;
    if ratio >= 0.95 {
        Pressure::Critical
    } else if ratio >= 0.85 {
        Pressure::Rollup
    } else if ratio >= 0.70 {
        Pressure::Downsample
    } else {
        Pressure::Healthy
    }
}

fn segment_name(id: u64) -> String {
    format!("{id:012}.seg")
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn file_name_string(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn ensure_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn open_segment_writer(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

fn atomic_write(path: &Path, data: &[u8], sync_directory: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "wal path has no parent"))?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = parent.join(format!(".wal-{}-{nanos}.tmp", std::process::id()));
    let write_result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    if sync_directory {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn manifest_bytes(ranges: &BTreeMap<String, SequenceRange>) -> Vec<u8> {
    let mut out = String::from("{\"ranges\":{");
    for (index, (key, range)) in ranges.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_json_string(&mut out, key);
        out.push_str(":{\"node_uuid\":");
        push_json_string(&mut out, &b64_encode(&range.node_uuid));
        out.push_str(",\"session_id\":");
        push_json_string(&mut out, &b64_encode(&range.session_id));
        out.push_str(",\"start_sequence\":");
        out.push_str(&range.start_sequence.to_string());
        out.push_str(",\"end_sequence\":");
        out.push_str(&range.end_sequence.to_string());
        out.push('}');
    }
    out.push_str("}}");
    out.into_bytes()
}

struct ScannedFrame {
    offset: u64,
    length: u32,
    kind: u8,
    start: u64,
    end: u64,
    node_uuid: Vec<u8>,
    session: Vec<u8>,
}

enum FrameError {
    UnexpectedEof,
    Corrupt(String),
}

struct ScanOut {
    frames: Vec<ScannedFrame>,
    valid_size: u64,
    error: Option<FrameError>,
}

fn read_limited(file: &mut File, buf: &mut [u8], max: u64) -> io::Result<usize> {
    let want = usize::try_from(max.min(buf.len() as u64)).unwrap_or(buf.len());
    let mut filled = 0;
    while filled < want {
        match file.read(&mut buf[filled..want]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

fn scan_file(path: &Path, limit: u64) -> Result<ScanOut, AppendError> {
    let mut file = File::open(path)?;
    let mut frames = Vec::new();
    let mut offset = 0u64;
    while offset < limit {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        let header_n = read_limited(&mut file, &mut header, limit - offset)?;
        if header_n == 0 {
            return Ok(ScanOut {
                frames,
                valid_size: offset,
                error: None,
            });
        }
        if header_n < FRAME_HEADER_SIZE {
            return Ok(ScanOut {
                frames,
                valid_size: offset,
                error: Some(FrameError::UnexpectedEof),
            });
        }
        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        let version = u16::from_be_bytes(header[4..6].try_into().unwrap());
        if magic != FRAME_MAGIC || version != FRAME_VERSION {
            return Ok(ScanOut {
                frames,
                valid_size: offset,
                error: Some(FrameError::Corrupt(format!(
                    "invalid wal frame header at offset {offset}"
                ))),
            });
        }
        let length = u32::from_be_bytes(header[8..12].try_into().unwrap());
        if length == 0 || u64::from(length) > DEFAULT_SEGMENT_SIZE * 2 {
            return Ok(ScanOut {
                frames,
                valid_size: offset,
                error: Some(FrameError::Corrupt(format!(
                    "invalid wal frame length {length}"
                ))),
            });
        }
        let mut payload = vec![0u8; length as usize];
        let payload_n = read_limited(
            &mut file,
            &mut payload,
            limit - offset - FRAME_HEADER_SIZE as u64,
        )?;
        if payload_n < payload.len() {
            return Ok(ScanOut {
                frames,
                valid_size: offset,
                error: Some(FrameError::UnexpectedEof),
            });
        }
        let expect = u32::from_be_bytes(header[12..16].try_into().unwrap());
        if crc32_castagnoli(&payload) != expect {
            return Ok(ScanOut {
                frames,
                valid_size: offset,
                error: Some(FrameError::Corrupt(format!(
                    "wal checksum mismatch at offset {offset}"
                ))),
            });
        }
        let record = match pb::TelemetryRecord::decode(payload.as_slice()) {
            Ok(record) => record,
            Err(err) => {
                return Ok(ScanOut {
                    frames,
                    valid_size: offset,
                    error: Some(FrameError::Corrupt(format!(
                        "decode wal record at offset {offset}: {err}"
                    ))),
                });
            }
        };
        let span = record_span(&record);
        frames.push(ScannedFrame {
            offset,
            length,
            kind: span.kind,
            start: span.start,
            end: span.end,
            node_uuid: span.node,
            session: span.session,
        });
        offset += FRAME_HEADER_SIZE as u64 + u64::from(length);
    }
    Ok(ScanOut {
        frames,
        valid_size: offset,
        error: None,
    })
}

fn ranges_from_scanned(frames: &[ScannedFrame]) -> BTreeMap<String, SequenceRange> {
    let mut ranges = BTreeMap::new();
    for frame in frames {
        add_raw_range(
            &mut ranges,
            &frame.node_uuid,
            &frame.session,
            frame.start,
            frame.end,
        );
    }
    ranges
}

fn range_values(ranges: &BTreeMap<String, SequenceRange>) -> Vec<SequenceRange> {
    ranges.values().cloned().collect()
}

fn frame_error_reason(err: &FrameError) -> String {
    match err {
        FrameError::UnexpectedEof => "unexpected EOF".into(),
        FrameError::Corrupt(reason) => reason.clone(),
    }
}

struct Inner {
    cfg: WalConfig,
    segments: Vec<Segment>,
    buffer: Option<BufWriter<File>>,
    unsynced: usize,
    total: u64,
    issues: Vec<RecoveryIssue>,
    pending: Vec<PendingWrite>,
    durable_heads: BTreeMap<String, u64>,
    closed: bool,
}

impl Inner {
    fn close_handles(&mut self) {
        self.buffer.take();
        for segment in &mut self.segments {
            segment.reader.take();
        }
    }

    fn close_locked(&mut self) -> Result<(), AppendError> {
        if self.closed {
            return Ok(());
        }
        let result = self.sync_locked();
        self.close_handles();
        self.closed = true;
        result
    }

    fn sync_locked(&mut self) -> Result<(), AppendError> {
        if self.unsynced == 0 {
            return Ok(());
        }
        {
            let buffer = self
                .buffer
                .as_mut()
                .ok_or_else(|| AppendError::Other("wal has no active segment".into()))?;
            buffer.flush()?;
            buffer.get_mut().sync_all()?;
        }
        let index = self.segments.len() - 1;
        let meta = with_suffix(&self.segments[index].path, ".meta");
        let ranges = self.segments[index].ranges.clone();
        atomic_write(&meta, &manifest_bytes(&ranges), false)?;
        let pending = std::mem::take(&mut self.pending);
        for item in &pending {
            let session_index = self.segments[index].intern_session(&item.session);
            self.segments[index].frames.push(FrameRef {
                offset: item.offset,
                length: item.length,
                session: session_index,
                kind: item.kind,
                start: item.start,
                end: item.end,
            });
            note_durable(&mut self.durable_heads, &item.session, item.end);
        }
        if pending.capacity() <= MAX_PENDING_CAP {
            let mut pending = pending;
            pending.clear();
            self.pending = pending;
        }
        self.unsynced = 0;
        Ok(())
    }

    fn rotate_locked(&mut self) -> Result<(), AppendError> {
        self.sync_locked()?;
        self.buffer.take();
        let id = self.segments.last().map(|segment| segment.id).unwrap_or(0) + 1;
        let path = self.cfg.dir.join(segment_name(id));
        let file = open_segment_writer(&path)?;
        self.segments.push(Segment::new(id, path));
        self.buffer = Some(BufWriter::with_capacity(64 * 1024, file));
        self.segments.last_mut().unwrap().open_reader()?;
        Ok(())
    }

    fn open_active(&mut self) -> Result<(), AppendError> {
        if self.segments.is_empty() {
            let path = self.cfg.dir.join(segment_name(1));
            self.segments.push(Segment::new(1, path));
        }
        let path = self.segments.last().unwrap().path.clone();
        let file = open_segment_writer(&path)?;
        self.buffer = Some(BufWriter::with_capacity(64 * 1024, file));
        self.segments.last_mut().unwrap().open_reader()?;
        Ok(())
    }

    fn ingest(&mut self, index: usize, frames: &[ScannedFrame]) {
        for frame in frames {
            let session = hex_encode(&frame.session);
            let session_index = self.segments[index].intern_session(&session);
            self.segments[index].frames.push(FrameRef {
                offset: frame.offset,
                length: frame.length,
                session: session_index,
                kind: frame.kind,
                start: frame.start,
                end: frame.end,
            });
            note_durable(&mut self.durable_heads, &session, frame.end);
        }
    }

    fn recover(&mut self) -> Result<(), AppendError> {
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.cfg.dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".seg") {
                paths.push(entry.path());
            }
        }
        paths.sort();
        let last = paths.len().saturating_sub(1);
        for (index, path) in paths.iter().enumerate() {
            let file_len = fs::metadata(path)?.len();
            let scanned = scan_file(path, file_len)?;
            let mut ranges = ranges_from_scanned(&scanned.frames);
            let mut size = file_len;
            if let Some(err) = &scanned.error {
                let unexpected = matches!(err, FrameError::UnexpectedEof);
                if unexpected && index == last {
                    let file = OpenOptions::new().write(true).open(path)?;
                    file.set_len(scanned.valid_size)?;
                    size = scanned.valid_size;
                    self.issues.push(RecoveryIssue {
                        segment: file_name_string(path),
                        reason: "truncated_partial_tail".into(),
                        ranges: Vec::new(),
                    });
                } else {
                    if let Ok(manifest) = read_manifest(&with_suffix(path, ".meta")) {
                        ranges = manifest;
                    }
                    let nanos = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos();
                    let quarantine = with_suffix(path, &format!(".corrupt-{nanos}"));
                    fs::rename(path, &quarantine)?;
                    match fs::rename(
                        with_suffix(path, ".meta"),
                        with_suffix(&quarantine, ".meta"),
                    ) {
                        Ok(()) => {}
                        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                        Err(err) => return Err(err.into()),
                    }
                    self.issues.push(RecoveryIssue {
                        segment: file_name_string(path),
                        reason: frame_error_reason(err),
                        ranges: range_values(&ranges),
                    });
                    continue;
                }
            }
            let id = parse_segment_id(path)?;
            let mut segment = Segment::new(id, path.clone());
            segment.size = size;
            segment.ranges = ranges;
            self.segments.push(segment);
            let seg_index = self.segments.len() - 1;
            self.ingest(seg_index, &scanned.frames);
            atomic_write(
                &with_suffix(path, ".meta"),
                &manifest_bytes(&self.segments[seg_index].ranges),
                false,
            )?;
            self.segments[seg_index].open_reader()?;
            self.total += size;
        }
        Ok(())
    }

    fn append_locked(
        &mut self,
        record: &pb::TelemetryRecord,
        priority: i32,
        payload: &[u8],
    ) -> Result<(), AppendError> {
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| AppendError::Other("payload exceeds u32".into()))?;
        let frame_size = FRAME_HEADER_SIZE as u64 + u64::from(payload_len);
        let projected = self.total.saturating_add(frame_size);
        let pressure = pressure_for(projected, self.cfg.max_size);
        let p0 = pb::TelemetryPriority::P0Critical as i32;
        let p2 = pb::TelemetryPriority::P2Normal as i32;
        let p3 = pb::TelemetryPriority::P3Optional as i32;
        if pressure == Pressure::HardLimit {
            return Err(AppendError::HardLimit);
        }
        if projected > self.cfg.max_size - self.cfg.reserve_bytes && priority > p0 {
            return Err(AppendError::HardLimit);
        }
        if pressure >= Pressure::Rollup && priority >= p2 {
            return Err(AppendError::NeedsRollup);
        }
        if pressure >= Pressure::Downsample && priority >= p3 {
            return Err(AppendError::Downsampled);
        }
        if self.segments.is_empty() {
            return Err(AppendError::Other("wal has no active segment".into()));
        }
        let need_rotate = {
            let segment = self.segments.last().unwrap();
            segment.size > 0 && segment.size.saturating_add(frame_size) > self.cfg.segment_size
        };
        if need_rotate {
            self.rotate_locked()?;
        }
        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
        frame.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
        frame.extend_from_slice(&FRAME_VERSION.to_be_bytes());
        frame.extend_from_slice(&(priority as u16).to_be_bytes());
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(&crc32_castagnoli(payload).to_be_bytes());
        frame.extend_from_slice(payload);
        self.buffer
            .as_mut()
            .ok_or_else(|| AppendError::Other("wal has no active segment".into()))?
            .write_all(&frame)?;
        let span = record_span(record);
        let index = self.segments.len() - 1;
        let offset = self.segments[index].size;
        self.segments[index].size += frame_size;
        self.total += frame_size;
        self.unsynced += 1;
        add_raw_range(
            &mut self.segments[index].ranges,
            &span.node,
            &span.session,
            span.start,
            span.end,
        );
        self.pending.push(PendingWrite {
            offset,
            length: payload_len,
            session: hex_encode(&span.session),
            kind: span.kind,
            start: span.start,
            end: span.end,
        });
        if self.unsynced >= self.cfg.fsync_records {
            self.sync_locked()?;
        }
        Ok(())
    }

    fn apply_reclaim(&mut self, removed: &[bool], reclaimed: u64) {
        let mut kept = Vec::new();
        for (index, segment) in self.segments.drain(..).enumerate() {
            if !removed.get(index).copied().unwrap_or(false) {
                kept.push(segment);
            }
        }
        self.segments = kept;
        self.total = self.total.saturating_sub(reclaimed);
        self.durable_heads = rebuild_heads(&self.segments);
    }
}

fn parse_segment_id(path: &Path) -> Result<u64, AppendError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AppendError::Other("segment name is not utf-8".into()))?;
    let stem = name.strip_suffix(".seg").unwrap_or(name);
    stem.parse::<u64>()
        .map_err(|err| AppendError::Other(format!("segment id {name}: {err}")))
}

fn read_manifest(path: &Path) -> Result<BTreeMap<String, SequenceRange>, AppendError> {
    let data = fs::read(path)?;
    parse_manifest(&data).map_err(AppendError::Other)
}

pub struct Wal {
    inner: Mutex<Inner>,
}

impl Wal {
    pub fn open(mut cfg: WalConfig) -> Result<Self, AppendError> {
        cfg.normalize();
        if cfg.dir.as_os_str().is_empty() {
            return Err(AppendError::Other("wal directory is empty".into()));
        }
        ensure_dir(&cfg.dir)?;
        let mut inner = Inner {
            cfg,
            segments: Vec::new(),
            buffer: None,
            unsynced: 0,
            total: 0,
            issues: Vec::new(),
            pending: Vec::new(),
            durable_heads: BTreeMap::new(),
            closed: false,
        };
        if let Err(err) = inner.recover() {
            inner.close_handles();
            return Err(err);
        }
        if let Err(err) = inner.open_active() {
            inner.close_handles();
            return Err(err);
        }
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn append(&self, record: &pb::TelemetryRecord, priority: i32) -> Result<(), AppendError> {
        let payload = record.encode_to_vec();
        let mut inner = self.lock();
        if inner.closed {
            return Err(AppendError::Other("wal closed".into()));
        }
        inner.append_locked(record, priority, &payload)
    }

    pub fn sync(&self) -> Result<(), AppendError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(AppendError::Other("wal closed".into()));
        }
        inner.sync_locked()
    }

    pub fn pressure(&self) -> Pressure {
        let inner = self.lock();
        pressure_for(inner.total, inner.cfg.max_size)
    }

    pub fn size(&self) -> u64 {
        self.lock().total
    }

    pub fn stats(&self) -> WalStats {
        let inner = self.lock();
        let mut seen = BTreeSet::new();
        let mut frames = 0;
        for segment in &inner.segments {
            frames += segment.frames.len();
            for session in &segment.sessions {
                if !session.is_empty() {
                    seen.insert(session.clone());
                }
            }
        }
        for session in inner.durable_heads.keys() {
            seen.insert(session.clone());
        }
        WalStats {
            bytes: inner.total,
            frames,
            sessions: seen.len(),
        }
    }

    pub fn recovery_issues(&self) -> Vec<RecoveryIssue> {
        self.lock().issues.clone()
    }

    /// `visible` 在 WAL 锁内调用，不能再进入同一个 [`Wal`]。
    pub fn has_pending(&self, mut visible: impl FnMut(&str, u64) -> bool) -> bool {
        let inner = self.lock();
        inner
            .durable_heads
            .iter()
            .any(|(session, seq)| visible(session, *seq))
    }

    /// 只按帧索引筛选，命中后再按 offset 读 payload 并 prost decode。
    /// `match_fn` 在 WAL 锁内调用，不能再进入同一个 [`Wal`]。
    pub fn collect_pending(
        &self,
        mut match_fn: impl FnMut(&str, u64, u64) -> bool,
        limit: usize,
    ) -> Vec<pb::TelemetryRecord> {
        if limit == 0 {
            return Vec::new();
        }
        let mut inner = self.lock();
        let mut out = Vec::new();
        for seg_index in 0..inner.segments.len() {
            let frame_count = inner.segments[seg_index].frames.len();
            for frame_index in 0..frame_count {
                let (session, start, end, offset, length) = {
                    let segment = &inner.segments[seg_index];
                    let frame = &segment.frames[frame_index];
                    (
                        segment.session_of(frame.session).to_string(),
                        frame.start,
                        frame.end,
                        frame.offset,
                        frame.length,
                    )
                };
                if !match_fn(&session, start, end) {
                    continue;
                }
                match inner.segments[seg_index].read_record(offset, length) {
                    Ok(record) => {
                        out.push(record);
                        if out.len() >= limit {
                            return out;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
        out
    }

    /// `acknowledged` 在 WAL 锁内调用，不能再进入同一个 [`Wal`]。
    /// 只删除非活动段，且该段每个 range 都被接受；没有 range 的段保留。
    pub fn reclaim(
        &self,
        mut acknowledged: impl FnMut(&str, u64, u64) -> bool,
    ) -> Result<u64, AppendError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(AppendError::Other("wal closed".into()));
        }
        inner.sync_locked()?;
        let count = inner.segments.len();
        if count == 0 {
            return Ok(0);
        }
        let mut drop_segment = vec![false; count];
        for (index, segment) in inner.segments.iter().take(count - 1).enumerate() {
            let mut all_ack = !segment.ranges.is_empty();
            for range in segment.ranges.values() {
                let session = hex_encode(&range.session_id);
                if !acknowledged(&session, range.start_sequence, range.end_sequence) {
                    all_ack = false;
                    break;
                }
            }
            drop_segment[index] = all_ack;
        }
        let mut removed = vec![false; count];
        let mut reclaimed = 0u64;
        for index in 0..count - 1 {
            if !drop_segment[index] {
                continue;
            }
            inner.segments[index].reader.take();
            if let Err(err) = fs::remove_file(&inner.segments[index].path) {
                inner.apply_reclaim(&removed, reclaimed);
                return Err(err.into());
            }
            let meta = with_suffix(&inner.segments[index].path, ".meta");
            if let Err(err) = fs::remove_file(&meta)
                && err.kind() != io::ErrorKind::NotFound
            {
                removed[index] = true;
                reclaimed += inner.segments[index].size;
                inner.apply_reclaim(&removed, reclaimed);
                return Err(err.into());
            }
            removed[index] = true;
            reclaimed += inner.segments[index].size;
        }
        inner.apply_reclaim(&removed, reclaimed);
        Ok(reclaimed)
    }

    pub fn close(&self) -> Result<(), AppendError> {
        self.lock().close_locked()
    }

    pub fn durable_heads(&self) -> BTreeMap<String, u64> {
        self.lock().durable_heads.clone()
    }
}

impl Drop for Wal {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        let _ = inner.close_locked();
    }
}

#[derive(Debug)]
pub enum StateError {
    Io(io::Error),
    Invalid(String),
    Generation {
        endpoint_id: String,
        generation: u64,
    },
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::Io(err) => write!(f, "{err}"),
            StateError::Invalid(err) => write!(f, "decode wal state: {err}"),
            StateError::Generation {
                endpoint_id,
                generation,
            } => {
                write!(f, "unknown endpoint generation {endpoint_id}/{generation}")
            }
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StateError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for StateError {
    fn from(err: io::Error) -> Self {
        StateError::Io(err)
    }
}

/// `cursors == None` 对应 Go 的 nil map：同 generation 的 upsert 会保留已有 cursors 和 activations。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointState {
    pub endpoint_id: String,
    pub generation: u64,
    pub reliable: bool,
    pub activation_session: String,
    pub activation_sequence: u64,
    pub cursors: Option<BTreeMap<String, u64>>,
    pub activations: Option<BTreeMap<String, u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CursorState {
    pub config_version: u64,
    pub endpoints: BTreeMap<String, EndpointState>,
}

struct StateInner {
    path: PathBuf,
    data: CursorState,
}

impl StateInner {
    fn save_locked(&self) -> Result<(), StateError> {
        let text = state_to_pretty(&self.data);
        atomic_write(&self.path, text.as_bytes(), true)?;
        Ok(())
    }
}

pub struct StateStore {
    inner: Mutex<StateInner>,
}

impl StateStore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StateError> {
        let dir = dir.as_ref();
        ensure_dir(dir)?;
        let path = dir.join("state.json");
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(err.into()),
        };
        let data = if bytes.is_empty() {
            CursorState::default()
        } else {
            parse_cursor_state(&bytes).map_err(StateError::Invalid)?
        };
        Ok(Self {
            inner: Mutex::new(StateInner { path, data }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, StateInner> {
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn upsert_endpoint(&self, mut endpoint: EndpointState) -> Result<(), StateError> {
        let mut inner = self.lock();
        if let Some(current) = inner.data.endpoints.get(&endpoint.endpoint_id).cloned()
            && current.generation == endpoint.generation
            && endpoint.cursors.is_none()
        {
            endpoint.cursors = current.cursors;
            endpoint.activations = current.activations;
        }
        if endpoint.cursors.is_none() {
            endpoint.cursors = Some(BTreeMap::new());
        }
        if endpoint.activations.is_none() {
            endpoint.activations = Some(BTreeMap::new());
        }
        if !endpoint.activation_session.is_empty() {
            let activation = if endpoint.activation_sequence == 0 {
                1
            } else {
                endpoint.activation_sequence
            };
            endpoint
                .activations
                .get_or_insert_with(BTreeMap::new)
                .insert(endpoint.activation_session.clone(), activation);
            endpoint
                .cursors
                .get_or_insert_with(BTreeMap::new)
                .entry(endpoint.activation_session.clone())
                .or_insert(activation - 1);
        }
        inner
            .data
            .endpoints
            .insert(endpoint.endpoint_id.clone(), endpoint);
        inner.save_locked()
    }

    pub fn set_config_version(&self, version: u64) -> Result<(), StateError> {
        let mut inner = self.lock();
        if version <= inner.data.config_version {
            return Ok(());
        }
        inner.data.config_version = version;
        inner.save_locked()
    }

    pub fn remove_endpoint(&self, endpoint_id: &str) -> Result<(), StateError> {
        let mut inner = self.lock();
        inner.data.endpoints.remove(endpoint_id);
        inner.save_locked()
    }

    pub fn prune_sessions(
        &self,
        keep: &std::collections::HashSet<String>,
    ) -> Result<(), StateError> {
        let mut inner = self.lock();
        let mut changed = false;
        for endpoint in inner.data.endpoints.values_mut() {
            if let Some(cursors) = endpoint.cursors.as_mut() {
                let before = cursors.len();
                cursors.retain(|session, _| keep.contains(session));
                changed |= cursors.len() != before;
            }
            if let Some(activations) = endpoint.activations.as_mut() {
                let before = activations.len();
                activations.retain(|session, _| keep.contains(session));
                changed |= activations.len() != before;
            }
        }
        if !changed {
            return Ok(());
        }
        inner.save_locked()
    }

    pub fn update_ack(
        &self,
        endpoint_id: &str,
        generation: u64,
        session_id: &[u8],
        ack_through: u64,
    ) -> Result<(), StateError> {
        let mut inner = self.lock();
        let Some(endpoint) = inner.data.endpoints.get_mut(endpoint_id) else {
            return Err(StateError::Generation {
                endpoint_id: endpoint_id.to_string(),
                generation,
            });
        };
        if endpoint.generation != generation {
            return Err(StateError::Generation {
                endpoint_id: endpoint_id.to_string(),
                generation,
            });
        }
        let key = hex_encode(session_id);
        let current = endpoint
            .cursors
            .as_ref()
            .and_then(|cursors| cursors.get(&key))
            .copied()
            .unwrap_or(0);
        if current >= ack_through {
            return Ok(());
        }
        endpoint
            .cursors
            .get_or_insert_with(BTreeMap::new)
            .insert(key, ack_through);
        inner.save_locked()
    }

    pub fn ack(&self, endpoint_id: &str, session_id: &[u8]) -> u64 {
        let inner = self.lock();
        let key = hex_encode(session_id);
        inner
            .data
            .endpoints
            .get(endpoint_id)
            .and_then(|endpoint| endpoint.cursors.as_ref())
            .and_then(|cursors| cursors.get(&key))
            .copied()
            .unwrap_or(0)
    }

    pub fn endpoint(&self, id: &str) -> Option<EndpointState> {
        self.lock().data.endpoints.get(id).cloned()
    }

    pub fn snapshot(&self) -> CursorState {
        self.lock().data.clone()
    }
}

fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn json_string(text: &str) -> String {
    let mut out = String::new();
    push_json_string(&mut out, text);
    out
}

fn pad(out: &mut String, width: usize) {
    for _ in 0..width {
        out.push(' ');
    }
}

fn write_keyed_object(out: &mut String, fields: &[(&str, String)], brace_indent: usize) {
    if fields.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push_str("{\n");
    for (index, (key, value)) in fields.iter().enumerate() {
        pad(out, brace_indent + 2);
        push_json_string(out, key);
        out.push_str(": ");
        out.push_str(value);
        if index + 1 != fields.len() {
            out.push(',');
        }
        out.push('\n');
    }
    pad(out, brace_indent);
    out.push('}');
}

fn map_u64_pretty(map: &BTreeMap<String, u64>, brace_indent: usize) -> String {
    if map.is_empty() {
        return "{}".into();
    }
    let mut out = String::from("{\n");
    let last = map.len() - 1;
    for (index, (key, value)) in map.iter().enumerate() {
        pad(&mut out, brace_indent + 2);
        push_json_string(&mut out, key);
        out.push_str(": ");
        out.push_str(&value.to_string());
        if index != last {
            out.push(',');
        }
        out.push('\n');
    }
    pad(&mut out, brace_indent);
    out.push('}');
    out
}

fn write_endpoint(out: &mut String, endpoint: &EndpointState, brace_indent: usize) {
    let mut fields = Vec::new();
    fields.push(("endpoint_id", json_string(&endpoint.endpoint_id)));
    fields.push(("generation", endpoint.generation.to_string()));
    fields.push((
        "reliable",
        if endpoint.reliable {
            "true".into()
        } else {
            "false".into()
        },
    ));
    if !endpoint.activation_session.is_empty() {
        fields.push((
            "activation_session",
            json_string(&endpoint.activation_session),
        ));
    }
    if endpoint.activation_sequence != 0 {
        fields.push((
            "activation_sequence",
            endpoint.activation_sequence.to_string(),
        ));
    }
    let cursors = match &endpoint.cursors {
        Some(cursors) => map_u64_pretty(cursors, brace_indent + 2),
        None => "{}".into(),
    };
    fields.push(("cursors", cursors));
    if let Some(activations) = &endpoint.activations
        && !activations.is_empty()
    {
        fields.push(("activations", map_u64_pretty(activations, brace_indent + 2)));
    }
    write_keyed_object(out, &fields, brace_indent);
}

fn write_endpoints(
    out: &mut String,
    endpoints: &BTreeMap<String, EndpointState>,
    brace_indent: usize,
) {
    if endpoints.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push_str("{\n");
    let last = endpoints.len() - 1;
    for (index, (key, endpoint)) in endpoints.iter().enumerate() {
        pad(out, brace_indent + 2);
        push_json_string(out, key);
        out.push_str(": ");
        write_endpoint(out, endpoint, brace_indent + 2);
        if index != last {
            out.push(',');
        }
        out.push('\n');
    }
    pad(out, brace_indent);
    out.push('}');
}

fn state_to_pretty(state: &CursorState) -> String {
    let mut endpoints = String::new();
    write_endpoints(&mut endpoints, &state.endpoints, 2);
    let fields = [
        ("config_version", state.config_version.to_string()),
        ("endpoints", endpoints),
    ];
    let mut out = String::new();
    write_keyed_object(&mut out, &fields, 0);
    out
}

enum Json {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

struct Parser<'a> {
    src: &'a [u8],
    index: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.index).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.index += 1;
        Some(byte)
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.eat(byte) {
            Ok(())
        } else {
            Err(format!("expected byte {byte}"))
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.index += 1;
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.parse_lit(b"null", Json::Null),
            Some(b't') => self.parse_lit(b"true", Json::Bool(true)),
            Some(b'f') => self.parse_lit(b"false", Json::Bool(false)),
            Some(b'"') => Ok(Json::String(self.parse_string()?)),
            Some(b'{') => Ok(Json::Object(self.parse_object()?)),
            Some(b'[') => Ok(Json::Array(self.parse_array()?)),
            Some(b'0'..=b'9') => self.parse_number(),
            _ => Err("invalid json value".into()),
        }
    }

    fn parse_lit(&mut self, lit: &[u8], value: Json) -> Result<Json, String> {
        if self.src[self.index..].starts_with(lit) {
            self.index += lit.len();
            Ok(value)
        } else {
            Err("bad literal".into())
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut raw = Vec::new();
        loop {
            let byte = self
                .bump()
                .ok_or_else(|| "unterminated string".to_string())?;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escaped = self.bump().ok_or_else(|| "bad escape".to_string())?;
                    match escaped {
                        b'"' => raw.push(b'"'),
                        b'\\' => raw.push(b'\\'),
                        b'/' => raw.push(b'/'),
                        b'b' => raw.push(0x08),
                        b'f' => raw.push(0x0c),
                        b'n' => raw.push(b'\n'),
                        b'r' => raw.push(b'\r'),
                        b't' => raw.push(b'\t'),
                        b'u' => {
                            let code = self.read_hex4()?;
                            let ch =
                                char::from_u32(code).ok_or_else(|| "bad unicode".to_string())?;
                            let mut buf = [0u8; 4];
                            raw.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                other => raw.push(other),
            }
        }
        String::from_utf8(raw).map_err(|_| "invalid utf-8".to_string())
    }

    fn read_hex4(&mut self) -> Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..4 {
            let byte = self
                .bump()
                .ok_or_else(|| "short unicode escape".to_string())?;
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err("bad unicode escape".into()),
            };
            value = (value << 4) | u32::from(digit);
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.index;
        if self.peek() == Some(b'0') {
            self.index += 1;
            if matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err("leading zero".into());
            }
        } else {
            if !matches!(self.peek(), Some(b'1'..=b'9')) {
                return Err("bad number".into());
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.index += 1;
            }
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err("non-integer number".into());
        }
        let text = std::str::from_utf8(&self.src[start..self.index]).unwrap();
        let number = text
            .parse::<u64>()
            .map_err(|_| "number overflow".to_string())?;
        Ok(Json::Number(number))
    }

    fn parse_object(&mut self) -> Result<BTreeMap<String, Json>, String> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.eat(b'}') {
            return Ok(map);
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            map.insert(key, value);
            self.skip_ws();
            if self.eat(b',') {
                continue;
            }
            if self.eat(b'}') {
                break;
            }
            return Err("expected , or }".into());
        }
        Ok(map)
    }

    fn parse_array(&mut self) -> Result<Vec<Json>, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.eat(b']') {
            return Ok(items);
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            if self.eat(b',') {
                continue;
            }
            if self.eat(b']') {
                break;
            }
            return Err("expected , or ]".into());
        }
        Ok(items)
    }
}

fn parse_json(data: &[u8]) -> Result<Json, String> {
    let mut parser = Parser {
        src: data,
        index: 0,
    };
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.index != parser.src.len() {
        return Err("trailing json".into());
    }
    Ok(value)
}

fn as_object(value: &Json) -> Result<&BTreeMap<String, Json>, String> {
    match value {
        Json::Object(map) => Ok(map),
        _ => Err("expected object".into()),
    }
}

fn json_u64(value: &Json) -> Result<u64, String> {
    match value {
        Json::Number(number) => Ok(*number),
        _ => Err("expected number".into()),
    }
}

fn optional_u64(obj: &BTreeMap<String, Json>, key: &str) -> Result<u64, String> {
    match obj.get(key) {
        None | Some(Json::Null) => Ok(0),
        Some(value) => json_u64(value),
    }
}

fn json_bytes(value: &Json) -> Result<Vec<u8>, String> {
    match value {
        Json::String(text) => b64_decode(text),
        Json::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let number = json_u64(item)?;
                let byte = u8::try_from(number).map_err(|_| "byte out of range".to_string())?;
                out.push(byte);
            }
            Ok(out)
        }
        _ => Err("expected bytes".into()),
    }
}

fn parse_u64_map(value: &Json) -> Result<BTreeMap<String, u64>, String> {
    let obj = as_object(value)?;
    let mut out = BTreeMap::new();
    for (key, item) in obj {
        out.insert(key.clone(), json_u64(item)?);
    }
    Ok(out)
}

fn parse_endpoint(value: &Json) -> Result<EndpointState, String> {
    let obj = as_object(value)?;
    let endpoint_id = match obj.get("endpoint_id") {
        Some(Json::String(text)) => text.clone(),
        Some(Json::Null) | None => String::new(),
        Some(_) => return Err("endpoint_id".into()),
    };
    let reliable = match obj.get("reliable") {
        Some(Json::Bool(value)) => *value,
        Some(Json::Null) | None => false,
        Some(_) => return Err("reliable".into()),
    };
    let activation_session = match obj.get("activation_session") {
        Some(Json::String(text)) => text.clone(),
        Some(Json::Null) | None => String::new(),
        Some(_) => return Err("activation_session".into()),
    };
    let cursors = match obj.get("cursors") {
        None | Some(Json::Null) => Some(BTreeMap::new()),
        Some(value) => Some(parse_u64_map(value)?),
    };
    let activations = match obj.get("activations") {
        None | Some(Json::Null) => None,
        Some(value) => {
            let parsed = parse_u64_map(value)?;
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        }
    };
    Ok(EndpointState {
        endpoint_id,
        generation: optional_u64(obj, "generation")?,
        reliable,
        activation_session,
        activation_sequence: optional_u64(obj, "activation_sequence")?,
        cursors,
        activations,
    })
}

fn parse_cursor_state(data: &[u8]) -> Result<CursorState, String> {
    let value = parse_json(data)?;
    let obj = as_object(&value)?;
    let mut endpoints = BTreeMap::new();
    if let Some(raw) = obj.get("endpoints")
        && !matches!(raw, Json::Null)
    {
        for (key, endpoint) in as_object(raw)? {
            let mut parsed = parse_endpoint(endpoint)?;
            if parsed.endpoint_id.is_empty() {
                parsed.endpoint_id = key.clone();
            }
            endpoints.insert(key.clone(), parsed);
        }
    }
    Ok(CursorState {
        config_version: optional_u64(obj, "config_version")?,
        endpoints,
    })
}

fn parse_manifest(data: &[u8]) -> Result<BTreeMap<String, SequenceRange>, String> {
    let value = parse_json(data)?;
    let obj = as_object(&value)?;
    let Some(raw) = obj.get("ranges") else {
        return Err("missing ranges".into());
    };
    if matches!(raw, Json::Null) {
        return Ok(BTreeMap::new());
    }
    let mut ranges = BTreeMap::new();
    for (key, item) in as_object(raw)? {
        let fields = as_object(item)?;
        let node_uuid = json_bytes(
            fields
                .get("node_uuid")
                .ok_or_else(|| "node_uuid".to_string())?,
        )?;
        let session_id = json_bytes(
            fields
                .get("session_id")
                .ok_or_else(|| "session_id".to_string())?,
        )?;
        ranges.insert(
            key.clone(),
            SequenceRange {
                node_uuid,
                session_id,
                start_sequence: json_u64(
                    fields
                        .get("start_sequence")
                        .ok_or_else(|| "start_sequence".to_string())?,
                )?,
                end_sequence: json_u64(
                    fields
                        .get("end_sequence")
                        .ok_or_else(|| "end_sequence".to_string())?,
                )?,
            },
        );
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn scratch(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "santaizi-wal-{label}-{}-{n}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(label: &str) -> Self {
            Self(scratch(label))
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn event_record(node: &[u8], session: &[u8], sequence: u64) -> pb::TelemetryRecord {
        pb::TelemetryRecord {
            record: Some(pb::telemetry_record::Record::Event(pb::TelemetryEvent {
                event_id: vec![],
                node_uuid: node.to_vec(),
                session_id: session.to_vec(),
                sequence,
                event_type: pb::TelemetryEventType::Heartbeat as i32,
                priority: pb::TelemetryPriority::P0Critical as i32,
                collected_at_unix_nano: 0,
                agent_uptime_nano: 0,
                session_elapsed_nano: 0,
                protocol_version: 0,
                source_protocol: 0,
                reliability: 0,
                payload: Some(pb::telemetry_event::Payload::Heartbeat(
                    pb::HeartbeatPayload { boot_time_unix: 0 },
                )),
            })),
        }
    }

    fn event_sequence(record: &pb::TelemetryRecord) -> u64 {
        match &record.record {
            Some(pb::telemetry_record::Record::Event(event)) => event.sequence,
            _ => panic!("expected event"),
        }
    }

    #[test]
    fn append_sync_reopen_collects_same_sequence() {
        let dir = TmpDir::new("roundtrip");
        let node = [0u8; 16];
        let mut session = [0u8; 16];
        session[15] = 1;
        let cfg = WalConfig {
            dir: dir.path().to_path_buf(),
            segment_size: 8 << 20,
            max_size: 1 << 20,
            fsync_interval: Duration::from_secs(3600),
            fsync_records: 64,
            reserve_bytes: 1 << 20,
        };
        let wal = Wal::open(cfg).unwrap();
        let p0 = pb::TelemetryPriority::P0Critical as i32;
        wal.append(&event_record(&node, &session, 7), p0).unwrap();
        wal.sync().unwrap();
        let meta = fs::read_to_string(dir.path().join("000000000001.seg.meta")).unwrap();
        assert_eq!(
            meta,
            "{\"ranges\":{\"00000000000000000000000000000000/00000000000000000000000000000001\":{\"node_uuid\":\"AAAAAAAAAAAAAAAAAAAAAA==\",\"session_id\":\"AAAAAAAAAAAAAAAAAAAAAQ==\",\"start_sequence\":7,\"end_sequence\":7}}}"
        );
        wal.close().unwrap();

        let wal = Wal::open(WalConfig {
            dir: dir.path().to_path_buf(),
            ..WalConfig::default()
        })
        .unwrap();
        let got = wal.collect_pending(|_, _, _| true, 10);
        assert_eq!(got.len(), 1);
        assert_eq!(event_sequence(&got[0]), 7);
        assert_eq!(
            wal.durable_heads().get(&hex_encode(&session)).copied(),
            Some(7)
        );
        assert!(wal.recovery_issues().is_empty());
    }

    #[test]
    fn pressure_rejects_p2_at_rollup_and_p0_at_hard_limit() {
        let dir = TmpDir::new("pressure");
        let wal = Wal::open(WalConfig {
            dir: dir.path().to_path_buf(),
            segment_size: 1 << 20,
            max_size: 8192,
            fsync_interval: Duration::from_secs(3600),
            fsync_records: 10_000,
            reserve_bytes: 64,
        })
        .unwrap();
        let node = [9u8; 16];
        let session = [3u8; 16];
        let p2 = pb::TelemetryPriority::P2Normal as i32;
        let p0 = pb::TelemetryPriority::P0Critical as i32;
        let mut sequence = 1u64;
        while wal.pressure() < Pressure::Rollup {
            wal.append(&event_record(&node, &session, sequence), p0)
                .expect("P0 should fill up to the rollup watermark");
            sequence += 1;
            assert!(sequence < 10_000, "never reached rollup");
        }
        assert!(wal.pressure() < Pressure::HardLimit);
        let err = wal
            .append(&event_record(&node, &session, sequence), p2)
            .unwrap_err();
        assert!(
            matches!(err, AppendError::NeedsRollup),
            "P2 at >=85% should be NeedsRollup, got {err}"
        );
        wal.append(&event_record(&node, &session, sequence + 1), p0)
            .expect("P0 still fits before the hard limit");
        let err = loop {
            sequence += 1;
            match wal.append(&event_record(&node, &session, sequence), p0) {
                Ok(()) => continue,
                Err(err) => break err,
            }
        };
        assert!(matches!(err, AppendError::HardLimit), "full WAL got {err}");
    }

    #[test]
    fn pressure_watermarks() {
        let cases = [
            (0, Pressure::Healthy),
            (699, Pressure::Healthy),
            (700, Pressure::Downsample),
            (849, Pressure::Downsample),
            (850, Pressure::Rollup),
            (949, Pressure::Rollup),
            (950, Pressure::Critical),
            (999, Pressure::Critical),
            (1000, Pressure::HardLimit),
        ];
        for (size, want) in cases {
            assert_eq!(pressure_for(size, 1000), want, "size {size}");
        }
    }

    #[test]
    fn state_store_two_endpoints_ack_generation_and_no_rollback() {
        let dir = TmpDir::new("state");
        let store = StateStore::open(dir.path()).unwrap();
        store
            .upsert_endpoint(EndpointState {
                endpoint_id: "primary".into(),
                generation: 1,
                reliable: true,
                ..EndpointState::default()
            })
            .unwrap();
        store
            .upsert_endpoint(EndpointState {
                endpoint_id: "hk".into(),
                generation: 2,
                reliable: true,
                ..EndpointState::default()
            })
            .unwrap();
        let session = [1u8, 2, 3];
        store.update_ack("primary", 1, &session, 100).unwrap();
        store.update_ack("primary", 1, &session, 40).unwrap();
        assert_eq!(store.ack("primary", &session), 100);
        let err = store.update_ack("primary", 9, &session, 200).unwrap_err();
        assert!(matches!(err, StateError::Generation { .. }));
        store.update_ack("hk", 2, &session, 7).unwrap();
        assert_eq!(store.ack("hk", &session), 7);
        store.set_config_version(3).unwrap();
        store.set_config_version(2).unwrap();
        assert_eq!(store.snapshot().config_version, 3);

        let text = fs::read_to_string(dir.path().join("state.json")).unwrap();
        assert_eq!(
            text,
            "{\n  \"config_version\": 3,\n  \"endpoints\": {\n    \"hk\": {\n      \"endpoint_id\": \"hk\",\n      \"generation\": 2,\n      \"reliable\": true,\n      \"cursors\": {\n        \"010203\": 7\n      }\n    },\n    \"primary\": {\n      \"endpoint_id\": \"primary\",\n      \"generation\": 1,\n      \"reliable\": true,\n      \"cursors\": {\n        \"010203\": 100\n      }\n    }\n  }\n}"
        );
        assert!(!text.contains("activation_session"));
        assert!(!text.contains("activations"));

        drop(store);
        let store = StateStore::open(dir.path()).unwrap();
        assert_eq!(store.ack("primary", &session), 100);
        assert_eq!(store.ack("hk", &session), 7);

        store
            .upsert_endpoint(EndpointState {
                endpoint_id: "primary".into(),
                generation: 1,
                reliable: true,
                activation_session: "010203".into(),
                activation_sequence: 50,
                ..EndpointState::default()
            })
            .unwrap();
        assert_eq!(store.ack("primary", &session), 100);
        let primary = store.endpoint("primary").unwrap();
        assert_eq!(primary.activations.unwrap().get("010203"), Some(&50));

        let mut keep = HashSet::new();
        keep.insert("010203".into());
        store
            .upsert_endpoint(EndpointState {
                endpoint_id: "primary".into(),
                generation: 1,
                reliable: true,
                activation_session: "ffff".into(),
                activation_sequence: 1,
                ..EndpointState::default()
            })
            .unwrap();
        store.prune_sessions(&keep).unwrap();
        assert_eq!(store.ack("primary", &session), 100);
        let primary = store.endpoint("primary").unwrap();
        assert!(!primary.activations.unwrap_or_default().contains_key("ffff"));

        let other = TmpDir::new("state-compact");
        fs::write(
            other.path().join("state.json"),
            r#"{"endpoints":{"solo":{"reliable":true,"generation":4,"endpoint_id":"solo","cursors":{"aa":3}}},"config_version":8}"#,
        )
        .unwrap();
        let compact = StateStore::open(other.path()).unwrap();
        assert_eq!(compact.ack("solo", &[0xaa]), 3);
        assert_eq!(compact.snapshot().config_version, 8);
    }

    #[test]
    fn handcrafted_crc_frame_and_truncated_tail() {
        assert_eq!(crc32_castagnoli(b"123456789"), 0xE306_9283);
        assert_eq!(b64_encode(&[0u8; 16]), "AAAAAAAAAAAAAAAAAAAAAA==");
        assert_eq!(b64_encode(&[0xff]), "/w==");
        assert_eq!(b64_encode(&[0xff, 0xef]), "/+8=");
        assert_eq!(b64_decode("/+8=").unwrap(), vec![0xff, 0xef]);

        let dir = TmpDir::new("hand");
        let payload1 = [0x0a_u8, 0x02, 0x20, 0x01];
        let payload2 = [0x0a_u8, 0x02, 0x20, 0x02];
        assert_eq!(crc32_castagnoli(&payload1), 0xc3cb_39ac);
        assert_eq!(crc32_castagnoli(&payload2), 0xd09b_ca58);
        let mut bytes = Vec::new();
        push_known_frame(&mut bytes, &payload1, 1, 0xc3cb_39ac);
        push_known_frame(&mut bytes, &payload2, 1, 0xd09b_ca58);
        fs::write(dir.path().join("000000000001.seg"), &bytes).unwrap();

        let wal = Wal::open(WalConfig {
            dir: dir.path().to_path_buf(),
            max_size: 1 << 20,
            ..WalConfig::default()
        })
        .unwrap();
        let got = wal.collect_pending(|_, _, _| true, 10);
        assert_eq!(got.len(), 2);
        assert_eq!(event_sequence(&got[0]), 1);
        assert_eq!(event_sequence(&got[1]), 2);
        wal.close().unwrap();

        let path = dir.path().join("000000000001.seg");
        let len = fs::metadata(&path).unwrap().len();
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(len - 1).unwrap();
        drop(file);

        let wal = Wal::open(WalConfig {
            dir: dir.path().to_path_buf(),
            max_size: 1 << 20,
            ..WalConfig::default()
        })
        .unwrap();
        let issues = wal.recovery_issues();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].reason, "truncated_partial_tail");
        assert_eq!(issues[0].segment, "000000000001.seg");
        let got = wal.collect_pending(|_, _, _| true, 10);
        assert_eq!(got.len(), 1);
        assert_eq!(event_sequence(&got[0]), 1);
    }

    fn push_known_frame(buf: &mut Vec<u8>, payload: &[u8], priority: u16, crc: u32) {
        buf.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
        buf.extend_from_slice(&FRAME_VERSION.to_be_bytes());
        buf.extend_from_slice(&priority.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&crc.to_be_bytes());
        buf.extend_from_slice(payload);
    }

    #[test]
    fn corrupt_segment_is_quarantined_with_meta_ranges() {
        let dir = TmpDir::new("corrupt");
        let node = [0u8; 16];
        let mut session = [0u8; 16];
        session[15] = 1;
        let wal = Wal::open(WalConfig {
            dir: dir.path().to_path_buf(),
            max_size: 1 << 20,
            fsync_interval: Duration::from_secs(3600),
            ..WalConfig::default()
        })
        .unwrap();
        wal.append(
            &event_record(&node, &session, 7),
            pb::TelemetryPriority::P0Critical as i32,
        )
        .unwrap();
        wal.close().unwrap();
        let path = dir.path().join("000000000001.seg");
        let mut data = fs::read(&path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0xff;
        fs::write(&path, data).unwrap();

        let wal = Wal::open(WalConfig {
            dir: dir.path().to_path_buf(),
            max_size: 1 << 20,
            ..WalConfig::default()
        })
        .unwrap();
        let issues = wal.recovery_issues();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].segment, "000000000001.seg");
        assert!(
            issues[0].reason.contains("checksum"),
            "{}",
            issues[0].reason
        );
        assert_eq!(issues[0].ranges.len(), 1);
        assert_eq!(issues[0].ranges[0].start_sequence, 7);
        assert_eq!(issues[0].ranges[0].end_sequence, 7);
        assert!(wal.collect_pending(|_, _, _| true, 10).is_empty());
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|ent| ent.ok())
            .map(|ent| ent.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().any(|name| name.contains(".corrupt-")),
            "quarantine missing: {names:?}"
        );
    }

    #[test]
    fn reclaim_requires_every_session_range() {
        let dir = TmpDir::new("reclaim");
        let node = [0u8; 16];
        let mut session_a = [0u8; 16];
        session_a[15] = 1;
        let mut session_b = [0u8; 16];
        session_b[15] = 2;
        let wal = Wal::open(WalConfig {
            dir: dir.path().to_path_buf(),
            segment_size: 8 << 20,
            max_size: 8 << 20,
            fsync_interval: Duration::from_secs(3600),
            fsync_records: 1000,
            reserve_bytes: 1024,
        })
        .unwrap();
        let p0 = pb::TelemetryPriority::P0Critical as i32;
        wal.append(&event_record(&node, &session_a, 1), p0).unwrap();
        wal.append(&event_record(&node, &session_b, 1), p0).unwrap();
        wal.sync().unwrap();
        let filled = wal.size();
        wal.close().unwrap();

        let wal = Wal::open(WalConfig {
            dir: dir.path().to_path_buf(),
            segment_size: filled,
            max_size: 8 << 20,
            fsync_interval: Duration::from_secs(3600),
            fsync_records: 1000,
            reserve_bytes: 1024,
        })
        .unwrap();
        wal.append(&event_record(&node, &session_a, 2), p0).unwrap();
        wal.sync().unwrap();
        assert!(dir.path().join("000000000002.seg").exists());

        let hex_a = hex_encode(&session_a);
        let hex_b = hex_encode(&session_b);
        let kept = wal.reclaim(|session, _, _| session == hex_a).unwrap();
        assert_eq!(kept, 0);
        assert!(dir.path().join("000000000001.seg").exists());

        let removed = wal
            .reclaim(|session, _, _| session == hex_a || session == hex_b)
            .unwrap();
        assert!(removed > 0);
        assert!(!dir.path().join("000000000001.seg").exists());
        assert!(!dir.path().join("000000000001.seg.meta").exists());
        assert!(dir.path().join("000000000002.seg").exists());
        let got = wal.collect_pending(|_, _, _| true, 10);
        assert_eq!(got.len(), 1);
        assert_eq!(event_sequence(&got[0]), 2);
    }
}

use crate::config::CapabilityConfig;
use crate::pb;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use sysinfo::{Components, Disks, Networks, ProcessesToUpdate, System};

/// 与 Go `excludeNetInterfaces` 一致：名字里出现这些子串就排除。
const NIC_EXCLUDE: &[&str] = &["lo", "tun", "docker", "veth", "br-", "vmbr", "vnet", "kube"];
/// 与 Go `expectDiskFsTypes` 一致。
const FS_ALLOWLIST: &[&str] = &[
    "apfs",
    "ext4",
    "ext3",
    "ext2",
    "f2fs",
    "reiserfs",
    "jfs",
    "btrfs",
    "fuseblk",
    "zfs",
    "simfs",
    "ntfs",
    "fat32",
    "exfat",
    "xfs",
    "fuse.rclone",
];
const MOUNT_EXCLUDE_PREFIXES: &[&str] = &["/var/lib/kubelet"];

/// Go TrackNetworkSpeed：allowlist 非空时精确匹配并取代内置排除；为空时按子串排除。
fn nic_included(name: &str, allowlist: &[String]) -> bool {
    if !allowlist.is_empty() {
        return allowlist.iter().any(|n| n == name);
    }
    !NIC_EXCLUDE.iter().any(|p| name.contains(p))
}

/// Go collectDiskTotalAndUsed（monitor.go:333-348）：allowlist 非空时精确匹配
/// 挂载点，并取代内置文件系统白名单与 kubelet 排除；为空时走内置规则。
fn partition_included(mount: &str, fs: &str, allowlist: &[String]) -> bool {
    if !allowlist.is_empty() {
        return allowlist.iter().any(|m| m == mount);
    }
    FS_ALLOWLIST.contains(&fs) && !MOUNT_EXCLUDE_PREFIXES.iter().any(|p| mount.contains(p))
}

pub struct Monitor {
    sys: System,
    disks: Disks,
    networks: Networks,
    /// 上次网卡累计值，用于差分算速率。
    last_net: Option<(Instant, u64, u64)>,
    boot_time: u64,
    nic_allowlist: Vec<String>,
    partition_allowlist: Vec<String>,
}

impl Monitor {
    pub fn new() -> Self {
        Self::with_allowlists(Vec::new(), Vec::new())
    }

    /// nic / partition allowlist 非空时只统计列表内项（语义见 nic_included）。
    pub fn with_allowlists(nic_allowlist: Vec<String>, partition_allowlist: Vec<String>) -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self {
            sys,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            last_net: None,
            boot_time: System::boot_time(),
            nic_allowlist,
            partition_allowlist,
        }
    }

    /// 返回 (used, total)。
    fn disk_usage(&mut self) -> (u64, u64) {
        self.disks.refresh(true);
        let mut total = 0u64;
        let mut used = 0u64;
        let mut seen_devices = std::collections::HashSet::new();
        for d in self.disks.iter() {
            let fs = d.file_system().to_string_lossy().to_lowercase();
            let mount = d.mount_point().to_string_lossy();
            if !partition_included(&mount, &fs, &self.partition_allowlist) {
                continue;
            }
            let device = d.name().to_string_lossy().to_string();
            if !device.is_empty() && !seen_devices.insert(device) {
                continue;
            }
            total += d.total_space();
            used += d.total_space().saturating_sub(d.available_space());
        }
        if total == 0 {
            // 与 Go 探针的 df / 回退等价：白名单全落空时至少统计根分区。
            if let Some(d) = self
                .disks
                .iter()
                .find(|d| d.mount_point() == std::path::Path::new("/"))
            {
                total = d.total_space();
                used = d.total_space().saturating_sub(d.available_space());
            }
        }
        (used, total)
    }

    pub fn boot_time(&self) -> u64 {
        self.boot_time
    }

    pub fn host(
        &mut self,
        ip: &str,
        country_code: &str,
        version: &str,
        caps: &CapabilityConfig,
    ) -> pb::Host {
        let virt = detect_virtualization();
        let (_, disk_total) = if caps.host_info && caps.disk {
            self.disk_usage()
        } else {
            (0, 0)
        };
        let cpu = if caps.host_info {
            let cpu_model = self
                .sys
                .cpus()
                .first()
                .map(|c| c.brand().trim().to_string())
                .unwrap_or_default();
            let cores = self.sys.cpus().len();
            if cpu_model.is_empty() {
                Vec::new()
            } else {
                let kind = if virt.is_empty() {
                    "Physical"
                } else {
                    "Virtual"
                };
                vec![format!("{cpu_model} {cores} {kind} Core")]
            }
        } else {
            Vec::new()
        };
        pb::Host {
            platform: if caps.host_info {
                os_id()
            } else {
                String::new()
            },
            platform_version: if caps.host_info {
                System::os_version().unwrap_or_default()
            } else {
                String::new()
            },
            cpu,
            mem_total: if caps.host_info && caps.memory {
                self.sys.total_memory()
            } else {
                0
            },
            disk_total,
            swap_total: if caps.host_info && caps.memory {
                self.sys.total_swap()
            } else {
                0
            },
            arch: if caps.host_info {
                System::cpu_arch()
            } else {
                String::new()
            },
            virtualization: if caps.host_info { virt } else { String::new() },
            boot_time: self.boot_time,
            ip: if caps.ip_report {
                ip.to_string()
            } else {
                String::new()
            },
            country_code: if caps.ip_report {
                country_code.to_string()
            } else {
                String::new()
            },
            version: version.to_string(),
            gpu: if caps.host_info && caps.gpu {
                gpu_model_names()
            } else {
                Vec::new()
            },
        }
    }

    pub fn collect_state(&mut self, caps: &CapabilityConfig) -> pb::State {
        if caps.cpu {
            self.sys.refresh_cpu_usage();
        }
        if caps.memory {
            self.sys.refresh_memory();
        }
        if caps.processes {
            self.sys.refresh_processes(ProcessesToUpdate::All, true);
        }
        let load = if caps.cpu {
            System::load_average()
        } else {
            sysinfo::LoadAvg {
                one: 0.0,
                five: 0.0,
                fifteen: 0.0,
            }
        };
        let (disk_used, _) = if caps.disk { self.disk_usage() } else { (0, 0) };

        let mut rx_total = 0u64;
        let mut tx_total = 0u64;
        let mut in_speed = 0u64;
        let mut out_speed = 0u64;
        if caps.network {
            self.networks.refresh(true);
            for (name, data) in self.networks.iter() {
                if !nic_included(name, &self.nic_allowlist) {
                    continue;
                }
                rx_total += data.total_received();
                tx_total += data.total_transmitted();
            }
            let now = Instant::now();
            if let Some((prev_at, prev_rx, prev_tx)) =
                self.last_net.replace((now, rx_total, tx_total))
            {
                let secs = now.duration_since(prev_at).as_secs_f64();
                if secs > 0.0 {
                    in_speed = (rx_total.saturating_sub(prev_rx) as f64 / secs) as u64;
                    out_speed = (tx_total.saturating_sub(prev_tx) as f64 / secs) as u64;
                }
            }
        }

        let (tcp, udp) = if caps.connections {
            sockstat_counts()
        } else {
            (0, 0)
        };
        pb::State {
            cpu: if caps.cpu {
                self.sys.global_cpu_usage() as f64
            } else {
                0.0
            },
            // Go 口径：used = Total - Available。
            mem_used: if caps.memory {
                self.sys
                    .total_memory()
                    .saturating_sub(self.sys.available_memory())
            } else {
                0
            },
            swap_used: if caps.memory { self.sys.used_swap() } else { 0 },
            disk_used,
            net_in_transfer: rx_total,
            net_out_transfer: tx_total,
            net_in_speed: in_speed,
            net_out_speed: out_speed,
            uptime: System::uptime(),
            load1: load.one,
            load5: load.five,
            load15: load.fifteen,
            tcp_conn_count: tcp,
            udp_conn_count: udp,
            process_count: if caps.processes {
                self.sys.processes().len() as u64
            } else {
                0
            },
            temperatures: if caps.temperature {
                collect_temperatures()
            } else {
                Vec::new()
            },
            gpu: if caps.gpu { gpu_utilization() } else { 0.0 },
        }
    }
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

static GPU_MODEL_FAILS: AtomicU32 = AtomicU32::new(0);
static GPU_UTIL_FAILS: AtomicU32 = AtomicU32::new(0);

fn gpu_try(counter: &AtomicU32) -> bool {
    counter.load(Ordering::Relaxed) < 3
}

fn gpu_fail(counter: &AtomicU32) {
    counter.fetch_add(1, Ordering::Relaxed);
}

fn gpu_ok(counter: &AtomicU32) {
    counter.store(0, Ordering::Relaxed);
}

fn run_smi(path: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(path).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn which_smi(preferred: &str, name: &str, args: &[&str]) -> Option<String> {
    run_smi(preferred, args).or_else(|| run_smi(name, args))
}

/// 型号：nvidia-smi 名称，失败再 rocm。连续失败 3 次后本进程不再试。
fn gpu_model_names() -> Vec<String> {
    if !gpu_try(&GPU_MODEL_FAILS) {
        return Vec::new();
    }
    if let Some(text) = which_smi(
        "/usr/bin/nvidia-smi",
        "nvidia-smi",
        &["--query-gpu=name", "--format=csv,noheader"],
    ) {
        let names: Vec<String> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && *l != "[Not Supported]")
            .map(str::to_string)
            .collect();
        if !names.is_empty() {
            gpu_ok(&GPU_MODEL_FAILS);
            return names;
        }
    }
    if let Some(text) = which_smi("/opt/rocm/bin/rocm-smi", "rocm-smi", &["--showproductname"]) {
        let names: Vec<String> = text
            .lines()
            .filter_map(|line| {
                let (label, value) = line.split_once(':')?;
                if !label.to_ascii_lowercase().contains("card model") {
                    return None;
                }
                let value = value.trim();
                if value.is_empty() || value.eq_ignore_ascii_case("N/A") {
                    None
                } else {
                    Some(value.to_string())
                }
            })
            .collect();
        if !names.is_empty() {
            gpu_ok(&GPU_MODEL_FAILS);
            return names;
        }
    }
    gpu_fail(&GPU_MODEL_FAILS);
    Vec::new()
}

/// 只取第一张卡。先 nvidia-smi -q -x 的 gpu_util，再 rocm-smi -u --json。
fn gpu_utilization() -> f64 {
    if !gpu_try(&GPU_UTIL_FAILS) {
        return 0.0;
    }
    if let Some(xml) = which_smi("/usr/bin/nvidia-smi", "nvidia-smi", &["-q", "-x"])
        && let Some(value) = first_tagged_number(&xml, "gpu_util")
    {
        gpu_ok(&GPU_UTIL_FAILS);
        return value;
    }
    if let Some(json) = which_smi("/opt/rocm/bin/rocm-smi", "rocm-smi", &["-u", "--json"])
        && let Some(value) = first_number_after(&json, "GPU use (%)")
    {
        gpu_ok(&GPU_UTIL_FAILS);
        return value;
    }
    gpu_fail(&GPU_UTIL_FAILS);
    0.0
}

fn first_tagged_number(xml: &str, tag: &str) -> Option<f64> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    xml[start..end]
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
}

fn first_number_after(text: &str, needle: &str) -> Option<f64> {
    let rest = text.get(text.find(needle)? + needle.len()..)?;
    let mut digits = String::new();
    let mut seen = false;
    for ch in rest.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            digits.push(ch);
            seen = true;
        } else if seen {
            break;
        }
    }
    digits.parse().ok()
}

fn collect_temperatures() -> Vec<pb::StateSensorTemperature> {
    let mut components = Components::new_with_refreshed_list();
    components.refresh(true);
    let mut out: Vec<pb::StateSensorTemperature> = components
        .iter()
        .filter_map(|c| {
            let name = c.label().trim();
            if name.is_empty() || name.eq_ignore_ascii_case("noname") || name == "PMU tcal" {
                return None;
            }
            let temp = c.temperature()?;
            if temp <= 0.0 {
                return None;
            }
            Some(pb::StateSensorTemperature {
                name: name.to_string(),
                temperature: temp as f64,
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// 对齐 gopsutil 常见虚拟化标识；读不到则空串。
pub fn detect_virtualization() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/1/cgroup") {
            let lower = text.to_lowercase();
            if lower.contains("docker") {
                return "docker".into();
            }
            if lower.contains("lxc") {
                return "lxc".into();
            }
        }
        let vendor = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")
            .unwrap_or_default()
            .to_lowercase();
        let product = std::fs::read_to_string("/sys/class/dmi/id/product_name")
            .unwrap_or_default()
            .to_lowercase();
        let blob = format!("{vendor} {product}");
        if let Some(kind) = virt_from_dmi(&blob) {
            return kind.into();
        }
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo")
            && cpuinfo.lines().any(|l| {
                let l = l.to_lowercase();
                l.starts_with("flags") && l.contains("hypervisor")
            })
        {
            return "hypervisor".into();
        }
    }
    String::new()
}

fn virt_from_dmi(blob: &str) -> Option<&'static str> {
    if blob.contains("kvm") || blob.contains("qemu") || blob.contains("bochs") {
        Some("kvm")
    } else if blob.contains("vmware") {
        Some("vmware")
    } else if blob.contains("xen") {
        Some("xen")
    } else if blob.contains("microsoft") || blob.contains("hyper-v") {
        Some("microsoft")
    } else if blob.contains("virtualbox") || blob.contains("innotek") {
        Some("virtualbox")
    } else if blob.contains("parallels") {
        Some("parallels")
    } else if blob.contains("bhyve") {
        Some("bhyve")
    } else if blob.contains("amazon") {
        Some("amazon")
    } else if blob.contains("google") {
        Some("google")
    } else if blob.contains("openstack") {
        Some("openstack")
    } else {
        None
    }
}

/// Linux 取 /etc/os-release 的 ID（面板按 distro id 匹配系统图标）。
fn os_id() -> String {
    #[cfg(target_os = "linux")]
    if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("ID=") {
                return v.trim().trim_matches('"').to_lowercase();
            }
        }
    }
    System::name()
        .map(|n| {
            n.split_whitespace()
                .next()
                .unwrap_or_default()
                .to_lowercase()
        })
        .unwrap_or_default()
}

/// Linux 读 /proc/net/sockstat{,6} 的 inuse；其余平台 MVP 先给 0。
#[cfg(target_os = "linux")]
fn sockstat_counts() -> (u64, u64) {
    fn inuse(path: &str, prefix: &str) -> u64 {
        let Ok(text) = std::fs::read_to_string(path) else {
            return 0;
        };
        text.lines()
            .find(|l| l.starts_with(prefix))
            .and_then(|l| l.split_whitespace().nth(2))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }
    let tcp = inuse("/proc/net/sockstat", "TCP:") + inuse("/proc/net/sockstat6", "TCP6:");
    let udp = inuse("/proc/net/sockstat", "UDP:") + inuse("/proc/net/sockstat6", "UDP6:");
    (tcp, udp)
}

#[cfg(not(target_os = "linux"))]
fn sockstat_counts() -> (u64, u64) {
    (0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_state_sane() {
        let mut m = Monitor::new();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        let caps = CapabilityConfig::default();
        let s = m.collect_state(&caps);
        assert!(s.cpu >= 0.0, "cpu={}", s.cpu);
        assert!(s.mem_used > 0, "mem_used 不应为 0");
        assert!(s.uptime > 0, "uptime 不应为 0");
        assert!(s.process_count > 0, "process_count 不应为 0");
        // 第二帧起速率按差分得出，不为负即可（u64 天然非负，主要验证不 panic）。
        let s2 = m.collect_state(&caps);
        let _ = (s2.net_in_speed, s2.net_out_speed);
    }

    #[test]
    fn virt_from_dmi_kvm() {
        assert_eq!(virt_from_dmi("qemu"), Some("kvm"));
        assert_eq!(virt_from_dmi("vmware, inc."), Some("vmware"));
        assert_eq!(virt_from_dmi("physical box"), None);
    }

    #[test]
    fn nic_allowlist_replaces_default_excludes() {
        let empty: Vec<String> = Vec::new();
        // 空 allowlist 走内置前缀排除
        assert!(nic_included("eth0", &empty));
        assert!(!nic_included("docker0", &empty));
        assert!(!nic_included("lo", &empty));
        // 非空 allowlist 精确匹配，取代内置排除
        let allow = vec!["eth0".to_string(), "tun0".to_string()];
        assert!(nic_included("eth0", &allow));
        assert!(nic_included("tun0", &allow), "白名单可放行默认排除的接口");
        assert!(!nic_included("ens3", &allow));
        assert!(!nic_included("eth", &allow), "精确匹配，不是前缀");
    }

    #[test]
    fn partition_allowlist_replaces_fs_allowlist() {
        let empty: Vec<String> = Vec::new();
        // 空 allowlist 走内置 fs 白名单 + kubelet 排除
        assert!(partition_included("/", "ext4", &empty));
        assert!(!partition_included("/boot", "tmpfs", &empty));
        assert!(!partition_included("/var/lib/kubelet/pods", "ext4", &empty));
        // 非空 allowlist 精确匹配挂载点，fs 类型不再过滤
        let allow = vec!["/data".to_string()];
        assert!(partition_included("/data", "tmpfs", &allow));
        assert!(!partition_included("/", "ext4", &allow));
        assert!(
            !partition_included("/data/sub", "ext4", &allow),
            "精确匹配挂载点"
        );
    }

    #[test]
    fn collect_host_sane() {
        let mut m = Monitor::new();
        let h = m.host("1.2.3.4", "cn", "0.1.0", &CapabilityConfig::default());
        assert!(h.mem_total > 0);
        assert!(h.disk_total > 0, "磁盘白名单与 / 回退都落空");
        assert!(!h.cpu.is_empty(), "CPU 型号为空");
        assert!(h.boot_time > 0);
        assert!(!h.platform.is_empty());
    }
}

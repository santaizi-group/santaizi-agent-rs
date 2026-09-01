use crate::pb;
use std::time::Instant;
use sysinfo::{Disks, Networks, ProcessesToUpdate, System};

/// 与 Go 探针一致的内置网卡排除前缀（santaizi-agent/pkg/monitor）。
const NIC_EXCLUDE_PREFIXES: &[&str] =
    &["lo", "tun", "docker", "veth", "br-", "vmbr", "vnet", "kube"];
/// 与 Go 探针一致的文件系统白名单。
const FS_ALLOWLIST: &[&str] = &[
    "apfs", "ext2", "ext3", "ext4", "f2fs", "reiserfs", "jfs", "jfs2", "btrfs", "fuseblk", "zfs",
    "simfs", "ntfs", "fat32", "exfat", "xfs", "hfs", "ufs",
];
const MOUNT_EXCLUDE_PREFIXES: &[&str] = &["/var/lib/kubelet"];

pub struct Monitor {
    sys: System,
    disks: Disks,
    networks: Networks,
    /// 上次网卡累计值，用于差分算速率。
    last_net: Option<(Instant, u64, u64)>,
    boot_time: u64,
}

impl Monitor {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self {
            sys,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            last_net: None,
            boot_time: System::boot_time(),
        }
    }

    /// 返回 (used, total)。
    fn disk_usage(&mut self) -> (u64, u64) {
        self.disks.refresh(true);
        let mut total = 0u64;
        let mut used = 0u64;
        for d in self.disks.iter() {
            let fs = d.file_system().to_string_lossy().to_lowercase();
            let mount = d.mount_point().to_string_lossy();
            if !FS_ALLOWLIST.contains(&fs.as_str()) {
                continue;
            }
            if MOUNT_EXCLUDE_PREFIXES.iter().any(|p| mount.starts_with(p)) {
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

    pub fn host(&mut self, ip: &str, country_code: &str, version: &str) -> pb::Host {
        let (_, disk_total) = self.disk_usage();
        let cpu_model = self
            .sys
            .cpus()
            .first()
            .map(|c| c.brand().trim().to_string())
            .unwrap_or_default();
        let cores = self.sys.cpus().len();
        let cpu = if cpu_model.is_empty() {
            Vec::new()
        } else {
            vec![format!("{cpu_model} {cores} Core")]
        };
        pb::Host {
            platform: os_id(),
            platform_version: System::os_version().unwrap_or_default(),
            cpu,
            mem_total: self.sys.total_memory(),
            disk_total,
            swap_total: self.sys.total_swap(),
            arch: System::cpu_arch(),
            virtualization: String::new(),
            boot_time: self.boot_time,
            ip: ip.to_string(),
            country_code: country_code.to_string(),
            version: version.to_string(),
            gpu: Vec::new(),
        }
    }

    pub fn collect_state(&mut self) -> pb::State {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        let load = System::load_average();
        let (disk_used, _) = self.disk_usage();

        self.networks.refresh(true);
        let mut rx_total = 0u64;
        let mut tx_total = 0u64;
        for (name, data) in self.networks.iter() {
            if NIC_EXCLUDE_PREFIXES.iter().any(|p| name.starts_with(p)) {
                continue;
            }
            rx_total += data.total_received();
            tx_total += data.total_transmitted();
        }
        let now = Instant::now();
        let mut in_speed = 0u64;
        let mut out_speed = 0u64;
        if let Some((prev_at, prev_rx, prev_tx)) = self.last_net.replace((now, rx_total, tx_total))
        {
            let secs = now.duration_since(prev_at).as_secs_f64();
            if secs > 0.0 {
                in_speed = (rx_total.saturating_sub(prev_rx) as f64 / secs) as u64;
                out_speed = (tx_total.saturating_sub(prev_tx) as f64 / secs) as u64;
            }
        }

        let (tcp, udp) = sockstat_counts();
        pb::State {
            cpu: self.sys.global_cpu_usage() as f64,
            // Go 口径：used = Total - Available。
            mem_used: self
                .sys
                .total_memory()
                .saturating_sub(self.sys.available_memory()),
            swap_used: self.sys.used_swap(),
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
            process_count: self.sys.processes().len() as u64,
            temperatures: Vec::new(),
            gpu: 0.0,
        }
    }
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
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
        let s = m.collect_state();
        assert!(s.cpu >= 0.0, "cpu={}", s.cpu);
        assert!(s.mem_used > 0, "mem_used 不应为 0");
        assert!(s.uptime > 0, "uptime 不应为 0");
        assert!(s.process_count > 0, "process_count 不应为 0");
        // 第二帧起速率按差分得出，不为负即可（u64 天然非负，主要验证不 panic）。
        let s2 = m.collect_state();
        let _ = (s2.net_in_speed, s2.net_out_speed);
    }

    #[test]
    fn collect_host_sane() {
        let mut m = Monitor::new();
        let h = m.host("1.2.3.4", "cn", "0.1.0");
        assert!(h.mem_total > 0);
        assert!(h.disk_total > 0, "磁盘白名单与 / 回退都落空");
        assert!(!h.cpu.is_empty(), "CPU 型号为空");
        assert!(h.boot_time > 0);
        assert!(!h.platform.is_empty());
    }
}

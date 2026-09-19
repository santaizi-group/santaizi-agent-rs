use anyhow::{Context, Result, bail};
use std::path::Path;

/// v2 节点身份：16 字节随机 ID 持久化在 <data_dir>/identity（对齐 Go pkg/identity）。
pub fn load_or_create(data_dir: &str) -> Result<[u8; 16]> {
    let dir = Path::new(data_dir);
    let path = dir.join("identity");
    match std::fs::read(&path) {
        Ok(bytes) => {
            let id: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("{} 长度 {} 字节，应为 16", path.display(), bytes.len())
            })?;
            Ok(id)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("创建数据目录 {} 失败", dir.display()))?;
            let id: [u8; 16] = rand::random();
            // 创建即 0600：先写后 chmod 会留下 umask 默认权限窗口
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .with_context(|| format!("写入 {} 失败", path.display()))?;
                f.write_all(&id)
                    .with_context(|| format!("写入 {} 失败", path.display()))?;
            }
            #[cfg(not(unix))]
            std::fs::write(&path, id).with_context(|| format!("写入 {} 失败", path.display()))?;
            Ok(id)
        }
        Err(e) => Err(e).with_context(|| format!("读取 {} 失败", path.display())),
    }
}

/// 每次启动新的 16 字节会话 ID（对齐 Go：每进程一个 session）。
pub fn new_session_id() -> [u8; 16] {
    rand::random()
}

/// event_id = SHA256(node ‖ session ‖ seq 大端) 前 16 字节（对齐 Go session.Next）。
pub fn event_id(node: &[u8; 16], session: &[u8; 16], seq: u64) -> [u8; 16] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(node);
    h.update(session);
    h.update(seq.to_be_bytes());
    let digest = h.finalize();
    digest[..16].try_into().expect("sha256 输出 32 字节")
}

/// 压缩空洞 gap_id = SHA256(node ‖ session ‖ start ‖ end 大端) 前 16 字节。
pub fn compacted_gap_id(node: &[u8; 16], session: &[u8; 16], start: u64, end: u64) -> [u8; 16] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(node);
    h.update(session);
    h.update(start.to_be_bytes());
    h.update(end.to_be_bytes());
    let digest = h.finalize();
    digest[..16].try_into().expect("sha256 输出 32 字节")
}

pub fn validate_node_uuid(bytes: &[u8]) -> Result<()> {
    if bytes.len() != 16 {
        bail!("node_uuid 需为 16 字节");
    }
    Ok(())
}

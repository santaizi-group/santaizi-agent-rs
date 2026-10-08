//! NAT 流：校验、10 秒拨目标、面板帧与目标字节互转。状态机不依赖真网。

use crate::pb;
use anyhow::{Result, bail};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::StreamExt;

pub const FRAME_DATA_MAX: usize = 32 * 1024;
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// 拒绝原因与 Go 完全一致。`None` 表示可以拨号。
pub fn rejection(enabled: bool, req: &pb::NatOpenRequest, now_unix: i64) -> Option<&'static str> {
    if !enabled {
        return Some("NAT capability is disabled");
    }
    if req.stream_id.is_empty() {
        return Some("stream_id is required");
    }
    if req.target_host.trim().is_empty() || req.target_port == 0 || req.target_port > 65535 {
        return Some("NAT target requires a host and valid port");
    }
    if req.expires_at_unix != 0 && now_unix >= req.expires_at_unix {
        return Some("NAT request has expired");
    }
    None
}

pub fn open_frame(stream_id: &str) -> pb::NatFrame {
    pb::NatFrame {
        stream_id: stream_id.to_string(),
        kind: pb::NatFrameKind::Open as i32,
        data: Vec::new(),
        error: String::new(),
    }
}

pub async fn dial_target(host: &str, port: u32) -> Result<TcpStream> {
    let addr = join_host_port(host.trim(), port);
    match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(res) => res.map_err(|err| anyhow::anyhow!("dial {addr}: {err}")),
        Err(_) => bail!("dial {addr}: connection timed out"),
    }
}

fn join_host_port(host: &str, port: u32) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// 目标读到的数据最多 32KiB 一帧 DATA。EOF 发 CLOSE 且 error 为空；其他读错误发 ERROR。
/// 收方向 DATA 写入目标；CLOSE / ERROR / stream_id 不符拆流。
pub async fn relay<R, W, S, E>(
    stream_id: &str,
    mut reader: R,
    mut writer: W,
    outbound: mpsc::Sender<pb::NatFrame>,
    mut inbound: S,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    S: Stream<Item = std::result::Result<pb::NatFrame, E>> + Unpin,
    E: std::fmt::Display,
{
    let to_panel = async {
        let mut buf = vec![0u8; FRAME_DATA_MAX];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = outbound
                        .send(pb::NatFrame {
                            stream_id: stream_id.to_string(),
                            kind: pb::NatFrameKind::Close as i32,
                            data: Vec::new(),
                            error: String::new(),
                        })
                        .await;
                    return Ok(());
                }
                Ok(n) => {
                    outbound
                        .send(pb::NatFrame {
                            stream_id: stream_id.to_string(),
                            kind: pb::NatFrameKind::Data as i32,
                            data: buf[..n].to_vec(),
                            error: String::new(),
                        })
                        .await
                        .map_err(|_| anyhow::anyhow!("NAT outbound closed"))?;
                }
                Err(err) => {
                    let _ = outbound
                        .send(pb::NatFrame {
                            stream_id: stream_id.to_string(),
                            kind: pb::NatFrameKind::Error as i32,
                            data: Vec::new(),
                            error: err.to_string(),
                        })
                        .await;
                    return Err(anyhow::anyhow!(err));
                }
            }
        }
    };
    let from_panel = async {
        while let Some(item) = inbound.next().await {
            let frame = item.map_err(|err| anyhow::anyhow!("{err}"))?;
            if frame.stream_id != stream_id {
                bail!("NAT stream identifier mismatch");
            }
            let kind =
                pb::NatFrameKind::try_from(frame.kind).unwrap_or(pb::NatFrameKind::Unspecified);
            match kind {
                pb::NatFrameKind::Data => {
                    writer.write_all(&frame.data).await?;
                    writer.flush().await?;
                }
                pb::NatFrameKind::Close => return Ok(()),
                pb::NatFrameKind::Error => bail!("{}", frame.error),
                _ => bail!("unexpected NAT frame kind"),
            }
        }
        bail!("NAT stream closed")
    };
    tokio::pin!(to_panel);
    tokio::pin!(from_panel);
    tokio::select! {
        result = &mut to_panel => result,
        result = &mut from_panel => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::duplex;
    use tokio_stream::wrappers::ReceiverStream;

    fn req(stream_id: &str, host: &str, port: u32, expires: i64) -> pb::NatOpenRequest {
        pb::NatOpenRequest {
            stream_id: stream_id.into(),
            target_host: host.into(),
            target_port: port,
            expires_at_unix: expires,
        }
    }

    #[test]
    fn rejection_strings_match_go() {
        let now = 1_700_000_000;
        assert_eq!(
            rejection(false, &req("s", "10.0.0.1", 80, 0), now),
            Some("NAT capability is disabled")
        );
        assert_eq!(
            rejection(true, &req("", "10.0.0.1", 80, 0), now),
            Some("stream_id is required")
        );
        assert_eq!(
            rejection(true, &req("s", "  ", 80, 0), now),
            Some("NAT target requires a host and valid port")
        );
        assert_eq!(
            rejection(true, &req("s", "10.0.0.1", 0, 0), now),
            Some("NAT target requires a host and valid port")
        );
        assert_eq!(
            rejection(true, &req("s", "10.0.0.1", 65536, 0), now),
            Some("NAT target requires a host and valid port")
        );
        assert_eq!(
            rejection(true, &req("s", "10.0.0.1", 80, now), now),
            Some("NAT request has expired")
        );
        assert_eq!(rejection(true, &req("s", "10.0.0.1", 65535, 0), now), None);
        assert_eq!(
            rejection(true, &req("s", "10.0.0.1", 80, now + 5), now),
            None
        );
    }

    struct BoomRead;

    impl AsyncRead for BoomRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("boom")))
        }
    }

    struct NopWrite;

    impl AsyncWrite for NopWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn data_is_chunked_and_eof_closes() {
        let (client, mut peer) = duplex(64 * 1024);
        let (read, write) = tokio::io::split(client);
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let (_in_tx, in_rx) = mpsc::channel::<std::result::Result<pb::NatFrame, String>>(1);
        let inbound = ReceiverStream::new(in_rx);
        let relay_task =
            tokio::spawn(async move { relay("sid", read, write, out_tx, inbound).await });
        let payload = vec![7u8; FRAME_DATA_MAX + 100];
        peer.write_all(&payload).await.unwrap();
        let mut got = Vec::new();
        while got.len() < payload.len() {
            let frame = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(frame.stream_id, "sid");
            assert_eq!(frame.kind, pb::NatFrameKind::Data as i32);
            assert!(frame.data.len() <= FRAME_DATA_MAX);
            assert!(frame.error.is_empty());
            got.extend_from_slice(&frame.data);
        }
        assert_eq!(got, payload);
        drop(peer);
        let frame = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.kind, pb::NatFrameKind::Close as i32);
        assert!(frame.error.is_empty());
        assert!(frame.data.is_empty());
        relay_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn read_error_sends_error_frame() {
        let (out_tx, mut out_rx) = mpsc::channel(2);
        let (_in_tx, in_rx) = mpsc::channel::<std::result::Result<pb::NatFrame, String>>(1);
        let inbound = ReceiverStream::new(in_rx);
        let err = relay("sid", BoomRead, NopWrite, out_tx, inbound)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("boom"), "{err}");
        let frame = out_rx.recv().await.unwrap();
        assert_eq!(frame.kind, pb::NatFrameKind::Error as i32);
        assert_eq!(frame.error, "boom");
    }

    #[tokio::test]
    async fn inbound_data_close_and_mismatch() {
        let (client, mut peer) = duplex(1024);
        let (read, write) = tokio::io::split(client);
        let (out_tx, _out_rx) = mpsc::channel::<pb::NatFrame>(2);
        let (in_tx, in_rx) = mpsc::channel::<std::result::Result<pb::NatFrame, String>>(4);
        let inbound = ReceiverStream::new(in_rx);
        let task = tokio::spawn(async move { relay("sid", read, write, out_tx, inbound).await });
        in_tx
            .send(Ok(pb::NatFrame {
                stream_id: "sid".into(),
                kind: pb::NatFrameKind::Data as i32,
                data: b"hi".to_vec(),
                error: String::new(),
            }))
            .await
            .unwrap();
        let mut buf = [0u8; 2];
        peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
        in_tx
            .send(Ok(pb::NatFrame {
                stream_id: "sid".into(),
                kind: pb::NatFrameKind::Close as i32,
                data: Vec::new(),
                error: String::new(),
            }))
            .await
            .unwrap();
        task.await.unwrap().unwrap();

        let (client, _peer) = duplex(64);
        let (read, write) = tokio::io::split(client);
        let (out_tx, _out_rx) = mpsc::channel(2);
        let (in_tx, in_rx) = mpsc::channel::<std::result::Result<pb::NatFrame, String>>(1);
        let inbound = ReceiverStream::new(in_rx);
        let task = tokio::spawn(async move { relay("sid", read, write, out_tx, inbound).await });
        in_tx
            .send(Ok(pb::NatFrame {
                stream_id: "other".into(),
                kind: pb::NatFrameKind::Data as i32,
                data: b"x".to_vec(),
                error: String::new(),
            }))
            .await
            .unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err.to_string(), "NAT stream identifier mismatch");
    }
}

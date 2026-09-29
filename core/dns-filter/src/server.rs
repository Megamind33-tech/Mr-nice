//! UDP and TCP listeners.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::engine::{FilterEngine, Transport};

/// Upper bound on concurrently handled queries per listener, so a flood
/// cannot exhaust memory or sockets.
const MAX_IN_FLIGHT: usize = 1024;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve DNS over UDP until the task is cancelled.
pub async fn run_udp(engine: Arc<FilterEngine>, socket: UdpSocket) -> io::Result<()> {
    let socket = Arc::new(socket);
    let limit = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            // Windows reports ICMP port-unreachable for an earlier send as
            // WSAECONNRESET on the next receive; it is not fatal.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(e) => {
                tracing::warn!(error = %e, "udp receive failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            tracing::warn!("dropping udp query: too many in flight");
            continue;
        };
        let packet = buf[..n].to_vec();
        let engine = engine.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            if let Some(resp) = engine.handle(&packet, Transport::Udp).await {
                if let Err(e) = socket.send_to(&resp, peer).await {
                    tracing::debug!(error = %e, %peer, "udp send failed");
                }
            }
            drop(permit);
        });
    }
}

/// Serve DNS over TCP (RFC 7766 framing) until the task is cancelled.
pub async fn run_tcp(engine: Arc<FilterEngine>, listener: TcpListener) -> io::Result<()> {
    let limit = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "tcp accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let engine = engine.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_tcp_conn(engine, stream).await {
                tracing::debug!(error = %e, %peer, "tcp connection ended");
            }
            drop(permit);
        });
    }
}

async fn serve_tcp_conn(engine: Arc<FilterEngine>, mut stream: TcpStream) -> io::Result<()> {
    loop {
        let len = match timeout(TCP_IDLE_TIMEOUT, stream.read_u16()).await {
            Ok(Ok(len)) => len as usize,
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()),
        };
        let mut packet = vec![0u8; len];
        timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut packet))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp read timed out"))??;
        let Some(resp) = engine.handle(&packet, Transport::Tcp).await else {
            continue;
        };
        let resp_len = u16::try_from(resp.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response too large"))?;
        let mut framed = Vec::with_capacity(resp.len() + 2);
        framed.extend_from_slice(&resp_len.to_be_bytes());
        framed.extend_from_slice(&resp);
        stream.write_all(&framed).await?;
    }
}

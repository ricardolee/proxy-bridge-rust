use anyhow::Result;
use log::{debug, info};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};

use proxy_bridge_core::config::*;
use proxy_bridge_core::connection::ConnectionTracker;
use proxy_bridge_core::proxy::socks5;

/// Run the UDP relay server for SOCKS5 UDP ASSOCIATE.
pub async fn run_udp_relay(
    port: u16,
    proxy_config: Arc<ProxyConfig>,
    conn_tracker: Arc<ConnectionTracker>,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
    info!("UDP relay listening on 0.0.0.0:{}", port);

    let mut _control_sock: Option<TcpStream> = None;
    let mut send_sock: Option<UdpSocket> = None;
    let mut relay_addr: Option<SocketAddr> = None;

    let mut buf = [0u8; 65536];

    while running.load(Ordering::Relaxed) {
        // Try to establish UDP ASSOCIATE if not connected
        if relay_addr.is_none() {
            match establish_udp_associate(&proxy_config).await {
                Ok((ctrl, snd, addr)) => {
                    _control_sock = Some(ctrl);
                    send_sock = Some(snd);
                    relay_addr = Some(addr);
                    info!("UDP ASSOCIATE established with SOCKS5 proxy");
                }
                Err(e) => {
                    debug!("UDP ASSOCIATE failed (will retry): {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            }
        }

        // Receive from local clients
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(1),
            socket.recv_from(&mut buf),
        )
        .await;

        match result {
            Ok(Ok((len, from_addr))) => {
                let client_port = from_addr.port();
                if let Some((dest_ip, dest_port)) = conn_tracker.get(client_port) {
                    let packet = socks5::build_socks5_udp_packet(dest_ip, dest_port, &buf[..len]);
                    if let (Some(ref snd), Some(ref addr)) = (&send_sock, &relay_addr) {
                        if snd.send_to(&packet, addr).await.is_err() {
                            relay_addr = None; // reset on error
                        }
                    }
                }
            }
            Ok(Err(e)) => debug!("UDP relay recv error: {}", e),
            Err(_) => {} // timeout, continue loop
        }

        // Receive from proxy (if connected)
        if let Some(ref snd) = send_sock {
            if let Ok(Ok((len, _))) = tokio::time::timeout(
                tokio::time::Duration::from_millis(10),
                snd.recv_from(&mut buf),
            )
            .await
            {
                if let Some((src_ip, src_port, data_offset)) =
                    socks5::parse_socks5_udp_packet(&buf[..len])
                {
                    if let Some(client_port) = conn_tracker.find_by_dest(src_ip, src_port) {
                        let client_addr: SocketAddr =
                            format!("127.0.0.1:{}", client_port).parse().unwrap();
                        let _ = socket.send_to(&buf[data_offset..len], client_addr).await;
                    }
                }
            }
        }
    }

    info!("UDP relay stopped");
    Ok(())
}

async fn establish_udp_associate(
    proxy_config: &ProxyConfig,
) -> Result<(TcpStream, UdpSocket, SocketAddr)> {
    let proxy_ip = proxy_config
        .resolved_ip
        .ok_or_else(|| anyhow::anyhow!("Proxy IP not resolved"))?;

    let proxy_addr = std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::from(proxy_ip.to_ne_bytes()),
        proxy_config.port,
    );

    let mut tcp_stream = TcpStream::connect(std::net::SocketAddr::V4(proxy_addr)).await?;

    let (relay_ip, relay_port) = socks5::socks5_udp_associate(
        &mut tcp_stream,
        proxy_config.username.as_deref(),
        proxy_config.password.as_deref(),
    )
    .await?;

    // If server returns 0.0.0.0, use proxy's IP
    let actual_ip = if relay_ip == 0 { proxy_ip } else { relay_ip };

    let relay_addr = SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::from(actual_ip.to_ne_bytes()),
        relay_port,
    ));

    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;

    Ok((tcp_stream, udp_socket, relay_addr))
}

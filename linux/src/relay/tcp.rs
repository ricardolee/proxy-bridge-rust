use anyhow::Result;
use log::{debug, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

use proxy_bridge_core::config::*;
use proxy_bridge_core::connection::ConnectionTracker;
use proxy_bridge_core::proxy::{http, socks5};

/// Run the TCP relay server on the specified port.
/// Accepts connections redirected by nftables NAT and forwards them through the proxy.
pub async fn run_tcp_relay(
    port: u16,
    proxy_config: Arc<ProxyConfig>,
    conn_tracker: Arc<ConnectionTracker>,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("TCP relay listening on 0.0.0.0:{}", port);

    loop {
        if !running.load(Ordering::Relaxed) {
            break;
        }

        let (client_stream, client_addr) = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!("TCP relay accept error: {}", e);
                        continue;
                    }
                }
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                continue;
            }
        };

        let client_port = client_addr.port();

        // Look up original destination from connection tracker
        let (dest_ip, dest_port) = match conn_tracker.get(client_port) {
            Some(dest) => dest,
            None => {
                debug!("TCP relay: no tracked connection for port {}", client_port);
                continue;
            }
        };

        let proxy_cfg = proxy_config.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_tcp_connection(client_stream, dest_ip, dest_port, &proxy_cfg).await
            {
                debug!("TCP relay connection error: {}", e);
            }
        });
    }

    info!("TCP relay stopped");
    Ok(())
}

/// Handle a single TCP connection: connect to proxy, handshake, then relay data
async fn handle_tcp_connection(
    mut client: TcpStream,
    dest_ip: u32,
    dest_port: u16,
    proxy_config: &ProxyConfig,
) -> Result<()> {
    let proxy_ip = proxy_config.resolved_ip.ok_or_else(|| {
        anyhow::anyhow!("Proxy IP not resolved")
    })?;

    // Connect to proxy server
    let proxy_addr = std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::from(proxy_ip.to_ne_bytes()),
        proxy_config.port,
    );

    let mut proxy_stream =
        TcpStream::connect(std::net::SocketAddr::V4(proxy_addr)).await?;

    // Perform proxy handshake
    match proxy_config.proxy_type {
        ProxyType::Socks5 => {
            socks5::socks5_connect(
                &mut proxy_stream,
                dest_ip,
                dest_port,
                proxy_config.username.as_deref(),
                proxy_config.password.as_deref(),
            )
            .await?;
        }
        ProxyType::Http => {
            http::http_connect(
                &mut proxy_stream,
                dest_ip,
                dest_port,
                proxy_config.username.as_deref(),
                proxy_config.password.as_deref(),
            )
            .await?;
        }
    }

    // Bidirectional relay
    let _ = tokio::io::copy_bidirectional(&mut client, &mut proxy_stream).await;

    Ok(())
}

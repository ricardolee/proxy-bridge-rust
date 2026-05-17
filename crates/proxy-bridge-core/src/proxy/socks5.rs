use crate::config::*;
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Perform SOCKS5 CONNECT handshake over an established TCP connection.
/// After success, the stream is ready for bidirectional data transfer.
pub async fn socks5_connect(
    stream: &mut TcpStream,
    dest_ip: u32,
    dest_port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    let use_auth = username.is_some() && password.is_some();

    // --- Method negotiation ---
    let mut buf = Vec::with_capacity(4);
    buf.push(SOCKS5_VERSION);
    if use_auth {
        buf.push(0x02); // 2 methods
        buf.push(SOCKS5_AUTH_NONE);
        buf.push(SOCKS5_AUTH_PASSWORD);
    } else {
        buf.push(0x01); // 1 method
        buf.push(SOCKS5_AUTH_NONE);
    }
    stream
        .write_all(&buf)
        .await
        .context("socks5: failed to send auth methods")?;

    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .context("socks5: failed to read auth response")?;

    if resp[0] != SOCKS5_VERSION {
        bail!("socks5: invalid version in auth response: {}", resp[0]);
    }

    // --- Authentication ---
    if resp[1] == SOCKS5_AUTH_PASSWORD && use_auth {
        let user = username.unwrap();
        let pass = password.unwrap();

        let mut auth_buf = Vec::with_capacity(3 + user.len() + pass.len());
        auth_buf.push(0x01); // auth version
        auth_buf.push(user.len() as u8);
        auth_buf.extend_from_slice(user.as_bytes());
        auth_buf.push(pass.len() as u8);
        auth_buf.extend_from_slice(pass.as_bytes());

        stream
            .write_all(&auth_buf)
            .await
            .context("socks5: failed to send credentials")?;

        let mut auth_resp = [0u8; 2];
        stream
            .read_exact(&mut auth_resp)
            .await
            .context("socks5: failed to read auth result")?;

        if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
            bail!("socks5: authentication failed");
        }
    } else if resp[1] != SOCKS5_AUTH_NONE {
        bail!("socks5: unsupported auth method: {}", resp[1]);
    }

    // --- CONNECT request ---
    let mut connect_buf = [0u8; 10];
    connect_buf[0] = SOCKS5_VERSION;
    connect_buf[1] = SOCKS5_CMD_CONNECT;
    connect_buf[2] = 0x00; // reserved
    connect_buf[3] = SOCKS5_ATYP_IPV4;
    connect_buf[4..8].copy_from_slice(&dest_ip.to_ne_bytes());
    connect_buf[8..10].copy_from_slice(&dest_port.to_be_bytes());

    stream
        .write_all(&connect_buf)
        .await
        .context("socks5: failed to send connect request")?;

    let mut connect_resp = [0u8; 10];
    stream
        .read_exact(&mut connect_resp)
        .await
        .context("socks5: failed to read connect response")?;

    if connect_resp[0] != SOCKS5_VERSION {
        bail!("socks5: invalid version in connect response");
    }
    if connect_resp[1] != 0x00 {
        bail!("socks5: connect failed with status {}", connect_resp[1]);
    }

    Ok(())
}

/// Perform SOCKS5 UDP ASSOCIATE handshake.
/// Returns the relay address (ip, port) that the proxy allocated for UDP forwarding.
pub async fn socks5_udp_associate(
    stream: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(u32, u16)> {
    let use_auth = username.is_some() && password.is_some();

    // --- Method negotiation (same as CONNECT) ---
    let mut buf = Vec::with_capacity(4);
    buf.push(SOCKS5_VERSION);
    if use_auth {
        buf.push(0x02);
        buf.push(SOCKS5_AUTH_NONE);
        buf.push(SOCKS5_AUTH_PASSWORD);
    } else {
        buf.push(0x01);
        buf.push(SOCKS5_AUTH_NONE);
    }
    stream.write_all(&buf).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != SOCKS5_VERSION {
        bail!("socks5 udp: invalid version");
    }

    if resp[1] == SOCKS5_AUTH_PASSWORD && use_auth {
        let user = username.unwrap();
        let pass = password.unwrap();
        let mut auth_buf = Vec::with_capacity(3 + user.len() + pass.len());
        auth_buf.push(0x01);
        auth_buf.push(user.len() as u8);
        auth_buf.extend_from_slice(user.as_bytes());
        auth_buf.push(pass.len() as u8);
        auth_buf.extend_from_slice(pass.as_bytes());
        stream.write_all(&auth_buf).await?;

        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).await?;
        if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
            bail!("socks5 udp: authentication failed");
        }
    } else if resp[1] != SOCKS5_AUTH_NONE {
        bail!("socks5 udp: unsupported auth method");
    }

    // --- UDP ASSOCIATE request ---
    let associate_buf = [
        SOCKS5_VERSION,
        SOCKS5_CMD_UDP_ASSOCIATE,
        0x00,              // reserved
        SOCKS5_ATYP_IPV4,
        0, 0, 0, 0, // 0.0.0.0
        0, 0,       // port 0
    ];
    stream.write_all(&associate_buf).await?;

    let mut associate_resp = [0u8; 10];
    stream.read_exact(&mut associate_resp).await?;

    if associate_resp[0] != SOCKS5_VERSION || associate_resp[1] != 0x00 {
        bail!(
            "socks5 udp: associate failed with status {}",
            associate_resp[1]
        );
    }

    if associate_resp[3] != SOCKS5_ATYP_IPV4 {
        bail!("socks5 udp: unsupported address type in associate response");
    }

    let relay_ip = u32::from_ne_bytes(associate_resp[4..8].try_into().unwrap());
    let relay_port = u16::from_be_bytes(associate_resp[8..10].try_into().unwrap());

    Ok((relay_ip, relay_port))
}

/// Build a SOCKS5 UDP packet header + data for forwarding
pub fn build_socks5_udp_packet(dest_ip: u32, dest_port: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(10 + data.len());
    packet.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, RSV, FRAG
    packet.push(SOCKS5_ATYP_IPV4);
    packet.extend_from_slice(&dest_ip.to_ne_bytes());
    packet.extend_from_slice(&dest_port.to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

/// Parse a SOCKS5 UDP response packet, returns (source_ip, source_port, data_offset)
pub fn parse_socks5_udp_packet(packet: &[u8]) -> Option<(u32, u16, usize)> {
    if packet.len() < 10 {
        return None;
    }
    // Check fragment (must be 0, we don't support fragmentation)
    if packet[2] != 0x00 {
        return None;
    }
    if packet[3] != SOCKS5_ATYP_IPV4 {
        return None;
    }

    let src_ip = u32::from_ne_bytes(packet[4..8].try_into().ok()?);
    let src_port = u16::from_be_bytes(packet[8..10].try_into().ok()?);
    Some((src_ip, src_port, 10))
}

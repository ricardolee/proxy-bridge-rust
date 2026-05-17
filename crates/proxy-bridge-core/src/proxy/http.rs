use crate::rule::format_ip;
use anyhow::{bail, Context, Result};
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Perform HTTP CONNECT handshake over an established TCP connection.
/// After success, the stream is ready for bidirectional data transfer.
pub async fn http_connect(
    stream: &mut TcpStream,
    dest_ip: u32,
    dest_port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    let dest_ip_str = format_ip(dest_ip);

    let mut request = format!(
        "CONNECT {}:{} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         Proxy-Connection: Keep-Alive\r\n",
        dest_ip_str, dest_port, dest_ip_str, dest_port
    );

    // Add authentication header if credentials provided
    if let (Some(user), Some(pass)) = (username, password) {
        let credentials = format!("{}:{}", user, pass);
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
    }

    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .await
        .context("http connect: failed to send request")?;

    // Read response (at least "HTTP/1.x 200")
    let mut buf = [0u8; 1024];
    let n = stream
        .read(&mut buf)
        .await
        .context("http connect: failed to read response")?;

    if n < 12 {
        bail!("http connect: response too short ({} bytes)", n);
    }

    let response = String::from_utf8_lossy(&buf[..n]);

    if !response.starts_with("HTTP/1.") {
        bail!("http connect: invalid response");
    }

    // Parse status code
    let status_code: u16 = response
        .get(9..12)
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    if status_code != 200 {
        bail!("http connect: failed with status {}", status_code);
    }

    Ok(())
}

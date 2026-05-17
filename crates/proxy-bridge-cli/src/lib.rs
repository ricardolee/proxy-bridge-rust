use anyhow::{bail, Result};
use clap::Parser;
use proxy_bridge_core::config::ProxyType;

pub const VERSION: &str = "0.1.0";

/// ProxyBridge CLI arguments (cross-platform)
#[derive(Parser, Debug)]
#[command(
    name = "proxy-bridge",
    about = "Process-level transparent proxy for Linux applications",
    version = VERSION,
    after_help = "EXAMPLES:\n  \
        # Basic usage with default proxy\n  \
        sudo proxy-bridge --rule curl:*:*:TCP:PROXY\n\n  \
        # Multiple rules with custom proxy\n  \
        sudo proxy-bridge --proxy socks5://192.168.1.10:1080 \\\n       \
        --rule curl:*:*:TCP:PROXY \\\n       \
        --rule wget:*:*:TCP:PROXY \\\n       \
        --verbose 2\n\n  \
        # Route DNS through proxy with multiple apps\n  \
        sudo proxy-bridge --proxy socks5://127.0.0.1:1080 \\\n       \
        --rule \"curl;wget;firefox:*:*:BOTH:PROXY\" \\\n       \
        --dns-via-proxy true --verbose 3\n\n\
        NOTE: ProxyBridge requires root privileges to use nfqueue.\n  \
        Run with 'sudo' or as root user."
)]
pub struct CliArgs {
    /// Proxy server URL: type://ip:port or type://ip:port:username:password
    /// Examples: socks5://127.0.0.1:1080, http://proxy.com:8080:user:pass
    #[arg(long, default_value = "socks5://127.0.0.1:4444")]
    pub proxy: String,

    /// Traffic routing rule (can be specified multiple times)
    /// Format: process:hosts:ports:protocol:action
    #[arg(long, action = clap::ArgAction::Append)]
    pub rule: Vec<String>,

    /// Route DNS queries through proxy
    #[arg(long, default_value = "true")]
    pub dns_via_proxy: bool,

    /// Logging verbosity: 0=none, 1=logs, 2=connections, 3=both
    #[arg(long, default_value = "0")]
    pub verbose: u8,

    /// Cleanup resources from a previous crashed instance
    #[arg(long)]
    pub cleanup: bool,
}

/// Parsed proxy URL components
#[derive(Debug)]
pub struct ParsedProxy {
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Parse a proxy URL like "socks5://127.0.0.1:1080" or "http://host:port:user:pass"
pub fn parse_proxy_url(url: &str) -> Result<ParsedProxy> {
    let scheme_end = url
        .find("://")
        .ok_or_else(|| anyhow::anyhow!("Invalid proxy URL format. Expected type://host:port"))?;

    let scheme = &url[..scheme_end];
    let rest = &url[scheme_end + 3..];

    let proxy_type = match scheme.to_uppercase().as_str() {
        "SOCKS5" => ProxyType::Socks5,
        "HTTP" => ProxyType::Http,
        other => bail!("Invalid proxy type '{}'. Use 'socks5' or 'http'", other),
    };

    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() < 2 {
        bail!("Invalid proxy URL. Missing host or port");
    }

    let host = parts[0].to_string();
    let port: u16 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid proxy port '{}'", parts[1]))?;

    if port == 0 {
        bail!("Invalid proxy port '0'");
    }

    let (username, password) = if parts.len() >= 4 {
        (
            Some(parts[2].to_string()),
            Some(parts[3].to_string()),
        )
    } else {
        (None, None)
    };

    Ok(ParsedProxy {
        proxy_type,
        host,
        port,
        username,
        password,
    })
}

/// Print the ProxyBridge ASCII banner
pub fn show_banner() {
    println!();
    println!(r"  ____                        ____       _     _            ");
    println!(r" |  _ \ _ __ _____  ___   _  | __ ) _ __(_) __| | __ _  ___ ");
    println!(r" | |_) | '__/ _ \ \/ / | | | |  _ \| '__| |/ _` |/ _` |/ _ \");
    println!(r" |  __/| | | (_) >  <| |_| | | |_) | |  | | (_| | (_| |  __/");
    println!(r" |_|   |_|  \___/_/\_\\__, | |____/|_|  |_|\__,_|\__, |\___|");
    println!(r"                      |___/                      |___/  V{}", VERSION);
    println!();
    println!("  Process-level transparent proxy for Linux applications");
    println!();
    println!("\tRust implementation");
    println!("\tGitHub: https://github.com/InterceptSuite/ProxyBridge");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proxy_url_socks5() {
        let parsed = parse_proxy_url("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(parsed.proxy_type, ProxyType::Socks5);
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 1080);
        assert!(parsed.username.is_none());
    }

    #[test]
    fn test_parse_proxy_url_http_with_auth() {
        let parsed = parse_proxy_url("http://proxy.com:8080:user:pass").unwrap();
        assert_eq!(parsed.proxy_type, ProxyType::Http);
        assert_eq!(parsed.host, "proxy.com");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.username.as_deref(), Some("user"));
        assert_eq!(parsed.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_parse_proxy_url_invalid() {
        assert!(parse_proxy_url("invalid").is_err());
        assert!(parse_proxy_url("ftp://host:80").is_err());
    }
}

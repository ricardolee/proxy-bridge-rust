/// TCP relay local port (iptables/nftables redirects marked TCP packets here)
pub const LOCAL_PROXY_PORT: u16 = 34010;

/// UDP relay local port (iptables/nftables redirects marked UDP packets here)
pub const LOCAL_UDP_RELAY_PORT: u16 = 34011;

/// NFQUEUE queue number
pub const NFQUEUE_NUM: u16 = 0;

/// Packet mark for TCP traffic to be proxied
pub const TCP_MARK: u32 = 1;

/// Packet mark for UDP traffic to be proxied
pub const UDP_MARK: u32 = 2;

/// PID cache time-to-live in milliseconds
pub const PID_CACHE_TTL_MS: u64 = 10_000;

/// Stale connection timeout in milliseconds
pub const CONNECTION_TIMEOUT_MS: u64 = 60_000;

/// Stale connection cleanup interval in seconds
pub const CLEANUP_INTERVAL_SECS: u64 = 30;

/// SOCKS5 protocol constants
pub const SOCKS5_VERSION: u8 = 0x05;
pub const SOCKS5_AUTH_NONE: u8 = 0x00;
pub const SOCKS5_AUTH_PASSWORD: u8 = 0x02;
pub const SOCKS5_CMD_CONNECT: u8 = 0x01;
pub const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const SOCKS5_ATYP_IPV4: u8 = 0x01;

/// Proxy type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyType {
    Http,
    Socks5,
}

/// Rule action: what to do with matching traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Forward through proxy
    Proxy,
    /// Allow direct connection
    Direct,
    /// Drop the packet
    Block,
}

/// Rule protocol filter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProtocol {
    Tcp,
    Udp,
    Both,
}

/// Proxy server configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Cached resolved IP address (network byte order)
    pub resolved_ip: Option<u32>,
}

impl ProxyConfig {
    pub fn new(proxy_type: ProxyType, host: String, port: u16) -> Self {
        Self {
            proxy_type,
            host,
            port,
            username: None,
            password: None,
            resolved_ip: None,
        }
    }

    pub fn has_auth(&self) -> bool {
        self.username.is_some() && self.password.is_some()
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            proxy_type: ProxyType::Socks5,
            host: "127.0.0.1".to_string(),
            port: 4444,
            username: None,
            password: None,
            resolved_ip: None,
        }
    }
}

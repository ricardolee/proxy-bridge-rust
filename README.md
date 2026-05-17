# ProxyBridge (Rust)

A process-level transparent proxy that redirects TCP and UDP traffic from specific applications through SOCKS5 or HTTP proxies, with the ability to route, block, or allow traffic on a per-process basis. Works with proxy-unaware applications without requiring any configuration changes.

```
  ____                        ____       _     _
 |  _ \ _ __ _____  ___   _  | __ ) _ __(_) __| | __ _  ___
 | |_) | '__/ _ \ \/ / | | | |  _ \| '__| |/ _` |/ _` |/ _ \
 |  __/| | | (_) >  <| |_| | | |_) | |  | | (_| | (_| |  __/
 |_|   |_|  \___/_/\_\\__, | |____/|_|  |_|\__,_|\__, |\___|
                      |___/                      |___/
```

## Features

- **Process-level routing** — Proxy, block, or direct traffic per application (e.g. only `curl`, not `wget`)
- **Transparent interception** — Works with proxy-unaware applications; no app configuration needed
- **SOCKS5 & HTTP proxy** — Full SOCKS5 (TCP + UDP) and HTTP CONNECT support with optional authentication
- **Flexible rules** — Target by process name (with wildcards), destination IP ranges, port ranges, and protocol (TCP/UDP/both)
- **Async I/O** — Built on Tokio for efficient, non-blocking TCP/UDP relay
- **Cross-platform architecture** — Core logic is shared; platform-specific implementations are isolated

## Architecture

The project is structured as a Cargo workspace with shared core crates and platform-specific implementations:

```
proxy-bridge-rust/
├── Cargo.toml                     # Workspace definition
├── crates/
│   ├── proxy-bridge-core/         # Cross-platform core library
│   │   └── src/
│   │       ├── config.rs          # Constants, types (ProxyConfig, RuleAction, etc.)
│   │       ├── connection.rs      # ConnectionTracker & PidCache
│   │       ├── rule.rs            # RuleEngine, pattern matching, IP/port/process matchers
│   │       └── proxy/
│   │           ├── socks5.rs      # SOCKS5 CONNECT + UDP ASSOCIATE implementation
│   │           └── http.rs        # HTTP CONNECT proxy implementation
│   └── proxy-bridge-cli/          # Cross-platform CLI (clap argument parsing, banner)
│       └── src/lib.rs
└── linux/                         # Linux platform implementation
    └── ...
```

### Core Crates

| Crate | Description |
|---|---|
| `proxy-bridge-core` | Rule engine, connection tracking, PID cache, SOCKS5/HTTP proxy protocol implementations — shared across all platforms |
| `proxy-bridge-cli` | CLI argument parsing (clap), proxy URL parsing, banner display — shared across all platforms |

### Rule Format

All platforms share the same rule syntax:

```
process:hosts:ports:protocol:action
```

| Field | Description | Examples |
|---|---|---|
| `process` | Process name (wildcard `*` supported) | `curl`, `fire*`, `*fox`, `curl;wget` |
| `hosts` | Destination IP filter | `*`, `192.168.1.*`, `10.0.0.1-255` |
| `ports` | Destination port filter | `*`, `80`, `80,443`, `1024-65535` |
| `protocol` | Protocol filter | `tcp`, `udp`, `both` |
| `action` | What to do | `proxy`, `direct`, `block` |

## Platform Support

| Platform | Status | Documentation |
|---|---|---|
| 📙 Linux | ✅ Implemented | [linux/README.md](linux/README.md) |
| 📘 Windows | 🔲 Planned | — |
| 📗 macOS | 🔲 Planned | — |

## Use Cases

- Redirect proxy-unaware applications (games, desktop apps) through security testing proxies
- Route specific applications through Tor, SOCKS5, or HTTP proxies
- Intercept and analyze traffic from applications that don't support proxy configuration
- Block specific applications from accessing the network
- Test application behavior under different network conditions

## Acknowledgments

This project is inspired by [ProxyBridge](https://github.com/InterceptSuite/ProxyBridge) by Sourav Kalal / InterceptSuite — a cross-platform universal proxy client written in C/C#/Swift that supports Windows, macOS, and Linux with both GUI and CLI interfaces.

## License

MIT

# ProxyBridge — Linux Implementation

Linux platform implementation using NFQUEUE for kernel-level packet interception and nftables for traffic redirection.

## How It Works

```
┌────────────┐     ┌──────────┐     ┌───────────────┐     ┌────────────┐
│ Application│────▶│ nftables │────▶│   NFQUEUE     │────▶│ Rule Engine│
│ (e.g. curl)│     │ (mangle) │     │ (packet hook) │     │ (match PID)│
└────────────┘     └──────────┘     └───────────────┘     └─────┬──────┘
                                                                │
                                    ┌───────────────────────────┼──────────┐
                                    │               ┌───────────┘          │
                                    ▼               ▼                      ▼
                               ┌─────────┐   ┌───────────┐          ┌──────────┐
                               │  DIRECT  │   │   PROXY   │          │  BLOCK   │
                               │ (accept) │   │ (mark pkt)│          │  (drop)  │
                               └─────────┘   └─────┬─────┘          └──────────┘
                                                    │
                                              ┌─────▼─────┐
                                              │  nftables  │
                                              │(NAT redir) │
                                              └─────┬─────┘
                                                    │
                                              ┌─────▼─────┐     ┌────────────┐
                                              │ TCP/UDP    │────▶│ SOCKS5/HTTP│
                                              │ Relay      │     │ Proxy      │
                                              └────────────┘     └────────────┘
```

1. **NFQUEUE** intercepts all outbound TCP/UDP packets via nftables mangle chain
2. **Process identification** resolves the packet's source PID using Netlink SOCK_DIAG (with `/proc/net` fallback for UDP)
3. **Rule engine** matches the process name against configured rules (supporting wildcards, IP ranges, port ranges)
4. **Matched packets** are marked and redirected by nftables NAT to a local TCP or UDP relay
5. **Relay** establishes SOCKS5/HTTP CONNECT tunnel to the upstream proxy and performs bidirectional data forwarding

## Requirements

- Linux kernel with NFQUEUE support (not compatible with WSL1/WSL2)
- Root privileges (`sudo`)
- Rust toolchain (1.70+)
- System libraries:

  | Library | Purpose |
  |---|---|
  | `libnetfilter_queue-dev` | NFQUEUE packet interception |
  | `libnftnl-dev` | nftables Netlink API |
  | `libmnl-dev` | Netlink message helper |

### Install Dependencies

```bash
# Debian / Ubuntu
sudo apt install libnetfilter-queue-dev libnftnl-dev libmnl-dev

# Fedora / RHEL
sudo dnf install libnetfilter_queue-devel libnftnl-devel libmnl-devel

# Arch Linux
sudo pacman -S libnetfilter_queue libnftnl libmnl
```

## Build

```bash
# From the workspace root:
cargo build -p proxy-bridge-linux --target-dir linux/target

# The binary is at:
# linux/target/debug/proxy-bridge
```

## Usage

```bash
# Basic: proxy all curl traffic through a SOCKS5 proxy
sudo ./proxy-bridge --proxy socks5://127.0.0.1:1080 \
    --rule "curl:*:*:both:proxy"

# Proxy multiple applications
sudo ./proxy-bridge --proxy socks5://192.168.1.10:1080 \
    --rule "curl:*:*:tcp:proxy" \
    --rule "wget:*:*:tcp:proxy" \
    --verbose 2

# Block an application from accessing the network
sudo ./proxy-bridge --proxy socks5://127.0.0.1:1080 \
    --rule "firefox:*:*:both:block"

# HTTP proxy with authentication
sudo ./proxy-bridge --proxy http://proxy.example.com:8080:user:pass \
    --rule "curl:*:443:tcp:proxy"

# Route DNS through proxy
sudo ./proxy-bridge --proxy socks5://127.0.0.1:1080 \
    --rule "curl;wget;firefox:*:*:both:proxy" \
    --dns-via-proxy true --verbose 3
```

### CLI Options

| Option | Default | Description |
|---|---|---|
| `--proxy <URL>` | `socks5://127.0.0.1:4444` | Proxy server URL |
| `--rule <RULE>` | *(none)* | Traffic routing rule (repeatable) |
| `--dns-via-proxy` | `true` | Route DNS queries through proxy |
| `--verbose <N>` | `0` | Logging: 0=none, 1=logs, 2=connections, 3=both |
| `--cleanup` | — | Clean up resources from a previous crashed instance |

## Source Structure

```
linux/
├── Cargo.toml
├── build.rs                       # System library detection (pkg-config)
├── src/
│   ├── main.rs                    # Entry point, wiring, signal handling
│   ├── netfilter.rs               # nftables rule management via Netlink (nftnl)
│   ├── nfqueue.rs                 # NFQUEUE packet processor (packet → PID → rule match)
│   ├── process.rs                 # PID resolution (Netlink SOCK_DIAG + /proc fallback)
│   └── relay/
│       ├── tcp.rs                 # Async TCP relay (Tokio) through SOCKS5/HTTP proxy
│       └── udp.rs                 # Async UDP relay (Tokio) through SOCKS5 UDP ASSOCIATE
├── target/                        # Build output
└── tests/
    ├── run_integration_tests.sh   # Sandboxed integration tests (network namespace)
    └── mock_servers.py            # Mock SOCKS5 proxy & HTTP target server
```

### Key Components

| Module | Description |
|---|---|
| `netfilter.rs` | Creates a dedicated `proxybridge` nftables table with mangle (NFQUEUE) and NAT (redirect) chains. Uses the `nftnl` crate for type-safe Netlink batching. |
| `nfqueue.rs` | Processes intercepted packets: parses IP/TCP/UDP headers, resolves PIDs, matches rules, marks packets for proxy or drops for block. |
| `process.rs` | Resolves socket → PID using Netlink SOCK_DIAG (fast path) with `/proc/net/udp` fallback. Includes UID-based `/proc` scanning optimization. |
| `relay/tcp.rs` | Accepts NAT-redirected TCP connections, looks up original destination from the connection tracker, establishes SOCKS5/HTTP tunnel, and relays bidirectionally via `tokio::io::copy_bidirectional`. |
| `relay/udp.rs` | Handles NAT-redirected UDP packets via SOCKS5 UDP ASSOCIATE, encapsulating/decapsulating the SOCKS5 UDP header format. |

## Testing

Integration tests run in an **isolated Linux network namespace** — they never affect the host system.

```bash
# Run integration tests (requires root for namespace creation)
sudo bash linux/tests/run_integration_tests.sh
```

The test suite verifies three scenarios:

| Scenario | Description |
|---|---|
| **A — Proxy** | `curl` traffic is intercepted and forwarded through the mock SOCKS5 proxy |
| **B — Bypass** | `wget` traffic goes direct (no matching rule) |
| **C — Block** | `curl` traffic is dropped when the rule action is `block` |

### Test Sandbox Details

- A **network namespace** (`pb_test_ns`) provides full isolation from the host
- A **dummy interface** (`dummy0`) with IPs `10.99.0.1` (proxy) and `10.99.0.2` (target) avoids loopback traffic filtering
- Mock SOCKS5 proxy and HTTP target server are Python scripts running inside the namespace
- Cleanup (namespace deletion, process termination) is guaranteed via `trap EXIT`

use anyhow::Result;
use log::{debug, info};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use proxy_bridge_core::config::*;
use proxy_bridge_core::connection::{ConnectionTracker, PidCache};
use proxy_bridge_core::rule::{is_broadcast_or_multicast, format_ip, RuleEngine};

use crate::process::{extract_filename, get_pid_from_connection, get_process_name};

/// Callback type for connection events
pub type ConnectionCallback = Box<dyn Fn(&str, u32, &str, u16, &str) + Send + Sync>;

/// Start the NFQUEUE packet processor in a blocking loop.
/// Should be called in a dedicated thread (not a tokio task).
pub fn run_nfqueue(
    rule_engine: Arc<RuleEngine>,
    conn_tracker: Arc<ConnectionTracker>,
    pid_cache: Arc<PidCache>,
    proxy_config: Arc<ProxyConfig>,
    dns_via_proxy: bool,
    running: Arc<AtomicBool>,
    current_pid: u32,
    verbose_level: u8,
) -> Result<()> {
    let mut queue = nfq::Queue::open()
        .map_err(|e| anyhow::anyhow!("Failed to open NFQUEUE: {}", e))?;

    queue
        .bind(NFQUEUE_NUM)
        .map_err(|e| anyhow::anyhow!("Failed to bind NFQUEUE {}: {}", NFQUEUE_NUM, e))?;

    info!("NFQUEUE bound to queue {}", NFQUEUE_NUM);

    while running.load(Ordering::Relaxed) {
        let mut msg = match queue.recv() {
            Ok(msg) => msg,
            Err(e) => {
                // ENOBUFS = kernel queue full (normal under load)
                // EINTR = signal interrupt
                if running.load(Ordering::Relaxed) {
                    debug!("NFQUEUE recv error (continuing): {}", e);
                }
                continue;
            }
        };

        let payload = msg.get_payload();
        if payload.len() < 20 {
            // Too short for IP header
            msg.set_verdict(nfq::Verdict::Accept);
            queue.verdict(msg).ok();
            continue;
        }

        // Parse IP header
        let version_ihl = payload[0];
        let ihl = (version_ihl & 0x0F) as usize * 4;
        let protocol = payload[9];
        let src_ip = u32::from_ne_bytes(payload[12..16].try_into().unwrap_or([0; 4]));
        let dest_ip = u32::from_ne_bytes(payload[16..20].try_into().unwrap_or([0; 4]));

        // Fast path: no active rules
        if !rule_engine.has_active_rules() {
            msg.set_verdict(nfq::Verdict::Accept);
            queue.verdict(msg).ok();
            continue;
        }

        let (src_port, dest_port, is_tcp, is_syn);

        if protocol == libc::IPPROTO_TCP as u8 {
            if payload.len() < ihl + 20 {
                msg.set_verdict(nfq::Verdict::Accept);
                queue.verdict(msg).ok();
                continue;
            }
            let tcp_offset = ihl;
            src_port =
                u16::from_be_bytes(payload[tcp_offset..tcp_offset + 2].try_into().unwrap());
            dest_port =
                u16::from_be_bytes(payload[tcp_offset + 2..tcp_offset + 4].try_into().unwrap());
            let flags = payload[tcp_offset + 13];
            is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0; // SYN && !ACK
            is_tcp = true;
        } else if protocol == libc::IPPROTO_UDP as u8 {
            if payload.len() < ihl + 8 {
                msg.set_verdict(nfq::Verdict::Accept);
                queue.verdict(msg).ok();
                continue;
            }
            let udp_offset = ihl;
            src_port =
                u16::from_be_bytes(payload[udp_offset..udp_offset + 2].try_into().unwrap());
            dest_port =
                u16::from_be_bytes(payload[udp_offset + 2..udp_offset + 4].try_into().unwrap());
            is_syn = false;
            is_tcp = false;
        } else {
            msg.set_verdict(nfq::Verdict::Accept);
            queue.verdict(msg).ok();
            continue;
        }

        let is_udp = !is_tcp;

        // Skip our own relay ports
        if is_tcp && src_port == LOCAL_PROXY_PORT {
            msg.set_verdict(nfq::Verdict::Accept);
            queue.verdict(msg).ok();
            continue;
        }
        if is_udp && src_port == LOCAL_UDP_RELAY_PORT {
            msg.set_verdict(nfq::Verdict::Accept);
            queue.verdict(msg).ok();
            continue;
        }

        // Already tracked connection → accept
        if conn_tracker.is_tracked(src_port) {
            msg.set_verdict(nfq::Verdict::Accept);
            queue.verdict(msg).ok();
            continue;
        }

        // TCP: only process SYN (new connections)
        if is_tcp && !is_syn {
            msg.set_verdict(nfq::Verdict::Accept);
            queue.verdict(msg).ok();
            continue;
        }

        // DNS handling
        let mut action = if dest_port == 53 && !dns_via_proxy {
            RuleAction::Direct
        } else {
            // Look up process and match rules
            let pid = get_pid_from_connection(src_ip, src_port, is_udp, &pid_cache);

            if pid == 0 || pid == current_pid {
                RuleAction::Direct
            } else {
                match get_process_name(pid) {
                    Some(name) => {
                        let matched = rule_engine.match_rule(&name, dest_ip, dest_port, is_udp);

                        // Log connection if verbose
                        if verbose_level >= 2 {
                            let display_name = extract_filename(&name);
                            let dest_str = format_ip(dest_ip);
                            let proto_str = if is_udp { "udp" } else { "tcp" };
                            let action_str = match matched {
                                RuleAction::Proxy => format!(
                                    "proxy {}://{}:{} {}",
                                    if proxy_config.proxy_type == ProxyType::Http {
                                        "http"
                                    } else {
                                        "socks5"
                                    },
                                    proxy_config.host,
                                    proxy_config.port,
                                    proto_str
                                ),
                                RuleAction::Direct => format!("direct {}", proto_str),
                                RuleAction::Block => format!("blocked {}", proto_str),
                            };
                            info!(
                                "[CONN] {} (PID:{}) -> {}:{} via {}",
                                display_name, pid, dest_str, dest_port, action_str
                            );
                        }

                        matched
                    }
                    None => RuleAction::Direct,
                }
            }
        };

        // Don't proxy broadcast/multicast
        if action == RuleAction::Proxy && is_broadcast_or_multicast(dest_ip) {
            action = RuleAction::Direct;
        }

        // DHCP ports bypass
        if action == RuleAction::Proxy && is_udp && (dest_port == 67 || dest_port == 68) {
            action = RuleAction::Direct;
        }

        // HTTP proxy doesn't support UDP
        if action == RuleAction::Proxy && is_udp && proxy_config.proxy_type != ProxyType::Socks5 {
            action = RuleAction::Direct;
        }

        // No proxy configured
        if action == RuleAction::Proxy && (proxy_config.host.is_empty() || proxy_config.port == 0)
        {
            action = RuleAction::Direct;
        }

        match action {
            RuleAction::Direct => {
                msg.set_verdict(nfq::Verdict::Accept);
            }
            RuleAction::Block => {
                msg.set_verdict(nfq::Verdict::Drop);
            }
            RuleAction::Proxy => {
                // Store connection for relay lookup
                conn_tracker.add(src_port, src_ip, dest_ip, dest_port);

                // Mark packet: 1 for TCP, 2 for UDP
                let mark = if is_tcp { TCP_MARK } else { UDP_MARK };
                msg.set_nfmark(mark);
                msg.set_verdict(nfq::Verdict::Accept);
            }
        }

        queue.verdict(msg).ok();
    }

    info!("NFQUEUE processor stopped");
    Ok(())
}

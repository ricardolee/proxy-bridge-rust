use anyhow::Result;
use clap::Parser;
use log::error;
use std::net::ToSocketAddrs;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use proxy_bridge_cli::{parse_proxy_url, show_banner, CliArgs};
use proxy_bridge_core::config::*;
use proxy_bridge_core::connection::{ConnectionTracker, PidCache};
use proxy_bridge_core::rule::{parse_rule_str, RuleEngine};

use proxy_bridge_linux::netfilter::NetfilterManager;
use proxy_bridge_linux::nfqueue;
use proxy_bridge_linux::relay;

fn main() -> Result<()> {
    let args = CliArgs::parse();

    // Initialize logger
    let log_level = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "info",
        _ => "debug",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    // Handle --cleanup
    if args.cleanup {
        println!("Running cleanup...");
        NetfilterManager::cleanup()?;
        println!("Cleanup complete.");
        return Ok(());
    }

    show_banner();

    // Check root
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("\x1b[31m\nERROR: ProxyBridge requires root privileges!\x1b[0m");
        eprintln!("Please run this application with sudo or as root.\n");
        process::exit(1);
    }

    // Parse proxy config
    let parsed = parse_proxy_url(&args.proxy)?;
    let mut proxy_config = ProxyConfig::new(parsed.proxy_type, parsed.host.clone(), parsed.port);
    proxy_config.username = parsed.username;
    proxy_config.password = parsed.password;

    // Resolve proxy hostname
    let addr_str = format!("{}:{}", proxy_config.host, proxy_config.port);
    if let Some(addr) = addr_str.to_socket_addrs()?.find(|a| a.is_ipv4()) {
        if let std::net::SocketAddr::V4(v4) = addr {
            proxy_config.resolved_ip = Some(u32::from_ne_bytes(v4.ip().octets()));
        }
    }
    if proxy_config.resolved_ip.is_none() {
        eprintln!("ERROR: Failed to resolve proxy host '{}'", proxy_config.host);
        process::exit(1);
    }

    // Display config
    println!(
        "Proxy: {}://{}:{}",
        if proxy_config.proxy_type == ProxyType::Http { "http" } else { "socks5" },
        proxy_config.host,
        proxy_config.port
    );
    if proxy_config.has_auth() {
        println!("Proxy Auth: {}:***", proxy_config.username.as_deref().unwrap_or(""));
    }
    println!("DNS via Proxy: {}", if args.dns_via_proxy { "Enabled" } else { "Disabled" });

    let proxy_config = Arc::new(proxy_config);
    let rule_engine = Arc::new(RuleEngine::new());
    let conn_tracker = Arc::new(ConnectionTracker::new());
    let pid_cache = Arc::new(PidCache::new());
    let running = Arc::new(AtomicBool::new(true));

    // Add rules
    if !args.rule.is_empty() {
        println!("Rules: {}", args.rule.len());
        for rule_str in &args.rule {
            let (proc_name, hosts, ports, protocol, action) = parse_rule_str(rule_str)?;
            let rule_id = rule_engine.add_rule(&proc_name, &hosts, &ports, protocol, action);
            if rule_id > 0 {
                let proto_str = match protocol {
                    RuleProtocol::Tcp => "TCP",
                    RuleProtocol::Udp => "UDP",
                    RuleProtocol::Both => "BOTH",
                };
                let action_str = match action {
                    RuleAction::Proxy => "PROXY",
                    RuleAction::Direct => "DIRECT",
                    RuleAction::Block => "BLOCK",
                };
                println!("  [{}] {}:{}:{}:{} -> {}", rule_id, proc_name, hosts, ports, proto_str, action_str);
            }
        }
    } else {
        eprintln!("\x1b[33mWARNING: No rules specified. No traffic will be proxied.\x1b[0m");
        eprintln!("Use --rule to add proxy rules. See --help for examples.");
    }

    // Setup nftables rules
    NetfilterManager::setup(LOCAL_PROXY_PORT, LOCAL_UDP_RELAY_PORT, NFQUEUE_NUM)?;

    let current_pid = process::id();

    // Start NFQUEUE in a dedicated thread
    let nfq_running = running.clone();
    let nfq_rules = rule_engine.clone();
    let nfq_conn = conn_tracker.clone();
    let nfq_pid_cache = pid_cache.clone();
    let nfq_proxy = proxy_config.clone();
    let dns_via = args.dns_via_proxy;
    let verbose = args.verbose;

    let _nfq_handle = std::thread::spawn(move || {
        if let Err(e) = nfqueue::run_nfqueue(
            nfq_rules, nfq_conn, nfq_pid_cache, nfq_proxy,
            dns_via, nfq_running, current_pid, verbose,
        ) {
            error!("NFQUEUE error: {}", e);
        }
    });

    // Start tokio runtime for relay servers
    let rt = tokio::runtime::Runtime::new()?;
    let relay_running = running.clone();

    // Setup signal handler
    let sig_running = running.clone();
    ctrlc::set_handler(move || {
        println!("\n\nStopping ProxyBridge...");
        sig_running.store(false, Ordering::Relaxed);
    })?;

    println!("\nProxyBridge started. Press Ctrl+C to stop...\n");

    rt.block_on(async {
        let tcp_running = relay_running.clone();
        let tcp_proxy = proxy_config.clone();
        let tcp_conn = conn_tracker.clone();

        let tcp_task = tokio::spawn(async move {
            if let Err(e) = relay::tcp::run_tcp_relay(
                LOCAL_PROXY_PORT, tcp_proxy, tcp_conn, tcp_running,
            ).await {
                error!("TCP relay error: {}", e);
            }
        });

        // Start UDP relay only for SOCKS5
        let udp_task = if proxy_config.proxy_type == ProxyType::Socks5 {
            let udp_running = relay_running.clone();
            let udp_proxy = proxy_config.clone();
            let udp_conn = conn_tracker.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = relay::udp::run_udp_relay(
                    LOCAL_UDP_RELAY_PORT, udp_proxy, udp_conn, udp_running,
                ).await {
                    error!("UDP relay error: {}", e);
                }
            }))
        } else {
            None
        };

        // Cleanup timer
        let cleanup_conn = conn_tracker.clone();
        let cleanup_pid = pid_cache.clone();
        let cleanup_running = relay_running.clone();
        let cleanup_task = tokio::spawn(async move {
            while cleanup_running.load(Ordering::Relaxed) {
                tokio::time::sleep(tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECS)).await;
                cleanup_conn.cleanup_stale();
                cleanup_pid.cleanup();
            }
        });

        // Wait for shutdown
        while relay_running.load(Ordering::Relaxed) {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        tcp_task.abort();
        if let Some(t) = udp_task { t.abort(); }
        cleanup_task.abort();
    });

    // Cleanup
    NetfilterManager::cleanup()?;
    println!("ProxyBridge stopped.");

    Ok(())
}

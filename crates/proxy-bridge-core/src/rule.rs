use crate::config::{RuleAction, RuleProtocol};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

static NEXT_RULE_ID: AtomicU32 = AtomicU32::new(1);

/// A traffic routing rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,
    pub process_name: String,
    pub target_hosts: String,
    pub target_ports: String,
    pub protocol: RuleProtocol,
    pub action: RuleAction,
    pub enabled: bool,
}

/// Thread-safe rule engine
#[derive(Debug, Clone)]
pub struct RuleEngine {
    rules: Arc<RwLock<Vec<Rule>>>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a new rule, returns the assigned rule ID (0 on failure)
    pub fn add_rule(
        &self,
        process_name: &str,
        target_hosts: &str,
        target_ports: &str,
        protocol: RuleProtocol,
        action: RuleAction,
    ) -> u32 {
        if process_name.is_empty() {
            return 0;
        }

        let rule = Rule {
            id: NEXT_RULE_ID.fetch_add(1, Ordering::Relaxed),
            process_name: process_name.to_string(),
            target_hosts: if target_hosts.is_empty() {
                "*".to_string()
            } else {
                target_hosts.to_string()
            },
            target_ports: if target_ports.is_empty() {
                "*".to_string()
            } else {
                target_ports.to_string()
            },
            protocol,
            action,
            enabled: true,
        };

        let id = rule.id;
        let mut rules = self.rules.write().unwrap();
        rules.push(rule);
        id
    }

    /// Enable a rule by ID
    pub fn enable_rule(&self, rule_id: u32) -> bool {
        let mut rules = self.rules.write().unwrap();
        if let Some(rule) = rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = true;
            true
        } else {
            false
        }
    }

    /// Disable a rule by ID
    pub fn disable_rule(&self, rule_id: u32) -> bool {
        let mut rules = self.rules.write().unwrap();
        if let Some(rule) = rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = false;
            true
        } else {
            false
        }
    }

    /// Delete a rule by ID
    pub fn delete_rule(&self, rule_id: u32) -> bool {
        let mut rules = self.rules.write().unwrap();
        let len_before = rules.len();
        rules.retain(|r| r.id != rule_id);
        rules.len() != len_before
    }

    /// Check if there are any active (enabled) rules
    pub fn has_active_rules(&self) -> bool {
        let rules = self.rules.read().unwrap();
        rules.iter().any(|r| r.enabled)
    }

    /// Match a connection against all rules.
    /// Returns the action for the first matching rule, or Direct if none match.
    pub fn match_rule(
        &self,
        process_name: &str,
        dest_ip: u32,
        dest_port: u16,
        is_udp: bool,
    ) -> RuleAction {
        let rules = self.rules.read().unwrap();
        let mut wildcard_rule: Option<&Rule> = None;

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // Protocol filter
            match rule.protocol {
                RuleProtocol::Tcp if is_udp => continue,
                RuleProtocol::Udp if !is_udp => continue,
                _ => {}
            }

            let is_wildcard_process =
                rule.process_name == "*" || rule.process_name.eq_ignore_ascii_case("ANY");

            if is_wildcard_process {
                let has_ip_filter = rule.target_hosts != "*";
                let has_port_filter = rule.target_ports != "*";

                if has_ip_filter || has_port_filter {
                    if match_ip_list(&rule.target_hosts, dest_ip)
                        && match_port_list(&rule.target_ports, dest_port)
                    {
                        return rule.action;
                    }
                    continue;
                }

                if wildcard_rule.is_none() {
                    wildcard_rule = Some(rule);
                }
                continue;
            }

            if match_process_list(&rule.process_name, process_name)
                && match_ip_list(&rule.target_hosts, dest_ip)
                && match_port_list(&rule.target_ports, dest_port)
            {
                return rule.action;
            }
        }

        if let Some(rule) = wildcard_rule {
            return rule.action;
        }

        RuleAction::Direct
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

// --- Pattern matching functions ---

/// Match a process name against a semicolon-separated list of patterns
pub fn match_process_list(process_list: &str, process_name: &str) -> bool {
    if process_list == "*" {
        return true;
    }
    process_list
        .split(';')
        .any(|pattern| match_process_pattern(pattern.trim(), process_name))
}

/// Match a single process pattern (supports * prefix/suffix wildcards)
fn match_process_pattern(pattern: &str, process_full_path: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Extract filename from path
    let filename = process_full_path
        .rsplit('/')
        .next()
        .unwrap_or(process_full_path);

    let is_full_path_pattern = pattern.contains('/');
    let match_target = if is_full_path_pattern {
        process_full_path
    } else {
        filename
    };

    // Trailing wildcard: "fire*" matches "firefox"
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return match_target
            .get(..prefix.len())
            .map_or(false, |s| s.eq_ignore_ascii_case(prefix));
    }

    // Leading wildcard: "*fox" matches "firefox"
    if pattern.starts_with('*') {
        let suffix = &pattern[1..];
        return match_target
            .get(match_target.len().saturating_sub(suffix.len())..)
            .map_or(false, |s| s.eq_ignore_ascii_case(suffix));
    }

    // Exact match (case-insensitive)
    match_target.eq_ignore_ascii_case(pattern)
}

/// Match an IP against a semicolon-separated list of patterns
pub fn match_ip_list(ip_list: &str, ip: u32) -> bool {
    if ip_list.is_empty() || ip_list == "*" {
        return true;
    }
    ip_list
        .split(';')
        .any(|pattern| match_ip_pattern(pattern.trim(), ip))
}

/// Match a single IP pattern like "192.168.*.*" or "10.0.0.1-255"
fn match_ip_pattern(pattern: &str, ip: u32) -> bool {
    if pattern == "*" {
        return true;
    }

    let ip_octets = [
        (ip & 0xFF) as u8,
        ((ip >> 8) & 0xFF) as u8,
        ((ip >> 16) & 0xFF) as u8,
        ((ip >> 24) & 0xFF) as u8,
    ];

    let pattern_parts: Vec<&str> = pattern.split('.').collect();
    if pattern_parts.len() != 4 {
        return false;
    }

    for (i, part) in pattern_parts.iter().enumerate() {
        if *part == "*" {
            continue;
        }

        if let Some((start_str, end_str)) = part.split_once('-') {
            let start: u8 = start_str.parse().unwrap_or(0);
            let end: u8 = end_str.parse().unwrap_or(0);
            if ip_octets[i] < start || ip_octets[i] > end {
                return false;
            }
        } else {
            let val: u8 = part.parse().unwrap_or(255);
            if ip_octets[i] != val {
                return false;
            }
        }
    }
    true
}

/// Match a port against a comma/semicolon-separated list of patterns
pub fn match_port_list(port_list: &str, port: u16) -> bool {
    if port_list.is_empty() || port_list == "*" {
        return true;
    }
    port_list
        .split([',', ';'])
        .any(|pattern| match_port_pattern(pattern.trim(), port))
}

/// Match a single port pattern like "80" or "80-8080"
fn match_port_pattern(pattern: &str, port: u16) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some((start_str, end_str)) = pattern.split_once('-') {
        let start: u16 = start_str.parse().unwrap_or(0);
        let end: u16 = end_str.parse().unwrap_or(0);
        port >= start && port <= end
    } else {
        let val: u16 = pattern.parse().unwrap_or(0);
        port == val
    }
}

/// Parse a CLI rule string "process:hosts:ports:protocol:action" into components
pub fn parse_rule_str(
    rule_str: &str,
) -> anyhow::Result<(String, String, String, RuleProtocol, RuleAction)> {
    let parts: Vec<&str> = rule_str.split(':').collect();
    if parts.len() != 5 {
        anyhow::bail!(
            "Invalid rule format '{}'. Expected: process:hosts:ports:protocol:action",
            rule_str
        );
    }

    let process = if parts[0].is_empty() { "*" } else { parts[0] };
    let hosts = if parts[1].is_empty() { "*" } else { parts[1] };
    let ports = if parts[2].is_empty() { "*" } else { parts[2] };

    let protocol = match parts[3].to_uppercase().as_str() {
        "TCP" => RuleProtocol::Tcp,
        "UDP" => RuleProtocol::Udp,
        "BOTH" => RuleProtocol::Both,
        other => anyhow::bail!("Invalid protocol '{}'. Use TCP, UDP, or BOTH", other),
    };

    let action = match parts[4].to_uppercase().as_str() {
        "PROXY" => RuleAction::Proxy,
        "DIRECT" => RuleAction::Direct,
        "BLOCK" => RuleAction::Block,
        other => anyhow::bail!("Invalid action '{}'. Use PROXY, DIRECT, or BLOCK", other),
    };

    Ok((
        process.to_string(),
        hosts.to_string(),
        ports.to_string(),
        protocol,
        action,
    ))
}

// --- Helper ---

/// Check if an IP is broadcast, multicast, or loopback
pub fn is_broadcast_or_multicast(ip: u32) -> bool {
    let first_octet = (ip & 0xFF) as u8;
    let second_octet = ((ip >> 8) & 0xFF) as u8;

    // Loopback 127.x.x.x
    if first_octet == 127 {
        return true;
    }
    // Link-local 169.254.x.x
    if first_octet == 169 && second_octet == 254 {
        return true;
    }
    // Broadcast
    if ip == 0xFFFF_FFFF {
        return true;
    }
    // Subnet broadcast
    if (ip & 0xFF00_0000) == 0xFF00_0000 {
        return true;
    }
    // Multicast 224-239.x.x.x
    if (224..=239).contains(&first_octet) {
        return true;
    }
    false
}

/// Format a u32 IP (network byte order) to string
pub fn format_ip(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        ip & 0xFF,
        (ip >> 8) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 24) & 0xFF,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_process_pattern() {
        assert!(match_process_pattern("*", "/usr/bin/curl"));
        assert!(match_process_pattern("curl", "/usr/bin/curl"));
        assert!(match_process_pattern("curl", "curl"));
        assert!(match_process_pattern("cur*", "/usr/bin/curl"));
        assert!(match_process_pattern("*rl", "/usr/bin/curl"));
        assert!(!match_process_pattern("wget", "/usr/bin/curl"));
        assert!(match_process_pattern("fire*", "/usr/bin/firefox"));
        assert!(match_process_pattern("*fox", "/usr/bin/firefox"));
    }

    #[test]
    fn test_match_process_list() {
        assert!(match_process_list("curl;wget", "/usr/bin/curl"));
        assert!(match_process_list("curl;wget", "/usr/bin/wget"));
        assert!(!match_process_list("curl;wget", "/usr/bin/firefox"));
        assert!(match_process_list("*", "/usr/bin/anything"));
    }

    #[test]
    fn test_match_ip_pattern() {
        // 192.168.1.100 in network byte order
        let ip = 192 | (168 << 8) | (1 << 16) | (100 << 24);
        assert!(match_ip_pattern("*", ip));
        assert!(match_ip_pattern("192.168.1.100", ip));
        assert!(match_ip_pattern("192.168.*.*", ip));
        assert!(match_ip_pattern("192.168.1.50-200", ip));
        assert!(!match_ip_pattern("10.0.0.1", ip));
    }

    #[test]
    fn test_match_port_pattern() {
        assert!(match_port_pattern("*", 443));
        assert!(match_port_pattern("443", 443));
        assert!(match_port_pattern("80-8080", 443));
        assert!(!match_port_pattern("80", 443));
        assert!(!match_port_pattern("1-80", 443));
    }

    #[test]
    fn test_match_port_list() {
        assert!(match_port_list("80;443", 443));
        assert!(match_port_list("80,443", 443));
        assert!(match_port_list("80-8080", 443));
        assert!(!match_port_list("80;8080", 443));
    }

    #[test]
    fn test_parse_rule_str() {
        let (proc, hosts, ports, proto, action) =
            parse_rule_str("curl:*:*:TCP:PROXY").unwrap();
        assert_eq!(proc, "curl");
        assert_eq!(hosts, "*");
        assert_eq!(ports, "*");
        assert_eq!(proto, RuleProtocol::Tcp);
        assert_eq!(action, RuleAction::Proxy);
    }

    #[test]
    fn test_is_broadcast_or_multicast() {
        let loopback = 127 | (0 << 8) | (0 << 16) | (1 << 24); // 127.0.0.1
        assert!(is_broadcast_or_multicast(loopback));

        let multicast = 224 | (0 << 8) | (0 << 16) | (1 << 24); // 224.0.0.1
        assert!(is_broadcast_or_multicast(multicast));

        let normal = 8 | (8 << 8) | (8 << 16) | (8 << 24); // 8.8.8.8
        assert!(!is_broadcast_or_multicast(normal));
    }

    #[test]
    fn test_format_ip() {
        let ip = 192 | (168 << 8) | (1 << 16) | (100 << 24);
        assert_eq!(format_ip(ip), "192.168.1.100");
    }

    #[test]
    fn test_rule_engine() {
        let engine = RuleEngine::new();
        let id = engine.add_rule("curl", "*", "*", RuleProtocol::Tcp, RuleAction::Proxy);
        assert!(id > 0);
        assert!(engine.has_active_rules());

        // Match: curl TCP should proxy
        let action = engine.match_rule("/usr/bin/curl", 0x08080808, 443, false);
        assert_eq!(action, RuleAction::Proxy);

        // No match: wget should be direct
        let action = engine.match_rule("/usr/bin/wget", 0x08080808, 443, false);
        assert_eq!(action, RuleAction::Direct);

        // Disable rule
        engine.disable_rule(id);
        assert!(!engine.has_active_rules());
    }
}

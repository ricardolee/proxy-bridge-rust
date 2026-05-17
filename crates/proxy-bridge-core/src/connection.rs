use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::config::{CONNECTION_TIMEOUT_MS, PID_CACHE_TTL_MS};

/// Tracked connection info (original destination before NAT redirect)
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub src_ip: u32,
    pub src_port: u16,
    pub orig_dest_ip: u32,
    pub orig_dest_port: u16,
    pub last_activity: Instant,
}

/// Thread-safe connection tracker keyed by source port
#[derive(Debug, Clone)]
pub struct ConnectionTracker {
    connections: Arc<RwLock<HashMap<u16, ConnectionInfo>>>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add or update a connection entry
    pub fn add(&self, src_port: u16, src_ip: u32, dest_ip: u32, dest_port: u16) {
        let mut conns = self.connections.write().unwrap();
        conns.insert(
            src_port,
            ConnectionInfo {
                src_ip,
                src_port,
                orig_dest_ip: dest_ip,
                orig_dest_port: dest_port,
                last_activity: Instant::now(),
            },
        );
    }

    /// Get original destination for a connection by source port
    pub fn get(&self, src_port: u16) -> Option<(u32, u16)> {
        let conns = self.connections.read().unwrap();
        conns.get(&src_port).map(|c| {
            // Note: last_activity update is a benign race (same as original C code)
            (c.orig_dest_ip, c.orig_dest_port)
        })
    }

    /// Check if a connection is being tracked
    pub fn is_tracked(&self, src_port: u16) -> bool {
        let conns = self.connections.read().unwrap();
        conns.contains_key(&src_port)
    }

    /// Remove stale connections older than CONNECTION_TIMEOUT_MS
    pub fn cleanup_stale(&self) {
        let mut conns = self.connections.write().unwrap();
        conns.retain(|_, info| info.last_activity.elapsed().as_millis() < CONNECTION_TIMEOUT_MS as u128);
    }

    /// Remove all connections
    pub fn clear(&self) {
        let mut conns = self.connections.write().unwrap();
        conns.clear();
    }

    /// Find a connection by original destination (for UDP relay response routing)
    pub fn find_by_dest(&self, dest_ip: u32, dest_port: u16) -> Option<u16> {
        let conns = self.connections.read().unwrap();
        for (_, info) in conns.iter() {
            if info.orig_dest_ip == dest_ip && info.orig_dest_port == dest_port {
                return Some(info.src_port);
            }
        }
        None
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// PID cache entry
#[derive(Debug, Clone)]
struct PidCacheEntry {
    pid: u32,
    timestamp: Instant,
}

/// Cache key for PID lookups
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct PidCacheKey {
    src_ip: u32,
    src_port: u16,
    is_udp: bool,
}

/// Thread-safe PID cache with TTL
#[derive(Debug, Clone)]
pub struct PidCache {
    cache: Arc<Mutex<HashMap<PidCacheKey, PidCacheEntry>>>,
}

impl PidCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get cached PID if not expired
    pub fn get(&self, src_ip: u32, src_port: u16, is_udp: bool) -> Option<u32> {
        let cache = self.cache.lock().unwrap();
        let key = PidCacheKey {
            src_ip,
            src_port,
            is_udp,
        };
        cache.get(&key).and_then(|entry| {
            if entry.timestamp.elapsed().as_millis() < PID_CACHE_TTL_MS as u128 {
                Some(entry.pid)
            } else {
                None
            }
        })
    }

    /// Store a PID in cache
    pub fn put(&self, src_ip: u32, src_port: u16, pid: u32, is_udp: bool) {
        let mut cache = self.cache.lock().unwrap();
        let key = PidCacheKey {
            src_ip,
            src_port,
            is_udp,
        };
        cache.insert(
            key,
            PidCacheEntry {
                pid,
                timestamp: Instant::now(),
            },
        );
    }

    /// Remove expired entries
    pub fn cleanup(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.retain(|_, entry| entry.timestamp.elapsed().as_millis() < PID_CACHE_TTL_MS as u128);
    }

    /// Clear all entries
    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }
}

impl Default for PidCache {
    fn default() -> Self {
        Self::new()
    }
}

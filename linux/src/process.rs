use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;

use proxy_bridge_core::connection::PidCache;

/// Find the PID that owns a network connection by source IP, port, and protocol.
/// Uses Netlink SOCK_DIAG first, then falls back to /proc/net parsing for UDP.
pub fn get_pid_from_connection(
    src_ip: u32,
    src_port: u16,
    is_udp: bool,
    pid_cache: &PidCache,
) -> u32 {
    // Check cache first
    if let Some(pid) = pid_cache.get(src_ip, src_port, is_udp) {
        return pid;
    }

    // Try Netlink SOCK_DIAG
    let pid = match get_pid_via_netlink(src_ip, src_port, is_udp) {
        Some(pid) => pid,
        None => {
            // Fallback for UDP: parse /proc/net/udp
            if is_udp {
                get_pid_from_proc_net_udp(src_port).unwrap_or(0)
            } else {
                0
            }
        }
    };

    if pid != 0 {
        pid_cache.put(src_ip, src_port, pid, is_udp);
    }

    pid
}

/// Use Netlink SOCK_DIAG to find socket inode, then scan /proc for PID
fn get_pid_via_netlink(src_ip: u32, src_port: u16, is_udp: bool) -> Option<u32> {
    use std::mem;

    // Open Netlink SOCK_DIAG socket
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return None;
    }

    // Set timeout
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000, // 100ms
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            mem::size_of::<libc::timeval>() as u32,
        );
    }

    // Build inet_diag_req_v2 request
    #[repr(C)]
    struct InetDiagReqV2 {
        sdiag_family: u8,
        sdiag_protocol: u8,
        idiag_ext: u8,
        pad: u8,
        idiag_states: u32,
        id: InetDiagSockId,
    }

    #[repr(C)]
    struct InetDiagSockId {
        idiag_sport: u16,
        idiag_dport: u16,
        idiag_src: [u32; 4],
        idiag_dst: [u32; 4],
        idiag_if: u32,
        idiag_cookie: [u32; 2],
    }

    #[repr(C)]
    struct NlRequest {
        nlh: libc::nlmsghdr,
        req: InetDiagReqV2,
    }

    const SOCK_DIAG_BY_FAMILY: u16 = 20;

    let mut request: NlRequest = unsafe { mem::zeroed() };
    request.nlh.nlmsg_len = mem::size_of::<NlRequest>() as u32;
    request.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16 | libc::NLM_F_DUMP as u16;
    request.req.sdiag_family = libc::AF_INET as u8;
    request.req.sdiag_protocol = if is_udp {
        libc::IPPROTO_UDP as u8
    } else {
        libc::IPPROTO_TCP as u8
    };

    if !is_udp {
        // TCP: filter to SYN_SENT(2) + ESTABLISHED(3)
        request.req.idiag_states = (1 << 2) | (1 << 3);
    } else {
        request.req.idiag_states = u32::MAX;
    }

    let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;

    let sent = unsafe {
        libc::sendto(
            fd,
            &request as *const _ as *const libc::c_void,
            mem::size_of::<NlRequest>(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };

    if sent < 0 {
        unsafe { libc::close(fd) };
        return None;
    }

    // inet_diag_msg structure (partial)
    #[repr(C)]
    struct InetDiagMsg {
        idiag_family: u8,
        idiag_state: u8,
        idiag_timer: u8,
        idiag_retrans: u8,
        id: InetDiagSockId,
        idiag_expires: u32,
        idiag_rqueue: u32,
        idiag_wqueue: u32,
        idiag_uid: u32,
        idiag_inode: u32,
    }

    let mut target_inode: u64 = 0;
    let mut target_uid: u32 = u32::MAX;
    let mut found = false;

    let mut buf = [0u8; 16384];
    'outer: loop {
        let len = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if len <= 0 {
            break;
        }

        let mut offset = 0usize;
        while offset < len as usize {
            let nlh = unsafe { &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr) };

            if nlh.nlmsg_type == libc::NLMSG_DONE as u16
                || nlh.nlmsg_type == libc::NLMSG_ERROR as u16
            {
                break 'outer;
            }

            if nlh.nlmsg_type == SOCK_DIAG_BY_FAMILY {
                let msg = unsafe {
                    &*(buf.as_ptr().add(offset + mem::size_of::<libc::nlmsghdr>())
                        as *const InetDiagMsg)
                };

                if msg.id.idiag_src[0] == src_ip
                    && u16::from_be(msg.id.idiag_sport) == src_port
                {
                    target_inode = msg.idiag_inode as u64;
                    target_uid = msg.idiag_uid;
                    found = true;
                    break 'outer;
                }
            }

            offset += nlmsg_align(nlh.nlmsg_len as usize);
        }
    }

    unsafe { libc::close(fd) };

    if found && target_inode != 0 {
        find_pid_from_inode(target_inode, target_uid)
    } else {
        None
    }
}

/// Align to NLMSG boundary
fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Scan /proc to find which process owns a socket inode
fn find_pid_from_inode(target_inode: u64, uid_hint: u32) -> Option<u32> {
    let expected = format!("socket:[{}]", target_inode);

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return None,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip non-PID directories
        if !name_str.chars().next().map_or(false, |c| c.is_ascii_digit()) {
            continue;
        }

        // UID hint optimization: skip other users' processes
        if uid_hint != u32::MAX {
            if let Ok(meta) = entry.metadata() {
                if meta.uid() != uid_hint {
                    continue;
                }
            }
        }

        let fd_path = format!("/proc/{}/fd", name_str);
        let fd_dir = match fs::read_dir(&fd_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fd_dir.flatten() {
            let link_path = fd_entry.path();
            if let Ok(target) = fs::read_link(&link_path) {
                if target.to_string_lossy() == expected {
                    return name_str.parse().ok();
                }
            }
        }
    }

    None
}

/// Fallback: parse /proc/net/udp to find inode, then find PID
fn get_pid_from_proc_net_udp(src_port: u16) -> Option<u32> {
    for path in &["/proc/net/udp", "/proc/net/udp6"] {
        if let Ok(file) = fs::File::open(path) {
            let reader = BufReader::new(file);
            for (i, line) in reader.lines().enumerate() {
                if i == 0 {
                    continue; // skip header
                }
                let line = match line {
                    Ok(l) => l,
                    Err(_) => continue,
                };

                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 10 {
                    continue;
                }

                // Parse local_address:port
                if let Some((_, port_hex)) = fields[1].split_once(':') {
                    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
                    if port == src_port {
                        // Field 9 is inode
                        let inode: u64 = fields[9].parse().unwrap_or(0);
                        if inode != 0 {
                            // Field 7 is uid
                            let uid: u32 = fields[7].parse().unwrap_or(u32::MAX);
                            return find_pid_from_inode(inode, uid);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Get process name from PID by reading /proc/PID/exe symlink
pub fn get_process_name(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    if pid == 1 {
        return Some("systemd".to_string());
    }

    let path = format!("/proc/{}/exe", pid);
    fs::read_link(&path).ok().map(|p| p.to_string_lossy().into_owned())
}

/// Extract just the filename from a full path
pub fn extract_filename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

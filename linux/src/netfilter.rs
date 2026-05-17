use anyhow::Result;
use log::info;
use std::ptr;

use nftnl::expr::Expression;
use nftnl::nftnl_sys as sys;
use nftnl::{Batch, Chain, ChainType, Hook, MsgType, Policy, ProtoFamily, Rule, Table};

/// Table name used by ProxyBridge (easy to identify and cleanup)
const TABLE_NAME: &str = "proxybridge";

/// Custom Queue expression since it's not present in nftnl crate.
pub struct Queue {
    num: u16,
}

impl Queue {
    pub fn new(num: u16) -> Self {
        Self { num }
    }
}

impl Expression for Queue {
    fn to_expr(&self, _rule: &Rule) -> ptr::NonNull<sys::nftnl_expr> {
        let name = std::ffi::CStr::from_bytes_with_nul(b"queue\0").unwrap();
        let expr = unsafe { sys::nftnl_expr_alloc(name.as_ptr()) };
        let expr_ptr = ptr::NonNull::new(expr).expect("Failed to allocate queue expression");
        unsafe {
            sys::nftnl_expr_set_u16(
                expr_ptr.as_ptr(),
                sys::NFTNL_EXPR_QUEUE_NUM as u16,
                self.num,
            );
        }
        expr_ptr
    }
}

/// Custom Redir expression since it's not present in nftnl crate.
pub struct Redir {
    proto_register: Option<nftnl::expr::Register>,
}

impl Redir {
    pub fn new(proto_register: Option<nftnl::expr::Register>) -> Self {
        Self { proto_register }
    }
}

impl Expression for Redir {
    fn to_expr(&self, _rule: &Rule) -> ptr::NonNull<sys::nftnl_expr> {
        let name = std::ffi::CStr::from_bytes_with_nul(b"redir\0").unwrap();
        let expr = unsafe { sys::nftnl_expr_alloc(name.as_ptr()) };
        let expr_ptr = ptr::NonNull::new(expr).expect("Failed to allocate redir expression");
        if let Some(reg) = self.proto_register {
            unsafe {
                sys::nftnl_expr_set_u32(
                    expr_ptr.as_ptr(),
                    sys::NFTNL_EXPR_REDIR_REG_PROTO_MIN as u16,
                    reg.to_raw(),
                );
            }
        }
        expr_ptr
    }
}

/// Manages nftables rules via Netlink using nftnl.
/// Creates a dedicated "proxybridge" table with mangle and nat chains.
pub struct NetfilterManager;

impl NetfilterManager {
    /// Setup all nftables rules needed for ProxyBridge.
    /// Creates table, chains, and rules atomically via Netlink batch.
    pub fn setup(tcp_relay_port: u16, udp_relay_port: u16, queue_num: u16) -> Result<()> {
        // First try to clean up any leftover rules
        let _ = Self::cleanup();

        let mut batch = Batch::new();
        let table = Table::new(std::ffi::CStr::from_bytes_with_nul(b"proxybridge\0").unwrap(), ProtoFamily::Inet);

        // Create table
        batch.add(&table, MsgType::Add);

        // --- Mangle chain: intercept OUTPUT packets to NFQUEUE ---
        let mut mangle_chain = Chain::new(std::ffi::CStr::from_bytes_with_nul(b"mangle_output\0").unwrap(), &table);
        mangle_chain.set_hook(Hook::Out, -150); // mangle priority
        mangle_chain.set_type(ChainType::Filter);
        mangle_chain.set_policy(Policy::Accept);
        batch.add(&mangle_chain, MsgType::Add);

        // Rule: ip protocol tcp queue num <queue_num>
        let mut tcp_queue_rule = Rule::new(&mangle_chain);
        tcp_queue_rule.add_expr(&nftnl::expr::Meta::L4Proto);
        tcp_queue_rule.add_expr(&nftnl::expr::Cmp::new(
            nftnl::expr::CmpOp::Eq,
            libc::IPPROTO_TCP as u8,
        ));
        tcp_queue_rule.add_expr(&Queue::new(queue_num));
        batch.add(&tcp_queue_rule, MsgType::Add);

        // Rule: ip protocol udp queue num <queue_num>
        let mut udp_queue_rule = Rule::new(&mangle_chain);
        udp_queue_rule.add_expr(&nftnl::expr::Meta::L4Proto);
        udp_queue_rule.add_expr(&nftnl::expr::Cmp::new(
            nftnl::expr::CmpOp::Eq,
            libc::IPPROTO_UDP as u8,
        ));
        udp_queue_rule.add_expr(&Queue::new(queue_num));
        batch.add(&udp_queue_rule, MsgType::Add);

        // --- NAT chain: redirect marked packets to local relay ports ---
        let mut nat_chain = Chain::new(std::ffi::CStr::from_bytes_with_nul(b"nat_output\0").unwrap(), &table);
        nat_chain.set_hook(Hook::Out, -100); // nat output priority
        nat_chain.set_type(ChainType::Nat);
        nat_chain.set_policy(Policy::Accept);
        batch.add(&nat_chain, MsgType::Add);

        // Rule: ip protocol tcp mark 1 redirect to :tcp_relay_port
        let mut tcp_redir_rule = Rule::new(&nat_chain);
        tcp_redir_rule.add_expr(&nftnl::expr::Meta::L4Proto);
        tcp_redir_rule.add_expr(&nftnl::expr::Cmp::new(
            nftnl::expr::CmpOp::Eq,
            libc::IPPROTO_TCP as u8,
        ));
        tcp_redir_rule.add_expr(&nftnl::expr::Meta::Mark { set: false });
        tcp_redir_rule.add_expr(&nftnl::expr::Cmp::new(
            nftnl::expr::CmpOp::Eq,
            1u32,
        ));
        tcp_redir_rule.add_expr(&nftnl::expr::Immediate::new(
            tcp_relay_port.to_be(),
            nftnl::expr::Register::Reg1,
        ));
        tcp_redir_rule.add_expr(&Redir::new(Some(nftnl::expr::Register::Reg1)));
        batch.add(&tcp_redir_rule, MsgType::Add);

        // Rule: ip protocol udp mark 2 redirect to :udp_relay_port
        let mut udp_redir_rule = Rule::new(&nat_chain);
        udp_redir_rule.add_expr(&nftnl::expr::Meta::L4Proto);
        udp_redir_rule.add_expr(&nftnl::expr::Cmp::new(
            nftnl::expr::CmpOp::Eq,
            libc::IPPROTO_UDP as u8,
        ));
        udp_redir_rule.add_expr(&nftnl::expr::Meta::Mark { set: false });
        udp_redir_rule.add_expr(&nftnl::expr::Cmp::new(
            nftnl::expr::CmpOp::Eq,
            2u32,
        ));
        udp_redir_rule.add_expr(&nftnl::expr::Immediate::new(
            udp_relay_port.to_be(),
            nftnl::expr::Register::Reg1,
        ));
        udp_redir_rule.add_expr(&Redir::new(Some(nftnl::expr::Register::Reg1)));
        batch.add(&udp_redir_rule, MsgType::Add);

        // Send batch to kernel via Netlink
        let finalized = batch.finalize();
        send_and_process(&finalized)?;

        info!("nftables rules installed (table: {})", TABLE_NAME);
        Ok(())
    }

    /// Remove all ProxyBridge nftables rules by deleting the entire table.
    /// This is atomic and guaranteed to clean up everything.
    pub fn cleanup() -> Result<()> {
        let mut batch = Batch::new();
        let table = Table::new(std::ffi::CStr::from_bytes_with_nul(b"proxybridge\0").unwrap(), ProtoFamily::Inet);
        batch.add(&table, MsgType::Del);

        let finalized = batch.finalize();
        // Ignore errors (table might not exist)
        let _ = send_and_process(&finalized);

        info!("nftables rules cleaned up (table: {})", TABLE_NAME);
        Ok(())
    }
}

/// Send a finalized nftnl batch to the kernel via a Netlink socket.
fn send_and_process(batch: &nftnl::FinalizedBatch) -> Result<()> {
    let socket = mnl::Socket::open(mnl::Bus::Netfilter)
        .map_err(|e| anyhow::anyhow!("Failed to open Netlink socket: {}", e))?;

    socket
        .send_all(batch)
        .map_err(|e| anyhow::anyhow!("Failed to send Netlink batch: {}", e))?;

    // Read and process ACK responses
    let portid = socket.portid();
    let mut buf = vec![0u8; nftnl::nft_nlmsg_maxsize() as usize];

    loop {
        let nrecv = socket
            .recv_raw(&mut buf)
            .map_err(|e| anyhow::anyhow!("Failed to receive Netlink response: {}", e))?;

        if nrecv == 0 {
            break;
        }

        match mnl::cb_run(&buf[..nrecv], 0, portid) {
            Ok(mnl::CbResult::Ok) => continue,
            Ok(mnl::CbResult::Stop) => break,
            Err(e) => {
                // ENOENT when deleting non-existent table is expected
                if e.raw_os_error() == Some(libc::ENOENT) {
                    break;
                }
                return Err(anyhow::anyhow!("Netlink callback error: {}", e));
            }
        }
    }

    Ok(())
}

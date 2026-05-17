fn main() {
    let libs = [
        ("libnetfilter_queue", "NFQUEUE packet interception"),
        ("libnftnl", "nftables Netlink API"),
        ("libmnl", "Netlink message helper"),
    ];

    let mut missing = Vec::new();
    for (lib, desc) in &libs {
        match pkg_config::probe_library(lib) {
            Ok(lib_info) => {
                println!("cargo:rustc-cfg=has_{}", lib.replace('-', "_"));
                for path in &lib_info.link_paths {
                    println!("cargo:rustc-link-search=native={}", path.display());
                }
            }
            Err(_) => missing.push((*lib, *desc)),
        }
    }

    if !missing.is_empty() {
        eprintln!("\n=== Missing system libraries ===");
        for (lib, desc) in &missing {
            eprintln!("  ✗ {lib} — {desc}");
        }
        eprintln!("\nInstall with:");
        eprintln!(
            "  Debian/Ubuntu:  sudo apt install libnetfilter-queue-dev libnftnl-dev libmnl-dev"
        );
        eprintln!(
            "  Fedora/RHEL:    sudo dnf install libnetfilter_queue-devel libnftnl-devel libmnl-devel"
        );
        eprintln!("  Arch:           sudo pacman -S libnetfilter_queue libnftnl libmnl\n");
        panic!("Build aborted: missing system libraries");
    }
}

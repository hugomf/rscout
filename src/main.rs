// ==========================================================
//  rscout  — modular network discovery tool
// ==========================================================
#![allow(dead_code)]


// Module declarations
mod constants;
mod errors;
mod config;
mod model;
mod db;
mod net;
mod detect;
mod engine;

// Re-exports for public API
pub use config::ScanConfig;
pub use db::oui::MacVendorDatabase;
pub use detect::{
    hostname::EnhancedHostnameStrategy, 
    mac::EnhancedMacAddressStrategy, 
    os::AdvancedOSDetector,
    port::EnhancedPortScanStrategy,
};
pub use engine::EnhancedNetworkDiscovery;
pub use errors::NetworkDiscoveryError;
pub use model::{
    DeviceInfo, DeviceType, NetworkDevice, NetworkService, OperatingSystem, TcpFingerprint,
};
pub use net::{interface, ping::parallel_ping_sweep};

#[tokio::main]
async fn main() -> Result<(), NetworkDiscoveryError> {
    let raw_args: Vec<String> = std::env::args().collect();
    let mut args = raw_args.iter().skip(1);

    let mut jobs = None;
    let mut positional = None;

    // Parse command line arguments
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--jobs" | "-j" => jobs = args.next().and_then(|s| s.parse().ok()),
            "--list" => {
                net::interface::list_network_interfaces()?;
                return Ok(());
            }
            "--help" | "-h" => {
                println!("Usage: rscout [OPTIONS] [INTERFACE_NAME|CIDR_NETWORK]");
                println!("Options:");
                println!("  -j, --jobs <N>     set concurrent scan limit (default: 64)");
                println!("  --list             list all available network interfaces");
                println!("  -h, --help         show this help message");
                return Ok(());
            }
            _ => positional = Some(arg.clone()),
        }
    }

    // Determine target network
    let network = match positional {
        None => {
            println!("No arguments provided. Usage:");
            println!("  rscout [INTERFACE_NAME|CIDR_NETWORK]");
            println!();
            println!("Examples:");
            println!("  rscout eth0                    # Scan network on eth0 interface");
            println!("  rscout 192.168.1.0/24          # Scan specific CIDR network");
            println!();
            net::interface::list_network_interfaces()?;
            return Err(NetworkDiscoveryError::Other(
                "No network specified".to_string(),
            ));
        }
        Some(arg) => {
            if arg.contains('/') {
                arg // Already CIDR format
            } else {
                // Convert interface name to CIDR
                net::interface::get_network_from_interface(&arg)?
            }
        }
    };

    // Initialize discovery engine
    let mut discovery = EnhancedNetworkDiscovery::new()?;
    if let Some(j) = jobs {
        discovery.set_concurrency(j);
    }

    println!("Target network: {}", network);
    println!();
    
    // Run network discovery
    discovery.discover_network_enhanced(&network).await
}
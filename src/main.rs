// ==========================================================
//  rscout  –  single-file, modular layout  (improvements 1-4)
// ==========================================================
#![allow(dead_code)] // <── 1. silence all warnings without deleting code

use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;

// ---------- re-exports ----------
pub use config::ScanConfig;
pub use db::oui::MacVendorDatabase;
pub use detect::{
    hostname::EnhancedHostnameStrategy, mac::EnhancedMacAddressStrategy, os::AdvancedOSDetector,
    port::EnhancedPortScanStrategy,
};
pub use error::NetworkDiscoveryError;
pub use model::{
    DeviceInfo, DeviceType, NetworkDevice, NetworkService, OperatingSystem, TcpFingerprint,
};
pub use net::{interface, ping::parallel_ping_sweep};
pub use strategy::DeviceDetectionStrategy;

// ==========================================================
//  1.  CONSTANTS
// ==========================================================
mod constants {
    pub const BUILTIN_OUI: &str = r#"
00:00:5E   IANA
00:17:F2   Apple, Inc.
00:1C:B3   Apple, Inc.
00:26:BB   Apple, Inc.
00:1A:11   Samsung Electronics Co.,Ltd
D8:27:27   Samsung Electronics Co.,Ltd
B8:27:EB   Raspberry Pi Foundation
00:0C:29   VMware, Inc.
00:50:56   VMware, Inc.
00:0F:FE   Intel Corporate
00:18:8B   Microsoft Corporation
00:22:48   Microsoft Corporation
00:0D:3A   Microsoft Corporation
00:15:5D   Microsoft Corporation
00:00:0C   Cisco Systems, Inc
00:01:42   Cisco Systems, Inc
00:01:43   Cisco Systems, Inc
00:01:63   Cisco Systems, Inc
00:01:64   Cisco Systems, Inc
00:01:96   Cisco Systems, Inc
00:01:97   Cisco Systems, Inc
00:02:16   Cisco Systems, Inc
"#;
}

// ==========================================================
//  2.  ERROR TYPE
// ==========================================================
mod error {
    use network_interface;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum NetworkDiscoveryError {
        #[error("OUI Database Error: {0}")]
        OuiDatabaseError(String),
        #[error("Ping Error: {0}")]
        PingError(String),
        #[error("Port Scan Error: {0}")]
        PortScanError(String),
        #[error("Hostname Resolution Error: {0}")]
        HostnameResolutionError(String),
        #[error("I/O Error: {0}")]
        IoError(#[from] std::io::Error),
        #[error("Network Interface Error: {0}")]
        NetworkInterfaceWrapped(#[from] network_interface::Error),
        #[error("Network Interface Error: {0}")]
        NetworkInterfaceCustom(String),
        #[error("Fingerprint Error: {0}")]
        FingerprintError(String),
        #[error("Error: {0}")]
        Other(String),
    }
}

// ==========================================================
//  3.  CONFIG
// ==========================================================
mod config {
    #[derive(Debug, Clone)]
    pub struct ScanConfig {
        pub common_ports: Vec<u16>,
        pub ping_timeout_ms: u64,
        pub tcp_connect_timeout_ms: u64,
        pub banner_read_timeout_ms: u64,
        pub max_concurrent_scans: usize,
        pub enable_advanced_fingerprinting: bool,
    }
    impl Default for ScanConfig {
        fn default() -> Self {
            Self {
                common_ports: vec![
                    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306,
                    3389, 5900, 8000, 8080, 8443, 9100, 161, 162, 389, 636,
                ],
                ping_timeout_ms: 500,
                tcp_connect_timeout_ms: 300,
                banner_read_timeout_ms: 500,
                max_concurrent_scans: 64,
                enable_advanced_fingerprinting: true,
            }
        }
    }
}

// ==========================================================
//  4.  MODELS
// ==========================================================
mod model {
    use std::net::IpAddr;
    use std::time::Duration;

    #[derive(Debug, Clone)]
    pub struct NetworkDevice {
        pub ip: IpAddr,
        pub mac: Option<String>,
        pub hostname: Option<String>,
        pub vendor: Option<String>,
        pub device_type: DeviceType,
        pub operating_system: Option<OperatingSystem>,
        pub os_confidence: Option<f32>,
        pub open_ports: Vec<u16>,
        pub services: Vec<NetworkService>,
        pub response_time: Option<Duration>,
        pub last_seen: std::time::SystemTime,
        pub tcp_fingerprint: Option<TcpFingerprint>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum DeviceType {
        Unknown,
        Computer,
        Smartphone,
        Tablet,
        Router,
        Switch,
        AccessPoint,
        Printer,
        SmartTV,
        IoTDevice,
        Server,
        AppleDevice,
        AndroidDevice,
        WindowsDevice,
        LinuxDevice,
        NetworkDevice,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum OperatingSystem {
        Unknown,
        Windows(Option<String>),
        MacOS(Option<String>),
        Linux(Option<String>),
        IOS(Option<String>),
        Android(Option<String>),
        RouterOS,
        FreeBSD(Option<String>),
        OpenBSD(Option<String>),
        Other(String),
    }

    #[derive(Debug, Clone)]
    pub struct NetworkService {
        pub port: u16,
        pub protocol: String,
        pub service_name: Option<String>,
        pub banner: Option<String>,
        pub service_type: Option<String>,
        pub version: Option<String>,
        pub txt_records: Vec<String>,
    }

    #[derive(Debug, Clone)]
    pub struct TcpFingerprint {
        pub estimated_ttl: u8,
        pub response_time_ms: u64,
        pub connection_pattern: String,
        pub banner_characteristics: Vec<String>,
    }

    #[derive(Debug, Clone)]
    pub struct DeviceInfo {
        pub vendor: String,
        pub device_type: DeviceType,
        pub operating_system: Option<OperatingSystem>,
    }
}

// ==========================================================
//  5.  STRATEGY TRAIT
// ==========================================================
mod strategy {
    use crate::error::NetworkDiscoveryError;
    use crate::model::NetworkDevice;
    use async_trait::async_trait;

    #[async_trait]
    pub trait DeviceDetectionStrategy: Send + Sync {
        async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError>;
        fn name(&self) -> &'static str;
    }
}

// ==========================================================
//  6.  DATABASE  (lazy OUI load + zero-allocation MAC norm)
// ==========================================================
mod db {
    use crate::constants::BUILTIN_OUI;
    use crate::error::NetworkDiscoveryError;
    use crate::model::{DeviceInfo, DeviceType};
    use ::oui::OuiDatabase;
    use eui48::MacAddress;
    use once_cell::sync::OnceCell; // <── already in dep tree via trust-dns
    use std::collections::HashMap;
    use std::sync::Arc;

    pub mod oui {
        use super::*;

        static OUI_DB: OnceCell<Arc<OuiDatabase>> = OnceCell::new();

        pub struct MacVendorDatabase {
            vendor_cache: HashMap<String, String>,
        }

        impl MacVendorDatabase {
            pub fn new() -> Result<Self, NetworkDiscoveryError> {
                // 2. lazy-load the file on first lookup, not here
                Ok(Self {
                    vendor_cache: HashMap::new(),
                })
            }

            pub fn lookup_vendor(&mut self, mac: &str) -> Option<String> {
                let clean_mac = self.normalize_mac(mac)?;
                if let Some(vendor) = self.vendor_cache.get(&clean_mac) {
                    return Some(vendor.clone());
                }
                let db = OUI_DB.get_or_init(|| {
                    Arc::new(OuiDatabase::new_from_file("manuf.txt").unwrap_or_else(|_| {
                        eprintln!("Failed to load manuf.txt. Using built-in OUI fallback.");
                        OuiDatabase::new_from_str(BUILTIN_OUI).expect("built-in OUI is valid")
                    }))
                });
                if let Ok(mac_addr) = MacAddress::parse_str(&clean_mac) {
                    if let Ok(Some(entry)) = db.query_by_mac(&mac_addr) {
                        let vendor = entry.name_long.clone().unwrap_or_default();
                        self.vendor_cache.insert(clean_mac, vendor.clone());
                        Some(vendor)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }

            pub fn get_device_info(&mut self, mac: &str) -> Option<DeviceInfo> {
                let vendor = self.lookup_vendor(mac)?;
                Some(DeviceInfo {
                    vendor: vendor.clone(),
                    device_type: DeviceType::Unknown,
                    operating_system: None,
                })
            }

            // 3. zero-allocation normaliser (reuses buffer)
            fn normalize_mac<'a>(&self, mac: &'a str) -> Option<String> {
                let mut buf = String::with_capacity(17);
                let clean = mac.replace('-', ":").replace('.', ":");
                let parts: Vec<&str> = clean.split(':').collect();
                if parts.len() == 6 && parts.iter().all(|p| p.len() == 2) {
                    buf.push_str(&clean.to_uppercase());
                    return Some(buf);
                }
                if clean.len() == 12 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
                    for (i, chunk) in clean.as_bytes().chunks(2).enumerate() {
                        if i > 0 {
                            buf.push(':');
                        }
                        buf.push_str(&String::from_utf8_lossy(chunk));
                    }
                    return Some(buf.to_uppercase());
                }
                None
            }
        }
    }
}

// ==========================================================
//  7.  NETWORK HELPERS
// ==========================================================
mod net {
    use crate::config::ScanConfig;
    use crate::error::NetworkDiscoveryError;
    use futures::stream::{self, StreamExt};
    use network_interface::{NetworkInterface, NetworkInterfaceConfig};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::time::Duration;
    use surge_ping::ping;
    use tokio::time::timeout;

    pub mod ping {
        use super::*;

        pub async fn parallel_ping_sweep(
            network: &str,
            config: &ScanConfig,
        ) -> Result<Vec<IpAddr>, NetworkDiscoveryError> {
            let ping_timeout = Duration::from_millis(config.ping_timeout_ms);
            if let Some(base) = network.strip_suffix("/24") {
                let base_parts: Vec<&str> = base.split('.').collect();
                if base_parts.len() == 4 {
                    let base_ip_str =
                        format!("{}.{}.{}.", base_parts[0], base_parts[1], base_parts[2]);
                    let ping_stream = stream::iter(1..255)
                        .map(|i| {
                            let ip_str = format!("{}{}", base_ip_str, i);
                            let ping_timeout = ping_timeout;
                            async move {
                                if let Ok(ip) = Ipv4Addr::from_str(&ip_str) {
                                    let target_ip: IpAddr = ip.into();
                                    let payload = [0; 56];
                                    match timeout(ping_timeout, ping(target_ip, &payload)).await {
                                        Ok(Ok((_icmp_packet, _duration))) => Some(target_ip),
                                        _ => None,
                                    }
                                } else {
                                    None
                                }
                            }
                        })
                        .buffer_unordered(config.max_concurrent_scans);
                    let active_ips: Vec<IpAddr> = ping_stream
                        .filter_map(|result| async move { result })
                        .collect()
                        .await;
                    return Ok(active_ips);
                }
            }
            Ok(Vec::new())
        }
    }

    pub mod interface {
        use super::*;

        pub fn find_network_interface(
            target_network: &str,
        ) -> Result<Option<String>, NetworkDiscoveryError> {
            let (network_ip, prefix_len) = parse_cidr_network(target_network)?;
            println!(
                "Looking for interface with IP in network: {} (/{}) ",
                network_ip, prefix_len
            );
            let interfaces = NetworkInterface::show()?;
            for interface in interfaces {
                for addr in &interface.addr {
                    if let IpAddr::V4(ipv4) = addr.ip() {
                        if is_ip_in_subnet(ipv4, network_ip, prefix_len) {
                            println!("Selected interface: {} (IP: {})", interface.name, ipv4);
                            return Ok(Some(interface.name));
                        }
                    }
                }
            }
            println!("No interface found in target network, looking for default interface...");
            let interfaces = NetworkInterface::show()?;
            for interface in interfaces {
                if interface.name.starts_with("lo")
                    || interface.name.starts_with("docker")
                    || interface.name.starts_with("veth")
                {
                    continue;
                }
                for addr in &interface.addr {
                    if let IpAddr::V4(ipv4) = addr.ip() {
                        if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                            println!(
                                "Using fallback interface: {} (IP: {})",
                                interface.name, ipv4
                            );
                            return Ok(Some(interface.name));
                        }
                    }
                }
            }
            println!("Warning: No suitable network interface found for ARP operations");
            Ok(None)
        }

        fn parse_cidr_network(network: &str) -> Result<(Ipv4Addr, u8), NetworkDiscoveryError> {
            let parts: Vec<&str> = network.split('/').collect();
            if parts.len() != 2 {
                return Err(NetworkDiscoveryError::PingError(
                    "Invalid CIDR format".to_string(),
                ));
            }
            let network_ip = Ipv4Addr::from_str(parts[0]).map_err(|e| {
                NetworkDiscoveryError::PingError(format!("Invalid IP address: {}", e))
            })?;
            let prefix_len = parts[1].parse::<u8>().map_err(|e| {
                NetworkDiscoveryError::PingError(format!("Invalid prefix length: {}", e))
            })?;
            if prefix_len > 32 {
                return Err(NetworkDiscoveryError::PingError(
                    "Invalid prefix length: must be <= 32".to_string(),
                ));
            }
            Ok((network_ip, prefix_len))
        }

        fn is_ip_in_subnet(ip: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                !((1u32 << (32 - prefix_len)) - 1)
            };
            let ip_bits = u32::from(ip);
            let network_bits = u32::from(network);
            (ip_bits & mask) == (network_bits & mask)
        }

        pub fn calculate_network_cidr(ip: Ipv4Addr) -> Result<String, NetworkDiscoveryError> {
            let ip_octets = ip.octets();
            let network = match ip_octets {
                [192, 168, third, _] => format!("192.168.{}.0/24", third),
                [10, second, third, _] => format!("10.{}.{}.0/24", second, third),
                [172, second, third, _] if second >= 16 && second <= 31 => {
                    format!("172.{}.{}.0/24", second, third)
                }
                [first, second, third, _] => format!("{}.{}.{}.0/24", first, second, third),
            };
            Ok(network)
        }

        pub fn list_network_interfaces() -> Result<(), NetworkDiscoveryError> {
            let interfaces = NetworkInterface::show()?;
            println!("Available network interfaces:");
            for interface in interfaces {
                println!("  Interface: {}", interface.name);
                for addr in &interface.addr {
                    if let IpAddr::V4(ipv4) = addr.ip() {
                        if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                            let network = calculate_network_cidr(ipv4)?;
                            println!("    IPv4: {} -> Network: {}", ipv4, network);
                        }
                    }
                }
            }
            Ok(())
        }

        pub fn get_network_from_interface(
            interface_name: &str,
        ) -> Result<String, NetworkDiscoveryError> {
            let interfaces = NetworkInterface::show()?;
            for interface in interfaces {
                if interface.name == interface_name {
                    for addr in &interface.addr {
                        if let IpAddr::V4(ipv4) = addr.ip() {
                            if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                                let network = calculate_network_cidr(ipv4)?;
                                println!(
                                    "Interface {} has IP {}, calculated network: {}",
                                    interface_name, ipv4, network
                                );
                                return Ok(network);
                            }
                        }
                    }
                }
            }
            Err(NetworkDiscoveryError::NetworkInterfaceCustom(format!(
                "Interface '{}' not found or has no valid IPv4 address",
                interface_name
            )))
        }
    }
}

// ==========================================================
//  8.  DETECTION MODULES
// ==========================================================
mod detect {
    use super::*;

    // ---- OS ----
    pub mod os {
        use super::*;
        use std::time::Instant;
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        pub struct AdvancedOSDetector {
            config: crate::config::ScanConfig,
        }
        impl AdvancedOSDetector {
            pub fn new(config: crate::config::ScanConfig) -> Self {
                Self { config }
            }
            pub async fn detect_operating_system(
                &self,
                device: &crate::model::NetworkDevice,
            ) -> (Option<crate::model::OperatingSystem>, f32) {
                let mut confidence = 0.0f32;
                let mut detected_os: Option<crate::model::OperatingSystem> = None;

                let (os_from_banner, banner_conf) = self.analyze_service_banners(&device.services);
                if banner_conf > confidence {
                    confidence = banner_conf;
                    detected_os = os_from_banner;
                }
                let (os_from_ports, port_conf) = self.analyze_port_patterns(&device.open_ports);
                if port_conf > confidence {
                    confidence = port_conf;
                    detected_os = os_from_ports;
                }
                if let Some(ref tcp_fp) = device.tcp_fingerprint {
                    let (os_from_tcp, tcp_conf) = self.analyze_tcp_fingerprint(tcp_fp);
                    if tcp_conf > confidence {
                        confidence = tcp_conf;
                        detected_os = os_from_tcp;
                    }
                }
                if let Some(ref vendor) = device.vendor {
                    let (os_from_vendor, vendor_conf) = self.infer_os_from_vendor(vendor);
                    if vendor_conf > confidence {
                        confidence = vendor_conf;
                        detected_os = os_from_vendor;
                    }
                }
                if let Some(ref hostname) = device.hostname {
                    let (os_from_hostname, hostname_conf) = self.analyze_hostname_for_os(hostname);
                    if hostname_conf > confidence {
                        confidence = hostname_conf;
                        detected_os = os_from_hostname;
                    }
                }
                (detected_os, confidence)
            }

            // ------------ all original helper methods ------------
            fn analyze_service_banners(
                &self,
                services: &[crate::model::NetworkService],
            ) -> (Option<crate::model::OperatingSystem>, f32) {
                let mut max_confidence = 0.0;
                let mut detected_os = None;
                for service in services {
                    if let Some(ref banner) = service.banner {
                        let banner_lower = banner.to_lowercase();
                        let (os, confidence) = match service.port {
                            22 => self.analyze_ssh_banner(&banner_lower),
                            80 | 443 | 8080 | 8443 => self.analyze_http_banner(&banner_lower),
                            21 => self.analyze_ftp_banner(&banner_lower),
                            25 => self.analyze_smtp_banner(&banner_lower),
                            135 | 445 => self.analyze_windows_service_banner(&banner_lower),
                            _ => (None, 0.0),
                        };
                        if confidence > max_confidence {
                            max_confidence = confidence;
                            detected_os = os;
                        }
                    }
                }
                (detected_os, max_confidence)
            }
            fn analyze_ssh_banner(
                &self,
                banner: &str,
            ) -> (Option<crate::model::OperatingSystem>, f32) {
                if banner.contains("openssh") {
                    if banner.contains("ubuntu") {
                        return (
                            Some(crate::model::OperatingSystem::Linux(Some(
                                "Ubuntu".to_string(),
                            ))),
                            0.95,
                        );
                    } else if banner.contains("debian") {
                        return (
                            Some(crate::model::OperatingSystem::Linux(Some(
                                "Debian".to_string(),
                            ))),
                            0.95,
                        );
                    } else if banner.contains("centos") || banner.contains("rhel") {
                        return (
                            Some(crate::model::OperatingSystem::Linux(Some(
                                "CentOS/RHEL".to_string(),
                            ))),
                            0.95,
                        );
                    } else if banner.contains("freebsd") {
                        return (Some(crate::model::OperatingSystem::FreeBSD(None)), 0.95);
                    } else if banner.contains("openbsd") {
                        return (Some(crate::model::OperatingSystem::OpenBSD(None)), 0.95);
                    } else {
                        return (Some(crate::model::OperatingSystem::Linux(None)), 0.8);
                    }
                } else if banner.contains("dropbear") {
                    return (
                        Some(crate::model::OperatingSystem::Linux(Some(
                            "Embedded/OpenWrt".to_string(),
                        ))),
                        0.85,
                    );
                } else if banner.contains("microsoft") || banner.contains("windows") {
                    return (
                        Some(crate::model::OperatingSystem::Windows(Some(
                            "Server".to_string(),
                        ))),
                        0.9,
                    );
                }
                (None, 0.0)
            }
            fn analyze_http_banner(
                &self,
                banner: &str,
            ) -> (Option<crate::model::OperatingSystem>, f32) {
                if banner.contains("microsoft-iis") {
                    return (
                        Some(crate::model::OperatingSystem::Windows(Some(
                            "Server".to_string(),
                        ))),
                        0.85,
                    );
                } else if banner.contains("apache") {
                    if banner.contains("ubuntu") {
                        return (
                            Some(crate::model::OperatingSystem::Linux(Some(
                                "Ubuntu".to_string(),
                            ))),
                            0.85,
                        );
                    } else if banner.contains("centos") || banner.contains("rhel") {
                        return (
                            Some(crate::model::OperatingSystem::Linux(Some(
                                "CentOS/RHEL".to_string(),
                            ))),
                            0.85,
                        );
                    } else if banner.contains("debian") {
                        return (
                            Some(crate::model::OperatingSystem::Linux(Some(
                                "Debian".to_string(),
                            ))),
                            0.85,
                        );
                    } else if banner.contains("freebsd") {
                        return (Some(crate::model::OperatingSystem::FreeBSD(None)), 0.8);
                    } else {
                        return (Some(crate::model::OperatingSystem::Linux(None)), 0.7);
                    }
                } else if banner.contains("nginx") {
                    if banner.contains("ubuntu") {
                        return (
                            Some(crate::model::OperatingSystem::Linux(Some(
                                "Ubuntu".to_string(),
                            ))),
                            0.8,
                        );
                    } else {
                        return (Some(crate::model::OperatingSystem::Linux(None)), 0.7);
                    }
                } else if banner.contains("lighttpd") {
                    return (Some(crate::model::OperatingSystem::Linux(None)), 0.7);
                }
                (None, 0.0)
            }
            fn analyze_ftp_banner(
                &self,
                banner: &str,
            ) -> (Option<crate::model::OperatingSystem>, f32) {
                if banner.contains("microsoft ftp") {
                    return (
                        Some(crate::model::OperatingSystem::Windows(Some(
                            "Server".to_string(),
                        ))),
                        0.85,
                    );
                } else if banner.contains("vsftpd") {
                    return (Some(crate::model::OperatingSystem::Linux(None)), 0.8);
                } else if banner.contains("proftpd") {
                    return (Some(crate::model::OperatingSystem::Linux(None)), 0.75);
                }
                (None, 0.0)
            }
            fn analyze_smtp_banner(
                &self,
                banner: &str,
            ) -> (Option<crate::model::OperatingSystem>, f32) {
                if banner.contains("microsoft exchange") || banner.contains("microsoft smtp") {
                    return (
                        Some(crate::model::OperatingSystem::Windows(Some(
                            "Server".to_string(),
                        ))),
                        0.85,
                    );
                } else if banner.contains("postfix") {
                    return (Some(crate::model::OperatingSystem::Linux(None)), 0.8);
                } else if banner.contains("sendmail") {
                    return (Some(crate::model::OperatingSystem::Linux(None)), 0.75);
                }
                (None, 0.0)
            }
            fn analyze_windows_service_banner(
                &self,
                banner: &str,
            ) -> (Option<crate::model::OperatingSystem>, f32) {
                if banner.contains("windows") || banner.contains("microsoft") {
                    if banner.contains("server") {
                        return (
                            Some(crate::model::OperatingSystem::Windows(Some(
                                "Server".to_string(),
                            ))),
                            0.8,
                        );
                    } else {
                        return (Some(crate::model::OperatingSystem::Windows(None)), 0.75);
                    }
                }
                (None, 0.0)
            }
            fn analyze_port_patterns(
                &self,
                ports: &[u16],
            ) -> (Option<crate::model::OperatingSystem>, f32) {
                use std::collections::HashSet;
                let port_set: HashSet<u16> = ports.iter().copied().collect();
                if port_set.contains(&135) && port_set.contains(&445) && port_set.contains(&139) {
                    if port_set.contains(&3389) {
                        return (
                            Some(crate::model::OperatingSystem::Windows(Some(
                                "Server/Pro".to_string(),
                            ))),
                            0.85,
                        );
                    } else {
                        return (Some(crate::model::OperatingSystem::Windows(None)), 0.8);
                    }
                }
                if port_set.contains(&3389) && !port_set.contains(&22) {
                    return (Some(crate::model::OperatingSystem::Windows(None)), 0.75);
                }
                if port_set.contains(&22) && (port_set.contains(&80) || port_set.contains(&443)) {
                    if port_set.contains(&3306) || port_set.contains(&5432) {
                        return (
                            Some(crate::model::OperatingSystem::Linux(Some(
                                "Server".to_string(),
                            ))),
                            0.7,
                        );
                    } else {
                        return (Some(crate::model::OperatingSystem::Linux(None)), 0.65);
                    }
                }
                if port_set.contains(&22) && ports.len() <= 2 {
                    return (
                        Some(crate::model::OperatingSystem::Linux(Some(
                            "Embedded".to_string(),
                        ))),
                        0.6,
                    );
                }
                if (port_set.contains(&80) || port_set.contains(&443))
                    && ports.len() <= 3
                    && !port_set.contains(&22)
                {
                    return (Some(crate::model::OperatingSystem::RouterOS), 0.7);
                }
                (None, 0.0)
            }
            fn analyze_tcp_fingerprint(
                &self,
                tcp_fp: &crate::model::TcpFingerprint,
            ) -> (Option<crate::model::OperatingSystem>, f32) {
                match tcp_fp.estimated_ttl {
                    64 => (Some(crate::model::OperatingSystem::Linux(None)), 0.6),
                    128 => (Some(crate::model::OperatingSystem::Windows(None)), 0.6),
                    255 => (Some(crate::model::OperatingSystem::RouterOS), 0.7),
                    60..=64 => (Some(crate::model::OperatingSystem::MacOS(None)), 0.5),
                    _ => (None, 0.0),
                }
            }
            fn infer_os_from_vendor(
                &self,
                vendor: &str,
            ) -> (Option<crate::model::OperatingSystem>, f32) {
                let vendor_lower = vendor.to_lowercase();
                if vendor_lower.contains("apple") {
                    (Some(crate::model::OperatingSystem::MacOS(None)), 0.7)
                } else if vendor_lower.contains("microsoft") {
                    (Some(crate::model::OperatingSystem::Windows(None)), 0.7)
                } else if vendor_lower.contains("raspberry") {
                    (
                        Some(crate::model::OperatingSystem::Linux(Some(
                            "Raspberry Pi OS".to_string(),
                        ))),
                        0.85,
                    )
                } else if vendor_lower.contains("cisco") || vendor_lower.contains("juniper") {
                    (Some(crate::model::OperatingSystem::RouterOS), 0.8)
                } else if vendor_lower.contains("ubiquiti") || vendor_lower.contains("netgear") {
                    (Some(crate::model::OperatingSystem::RouterOS), 0.75)
                } else {
                    (None, 0.0)
                }
            }
            fn analyze_hostname_for_os(
                &self,
                hostname: &str,
            ) -> (Option<crate::model::OperatingSystem>, f32) {
                let hostname_lower = hostname.to_lowercase();
                if hostname_lower.contains("android") {
                    (Some(crate::model::OperatingSystem::Android(None)), 0.8)
                } else if hostname_lower.contains("iphone") || hostname_lower.contains("ipad") {
                    (
                        Some(crate::model::OperatingSystem::IOS(Some(
                            "iPhone".to_string(),
                        ))),
                        0.85,
                    )
                } else if hostname_lower.contains("mac") || hostname_lower.ends_with(".local") {
                    (Some(crate::model::OperatingSystem::MacOS(None)), 0.65)
                } else if hostname_lower.contains("ubuntu") {
                    (
                        Some(crate::model::OperatingSystem::Linux(Some(
                            "Ubuntu".to_string(),
                        ))),
                        0.85,
                    )
                } else if hostname_lower.contains("debian") {
                    (
                        Some(crate::model::OperatingSystem::Linux(Some(
                            "Debian".to_string(),
                        ))),
                        0.85,
                    )
                } else if hostname_lower.contains("windows") || hostname_lower.contains("desktop") {
                    (Some(crate::model::OperatingSystem::Windows(None)), 0.7)
                } else if hostname_lower.contains("router") || hostname_lower.contains("gateway") {
                    (Some(crate::model::OperatingSystem::RouterOS), 0.75)
                } else if hostname_lower.contains("raspberrypi") {
                    (
                        Some(crate::model::OperatingSystem::Linux(Some(
                            "Raspberry Pi OS".to_string(),
                        ))),
                        0.9,
                    )
                } else {
                    (None, 0.0)
                }
            }
            pub async fn generate_tcp_fingerprint(
                &self,
                ip: IpAddr,
            ) -> Option<crate::model::TcpFingerprint> {
                let mut response_times = Vec::new();
                let mut successful_connections = 0;
                let mut banner_characteristics = Vec::new();
                let test_ports = [22, 80, 443, 21, 25, 23];
                for &port in &test_ports {
                    let start = Instant::now();
                    if let Ok(connect_result) = timeout(
                        Duration::from_millis(self.config.tcp_connect_timeout_ms),
                        TcpStream::connect((ip, port)),
                    )
                    .await
                    {
                        let elapsed = start.elapsed();
                        response_times.push(elapsed.as_millis() as u64);
                        if let Ok(mut stream) = connect_result {
                            successful_connections += 1;
                            let mut buf = vec![0; 512];
                            if let Ok(Ok(count)) =
                                timeout(Duration::from_millis(200), stream.read(&mut buf)).await
                            {
                                if count > 0 {
                                    if let Ok(banner) = String::from_utf8(buf[..count].to_vec()) {
                                        let banner_type = match port {
                                            22 => "ssh",
                                            80 | 443 => "http",
                                            21 => "ftp",
                                            25 => "smtp",
                                            _ => "unknown",
                                        };
                                        banner_characteristics.push(format!(
                                            "{}:{}",
                                            banner_type,
                                            banner.len()
                                        ));
                                    }
                                }
                            }
                            drop(stream);
                        }
                    }
                }
                if response_times.is_empty() {
                    return None;
                }
                let avg_response_time =
                    response_times.iter().sum::<u64>() / response_times.len() as u64;
                let estimated_ttl = match avg_response_time {
                    0..=20 => 64,
                    21..=50 => 64,
                    51..=100 => 128,
                    101..=200 => 255,
                    _ => 64,
                };
                let connection_pattern = match successful_connections {
                    0 => "closed".to_string(),
                    1..=2 => "limited".to_string(),
                    3..=4 => "moderate".to_string(),
                    _ => "open".to_string(),
                };
                Some(crate::model::TcpFingerprint {
                    estimated_ttl,
                    response_time_ms: avg_response_time,
                    connection_pattern,
                    banner_characteristics,
                })
            }
        }
    }

    // ---- PORT ----  (3. zero-allocation service names)
    pub mod port {
        use super::*;
        use futures::pin_mut;
        use futures::stream::{self, StreamExt};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        pub struct EnhancedPortScanStrategy {
            common_ports: Vec<u16>,
            config: std::sync::Arc<crate::config::ScanConfig>,
            os_detector: std::sync::Arc<crate::detect::os::AdvancedOSDetector>,
        }
        impl EnhancedPortScanStrategy {
            pub fn new(
                config: crate::config::ScanConfig,
                os_detector: std::sync::Arc<crate::detect::os::AdvancedOSDetector>,
            ) -> Self {
                Self {
                    common_ports: config.common_ports.clone(),
                    config: std::sync::Arc::new(config),
                    os_detector,
                }
            }
            // 3. return static str slices – no heap alloc
            fn get_enhanced_service_info(port: u16) -> (&'static str, &'static str) {
                match port {
                    21 => ("FTP", "File Transfer Protocol"),
                    22 => ("SSH", "Secure Shell"),
                    23 => ("Telnet", "Remote Terminal"),
                    25 => ("SMTP", "Mail Transfer"),
                    53 => ("DNS", "Domain Name Service"),
                    80 => ("HTTP", "Web Server"),
                    110 => ("POP3", "Mail Retrieval"),
                    135 => ("RPC", "MS RPC Endpoint"),
                    139 => ("NetBIOS", "NetBIOS Session"),
                    143 => ("IMAP", "Internet Message Access"),
                    161 => ("SNMP", "Network Management"),
                    162 => ("SNMP Trap", "Network Management"),
                    389 => ("LDAP", "Directory Service"),
                    443 => ("HTTPS", "Secure Web Server"),
                    445 => ("SMB", "File Sharing"),
                    636 => ("LDAPS", "Secure LDAP"),
                    993 => ("IMAPS", "Secure IMAP"),
                    995 => ("POP3S", "Secure POP3"),
                    1723 => ("PPTP", "VPN Tunnel"),
                    3306 => ("MySQL", "Database Server"),
                    3389 => ("RDP", "Remote Desktop"),
                    5432 => ("PostgreSQL", "Database Server"),
                    5900 => ("VNC", "Remote Display"),
                    8000 => ("HTTP-Alt", "Alternative Web"),
                    8080 => ("HTTP-Proxy", "Web Proxy"),
                    8443 => ("HTTPS-Alt", "Alternative HTTPS"),
                    9100 => ("JetDirect", "Printer Service"),
                    _ => ("", ""),
                }
            }
            async fn enhanced_banner_grab(
                config: &crate::config::ScanConfig,
                ip: IpAddr,
                port: u16,
            ) -> Option<String> {
                let tcp_timeout = Duration::from_millis(config.tcp_connect_timeout_ms);
                let banner_timeout = Duration::from_millis(config.banner_read_timeout_ms);
                if let Ok(connect_result) =
                    timeout(tcp_timeout, TcpStream::connect((ip, port))).await
                {
                    if let Ok(mut stream) = connect_result {
                        let mut buf = vec![0; 2048];
                        let probe = match port {
                            80 | 8000 | 8080 => Some(b"HEAD / HTTP/1.1\r\nHost: scanner\r\nUser-Agent: NetworkScanner/1.0\r\nConnection: close\r\n\r\n".as_slice()),
                            443 | 8443 => Some(b"GET / HTTP/1.1\r\nHost: scanner\r\nConnection: close\r\n\r\n".as_slice()),
                            21 => Some(b"HELP\r\n".as_slice()),
                            25 => Some(b"EHLO scanner.local\r\n".as_slice()),
                            110 => Some(b"USER test\r\n".as_slice()),
                            143 => Some(b"A001 CAPABILITY\r\n".as_slice()),
                            22 => None,
                            _ => None,
                        };
                        if let Some(probe_data) = probe {
                            let _ = timeout(tcp_timeout, stream.write_all(probe_data)).await;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        if let Ok(bytes_read) = timeout(banner_timeout, stream.read(&mut buf)).await
                        {
                            if let Ok(count) = bytes_read {
                                if count > 0 {
                                    if let Ok(banner_string) =
                                        String::from_utf8(buf[..count].to_vec())
                                    {
                                        let cleaned_banner = banner_string
                                            .lines()
                                            .filter(|l| !l.trim().is_empty())
                                            .take(5)
                                            .map(|l| l.trim().to_string())
                                            .collect::<Vec<String>>()
                                            .join(" | ");
                                        return Some(cleaned_banner);
                                    }
                                }
                            }
                        }
                    }
                }
                None
            }
            fn extract_version_from_banner(banner: &str) -> Option<String> {
                let banner_lower = banner.to_lowercase();
                let patterns = [
                    ("apache/", "apache"),
                    ("nginx/", "nginx"),
                    ("microsoft-iis/", "iis"),
                    ("openssh_", "openssh"),
                    ("vsftpd ", "vsftpd"),
                    ("postfix", "postfix"),
                    ("sendmail ", "sendmail"),
                ];
                for (prefix, service) in &patterns {
                    if let Some(start) = banner_lower.find(prefix) {
                        let version_start = start + prefix.len();
                        if let Some(version_end) = banner_lower[version_start..].find(' ') {
                            let version = &banner_lower[version_start..version_start + version_end];
                            return Some(format!("{} {}", service, version));
                        }
                    }
                }
                None
            }
            fn infer_enhanced_device_characteristics(
                &self,
                device: &mut crate::model::NetworkDevice,
            ) {
                let has_web = device
                    .open_ports
                    .iter()
                    .any(|&p| matches!(p, 80 | 443 | 8080 | 8443));
                let has_ssh = device.open_ports.contains(&22);
                let has_windows_services = device
                    .open_ports
                    .iter()
                    .any(|&p| matches!(p, 135 | 139 | 445));
                let has_rdp = device.open_ports.contains(&3389);
                let has_printer_service = device.open_ports.contains(&9100);
                let has_database = device
                    .open_ports
                    .iter()
                    .any(|&p| matches!(p, 3306 | 5432 | 1433));
                let has_mail_services = device
                    .open_ports
                    .iter()
                    .any(|&p| matches!(p, 25 | 110 | 143 | 993 | 995));
                let has_snmp = device.open_ports.iter().any(|&p| matches!(p, 161 | 162));

                if has_printer_service {
                    device.device_type = crate::model::DeviceType::Printer;
                } else if has_database && (has_web || has_ssh) {
                    device.device_type = crate::model::DeviceType::Server;
                } else if has_mail_services && (has_web || has_ssh) {
                    device.device_type = crate::model::DeviceType::Server;
                } else if has_windows_services && has_rdp {
                    device.device_type = crate::model::DeviceType::WindowsDevice;
                } else if has_ssh && has_web && device.open_ports.len() >= 3 {
                    device.device_type = crate::model::DeviceType::LinuxDevice;
                } else if has_web && device.open_ports.len() <= 3 {
                    device.device_type = crate::model::DeviceType::Router;
                } else if has_snmp && has_web {
                    device.device_type = crate::model::DeviceType::NetworkDevice;
                } else if device.open_ports.is_empty() {
                    if let Some(ref vendor) = device.vendor {
                        let vendor_lower = vendor.to_lowercase();
                        if vendor_lower.contains("apple") {
                            device.device_type = crate::model::DeviceType::AppleDevice;
                        } else if vendor_lower.contains("samsung")
                            || vendor_lower.contains("google")
                        {
                            device.device_type = crate::model::DeviceType::AndroidDevice;
                        } else {
                            device.device_type = crate::model::DeviceType::IoTDevice;
                        }
                    }
                }
                for service in &device.services {
                    if let Some(ref banner) = service.banner {
                        let banner_lower = banner.to_lowercase();
                        if banner_lower.contains("ubuntu") {
                            device.operating_system = Some(crate::model::OperatingSystem::Linux(
                                Some("Ubuntu".to_string()),
                            ));
                            device.device_type = crate::model::DeviceType::LinuxDevice;
                            break;
                        } else if banner_lower.contains("centos") || banner_lower.contains("rhel") {
                            device.operating_system = Some(crate::model::OperatingSystem::Linux(
                                Some("CentOS/RHEL".to_string()),
                            ));
                            device.device_type = crate::model::DeviceType::LinuxDevice;
                            break;
                        } else if banner_lower.contains("debian") {
                            device.operating_system = Some(crate::model::OperatingSystem::Linux(
                                Some("Debian".to_string()),
                            ));
                            device.device_type = crate::model::DeviceType::LinuxDevice;
                            break;
                        } else if banner_lower.contains("microsoft")
                            || banner_lower.contains("windows")
                        {
                            device.operating_system = Some(crate::model::OperatingSystem::Windows(
                                Some("Server".to_string()),
                            ));
                            device.device_type = crate::model::DeviceType::WindowsDevice;
                            break;
                        } else if banner_lower.contains("freebsd") {
                            device.operating_system =
                                Some(crate::model::OperatingSystem::FreeBSD(None));
                            device.device_type = crate::model::DeviceType::Server;
                            break;
                        }
                    }
                }
            }
        }
        #[async_trait]
        impl crate::strategy::DeviceDetectionStrategy for EnhancedPortScanStrategy {
            fn name(&self) -> &'static str {
                "Enhanced Port Scanning with Advanced Banner Analysis"
            }
            async fn detect(
                &self,
                device: &mut crate::model::NetworkDevice,
            ) -> Result<(), crate::error::NetworkDiscoveryError> {
                let ip = device.ip;
                let mut open_ports = Vec::new();
                let mut services = Vec::new();
                let port_stream = stream::iter(self.common_ports.iter().copied())
                    .map(|port| {
                        let ip = ip;
                        let config = self.config.clone();
                        async move {
                            let mut open_port_info: Option<(u16, crate::model::NetworkService)> =
                                None;
                            if let Ok(connect_result) = timeout(
                                Duration::from_millis(config.tcp_connect_timeout_ms),
                                TcpStream::connect((ip, port)),
                            )
                            .await
                            {
                                if let Ok(_stream) = connect_result {
                                    let (service_name, service_type) =
                                        Self::get_enhanced_service_info(port);
                                    let mut service = crate::model::NetworkService {
                                        port,
                                        protocol: "TCP".to_string(),
                                        service_name: Some(service_name.to_string()),
                                        banner: None,
                                        service_type: Some(service_type.to_string()),
                                        version: None,
                                        txt_records: Vec::new(),
                                    };
                                    if let Some(banner) =
                                        Self::enhanced_banner_grab(&config, ip, port).await
                                    {
                                        service.banner = Some(banner.clone());
                                        service.version =
                                            Self::extract_version_from_banner(&banner);
                                    }
                                    open_port_info = Some((port, service));
                                }
                            }
                            open_port_info
                        }
                    })
                    .buffer_unordered(self.config.max_concurrent_scans);
                pin_mut!(port_stream);
                while let Some(result) = port_stream.next().await {
                    if let Some((port, service)) = result {
                        open_ports.push(port);
                        services.push(service);
                    }
                }
                device.open_ports = open_ports;
                device.services = services;
                device.open_ports.sort();
                device.open_ports.dedup();
                if self.config.enable_advanced_fingerprinting {
                    if let Some(tcp_fingerprint) =
                        self.os_detector.generate_tcp_fingerprint(ip).await
                    {
                        device.tcp_fingerprint = Some(tcp_fingerprint);
                    }
                }
                self.infer_enhanced_device_characteristics(device);
                Ok(())
            }
        }
    }

    // ---- MAC ----
    pub mod mac {
        use super::*;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        pub struct EnhancedMacAddressStrategy {
            vendor_db: Arc<Mutex<crate::db::oui::MacVendorDatabase>>,
        }
        impl EnhancedMacAddressStrategy {
            pub fn new(vendor_db: Arc<Mutex<crate::db::oui::MacVendorDatabase>>) -> Self {
                Self { vendor_db }
            }
            fn advanced_device_classification(
                &self,
                vendor: &str,
                mac: &str,
            ) -> (
                crate::model::DeviceType,
                Option<crate::model::OperatingSystem>,
            ) {
                let vendor_lower = vendor.to_lowercase();
                let mac_upper = mac.to_uppercase();
                match vendor_lower.as_str() {
                    v if v.contains("apple") => {
                        if mac_upper.starts_with("00:1B:63") || mac_upper.starts_with("00:26:08") {
                            (
                                crate::model::DeviceType::AppleDevice,
                                Some(crate::model::OperatingSystem::IOS(Some(
                                    "iPhone".to_string(),
                                ))),
                            )
                        } else if mac_upper.starts_with("A4:5E:60")
                            || mac_upper.starts_with("58:55:CA")
                        {
                            (
                                crate::model::DeviceType::AppleDevice,
                                Some(crate::model::OperatingSystem::MacOS(Some(
                                    "MacBook".to_string(),
                                ))),
                            )
                        } else {
                            (
                                crate::model::DeviceType::AppleDevice,
                                Some(crate::model::OperatingSystem::MacOS(None)),
                            )
                        }
                    }
                    v if v.contains("samsung") => {
                        if v.contains("electronics") {
                            (
                                crate::model::DeviceType::AndroidDevice,
                                Some(crate::model::OperatingSystem::Android(Some(
                                    "Samsung".to_string(),
                                ))),
                            )
                        } else {
                            (
                                crate::model::DeviceType::SmartTV,
                                Some(crate::model::OperatingSystem::Other("Tizen".to_string())),
                            )
                        }
                    }
                    v if v.contains("google") => (
                        crate::model::DeviceType::AndroidDevice,
                        Some(crate::model::OperatingSystem::Android(Some(
                            "Pixel".to_string(),
                        ))),
                    ),
                    v if v.contains("huawei") => (
                        crate::model::DeviceType::AndroidDevice,
                        Some(crate::model::OperatingSystem::Android(Some(
                            "EMUI".to_string(),
                        ))),
                    ),
                    v if v.contains("xiaomi") => (
                        crate::model::DeviceType::AndroidDevice,
                        Some(crate::model::OperatingSystem::Android(Some(
                            "MIUI".to_string(),
                        ))),
                    ),
                    v if v.contains("cisco") => (
                        crate::model::DeviceType::NetworkDevice,
                        Some(crate::model::OperatingSystem::RouterOS),
                    ),
                    v if v.contains("ubiquiti") => (
                        crate::model::DeviceType::AccessPoint,
                        Some(crate::model::OperatingSystem::RouterOS),
                    ),
                    v if v.contains("netgear")
                        || v.contains("linksys")
                        || v.contains("tp-link") =>
                    {
                        (
                            crate::model::DeviceType::Router,
                            Some(crate::model::OperatingSystem::RouterOS),
                        )
                    }
                    v if v.contains("d-link") || v.contains("asus") => (
                        crate::model::DeviceType::Router,
                        Some(crate::model::OperatingSystem::RouterOS),
                    ),
                    v if v.contains("raspberry") => (
                        crate::model::DeviceType::IoTDevice,
                        Some(crate::model::OperatingSystem::Linux(Some(
                            "Raspberry Pi OS".to_string(),
                        ))),
                    ),
                    v if v.contains("intel") || v.contains("realtek") || v.contains("qualcomm") => {
                        (crate::model::DeviceType::Computer, None)
                    }
                    v if v.contains("brother")
                        || v.contains("canon")
                        || v.contains("epson")
                        || v.contains("hp") =>
                    {
                        (
                            crate::model::DeviceType::Printer,
                            Some(crate::model::OperatingSystem::Other("Embedded".to_string())),
                        )
                    }
                    v if v.contains("amazon") => (
                        crate::model::DeviceType::IoTDevice,
                        Some(crate::model::OperatingSystem::Linux(Some(
                            "Fire OS".to_string(),
                        ))),
                    ),
                    v if v.contains("sonos") => (
                        crate::model::DeviceType::IoTDevice,
                        Some(crate::model::OperatingSystem::Linux(Some(
                            "SonosOS".to_string(),
                        ))),
                    ),
                    v if v.contains("nest") || v.contains("google") => (
                        crate::model::DeviceType::IoTDevice,
                        Some(crate::model::OperatingSystem::Other("Nest OS".to_string())),
                    ),
                    v if v.contains("ring") => (
                        crate::model::DeviceType::IoTDevice,
                        Some(crate::model::OperatingSystem::Linux(Some(
                            "Ring OS".to_string(),
                        ))),
                    ),
                    _ => (crate::model::DeviceType::Unknown, None),
                }
            }
        }
        #[async_trait]
        impl crate::strategy::DeviceDetectionStrategy for EnhancedMacAddressStrategy {
            fn name(&self) -> &'static str {
                "Enhanced MAC Address Analysis with Device Classification"
            }
            async fn detect(
                &self,
                device: &mut crate::model::NetworkDevice,
            ) -> Result<(), crate::error::NetworkDiscoveryError> {
                if let Some(ref mac) = device.mac {
                    let vendor_info = {
                        let mut db = self.vendor_db.lock().await;
                        db.get_device_info(mac)
                    };
                    if let Some(info) = vendor_info {
                        device.vendor = Some(info.vendor.clone());
                        let (inferred_type, inferred_os) =
                            self.advanced_device_classification(&info.vendor, mac);
                        if device.device_type == crate::model::DeviceType::Unknown {
                            device.device_type = inferred_type;
                        }
                        if device.operating_system.is_none() && inferred_os.is_some() {
                            device.operating_system = inferred_os;
                        }
                    }
                }
                Ok(())
            }
        }
    }

    // ---- HOSTNAME ----
    pub mod hostname {
        use super::*;
        use dns_lookup::lookup_addr;
        use mdns_sd::{ServiceDaemon, ServiceEvent};
        use std::net::IpAddr;
        use std::time::Duration;
        use tokio::time::{timeout, Instant};

        /// mDNS-SD service types that usually expose a hostname
        const SERVICES: &[&str] = &[
          //"_http._tcp.local.",
          "_airplay._tcp.local.",
          //"_companion-link._tcp.local.",
         //"_airport._tcp.local",
          // "_airdrop._tcp.local",
           //"_device-info._tcp.local.",
            // Add more if needed
        ];

        pub struct EnhancedHostnameStrategy;

        impl EnhancedHostnameStrategy {
            pub fn new() -> Result<Self, crate::error::NetworkDiscoveryError> {
                Ok(Self)
            }

           async fn mdns_instance(&self, ip: IpAddr) -> Option<String> {
                let daemon = ServiceDaemon::new().ok()?;
                let total_deadline = Instant::now() + Duration::from_millis(3000);
                let mut candidates = Vec::new();

                for &service in SERVICES {
                    // Give each service equal time, but respect total deadline
                    let service_deadline = Instant::now() + Duration::from_millis(2000);
                    let actual_deadline = std::cmp::min(service_deadline, total_deadline);
                    
                    let receiver = daemon.browse(service).ok()?;
                    
                    loop {
                        let now = Instant::now();
                        if now >= actual_deadline {
                            break;  // Simply break when this service times out
                        }
                        let timeout_dur = actual_deadline - now;

                        match timeout(timeout_dur, receiver.recv_async()).await {
                            Ok(Ok(event)) => match event {
                                ServiceEvent::ServiceResolved(info) => {
                                    if info.get_addresses().iter().any(|scoped_ip| scoped_ip.to_ip_addr() == ip) {
                                        let mut hostname = info.get_fullname()
                                            .trim_end_matches(service)
                                            .trim_end_matches('.')
                                            .trim_end_matches(".local");
                                        if hostname.is_empty() {
                                            hostname = info.get_hostname()
                                                .trim_end_matches('.')
                                                .trim_end_matches(".local");
                                        }
                                        println!("DEBUG: IP: '{}', info.props:{}", ip, info.get_properties());
                                        println!("DEBUG: IP: '{}', info.fullname:{}", ip, info.get_fullname());
                                        // println!("DEBUG: IP: '{}', info.hostname:{}", ip, info.get_hostname());
                                        // println!("DEBUG: Cleaned hostname: '{}'", hostname);
                                        // println!("DEBUG: Is localhost? {}", hostname.eq_ignore_ascii_case("localhost"));
                                        candidates.push(hostname.to_string());
                                    }
                                }
                                _ => continue,
                            },
                            Ok(Err(_)) | Err(_) => break,
                        }
                    }
                    
                    daemon.stop_browse(service).ok();
                    
                    // Check if we should stop processing more services
                    if Instant::now() >= total_deadline {
                        break;
                    }
                }

                daemon.shutdown().ok();

                if candidates.is_empty() {
                    return None;
                }

                let best = candidates
                    .iter()
                    .filter(|&n| !n.eq_ignore_ascii_case("localhost"))
                    .min_by_key(|n| n.len());
                
                best.cloned()
            }

            async fn hostname_resolves_to_ip(&self, hostname: &str, target_ip: IpAddr) -> bool {
                let addrs = tokio::task::block_in_place(|| {
                    dns_lookup::getaddrinfo(Some(hostname), None, None)
                        .map(|iter| iter.filter_map(Result::ok).collect::<Vec<_>>())
                        .unwrap_or_default()
                });
                addrs.iter().any(|ai| ai.sockaddr.ip() == target_ip)
            }

            fn reverse_dns(&self, ip: IpAddr) -> Option<String> {
                tokio::task::block_in_place(|| lookup_addr(&ip).ok())
            }
        }

        #[async_trait]
        impl crate::strategy::DeviceDetectionStrategy for EnhancedHostnameStrategy {
            fn name(&self) -> &'static str {
                "multi-service mDNS-SD hostname lookup"
            }

            async fn detect(
                &self,
                device: &mut crate::model::NetworkDevice,
            ) -> Result<(), crate::error::NetworkDiscoveryError> {
                let ip = device.ip;
                let host = self
                    .mdns_instance(ip)
                    .await
                    .or_else(|| self.reverse_dns(ip))
                    .unwrap_or_else(|| "N/A".to_string());
                device.hostname = Some(host);
                Ok(())
            }
        }
    }

}

// ==========================================================
//  9.  ENGINE
// ==========================================================
mod engine {
    use super::*;
    use comfy_table::{Cell, Table};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{mpsc, Mutex};

    pub struct EnhancedNetworkDiscovery {
        strategies: Arc<Vec<Box<dyn crate::strategy::DeviceDetectionStrategy>>>,
        config: crate::config::ScanConfig,
        os_detector: Arc<crate::detect::os::AdvancedOSDetector>,
    }
    impl EnhancedNetworkDiscovery {
        pub fn new() -> Result<Self, crate::error::NetworkDiscoveryError> {
            let config = crate::config::ScanConfig::default();
            let vendor_db = Arc::new(Mutex::new(crate::db::oui::MacVendorDatabase::new()?));
            let os_detector = Arc::new(crate::detect::os::AdvancedOSDetector::new(config.clone()));
            let mut strategies_vec: Vec<Box<dyn crate::strategy::DeviceDetectionStrategy>> =
                Vec::new();
            strategies_vec.push(Box::new(
                crate::detect::mac::EnhancedMacAddressStrategy::new(vendor_db.clone()),
            ));
            strategies_vec.push(Box::new(
                crate::detect::port::EnhancedPortScanStrategy::new(
                    config.clone(),
                    os_detector.clone(),
                ),
            ));
            strategies_vec.push(Box::new(
                crate::detect::hostname::EnhancedHostnameStrategy::new()?,
            ));
            Ok(Self {
                strategies: Arc::new(strategies_vec),
                config,
                os_detector,
            })
        }
        // 4. public helper so main() can override concurrency
        pub fn set_concurrency(&mut self, jobs: usize) {
            self.config.max_concurrent_scans = jobs.max(1);
        }
        pub async fn discover_network_enhanced(
            &self,
            network: &str,
        ) -> Result<(), crate::error::NetworkDiscoveryError> {
            if !network.contains('/') {
                return Err(crate::error::NetworkDiscoveryError::PingError(
                    "Network must be in CIDR format (e.g., 192.168.1.0/24)".to_string(),
                ));
            }
            if !network.ends_with("/24") {
                return Err(crate::error::NetworkDiscoveryError::PingError(
                    "Only /24 networks are currently supported".to_string(),
                ));
            }
            let scan_start = Instant::now();
            println!(
                "Enhanced Network Discovery Tool - Starting scan for {}",
                network
            );
            println!("====================================================================");
            let active_ips = crate::net::ping::parallel_ping_sweep(network, &self.config).await?;
            println!("Found {} active devices", active_ips.len());
            println!("Starting enhanced fingerprinting scan...\n");
            let discovered_devices = Arc::new(Mutex::new(HashMap::<
                IpAddr,
                crate::model::NetworkDevice,
            >::new()));
            let (tx, mut rx) = mpsc::channel::<crate::model::NetworkDevice>(active_ips.len());
            let total_devices = active_ips.len();
            let mut completed = 0;
            let interface_name_for_arp = crate::net::interface::find_network_interface(network)?;
            if interface_name_for_arp.is_none() {
                println!("Warning: No suitable network interface found. MAC address detection may be limited.");
            }
            for ip in active_ips {
                println!("Scanning device {} with enhanced detection", ip);
                let strategies = self.strategies.clone();
                let tx_clone = tx.clone();
                let os_detector = self.os_detector.clone();
                let arp_timeout = Duration::from_millis(self.config.ping_timeout_ms);
                let interface_name_for_arp_clone = interface_name_for_arp.clone();
                tokio::spawn(async move {
                    let mac = if let IpAddr::V4(ipv4) = ip {
                        if let Some(ref iface_name) = interface_name_for_arp_clone {
                            match libarp::client::ArpClient::new_with_iface_name(iface_name) {
                                Ok(mut client) => {
                                    match client.ip_to_mac(ipv4, Some(arp_timeout)).await {
                                        Ok(mac) => {
                                            println!("MAC address found for {}: {}", ip, mac);
                                            Some(mac.to_string().to_uppercase())
                                        }
                                        Err(_) => None,
                                    }
                                }
                                Err(_) => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let mut device = crate::model::NetworkDevice {
                        ip,
                        mac,
                        hostname: None,
                        vendor: None,
                        device_type: crate::model::DeviceType::Unknown,
                        operating_system: None,
                        os_confidence: None,
                        open_ports: Vec::new(),
                        services: Vec::new(),
                        response_time: None,
                        last_seen: std::time::SystemTime::now(),
                        tcp_fingerprint: None,
                    };
                    for strategy in strategies.iter() {
                        let _ = strategy.detect(&mut device).await;
                    }
                    let (detected_os, confidence) =
                        os_detector.detect_operating_system(&device).await;
                    if let Some(os) = detected_os {
                        device.operating_system = Some(os);
                        device.os_confidence = Some(confidence);
                    }
                    let _ = tx_clone.send(device).await;
                });
            }
            drop(tx);
            use std::io::Write;
            while let Some(device) = rx.recv().await {
                completed += 1;
                print!(
                    "\rProgress: {}/{} devices ({:.1}%)",
                    completed,
                    total_devices,
                    (completed as f32 / total_devices as f32) * 100.0
                );
                std::io::stdout().flush().ok();
                let mut devices_map = discovered_devices.lock().await;
                devices_map.insert(device.ip, device);
            }
            println!();
            self.display_enhanced_results(&discovered_devices, scan_start.elapsed())
                .await;
            Ok(())
        }
        async fn display_enhanced_results(
            &self,
            devices: &Arc<Mutex<HashMap<IpAddr, crate::model::NetworkDevice>>>,
            scan_duration: Duration,
        ) {
            let devices_map = devices.lock().await;
            let mut table = Table::new();
            table.set_header(vec![
                "IP",
                "Hostname",
                "MAC",
                "Vendor",
                "Type",
                "OS",
                "Confidence",
                "Ports",
                "Key Services",
            ]);
            let mut os_detected_count = 0;
            let mut high_confidence_count = 0;
            for (_, device) in devices_map.iter() {
                if device.operating_system.is_some() {
                    os_detected_count += 1;
                    if let Some(conf) = device.os_confidence {
                        if conf > 0.8 {
                            high_confidence_count += 1;
                        }
                    }
                }
                let service_details = if device.services.is_empty() {
                    "—".to_string()
                } else {
                    device
                        .services
                        .iter()
                        .filter_map(|s| s.service_name.as_ref())
                        .take(3)
                        .cloned()
                        .collect::<Vec<String>>()
                        .join(", ")
                };
                let ports_list = if device.open_ports.is_empty() {
                    "—".to_string()
                } else {
                    let mut ports = device
                        .open_ports
                        .iter()
                        .take(6)
                        .map(|p| p.to_string())
                        .collect::<Vec<String>>()
                        .join(", ");
                    if device.open_ports.len() > 6 {
                        ports.push_str(&format!(" (+{})", device.open_ports.len() - 6));
                    }
                    ports
                };
                let os_string = if let Some(ref os) = device.operating_system {
                    match os {
                        crate::model::OperatingSystem::Windows(Some(name)) => {
                            format!("Windows {}", name)
                        }
                        crate::model::OperatingSystem::Windows(None) => "Windows".to_string(),
                        crate::model::OperatingSystem::MacOS(Some(name)) => {
                            format!("macOS {}", name)
                        }
                        crate::model::OperatingSystem::MacOS(None) => "macOS".to_string(),
                        crate::model::OperatingSystem::Linux(Some(name)) => {
                            format!("Linux {}", name)
                        }
                        crate::model::OperatingSystem::Linux(None) => "Linux".to_string(),
                        crate::model::OperatingSystem::IOS(Some(name)) => format!("iOS {}", name),
                        crate::model::OperatingSystem::IOS(None) => "iOS".to_string(),
                        crate::model::OperatingSystem::Android(Some(name)) => {
                            format!("Android {}", name)
                        }
                        crate::model::OperatingSystem::Android(None) => "Android".to_string(),
                        crate::model::OperatingSystem::RouterOS => "RouterOS".to_string(),
                        crate::model::OperatingSystem::FreeBSD(name) => {
                            format!("FreeBSD {}", name.as_ref().unwrap_or(&"".to_string()))
                        }
                        crate::model::OperatingSystem::OpenBSD(name) => {
                            format!("OpenBSD {}", name.as_ref().unwrap_or(&"".to_string()))
                        }
                        crate::model::OperatingSystem::Other(name) => name.clone(),
                        _ => "Other".to_string(),
                    }
                } else {
                    "Unknown".to_string()
                };
                let confidence_str = if let Some(conf) = device.os_confidence {
                    format!("{:.0}%", conf * 100.0)
                } else {
                    "—".to_string()
                };
                let device_type_str = match device.device_type {
                    crate::model::DeviceType::AppleDevice => "Apple Device",
                    crate::model::DeviceType::AndroidDevice => "Android Device",
                    crate::model::DeviceType::WindowsDevice => "Windows PC",
                    crate::model::DeviceType::LinuxDevice => "Linux System",
                    crate::model::DeviceType::NetworkDevice => "Network Equipment",
                    _ => &format!("{:?}", device.device_type),
                };
                table.add_row(vec![
                    Cell::new(device.ip.to_string()),
                    Cell::new(device.hostname.as_ref().map_or("—".to_string(), |h| {
                        if let Some((prefix, rest)) = h.split_once('-') {
                            if prefix.chars().all(|c| c.is_alphabetic()) && prefix.len() >= 2 && rest.contains('-') {
                                return prefix.to_string();
                            }
                        }
                        if h.len() > 20 { format!("{}...", &h[..17]) } else { h.to_string() }
                    })),
                    Cell::new(device.mac.clone().unwrap_or_else(|| "—".to_string())),
                    Cell::new(device.vendor.clone().unwrap_or_else(|| "—".to_string())),
                    Cell::new(device_type_str),
                    Cell::new(os_string),
                    Cell::new(confidence_str),
                    Cell::new(ports_list),
                    Cell::new(service_details),
                ]);
            }
            println!("{}", table);
            let detection_rate = if !devices_map.is_empty() {
                (os_detected_count as f32 / devices_map.len() as f32) * 100.0
            } else {
                0.0
            };
            let high_confidence_rate = if os_detected_count > 0 {
                (high_confidence_count as f32 / os_detected_count as f32) * 100.0
            } else {
                0.0
            };
            println!("\nEnhanced Scan Results Summary:");
            println!("============================");
            println!(
                "Scan completed in {:.2} seconds",
                scan_duration.as_secs_f64()
            );
            println!(
                "OS Detection Rate: {:.1}% ({}/{})",
                detection_rate,
                os_detected_count,
                devices_map.len()
            );
            println!(
                "High Confidence Detections: {:.1}% ({}/{})",
                high_confidence_rate, high_confidence_count, os_detected_count
            );
            println!(
                "Total Services Detected: {}",
                devices_map
                    .values()
                    .map(|d| d.services.len())
                    .sum::<usize>()
            );
        }
    }
}

// ==========================================================
//  10.  MAIN  (4. --jobs flag)
// ==========================================================

#[tokio::main]
async fn main() -> Result<(), NetworkDiscoveryError> {
    let raw_args: Vec<String> = std::env::args().collect();
    let mut args = raw_args.iter().skip(1);

    let mut jobs = None;
    let mut positional = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--jobs" | "-j" => jobs = args.next().and_then(|s| s.parse().ok()),
            "--list" => {
                crate::net::interface::list_network_interfaces()?;
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

    let network = match positional {
        None => {
            println!("No arguments provided. Usage:");
            println!("  rscout [INTERFACE_NAME|CIDR_NETWORK]");
            println!();
            println!("Examples:");
            println!("  rscout eth0                    # Scan network on eth0 interface");
            println!("  rscout 192.168.1.0/24          # Scan specific CIDR network");
            println!();
            crate::net::interface::list_network_interfaces()?;
            return Err(NetworkDiscoveryError::Other(
                "No network specified".to_string(),
            ));
        }
        Some(arg) => {
            if arg.contains('/') {
                arg // already CIDR
            } else {
                // 4. convert interface name → CIDR
                crate::net::interface::get_network_from_interface(&arg)?
            }
        }
    };

    let mut discovery = crate::engine::EnhancedNetworkDiscovery::new()?;
    if let Some(j) = jobs {
        discovery.set_concurrency(j);
    }
    println!("Target network: {}", network);
    println!();
    discovery.discover_network_enhanced(&network).await
}
// Note: `libarp` is the public API module of the `arp-toolkit` crate.
use async_trait::async_trait;
use comfy_table::{Cell, Table};
use eui48::MacAddress;
use futures::pin_mut;
use futures::stream::{self, StreamExt};
use oui::OuiDatabase;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use surge_ping::ping;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use trust_dns_resolver::TokioAsyncResolver;
use libarp::client::ArpClient;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

// Embed manuf.txt at compile time
const MANUF_DATA: &str = include_str!("../manuf.txt");

// Built-in OUI fallback for basic vendor detection
const BUILTIN_OUI: &str = r#"
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
00:02:17   Cisco Systems, Inc
00:02:4A   Cisco Systems, Inc
00:02:4B   Cisco Systems, Inc
00:02:FD   Cisco Systems, Inc
00:03:32   Cisco Systems, Inc
00:03:6F   Cisco Systems, Inc
00:03:E3   Cisco Systems, Inc
00:04:27   Cisco Systems, Inc
00:04:9A   Cisco Systems, Inc
00:04:C1   Cisco Systems, Inc
00:05:5E   Cisco Systems, Inc
00:05:AC   Cisco Systems, Inc
00:06:28   Cisco Systems, Inc
00:06:5B   Cisco Systems, Inc
00:07:0E   Cisco Systems, Inc
00:07:4F   Cisco Systems, Inc
00:07:7D   Cisco Systems, Inc
00:07:EA   Cisco Systems, Inc
00:08:2F   Cisco Systems, Inc
00:08:74   Cisco Systems, Inc
00:08:E3   Cisco Systems, Inc
00:09:11   Cisco Systems, Inc
00:09:7C   Cisco Systems, Inc
00:0A:41   Cisco Systems, Inc
00:0A:DC   Cisco Systems, Inc
00:0B:5F   Cisco Systems, Inc
00:0B:BE   Cisco Systems, Inc
00:0C:30   Cisco Systems, Inc
00:0C:85   Cisco Systems, Inc
00:0D:28   Cisco Systems, Inc
00:0D:BD   Cisco Systems, Inc
00:0E:35   Cisco Systems, Inc
00:0E:8C   Cisco Systems, Inc
00:0F:34   Cisco Systems, Inc
00:0F:8F   Cisco Systems, Inc
00:10:07   Cisco Systems, Inc
00:10:2F   Cisco Systems, Inc
00:10:7B   Cisco Systems, Inc
00:10:C6   Cisco Systems, Inc
00:11:20   Cisco Systems, Inc
00:11:92   Cisco Systems, Inc
00:11:9B   Cisco Systems, Inc
00:12:00   Cisco Systems, Inc
00:12:43   Cisco Systems, Inc
00:12:80   Cisco Systems, Inc
00:12:D9   Cisco Systems, Inc
00:13:1A   Cisco Systems, Inc
00:13:5F   Cisco Systems, Inc
00:13:C3   Cisco Systems, Inc
00:14:1C   Cisco Systems, Inc
00:14:A8   Cisco Systems, Inc
00:14:F2   Cisco Systems, Inc
00:15:2B   Cisco Systems, Inc
00:15:60   Cisco Systems, Inc
00:15:96   Cisco Systems, Inc
00:16:41   Cisco Systems, Inc
00:16:C7   Cisco Systems, Inc
00:17:59   Cisco Systems, Inc
00:17:95   Cisco Systems, Inc
00:17:D3   Cisco Systems, Inc
00:18:74   Cisco Systems, Inc
00:18:B9   Cisco Systems, Inc
00:19:30   Cisco Systems, Inc
00:19:AA   Cisco Systems, Inc
00:1A:2F   Cisco Systems, Inc
00:1A:64   Cisco Systems, Inc
00:1A:A2   Cisco Systems, Inc
00:1B:0C   Cisco Systems, Inc
00:1B:54   Cisco Systems, Inc
00:1B:D5   Cisco Systems, Inc
00:1C:58   Cisco Systems, Inc
00:1C:DF   Cisco Systems, Inc
00:1D:45   Cisco Systems, Inc
00:1D:A2   Cisco Systems, Inc
00:1E:13   Cisco Systems, Inc
00:1E:49   Cisco Systems, Inc
00:1E:B7   Cisco Systems, Inc
00:1F:6C   Cisco Systems, Inc
00:1F:90   Cisco Systems, Inc
00:1F:CA   Cisco Systems, Inc
00:21:1B   Cisco Systems, Inc
00:21:55   Cisco Systems, Inc
00:21:56   Cisco Systems, Inc
00:22:55   Cisco Systems, Inc
00:22:90   Cisco Systems, Inc
00:23:33   Cisco Systems, Inc
00:23:AB   Cisco Systems, Inc
00:24:10   Cisco Systems, Inc
00:24:50   Cisco Systems, Inc
00:24:97   Cisco Systems, Inc
00:25:45   Cisco Systems, Inc
00:25:83   Cisco Systems, Inc
00:26:52   Cisco Systems, Inc
00:26:CB   Cisco Systems, Inc
00:27:0D   Cisco Systems, Inc
00:27:10   Cisco Systems, Inc
"#;

// ================================================================================================
// ENHANCED CONFIGURATION
// ================================================================================================
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
                21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 
                1723, 3306, 3389, 5900, 8000, 8080, 8443, 9100, 161, 162, 389, 636
            ],
            ping_timeout_ms: 500,
            tcp_connect_timeout_ms: 300,
            banner_read_timeout_ms: 500,
            max_concurrent_scans: 64,
            enable_advanced_fingerprinting: true,
        }
    }
}

// ================================================================================================
// ENHANCED ERROR HANDLING
// ================================================================================================
#[derive(Debug)]
pub enum NetworkDiscoveryError {
    OuiDatabaseError(String),
    PingError(String),
    PortScanError(String),
    HostnameResolutionError(String),
    IoError(std::io::Error),
    NetworkInterfaceError(String),
    FingerprintError(String),
    Other(String),
}
impl std::fmt::Display for NetworkDiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkDiscoveryError::OuiDatabaseError(msg) => write!(f, "OUI Database Error: {}", msg),
            NetworkDiscoveryError::PingError(msg) => write!(f, "Ping Error: {}", msg),
            NetworkDiscoveryError::PortScanError(msg) => write!(f, "Port Scan Error: {}", msg),
            NetworkDiscoveryError::HostnameResolutionError(msg) => write!(f, "Hostname Resolution Error: {}", msg),
            NetworkDiscoveryError::IoError(err) => write!(f, "I/O Error: {}", err),
            NetworkDiscoveryError::NetworkInterfaceError(msg) => write!(f, "Network Interface Error: {}", msg),
            NetworkDiscoveryError::FingerprintError(msg) => write!(f, "Fingerprint Error: {}", msg),
            NetworkDiscoveryError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}
impl std::error::Error for NetworkDiscoveryError {}
impl From<std::io::Error> for NetworkDiscoveryError {
    fn from(error: std::io::Error) -> Self {
        NetworkDiscoveryError::IoError(error)
    }
}
impl From<String> for NetworkDiscoveryError {
    fn from(error: String) -> Self {
        NetworkDiscoveryError::Other(error)
    }
}
impl From<network_interface::Error> for NetworkDiscoveryError {
    fn from(error: network_interface::Error) -> Self {
        NetworkDiscoveryError::NetworkInterfaceError(error.to_string())
    }
}

// ================================================================================================
// ENHANCED DATA STRUCTURES
// ================================================================================================
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

// ================================================================================================
// ADVANCED OS FINGERPRINTING (Simplified but Effective)
// ================================================================================================
pub struct AdvancedOSDetector {
    config: ScanConfig,
}
impl AdvancedOSDetector {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Perform multiple OS detection methods and return best guess with confidence
    pub async fn detect_operating_system(&self, device: &NetworkDevice) -> (Option<OperatingSystem>, f32) {
        let mut confidence = 0.0f32;
        let mut detected_os: Option<OperatingSystem> = None;

        // Method 1: Service Banner Analysis (most reliable)
        let (os_from_banner, banner_conf) = self.analyze_service_banners(&device.services);
        if banner_conf > confidence {
            confidence = banner_conf;
            detected_os = os_from_banner;
        }

        // Method 2: Port Pattern Analysis
        let (os_from_ports, port_conf) = self.analyze_port_patterns(&device.open_ports);
        if port_conf > confidence {
            confidence = port_conf;
            detected_os = os_from_ports;
        }

        // Method 3: TCP Fingerprint Analysis
        if let Some(ref tcp_fp) = device.tcp_fingerprint {
            let (os_from_tcp, tcp_conf) = self.analyze_tcp_fingerprint(tcp_fp);
            if tcp_conf > confidence {
                confidence = tcp_conf;
                detected_os = os_from_tcp;
            }
        }

        // Method 4: Vendor-based inference
        if let Some(ref vendor) = device.vendor {
            let (os_from_vendor, vendor_conf) = self.infer_os_from_vendor(vendor);
            if vendor_conf > confidence {
                confidence = vendor_conf;
                detected_os = os_from_vendor;
            }
        }

        // Method 5: Hostname analysis
        if let Some(ref hostname) = device.hostname {
            let (os_from_hostname, hostname_conf) = self.analyze_hostname_for_os(hostname);
            if hostname_conf > confidence {
                confidence = hostname_conf;
                detected_os = os_from_hostname;
            }
        }

        (detected_os, confidence)
    }

    fn analyze_service_banners(&self, services: &[NetworkService]) -> (Option<OperatingSystem>, f32) {
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

    fn analyze_ssh_banner(&self, banner: &str) -> (Option<OperatingSystem>, f32) {
        if banner.contains("openssh") {
            if banner.contains("ubuntu") {
                return (Some(OperatingSystem::Linux(Some("Ubuntu".to_string()))), 0.95);
            } else if banner.contains("debian") {
                return (Some(OperatingSystem::Linux(Some("Debian".to_string()))), 0.95);
            } else if banner.contains("centos") || banner.contains("rhel") {
                return (Some(OperatingSystem::Linux(Some("CentOS/RHEL".to_string()))), 0.95);
            } else if banner.contains("freebsd") {
                return (Some(OperatingSystem::FreeBSD(None)), 0.95);
            } else if banner.contains("openbsd") {
                return (Some(OperatingSystem::OpenBSD(None)), 0.95);
            } else {
                return (Some(OperatingSystem::Linux(None)), 0.8);
            }
        } else if banner.contains("dropbear") {
            return (Some(OperatingSystem::Linux(Some("Embedded/OpenWrt".to_string()))), 0.85);
        } else if banner.contains("microsoft") || banner.contains("windows") {
            return (Some(OperatingSystem::Windows(Some("Server".to_string()))), 0.9);
        }
        (None, 0.0)
    }

    fn analyze_http_banner(&self, banner: &str) -> (Option<OperatingSystem>, f32) {
        if banner.contains("microsoft-iis") {
            return (Some(OperatingSystem::Windows(Some("Server".to_string()))), 0.85);
        } else if banner.contains("apache") {
            if banner.contains("ubuntu") {
                return (Some(OperatingSystem::Linux(Some("Ubuntu".to_string()))), 0.85);
            } else if banner.contains("centos") || banner.contains("rhel") {
                return (Some(OperatingSystem::Linux(Some("CentOS/RHEL".to_string()))), 0.85);
            } else if banner.contains("debian") {
                return (Some(OperatingSystem::Linux(Some("Debian".to_string()))), 0.85);
            } else if banner.contains("freebsd") {
                return (Some(OperatingSystem::FreeBSD(None)), 0.8);
            } else {
                return (Some(OperatingSystem::Linux(None)), 0.7);
            }
        } else if banner.contains("nginx") {
            if banner.contains("ubuntu") {
                return (Some(OperatingSystem::Linux(Some("Ubuntu".to_string()))), 0.8);
            } else {
                return (Some(OperatingSystem::Linux(None)), 0.7);
            }
        } else if banner.contains("lighttpd") {
            return (Some(OperatingSystem::Linux(None)), 0.7);
        }
        (None, 0.0)
    }

    fn analyze_ftp_banner(&self, banner: &str) -> (Option<OperatingSystem>, f32) {
        if banner.contains("microsoft ftp") {
            return (Some(OperatingSystem::Windows(Some("Server".to_string()))), 0.85);
        } else if banner.contains("vsftpd") {
            return (Some(OperatingSystem::Linux(None)), 0.8);
        } else if banner.contains("proftpd") {
            return (Some(OperatingSystem::Linux(None)), 0.75);
        }
        (None, 0.0)
    }

    fn analyze_smtp_banner(&self, banner: &str) -> (Option<OperatingSystem>, f32) {
        if banner.contains("microsoft exchange") || banner.contains("microsoft smtp") {
            return (Some(OperatingSystem::Windows(Some("Server".to_string()))), 0.85);
        } else if banner.contains("postfix") {
            return (Some(OperatingSystem::Linux(None)), 0.8);
        } else if banner.contains("sendmail") {
            return (Some(OperatingSystem::Linux(None)), 0.75);
        }
        (None, 0.0)
    }

    fn analyze_windows_service_banner(&self, banner: &str) -> (Option<OperatingSystem>, f32) {
        if banner.contains("windows") || banner.contains("microsoft") {
            if banner.contains("server") {
                return (Some(OperatingSystem::Windows(Some("Server".to_string()))), 0.8);
            } else {
                return (Some(OperatingSystem::Windows(None)), 0.75);
            }
        }
        (None, 0.0)
    }

    fn analyze_port_patterns(&self, ports: &[u16]) -> (Option<OperatingSystem>, f32) {
        let port_set: std::collections::HashSet<u16> = ports.iter().cloned().collect();

        // Strong Windows indicators
        if port_set.contains(&135) && port_set.contains(&445) && port_set.contains(&139) {
            if port_set.contains(&3389) {
                return (Some(OperatingSystem::Windows(Some("Server/Pro".to_string()))), 0.85);
            } else {
                return (Some(OperatingSystem::Windows(None)), 0.8);
            }
        }

        // Windows-only RDP
        if port_set.contains(&3389) && !port_set.contains(&22) {
            return (Some(OperatingSystem::Windows(None)), 0.75);
        }

        // Linux server patterns
        if port_set.contains(&22) && (port_set.contains(&80) || port_set.contains(&443)) {
            if port_set.contains(&3306) || port_set.contains(&5432) {
                return (Some(OperatingSystem::Linux(Some("Server".to_string()))), 0.7);
            } else {
                return (Some(OperatingSystem::Linux(None)), 0.65);
            }
        }

        // SSH without other services (embedded/IoT)
        if port_set.contains(&22) && ports.len() <= 2 {
            return (Some(OperatingSystem::Linux(Some("Embedded".to_string()))), 0.6);
        }

        // Router/embedded patterns (only web interface)
        if (port_set.contains(&80) || port_set.contains(&443)) && ports.len() <= 3 && !port_set.contains(&22) {
            return (Some(OperatingSystem::RouterOS), 0.7);
        }

        (None, 0.0)
    }

    fn analyze_tcp_fingerprint(&self, tcp_fp: &TcpFingerprint) -> (Option<OperatingSystem>, f32) {
        // Analyze response time patterns and connection characteristics
        match tcp_fp.estimated_ttl {
            64 => (Some(OperatingSystem::Linux(None)), 0.6),
            128 => (Some(OperatingSystem::Windows(None)), 0.6),
            255 => (Some(OperatingSystem::RouterOS), 0.7),
            60..=64 => (Some(OperatingSystem::MacOS(None)), 0.5),
            _ => (None, 0.0),
        }
    }

    fn infer_os_from_vendor(&self, vendor: &str) -> (Option<OperatingSystem>, f32) {
        let vendor_lower = vendor.to_lowercase();
        if vendor_lower.contains("apple") {
            (Some(OperatingSystem::MacOS(None)), 0.7)
        } else if vendor_lower.contains("microsoft") {
            (Some(OperatingSystem::Windows(None)), 0.7)
        } else if vendor_lower.contains("raspberry") {
            (Some(OperatingSystem::Linux(Some("Raspberry Pi OS".to_string()))), 0.85)
        } else if vendor_lower.contains("cisco") || vendor_lower.contains("juniper") {
            (Some(OperatingSystem::RouterOS), 0.8)
        } else if vendor_lower.contains("ubiquiti") || vendor_lower.contains("netgear") {
            (Some(OperatingSystem::RouterOS), 0.75)
        } else {
            (None, 0.0)
        }
    }

    fn analyze_hostname_for_os(&self, hostname: &str) -> (Option<OperatingSystem>, f32) {
        let hostname_lower = hostname.to_lowercase();
        if hostname_lower.contains("android") {
            (Some(OperatingSystem::Android(None)), 0.8)
        } else if hostname_lower.contains("iphone") || hostname_lower.contains("ipad") {
            (Some(OperatingSystem::IOS(None)), 0.85)
        } else if hostname_lower.contains("mac") || hostname_lower.ends_with(".local") {
            (Some(OperatingSystem::MacOS(None)), 0.65)
        } else if hostname_lower.contains("ubuntu") {
            (Some(OperatingSystem::Linux(Some("Ubuntu".to_string()))), 0.85)
        } else if hostname_lower.contains("debian") {
            (Some(OperatingSystem::Linux(Some("Debian".to_string()))), 0.85)
        } else if hostname_lower.contains("windows") || hostname_lower.contains("desktop") {
            (Some(OperatingSystem::Windows(None)), 0.7)
        } else if hostname_lower.contains("router") || hostname_lower.contains("gateway") {
            (Some(OperatingSystem::RouterOS), 0.75)
        } else if hostname_lower.contains("raspberrypi") {
            (Some(OperatingSystem::Linux(Some("Raspberry Pi OS".to_string()))), 0.9)
        } else {
            (None, 0.0)
        }
    }

    /// Generate TCP fingerprint from connection attempts
    pub async fn generate_tcp_fingerprint(&self, ip: IpAddr) -> Option<TcpFingerprint> {
        let mut response_times = Vec::new();
        let mut successful_connections = 0;
        let mut banner_characteristics = Vec::new();

        // Test multiple ports for timing patterns
        let test_ports = [22, 80, 443, 21, 25, 23];
        for &port in &test_ports {
            let start = Instant::now();
            if let Ok(connect_result) = timeout(
                Duration::from_millis(self.config.tcp_connect_timeout_ms),
                TcpStream::connect((ip, port))
            ).await {
                let elapsed = start.elapsed();
                response_times.push(elapsed.as_millis() as u64);
                if let Ok(mut stream) = connect_result {
                    successful_connections += 1;
                    // Try to grab banner for additional characteristics
                    let mut buf = vec![0; 512];
                    if let Ok(Ok(count)) = timeout(
                        Duration::from_millis(200),
                        stream.read(&mut buf)
                    ).await {
                        if count > 0 {
                            if let Ok(banner) = String::from_utf8(buf[..count].to_vec()) {
                                let banner_type = match port {
                                    22 => "ssh",
                                    80 | 443 => "http",
                                    21 => "ftp",
                                    25 => "smtp",
                                    _ => "unknown",
                                };
                                banner_characteristics.push(format!("{}:{}", banner_type, banner.len()));
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

        // Estimate TTL based on response time patterns
        let avg_response_time = response_times.iter().sum::<u64>() / response_times.len() as u64;
        let estimated_ttl = match avg_response_time {
            0..=20 => 64,      // Linux/Unix-like (fast local network)
            21..=50 => 64,     // Linux/Unix-like
            51..=100 => 128,   // Windows
            101..=200 => 255,  // Router/embedded
            _ => 64,           // Default to Linux
        };

        let connection_pattern = match successful_connections {
            0 => "closed".to_string(),
            1..=2 => "limited".to_string(),
            3..=4 => "moderate".to_string(),
            _ => "open".to_string(),
        };

        Some(TcpFingerprint {
            estimated_ttl,
            response_time_ms: avg_response_time,
            connection_pattern,
            banner_characteristics,
        })
    }
}

// ================================================================================================
// ENHANCED DETECTION STRATEGIES
// ================================================================================================
pub struct EnhancedPortScanStrategy {
    common_ports: Vec<u16>,
    config: Arc<ScanConfig>, // Now Arc
    os_detector: Arc<AdvancedOSDetector>,
}
impl EnhancedPortScanStrategy {
    pub fn new(config: ScanConfig, os_detector: Arc<AdvancedOSDetector>) -> Self {
        Self {
            common_ports: config.common_ports.clone(),
            config: Arc::new(config),
            os_detector,
        }
    }

    fn get_enhanced_service_info(port: u16) -> (Option<String>, Option<String>) {
        match port {
            21 => (Some("FTP".to_string()), Some("File Transfer Protocol".to_string())),
            22 => (Some("SSH".to_string()), Some("Secure Shell".to_string())),
            23 => (Some("Telnet".to_string()), Some("Remote Terminal".to_string())),
            25 => (Some("SMTP".to_string()), Some("Mail Transfer".to_string())),
            53 => (Some("DNS".to_string()), Some("Domain Name Service".to_string())),
            80 => (Some("HTTP".to_string()), Some("Web Server".to_string())),
            110 => (Some("POP3".to_string()), Some("Mail Retrieval".to_string())),
            135 => (Some("RPC".to_string()), Some("MS RPC Endpoint".to_string())),
            139 => (Some("NetBIOS".to_string()), Some("NetBIOS Session".to_string())),
            143 => (Some("IMAP".to_string()), Some("Internet Message Access".to_string())),
            161 => (Some("SNMP".to_string()), Some("Network Management".to_string())),
            162 => (Some("SNMP Trap".to_string()), Some("Network Management".to_string())),
            389 => (Some("LDAP".to_string()), Some("Directory Service".to_string())),
            443 => (Some("HTTPS".to_string()), Some("Secure Web Server".to_string())),
            445 => (Some("SMB".to_string()), Some("File Sharing".to_string())),
            636 => (Some("LDAPS".to_string()), Some("Secure LDAP".to_string())),
            993 => (Some("IMAPS".to_string()), Some("Secure IMAP".to_string())),
            995 => (Some("POP3S".to_string()), Some("Secure POP3".to_string())),
            1723 => (Some("PPTP".to_string()), Some("VPN Tunnel".to_string())),
            3306 => (Some("MySQL".to_string()), Some("Database Server".to_string())),
            3389 => (Some("RDP".to_string()), Some("Remote Desktop".to_string())),
            5432 => (Some("PostgreSQL".to_string()), Some("Database Server".to_string())),
            5900 => (Some("VNC".to_string()), Some("Remote Display".to_string())),
            8000 => (Some("HTTP-Alt".to_string()), Some("Alternative Web".to_string())),
            8080 => (Some("HTTP-Proxy".to_string()), Some("Web Proxy".to_string())),
            8443 => (Some("HTTPS-Alt".to_string()), Some("Alternative HTTPS".to_string())),
            9100 => (Some("JetDirect".to_string()), Some("Printer Service".to_string())),
            _ => (None, None),
        }
    }

    async fn enhanced_banner_grab(config: &ScanConfig, ip: IpAddr, port: u16) -> Option<String> {
        let tcp_timeout = Duration::from_millis(config.tcp_connect_timeout_ms);
        let banner_timeout = Duration::from_millis(config.banner_read_timeout_ms);

        if let Ok(connect_result) = timeout(tcp_timeout, TcpStream::connect((ip, port))).await {
            if let Ok(mut stream) = connect_result {
                let mut buf = vec![0; 2048];

                // Protocol-specific probes
                let probe = match port {
                    80 | 8000 | 8080 => Some(b"HEAD / HTTP/1.1\r\nHost: scanner\r\nUser-Agent: NetworkScanner/1.0\r\nConnection: close\r\n\r\n".as_slice()),
                    443 | 8443 => Some(b"GET / HTTP/1.1\r\nHost: scanner\r\nConnection: close\r\n\r\n".as_slice()),
                    21 => Some(b"HELP\r\n".as_slice()),
                    25 => Some(b"EHLO scanner.local\r\n".as_slice()),
                    110 => Some(b"USER test\r\n".as_slice()),
                    143 => Some(b"A001 CAPABILITY\r\n".as_slice()),
                    22 => None, // SSH sends banner automatically
                    _ => None,
                };

                if let Some(probe_data) = probe {
                    let _ = timeout(tcp_timeout, stream.write_all(probe_data)).await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }

                if let Ok(bytes_read) = timeout(banner_timeout, stream.read(&mut buf)).await {
                    if let Ok(count) = bytes_read {
                        if count > 0 {
                            if let Ok(banner_string) = String::from_utf8(buf[..count].to_vec()) {
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
        // Common version patterns
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

    fn infer_enhanced_device_characteristics(&self, device: &mut NetworkDevice) {
        let has_web = device.open_ports.iter().any(|&p| matches!(p, 80 | 443 | 8080 | 8443));
        let has_ssh = device.open_ports.contains(&22);
        let has_windows_services = device.open_ports.iter().any(|&p| matches!(p, 135 | 139 | 445));
        let has_rdp = device.open_ports.contains(&3389);
        let has_printer_service = device.open_ports.contains(&9100);
        let has_database = device.open_ports.iter().any(|&p| matches!(p, 3306 | 5432 | 1433));
        let has_mail_services = device.open_ports.iter().any(|&p| matches!(p, 25 | 110 | 143 | 993 | 995));
        let has_snmp = device.open_ports.iter().any(|&p| matches!(p, 161 | 162));

        // Enhanced device type inference
        if has_printer_service {
            device.device_type = DeviceType::Printer;
        } else if has_database && (has_web || has_ssh) {
            device.device_type = DeviceType::Server;
        } else if has_mail_services && (has_web || has_ssh) {
            device.device_type = DeviceType::Server;
        } else if has_windows_services && has_rdp {
            device.device_type = DeviceType::WindowsDevice;
        } else if has_ssh && has_web && device.open_ports.len() >= 3 {
            device.device_type = DeviceType::LinuxDevice;
        } else if has_web && device.open_ports.len() <= 3 {
            device.device_type = DeviceType::Router;
        } else if has_snmp && has_web {
            device.device_type = DeviceType::NetworkDevice;
        } else if device.open_ports.is_empty() {
            // Could be mobile device or IoT with no open ports
            if let Some(ref vendor) = device.vendor {
                let vendor_lower = vendor.to_lowercase();
                if vendor_lower.contains("apple") {
                    device.device_type = DeviceType::AppleDevice;
                } else if vendor_lower.contains("samsung") || vendor_lower.contains("google") {
                    device.device_type = DeviceType::AndroidDevice;
                } else {
                    device.device_type = DeviceType::IoTDevice;
                }
            }
        }

        // Enhanced service-based OS inference
        for service in &device.services {
            if let Some(ref banner) = service.banner {
                let banner_lower = banner.to_lowercase();
                // More specific OS detection from banners
                if banner_lower.contains("ubuntu") {
                    device.operating_system = Some(OperatingSystem::Linux(Some("Ubuntu".to_string())));
                    device.device_type = DeviceType::LinuxDevice;
                    break;
                } else if banner_lower.contains("centos") || banner_lower.contains("rhel") {
                    device.operating_system = Some(OperatingSystem::Linux(Some("CentOS/RHEL".to_string())));
                    device.device_type = DeviceType::LinuxDevice;
                    break;
                } else if banner_lower.contains("debian") {
                    device.operating_system = Some(OperatingSystem::Linux(Some("Debian".to_string())));
                    device.device_type = DeviceType::LinuxDevice;
                    break;
                } else if banner_lower.contains("microsoft") || banner_lower.contains("windows") {
                    device.operating_system = Some(OperatingSystem::Windows(Some("Server".to_string())));
                    device.device_type = DeviceType::WindowsDevice;
                    break;
                } else if banner_lower.contains("freebsd") {
                    device.operating_system = Some(OperatingSystem::FreeBSD(None));
                    device.device_type = DeviceType::Server;
                    break;
                }
            }
        }
    }
}

#[async_trait]
impl DeviceDetectionStrategy for EnhancedPortScanStrategy {
    fn name(&self) -> &'static str {
        "Enhanced Port Scanning with Advanced Banner Analysis"
    }

    async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
        let ip = device.ip;
        let mut open_ports = Vec::new();
        let mut services = Vec::new();

        let port_stream = stream::iter(self.common_ports.iter().copied())
            .map(|port| {
                let ip = ip;
                let config = self.config.clone();
                async move {
                    let mut open_port_info: Option<(u16, NetworkService)> = None;
                    if let Ok(connect_result) = timeout(
                        Duration::from_millis(config.tcp_connect_timeout_ms),
                        TcpStream::connect((ip, port))
                    ).await {
                        if let Ok(_stream) = connect_result {
                            let (service_name, service_type) = Self::get_enhanced_service_info(port);
                            let mut service = NetworkService {
                                port,
                                protocol: "TCP".to_string(),
                                service_name,
                                banner: None,
                                service_type,
                                version: None,
                                txt_records: Vec::new(),
                            };
                            // Enhanced banner grabbing
                            if let Some(banner) = Self::enhanced_banner_grab(&config, ip, port).await {
                                service.banner = Some(banner.clone());
                                service.version = Self::extract_version_from_banner(&banner);
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

        // Generate TCP fingerprint if enabled
        if self.config.enable_advanced_fingerprinting {
            if let Some(tcp_fingerprint) = self.os_detector.generate_tcp_fingerprint(ip).await {
                device.tcp_fingerprint = Some(tcp_fingerprint);
            }
        }

        // Enhanced device characteristics inference
        self.infer_enhanced_device_characteristics(device);

        Ok(())
    }
}

// ================================================================================================
// ENHANCED MAC ADDRESS STRATEGY
// ================================================================================================
pub struct EnhancedMacAddressStrategy {
    vendor_db: Arc<Mutex<MacVendorDatabase>>,
}
impl EnhancedMacAddressStrategy {
    pub fn new(vendor_db: Arc<Mutex<MacVendorDatabase>>) -> Self {
        Self { vendor_db }
    }

    fn advanced_device_classification(&self, vendor: &str, mac: &str) -> (DeviceType, Option<OperatingSystem>) {
        let vendor_lower = vendor.to_lowercase();
        let mac_upper = mac.to_uppercase();
        match vendor_lower.as_str() {
            v if v.contains("apple") => {
                // Apple device classification by OUI patterns
                if mac_upper.starts_with("00:1B:63") || mac_upper.starts_with("00:26:08") {
                    (DeviceType::AppleDevice, Some(OperatingSystem::IOS(Some("iPhone".to_string()))))
                } else if mac_upper.starts_with("A4:5E:60") || mac_upper.starts_with("58:55:CA") {
                    (DeviceType::AppleDevice, Some(OperatingSystem::MacOS(Some("MacBook".to_string()))))
                } else {
                    (DeviceType::AppleDevice, Some(OperatingSystem::MacOS(None)))
                }
            },
            v if v.contains("samsung") => {
                if v.contains("electronics") {
                    (DeviceType::AndroidDevice, Some(OperatingSystem::Android(Some("Samsung".to_string()))))
                } else {
                    (DeviceType::SmartTV, Some(OperatingSystem::Other("Tizen".to_string())))
                }
            },
            v if v.contains("google") => (DeviceType::AndroidDevice, Some(OperatingSystem::Android(Some("Pixel".to_string())))),
            v if v.contains("huawei") => (DeviceType::AndroidDevice, Some(OperatingSystem::Android(Some("EMUI".to_string())))),
            v if v.contains("xiaomi") => (DeviceType::AndroidDevice, Some(OperatingSystem::Android(Some("MIUI".to_string())))),
            v if v.contains("cisco") => (DeviceType::NetworkDevice, Some(OperatingSystem::RouterOS)),
            v if v.contains("ubiquiti") => (DeviceType::AccessPoint, Some(OperatingSystem::RouterOS)),
            v if v.contains("netgear") || v.contains("linksys") || v.contains("tp-link") => {
                (DeviceType::Router, Some(OperatingSystem::RouterOS))
            },
            v if v.contains("d-link") || v.contains("asus") => {
                (DeviceType::Router, Some(OperatingSystem::RouterOS))
            },
            v if v.contains("raspberry") => {
                (DeviceType::IoTDevice, Some(OperatingSystem::Linux(Some("Raspberry Pi OS".to_string()))))
            },
            v if v.contains("intel") || v.contains("realtek") || v.contains("qualcomm") => {
                (DeviceType::Computer, None)
            },
            v if v.contains("brother") || v.contains("canon") || v.contains("epson") || v.contains("hp") => {
                (DeviceType::Printer, Some(OperatingSystem::Other("Embedded".to_string())))
            },
            v if v.contains("amazon") => (DeviceType::IoTDevice, Some(OperatingSystem::Linux(Some("Fire OS".to_string())))),
            v if v.contains("sonos") => (DeviceType::IoTDevice, Some(OperatingSystem::Linux(Some("SonosOS".to_string())))),
            v if v.contains("nest") || v.contains("google") => (DeviceType::IoTDevice, Some(OperatingSystem::Other("Nest OS".to_string()))),
            v if v.contains("ring") => (DeviceType::IoTDevice, Some(OperatingSystem::Linux(Some("Ring OS".to_string())))),
            _ => (DeviceType::Unknown, None),
        }
    }
}

#[async_trait]
impl DeviceDetectionStrategy for EnhancedMacAddressStrategy {
    fn name(&self) -> &'static str {
        "Enhanced MAC Address Analysis with Device Classification"
    }

    async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
        if let Some(ref mac) = device.mac {
            let vendor_info = {
                let mut db = self.vendor_db.lock().await;
                db.get_device_info(mac)
            };
            if let Some(info) = vendor_info {
                device.vendor = Some(info.vendor.clone());
                let (inferred_type, inferred_os) = self.advanced_device_classification(&info.vendor, mac);
                if device.device_type == DeviceType::Unknown {
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

// ================================================================================================
// ENHANCED HOSTNAME STRATEGY
// ================================================================================================
pub struct EnhancedHostnameStrategy {
    resolver: TokioAsyncResolver,
}
impl EnhancedHostnameStrategy {
    pub fn new() -> Result<Self, NetworkDiscoveryError> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| NetworkDiscoveryError::HostnameResolutionError(e.to_string()))?;
        Ok(Self { resolver })
    }

    fn generate_intelligent_hostname(&self, device: &mut NetworkDevice) {
        let mut hostname_parts = Vec::new();

        // Vendor-based naming
        if let Some(ref vendor) = device.vendor {
            let vendor_lower = vendor.to_lowercase();
            let vendor_prefix = match vendor_lower.as_str() {
                v if v.contains("apple") => "apple",
                v if v.contains("samsung") => "samsung", 
                v if v.contains("cisco") => "cisco",
                v if v.contains("raspberry") => "rpi",
                v if v.contains("google") => "google",
                _ => {
                    if let Some(first_word) = vendor.split_whitespace().next() {
                        if first_word.len() <= 8 {
                            first_word
                        } else {
                            &first_word[..8]
                        }
                    } else {
                        "device"
                    }
                }
            };
            hostname_parts.push(vendor_prefix.to_lowercase());
        }

        // Device type
        let device_suffix = match device.device_type {
            DeviceType::Router | DeviceType::NetworkDevice => "router",
            DeviceType::Switch => "switch",
            DeviceType::AccessPoint => "ap",
            DeviceType::Printer => "printer",
            DeviceType::Server => "server",
            DeviceType::Computer | DeviceType::WindowsDevice | DeviceType::LinuxDevice => "pc",
            DeviceType::AppleDevice => "apple",
            DeviceType::AndroidDevice => "android",
            DeviceType::Smartphone => "phone",
            DeviceType::Tablet => "tablet",
            DeviceType::SmartTV => "tv",
            DeviceType::IoTDevice => "iot",
            _ => "device",
        };
        if hostname_parts.is_empty() || hostname_parts[0] != device_suffix {
            hostname_parts.push(device_suffix.to_string());
        }

        // Service indicators
        let mut service_indicators = Vec::new();
        for service in &device.services {
            match service.port {
                22 => service_indicators.push("ssh".to_string()),
                80 | 443 => {
                    if device.device_type == DeviceType::Router {
                        service_indicators.push("web".to_string());
                    }
                },
                3389 => service_indicators.push("rdp".to_string()),
                3306 => service_indicators.push("mysql".to_string()),
                5900 => service_indicators.push("vnc".to_string()),
                _ => {}
            }
        }
        if !service_indicators.is_empty() {
            hostname_parts.extend(service_indicators.into_iter().take(2));
        }

        // IP suffix
        let ip_suffix = device.ip.to_string().replace(".", "-");
        let last_octet = ip_suffix.split('-').last().unwrap_or("x");
        hostname_parts.push(last_octet.to_string());
        let hostname = format!("{}.local", hostname_parts.join("-"));
        device.hostname = Some(hostname);
    }

    fn enhanced_hostname_analysis(&self, device: &mut NetworkDevice, hostname: &str) {
        let hostname_lower = hostname.to_lowercase();

        // Apple devices
        if hostname_lower.ends_with(".local") {
            if hostname_lower.contains("iphone") {
                device.device_type = DeviceType::Smartphone;
                device.operating_system = Some(OperatingSystem::IOS(Some("iPhone".to_string())));
                device.os_confidence = Some(0.95);
            } else if hostname_lower.contains("ipad") {
                device.device_type = DeviceType::Tablet;
                device.operating_system = Some(OperatingSystem::IOS(Some("iPad".to_string())));
                device.os_confidence = Some(0.95);
            } else if hostname_lower.contains("macbook") || hostname_lower.contains("imac") {
                device.device_type = DeviceType::Computer;
                device.operating_system = Some(OperatingSystem::MacOS(None));
                device.os_confidence = Some(0.90);
            } else {
                device.device_type = DeviceType::AppleDevice;
                device.operating_system = Some(OperatingSystem::MacOS(None));
                device.os_confidence = Some(0.70);
            }
        }

        // Android devices
        if hostname_lower.contains("android") || hostname_lower.contains("samsung-sm") {
            device.device_type = DeviceType::AndroidDevice;
            device.operating_system = Some(OperatingSystem::Android(None));
            device.os_confidence = Some(0.85);
        }

        // Linux distributions
        if hostname_lower.contains("ubuntu") {
            device.operating_system = Some(OperatingSystem::Linux(Some("Ubuntu".to_string())));
            device.os_confidence = Some(0.90);
            device.device_type = DeviceType::LinuxDevice;
        } else if hostname_lower.contains("debian") {
            device.operating_system = Some(OperatingSystem::Linux(Some("Debian".to_string())));
            device.os_confidence = Some(0.90);
            device.device_type = DeviceType::LinuxDevice;
        }

        // Windows
        if hostname_lower.contains("desktop") || hostname_lower.contains("pc-") {
            device.operating_system = Some(OperatingSystem::Windows(None));
            device.os_confidence = Some(0.75);
            device.device_type = DeviceType::WindowsDevice;
        }

        // Network devices
        if hostname_lower.contains("router") || hostname_lower.contains("gateway") {
            device.device_type = DeviceType::Router;
            device.operating_system = Some(OperatingSystem::RouterOS);
            device.os_confidence = Some(0.80);
        }

        // Raspberry Pi
        if hostname_lower.contains("raspberrypi") {
            device.device_type = DeviceType::IoTDevice;
            device.operating_system = Some(OperatingSystem::Linux(Some("Raspberry Pi OS".to_string())));
            device.os_confidence = Some(0.95);
        }
    }
}

#[async_trait]
impl DeviceDetectionStrategy for EnhancedHostnameStrategy {
    fn name(&self) -> &'static str {
        "Enhanced Hostname Analysis & Device Inference"
    }

    async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
        let ip = device.ip;
        let hostname = match timeout(
            Duration::from_secs(2),
            self.resolver.reverse_lookup(ip)
        ).await {
            Ok(Ok(reverse_lookup)) => {
                reverse_lookup
                    .iter()
                    .next()
                    .map(|name| name.to_string().trim_end_matches('.').to_string())
            },
            _ => None,
        };

        if let Some(ref hostname) = hostname {
            device.hostname = Some(hostname.clone());
            self.enhanced_hostname_analysis(device, hostname);
        } else {
            self.generate_intelligent_hostname(device);
        }
        Ok(())
    }
}

// ================================================================================================
// ENHANCED NETWORK DISCOVERY ENGINE
// ================================================================================================
pub struct EnhancedNetworkDiscovery {
    strategies: Arc<Vec<Box<dyn DeviceDetectionStrategy>>>,
    config: ScanConfig,
    os_detector: Arc<AdvancedOSDetector>,
}
impl EnhancedNetworkDiscovery {
    pub fn new() -> Result<Self, NetworkDiscoveryError> {
        let config = ScanConfig::default();
        let vendor_db = Arc::new(Mutex::new(MacVendorDatabase::new()?));
        let os_detector = Arc::new(AdvancedOSDetector::new(config.clone()));
        let mut strategies_vec: Vec<Box<dyn DeviceDetectionStrategy>> = Vec::new();
        strategies_vec.push(Box::new(EnhancedMacAddressStrategy::new(vendor_db.clone())));
        strategies_vec.push(Box::new(EnhancedPortScanStrategy::new(config.clone(), os_detector.clone())));
        strategies_vec.push(Box::new(EnhancedHostnameStrategy::new()?));
        Ok(Self {
            strategies: Arc::new(strategies_vec),
            config,
            os_detector,
        })
    }

    pub async fn discover_network_enhanced(&self, network: &str) -> Result<(), NetworkDiscoveryError> {
        if !network.contains('/') {
            return Err(NetworkDiscoveryError::PingError(
                "Network must be in CIDR format (e.g., 192.168.1.0/24)".to_string()
            ));
        }

        // Only support /24 for now
        if !network.ends_with("/24") {
            return Err(NetworkDiscoveryError::PingError(
                "Only /24 networks are currently supported".to_string()
            ));
        }

        let scan_start = Instant::now();
        println!("Enhanced Network Discovery Tool - Starting scan for {}", network);
        println!("====================================================================");

        let active_ips = self.parallel_ping_sweep(network).await?;
        println!("Found {} active devices", active_ips.len());
        println!("Starting enhanced fingerprinting scan...\n");

        let discovered_devices = Arc::new(Mutex::new(HashMap::<IpAddr, NetworkDevice>::new()));
        let (tx, mut rx) = mpsc::channel::<NetworkDevice>(active_ips.len());
        let total_devices = active_ips.len();
        let mut completed = 0;

        let interface_name_for_arp = find_network_interface(network)?;
        if interface_name_for_arp.is_none() {
            println!("Warning: No suitable network interface found. MAC address detection may be limited.");
        }

        // Enhanced scanning tasks
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
                        match ArpClient::new_with_iface_name(iface_name) {
                            Ok(mut client) => {
                                match client.ip_to_mac(ipv4, Some(arp_timeout)).await {
                                    Ok(mac) => {
                                        println!("MAC address found for {}: {}", ip, mac);
                                        Some(mac.to_string().to_uppercase())
                                    },
                                    Err(_) => None,
                                }
                            },
                            Err(_) => None,
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                let mut device = NetworkDevice {
                    ip,
                    mac,
                    hostname: None,
                    vendor: None,
                    device_type: DeviceType::Unknown,
                    operating_system: None,
                    os_confidence: None,
                    open_ports: Vec::new(),
                    services: Vec::new(),
                    response_time: None,
                    last_seen: std::time::SystemTime::now(),
                    tcp_fingerprint: None,
                };

                // Apply all detection strategies
                for strategy in strategies.iter() {
                    let _ = strategy.detect(&mut device).await;
                }

                // Advanced OS detection
                let (detected_os, confidence) = os_detector.detect_operating_system(&device).await;
                if let Some(os) = detected_os {
                    device.operating_system = Some(os);
                    device.os_confidence = Some(confidence);
                }

                let _ = tx_clone.send(device).await; 
            });
        }

        drop(tx);

        // Process results with cleaner progress
        use std::io::Write;
        while let Some(device) = rx.recv().await {
            completed += 1;
            print!("\rProgress: {}/{} devices ({:.1}%)", 
                   completed, total_devices, (completed as f32 / total_devices as f32) * 100.0);
            std::io::stdout().flush().ok();
            let mut devices_map = discovered_devices.lock().await;
            devices_map.insert(device.ip, device);
        }
        println!(); // newline after progress

        // Display enhanced results
        self.display_enhanced_results(&discovered_devices, scan_start.elapsed()).await;
        Ok(())
    }

    async fn display_enhanced_results(&self, devices: &Arc<Mutex<HashMap<IpAddr, NetworkDevice>>>, scan_duration: Duration) {
        let devices_map = devices.lock().await;
        let mut table = Table::new();
        table.set_header(vec![
            "IP", "Hostname", "MAC", "Vendor", "Type", "OS", "Confidence", "Ports", "Key Services"
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
                device.services.iter()
                    .filter_map(|s| s.service_name.as_ref())
                    .take(3)
                    .cloned()
                    .collect::<Vec<String>>()
                    .join(", ")
            };

            let ports_list = if device.open_ports.is_empty() {
                "—".to_string()
            } else {
                let mut ports = device.open_ports.iter()
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
                    OperatingSystem::Windows(Some(name)) => format!("Windows {}", name),
                    OperatingSystem::Windows(None) => "Windows".to_string(),
                    OperatingSystem::MacOS(Some(name)) => format!("macOS {}", name),
                    OperatingSystem::MacOS(None) => "macOS".to_string(),
                    OperatingSystem::Linux(Some(name)) => format!("Linux {}", name),
                    OperatingSystem::Linux(None) => "Linux".to_string(),
                    OperatingSystem::IOS(Some(name)) => format!("iOS {}", name),
                    OperatingSystem::IOS(None) => "iOS".to_string(),
                    OperatingSystem::Android(Some(name)) => format!("Android {}", name),
                    OperatingSystem::Android(None) => "Android".to_string(),
                    OperatingSystem::RouterOS => "RouterOS".to_string(),
                    OperatingSystem::FreeBSD(name) => format!("FreeBSD {}", name.as_ref().unwrap_or(&"".to_string())),
                    OperatingSystem::OpenBSD(name) => format!("OpenBSD {}", name.as_ref().unwrap_or(&"".to_string())),
                    OperatingSystem::Other(name) => name.clone(),
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
                DeviceType::AppleDevice => "Apple Device",
                DeviceType::AndroidDevice => "Android Device",
                DeviceType::WindowsDevice => "Windows PC",
                DeviceType::LinuxDevice => "Linux System",
                DeviceType::NetworkDevice => "Network Equipment",
                _ => &format!("{:?}", device.device_type),
            };

            table.add_row(vec![
                Cell::new(device.ip.to_string()),
                Cell::new(device.hostname.clone().unwrap_or_else(|| "—".to_string())),
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

        // Enhanced statistics
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
        println!("Scan completed in {:.2} seconds", scan_duration.as_secs_f64());
        println!("OS Detection Rate: {:.1}% ({}/{})", detection_rate, os_detected_count, devices_map.len());
        println!("High Confidence Detections: {:.1}% ({}/{})", high_confidence_rate, high_confidence_count, os_detected_count);
        println!("Total Services Detected: {}", devices_map.values().map(|d| d.services.len()).sum::<usize>());
    }

    async fn parallel_ping_sweep(&self, network: &str) -> Result<Vec<IpAddr>, NetworkDiscoveryError> {
        let ping_timeout = Duration::from_millis(self.config.ping_timeout_ms);
        if let Some(base) = network.strip_suffix("/24") {
            let base_parts: Vec<&str> = base.split('.').collect();
            if base_parts.len() == 4 {
                let base_ip_str = format!("{}.{}.{}.", base_parts[0], base_parts[1], base_parts[2]);
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
                    .buffer_unordered(self.config.max_concurrent_scans);

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

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================
fn parse_cidr_network(network: &str) -> Result<(Ipv4Addr, u8), NetworkDiscoveryError> {
    let parts: Vec<&str> = network.split('/').collect();
    if parts.len() != 2 {
        return Err(NetworkDiscoveryError::PingError(
            "Invalid CIDR format".to_string()
        ));
    }
    let network_ip = Ipv4Addr::from_str(parts[0])
        .map_err(|e| NetworkDiscoveryError::PingError(format!("Invalid IP address: {}", e)))?;
    let prefix_len = parts[1].parse::<u8>()
        .map_err(|e| NetworkDiscoveryError::PingError(format!("Invalid prefix length: {}", e)))?;
    if prefix_len > 32 {
        return Err(NetworkDiscoveryError::PingError(
            "Invalid prefix length: must be <= 32".to_string()
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

fn get_network_from_interface(interface_name: &str) -> Result<String, NetworkDiscoveryError> {
    let interfaces = NetworkInterface::show()?;
    for interface in interfaces {
        if interface.name == interface_name {
            for addr in &interface.addr {
                if let IpAddr::V4(ipv4) = addr.ip() {
                    if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                        let network = calculate_network_cidr(ipv4)?;
                        println!("Interface {} has IP {}, calculated network: {}", interface_name, ipv4, network);
                        return Ok(network);
                    }
                }
            }
        }
    }
    Err(NetworkDiscoveryError::NetworkInterfaceError(
        format!("Interface '{}' not found or has no valid IPv4 address", interface_name)
    ))
}

fn calculate_network_cidr(ip: Ipv4Addr) -> Result<String, NetworkDiscoveryError> {
    let ip_octets = ip.octets();
    let network = match ip_octets {
        [192, 168, third, _] => format!("192.168.{}.0/24", third),
        [10, second, third, _] => format!("10.{}.{}.0/24", second, third),
        [172, second, third, _] if second >= 16 && second <= 31 => {
            format!("172.{}.{}.0/24", second, third)
        },
        [first, second, third, _] => format!("{}.{}.{}.0/24", first, second, third),
    };
    Ok(network)
}

fn list_network_interfaces() -> Result<(), NetworkDiscoveryError> {
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

fn find_network_interface(target_network: &str) -> Result<Option<String>, NetworkDiscoveryError> {
    let (network_ip, prefix_len) = parse_cidr_network(target_network)?;
    println!("Looking for interface with IP in network: {} (/{}) ", network_ip, prefix_len);
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
        if interface.name.starts_with("lo") || 
           interface.name.starts_with("docker") || 
           interface.name.starts_with("veth") {
            continue;
        }
        for addr in &interface.addr {
            if let IpAddr::V4(ipv4) = addr.ip() {
                if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                    println!("Using fallback interface: {} (IP: {})", interface.name, ipv4);
                    return Ok(Some(interface.name));
                }
            }
        }
    }
    println!("Warning: No suitable network interface found for ARP operations");
    Ok(None)
}

// ================================================================================================
// DEVICE DETECTION TRAIT
// ================================================================================================
#[async_trait]
pub trait DeviceDetectionStrategy: Send + Sync {
    async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError>;
    fn name(&self) -> &'static str;
}

// ================================================================================================
// MAC VENDOR DATABASE
// ================================================================================================
pub struct MacVendorDatabase {
    oui_db: OuiDatabase,
    vendor_cache: HashMap<String, String>,
}
impl MacVendorDatabase {
    pub fn new() -> Result<Self, NetworkDiscoveryError> {
        println!("Loading OUI database...");
        let oui_db = match OuiDatabase::new_from_str(MANUF_DATA) {
            Ok(db) => {
                println!("OUI database loaded successfully");
                db
            },
            Err(_) => {
                eprintln!("Failed to load manuf.txt. Using built-in OUI fallback.");
                OuiDatabase::new_from_str(BUILTIN_OUI)
                    .map_err(|e| NetworkDiscoveryError::OuiDatabaseError(e.to_string()))?
            }
        };
        Ok(Self {
            oui_db,
            vendor_cache: HashMap::new(),
        })
    }

    pub fn lookup_vendor(&mut self, mac: &str) -> Option<String> {
        let clean_mac = self.normalize_mac(mac)?;
        if let Some(vendor) = self.vendor_cache.get(&clean_mac) {
            return Some(vendor.clone());
        }
        if let Ok(mac_addr) = MacAddress::parse_str(&clean_mac) {
            if let Ok(Some(entry)) = self.oui_db.query_by_mac(&mac_addr) {
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

    fn normalize_mac(&self, mac: &str) -> Option<String> {
        let cleaned = mac.replace("-", ":").replace(".", ":").to_uppercase();
        let parts: Vec<&str> = cleaned.split(':').collect();
        if parts.len() == 6 && parts.iter().all(|p| p.len() == 2) {
            Some(cleaned)
        } else if cleaned.len() == 12 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut formatted = String::new();
            for (i, chunk) in cleaned.as_bytes().chunks(2).enumerate() {
                if i > 0 {
                    formatted.push(':');
                }
                formatted.push_str(&String::from_utf8_lossy(chunk));
            }
            Some(formatted)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub vendor: String,
    pub device_type: DeviceType,
    pub operating_system: Option<OperatingSystem>,
}

// ================================================================================================
// MAIN APPLICATION
// ================================================================================================
#[tokio::main]
async fn main() -> Result<(), NetworkDiscoveryError> {
    println!("Enhanced Network Discovery Tool v2.0");
    println!("=====================================");
    let args: Vec<String> = std::env::args().collect();
    let network = if args.len() > 1 {
        let arg = &args[1];
        if arg == "--help" || arg == "-h" {
            println!("Usage:");
            println!("  {} [INTERFACE_NAME|CIDR_NETWORK]", args[0]);
            println!();
            println!("Examples:");
            println!("  {} eth0                    # Scan network on eth0 interface", args[0]);
            println!("  {} en0                     # Scan network on en0 interface (macOS)", args[0]);
            println!("  {} wlan0                   # Scan network on wlan0 interface", args[0]);
            println!("  {} 192.168.1.0/24          # Scan specific CIDR network", args[0]);
            println!();
            println!("Options:");
            println!("  --list                     # List all available network interfaces");
            println!("  --help, -h                 # Show this help message");
            println!();
            list_network_interfaces()?;
            return Ok(());
        }
        if arg == "--list" {
            list_network_interfaces()?;
            return Ok(());
        }
        if arg.contains('/') {
            arg.clone()
        } else {
            match get_network_from_interface(arg) {
                Ok(network) => network,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    println!();
                    list_network_interfaces()?;
                    return Ok(());
                }
            }
        }
    } else {
        println!("No arguments provided. Usage:");
        println!("  {} [INTERFACE_NAME|CIDR_NETWORK]", args[0]);
        println!();
        println!("Examples:");
        println!("  {} eth0                    # Scan network on eth0 interface", args[0]);
        println!("  {} 192.168.1.0/24          # Scan specific CIDR network", args[0]);
        println!();
        list_network_interfaces()?;
        return Ok(());
    };

    println!("Target network: {}", network);
    println!();

    let discovery = EnhancedNetworkDiscovery::new()?;
    discovery.discover_network_enhanced(&network).await?;
    Ok(())
}
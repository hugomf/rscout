use async_trait::async_trait;
use comfy_table::{Cell, Table};
use eui48::MacAddress;
use futures::future::join_all;
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
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::timeout;
use trust_dns_resolver::TokioAsyncResolver;
use libarp::client::ArpClient;

// ================================================================================================
// CONFIGURATION & CONSTANTS
// ================================================================================================

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub common_ports: Vec<u16>,
    pub ping_timeout_ms: u64,
    pub tcp_connect_timeout_ms: u64,
    pub banner_read_timeout_ms: u64,
    pub private_network_ranges: Vec<(u8, u8, u8)>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            common_ports: vec![
                21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8000, 8080, 8443,
            ],
            ping_timeout_ms: 500,
            tcp_connect_timeout_ms: 300,
            banner_read_timeout_ms: 500,
            private_network_ranges: vec![
                (192, 168, 0),
                (10, 0, 0),
                (172, 16, 0),
            ],
        }
    }
}

// ================================================================================================
// CUSTOM ERROR TYPES
// ================================================================================================

#[derive(Debug)]
pub enum NetworkDiscoveryError {
    OuiDatabaseError(String),
    PingError(String),
    PortScanError(String),
    HostnameResolutionError(String),
    IoError(std::io::Error),
    NetworkInterfaceError(String),
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

// ================================================================================================
// CORE DATA STRUCTURES AND TRAITS
// ================================================================================================

/// Represents a network device discovered during scanning
#[derive(Debug, Clone)]
pub struct NetworkDevice {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: DeviceType,
    pub operating_system: Option<OperatingSystem>,
    pub open_ports: Vec<u16>,
    pub services: Vec<NetworkService>,
    pub response_time: Option<Duration>,
    pub last_seen: std::time::SystemTime,
}

/// Enum representing different types of network devices
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
}

/// Enum representing different operating systems
#[derive(Debug, Clone, PartialEq)]
pub enum OperatingSystem {
    Unknown,
    Windows(Option<String>),
    MacOS(Option<String>),
    Linux(Option<String>),
    IOS(Option<String>),
    Android(Option<String>),
    RouterOS,
    Other(String),
}

/// Represents a network service running on a device
#[derive(Debug, Clone)]
pub struct NetworkService {
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub service_type: Option<String>,
    pub txt_records: Vec<String>,
}

/// Trait defining the interface for device detection strategies
#[async_trait]
pub trait DeviceDetectionStrategy: Send + Sync {
    /// Detect device information using this strategy
    async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError>;
    /// Return the name of this detection strategy
    fn name(&self) -> &'static str;
}

// ================================================================================================
// MAC ADDRESS VENDOR DATABASE USING OUI
// ================================================================================================

pub struct MacVendorDatabase {
    oui_db: OuiDatabase,
    vendor_cache: HashMap<String, String>,
}

impl MacVendorDatabase {
    /// Create a new MAC vendor database
    pub fn new() -> Result<Self, NetworkDiscoveryError> {
        println!("📋 Loading OUI database...");
        let file_path = "manuf.txt";
        let oui_db = match OuiDatabase::new_from_file(file_path) {
            Ok(db) => db,
            Err(e) => {
                eprintln!("⚠️ Failed to load {} from project root: {}", file_path, e);
                println!("⚠️ Using fallback OUI database (this will result in missing vendor info)");
                OuiDatabase::new_from_str("")
                    .map_err(|e| NetworkDiscoveryError::OuiDatabaseError(e.to_string()))?
            }
        };
        println!("✅ OUI database loaded successfully");
        Ok(Self {
            oui_db,
            vendor_cache: HashMap::new(),
        })
    }

    /// Look up vendor information for a MAC address
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

    /// Get complete device information from MAC address
    pub fn get_device_info(&mut self, mac: &str) -> Option<DeviceInfo> {
        let vendor = self.lookup_vendor(mac)?;
        Some(DeviceInfo {
            vendor: vendor.clone(),
            device_type: self.infer_device_type(&vendor),
            operating_system: self.infer_operating_system(&vendor),
        })
    }

    /// Normalize MAC address format
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

    /// Infer device type from vendor name
    fn infer_device_type(&self, vendor: &str) -> DeviceType {
        let vendor_lower = vendor.to_lowercase();
        
        match vendor_lower.as_str() {
            v if v.contains("apple") => DeviceType::AppleDevice,
            v if v.contains("samsung") && (v.contains("electronics") || v.contains("mobile")) => {
                DeviceType::Smartphone
            }
            v if v.contains("cisco") => DeviceType::Router,
            v if v.contains("netgear")
                || v.contains("linksys")
                || v.contains("tp-link")
                || v.contains("d-link")
                || v.contains("asus") && v.contains("tek") => {
                DeviceType::Router
            }
            v if v.contains("ubiquiti") || v.contains("aruba") || v.contains("ruckus") => {
                DeviceType::AccessPoint
            }
            v if v.contains("hewlett") && v.contains("packard") => DeviceType::Printer,
            v if v.contains("canon") || v.contains("epson") || v.contains("brother") => {
                DeviceType::Printer
            }
            v if v.contains("vmware")
                || v.contains("virtualbox")
                || v.contains("parallels")
                || v.contains("microsoft") && v.contains("virtual") => {
                DeviceType::Computer
            }
            v if v.contains("intel") || v.contains("realtek") || v.contains("qualcomm") => {
                DeviceType::Computer
            }
            v if v.contains("lg") && v.contains("electronics") => DeviceType::SmartTV,
            v if v.contains("sony") && (v.contains("computer") || v.contains("mobile")) => {
                DeviceType::SmartTV
            }
            v if v.contains("amazon") || v.contains("google") && v.contains("nest") => {
                DeviceType::IoTDevice
            }
            v if v.contains("raspberry") || v.contains("arduino") => DeviceType::IoTDevice,
            _ => DeviceType::Unknown,
        }
    }

    /// Infer operating system from vendor name
    fn infer_operating_system(&self, vendor: &str) -> Option<OperatingSystem> {
        let vendor_lower = vendor.to_lowercase();
        
        match vendor_lower.as_str() {
            v if v.contains("apple") => Some(OperatingSystem::MacOS(None)),
            v if v.contains("microsoft") => Some(OperatingSystem::Windows(None)),
            v if v.contains("samsung") && v.contains("electronics") => {
                Some(OperatingSystem::Android(None))
            }
            v if v.contains("cisco") || v.contains("juniper") => Some(OperatingSystem::RouterOS),
            v if v.contains("vmware") => Some(OperatingSystem::Linux(Some("VMware".to_string()))),
            v if v.contains("raspberry") => {
                Some(OperatingSystem::Linux(Some("Raspberry Pi OS".to_string())))
            }
            _ => None,
        }
    }
}

/// Struct containing device information derived from MAC address
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub vendor: String,
    pub device_type: DeviceType,
    pub operating_system: Option<OperatingSystem>,
}

// ================================================================================================
// DEVICE DETECTION STRATEGIES
// ================================================================================================

/// Strategy for detecting devices by analyzing MAC addresses
pub struct MacAddressStrategy {
    vendor_db: Arc<Mutex<MacVendorDatabase>>,
}

impl MacAddressStrategy {
    /// Create a new MAC address detection strategy
    pub fn new(vendor_db: Arc<Mutex<MacVendorDatabase>>) -> Self {
        Self { vendor_db }
    }
}

#[async_trait]
impl DeviceDetectionStrategy for MacAddressStrategy {
    fn name(&self) -> &'static str {
        "MAC Address Analysis (OUI Database)"
    }

    async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
        if let Some(ref mac) = device.mac {
            let device_info = {
                let mut db = self.vendor_db.lock().await;
                db.get_device_info(mac)
            };
            
            if let Some(info) = device_info {
                device.vendor = Some(info.vendor);
                if device.device_type == DeviceType::Unknown {
                    device.device_type = info.device_type;
                }
                if device.operating_system.is_none() {
                    device.operating_system = info.operating_system;
                }
            }
        }
        Ok(())
    }
}

/// Strategy for detecting devices by scanning open ports
pub struct PortScanStrategy {
    common_ports: Vec<u16>,
    config: ScanConfig,
}

impl PortScanStrategy {
    /// Create a new port scanning strategy
    pub fn new(config: ScanConfig) -> Self {
        Self {
            common_ports: config.common_ports.clone(),
            config,
        }
    }

    fn get_service_name(port: u16) -> Option<String> {
        match port {
            21 => Some("FTP".to_string()),
            22 => Some("SSH".to_string()),
            23 => Some("Telnet".to_string()),
            25 => Some("SMTP".to_string()),
            53 => Some("DNS".to_string()),
            80 => Some("HTTP".to_string()),
            110 => Some("POP3".to_string()),
            135 => Some("RPC".to_string()),
            139 => Some("NetBIOS".to_string()),
            143 => Some("IMAP".to_string()),
            443 => Some("HTTPS".to_string()),
            445 => Some("SMB".to_string()),
            993 => Some("IMAPS".to_string()),
            995 => Some("POP3S".to_string()),
            1723 => Some("PPTP".to_string()),
            3306 => Some("MySQL".to_string()),
            3389 => Some("RDP".to_string()),
            5900 => Some("VNC".to_string()),
            8000 => Some("HTTP-Alt".to_string()),
            8080 => Some("HTTP-Proxy".to_string()),
            8443 => Some("HTTPS-Alt".to_string()),
            _ => None,
        }
    }
}

#[async_trait]
impl DeviceDetectionStrategy for PortScanStrategy {
    fn name(&self) -> &'static str {
        "Port Scanning & Banner Grabbing"
    }

    async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
        let ip = device.ip;
        let mut port_handles = Vec::new();
        let tcp_timeout = Duration::from_millis(self.config.tcp_connect_timeout_ms);
        let banner_timeout = Duration::from_millis(self.config.banner_read_timeout_ms);

        for &port in &self.common_ports {
            let handle = tokio::spawn(async move {
                let mut open_port_info: Option<(u16, NetworkService)> = None;
                
                if let Ok(connect_result) = timeout(
                    tcp_timeout,
                    TcpStream::connect((ip, port))
                ).await {
                    if let Ok(mut stream) = connect_result {
                        let mut service = NetworkService {
                            port,
                            protocol: "TCP".to_string(),
                            service_name: Self::get_service_name(port),
                            banner: None,
                            service_type: None,
                            txt_records: Vec::new(),
                        };

                        let mut buf = vec![0; 1024];
                        
                        // Send HTTP request for web ports
                        if port == 80 || port == 443 || port == 8080 || port == 8443 {
                            let request = b"HEAD / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";
                            let _ = timeout(
                                tcp_timeout,
                                stream.write_all(request)
                            ).await;
                        }

                        // Read banner
                        if let Ok(bytes_read) = timeout(
                            banner_timeout,
                            stream.read(&mut buf)
                        ).await {
                            if let Ok(count) = bytes_read {
                                if count > 0 {
                                    if let Ok(banner_string) = String::from_utf8(buf[..count].to_vec()) {
                                        service.banner = Some(banner_string.lines()
                                            .filter(|l| !l.trim().is_empty())
                                            .take(3)
                                            .map(|l| l.trim().to_string())
                                            .collect::<Vec<String>>()
                                            .join(" | ")
                                        );
                                    }
                                }
                            }
                        }
                        
                        open_port_info = Some((port, service));
                    }
                }
                open_port_info
            });
            
            port_handles.push(handle);
        }

        let results = join_all(port_handles).await;
        
        for result in results {
            if let Ok(Some((port, service))) = result {
                device.open_ports.push(port);
                device.services.push(service);
            }
        }

        // Sort and deduplicate ports
        device.open_ports.sort();
        device.open_ports.dedup();

        // Infer device type and OS from services
        let mut has_web_server = false;
        let mut has_windows_service = false;
        let mut has_ssh = false;

        for service in &device.services {
            match service.port {
                80 | 443 | 8080 | 8443 => {
                    has_web_server = true;
                    if let Some(ref banner) = service.banner {
                        let lower_banner = banner.to_lowercase();
                        if lower_banner.contains("apache") || lower_banner.contains("nginx") {
                            if device.operating_system.is_none() {
                                device.operating_system = Some(OperatingSystem::Linux(None));
                            }
                            if device.device_type == DeviceType::Unknown {
                                device.device_type = DeviceType::Server;
                            }
                        } else if lower_banner.contains("microsoft-iis") {
                            if device.operating_system.is_none() {
                                device.operating_system = Some(OperatingSystem::Windows(None));
                            }
                            if device.device_type == DeviceType::Unknown {
                                device.device_type = DeviceType::Server;
                            }
                        } else if lower_banner.contains("router") || lower_banner.contains("admin page") {
                            if device.device_type == DeviceType::Unknown {
                                device.device_type = DeviceType::Router;
                            }
                        }
                    }
                }
                22 => {
                    has_ssh = true;
                    if let Some(ref banner) = service.banner {
                        let lower_banner = banner.to_lowercase();
                        if lower_banner.contains("debian") || lower_banner.contains("ubuntu") {
                            device.operating_system = Some(OperatingSystem::Linux(Some("Debian/Ubuntu".to_string())));
                        } else if lower_banner.contains("openssh") {
                            device.operating_system = Some(OperatingSystem::Linux(None));
                        }
                    }
                }
                135 | 139 | 445 | 3389 => {
                    has_windows_service = true;
                }
                _ => {}
            }
        }

        // Set OS if not already determined
        if device.operating_system.is_none() {
            if has_windows_service {
                device.operating_system = Some(OperatingSystem::Windows(None));
            } else if has_ssh {
                device.operating_system = Some(OperatingSystem::Linux(None));
            }
        }

        // Set device type if not already determined
        if device.device_type == DeviceType::Unknown {
            if has_windows_service || has_ssh {
                device.device_type = DeviceType::Computer;
            } else if has_web_server {
                device.device_type = DeviceType::Router;
            }
        }

        Ok(())
    }
}

/// Strategy for detecting devices by analyzing hostnames
pub struct HostnameAnalysisStrategy {
    resolver: TokioAsyncResolver,
}

impl HostnameAnalysisStrategy {
    pub fn new() -> Result<Self, NetworkDiscoveryError> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| NetworkDiscoveryError::HostnameResolutionError(e.to_string()))?;
        Ok(Self { resolver })
    }

    fn generate_smart_hostname(&self, device: &mut NetworkDevice) {
        let mut hostname = String::new();
        
        // Generate hostname based on vendor
        if let Some(ref vendor) = device.vendor {
            let vendor_lower = vendor.to_lowercase();
            
            hostname = match vendor_lower.as_str() {
                v if v.contains("bose") => "bose-speaker".to_string(),
                v if v.contains("raspberry") => "raspberry-pi".to_string(),
                v if v.contains("epson") => "epson-printer".to_string(),
                v if v.contains("huawei") => "huawei-router".to_string(),
                v if v.contains("dahua") => "dahua-camera".to_string(),
                _ => {
                    if let Some(first_word) = vendor.split_whitespace().next() {
                        // Corrected line: create a new String and return it
                        first_word.to_lowercase()
                    } else {
                        "device".to_string()
                    }
                }
            }.to_string();
        }

        // Fallback to device type if no vendor-based hostname
        if hostname.is_empty() {
            hostname = match device.device_type {
                DeviceType::Router => "router",
                DeviceType::Printer => "printer",
                DeviceType::Computer => "computer",
                DeviceType::IoTDevice => "iot-device",
                DeviceType::SmartTV => "smart-tv",
                DeviceType::Server => "server",
                _ => "device",
            }.to_string();
        }

        // Add service indicators
        if !device.open_ports.is_empty() {
            let mut suffixes = Vec::new();
            
            if device.open_ports.contains(&22) && !hostname.contains("ssh") {
                suffixes.push("ssh");
            }
            if (device.open_ports.contains(&80) || device.open_ports.contains(&443)) && 
               device.device_type == DeviceType::Router && !hostname.contains("web") {
                suffixes.push("admin");
            }
            if device.open_ports.contains(&3389) {
                suffixes.push("rdp");
            }
            if device.open_ports.contains(&5900) {
                suffixes.push("vnc");
            }
            
            if !suffixes.is_empty() {
                hostname.push_str(&format!("-{}", suffixes.join("-")));
            }
        }

        // Add banner-based indicators
        for service in &device.services {
            if let Some(ref banner) = service.banner {
                let banner_lower = banner.to_lowercase();
                
                if banner_lower.contains("dropbear") && !hostname.contains("embedded") {
                    hostname = "embedded-linux".to_string();
                    break;
                } else if banner_lower.contains("microsoft-iis") {
                    hostname.push_str("-iis");
                } else if banner_lower.contains("apache") {
                    hostname.push_str("-apache");
                } else if banner_lower.contains("nginx") {
                    hostname.push_str("-nginx");
                }
            }
        }

        // Add IP suffix and .local domain
        let ip_suffix = device.ip.to_string().replace(".", "-");
        let last_octet = ip_suffix.split('-').last().unwrap_or("x");
        hostname.push_str(&format!("-{}", last_octet));
        hostname.push_str(".local");
        
        device.hostname = Some(hostname);
    }

    fn infer_from_hostname(&self, device: &mut NetworkDevice, hostname: &str) {
        let hostname_lower = hostname.to_lowercase();
        
        // Apply all inference methods
        self.infer_apple_devices(device, &hostname_lower);
        self.infer_network_infrastructure(device, &hostname_lower);
        self.infer_printers(device, &hostname_lower);
        self.infer_android_devices(device, &hostname_lower);
        self.infer_google_devices(device, &hostname_lower);
        self.infer_raspberry_pi(device, &hostname_lower);
        self.infer_gaming_consoles(device, &hostname_lower);
        self.infer_servers(device, &hostname_lower);
        self.infer_windows_machines(device, &hostname_lower);
        self.infer_smart_tvs(device, &hostname_lower);
    }

    fn infer_apple_devices(&self, device: &mut NetworkDevice, hostname_lower: &str) {
        if hostname_lower.contains("apple") || hostname_lower.ends_with(".local") {
            if hostname_lower.contains("iphone") {
                device.device_type = DeviceType::Smartphone;
                device.operating_system = Some(OperatingSystem::IOS(None));
                device.vendor = device.vendor.clone().or(Some("Apple".to_string()));
            } else if hostname_lower.contains("ipad") {
                device.device_type = DeviceType::Tablet;
                device.operating_system = Some(OperatingSystem::IOS(None));
                device.vendor = device.vendor.clone().or(Some("Apple".to_string()));
            } else if hostname_lower.contains("mac") || hostname_lower.contains("imac") || hostname_lower.contains("macbook") {
                device.device_type = DeviceType::Computer;
                device.operating_system = Some(OperatingSystem::MacOS(None));
                device.vendor = device.vendor.clone().or(Some("Apple".to_string()));
            } else if hostname_lower.contains("appletv") || hostname_lower.contains("apple-tv") {
                device.device_type = DeviceType::SmartTV;
                device.operating_system = Some(OperatingSystem::Other("tvOS".to_string()));
                device.vendor = device.vendor.clone().or(Some("Apple".to_string()));
            }
        }
    }

    fn infer_network_infrastructure(&self, device: &mut NetworkDevice, hostname_lower: &str) {
        if hostname_lower.contains("router") || hostname_lower.contains("gateway") || hostname_lower.contains("ap-") {
            device.device_type = DeviceType::Router;
        } else if hostname_lower.contains("switch") {
            device.device_type = DeviceType::Switch;
        }
    }

    fn infer_printers(&self, device: &mut NetworkDevice, hostname_lower: &str) {
        if hostname_lower.contains("printer") || hostname_lower.contains("hp-") || 
           hostname_lower.contains("canon-") || hostname_lower.contains("epson") || 
           hostname_lower.contains("brother") {
            device.device_type = DeviceType::Printer;
        }
    }

    fn infer_android_devices(&self, device: &mut NetworkDevice, hostname_lower: &str) {
        if hostname_lower.contains("android") || hostname_lower.contains("samsung") {
            if device.device_type == DeviceType::Unknown {
                device.device_type = DeviceType::Smartphone;
            }
            device.operating_system = Some(OperatingSystem::Android(None));
        }
    }

    fn infer_google_devices(&self, device: &mut NetworkDevice, hostname_lower: &str) {
        if hostname_lower.contains("chromecast") || hostname_lower.contains("google-") || hostname_lower.contains("nest-") {
            if device.device_type == DeviceType::Unknown {
                device.device_type = if hostname_lower.contains("chromecast") {
                    DeviceType::SmartTV
                } else {
                    DeviceType::IoTDevice
                };
            }
            device.vendor = device.vendor.clone().or(Some("Google".to_string()));
        }
    }

    fn infer_raspberry_pi(&self, device: &mut NetworkDevice, hostname_lower: &str) {
        if hostname_lower.contains("raspberrypi") || hostname_lower.contains("raspberry") {
            device.device_type = DeviceType::IoTDevice;
            device.operating_system = Some(OperatingSystem::Linux(Some("Raspberry Pi OS".to_string())));
            device.vendor = device.vendor.clone().or(Some("Raspberry Pi Trading Ltd".to_string()));
        }
    }

    fn infer_gaming_consoles(&self, device: &mut NetworkDevice, hostname_lower: &str) {
        if hostname_lower.contains("xbox") || hostname_lower.contains("playstation") {
            device.device_type = DeviceType::IoTDevice;
        }
    }

    fn infer_servers(&self, device: &mut NetworkDevice, hostname_lower: &str) {
        if hostname_lower.contains("server") || hostname_lower.contains("srv") {
            device.device_type = DeviceType::Server;
        }
    }

    fn infer_windows_machines(&self, device: &mut NetworkDevice, hostname_lower: &str) {
        if hostname_lower.contains("desktop") || hostname_lower.contains("laptop") || hostname_lower.contains("pc") {
            device.device_type = DeviceType::Computer;
            device.operating_system = Some(OperatingSystem::Windows(None));
        }
    }

    fn infer_smart_tvs(&self, device: &mut NetworkDevice, hostname_lower: &str) {
        if hostname_lower.contains("tv") || hostname_lower.contains("roku") || hostname_lower.contains("firetv") {
            device.device_type = DeviceType::SmartTV;
        }
    }
}

#[async_trait]
impl DeviceDetectionStrategy for HostnameAnalysisStrategy {
    fn name(&self) -> &'static str {
        "Smart Hostname & Device Inference"
    }

    async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
        let ip = device.ip;
        
        // Try reverse DNS lookup
        let hostname = if let Ok(reverse_lookup) = self.resolver.reverse_lookup(ip).await {
            reverse_lookup
                .iter()
                .next()
                .map(|name| name.to_string().trim_end_matches('.').to_string())
        } else {
            None
        };

        if let Some(ref hostname) = hostname {
            device.hostname = Some(hostname.clone());
            self.infer_from_hostname(device, hostname);
        } else {
            self.generate_smart_hostname(device);
        }
        
        Ok(())
    }
}

/// Strategy for analyzing ping responses
pub struct PingAnalysisStrategy;

impl PingAnalysisStrategy {
    /// Create a new ping analysis strategy
    pub fn new() -> Self {
        PingAnalysisStrategy
    }
}

#[async_trait]
impl DeviceDetectionStrategy for PingAnalysisStrategy {
    fn name(&self) -> &'static str {
        "Ping Analysis"
    }

    async fn detect(&self, _device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
        // Currently just a placeholder - could be expanded to analyze ping response times
        // or packet loss to infer device types or network conditions
        Ok(())
    }
}

// ================================================================================================
// NETWORK DISCOVERY ENGINE
// ================================================================================================

/// Main network discovery engine
pub struct NetworkDiscovery {
    strategies: Arc<Vec<Box<dyn DeviceDetectionStrategy>>>,
    config: ScanConfig,
}

impl NetworkDiscovery {
    /// Create a new network discovery engine
    pub fn new() -> Result<Self, NetworkDiscoveryError> {
        let config = ScanConfig::default();
        let vendor_db = Arc::new(Mutex::new(MacVendorDatabase::new()?));
        
        let mut strategies_vec: Vec<Box<dyn DeviceDetectionStrategy>> = Vec::new();
        strategies_vec.push(Box::new(MacAddressStrategy::new(vendor_db.clone())));
        strategies_vec.push(Box::new(PortScanStrategy::new(config.clone())));
        strategies_vec.push(Box::new(HostnameAnalysisStrategy::new()?));
        strategies_vec.push(Box::new(PingAnalysisStrategy::new()));
        
        Ok(Self {
            strategies: Arc::new(strategies_vec),
            config,
        })
    }

    /// Add a new detection strategy (for future expansion)
    pub fn add_strategy(&mut self, _strategy: Box<dyn DeviceDetectionStrategy>) {
        // Implementation for future expansion
        // Would need to modify the Arc<Vec<>> to be mutable or use a different data structure
    }

    /// Discover devices on the network and display results
    pub async fn discover_network_stream(&self, network: &str) -> Result<(), NetworkDiscoveryError> {
        if !network.contains('/') {
            return Err(NetworkDiscoveryError::PingError(
                "Network must be in CIDR format (e.g., 192.168.1.0/24)".to_string()
            ));
        }

        let scan_start = Instant::now();
        let active_ips = self.ping_sweep(network).await?;
        
        println!("📍 Found {} active devices", active_ips.len());
        println!("🔄 Starting detailed scan...\n");

        let discovered_devices = Arc::new(Mutex::new(HashMap::<IpAddr, NetworkDevice>::new()));
        let (tx, mut rx) = mpsc::channel::<NetworkDevice>(active_ips.len());
        
        let total_devices = active_ips.len();
        let mut completed = 0;

        // Create tasks for scanning each device
        for ip in active_ips {
            println!("- Scanning device {}", ip);
            
            let strategies = self.strategies.clone();
            let tx_clone = tx.clone();
            
            tokio::spawn(async move {
                let mut client = ArpClient::new().unwrap();
                let mac = if let IpAddr::V4(ipv4) = ip {
                    match client.ip_to_mac(ipv4, None).await {
                        Ok(mac) => Some(mac.to_string().to_uppercase()),
                        Err(e) => {
                            eprintln!("ARP error for {}: {}", ipv4, e);
                            None
                        }
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
                    open_ports: Vec::new(),
                    services: Vec::new(),
                    response_time: None,
                    last_seen: std::time::SystemTime::now(),
                };

                // Apply all detection strategies
                for strategy in strategies.iter() {
                    let _ = strategy.detect(&mut device).await;
                }

                let _ = tx_clone.send(device).await; 
            });
        }

        // Close the sender to signal no more devices will be sent
        drop(tx); 

        // Receive results and update device information
        while let Some(mut device) = rx.recv().await {
            completed += 1;
            println!("✅ Scanned {}/{} devices", completed, total_devices);
            
            let mut devices_map = discovered_devices.lock().await;
            
            if let Some(existing_device) = devices_map.get_mut(&device.ip) {
                // Update fields only if they're not already set
                if existing_device.mac.is_none() && device.mac.is_some() { 
                    existing_device.mac = device.mac.take(); 
                }
                if existing_device.hostname.is_none() && device.hostname.is_some() { 
                    existing_device.hostname = device.hostname.take(); 
                }
                if existing_device.vendor.is_none() && device.vendor.is_some() { 
                    existing_device.vendor = device.vendor.take(); 
                }
                if existing_device.device_type == DeviceType::Unknown && device.device_type != DeviceType::Unknown { 
                    existing_device.device_type = device.device_type; 
                }
                if existing_device.operating_system.is_none() && device.operating_system.is_some() { 
                    existing_device.operating_system = device.operating_system.take(); 
                }
                
                // Merge ports and services
                existing_device.open_ports.extend(device.open_ports.iter().cloned());
                existing_device.open_ports.sort();
                existing_device.open_ports.dedup();
                existing_device.services.extend(device.services.iter().cloned());
            } else {
                devices_map.insert(device.ip, device);
            }
        }

        // Display results in a table
        let devices_map = discovered_devices.lock().await;
        let mut table = Table::new();
        table.set_header(vec!["IP", "Hostname", "Vendor", "Type", "OS", "Ports", "Services"]);

        for (_, device) in devices_map.iter() {
            let service_details = if device.services.is_empty() {
                "—".to_string()
            } else {
                device.services.iter().map(|s| {
                    if let Some(ref name) = s.service_name {
                        name.clone()
                    } else {
                        s.port.to_string()
                    }
                }).collect::<Vec<String>>().join(", ")
            };

            let ports_list = if device.open_ports.is_empty() {
                "—".to_string()
            } else {
                device.open_ports.iter().map(|p| p.to_string()).collect::<Vec<String>>().join(", ")
            };

            let os_string = if let Some(ref os) = device.operating_system {
                match os {
                    OperatingSystem::Windows(_) => "Windows".to_string(),
                    OperatingSystem::MacOS(_) => "macOS".to_string(),
                    OperatingSystem::Linux(Some(name)) => format!("Linux ({})", name),
                    OperatingSystem::Linux(None) => "Linux".to_string(),
                    OperatingSystem::IOS(_) => "iOS".to_string(),
                    OperatingSystem::Android(_) => "Android".to_string(),
                    OperatingSystem::RouterOS => "RouterOS".to_string(),
                    _ => "Unknown".to_string(),
                }
            } else {
                "Unknown".to_string()
            };

            table.add_row(vec![
                Cell::new(device.ip.to_string()),
                Cell::new(device.hostname.clone().unwrap_or_else(|| "—".to_string())),
                Cell::new(device.vendor.clone().unwrap_or_else(|| "—".to_string())),
                Cell::new(format!("{:?}", device.device_type)),
                Cell::new(os_string),
                Cell::new(ports_list),
                Cell::new(service_details),
            ]);
        }

        println!("{}", table);
        let scan_duration = scan_start.elapsed();
        println!("\n⏱️  Scan completed in {:.2} seconds", scan_duration.as_secs_f64());
        
        Ok(())
    }

    /// Perform a ping sweep to find active devices on the network
    async fn ping_sweep(&self, network: &str) -> Result<Vec<IpAddr>, NetworkDiscoveryError> {
        let ping_timeout = Duration::from_millis(self.config.ping_timeout_ms);
        
        if let Some(base) = network.strip_suffix("/24") {
            let base_parts: Vec<&str> = base.split('.').collect();
            
            if base_parts.len() == 4 {
                let base_ip_str = format!("{}.{}.{}.", base_parts[0], base_parts[1], base_parts[2]);
                
                // Create a stream of futures for pinging each IP
                let ping_stream = stream::iter(1..255)
                    .map(|i| {
                        let ip_str = format!("{}{}", base_ip_str, i);
                        let ping_timeout = ping_timeout; // Capture for the closure
                        async move {
                            if let Ok(ip) = Ipv4Addr::from_str(&ip_str) {
                                let target_ip: IpAddr = ip.into();
                                let payload = [0; 56];
                                
                                match timeout(ping_timeout, ping(target_ip, &payload)).await {
                                    Ok(Ok((_icmp_packet, _duration))) => {
                                        Some(target_ip)
                                    },
                                    Ok(Err(e)) => {
                                        eprintln!("Ping error for {}: {}", target_ip, e);
                                        None
                                    },
                                    Err(_) => None,
                                }
                            } else {
                                None
                            }
                        }
                    })
                    // Limit concurrency to 64 pings at a time
                    .buffer_unordered(64);

                // Collect results as they come in
                let active_ips: Vec<IpAddr> = ping_stream
                    .filter_map(|result| async move { result }) // Filter out `None` values
                    .collect()
                    .await;
                    
                return Ok(active_ips);
            }
        }
        
        // Return empty vec if CIDR format is not /24 or parsing fails
        Ok(Vec::new())
    }
}

// ================================================================================================
// DISPLAY AND FORMATTING
// ================================================================================================

impl std::fmt::Display for NetworkDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "🖥️  Device: {}", self.ip)?;
        
        if let Some(ref hostname) = self.hostname {
            writeln!(f, "   📛 Hostname: {}", hostname)?;
            if hostname.ends_with(".local") {
                writeln!(f, "      └─ mDNS/Bonjour device")?;
            }
            if hostname.contains("apple") || hostname.contains("iphone") || hostname.contains("ipad") || hostname.contains("mac") {
                writeln!(f, "      └─ Apple ecosystem device")?;
            }
        } else {
            writeln!(f, "   📛 Hostname: Not resolved")?;
        }
        
        if let Some(ref mac) = self.mac {
            writeln!(f, "   🔗 MAC: {}", mac)?;
        }
        
        if let Some(ref vendor) = self.vendor {
            writeln!(f, "   🏢 Vendor: {}", vendor)?;
        }
        
        writeln!(f, "   📱 Type: {:?}", self.device_type)?;
        
        if let Some(ref os) = self.operating_system {
            writeln!(f, "   💻 OS: {:?}", os)?;
        }
        
        if !self.open_ports.is_empty() {
            writeln!(f, "   🔓 Open Ports: {:?}", self.open_ports)?;
        }
        
        if let Some(response_time) = self.response_time {
            writeln!(f, "   ⚡ Response Time: {:?}", response_time)?;
        }
        
        if !self.services.is_empty() {
            writeln!(f, "   🛠️  Services:")?;
            for service in &self.services {
                let mut service_line = format!("      • {}/{}", service.port, service.protocol);
                
                if let Some(ref name) = service.service_name {
                    service_line.push_str(&format!(" ({})", name));
                }
                
                if let Some(ref service_type) = service.service_type {
                    service_line.push_str(&format!(" [{}]", service_type));
                }
                
                if let Some(ref banner) = service.banner {
                    let short_banner = if banner.len() > 80 {
                        format!("{}...", &banner[..77])
                    } else {
                        banner.clone()
                    };
                    service_line.push_str(&format!(" | Banner: \"{}\"", short_banner.replace("\n", " ")));
                }
                
                writeln!(f, "{}", service_line)?;
            }
        }
        
        writeln!(f, "")
    }
}

// ================================================================================================
// MAIN APPLICATION
// ================================================================================================

#[tokio::main]
async fn main() -> Result<(), NetworkDiscoveryError> {
    println!("🌐 Network Discovery Tool - Rust Implementation");
    println!("================================================");
    
    let args: Vec<String> = std::env::args().collect();
    let network = if args.len() > 1 {
        args[1].clone()
    } else {
        "192.168.1.0/24".to_string()
    };
    
    println!("🔍 Target network: {}", network);
    println!();
    
    let discovery = NetworkDiscovery::new()?;
    discovery.discover_network_stream(&network).await?;
    
    Ok(())
}
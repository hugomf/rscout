use async_trait::async_trait;
use comfy_table::{Cell, Table};
use eui48::MacAddress;
use oui::OuiDatabase;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process;
use surge_ping::ping;
use regex;
use futures::future::join_all;

// ================================================================================================
// CORE DATA STRUCTURES AND TRAITS
// ================================================================================================

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

#[derive(Debug, Clone)]
pub struct NetworkService {
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub service_type: Option<String>,
    pub txt_records: Vec<String>,
}

#[async_trait]
pub trait DeviceDetectionStrategy: Send + Sync {
    async fn detect(
        &self,
        device: &mut NetworkDevice,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
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
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        println!("📋 Loading OUI database...");
        // include_bytes! expects path relative to CARGO_MANIFEST_DIR (project root)
        let file_path = "manuf.txt";
        let oui_db = match OuiDatabase::new_from_file(file_path) {
            Ok(db) => db,
            Err(e) => {
                eprintln!("⚠️ Failed to load {}  from project root: {}", file_path, e);
                println!("⚠️ Using fallback OUI database (this will result in missing vendor info)");
                OuiDatabase::new_from_str("")? // Fallback to an empty database
            }
        };
        println!("✅ OUI database loaded successfully");

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
            device_type: self.infer_device_type(&vendor),
            operating_system: self.infer_operating_system(&vendor),
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
                || v.contains("asus") && v.contains("tek") =>
            {
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
                || v.contains("microsoft") && v.contains("virtual") =>
            {
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

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub vendor: String,
    pub device_type: DeviceType,
    pub operating_system: Option<OperatingSystem>,
}

// ================================================================================================
// DEVICE DETECTION STRATEGIES
// ================================================================================================

pub struct MacAddressStrategy {
    vendor_db: Arc<Mutex<MacVendorDatabase>>,
}

impl MacAddressStrategy {
    pub fn new(vendor_db: Arc<Mutex<MacVendorDatabase>>) -> Self {
        Self { vendor_db }
    }
}

#[async_trait]
impl DeviceDetectionStrategy for MacAddressStrategy {
    fn name(&self) -> &'static str {
        "MAC Address Analysis (OUI Database)"
    }

    async fn detect(
        &self,
        device: &mut NetworkDevice,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

pub struct PortScanStrategy {
    common_ports: Vec<u16>,
}

impl PortScanStrategy {
    pub fn new() -> Self {
        Self {
            common_ports: vec![
                21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8000, 8080, 8443,
            ],
        }
    }
}

#[async_trait]
impl DeviceDetectionStrategy for PortScanStrategy {
    fn name(&self) -> &'static str {
        "Port Scanning & Banner Grabbing"
    }

    async fn detect(
        &self,
        device: &mut NetworkDevice,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ip = device.ip;
        let mut port_handles = Vec::new();

        for &port in &self.common_ports {
            let handle = tokio::spawn(async move {
                let mut open_port_info: Option<(u16, NetworkService)> = None;

                if let Ok(connect_result) = timeout(Duration::from_millis(300), TcpStream::connect((ip, port))).await {
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
                        if port == 80 || port == 443 || port == 8080 || port == 8443 {
                            let request = b"HEAD / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";
                            let _ = timeout(Duration::from_millis(300), stream.write_all(request)).await;
                        }

                        if let Ok(bytes_read) = timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
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
                device.open_ports.sort();
                device.open_ports.dedup();
                device.services.push(service);
            }
        }
        
        // Final inference pass after all ports have been scanned
        let mut has_web_server = false;
        let mut has_windows_service = false;
        let mut has_ssh = false;

        for service in &device.services {
            if service.port == 80 || service.port == 443 || service.port == 8080 || service.port == 8443 {
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
            } else if service.port == 22 {
                has_ssh = true;
                if let Some(ref banner) = service.banner {
                    let lower_banner = banner.to_lowercase();
                    if lower_banner.contains("debian") || lower_banner.contains("ubuntu") {
                        device.operating_system = Some(OperatingSystem::Linux(Some("Debian/Ubuntu".to_string())));
                    } else if lower_banner.contains("openssh") {
                        device.operating_system = Some(OperatingSystem::Linux(None));
                    }
                }
            } else if service.port == 135 || service.port == 139 || service.port == 445 || service.port == 3389 {
                has_windows_service = true;
            }
        }

        // Final inferences based on combined results
        if device.operating_system.is_none() {
            if has_windows_service {
                device.operating_system = Some(OperatingSystem::Windows(None));
            } else if has_ssh {
                device.operating_system = Some(OperatingSystem::Linux(None));
            }
        }
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

impl PortScanStrategy {
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

// Enhanced mDNS strategy with multiple hostname resolution methods
pub struct ImprovedMdnsStrategy;

#[async_trait]
impl DeviceDetectionStrategy for ImprovedMdnsStrategy {
    fn name(&self) -> &'static str {
        "Smart Hostname & Device Inference"
    }

    async fn detect(
        &self,
        device: &mut NetworkDevice,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ip = device.ip;
        
        // Try a few quick hostname resolution methods
        let hostname = Self::try_quick_hostname_resolution(ip).await;
        
        if let Some(ref hostname) = hostname {
            device.hostname = Some(hostname.clone());
            self.infer_from_hostname(device, hostname);
        } else {
            // Generate smart hostname based on available information
            self.generate_smart_hostname(device);
        }
        
        Ok(())
    }
}

impl ImprovedMdnsStrategy {
    // Try only the most reliable and fast hostname resolution methods
    async fn try_quick_hostname_resolution(ip: IpAddr) -> Option<String> {
        // Method 1: Check ARP table for existing hostname entries
        if let Some(hostname) = Self::check_arp_table(ip).await {
            return Some(hostname);
        }
        
        // Method 2: Quick nslookup (shorter timeout)
        if let Some(hostname) = Self::quick_nslookup(ip).await {
            return Some(hostname);
        }
        
        // Method 3: Quick dig lookup
        if let Some(hostname) = Self::quick_dig(ip).await {
            return Some(hostname);
        }
        
        None
    }
    
    async fn check_arp_table(ip: IpAddr) -> Option<String> {
        if let Ok(output) = tokio::time::timeout(
            Duration::from_secs(1),
            process::Command::new("arp").arg("-a").output()
        ).await {
            if let Ok(output) = output {
                if output.status.success() {
                    let response = String::from_utf8_lossy(&output.stdout);
                    for line in response.lines() {
                        if line.contains(&format!("({})", ip)) {
                            // Extract anything before the IP that's not just "?"
                            if let Some(ip_start) = line.find(&format!("({})", ip)) {
                                let hostname_part = line[..ip_start].trim();
                                if !hostname_part.is_empty() && hostname_part != "?" {
                                    return Some(hostname_part.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
    
    async fn quick_nslookup(ip: IpAddr) -> Option<String> {
        if let Ok(output) = tokio::time::timeout(
            Duration::from_secs(2),
            process::Command::new("nslookup").arg(ip.to_string()).output()
        ).await {
            if let Ok(output) = output {
                if output.status.success() {
                    let response = String::from_utf8_lossy(&output.stdout);
                    for line in response.lines() {
                        if line.contains("name =") {
                            if let Some(name_start) = line.find("name = ") {
                                let hostname = line[name_start + 7..].trim().trim_end_matches('.');
                                if !hostname.is_empty() && hostname != ip.to_string() {
                                    return Some(hostname.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
    
    async fn quick_dig(ip: IpAddr) -> Option<String> {
        if let Ok(output) = tokio::time::timeout(
            Duration::from_secs(2),
            process::Command::new("dig")
                .arg("-x")
                .arg(ip.to_string())
                .arg("+short")
                .output()
        ).await {
            if let Ok(output) = output {
                if output.status.success() {
                    let response = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !response.is_empty() && response != ip.to_string() {
                        return Some(response.trim_end_matches('.').to_string());
                    }
                }
            }
        }
        None
    }
    
    // Generate meaningful hostnames based on device characteristics
    fn generate_smart_hostname(&self, device: &mut NetworkDevice) {
        let mut hostname = String::new();
        
        // Base hostname on vendor and device type
        if let Some(ref vendor) = device.vendor {
            let vendor_lower = vendor.to_lowercase();
            if vendor_lower.contains("bose") {
                hostname = "bose-speaker".to_string();
            } else if vendor_lower.contains("raspberry") {
                hostname = "raspberry-pi".to_string();
            } else if vendor_lower.contains("epson") {
                hostname = "epson-printer".to_string();
            } else if vendor_lower.contains("huawei") {
                hostname = "huawei-router".to_string();
            } else if vendor_lower.contains("dahua") {
                hostname = "dahua-camera".to_string();
            } else {
                // Use first word of vendor
                if let Some(first_word) = vendor.split_whitespace().next() {
                    hostname = first_word.to_lowercase();
                }
            }
        }
        
        // If no vendor-based name, use device type
        if hostname.is_empty() {
            hostname = match device.device_type {
                DeviceType::Router => "router".to_string(),
                DeviceType::Printer => "printer".to_string(),
                DeviceType::Computer => "computer".to_string(),
                DeviceType::IoTDevice => "iot-device".to_string(),
                DeviceType::SmartTV => "smart-tv".to_string(),
                DeviceType::Server => "server".to_string(),
                _ => "device".to_string(),
            };
        }
        
        // Add device characteristics based on open ports/services
        if !device.open_ports.is_empty() {
            if device.open_ports.contains(&22) {
                if !hostname.contains("ssh") {
                    hostname.push_str("-ssh");
                }
            }
            if device.open_ports.contains(&80) || device.open_ports.contains(&443) {
                if !hostname.contains("web") && device.device_type == DeviceType::Router {
                    hostname.push_str("-admin");
                }
            }
            if device.open_ports.contains(&3389) {
                hostname.push_str("-rdp");
            }
            if device.open_ports.contains(&5900) {
                hostname.push_str("-vnc");
            }
        }
        
        // Add service-specific suffixes based on banners
        for service in &device.services {
            if let Some(ref banner) = service.banner {
                let banner_lower = banner.to_lowercase();
                if banner_lower.contains("dropbear") && !hostname.contains("embedded") {
                    hostname = "embedded-linux".to_string();
                } else if banner_lower.contains("microsoft-iis") {
                    hostname.push_str("-iis");
                } else if banner_lower.contains("apache") {
                    hostname.push_str("-apache");
                } else if banner_lower.contains("nginx") {
                    hostname.push_str("-nginx");
                }
            }
        }
        
        // Add IP suffix to make it unique
        let ip_suffix = device.ip.to_string().replace(".", "-");
        hostname.push_str(&format!("-{}", ip_suffix.split('-').last().unwrap_or("x")));
        
        // Add .local suffix
        hostname.push_str(".local");
        
        device.hostname = Some(hostname);
    }
    
    fn infer_from_hostname(&self, device: &mut NetworkDevice, hostname: &str) {
        let hostname_lower = hostname.to_lowercase();

        // Apple devices
        if hostname_lower.contains("apple") || hostname_lower.ends_with(".local") {
            if hostname_lower.contains("iphone") {
                device.device_type = DeviceType::Smartphone;
                device.operating_system = Some(OperatingSystem::IOS(None));
                device.vendor = device.vendor.clone().or(Some("Apple".to_string()));
            } else if hostname_lower.contains("ipad") {
                device.device_type = DeviceType::Tablet;
                device.operating_system = Some(OperatingSystem::IOS(None));
                device.vendor = device.vendor.clone().or(Some("Apple".to_string()));
            } else if hostname_lower.contains("mac")
                || hostname_lower.contains("imac")
                || hostname_lower.contains("macbook") {
                device.device_type = DeviceType::Computer;
                device.operating_system = Some(OperatingSystem::MacOS(None));
                device.vendor = device.vendor.clone().or(Some("Apple".to_string()));
            } else if hostname_lower.contains("appletv") || hostname_lower.contains("apple-tv") {
                device.device_type = DeviceType::SmartTV;
                device.operating_system = Some(OperatingSystem::Other("tvOS".to_string()));
                device.vendor = device.vendor.clone().or(Some("Apple".to_string()));
            }
        }

        // Network infrastructure
        if hostname_lower.contains("router") || hostname_lower.contains("gateway") || hostname_lower.contains("ap-") {
            device.device_type = DeviceType::Router;
        } else if hostname_lower.contains("switch") {
            device.device_type = DeviceType::Switch;
        }

        // Printers
        else if hostname_lower.contains("printer")
            || hostname_lower.contains("hp-")
            || hostname_lower.contains("canon-")
            || hostname_lower.contains("epson")
            || hostname_lower.contains("brother") {
            device.device_type = DeviceType::Printer;
        }

        // Android devices
        else if hostname_lower.contains("android") || hostname_lower.contains("samsung") {
            if device.device_type == DeviceType::Unknown {
                device.device_type = DeviceType::Smartphone;
            }
            device.operating_system = Some(OperatingSystem::Android(None));
        }

        // Google devices
        else if hostname_lower.contains("chromecast") || hostname_lower.contains("google-") || hostname_lower.contains("nest-") {
            if device.device_type == DeviceType::Unknown {
                device.device_type = if hostname_lower.contains("chromecast") {
                    DeviceType::SmartTV
                } else {
                    DeviceType::IoTDevice
                };
            }
            device.vendor = device.vendor.clone().or(Some("Google".to_string()));
        }

        // Raspberry Pi
        else if hostname_lower.contains("raspberrypi") || hostname_lower.contains("raspberry") {
            device.device_type = DeviceType::IoTDevice;
            device.operating_system = Some(OperatingSystem::Linux(Some("Raspberry Pi OS".to_string())));
            device.vendor = device.vendor.clone().or(Some("Raspberry Pi Trading Ltd".to_string()));
        }

        // Gaming consoles
        else if hostname_lower.contains("xbox") || hostname_lower.contains("playstation") {
            device.device_type = DeviceType::IoTDevice;
        }

        // Servers
        else if hostname_lower.contains("server") || hostname_lower.contains("srv") {
            device.device_type = DeviceType::Server;
        }

        // Windows machines (often have computer names)
        else if hostname_lower.contains("desktop") || hostname_lower.contains("laptop") || hostname_lower.contains("pc") {
            device.device_type = DeviceType::Computer;
            device.operating_system = Some(OperatingSystem::Windows(None));
        }

        // Smart TVs
        else if hostname_lower.contains("tv") || hostname_lower.contains("roku") || hostname_lower.contains("firetv") {
            device.device_type = DeviceType::SmartTV;
        }
    }
}



pub struct PingAnalysisStrategy;

#[async_trait]
impl DeviceDetectionStrategy for PingAnalysisStrategy {
    fn name(&self) -> &'static str {
        "Ping Analysis"
    }

    async fn detect(
        &self,
        _device: &mut NetworkDevice,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

// ================================================================================================
// NETWORK DISCOVERY ENGINE
// ================================================================================================

pub struct NetworkDiscovery {
    strategies: Arc<Vec<Box<dyn DeviceDetectionStrategy>>>,
}

impl NetworkDiscovery {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let vendor_db = Arc::new(Mutex::new(MacVendorDatabase::new()?));
        let mut strategies_vec: Vec<Box<dyn DeviceDetectionStrategy>> = Vec::new();

        strategies_vec.push(Box::new(MacAddressStrategy::new(vendor_db.clone())));
        strategies_vec.push(Box::new(PortScanStrategy::new()));
        strategies_vec.push(Box::new(ImprovedMdnsStrategy)); // Use the improved strategy

        Ok(Self {
            strategies: Arc::new(strategies_vec),
        })
    }

    pub fn add_strategy(&mut self, _strategy: Box<dyn DeviceDetectionStrategy>) {}

    pub async fn discover_network_stream(
        &self,
        network: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let active_ips = self.ping_sweep(network).await?;
        println!("📍 Found {} active devices\n", active_ips.len());
        
        // This HashMap will store the most up-to-date info for each device
        let discovered_devices = Arc::new(Mutex::new(HashMap::<IpAddr, NetworkDevice>::new()));

        let mut device_task_handles = Vec::new();
        let mac_addresses = Self::get_mac_address_map().await.unwrap_or_default();
        let (tx, mut rx) = mpsc::channel::<NetworkDevice>(active_ips.len());

        for ip in active_ips {
            println!("- Scanning device {}", ip);
            let strategies = self.strategies.clone();
            let tx_clone = tx.clone();
            let mac_addresses = mac_addresses.clone();

            device_task_handles.push(tokio::spawn(async move {
                let mut device = NetworkDevice {
                    ip,
                    mac: mac_addresses.get(&ip).cloned(),
                    hostname: None,
                    vendor: None,
                    device_type: DeviceType::Unknown,
                    operating_system: None,
                    open_ports: Vec::new(),
                    services: Vec::new(),
                    response_time: None,
                    last_seen: std::time::SystemTime::now(),
                };

                for strategy in strategies.iter() {
                    let _ = strategy.detect(&mut device).await;
                }
                
                let _ = tx_clone.send(device.clone()).await; 
            }));
        }

        drop(tx); 

        // Wait for all tasks to complete and collect all results
        while let Some(mut device) = rx.recv().await {
            let mut devices_map = discovered_devices.lock().await;

            if let Some(existing_device) = devices_map.get_mut(&device.ip) {
                if existing_device.mac.is_none() { existing_device.mac = device.mac.take(); }
                if existing_device.hostname.is_none() { existing_device.hostname = device.hostname.take(); }
                if existing_device.vendor.is_none() { existing_device.vendor = device.vendor.take(); }
                if existing_device.device_type == DeviceType::Unknown && device.device_type != DeviceType::Unknown { existing_device.device_type = device.device_type; }
                if existing_device.operating_system.is_none() { existing_device.operating_system = device.operating_system.take(); }
                existing_device.open_ports.extend(device.open_ports.iter().cloned());
                existing_device.open_ports.sort();
                existing_device.open_ports.dedup();
                existing_device.services.extend(device.services.iter().cloned());
            } else {
                devices_map.insert(device.ip, device);
            }
        }
        
        let devices_map = discovered_devices.lock().await;

        let mut table = Table::new();
        table.set_header(vec!["IP", "MAC", "Hostname", "OS", "Type", "Vendor", "Open Ports", "Services"]);
        
        for (_, device) in devices_map.iter() {
            let service_details = if device.services.is_empty() {
                "—".to_string()
            } else {
                device.services.iter().map(|s| {
                    if let Some(ref name) = s.service_name {
                        format!("{}/{}({})", s.port, s.protocol, name)
                    } else {
                        format!("{}/{}", s.port, s.protocol)
                    }
                }).collect::<Vec<String>>().join(", ")
            };

            let os_string = format!("{:?}", device.operating_system.clone().unwrap_or(OperatingSystem::Unknown));
            let banner_string = device.services.iter().find_map(|s| s.banner.as_ref()).cloned().unwrap_or_default();
            let short_banner = if banner_string.len() > 50 {
                format!("{}...", &banner_string[..47])
            } else {
                banner_string.to_string()
            };
            let os_details = if !short_banner.is_empty() {
                format!("{} [{}]", os_string, short_banner)
            } else {
                os_string
            };

            table.add_row(vec![
                Cell::new(device.ip.to_string()),
                Cell::new(device.mac.clone().unwrap_or_else(|| "—".to_string())),
                Cell::new(device.hostname.clone().unwrap_or_else(|| "—".to_string())),
                Cell::new(os_details),
                Cell::new(format!("{:?}", device.device_type)),
                Cell::new(device.vendor.clone().unwrap_or_else(|| "—".to_string())),
                Cell::new(if device.open_ports.is_empty() { "—".to_string() } else { format!("{:?}", device.open_ports) }),
                Cell::new(service_details),
            ]);
        }
        println!("{table}");

        Ok(())
    }

    async fn ping_sweep(&self, network: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error + Send + Sync>> {
        let mut active_ips = Vec::new();

        if let Some(base) = network.strip_suffix("/24") {
            let base_parts: Vec<&str> = base.split('.').collect();
            if base_parts.len() == 4 {
                let base_ip_str = format!("{}.{}.{}.", base_parts[0], base_parts[1], base_parts[2]);

                let mut handles = Vec::new();

                for i in 1..255 {
                    let ip_str = format!("{}{}", base_ip_str, i);
                    if let Ok(ip) = Ipv4Addr::from_str(&ip_str) {
                        let target_ip: IpAddr = ip.into();
                        
                        let handle = tokio::spawn(async move {
                            let payload = [0; 56];
                            
                            match timeout(Duration::from_millis(500), ping(target_ip, &payload)).await {
                                Ok(Ok((_icmp_packet, _duration))) => {
                                    return Some(target_ip);
                                },
                                Ok(Err(e)) => {
                                    eprintln!("Ping error for {}: {}", target_ip, e);
                                },
                                Err(_) => {},
                            }
                            None
                        });
                        handles.push(handle);
                    }
                }

                for handle in handles {
                    if let Ok(Some(ip)) = handle.await {
                        active_ips.push(ip);
                    }
                }
            }
        }
        Ok(active_ips)
    }

    async fn get_mac_address_map() -> Option<HashMap<IpAddr, String>> {
        let mut mac_map = HashMap::new();
        
        // Try multiple methods for getting MAC addresses
        let mut methods = Vec::new();
        
        // Method 1: arp -a
        methods.push(tokio::spawn(async {
            Self::get_mac_from_arp().await.unwrap_or_default()
        }));
        
        // Method 2: ip neighbor (Linux)
        #[cfg(target_os = "linux")]
        methods.push(tokio::spawn(async {
            Self::get_mac_from_ip_neighbor().await.unwrap_or_default()
        }));
        
        // Method 3: arp -a -n (no name resolution)
        methods.push(tokio::spawn(async {
            Self::get_mac_from_arp_no_resolve().await.unwrap_or_default()
        }));
        
        // Collect results from all methods
        for method in methods {
            if let Ok(result) = method.await {
                for (ip, mac) in result {
                    mac_map.entry(ip).or_insert(mac);
                }
            }
        }
        
        Some(mac_map)
    }
    
    async fn get_mac_from_arp() -> Option<HashMap<IpAddr, String>> {
        let mut mac_map = HashMap::new();
        
        if let Ok(output) = process::Command::new("arp")
            .arg("-a")
            .output()
            .await {
            if output.status.success() {
                let response = String::from_utf8_lossy(&output.stdout);
                let mac_pattern = regex::Regex::new(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})").unwrap();

                for line in response.lines() {
                    // Multiple formats to handle
                    // Format 1: ? (192.168.1.1) at 12:34:56:78:90:ab [ether] on en0
                    // Format 2: hostname (192.168.1.1) at 12:34:56:78:90:ab on en0
                    if let Some(ip_start) = line.find('(') {
                        if let Some(ip_end) = line.find(')') {
                            if let Ok(ip) = IpAddr::from_str(&line[ip_start + 1..ip_end]) {
                                if let Some(mat) = mac_pattern.find(line) {
                                    mac_map.insert(ip, mat.as_str().replace('-', ":").to_uppercase());
                                }
                            }
                        }
                    }
                }
            }
        }
        Some(mac_map)
    }
    
    #[cfg(target_os = "linux")]
    async fn get_mac_from_ip_neighbor() -> Option<HashMap<IpAddr, String>> {
        let mut mac_map = HashMap::new();
        
        if let Ok(output) = process::Command::new("ip")
            .arg("neighbor")
            .arg("show")
            .output()
            .await {
            if output.status.success() {
                let response = String::from_utf8_lossy(&output.stdout);
                
                for line in response.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        if let Ok(ip) = IpAddr::from_str(parts[0]) {
                            // Look for MAC address in the line (lladdr field)
                            if let Some(pos) = parts.iter().position(|&x| x == "lladdr") {
                                if pos + 1 < parts.len() {
                                    let mac = parts[pos + 1].replace('-', ":").to_uppercase();
                                    // Validate MAC format
                                    if mac.len() == 17 && mac.matches(':').count() == 5 {
                                        mac_map.insert(ip, mac);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Some(mac_map)
    }
    
    async fn get_mac_from_arp_no_resolve() -> Option<HashMap<IpAddr, String>> {
        let mut mac_map = HashMap::new();
        
        if let Ok(output) = process::Command::new("arp")
            .arg("-a")
            .arg("-n") // Don't resolve hostnames
            .output()
            .await {
            if output.status.success() {
                let response = String::from_utf8_lossy(&output.stdout);
                let mac_pattern = regex::Regex::new(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})").unwrap();

                for line in response.lines() {
                    if let Some(ip_start) = line.find('(') {
                        if let Some(ip_end) = line.find(')') {
                            if let Ok(ip) = IpAddr::from_str(&line[ip_start + 1..ip_end]) {
                                if let Some(mat) = mac_pattern.find(line) {
                                    mac_map.insert(ip, mat.as_str().replace('-', ":").to_uppercase());
                                }
                            }
                        }
                    }
                }
            }
        }
        Some(mac_map)
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
            
            // Show additional hostname insights
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
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🌐 Network Discovery Tool - Rust Implementation");
    println!("================================================\n");

    let args: Vec<String> = std::env::args().collect();
    let network = if args.len() > 1 {
        args[1].clone()
    } else {
        get_local_network().unwrap_or_else(|| "192.168.1.0/24".to_string())
    };

    println!("🔍 Target network: {}\n", network);

    let discovery = NetworkDiscovery::new()?;
    discovery.discover_network_stream(&network).await?;

    Ok(())
}

fn get_local_network() -> Option<String> {
    #[cfg(target_os = "linux")]
    if let Ok(output) = Command::new("ip")
        .arg("route")
        .arg("show")
        .arg("default")
        .output()
    {
        if output.status.success() {
            let response = String::from_utf8_lossy(&output.stdout);
            for line in response.lines() {
                if line.contains("default via") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for (i, part) in parts.iter().enumerate() {
                        if *part == "via" && i + 1 < parts.len() {
                            let gateway = parts[i + 1];
                            if let Ok(gateway_ip) = Ipv4Addr::from_str(gateway) {
                                let octets = gateway_ip.octets();
                                return Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]));
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    if let Ok(output) = Command::new("netstat")
        .arg("-rn")
        .output()
    {
        if output.status.success() {
            let response = String::from_utf8_lossy(&output.stdout);
            for line in response.lines() {
                if line.trim().starts_with("default") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let gateway = parts[1];
                        if let Ok(gateway_ip) = Ipv4Addr::from_str(gateway) {
                            let octets = gateway_ip.octets();
                            return Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]));
                        }
                    }
                }
            }
        }
    }

    if let Ok(output) = Command::new("hostname").arg("-I").output() {
        if output.status.success() {
            let response = String::from_utf8_lossy(&output.stdout);
            let ips: Vec<&str> = response.split_whitespace().collect();
            for ip_str in ips {
                if let Ok(ip) = Ipv4Addr::from_str(ip_str.trim()) {
                    let octets = ip.octets();
                    if (octets[0] == 192 && octets[1] == 168)
                        || (octets[0] == 10)
                        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                    {
                        return Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    if let Ok(output) = Command::new("ipconfig")
        .arg("getifaddr")
        .arg("en0")
        .output()
    {
        if output.status.success() {
            let response = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if let Ok(ip) = Ipv4Addr::from_str(&response) {
                let octets = ip.octets();
                return Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]));
            }
        }
    }

    None
}
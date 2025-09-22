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
use surge_ping::ping;



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
        let oui_db = match OuiDatabase::new_from_export(include_bytes!("../oui.csv")) {
            Ok(db) => db,
            Err(_) => {
                println!("⚠️  Using fallback OUI database");
                OuiDatabase::new_from_str("")?
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
                22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 1723, 3389, 5900, 8080, 8443,
            ],
        }
    }
}

#[async_trait]
impl DeviceDetectionStrategy for PortScanStrategy {
    fn name(&self) -> &'static str {
        "Port Scanning"
    }

    async fn detect(
        &self,
        device: &mut NetworkDevice,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ip = device.ip;

        for &port in &self.common_ports {
            if let Ok(result) = timeout(Duration::from_millis(1000), TcpStream::connect((ip, port))).await {
                if result.is_ok() {
                    device.open_ports.push(port);

                    let service = NetworkService {
                        port,
                        protocol: "TCP".to_string(),
                        service_name: Self::get_service_name(port),
                        banner: None,
                        service_type: None,
                        txt_records: Vec::new(),
                    };
                    device.services.push(service);

                    match port {
                        22 => {
                            if device.operating_system.is_none() {
                                device.operating_system = Some(OperatingSystem::Linux(None));
                            }
                        }
                        135 | 139 | 445 | 3389 => {
                            device.operating_system = Some(OperatingSystem::Windows(None));
                            if port == 3389 {
                                device.device_type = DeviceType::Server;
                            }
                        }
                        5900 => {
                            device.device_type = DeviceType::Computer;
                        }
                        80 | 443 | 8080 | 8443 => {
                            if device.device_type == DeviceType::Unknown {
                                device.device_type = DeviceType::Router;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }
}

impl PortScanStrategy {
    fn get_service_name(port: u16) -> Option<String> {
        match port {
            22 => Some("SSH".to_string()),
            23 => Some("Telnet".to_string()),
            53 => Some("DNS".to_string()),
            80 => Some("HTTP".to_string()),
            135 => Some("RPC".to_string()),
            139 => Some("NetBIOS".to_string()),
            443 => Some("HTTPS".to_string()),
            445 => Some("SMB".to_string()),
            993 => Some("IMAPS".to_string()),
            995 => Some("POP3S".to_string()),
            1723 => Some("PPTP".to_string()),
            3389 => Some("RDP".to_string()),
            5900 => Some("VNC".to_string()),
            8080 => Some("HTTP-Alt".to_string()),
            8443 => Some("HTTPS-Alt".to_string()),
            _ => None,
        }
    }
}

// Simplified mDNS strategy using system commands
pub struct MdnsStrategy;

#[async_trait]
impl DeviceDetectionStrategy for MdnsStrategy {
    fn name(&self) -> &'static str {
        "mDNS Service Discovery"
    }

    async fn detect(
        &self,
        device: &mut NetworkDevice,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Try to resolve hostname using mDNS
        if let Some(hostname) = self.resolve_mdns_hostname(&device.ip).await {
            device.hostname = Some(hostname.clone());

            // Infer device information from hostname
            self.infer_from_hostname(device, &hostname);
        }

        Ok(())
    }
}

impl MdnsStrategy {
    async fn resolve_mdns_hostname(&self, ip: &IpAddr) -> Option<String> {
        // Try using nslookup for reverse DNS
        if let Ok(output) = tokio::process::Command::new("nslookup")
            .arg(ip.to_string())
            .output()
            .await
        {
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

        // Try using dig as fallback
        if let Ok(output) = tokio::process::Command::new("dig")
            .arg("-x")
            .arg(ip.to_string())
            .arg("+short")
            .output()
            .await
        {
            if output.status.success() {
                let response = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !response.is_empty() && response != ip.to_string() {
                    return Some(response.trim_end_matches('.').to_string());
                }
            }
        }

        None
    }

    fn infer_from_hostname(&self, device: &mut NetworkDevice, hostname: &str) {
        let hostname_lower = hostname.to_lowercase();

        // Check for Apple devices
        if hostname_lower.contains("apple") || hostname_lower.contains(".local") {
            if hostname_lower.contains("iphone") {
                device.device_type = DeviceType::Smartphone;
                device.operating_system = Some(OperatingSystem::IOS(None));
                device.vendor = Some("Apple".to_string());
            } else if hostname_lower.contains("ipad") {
                device.device_type = DeviceType::Tablet;
                device.operating_system = Some(OperatingSystem::IOS(None));
                device.vendor = Some("Apple".to_string());
            } else if hostname_lower.contains("mac")
                || hostname_lower.contains("imac")
                || hostname_lower.contains("macbook")
            {
                device.device_type = DeviceType::Computer;
                device.operating_system = Some(OperatingSystem::MacOS(None));
                device.vendor = Some("Apple".to_string());
            } else if hostname_lower.contains("appletv") || hostname_lower.contains("apple-tv") {
                device.device_type = DeviceType::SmartTV;
                device.operating_system = Some(OperatingSystem::Other("tvOS".to_string()));
                device.vendor = Some("Apple".to_string());
            }
        }

        // Check for other devices
        if hostname_lower.contains("router") || hostname_lower.contains("gateway") {
            device.device_type = DeviceType::Router;
        } else if hostname_lower.contains("printer")
            || hostname_lower.contains("hp-")
            || hostname_lower.contains("canon-")
        {
            device.device_type = DeviceType::Printer;
        } else if hostname_lower.contains("android") || hostname_lower.contains("samsung") {
            device.device_type = DeviceType::Smartphone;
            device.operating_system = Some(OperatingSystem::Android(None));
        } else if hostname_lower.contains("chromecast") || hostname_lower.contains("google-") {
            device.device_type = DeviceType::SmartTV;
            device.vendor = Some("Google".to_string());
        } else if hostname_lower.contains("raspberrypi") || hostname_lower.contains("raspberry") {
            device.device_type = DeviceType::IoTDevice;
            device.operating_system = Some(OperatingSystem::Linux(Some(
                "Raspberry Pi OS".to_string(),
            )));
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
        // This strategy is now part of the initial ping sweep, so this detect method is a no-op
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
        strategies_vec.push(Box::new(MdnsStrategy));

        Ok(Self {
            strategies: Arc::new(strategies_vec),
        })
    }

    pub fn add_strategy(&mut self, _strategy: Box<dyn DeviceDetectionStrategy>) {
        // This method is intentionally a no-op as strategies are now Arc'd at initialization.
    }

    pub async fn discover_network_stream(
        &self,
        network: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let active_ips = self.ping_sweep(network).await?;
        println!("📍 Found {} active devices\n", active_ips.len());

        let (tx, mut rx) = mpsc::channel::<NetworkDevice>(100);

        // Spawn printer task
        let printer_handle = tokio::spawn(async move {
            let mut table = Table::new();
            table.set_header(vec!["IP", "MAC", "Hostname", "OS", "Type"]);

            // This loop will exit when all `tx` senders have been dropped
            while let Some(device) = rx.recv().await {
                table.add_row(vec![
                    Cell::new(device.ip.to_string()),
                    Cell::new(device.mac.clone().unwrap_or_else(|| "—".to_string())),
                    Cell::new(device.hostname.clone().unwrap_or_else(|| "—".to_string())),
                    Cell::new(format!(
                        "{:?}",
                        device.operating_system.clone().unwrap_or(OperatingSystem::Unknown)
                    )),
                    Cell::new(format!("{:?}", device.device_type)),
                ]);
                // This clears the screen and redraws the table.
                // It might be too aggressive for a large number of devices, 
                // but keeps the output concise for now.
                print!("\x1B[2J\x1B[1;1H"); 
                println!("{table}");
            }
        });

        let mut device_task_handles = Vec::new();

        // Spawn per-device tasks
        for ip in active_ips {
            let strategies = self.strategies.clone();
            let tx_clone = tx.clone(); // Clone tx for each spawned task
            device_task_handles.push(tokio::spawn(async move {
                let mut device = NetworkDevice {
                    ip,
                    mac: None,
                    hostname: None,
                    vendor: None,
                    device_type: DeviceType::Unknown,
                    operating_system: None,
                    open_ports: Vec::new(),
                    services: Vec::new(),
                    response_time: None,
                    last_seen: std::time::SystemTime::now(),
                };

                device.mac = Self::get_mac_address(&ip).await;

                for strategy in strategies.iter() {
                    let _ = strategy.detect(&mut device).await;
                    // No need to send device state after _every_ strategy,
                    // send once after all strategies for this device are done.
                }
                
                // Only send the device to the printer once all detection strategies have run
                let _ = tx_clone.send(device.clone()).await; 
            }));
        }

        // IMPORTANT: Drop the original `tx` sender.
        // This is crucial. If the original `tx` is not dropped, 
        // the `rx` in the printer task will never see the channel as "closed" 
        // and will hang indefinitely waiting for more messages, even if all 
        // cloned `tx_clone`s have also been dropped.
        drop(tx); 

        // Wait for all device processing tasks to complete
        for handle in device_task_handles {
            let _ = handle.await; // Handle errors if necessary
        }

        // Wait for the printer task to complete (it will complete once all senders are dropped and its buffer is empty)
        let _ = printer_handle.await;

        Ok(())
    }

    // THIS IS THE CORRECTED ping_sweep FUNCTION for surge-ping v0.8.2
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
                            let payload = [0; 56]; // Create a payload as &[u8]
                            
                            // Call surge_ping::ping directly with target_ip and payload
                            match timeout(Duration::from_millis(500), ping(target_ip, &payload)).await {
                                Ok(Ok((_icmp_packet, _duration))) => { // Deconstruct the tuple
                                    // Ping successful. The IP address is `target_ip`
                                    return Some(target_ip);
                                },
                                Ok(Err(e)) => {
                                    eprintln!("Ping error for {}: {}", target_ip, e);
                                },
                                Err(_) => {
                                    // Tokio timeout occurred
                                },
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

    async fn get_mac_address(ip: &IpAddr) -> Option<String> {
        let output = tokio::process::Command::new("arp")
            .arg("-n")
            .arg(ip.to_string())
            .output()
            .await
            .ok()?;

        if output.status.success() {
            let response = String::from_utf8_lossy(&output.stdout);
            for line in response.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[0].contains(&ip.to_string()) {
                    return Some(parts[2].to_string());
                }
            }
        }

        None
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
                if let Some(ref name) = service.service_name {
                    if let Some(ref service_type) = service.service_type {
                        writeln!(
                            f,
                            "      • {}/{} ({}) [{}]",
                            service.port, service.protocol, name, service_type
                        )?;
                    } else {
                        writeln!(
                            f,
                            "      • {}/{} ({})",
                            service.port, service.protocol, name
                        )?;
                    }
                } else {
                    writeln!(f, "      • {}/{}", service.port, service.protocol)?;
                }
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
    // Try to get the default gateway and infer network
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

    // Fallback: try to get local IP and infer network
    if let Ok(output) = Command::new("hostname").arg("-I").output() {
        if output.status.success() {
            let response = String::from_utf8_lossy(&output.stdout);
            let ips: Vec<&str> = response.split_whitespace().collect();
            for ip_str in ips {
                if let Ok(ip) = Ipv4Addr::from_str(ip_str.trim()) {
                    let octets = ip.octets();
                    // Check if it's a private IP address
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

    None
}
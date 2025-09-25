use std::net::IpAddr;
use std::time::Duration;

/// Represents a discovered network device with all its attributes
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

/// Classification of device types based on detection analysis
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

/// Operating system detection with optional version information
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

/// Network service discovered on a device
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

/// TCP fingerprint data for OS detection
#[derive(Debug, Clone)]
pub struct TcpFingerprint {
    pub estimated_ttl: u8,
    pub response_time_ms: u64,
    pub connection_pattern: String,
    pub banner_characteristics: Vec<String>,
}

/// Device information from vendor database lookup
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub vendor: String,
    pub device_type: DeviceType,
    pub operating_system: Option<OperatingSystem>,
}
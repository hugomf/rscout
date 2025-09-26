use rscout::model::{DeviceType, NetworkDevice, NetworkService};

/// Create a test network device with minimal configuration
pub fn create_test_device(ip: &str, mac: Option<&str>) -> NetworkDevice {
    NetworkDevice {
        ip: ip.parse().unwrap(),
        mac: mac.map(|s| s.to_string()),
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
    }
}

/// Create a test service with banner
#[allow(dead_code)]
pub fn create_test_service(port: u16, banner: Option<&str>) -> NetworkService {
    NetworkService {
        port,
        protocol: "TCP".to_string(),
        service_name: None,
        banner: banner.map(|s| s.to_string()),
        service_type: None,
        version: None,
        txt_records: Vec::new(),
    }
}

/// Create a test vendor database for MAC address tests
#[allow(dead_code)]
pub fn create_test_vendor_db() -> std::sync::Arc<tokio::sync::Mutex<rscout::db::oui::MacVendorDatabase>> {
    let db = rscout::db::oui::MacVendorDatabase::new().unwrap();
    std::sync::Arc::new(tokio::sync::Mutex::new(db))
}
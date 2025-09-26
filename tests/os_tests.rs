use rscout::detect::os::AdvancedOSDetector;
use rscout::config::ScanConfig;
use rscout::model::{OperatingSystem};
use test_utils::{create_test_device, create_test_service};
use std::net::{IpAddr, Ipv4Addr};

mod test_utils;

fn create_test_config() -> ScanConfig {
    ScanConfig::default()
}

#[tokio::test]
async fn test_os_detector_creation() {
    let config = create_test_config();
    let _detector = AdvancedOSDetector::new(config);
    // Just verify it can be created
    assert!(true);
}

#[tokio::test]
async fn test_os_detection_with_services() {
    let config = create_test_config();
    let detector = AdvancedOSDetector::new(config);
    
    // Create a device with SSH service (Ubuntu)
    let mut device = create_test_device("192.168.1.1", None);
    device.services = vec![
        create_test_service(22, Some("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")),
    ];
    
    let (os, confidence) = detector.detect_operating_system(&device).await;
    assert!(os.is_some());
    assert!(confidence > 0.0);
    assert_eq!(os, Some(OperatingSystem::Linux(Some("Ubuntu".to_string()))));
}

#[tokio::test]
async fn test_os_detection_with_windows_ports() {
    let config = create_test_config();
    let detector = AdvancedOSDetector::new(config);
    
    // Create a device with Windows-specific ports
    let mut device = create_test_device("192.168.1.1", None);
    device.open_ports = vec![135, 139, 445, 3389];
    device.vendor = Some("Microsoft Corporation".to_string());
    
    let (os, confidence) = detector.detect_operating_system(&device).await;
    assert!(os.is_some());
    assert!(confidence > 0.0);
    assert_eq!(os, Some(OperatingSystem::Windows(Some("Server/Pro".to_string()))));
}

#[tokio::test]
async fn test_os_detection_with_linux_server_ports() {
    let config = create_test_config();
    let detector = AdvancedOSDetector::new(config);
    
    // Create a device with Linux server ports
    let mut device = create_test_device("192.168.1.1", None);
    device.open_ports = vec![22, 80, 3306];
    
    let (os, confidence) = detector.detect_operating_system(&device).await;
    assert!(os.is_some());
    assert!(confidence > 0.0);
    assert_eq!(os, Some(OperatingSystem::Linux(Some("Server".to_string()))));
}

#[tokio::test]
async fn test_tcp_fingerprint_generation() {
    let config = create_test_config();
    let detector = AdvancedOSDetector::new(config);
    
    // Test with a local IP (should fail to connect in test environment)
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let _fingerprint = detector.generate_tcp_fingerprint(ip).await;
    
    // In test environment, this should return None due to connection failures
    // but the function should execute without panicking
    assert!(true); // Just verify the function can be called
}
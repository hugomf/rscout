use rscout::detect::hostname::EnhancedHostnameStrategy;
use rscout::detect::mac::EnhancedMacAddressStrategy;
use rscout::detect::os::AdvancedOSDetector;
use rscout::detect::port::EnhancedPortScanStrategy;
use rscout::detect::DeviceDetectionStrategy;
use rscout::config::ScanConfig;
use rscout::model::{DeviceType, OperatingSystem};
use test_utils::{create_test_device, create_test_vendor_db};
use std::sync::Arc;

mod test_utils;

#[tokio::test]
async fn test_multiple_strategies_on_same_device() {
    // Create a device and apply multiple detection strategies
    let mut device = create_test_device("192.168.1.100", Some("00:1B:63:AA:BB:CC"));
    
    // Apply hostname strategy
    let hostname_strategy = EnhancedHostnameStrategy::new().unwrap();
    let result = hostname_strategy.detect(&mut device).await;
    assert!(result.is_ok());
    
    // Apply MAC strategy
    let vendor_db = create_test_vendor_db();
    let mac_strategy = EnhancedMacAddressStrategy::new(vendor_db);
    let result = mac_strategy.detect(&mut device).await;
    assert!(result.is_ok());
    
    // Verify device has been updated by both strategies
    assert_eq!(device.device_type, DeviceType::AppleDevice);
    assert!(device.hostname.is_some());
}

#[tokio::test]
async fn test_device_detection_workflow() {
    // Test a complete device detection workflow
    let mut device = create_test_device("192.168.1.200", Some("A4:5E:60:AA:BB:CC"));
    
    // Apply detection strategies in sequence
    let hostname_strategy = EnhancedHostnameStrategy::new().unwrap();
    hostname_strategy.detect(&mut device).await.unwrap();
    
    let vendor_db = create_test_vendor_db();
    let mac_strategy = EnhancedMacAddressStrategy::new(vendor_db);
    mac_strategy.detect(&mut device).await.unwrap();
    
    // Verify the device has been properly classified
    assert_eq!(device.device_type, DeviceType::AppleDevice);
    assert!(matches!(device.operating_system, Some(OperatingSystem::MacOS(_))));
    assert!(device.hostname.is_some());
}

#[tokio::test]
async fn test_comprehensive_detection_pipeline() {
    // Test a comprehensive detection pipeline with all strategies
    let mut device = create_test_device("192.168.1.150", Some("08:00:27:AA:BB:CC"));
    
    // Apply hostname detection
    let hostname_strategy = EnhancedHostnameStrategy::new().unwrap();
    hostname_strategy.detect(&mut device).await.unwrap();
    
    // Apply MAC detection
    let vendor_db = create_test_vendor_db();
    let mac_strategy = EnhancedMacAddressStrategy::new(vendor_db);
    mac_strategy.detect(&mut device).await.unwrap();
    
    // Apply port scanning
    let config = ScanConfig::default();
    let os_detector = Arc::new(AdvancedOSDetector::new(config.clone()));
    let port_strategy = EnhancedPortScanStrategy::new(config, os_detector);
    port_strategy.detect(&mut device).await.unwrap();
    
    // Apply OS detection
    let os_detector = AdvancedOSDetector::new(ScanConfig::default());
    let (os, confidence) = os_detector.detect_operating_system(&device).await;
    
    // Verify comprehensive detection results
    assert!(device.hostname.is_some());
    assert!(device.vendor.is_some());
    assert!(device.open_ports.len() <= 50); // Should not exceed common ports
    assert!(os.is_some() || confidence == 0.0); // OS detection may or may not succeed
}
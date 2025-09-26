use rscout::detect::hostname::EnhancedHostnameStrategy;
use rscout::detect::mac::EnhancedMacAddressStrategy;
use rscout::detect::DeviceDetectionStrategy;
use rscout::model::DeviceType;
use test_utils::{create_test_device, create_test_vendor_db};


mod test_utils;

#[tokio::test]
async fn test_empty_device_detection() {
    // Test detection on a device with minimal information
    let mut device = create_test_device("192.168.1.1", None);
    
    let hostname_strategy = EnhancedHostnameStrategy::new().unwrap();
    let result = hostname_strategy.detect(&mut device).await;
    assert!(result.is_ok());
    
    let vendor_db = create_test_vendor_db();
    let mac_strategy = EnhancedMacAddressStrategy::new(vendor_db);
    let result = mac_strategy.detect(&mut device).await;
    assert!(result.is_ok());
    
    // Device should remain mostly unknown but without errors
    assert_eq!(device.device_type, DeviceType::Unknown);
    assert!(device.hostname.is_some()); // Should be set to "N/A"
}

#[tokio::test]
async fn test_invalid_ip_handling() {
    // Test that strategies handle invalid IPs gracefully
    let mut device = create_test_device("0.0.0.0", None);
    
    let hostname_strategy = EnhancedHostnameStrategy::new().unwrap();
    let result = hostname_strategy.detect(&mut device).await;
    assert!(result.is_ok());
    
    let vendor_db = create_test_vendor_db();
    let mac_strategy = EnhancedMacAddressStrategy::new(vendor_db);
    let result = mac_strategy.detect(&mut device).await;
    assert!(result.is_ok());
    
    // Strategies should handle invalid IPs without panicking
    assert!(true);
}

#[tokio::test]
async fn test_malformed_mac_address() {
    // Test handling of malformed MAC addresses
    let mut device = create_test_device("192.168.1.1", Some("invalid-mac"));
    
    let vendor_db = create_test_vendor_db();
    let mac_strategy = EnhancedMacAddressStrategy::new(vendor_db);
    let result = mac_strategy.detect(&mut device).await;
    
    // Should handle malformed MAC without panicking
    assert!(result.is_ok());
}
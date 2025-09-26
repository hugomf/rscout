use rscout::detect::mac::EnhancedMacAddressStrategy;
use rscout::detect::DeviceDetectionStrategy;
use rscout::model::DeviceType;
use test_utils::{create_test_device, create_test_vendor_db};

mod test_utils;

#[tokio::test]
async fn test_mac_strategy_creation() {
    let vendor_db = create_test_vendor_db();
    let strategy = EnhancedMacAddressStrategy::new(vendor_db);
    assert_eq!(strategy.name(), "Enhanced MAC Address Analysis with Device Classification");
}

#[tokio::test]
async fn test_mac_detection_with_apple_mac() {
    let vendor_db = create_test_vendor_db();
    let strategy = EnhancedMacAddressStrategy::new(vendor_db);
    let mut device = create_test_device("192.168.1.1", Some("00:1B:63:AA:BB:CC"));
    
    let result = strategy.detect(&mut device).await;
    assert!(result.is_ok());
    // Apple device should be detected
    assert_eq!(device.device_type, DeviceType::AppleDevice);
}

#[tokio::test]
async fn test_mac_detection_with_unknown_mac() {
    let vendor_db = create_test_vendor_db();
    let strategy = EnhancedMacAddressStrategy::new(vendor_db);
    // Use a MAC that doesn't match any patterns (not locally administered)
    let mut device = create_test_device("192.168.1.1", Some("00:11:22:33:44:55"));
    
    let result = strategy.detect(&mut device).await;
    assert!(result.is_ok());
    // Unknown MAC should remain unknown
    assert_eq!(device.device_type, DeviceType::Unknown);
}

#[tokio::test]
async fn test_mac_detection_without_mac() {
    let vendor_db = create_test_vendor_db();
    let strategy = EnhancedMacAddressStrategy::new(vendor_db);
    let mut device = create_test_device("192.168.1.1", None);
    
    let result = strategy.detect(&mut device).await;
    assert!(result.is_ok());
    // Device without MAC should remain unchanged
    assert_eq!(device.device_type, DeviceType::Unknown);
}

#[tokio::test]
async fn test_mac_detection_with_locally_administered_mac() {
    let vendor_db = create_test_vendor_db();
    let strategy = EnhancedMacAddressStrategy::new(vendor_db);
    // Use a locally administered MAC (second bit of first octet set)
    let mut device = create_test_device("192.168.1.1", Some("AA:BB:CC:DD:EE:FF"));
    
    let result = strategy.detect(&mut device).await;
    assert!(result.is_ok());
    // Locally administered MAC should be classified as Computer
    assert_eq!(device.device_type, DeviceType::Computer);
}
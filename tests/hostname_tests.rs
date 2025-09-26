use rscout::detect::hostname::EnhancedHostnameStrategy;
use rscout::detect::DeviceDetectionStrategy;
use test_utils::create_test_device;

mod test_utils;

#[tokio::test]
async fn test_hostname_strategy_creation() {
    let strategy = EnhancedHostnameStrategy::new();
    assert!(strategy.is_ok());
}

#[tokio::test]
async fn test_hostname_strategy_name() {
    let strategy = EnhancedHostnameStrategy::new().unwrap();
    assert_eq!(strategy.name(), "multi-service mDNS-SD hostname lookup");
}

#[tokio::test]
async fn test_hostname_detection_with_none() {
    let strategy = EnhancedHostnameStrategy::new().unwrap();
    let mut device = create_test_device("192.168.1.1", None);
    
    let result = strategy.detect(&mut device).await;
    assert!(result.is_ok());
    // Hostname should be set to "N/A" when no resolution is possible
    assert_eq!(device.hostname, Some("N/A".to_string()));
}
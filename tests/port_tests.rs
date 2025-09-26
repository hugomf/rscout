use rscout::detect::port::EnhancedPortScanStrategy;
use rscout::detect::os::AdvancedOSDetector;
use rscout::detect::DeviceDetectionStrategy;
use rscout::config::ScanConfig;
use test_utils::create_test_device;
use std::sync::Arc;

mod test_utils;

fn create_test_strategy() -> EnhancedPortScanStrategy {
    let config = ScanConfig::default();
    let os_detector = Arc::new(AdvancedOSDetector::new(config.clone()));
    EnhancedPortScanStrategy::new(config, os_detector)
}

#[tokio::test]
async fn test_port_strategy_creation() {
    let strategy = create_test_strategy();
    assert_eq!(strategy.name(), "Enhanced Port Scanning with Advanced Banner Analysis");
}

#[tokio::test]
async fn test_port_scanning_on_localhost() {
    let strategy = create_test_strategy();
    let mut device = create_test_device("127.0.0.1", None);
    
    // This will attempt to scan localhost ports
    // In test environment, most ports will be closed, but the function should execute
    let result = strategy.detect(&mut device).await;
    assert!(result.is_ok());
    
    // Verify the device structure was updated
    assert!(device.services.len() <= 50); // Should not exceed common ports
}
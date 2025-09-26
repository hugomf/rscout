//! RScout - A comprehensive network discovery tool
//! 
//! This library provides network discovery capabilities including:
//! - Device detection and classification
//! - Port scanning and service detection
//! - Operating system fingerprinting
//! - MAC address vendor lookup

pub mod config;
pub mod constants;
pub mod db;
pub mod detect;
pub mod engine;
pub mod errors;
pub mod model;
pub mod net;
pub mod table;

// Re-export commonly used types for convenience
pub use config::ScanConfig;
pub use detect::DeviceDetectionStrategy;
pub use detect::hostname::EnhancedHostnameStrategy;
pub use detect::mac::EnhancedMacAddressStrategy;
pub use detect::port::EnhancedPortScanStrategy;
pub use detect::os::AdvancedOSDetector;
pub use model::{NetworkDevice, DeviceType, OperatingSystem};
pub use errors::NetworkDiscoveryError;
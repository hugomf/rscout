use network_interface;
use thiserror::Error;

/// Comprehensive error types for network discovery operations
#[derive(Error, Debug)]
pub enum NetworkDiscoveryError {
    #[error("OUI Database Error: {0}")]
    OuiDatabaseError(String),
    
    #[error("Ping Error: {0}")]
    PingError(String),
    
    #[error("Port Scan Error: {0}")]
    PortScanError(String),
    
    #[error("Hostname Resolution Error: {0}")]
    HostnameResolutionError(String),
    
    #[error("I/O Error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Network Interface Error: {0}")]
    NetworkInterfaceWrapped(#[from] network_interface::Error),
    
    #[error("Network Interface Error: {0}")]
    NetworkInterfaceCustom(String),
    
    #[error("Fingerprint Error: {0}")]
    FingerprintError(String),
    
    #[error("Error: {0}")]
    Other(String),
}
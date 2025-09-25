use crate::errors::NetworkDiscoveryError;
use crate::model::NetworkDevice;
use async_trait::async_trait;

// Submodule declarations
pub mod os;
pub mod port;
pub mod mac;
pub mod hostname;

// Re-export the strategy trait
/// Device detection strategy trait
/// 
/// Each strategy implements a specific method for gathering information
/// about network devices (e.g., port scanning, MAC address lookup, 
/// hostname resolution, etc.)
#[async_trait]
pub trait DeviceDetectionStrategy: Send + Sync {
    /// Perform detection on the given device, modifying it in place
    /// with any discovered information
    async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError>;
    
    /// Return a human-readable name for this detection strategy
    fn name(&self) -> &'static str;
}

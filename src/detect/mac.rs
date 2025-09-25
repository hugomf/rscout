use super::DeviceDetectionStrategy;
use crate::db::oui::MacVendorDatabase;
use crate::errors::NetworkDiscoveryError;
use crate::model::{DeviceType, NetworkDevice, OperatingSystem};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Enhanced MAC address analysis strategy with advanced device classification
pub struct EnhancedMacAddressStrategy {
    vendor_db: Arc<Mutex<MacVendorDatabase>>,
}

impl EnhancedMacAddressStrategy {
    pub fn new(vendor_db: Arc<Mutex<MacVendorDatabase>>) -> Self {
        Self { vendor_db }
    }

    /// Advanced device classification based on vendor and specific MAC address patterns
    fn advanced_device_classification(
        &self,
        vendor: &str,
        mac: &str,
    ) -> (DeviceType, Option<OperatingSystem>) {
        let vendor_lower = vendor.to_lowercase();
        let mac_upper = mac.to_uppercase();

        match vendor_lower.as_str() {
            // Apple device classification
            v if v.contains("apple") => {
                if mac_upper.starts_with("00:1B:63") || mac_upper.starts_with("00:26:08") {
                    (
                        DeviceType::AppleDevice,
                        Some(OperatingSystem::IOS(Some("iPhone".to_string()))),
                    )
                } else if mac_upper.starts_with("A4:5E:60") || mac_upper.starts_with("58:55:CA") {
                    (
                        DeviceType::AppleDevice,
                        Some(OperatingSystem::MacOS(Some("MacBook".to_string()))),
                    )
                } else {
                    (
                        DeviceType::AppleDevice,
                        Some(OperatingSystem::MacOS(None)),
                    )
                }
            }
            
            // Samsung device classification
            v if v.contains("samsung") => {
                if v.contains("electronics") {
                    (
                        DeviceType::AndroidDevice,
                        Some(OperatingSystem::Android(Some("Samsung".to_string()))),
                    )
                } else {
                    (
                        DeviceType::SmartTV,
                        Some(OperatingSystem::Other("Tizen".to_string())),
                    )
                }
            }
            
            // Google devices
            v if v.contains("google") => (
                DeviceType::AndroidDevice,
                Some(OperatingSystem::Android(Some("Pixel".to_string()))),
            ),
            
            // Huawei devices
            v if v.contains("huawei") => (
                DeviceType::AndroidDevice,
                Some(OperatingSystem::Android(Some("EMUI".to_string()))),
            ),
            
            // Xiaomi devices
            v if v.contains("xiaomi") => (
                DeviceType::AndroidDevice,
                Some(OperatingSystem::Android(Some("MIUI".to_string()))),
            ),
            
            // OnePlus devices
            v if v.contains("oneplus") => (
                DeviceType::AndroidDevice,
                Some(OperatingSystem::Android(Some("OxygenOS".to_string()))),
            ),
            
            // Networking equipment
            v if v.contains("cisco") => (
                DeviceType::NetworkDevice,
                Some(OperatingSystem::RouterOS),
            ),
            
            v if v.contains("ubiquiti") => (
                DeviceType::AccessPoint,
                Some(OperatingSystem::RouterOS),
            ),
            
            v if v.contains("netgear") || v.contains("linksys") || v.contains("tp-link") => {
                (DeviceType::Router, Some(OperatingSystem::RouterOS))
            }
            
            v if v.contains("d-link") || v.contains("asus") => (
                DeviceType::Router,
                Some(OperatingSystem::RouterOS),
            ),
            
            // Specialized devices
            v if v.contains("raspberry") => (
                DeviceType::IoTDevice,
                Some(OperatingSystem::Linux(Some("Raspberry Pi OS".to_string()))),
            ),
            
            // Generic computer hardware vendors
            v if v.contains("intel") || v.contains("realtek") || v.contains("qualcomm") => {
                (DeviceType::Computer, None)
            }
            
            // Printer manufacturers
            v if v.contains("brother") 
                || v.contains("canon") 
                || v.contains("epson") 
                || v.contains("hp") 
                || v.contains("lexmark") => {
                (
                    DeviceType::Printer,
                    Some(OperatingSystem::Other("Embedded".to_string())),
                )
            }
            
            // Smart home and IoT devices
            v if v.contains("amazon") => (
                DeviceType::IoTDevice,
                Some(OperatingSystem::Linux(Some("Fire OS".to_string()))),
            ),
            
            v if v.contains("sonos") => (
                DeviceType::IoTDevice,
                Some(OperatingSystem::Linux(Some("SonosOS".to_string()))),
            ),
            
            v if v.contains("nest") => (
                DeviceType::IoTDevice,
                Some(OperatingSystem::Other("Nest OS".to_string())),
            ),
            
            v if v.contains("ring") => (
                DeviceType::IoTDevice,
                Some(OperatingSystem::Linux(Some("Ring OS".to_string()))),
            ),
            
            v if v.contains("philips") && v.contains("hue") => (
                DeviceType::IoTDevice,
                Some(OperatingSystem::Other("Embedded".to_string())),
            ),
            
            // Gaming consoles
            v if v.contains("sony") && v.contains("computer") => (
                DeviceType::Computer,
                Some(OperatingSystem::Other("PlayStation OS".to_string())),
            ),
            
            v if v.contains("microsoft") && v.contains("xbox") => (
                DeviceType::Computer,
                Some(OperatingSystem::Other("Xbox OS".to_string())),
            ),
            
            v if v.contains("nintendo") => (
                DeviceType::Computer,
                Some(OperatingSystem::Other("Nintendo OS".to_string())),
            ),
            
            // TV manufacturers
            v if v.contains("lg") && v.contains("electronics") => (
                DeviceType::SmartTV,
                Some(OperatingSystem::Other("webOS".to_string())),
            ),
            
            v if v.contains("sony") && v.contains("tv") => (
                DeviceType::SmartTV,
                Some(OperatingSystem::Android(Some("Android TV".to_string()))),
            ),
            
            // VMware virtual machines
            v if v.contains("vmware") => (
                DeviceType::Computer,
                Some(OperatingSystem::Other("Virtual Machine".to_string())),
            ),
            
            // Default case for unknown vendors
            _ => (DeviceType::Unknown, None),
        }
    }
    
    /// Additional heuristics based on MAC address patterns
    fn analyze_mac_patterns(&self, mac: &str) -> Option<DeviceType> {
        let mac_upper = mac.to_uppercase();
        
        // Check for locally administered addresses (bit 1 of first octet set)
        if let Some(first_octet) = mac_upper.split(':').next() {
            if let Ok(octet) = u8::from_str_radix(first_octet, 16) {
                if octet & 0x02 != 0 {
                    // Locally administered - often used by virtual machines or randomized addresses
                    return Some(DeviceType::Computer);
                }
            }
        }
        
        // Check for common virtualization prefixes
        if mac_upper.starts_with("00:0C:29") // VMware
            || mac_upper.starts_with("00:50:56") // VMware
            || mac_upper.starts_with("08:00:27") // VirtualBox
        {
            return Some(DeviceType::Computer);
        }
        
        None
    }
}

#[async_trait]
impl DeviceDetectionStrategy for EnhancedMacAddressStrategy {
    fn name(&self) -> &'static str {
        "Enhanced MAC Address Analysis with Device Classification"
    }

    async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
        if let Some(ref mac) = device.mac {
            // Look up vendor information
            let vendor_info = {
                let mut db = self.vendor_db.lock().await;
                db.get_device_info(mac)
            };

            if let Some(info) = vendor_info {
                device.vendor = Some(info.vendor.clone());
                
                // Perform advanced device classification
                let (inferred_type, inferred_os) = self.advanced_device_classification(&info.vendor, mac);

                // Update device type if it's currently unknown
                if device.device_type == DeviceType::Unknown {
                    device.device_type = inferred_type;
                }

                // Update operating system if not already detected
                if device.operating_system.is_none() && inferred_os.is_some() {
                    device.operating_system = inferred_os;
                }
            } else {
                // Try MAC pattern analysis if vendor lookup fails
                if let Some(pattern_type) = self.analyze_mac_patterns(mac) {
                    if device.device_type == DeviceType::Unknown {
                        device.device_type = pattern_type;
                    }
                }
            }
        }
        
        Ok(())
    }
}
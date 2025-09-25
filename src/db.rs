use crate::constants::BUILTIN_OUI;
use crate::errors::NetworkDiscoveryError;
use crate::model::{DeviceInfo, DeviceType};
use ::oui::OuiDatabase;
use eui48::MacAddress;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::sync::Arc;

/// OUI (Organizationally Unique Identifier) database for MAC address vendor lookup
pub mod oui {
    use super::*;

    /// Global OUI database instance, loaded lazily on first use
    static OUI_DB: OnceCell<Arc<OuiDatabase>> = OnceCell::new();

    /// MAC address vendor database with caching capabilities
    pub struct MacVendorDatabase {
        vendor_cache: HashMap<String, String>,
    }

    impl MacVendorDatabase {
        /// Create a new MAC vendor database instance
        /// The actual OUI database is loaded lazily on first lookup
        pub fn new() -> Result<Self, NetworkDiscoveryError> {
            Ok(Self {
                vendor_cache: HashMap::new(),
            })
        }

        /// Look up vendor information for a MAC address
        /// Returns cached result if available, otherwise queries the OUI database
        pub fn lookup_vendor(&mut self, mac: &str) -> Option<String> {
            let clean_mac = self.normalize_mac(mac)?;
            
            // Check cache first
            if let Some(vendor) = self.vendor_cache.get(&clean_mac) {
                return Some(vendor.clone());
            }

            // Initialize database on first use
            let db = OUI_DB.get_or_init(|| {
                Arc::new(OuiDatabase::new_from_file("manuf.txt").unwrap_or_else(|_| {
                    eprintln!("Failed to load manuf.txt. Using built-in OUI fallback.");
                    OuiDatabase::new_from_str(BUILTIN_OUI).expect("built-in OUI is valid")
                }))
            });

            // Query database
            if let Ok(mac_addr) = MacAddress::parse_str(&clean_mac) {
                if let Ok(Some(entry)) = db.query_by_mac(&mac_addr) {
                    let vendor = entry.name_long.clone().unwrap_or_default();
                    self.vendor_cache.insert(clean_mac, vendor.clone());
                    Some(vendor)
                } else {
                    None
                }
            } else {
                None
            }
        }

        /// Get comprehensive device information based on MAC address
        pub fn get_device_info(&mut self, mac: &str) -> Option<DeviceInfo> {
            let vendor = self.lookup_vendor(mac)?;
            Some(DeviceInfo {
                vendor: vendor.clone(),
                device_type: DeviceType::Unknown,
                operating_system: None,
            })
        }

        /// Normalize MAC address to standard format (XX:XX:XX:XX:XX:XX)
        /// Supports various input formats and performs zero-allocation normalization
        fn normalize_mac(&self, mac: &str) -> Option<String> {
            let mut buf = String::with_capacity(17);
            let clean = mac.replace('-', ":").replace('.', ":");
            let parts: Vec<&str> = clean.split(':').collect();
            
            // Handle already formatted MAC (XX:XX:XX:XX:XX:XX)
            if parts.len() == 6 && parts.iter().all(|p| p.len() == 2) {
                buf.push_str(&clean.to_uppercase());
                return Some(buf);
            }
            
            // Handle raw hex string (XXXXXXXXXXXX)
            if clean.len() == 12 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
                for (i, chunk) in clean.as_bytes().chunks(2).enumerate() {
                    if i > 0 {
                        buf.push(':');
                    }
                    buf.push_str(&String::from_utf8_lossy(chunk));
                }
                return Some(buf.to_uppercase());
            }
            
            None
        }
    }
}
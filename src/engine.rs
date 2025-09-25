use crate::config::ScanConfig;
use crate::detect::{
    hostname::EnhancedHostnameStrategy, mac::EnhancedMacAddressStrategy, os::AdvancedOSDetector,
    port::EnhancedPortScanStrategy, DeviceDetectionStrategy,
};
use crate::db::oui::MacVendorDatabase;
use crate::errors::NetworkDiscoveryError;
use crate::model::{DeviceType, NetworkDevice, OperatingSystem};
use crate::net::{interface, ping::parallel_ping_sweep};
use comfy_table::{Cell, Table};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

/// Main network discovery engine that orchestrates all detection strategies
pub struct EnhancedNetworkDiscovery {
    strategies: Arc<Vec<Box<dyn DeviceDetectionStrategy>>>,
    config: ScanConfig,
    os_detector: Arc<AdvancedOSDetector>,
}

impl EnhancedNetworkDiscovery {
    /// Create a new network discovery engine with all detection strategies
    pub fn new() -> Result<Self, NetworkDiscoveryError> {
        let config = ScanConfig::default();
        let vendor_db = Arc::new(Mutex::new(MacVendorDatabase::new()?));
        let os_detector = Arc::new(AdvancedOSDetector::new(config.clone()));

        let mut strategies_vec: Vec<Box<dyn DeviceDetectionStrategy>> = Vec::new();
        
        // Add MAC address detection strategy
        strategies_vec.push(Box::new(EnhancedMacAddressStrategy::new(vendor_db.clone())));
        
        // Add port scanning strategy
        strategies_vec.push(Box::new(EnhancedPortScanStrategy::new(
            config.clone(),
            os_detector.clone(),
        )));
        
        // Add hostname resolution strategy
        strategies_vec.push(Box::new(EnhancedHostnameStrategy::new()?));

        Ok(Self {
            strategies: Arc::new(strategies_vec),
            config,
            os_detector,
        })
    }

    /// Set the maximum number of concurrent scanning operations
    pub fn set_concurrency(&mut self, jobs: usize) {
        self.config.max_concurrent_scans = jobs.max(1);
    }

    /// Perform comprehensive network discovery on the specified network
    pub async fn discover_network_enhanced(
        &self,
        network: &str,
    ) -> Result<(), NetworkDiscoveryError> {
        // Validate network format
        if !network.contains('/') {
            return Err(NetworkDiscoveryError::PingError(
                "Network must be in CIDR format (e.g., 192.168.1.0/24)".to_string(),
            ));
        }

        if !network.ends_with("/24") {
            return Err(NetworkDiscoveryError::PingError(
                "Only /24 networks are currently supported".to_string(),
            ));
        }

        let scan_start = Instant::now();
        println!(
            "Enhanced Network Discovery Tool - Starting scan for {}",
            network
        );
        println!("====================================================================");

        // Phase 1: Host Discovery (Ping Sweep)
        let active_ips = parallel_ping_sweep(network, &self.config).await?;
        println!("Found {} active devices", active_ips.len());
        println!("Starting enhanced fingerprinting scan...\n");

        // Phase 2: Device Detection and Analysis
        let discovered_devices = Arc::new(Mutex::new(HashMap::<IpAddr, NetworkDevice>::new()));
        let (tx, mut rx) = mpsc::channel::<NetworkDevice>(active_ips.len());
        let total_devices = active_ips.len();
        let mut completed = 0;

        // Find appropriate network interface for ARP operations
        let interface_name_for_arp = interface::find_network_interface(network)?;
        if interface_name_for_arp.is_none() {
            println!("Warning: No suitable network interface found. MAC address detection may be limited.");
        }

        // Spawn detection tasks for each discovered device
        for ip in active_ips {
            println!("Scanning device {} with enhanced detection", ip);
            
            let strategies = self.strategies.clone();
            let tx_clone = tx.clone();
            let os_detector = self.os_detector.clone();
            let arp_timeout = Duration::from_millis(self.config.ping_timeout_ms);
            let interface_name_for_arp_clone = interface_name_for_arp.clone();

            tokio::spawn(async move {
                // Attempt MAC address resolution via ARP
                let mac = if let IpAddr::V4(ipv4) = ip {
                    if let Some(ref iface_name) = interface_name_for_arp_clone {
                        match libarp::client::ArpClient::new_with_iface_name(iface_name) {
                            Ok(mut client) => {
                                match client.ip_to_mac(ipv4, Some(arp_timeout)).await {
                                    Ok(mac) => {
                                        println!("MAC address found for {}: {}", ip, mac);
                                        Some(mac.to_string().to_uppercase())
                                    }
                                    Err(_) => None,
                                }
                            }
                            Err(_) => None,
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Initialize device structure
                let mut device = NetworkDevice {
                    ip,
                    mac,
                    hostname: None,
                    vendor: None,
                    device_type: DeviceType::Unknown,
                    operating_system: None,
                    os_confidence: None,
                    open_ports: Vec::new(),
                    services: Vec::new(),
                    response_time: None,
                    last_seen: std::time::SystemTime::now(),
                    tcp_fingerprint: None,
                };

                // Run all detection strategies
                for strategy in strategies.iter() {
                    let _ = strategy.detect(&mut device).await;
                }

                // Perform comprehensive OS detection
                let (detected_os, confidence) = os_detector.detect_operating_system(&device).await;
                if let Some(os) = detected_os {
                    device.operating_system = Some(os);
                    device.os_confidence = Some(confidence);
                }

                let _ = tx_clone.send(device).await;
            });
        }

        // Close the sender channel
        drop(tx);

        // Collect results and show progress
        use std::io::Write;
        while let Some(device) = rx.recv().await {
            completed += 1;
            print!(
                "\rProgress: {}/{} devices ({:.1}%)",
                completed,
                total_devices,
                (completed as f32 / total_devices as f32) * 100.0
            );
            std::io::stdout().flush().ok();

            let mut devices_map = discovered_devices.lock().await;
            devices_map.insert(device.ip, device);
        }

        println!();

        // Phase 3: Results Display and Analysis
        self.display_enhanced_results(&discovered_devices, scan_start.elapsed())
            .await;

        Ok(())
    }

    /// Display comprehensive scan results in a formatted table
    async fn display_enhanced_results(
        &self,
        devices: &Arc<Mutex<HashMap<IpAddr, NetworkDevice>>>,
        scan_duration: Duration,
    ) {
        let devices_map = devices.lock().await;
        let mut table = Table::new();
        
        table.set_header(vec![
            "IP",
            "Hostname",
            "MAC",
            "Vendor",
            "Type",
            "OS",
            "Confidence",
            "Ports",
            "Key Services",
        ]);

        let mut os_detected_count = 0;
        let mut high_confidence_count = 0;

        for (_, device) in devices_map.iter() {
            // Track OS detection statistics
            if device.operating_system.is_some() {
                os_detected_count += 1;
                if let Some(conf) = device.os_confidence {
                    if conf > 0.8 {
                        high_confidence_count += 1;
                    }
                }
            }

            // Format service details
            let service_details = if device.services.is_empty() {
                "—".to_string()
            } else {
                device
                    .services
                    .iter()
                    .filter_map(|s| s.service_name.as_ref())
                    .take(3)
                    .cloned()
                    .collect::<Vec<String>>()
                    .join(", ")
            };

            // Format ports list
            let ports_list = if device.open_ports.is_empty() {
                "—".to_string()
            } else {
                let mut ports = device
                    .open_ports
                    .iter()
                    .take(6)
                    .map(|p| p.to_string())
                    .collect::<Vec<String>>()
                    .join(", ");
                if device.open_ports.len() > 6 {
                    ports.push_str(&format!(" (+{})", device.open_ports.len() - 6));
                }
                ports
            };

            // Format OS string
            let os_string = if let Some(ref os) = device.operating_system {
                match os {
                    OperatingSystem::Windows(Some(name)) => format!("Windows {}", name),
                    OperatingSystem::Windows(None) => "Windows".to_string(),
                    OperatingSystem::MacOS(Some(name)) => format!("macOS {}", name),
                    OperatingSystem::MacOS(None) => "macOS".to_string(),
                    OperatingSystem::Linux(Some(name)) => format!("Linux {}", name),
                    OperatingSystem::Linux(None) => "Linux".to_string(),
                    OperatingSystem::IOS(Some(name)) => format!("iOS {}", name),
                    OperatingSystem::IOS(None) => "iOS".to_string(),
                    OperatingSystem::Android(Some(name)) => format!("Android {}", name),
                    OperatingSystem::Android(None) => "Android".to_string(),
                    OperatingSystem::RouterOS => "RouterOS".to_string(),
                    OperatingSystem::FreeBSD(name) => {
                        format!("FreeBSD {}", name.as_ref().unwrap_or(&"".to_string()))
                    }
                    OperatingSystem::OpenBSD(name) => {
                        format!("OpenBSD {}", name.as_ref().unwrap_or(&"".to_string()))
                    }
                    OperatingSystem::Other(name) => name.clone(),
                    _ => "Other".to_string(),
                }
            } else {
                "Unknown".to_string()
            };

            // Format confidence percentage
            let confidence_str = if let Some(conf) = device.os_confidence {
                format!("{:.0}%", conf * 100.0)
            } else {
                "—".to_string()
            };

            // Format device type
            let device_type_str = match device.device_type {
                DeviceType::AppleDevice => "Apple Device",
                DeviceType::AndroidDevice => "Android Device",
                DeviceType::WindowsDevice => "Windows PC",
                DeviceType::LinuxDevice => "Linux System",
                DeviceType::NetworkDevice => "Network Equipment",
                _ => &format!("{:?}", device.device_type),
            };

            // Format hostname (truncate if too long)
            let hostname_display = device.hostname.as_ref().map_or("—".to_string(), |h| {
                if let Some((prefix, rest)) = h.split_once('-') {
                    if prefix.chars().all(|c| c.is_alphabetic()) && prefix.len() >= 2 && rest.contains('-') {
                        return prefix.to_string();
                    }
                }
                if h.len() > 20 {
                    format!("{}...", &h[..17])
                } else {
                    h.to_string()
                }
            });

            table.add_row(vec![
                Cell::new(device.ip.to_string()),
                Cell::new(hostname_display),
                Cell::new(device.mac.clone().unwrap_or_else(|| "—".to_string())),
                Cell::new(device.vendor.clone().unwrap_or_else(|| "—".to_string())),
                Cell::new(device_type_str),
                Cell::new(os_string),
                Cell::new(confidence_str),
                Cell::new(ports_list),
                Cell::new(service_details),
            ]);
        }

        println!("{}", table);

        // Calculate and display summary statistics
        let detection_rate = if !devices_map.is_empty() {
            (os_detected_count as f32 / devices_map.len() as f32) * 100.0
        } else {
            0.0
        };

        let high_confidence_rate = if os_detected_count > 0 {
            (high_confidence_count as f32 / os_detected_count as f32) * 100.0
        } else {
            0.0
        };

        println!("\nEnhanced Scan Results Summary:");
        println!("============================");
        println!("Scan completed in {:.2} seconds", scan_duration.as_secs_f64());
        println!(
            "OS Detection Rate: {:.1}% ({}/{})",
            detection_rate, os_detected_count, devices_map.len()
        );
        println!(
            "High Confidence Detections: {:.1}% ({}/{})",
            high_confidence_rate, high_confidence_count, os_detected_count
        );
        println!(
            "Total Services Detected: {}",
            devices_map
                .values()
                .map(|d| d.services.len())
                .sum::<usize>()
        );
    }
}
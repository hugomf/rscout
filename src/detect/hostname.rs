use super::DeviceDetectionStrategy;
use crate::errors::NetworkDiscoveryError;
use crate::model::NetworkDevice;
use async_trait::async_trait;
use dns_lookup::lookup_addr;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::{timeout, Instant};

/// mDNS-SD service types that usually expose hostnames
const SERVICES: &[&str] = &[
    "_airplay._tcp.local.",
    // Add more services as needed for discovery
];

/// Enhanced hostname resolution strategy using multiple discovery methods
pub struct EnhancedHostnameStrategy;

    impl EnhancedHostnameStrategy {
        pub fn new() -> Result<Self, NetworkDiscoveryError> {
            Ok(Self)
        }

        async fn mdns_instance(&self, ip: IpAddr) -> Option<String> {
            let daemon = ServiceDaemon::new().ok()?;
            let total_deadline = Instant::now() + Duration::from_millis(3000);
            let mut candidates = Vec::new();

            for &service in SERVICES {
                let service_deadline = Instant::now() + Duration::from_millis(2000);
                let actual_deadline = std::cmp::min(service_deadline, total_deadline);
                
                let receiver = daemon.browse(service).ok()?;
                
                loop {
                    let now = Instant::now();
                    if now >= actual_deadline {
                        break;
                    }
                    let timeout_dur = actual_deadline - now;

                    match timeout(timeout_dur, receiver.recv_async()).await {
                        Ok(Ok(event)) => match event {
                            ServiceEvent::ServiceResolved(info) => {
                                if info.get_addresses().iter().any(|scoped_ip| scoped_ip.to_ip_addr() == ip) {
                                    let mut hostname = info.get_fullname()
                                        .trim_end_matches(service)
                                        .trim_end_matches('.')
                                        .trim_end_matches(".local");
                                    if hostname.is_empty() {
                                        hostname = info.get_hostname()
                                            .trim_end_matches('.')
                                            .trim_end_matches(".local");
                                    }
                                    candidates.push(hostname.to_string());
                                }
                            }
                            _ => continue,
                        },
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
                
                daemon.stop_browse(service).ok();
                
                if Instant::now() >= total_deadline {
                    break;
                }
            }

            daemon.shutdown().ok();

            if candidates.is_empty() {
                return None;
            }

            let best = candidates
                .iter()
                .filter(|&n| !n.eq_ignore_ascii_case("localhost"))
                .min_by_key(|n| n.len());
            
            best.cloned()
        }

        // Note: These methods were used in the original implementation but are now
        // handled directly in the detect method to avoid blocking issues
    }

    #[async_trait]
    impl DeviceDetectionStrategy for EnhancedHostnameStrategy {
        fn name(&self) -> &'static str {
            "multi-service mDNS-SD hostname lookup"
        }

        async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
            let ip = device.ip;
            
            // Try mDNS first
            let host = if let Some(hostname) = self.mdns_instance(ip).await {
                Some(hostname)
            } else {
                // Use async-compatible reverse DNS lookup
                tokio::task::spawn_blocking(move || lookup_addr(&ip).ok())
                    .await
                    .unwrap_or(None)
            };
            
            device.hostname = Some(host.unwrap_or_else(|| "N/A".to_string()));
            Ok(())
        }
    }
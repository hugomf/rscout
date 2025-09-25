use crate::config::ScanConfig;
use crate::model::{NetworkDevice, NetworkService, OperatingSystem, TcpFingerprint};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Advanced operating system detection using multiple analysis techniques
pub struct AdvancedOSDetector {
    config: ScanConfig,
}

impl AdvancedOSDetector {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Main OS detection method that combines multiple techniques
    pub async fn detect_operating_system(
        &self,
        device: &NetworkDevice,
    ) -> (Option<OperatingSystem>, f32) {
        let mut confidence = 0.0f32;
        let mut detected_os: Option<OperatingSystem> = None;

        // Analyze service banners
        let (os_from_banner, banner_conf) = self.analyze_service_banners(&device.services);
        if banner_conf > confidence {
            confidence = banner_conf;
            detected_os = os_from_banner;
        }

        // Analyze port patterns
        let (os_from_ports, port_conf) = self.analyze_port_patterns(&device.open_ports);
        if port_conf > confidence {
            confidence = port_conf;
            detected_os = os_from_ports;
        }

        // Analyze TCP fingerprint
        if let Some(ref tcp_fp) = device.tcp_fingerprint {
            let (os_from_tcp, tcp_conf) = self.analyze_tcp_fingerprint(tcp_fp);
            if tcp_conf > confidence {
                confidence = tcp_conf;
                detected_os = os_from_tcp;
            }
        }

        // Infer from vendor
        if let Some(ref vendor) = device.vendor {
            let (os_from_vendor, vendor_conf) = self.infer_os_from_vendor(vendor);
            if vendor_conf > confidence {
                confidence = vendor_conf;
                detected_os = os_from_vendor;
            }
        }

        // Analyze hostname
        if let Some(ref hostname) = device.hostname {
            let (os_from_hostname, hostname_conf) = self.analyze_hostname_for_os(hostname);
            if hostname_conf > confidence {
                confidence = hostname_conf;
                detected_os = os_from_hostname;
            }
        }

        (detected_os, confidence)
    }

    /// Analyze service banners for OS detection
    fn analyze_service_banners(
        &self,
        services: &[NetworkService],
    ) -> (Option<OperatingSystem>, f32) {
        let mut max_confidence = 0.0;
        let mut detected_os = None;

        for service in services {
            if let Some(ref banner) = service.banner {
                let banner_lower = banner.to_lowercase();
                let (os, confidence) = match service.port {
                    22 => self.analyze_ssh_banner(&banner_lower),
                    80 | 443 | 8080 | 8443 => self.analyze_http_banner(&banner_lower),
                    21 => self.analyze_ftp_banner(&banner_lower),
                    25 => self.analyze_smtp_banner(&banner_lower),
                    135 | 445 => self.analyze_windows_service_banner(&banner_lower),
                    _ => (None, 0.0),
                };
                if confidence > max_confidence {
                    max_confidence = confidence;
                    detected_os = os;
                }
            }
        }
        (detected_os, max_confidence)
    }

    /// SSH banner analysis for OS detection
    fn analyze_ssh_banner(&self, banner: &str) -> (Option<OperatingSystem>, f32) {
        if banner.contains("openssh") {
            if banner.contains("ubuntu") {
                return (Some(OperatingSystem::Linux(Some("Ubuntu".to_string()))), 0.95);
            } else if banner.contains("debian") {
                return (Some(OperatingSystem::Linux(Some("Debian".to_string()))), 0.95);
            } else if banner.contains("centos") || banner.contains("rhel") {
                return (Some(OperatingSystem::Linux(Some("CentOS/RHEL".to_string()))), 0.95);
            } else if banner.contains("freebsd") {
                return (Some(OperatingSystem::FreeBSD(None)), 0.95);
            } else if banner.contains("openbsd") {
                return (Some(OperatingSystem::OpenBSD(None)), 0.95);
            } else {
                return (Some(OperatingSystem::Linux(None)), 0.8);
            }
        } else if banner.contains("dropbear") {
            return (Some(OperatingSystem::Linux(Some("Embedded/OpenWrt".to_string()))), 0.85);
        } else if banner.contains("microsoft") || banner.contains("windows") {
            return (Some(OperatingSystem::Windows(Some("Server".to_string()))), 0.9);
        }
        (None, 0.0)
    }

    /// HTTP banner analysis for OS detection
    fn analyze_http_banner(&self, banner: &str) -> (Option<OperatingSystem>, f32) {
        if banner.contains("microsoft-iis") {
            return (Some(OperatingSystem::Windows(Some("Server".to_string()))), 0.85);
        } else if banner.contains("apache") {
            if banner.contains("ubuntu") {
                return (Some(OperatingSystem::Linux(Some("Ubuntu".to_string()))), 0.85);
            } else if banner.contains("centos") || banner.contains("rhel") {
                return (Some(OperatingSystem::Linux(Some("CentOS/RHEL".to_string()))), 0.85);
            } else if banner.contains("debian") {
                return (Some(OperatingSystem::Linux(Some("Debian".to_string()))), 0.85);
            } else if banner.contains("freebsd") {
                return (Some(OperatingSystem::FreeBSD(None)), 0.8);
            } else {
                return (Some(OperatingSystem::Linux(None)), 0.7);
            }
        } else if banner.contains("nginx") {
            if banner.contains("ubuntu") {
                return (Some(OperatingSystem::Linux(Some("Ubuntu".to_string()))), 0.8);
            } else {
                return (Some(OperatingSystem::Linux(None)), 0.7);
            }
        } else if banner.contains("lighttpd") {
            return (Some(OperatingSystem::Linux(None)), 0.7);
        }
        (None, 0.0)
    }

    /// FTP banner analysis for OS detection
    fn analyze_ftp_banner(&self, banner: &str) -> (Option<OperatingSystem>, f32) {
        if banner.contains("microsoft ftp") {
            return (Some(OperatingSystem::Windows(Some("Server".to_string()))), 0.85);
        } else if banner.contains("vsftpd") {
            return (Some(OperatingSystem::Linux(None)), 0.8);
        } else if banner.contains("proftpd") {
            return (Some(OperatingSystem::Linux(None)), 0.75);
        }
        (None, 0.0)
    }

    /// SMTP banner analysis for OS detection
    fn analyze_smtp_banner(&self, banner: &str) -> (Option<OperatingSystem>, f32) {
        if banner.contains("microsoft exchange") || banner.contains("microsoft smtp") {
            return (Some(OperatingSystem::Windows(Some("Server".to_string()))), 0.85);
        } else if banner.contains("postfix") {
            return (Some(OperatingSystem::Linux(None)), 0.8);
        } else if banner.contains("sendmail") {
            return (Some(OperatingSystem::Linux(None)), 0.75);
        }
        (None, 0.0)
    }

    /// Windows service banner analysis
    fn analyze_windows_service_banner(&self, banner: &str) -> (Option<OperatingSystem>, f32) {
        if banner.contains("windows") || banner.contains("microsoft") {
            if banner.contains("server") {
                return (Some(OperatingSystem::Windows(Some("Server".to_string()))), 0.8);
            } else {
                return (Some(OperatingSystem::Windows(None)), 0.75);
            }
        }
        (None, 0.0)
    }

    /// Port pattern analysis for OS detection
    fn analyze_port_patterns(&self, ports: &[u16]) -> (Option<OperatingSystem>, f32) {
        use std::collections::HashSet;
        let port_set: HashSet<u16> = ports.iter().copied().collect();

        // Windows port patterns
        if port_set.contains(&135) && port_set.contains(&445) && port_set.contains(&139) {
            if port_set.contains(&3389) {
                return (Some(OperatingSystem::Windows(Some("Server/Pro".to_string()))), 0.85);
            } else {
                return (Some(OperatingSystem::Windows(None)), 0.8);
            }
        }

        if port_set.contains(&3389) && !port_set.contains(&22) {
            return (Some(OperatingSystem::Windows(None)), 0.75);
        }

        // Linux server patterns
        if port_set.contains(&22) && (port_set.contains(&80) || port_set.contains(&443)) {
            if port_set.contains(&3306) || port_set.contains(&5432) {
                return (Some(OperatingSystem::Linux(Some("Server".to_string()))), 0.7);
            } else {
                return (Some(OperatingSystem::Linux(None)), 0.65);
            }
        }

        // Embedded Linux pattern
        if port_set.contains(&22) && ports.len() <= 2 {
            return (Some(OperatingSystem::Linux(Some("Embedded".to_string()))), 0.6);
        }

        // Router pattern
        if (port_set.contains(&80) || port_set.contains(&443))
            && ports.len() <= 3
            && !port_set.contains(&22)
        {
            return (Some(OperatingSystem::RouterOS), 0.7);
        }

        (None, 0.0)
    }

    /// TCP fingerprint analysis for OS detection
    fn analyze_tcp_fingerprint(&self, tcp_fp: &TcpFingerprint) -> (Option<OperatingSystem>, f32) {
        match tcp_fp.estimated_ttl {
            64 => (Some(OperatingSystem::Linux(None)), 0.6),
            128 => (Some(OperatingSystem::Windows(None)), 0.6),
            255 => (Some(OperatingSystem::RouterOS), 0.7),
            60..=64 => (Some(OperatingSystem::MacOS(None)), 0.5),
            _ => (None, 0.0),
        }
    }

    /// Infer OS from vendor information
    fn infer_os_from_vendor(&self, vendor: &str) -> (Option<OperatingSystem>, f32) {
        let vendor_lower = vendor.to_lowercase();
        if vendor_lower.contains("apple") {
            (Some(OperatingSystem::MacOS(None)), 0.7)
        } else if vendor_lower.contains("microsoft") {
            (Some(OperatingSystem::Windows(None)), 0.7)
        } else if vendor_lower.contains("raspberry") {
            (Some(OperatingSystem::Linux(Some("Raspberry Pi OS".to_string()))), 0.85)
        } else if vendor_lower.contains("cisco") || vendor_lower.contains("juniper") {
            (Some(OperatingSystem::RouterOS), 0.8)
        } else if vendor_lower.contains("ubiquiti") || vendor_lower.contains("netgear") {
            (Some(OperatingSystem::RouterOS), 0.75)
        } else {
            (None, 0.0)
        }
    }

    /// Analyze hostname patterns for OS detection
    fn analyze_hostname_for_os(&self, hostname: &str) -> (Option<OperatingSystem>, f32) {
        let hostname_lower = hostname.to_lowercase();
        if hostname_lower.contains("android") {
            (Some(OperatingSystem::Android(None)), 0.8)
        } else if hostname_lower.contains("iphone") || hostname_lower.contains("ipad") {
            (Some(OperatingSystem::IOS(Some("iPhone".to_string()))), 0.85)
        } else if hostname_lower.contains("mac") || hostname_lower.ends_with(".local") {
            (Some(OperatingSystem::MacOS(None)), 0.65)
        } else if hostname_lower.contains("ubuntu") {
            (Some(OperatingSystem::Linux(Some("Ubuntu".to_string()))), 0.85)
        } else if hostname_lower.contains("debian") {
            (Some(OperatingSystem::Linux(Some("Debian".to_string()))), 0.85)
        } else if hostname_lower.contains("windows") || hostname_lower.contains("desktop") {
            (Some(OperatingSystem::Windows(None)), 0.7)
        } else if hostname_lower.contains("router") || hostname_lower.contains("gateway") {
            (Some(OperatingSystem::RouterOS), 0.75)
        } else if hostname_lower.contains("raspberrypi") {
            (Some(OperatingSystem::Linux(Some("Raspberry Pi OS".to_string()))), 0.9)
        } else {
            (None, 0.0)
        }
    }

    /// Generate TCP fingerprint for advanced OS detection
    pub async fn generate_tcp_fingerprint(&self, ip: IpAddr) -> Option<TcpFingerprint> {
        let mut response_times = Vec::new();
        let mut successful_connections = 0;
        let mut banner_characteristics = Vec::new();
        let test_ports = [22, 80, 443, 21, 25, 23];

        for &port in &test_ports {
            let start = Instant::now();
            if let Ok(connect_result) = timeout(
                Duration::from_millis(self.config.tcp_connect_timeout_ms),
                TcpStream::connect((ip, port)),
            )
            .await
            {
                let elapsed = start.elapsed();
                response_times.push(elapsed.as_millis() as u64);

                if let Ok(mut stream) = connect_result {
                    successful_connections += 1;
                    let mut buf = vec![0; 512];
                    if let Ok(Ok(count)) =
                        timeout(Duration::from_millis(200), stream.read(&mut buf)).await
                    {
                        if count > 0 {
                            if let Ok(banner) = String::from_utf8(buf[..count].to_vec()) {
                                let banner_type = match port {
                                    22 => "ssh",
                                    80 | 443 => "http",
                                    21 => "ftp",
                                    25 => "smtp",
                                    _ => "unknown",
                                };
                                banner_characteristics.push(format!(
                                    "{}:{}",
                                    banner_type,
                                    banner.len()
                                ));
                            }
                        }
                    }
                    drop(stream);
                }
            }
        }

        if response_times.is_empty() {
            return None;
        }

        let avg_response_time = response_times.iter().sum::<u64>() / response_times.len() as u64;
        let estimated_ttl = match avg_response_time {
            0..=20 => 64,
            21..=50 => 64,
            51..=100 => 128,
            101..=200 => 255,
            _ => 64,
        };

        let connection_pattern = match successful_connections {
            0 => "closed".to_string(),
            1..=2 => "limited".to_string(),
            3..=4 => "moderate".to_string(),
            _ => "open".to_string(),
        };

        Some(TcpFingerprint {
            estimated_ttl,
            response_time_ms: avg_response_time,
            connection_pattern,
            banner_characteristics,
        })
    }
}
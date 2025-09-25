use crate::config::ScanConfig;
use crate::errors::NetworkDiscoveryError;
use crate::model::{NetworkDevice, NetworkService, OperatingSystem, TcpFingerprint, DeviceType};
use crate::db::oui::MacVendorDatabase;
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Device detection strategy trait
#[async_trait]
pub trait DeviceDetectionStrategy: Send + Sync {
    async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError>;
    fn name(&self) -> &'static str;
}

/// Operating system detection using multiple analysis techniques
pub mod os {
    use super::*;
    use std::time::Instant;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    pub struct AdvancedOSDetector {
        config: ScanConfig,
    }

    impl AdvancedOSDetector {
        pub fn new(config: ScanConfig) -> Self {
            Self { config }
        }

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

        fn analyze_port_patterns(&self, ports: &[u16]) -> (Option<OperatingSystem>, f32) {
            use std::collections::HashSet;
            let port_set: HashSet<u16> = ports.iter().copied().collect();

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

            if port_set.contains(&22) && (port_set.contains(&80) || port_set.contains(&443)) {
                if port_set.contains(&3306) || port_set.contains(&5432) {
                    return (Some(OperatingSystem::Linux(Some("Server".to_string()))), 0.7);
                } else {
                    return (Some(OperatingSystem::Linux(None)), 0.65);
                }
            }

            if port_set.contains(&22) && ports.len() <= 2 {
                return (Some(OperatingSystem::Linux(Some("Embedded".to_string()))), 0.6);
            }

            if (port_set.contains(&80) || port_set.contains(&443))
                && ports.len() <= 3
                && !port_set.contains(&22)
            {
                return (Some(OperatingSystem::RouterOS), 0.7);
            }

            (None, 0.0)
        }

        fn analyze_tcp_fingerprint(&self, tcp_fp: &TcpFingerprint) -> (Option<OperatingSystem>, f32) {
            match tcp_fp.estimated_ttl {
                64 => (Some(OperatingSystem::Linux(None)), 0.6),
                128 => (Some(OperatingSystem::Windows(None)), 0.6),
                255 => (Some(OperatingSystem::RouterOS), 0.7),
                60..=64 => (Some(OperatingSystem::MacOS(None)), 0.5),
                _ => (None, 0.0),
            }
        }

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
}

/// Port scanning and service detection
pub mod port {
    use super::*;
    use futures::pin_mut;
    use futures::stream::{self, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    pub struct EnhancedPortScanStrategy {
        common_ports: Vec<u16>,
        config: Arc<ScanConfig>,
        os_detector: Arc<super::os::AdvancedOSDetector>,
    }

    impl EnhancedPortScanStrategy {
        pub fn new(
            config: ScanConfig,
            os_detector: Arc<super::os::AdvancedOSDetector>,
        ) -> Self {
            Self {
                common_ports: config.common_ports.clone(),
                config: Arc::new(config),
                os_detector,
            }
        }

        fn get_enhanced_service_info(port: u16) -> (&'static str, &'static str) {
            match port {
                21 => ("FTP", "File Transfer Protocol"),
                22 => ("SSH", "Secure Shell"),
                23 => ("Telnet", "Remote Terminal"),
                25 => ("SMTP", "Mail Transfer"),
                53 => ("DNS", "Domain Name Service"),
                80 => ("HTTP", "Web Server"),
                110 => ("POP3", "Mail Retrieval"),
                135 => ("RPC", "MS RPC Endpoint"),
                139 => ("NetBIOS", "NetBIOS Session"),
                143 => ("IMAP", "Internet Message Access"),
                161 => ("SNMP", "Network Management"),
                162 => ("SNMP Trap", "Network Management"),
                389 => ("LDAP", "Directory Service"),
                443 => ("HTTPS", "Secure Web Server"),
                445 => ("SMB", "File Sharing"),
                636 => ("LDAPS", "Secure LDAP"),
                993 => ("IMAPS", "Secure IMAP"),
                995 => ("POP3S", "Secure POP3"),
                1723 => ("PPTP", "VPN Tunnel"),
                3306 => ("MySQL", "Database Server"),
                3389 => ("RDP", "Remote Desktop"),
                5432 => ("PostgreSQL", "Database Server"),
                5900 => ("VNC", "Remote Display"),
                8000 => ("HTTP-Alt", "Alternative Web"),
                8080 => ("HTTP-Proxy", "Web Proxy"),
                8443 => ("HTTPS-Alt", "Alternative HTTPS"),
                9100 => ("JetDirect", "Printer Service"),
                _ => ("", ""),
            }
        }

        async fn enhanced_banner_grab(
            config: &ScanConfig,
            ip: IpAddr,
            port: u16,
        ) -> Option<String> {
            let tcp_timeout = Duration::from_millis(config.tcp_connect_timeout_ms);
            let banner_timeout = Duration::from_millis(config.banner_read_timeout_ms);

            if let Ok(connect_result) = timeout(tcp_timeout, TcpStream::connect((ip, port))).await {
                if let Ok(mut stream) = connect_result {
                    let mut buf = vec![0; 2048];
                    let probe = match port {
                        80 | 8000 | 8080 => Some(b"HEAD / HTTP/1.1\r\nHost: scanner\r\nUser-Agent: NetworkScanner/1.0\r\nConnection: close\r\n\r\n".as_slice()),
                        443 | 8443 => Some(b"GET / HTTP/1.1\r\nHost: scanner\r\nConnection: close\r\n\r\n".as_slice()),
                        21 => Some(b"HELP\r\n".as_slice()),
                        25 => Some(b"EHLO scanner.local\r\n".as_slice()),
                        110 => Some(b"USER test\r\n".as_slice()),
                        143 => Some(b"A001 CAPABILITY\r\n".as_slice()),
                        22 => None,
                        _ => None,
                    };

                    if let Some(probe_data) = probe {
                        let _ = timeout(tcp_timeout, stream.write_all(probe_data)).await;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }

                    if let Ok(bytes_read) = timeout(banner_timeout, stream.read(&mut buf)).await {
                        if let Ok(count) = bytes_read {
                            if count > 0 {
                                if let Ok(banner_string) = String::from_utf8(buf[..count].to_vec()) {
                                    let cleaned_banner = banner_string
                                        .lines()
                                        .filter(|l| !l.trim().is_empty())
                                        .take(5)
                                        .map(|l| l.trim().to_string())
                                        .collect::<Vec<String>>()
                                        .join(" | ");
                                    return Some(cleaned_banner);
                                }
                            }
                        }
                    }
                }
            }
            None
        }

        fn extract_version_from_banner(banner: &str) -> Option<String> {
            let banner_lower = banner.to_lowercase();
            let patterns = [
                ("apache/", "apache"),
                ("nginx/", "nginx"),
                ("microsoft-iis/", "iis"),
                ("openssh_", "openssh"),
                ("vsftpd ", "vsftpd"),
                ("postfix", "postfix"),
                ("sendmail ", "sendmail"),
            ];

            for (prefix, service) in &patterns {
                if let Some(start) = banner_lower.find(prefix) {
                    let version_start = start + prefix.len();
                    if let Some(version_end) = banner_lower[version_start..].find(' ') {
                        let version = &banner_lower[version_start..version_start + version_end];
                        return Some(format!("{} {}", service, version));
                    }
                }
            }
            None
        }

        fn infer_enhanced_device_characteristics(&self, device: &mut NetworkDevice) {
            let has_web = device.open_ports.iter().any(|&p| matches!(p, 80 | 443 | 8080 | 8443));
            let has_ssh = device.open_ports.contains(&22);
            let has_windows_services = device.open_ports.iter().any(|&p| matches!(p, 135 | 139 | 445));
            let has_rdp = device.open_ports.contains(&3389);
            let has_printer_service = device.open_ports.contains(&9100);
            let has_database = device.open_ports.iter().any(|&p| matches!(p, 3306 | 5432 | 1433));
            let has_mail_services = device.open_ports.iter().any(|&p| matches!(p, 25 | 110 | 143 | 993 | 995));
            let has_snmp = device.open_ports.iter().any(|&p| matches!(p, 161 | 162));

            if has_printer_service {
                device.device_type = DeviceType::Printer;
            } else if has_database && (has_web || has_ssh) {
                device.device_type = DeviceType::Server;
            } else if has_mail_services && (has_web || has_ssh) {
                device.device_type = DeviceType::Server;
            } else if has_windows_services && has_rdp {
                device.device_type = DeviceType::WindowsDevice;
            } else if has_ssh && has_web && device.open_ports.len() >= 3 {
                device.device_type = DeviceType::LinuxDevice;
            } else if has_web && device.open_ports.len() <= 3 {
                device.device_type = DeviceType::Router;
            } else if has_snmp && has_web {
                device.device_type = DeviceType::NetworkDevice;
            } else if device.open_ports.is_empty() {
                if let Some(ref vendor) = device.vendor {
                    let vendor_lower = vendor.to_lowercase();
                    if vendor_lower.contains("apple") {
                        device.device_type = DeviceType::AppleDevice;
                    } else if vendor_lower.contains("samsung") || vendor_lower.contains("google") {
                        device.device_type = DeviceType::AndroidDevice;
                    } else {
                        device.device_type = DeviceType::IoTDevice;
                    }
                }
            }

            // OS detection from service banners
            for service in &device.services {
                if let Some(ref banner) = service.banner {
                    let banner_lower = banner.to_lowercase();
                    if banner_lower.contains("ubuntu") {
                        device.operating_system = Some(OperatingSystem::Linux(Some("Ubuntu".to_string())));
                        device.device_type = DeviceType::LinuxDevice;
                        break;
                    } else if banner_lower.contains("centos") || banner_lower.contains("rhel") {
                        device.operating_system = Some(OperatingSystem::Linux(Some("CentOS/RHEL".to_string())));
                        device.device_type = DeviceType::LinuxDevice;
                        break;
                    } else if banner_lower.contains("debian") {
                        device.operating_system = Some(OperatingSystem::Linux(Some("Debian".to_string())));
                        device.device_type = DeviceType::LinuxDevice;
                        break;
                    } else if banner_lower.contains("microsoft") || banner_lower.contains("windows") {
                        device.operating_system = Some(OperatingSystem::Windows(Some("Server".to_string())));
                        device.device_type = DeviceType::WindowsDevice;
                        break;
                    } else if banner_lower.contains("freebsd") {
                        device.operating_system = Some(OperatingSystem::FreeBSD(None));
                        device.device_type = DeviceType::Server;
                        break;
                    }
                }
            }
        }
    }

    #[async_trait]
    impl DeviceDetectionStrategy for EnhancedPortScanStrategy {
        fn name(&self) -> &'static str {
            "Enhanced Port Scanning with Advanced Banner Analysis"
        }

        async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
            let ip = device.ip;
            let mut open_ports = Vec::new();
            let mut services = Vec::new();

            let port_stream = stream::iter(self.common_ports.iter().copied())
                .map(|port| {
                    let ip = ip;
                    let config = self.config.clone();
                    async move {
                        let mut open_port_info: Option<(u16, NetworkService)> = None;
                        if let Ok(connect_result) = timeout(
                            Duration::from_millis(config.tcp_connect_timeout_ms),
                            TcpStream::connect((ip, port)),
                        )
                        .await
                        {
                            if let Ok(_stream) = connect_result {
                                let (service_name, service_type) = Self::get_enhanced_service_info(port);
                                let mut service = NetworkService {
                                    port,
                                    protocol: "TCP".to_string(),
                                    service_name: Some(service_name.to_string()),
                                    banner: None,
                                    service_type: Some(service_type.to_string()),
                                    version: None,
                                    txt_records: Vec::new(),
                                };

                                if let Some(banner) = Self::enhanced_banner_grab(&config, ip, port).await {
                                    service.banner = Some(banner.clone());
                                    service.version = Self::extract_version_from_banner(&banner);
                                }
                                open_port_info = Some((port, service));
                            }
                        }
                        open_port_info
                    }
                })
                .buffer_unordered(self.config.max_concurrent_scans);

            pin_mut!(port_stream);
            while let Some(result) = port_stream.next().await {
                if let Some((port, service)) = result {
                    open_ports.push(port);
                    services.push(service);
                }
            }

            device.open_ports = open_ports;
            device.services = services;
            device.open_ports.sort();
            device.open_ports.dedup();

            if self.config.enable_advanced_fingerprinting {
                if let Some(tcp_fingerprint) = self.os_detector.generate_tcp_fingerprint(ip).await {
                    device.tcp_fingerprint = Some(tcp_fingerprint);
                }
            }

            self.infer_enhanced_device_characteristics(device);
            Ok(())
        }
    }
}

/// MAC address analysis and vendor detection
pub mod mac {
    use super::*;

    pub struct EnhancedMacAddressStrategy {
        vendor_db: Arc<Mutex<MacVendorDatabase>>,
    }

    impl EnhancedMacAddressStrategy {
        pub fn new(vendor_db: Arc<Mutex<MacVendorDatabase>>) -> Self {
            Self { vendor_db }
        }

        fn advanced_device_classification(
            &self,
            vendor: &str,
            mac: &str,
        ) -> (DeviceType, Option<OperatingSystem>) {
            let vendor_lower = vendor.to_lowercase();
            let mac_upper = mac.to_uppercase();

            match vendor_lower.as_str() {
                v if v.contains("apple") => {
                    if mac_upper.starts_with("00:1B:63") || mac_upper.starts_with("00:26:08") {
                        (DeviceType::AppleDevice, Some(OperatingSystem::IOS(Some("iPhone".to_string()))))
                    } else if mac_upper.starts_with("A4:5E:60") || mac_upper.starts_with("58:55:CA") {
                        (DeviceType::AppleDevice, Some(OperatingSystem::MacOS(Some("MacBook".to_string()))))
                    } else {
                        (DeviceType::AppleDevice, Some(OperatingSystem::MacOS(None)))
                    }
                }
                v if v.contains("samsung") => {
                    if v.contains("electronics") {
                        (DeviceType::AndroidDevice, Some(OperatingSystem::Android(Some("Samsung".to_string()))))
                    } else {
                        (DeviceType::SmartTV, Some(OperatingSystem::Other("Tizen".to_string())))
                    }
                }
                v if v.contains("google") => (
                    DeviceType::AndroidDevice,
                    Some(OperatingSystem::Android(Some("Pixel".to_string()))),
                ),
                v if v.contains("huawei") => (
                    DeviceType::AndroidDevice,
                    Some(OperatingSystem::Android(Some("EMUI".to_string()))),
                ),
                v if v.contains("xiaomi") => (
                    DeviceType::AndroidDevice,
                    Some(OperatingSystem::Android(Some("MIUI".to_string()))),
                ),
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
                v if v.contains("raspberry") => (
                    DeviceType::IoTDevice,
                    Some(OperatingSystem::Linux(Some("Raspberry Pi OS".to_string()))),
                ),
                v if v.contains("intel") || v.contains("realtek") || v.contains("qualcomm") => {
                    (DeviceType::Computer, None)
                }
                v if v.contains("brother") || v.contains("canon") || v.contains("epson") || v.contains("hp") => {
                    (DeviceType::Printer, Some(OperatingSystem::Other("Embedded".to_string())))
                }
                v if v.contains("amazon") => (
                    DeviceType::IoTDevice,
                    Some(OperatingSystem::Linux(Some("Fire OS".to_string()))),
                ),
                v if v.contains("sonos") => (
                    DeviceType::IoTDevice,
                    Some(OperatingSystem::Linux(Some("SonosOS".to_string()))),
                ),
                v if v.contains("nest") || v.contains("google") => (
                    DeviceType::IoTDevice,
                    Some(OperatingSystem::Other("Nest OS".to_string())),
                ),
                v if v.contains("ring") => (
                    DeviceType::IoTDevice,
                    Some(OperatingSystem::Linux(Some("Ring OS".to_string()))),
                ),
                _ => (DeviceType::Unknown, None),
            }
        }
    }

    #[async_trait]
    impl DeviceDetectionStrategy for EnhancedMacAddressStrategy {
        fn name(&self) -> &'static str {
            "Enhanced MAC Address Analysis with Device Classification"
        }

        async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
            if let Some(ref mac) = device.mac {
                let vendor_info = {
                    let mut db = self.vendor_db.lock().await;
                    db.get_device_info(mac)
                };

                if let Some(info) = vendor_info {
                    device.vendor = Some(info.vendor.clone());
                    let (inferred_type, inferred_os) = self.advanced_device_classification(&info.vendor, mac);

                    if device.device_type == DeviceType::Unknown {
                        device.device_type = inferred_type;
                    }

                    if device.operating_system.is_none() && inferred_os.is_some() {
                        device.operating_system = inferred_os;
                    }
                }
            }
            Ok(())
        }
    }
}

/// Hostname resolution and mDNS discovery
pub mod hostname {
    use super::*;
    use dns_lookup::lookup_addr;
    use mdns_sd::{ServiceDaemon, ServiceEvent};
    use std::time::Duration;
    use tokio::time::{timeout, Instant};

    /// mDNS-SD service types that usually expose a hostname
    const SERVICES: &[&str] = &[
        "_airplay._tcp.local.",
        // Add more services as needed
    ];

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

        async fn hostname_resolves_to_ip(&self, hostname: &str, target_ip: IpAddr) -> bool {
            let addrs = tokio::task::block_in_place(|| {
                dns_lookup::getaddrinfo(Some(hostname), None, None)
                    .map(|iter| iter.filter_map(Result::ok).collect::<Vec<_>>())
                    .unwrap_or_default()
            });
            addrs.iter().any(|ai| ai.sockaddr.ip() == target_ip)
        }

        fn reverse_dns(&self, ip: IpAddr) -> Option<String> {
            tokio::task::block_in_place(|| lookup_addr(&ip).ok())
        }
    }

    #[async_trait]
    impl DeviceDetectionStrategy for EnhancedHostnameStrategy {
        fn name(&self) -> &'static str {
            "multi-service mDNS-SD hostname lookup"
        }

        async fn detect(&self, device: &mut NetworkDevice) -> Result<(), NetworkDiscoveryError> {
            let ip = device.ip;
            let host = self
                .mdns_instance(ip)
                .await
                .or_else(|| self.reverse_dns(ip))
                .unwrap_or_else(|| "N/A".to_string());
            device.hostname = Some(host);
            Ok(())
        }
    }
}
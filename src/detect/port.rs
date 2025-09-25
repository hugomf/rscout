use super::DeviceDetectionStrategy;
use crate::config::ScanConfig;
use crate::detect::os::AdvancedOSDetector;
use crate::errors::NetworkDiscoveryError;
use crate::model::{DeviceType, NetworkDevice, NetworkService, OperatingSystem};
use async_trait::async_trait;
use futures::pin_mut;
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Enhanced port scanning strategy with service detection and banner grabbing
pub struct EnhancedPortScanStrategy {
    common_ports: Vec<u16>,
    config: Arc<ScanConfig>,
    os_detector: Arc<AdvancedOSDetector>,
}

impl EnhancedPortScanStrategy {
    pub fn new(config: ScanConfig, os_detector: Arc<AdvancedOSDetector>) -> Self {
        Self {
            common_ports: config.common_ports.clone(),
            config: Arc::new(config),
            os_detector,
        }
    }

    /// Get service information for well-known ports
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

    /// Enhanced banner grabbing with service-specific probes
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
                
                // Send service-specific probes
                let probe = match port {
                    80 | 8000 | 8080 => Some(b"HEAD / HTTP/1.1\r\nHost: scanner\r\nUser-Agent: NetworkScanner/1.0\r\nConnection: close\r\n\r\n".as_slice()),
                    443 | 8443 => Some(b"GET / HTTP/1.1\r\nHost: scanner\r\nConnection: close\r\n\r\n".as_slice()),
                    21 => Some(b"HELP\r\n".as_slice()),
                    25 => Some(b"EHLO scanner.local\r\n".as_slice()),
                    110 => Some(b"USER test\r\n".as_slice()),
                    143 => Some(b"A001 CAPABILITY\r\n".as_slice()),
                    22 => None, // SSH sends banner immediately
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

    /// Extract version information from service banners
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

    /// Infer device characteristics from discovered services and ports
    fn infer_enhanced_device_characteristics(&self, device: &mut NetworkDevice) {
        let has_web = device.open_ports.iter().any(|&p| matches!(p, 80 | 443 | 8080 | 8443));
        let has_ssh = device.open_ports.contains(&22);
        let has_windows_services = device.open_ports.iter().any(|&p| matches!(p, 135 | 139 | 445));
        let has_rdp = device.open_ports.contains(&3389);
        let has_printer_service = device.open_ports.contains(&9100);
        let has_database = device.open_ports.iter().any(|&p| matches!(p, 3306 | 5432 | 1433));
        let has_mail_services = device.open_ports.iter().any(|&p| matches!(p, 25 | 110 | 143 | 993 | 995));
        let has_snmp = device.open_ports.iter().any(|&p| matches!(p, 161 | 162));

        // Device type inference based on service patterns
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
            // Infer from vendor if no ports are open
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

        // Create concurrent port scanning stream
        let port_stream = stream::iter(self.common_ports.iter().copied())
            .map(|port| {
                let ip = ip;
                let config = self.config.clone();
                async move {
                    let mut open_port_info: Option<(u16, NetworkService)> = None;
                    
                    // Attempt TCP connection
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

                            // Attempt banner grabbing
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

        // Collect results
        pin_mut!(port_stream);
        while let Some(result) = port_stream.next().await {
            if let Some((port, service)) = result {
                open_ports.push(port);
                services.push(service);
            }
        }

        // Update device with discovered information
        device.open_ports = open_ports;
        device.services = services;
        device.open_ports.sort();
        device.open_ports.dedup();

        // Generate TCP fingerprint if advanced fingerprinting is enabled
        if self.config.enable_advanced_fingerprinting {
            if let Some(tcp_fingerprint) = self.os_detector.generate_tcp_fingerprint(ip).await {
                device.tcp_fingerprint = Some(tcp_fingerprint);
            }
        }

        // Infer device characteristics from discovered services
        self.infer_enhanced_device_characteristics(device);
        
        Ok(())
    }
}
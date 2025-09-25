/// Configuration settings for network scanning operations
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// List of commonly used ports to scan
    pub common_ports: Vec<u16>,
    
    /// Timeout in milliseconds for ping operations
    pub ping_timeout_ms: u64,
    
    /// Timeout in milliseconds for TCP connection attempts
    pub tcp_connect_timeout_ms: u64,
    
    /// Timeout in milliseconds for banner grabbing operations
    pub banner_read_timeout_ms: u64,
    
    /// Maximum number of concurrent scanning operations
    pub max_concurrent_scans: usize,
    
    /// Enable advanced TCP fingerprinting techniques
    pub enable_advanced_fingerprinting: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            common_ports: vec![
                21,   // FTP
                22,   // SSH
                23,   // Telnet
                25,   // SMTP
                53,   // DNS
                80,   // HTTP
                110,  // POP3
                135,  // MS RPC
                139,  // NetBIOS
                143,  // IMAP
                443,  // HTTPS
                445,  // SMB
                993,  // IMAPS
                995,  // POP3S
                1723, // PPTP
                3306, // MySQL
                3389, // RDP
                5900, // VNC
                8000, // HTTP-Alt
                8080, // HTTP-Proxy
                8443, // HTTPS-Alt
                9100, // JetDirect
                161,  // SNMP
                162,  // SNMP Trap
                389,  // LDAP
                636,  // LDAPS
            ],
            ping_timeout_ms: 500,
            tcp_connect_timeout_ms: 300,
            banner_read_timeout_ms: 500,
            max_concurrent_scans: 64,
            enable_advanced_fingerprinting: true,
        }
    }
}
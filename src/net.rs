use crate::config::ScanConfig;
use crate::errors::NetworkDiscoveryError;
use futures::stream::{self, StreamExt};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use surge_ping::ping;
use tokio::time::timeout;

/// Network ping utilities for host discovery
pub mod ping {
    use super::*;

    /// Perform parallel ping sweep across a /24 network
    /// Returns a list of IP addresses that responded to ping
    pub async fn parallel_ping_sweep(
        network: &str,
        config: &ScanConfig,
    ) -> Result<Vec<IpAddr>, NetworkDiscoveryError> {
        let ping_timeout = Duration::from_millis(config.ping_timeout_ms);
        
        if let Some(base) = network.strip_suffix("/24") {
            let base_parts: Vec<&str> = base.split('.').collect();
            if base_parts.len() == 4 {
                let base_ip_str = format!("{}.{}.{}.", base_parts[0], base_parts[1], base_parts[2]);
                
                let ping_stream = stream::iter(1..255)
                    .map(|i| {
                        let ip_str = format!("{}{}", base_ip_str, i);
                        let ping_timeout = ping_timeout;
                        async move {
                            if let Ok(ip) = Ipv4Addr::from_str(&ip_str) {
                                let target_ip: IpAddr = ip.into();
                                let payload = [0; 56];
                                match timeout(ping_timeout, ping(target_ip, &payload)).await {
                                    Ok(Ok((_icmp_packet, _duration))) => Some(target_ip),
                                    _ => None,
                                }
                            } else {
                                None
                            }
                        }
                    })
                    .buffer_unordered(config.max_concurrent_scans);

                let active_ips: Vec<IpAddr> = ping_stream
                    .filter_map(|result| async move { result })
                    .collect()
                    .await;
                    
                return Ok(active_ips);
            }
        }
        Ok(Vec::new())
    }
}

/// Network interface detection and management utilities
pub mod interface {
    use super::*;

    /// Find the network interface that has an IP address in the target network
    pub fn find_network_interface(
        target_network: &str,
    ) -> Result<Option<String>, NetworkDiscoveryError> {
        let (network_ip, prefix_len) = parse_cidr_network(target_network)?;
        println!(
            "Looking for interface with IP in network: {} (/{}) ",
            network_ip, prefix_len
        );

        let interfaces = NetworkInterface::show()?;
        for interface in interfaces {
            for addr in &interface.addr {
                if let IpAddr::V4(ipv4) = addr.ip() {
                    if is_ip_in_subnet(ipv4, network_ip, prefix_len) {
                        println!("Selected interface: {} (IP: {})", interface.name, ipv4);
                        return Ok(Some(interface.name));
                    }
                }
            }
        }

        println!("No interface found in target network, looking for default interface...");
        let interfaces = NetworkInterface::show()?;
        for interface in interfaces {
            if interface.name.starts_with("lo")
                || interface.name.starts_with("docker")
                || interface.name.starts_with("veth")
            {
                continue;
            }
            for addr in &interface.addr {
                if let IpAddr::V4(ipv4) = addr.ip() {
                    if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                        println!(
                            "Using fallback interface: {} (IP: {})",
                            interface.name, ipv4
                        );
                        return Ok(Some(interface.name));
                    }
                }
            }
        }

        println!("Warning: No suitable network interface found for ARP operations");
        Ok(None)
    }

    /// Parse CIDR network notation (e.g., "192.168.1.0/24")
    fn parse_cidr_network(network: &str) -> Result<(Ipv4Addr, u8), NetworkDiscoveryError> {
        let parts: Vec<&str> = network.split('/').collect();
        if parts.len() != 2 {
            return Err(NetworkDiscoveryError::PingError(
                "Invalid CIDR format".to_string(),
            ));
        }

        let network_ip = Ipv4Addr::from_str(parts[0]).map_err(|e| {
            NetworkDiscoveryError::PingError(format!("Invalid IP address: {}", e))
        })?;

        let prefix_len = parts[1].parse::<u8>().map_err(|e| {
            NetworkDiscoveryError::PingError(format!("Invalid prefix length: {}", e))
        })?;

        if prefix_len > 32 {
            return Err(NetworkDiscoveryError::PingError(
                "Invalid prefix length: must be <= 32".to_string(),
            ));
        }

        Ok((network_ip, prefix_len))
    }

    /// Check if an IP address is within a subnet
    fn is_ip_in_subnet(ip: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
        if prefix_len > 32 {
            return false;
        }

        let mask = if prefix_len == 0 {
            0
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };

        let ip_bits = u32::from(ip);
        let network_bits = u32::from(network);
        (ip_bits & mask) == (network_bits & mask)
    }

    /// Calculate the network CIDR notation from an IP address
    pub fn calculate_network_cidr(ip: Ipv4Addr) -> Result<String, NetworkDiscoveryError> {
        let ip_octets = ip.octets();
        let network = match ip_octets {
            [192, 168, third, _] => format!("192.168.{}.0/24", third),
            [10, second, third, _] => format!("10.{}.{}.0/24", second, third),
            [172, second, third, _] if second >= 16 && second <= 31 => {
                format!("172.{}.{}.0/24", second, third)
            }
            [first, second, third, _] => format!("{}.{}.{}.0/24", first, second, third),
        };
        Ok(network)
    }

    /// List all available network interfaces and their networks
    pub fn list_network_interfaces() -> Result<(), NetworkDiscoveryError> {
        let interfaces = NetworkInterface::show()?;
        println!("Available network interfaces:");
        for interface in interfaces {
            println!("  Interface: {}", interface.name);
            for addr in &interface.addr {
                if let IpAddr::V4(ipv4) = addr.ip() {
                    if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                        let network = calculate_network_cidr(ipv4)?;
                        println!("    IPv4: {} -> Network: {}", ipv4, network);
                    }
                }
            }
        }
        Ok(())
    }

    /// Get the network CIDR for a specific interface name
    pub fn get_network_from_interface(
        interface_name: &str,
    ) -> Result<String, NetworkDiscoveryError> {
        let interfaces = NetworkInterface::show()?;
        for interface in interfaces {
            if interface.name == interface_name {
                for addr in &interface.addr {
                    if let IpAddr::V4(ipv4) = addr.ip() {
                        if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                            let network = calculate_network_cidr(ipv4)?;
                            println!(
                                "Interface {} has IP {}, calculated network: {}",
                                interface_name, ipv4, network
                            );
                            return Ok(network);
                        }
                    }
                }
            }
        }
        Err(NetworkDiscoveryError::NetworkInterfaceCustom(format!(
            "Interface '{}' not found or has no valid IPv4 address",
            interface_name
        )))
    }
}
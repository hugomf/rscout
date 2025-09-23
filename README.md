# RScout - Network Discovery Tool

A comprehensive network discovery and device identification tool written in Rust. RScout performs intelligent network scanning, device detection, and service enumeration to provide detailed information about devices on your local network.

## Features

### 🔍 Network Discovery
- **Ping Sweep**: Fast ICMP-based network scanning to discover active devices
- **MAC Address Resolution**: Automatic MAC address lookup from ARP tables
- **Hostname Resolution**: Multiple methods including ARP, nslookup, and dig

### 🖥️ Device Identification
- **Vendor Detection**: OUI database lookup for device manufacturer identification
- **Device Type Inference**: Smart classification (Computer, Router, Printer, IoT, etc.)
- **Operating System Detection**: OS fingerprinting through port scanning and banner analysis
- **Smart Hostname Generation**: Intelligent hostname creation based on device characteristics

### 🔌 Service Enumeration
- **Port Scanning**: Common service port detection (SSH, HTTP, RDP, etc.)
- **Banner Grabbing**: Service identification through protocol banners
- **Service Mapping**: Automatic mapping of open ports to known services

### 📊 Results Display
- **Tabular Output**: Clean, formatted table display using Comfy Table
- **Detailed Device Information**: Comprehensive device profiles with all discovered data
- **Service Details**: Complete service information including banners and protocols

## Installation

### Prerequisites
- Rust 1.70+ and Cargo
- Network access (requires appropriate permissions for network scanning)

### Building from Source
```bash
git clone <repository-url>
cd rscout
cargo build --release
```

### Installation via Cargo
```bash
cargo install rscout
```

## Usage

### Basic Network Scan
```bash
rscout
```
Scans the automatically detected local network (e.g., 192.168.1.0/24)

### Specific Network Scan
```bash
rscout 192.168.1.0/24
```
Scans the specified network range

### Custom Network Range
```bash
rscout 10.0.0.0/24
rscout 172.16.1.0/24
```

## Output Example

```
🌐 Network Discovery Tool - Rust Implementation
================================================

🔍 Target network: 192.168.1.0/24

📍 Found 8 active devices

- Scanning device 192.168.1.1
- Scanning device 192.168.1.15
- Scanning device 192.168.1.23
...

┌───────────────┬───────────────────┬─────────────────────┬─────────────────────────────┬────────────┬─────────────────────┬─────────────┬─────────────────────────────┐
│ IP            │ MAC               │ Hostname            │ OS                          │ Type       │ Vendor              │ Open Ports  │ Services                    │
├───────────────┼───────────────────┼─────────────────────┼─────────────────────────────┼────────────┼─────────────────────┼─────────────┼─────────────────────────────┤
│ 192.168.1.1   │ AA:BB:CC:DD:EE:FF │ router.local        │ RouterOS                    │ Router     │ Cisco Systems       │ [80, 443]   │ 80/TCP(HTTP), 443/TCP(HTTPS)│
│ 192.168.1.15  │ 11:22:33:44:55:66 │ macbook-pro.local   │ MacOS(None)                 │ Computer   │ Apple               │ [22, 80]    │ 22/TCP(SSH), 80/TCP(HTTP)   │
│ 192.168.1.23  │ FF:EE:DD:CC:BB:AA │ android-phone.local │ Android(None)               │ Smartphone │ Samsung Electronics │ —           │ —                           │
└───────────────┴───────────────────┴─────────────────────┴─────────────────────────────┴────────────┴─────────────────────┴─────────────┴─────────────────────────────┘
```

## Detection Strategies

RScout uses multiple intelligent detection strategies:

### 1. MAC Address Analysis
- OUI database lookup for vendor identification
- Device type inference based on manufacturer
- Operating system hints from vendor patterns

### 2. Port Scanning & Banner Grabbing
- Common service port detection (21-23, 25, 53, 80, 110, 135, 139, 143, 443, 445, etc.)
- HTTP/HTTPS banner analysis for web server identification
- SSH banner analysis for OS detection
- Windows service detection (RPC, NetBIOS, SMB, RDP)

### 3. Smart Hostname & Device Inference
- Multiple hostname resolution methods (ARP, nslookup, dig)
- Intelligent hostname generation based on device characteristics
- Device type inference from hostname patterns
- Service-based device classification

## Supported Device Types

- **Computer**: Desktops, laptops, workstations
- **Smartphone**: Mobile phones
- **Tablet**: Tablets and iPads
- **Router**: Network routers and gateways
- **Switch**: Network switches
- **AccessPoint**: Wireless access points
- **Printer**: Network printers
- **SmartTV**: Smart televisions and media devices
- **IoTDevice**: Internet of Things devices
- **Server**: Dedicated servers
- **AppleDevice**: Apple ecosystem devices

## Supported Operating Systems

- **Windows**: Various versions detected through services
- **MacOS**: Apple computers and devices
- **Linux**: Various distributions including Debian/Ubuntu
- **IOS**: Apple mobile devices
- **Android**: Android smartphones and tablets
- **RouterOS**: Router operating systems (Cisco, Juniper, etc.)
- **Other**: Custom and embedded systems

## Dependencies

- **tokio**: Async runtime for concurrent network operations
- **oui**: MAC address OUI database for vendor lookup
- **eui48**: MAC address parsing and validation
- **comfy-table**: Beautiful terminal table formatting
- **surge-ping**: High-performance ICMP ping implementation
- **regex**: Regular expression support for parsing
- **futures**: Async utilities and future combinators

## File Structure

```
rscout/
├── Cargo.toml          # Project configuration and dependencies
├── src/
│   ├── main.rs         # Main application entry point
│   └── table.rs        # Table formatting utilities
├── manuf.txt           # OUI database for MAC vendor lookup
└── README.md           # This file
```

## Network Requirements

- **Permissions**: Requires appropriate network permissions for ICMP and TCP scanning
- **Firewall**: May need firewall adjustments for comprehensive scanning
- **Platform Support**: Tested on macOS and Linux (Windows support may require adjustments)

## Security Considerations

⚠️ **Important**: Use this tool responsibly and only on networks you own or have explicit permission to scan. Unauthorized network scanning may violate laws or terms of service.

- Obtain proper authorization before scanning any network
- Respect network usage policies and privacy
- Use only for legitimate security testing and network administration

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

- Bug fixes
- New detection strategies
- Additional device type support
- Performance improvements
- Documentation enhancements

## License

This project is licensed under the MIT License - see the [Cargo.toml](Cargo.toml:7) file for details.

## Acknowledgments

- OUI database providers for MAC address vendor information
- The Rust community for excellent async networking libraries
- Contributors to the various crates that make this tool possible

---

**RScout** - Your intelligent network reconnaissance companion 🕵️‍♂️
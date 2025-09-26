# RScout - Network Discovery Tool

A fast, intelligent network discovery tool written in Rust that helps you discover and identify devices on your local network.

## Quick Start

### Installation
```bash
# Install using Cargo
cargo install rscout

# Or build from source
git clone https://github.com/your-username/rscout.git
cd rscout
cargo install --path .
```

### Basic Usage
```bash
# Scan your local network
rscout

# Scan specific network range
rscout 192.168.1.0/24

# Scan with custom concurrency (faster for large networks)
rscout --jobs 32 192.168.1.0/24
```

## Features

- **Device Discovery**: Find active devices using ICMP ping
- **Device Identification**: Detect device types (computers, phones, routers, etc.)
- **Vendor Detection**: Identify manufacturers from MAC addresses
- **OS Detection**: Fingerprint operating systems
- **Service Discovery**: Find open ports and services
- **Clean Output**: Beautiful table formatting with comprehensive information

## Usage Examples

### Basic Network Scan
```bash
rscout
```

### Advanced Options
```bash
# List available network interfaces
rscout --list

# Scan specific interface
rscout eth0

# Increase concurrency for faster scanning
rscout --jobs 128 192.168.1.0/24
```

## Output Example
```
🌐 Network Discovery Tool - Rust Implementation
================================================

🔍 Target network: 192.168.1.0/24
📍 Found 8 active devices

┌───────────────┬───────────────────┬─────────────────────┬────────────┬─────────────────────┐
│ IP            │ MAC               │ Hostname            │ Type       │ Vendor              │
├───────────────┼───────────────────┼─────────────────────┼────────────┼─────────────────────┤
│ 192.168.1.1   │ AA:BB:CC:DD:EE:FF │ router.local        │ Router     │ Cisco Systems       │
│ 192.168.1.15  │ 11:22:33:44:55:66 │ macbook-pro.local   │ Computer   │ Apple               │
│ 192.168.1.23  │ FF:EE:DD:CC:BB:AA │ android-phone.local │ Smartphone │ Samsung Electronics │
└───────────────┴───────────────────┴─────────────────────┴────────────┴─────────────────────┘
```

## Installation

### Prerequisites
- Rust 1.70+ and Cargo

### Platform Instructions

#### macOS/Linux
```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install RScout
cargo install rscout
```

#### Windows
Download Rust from https://rustup.rs/ then:
```bash
cargo install rscout
```

## Troubleshooting

### Permission Issues (Linux)
```bash
# Run with sudo
sudo rscout 192.168.1.0/24

# Or set capabilities for non-root usage
sudo setcap cap_net_raw+ep $(which rscout)
```

### Network Interface Issues
```bash
# List available interfaces
rscout --list

# Use specific interface
rscout eth0
```

### Debug Mode
```bash
# Enable debug logging
RUST_LOG=debug rscout 192.168.1.0/24
```

## Security Notice

⚠️ **Use responsibly**: Only scan networks you own or have permission to scan. Unauthorized scanning may violate laws or terms of service.

## Technical Documentation

For developers and contributors, see [TECHNICAL.md](TECHNICAL.md) for:
- Running test cases
- Project architecture
- Development setup
- API information

## License

MIT License - see LICENSE file for details.
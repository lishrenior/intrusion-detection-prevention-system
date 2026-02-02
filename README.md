# intrusion-detection-prevention-system
Network Intrusion Detection &amp; Prevention System
### Supported Features:
- **Protocols**: TCP, UDP, ICMP, IP
- **Flags**: A (ACK), S (SYN), F (FIN), R (RST), + (flag set regardless of others)
- **Content matching**: String-based payload filtering
- **Detection filters**: Count-based threshold detection with time windows

## Key Learning Outcomes

- Understanding of network packet filtering and firewall configuration
- Practical experience with Linux iptables
- Implementation of stateful and stateless packet inspection
- Custom IDS development using Python
- PCAP file analysis and packet parsing
- Pattern recognition for network attack detection

## Features Demonstrated

### Intrusion Prevention (iptables)
- IP-based access control
- Port-based filtering
- Rate limiting for DoS prevention
- Stateful connection tracking
- Default deny security policy

### Intrusion Detection (Python IDS)
- Multi-protocol packet analysis
- Content inspection
- TCP flag-based detection
- Flooding attack identification
- Port scan detection
- Time-window based attack correlation

## Requirements

- Linux-based operating system (or VM/Docker)
- Python 3.9
- Scapy library
- iptables (for firewall rules)
- Root/sudo access (for iptables application)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/intrusion-detection-prevention-system.git
cd intrusion-detection-prevention-system
```

2. Install Python dependencies:
```bash
pip install scapy
```

3. Ensure you have appropriate permissions for iptables (Linux only)

## Testing

The IDS was tested against various scenarios including:
- TCP/UDP/ICMP/IP packet detection
- Content-based malicious packet identification
- TCP flag analysis (SYN, FIN, RST, ACK)
- TCP flood detection
- SYN scan detection
- Time-sensitive attack patterns

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Developed for CYBR3000 - Information Security, The University of Queensland
- Assignment specification by UQ School of EECS
- Snort-inspired rule syntax

## Disclaimer

This project was created for educational purposes as part of a university assignment. The code is provided as-is for portfolio and learning purposes. Always ensure you have proper authorization before testing network security tools on any network.

---

**Note**: This project represents academic work completed in 2024. Feel free to reach out for questions or collaboration opportunities!

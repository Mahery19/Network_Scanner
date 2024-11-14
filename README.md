# Network Scanner

A Python-based network scanner that checks the availability of devices on a specified IP range, resolves their hostnames, and scans common ports for open connections.

## Features
- **Network Scanning**: Scans a specified network or subnet for active devices.
- **Hostname Resolution**: Resolves hostnames for active IP addresses using reverse DNS and DNS resolver.
- **Port Scanning**: Scans common ports (SSH, HTTP, HTTPS, etc.) to check if they are open.
- **Multithreaded**: Uses multithreading to speed up the scanning process.
- **Error Handling**: Handles invalid inputs and network errors gracefully.
- **Result Export**: Saves scan results to a file (`scan_results.txt`) in JSON format.

## Prerequisites
- Python 3.x
- Required Python libraries are listed in `requirements.txt`.

## Setup and Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/Mahery19/Network_Scanner.git
    cd network-scanner
    ```

2. Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Run the scanner:
    ```bash
    python network_scanner.py
    ```

2. Enter the network range when prompted (e.g., `192.168.1.0/24`).

3. Optionally, provide a comma-separated list of ports to scan (e.g., `22, 80, 443`), or press Enter to use the default ports.

4. View the list of active devices with their IPs, hostnames, and open ports.

## Example

```plaintext
Enter the network/subnet to scan (e.g., 192.168.1.0/24): 192.168.1.0/24
Enter ports to scan (comma-separated, or press Enter for default ports): 22, 80, 443
Scanning network: 192.168.1.0/24
Device found at IP: 192.168.1.10 (Hostname: example-device) - Open Ports: [22, 80]
Device found at IP: 192.168.1.20 (Hostname: Unknown Host) - Open Ports: [80, 443]

Scan Complete!
Active devices found:
192.168.1.10 - Hostname: example-device - Open Ports: [22, 80]
192.168.1.20 - Hostname: Unknown Host - Open Ports: [80, 443]

Results saved to scan_results.txt

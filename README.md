# Network Scanner

A Python-based network scanner that checks the availability of devices on a specified IP range. This tool pings each IP in a given subnet and displays the IPs of active devices.

## Features
- Scans a specified IP range or subnet for active devices.
- Displays IP addresses of devices that are online.
- Multithreaded scanning for faster results.

## Prerequisites
- Python 3.x installed on your system.

## Setup and Installation

1. Clone this repository:
    ```bash
    git clone <repository-url>
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

3. View the list of active devices as they are detected.

## Example

```plaintext
Enter the network/subnet to scan (e.g., 192.168.1.0/24): 192.168.1.0/24
Scanning network: 192.168.1.0/24
Device found at IP: 192.168.1.10
Device found at IP: 192.168.1.20

Scan Complete!
Active IPs found:
192.168.1.10
192.168.1.20

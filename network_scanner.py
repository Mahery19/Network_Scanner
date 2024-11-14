# import socket
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor


def ping_ip(ip):
    """
    Pings an IP address to check if it is active.
    """
    # Set the ping command based on the operating system
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", str(ip)]

    response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # If ping was successful, return True
    return response.returncode == 0


def scan_network(network):
    """
    Scans the specified network range.
    """
    # Convert the network to an IPv4 network object
    ip_network = ipaddress.ip_network(network, strict=False)

    # List to store active IPs
    active_ips = []

    print(f"Scanning network: {network}")

    # Multithreading for faster scanning
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Map ping_ip to each IP in the network and store active IPs
        results = {executor.submit(ping_ip, ip): ip for ip in ip_network.hosts()}

        for future in results:
            ip = results[future]
            if future.result():
                active_ips.append(ip)
                print(f"Device found at IP: {ip}")

    return active_ips


if __name__ == "__main__":
    # Get network input from the user
    network = input("Enter the network/subnet to scan (e.g., 192.168.1.0/24): ")

    # Scan the network
    active_devices = scan_network(network)

    # Display results
    print("\nScan Complete!")
    print("Active IPs found:")
    for ip in active_devices:
        print(ip)

import socket
import ipaddress
import subprocess
import platform
import dns.resolver  # To add DNS-based hostname resolution
from concurrent.futures import ThreadPoolExecutor, as_completed
import json


def ping_ip(ip):
    """
    Pings an IP address to check if it is active.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", str( ip )]

    try:
        response = subprocess.run( command, stdout=subprocess.PIPE, stderr=subprocess.PIPE )
        return response.returncode == 0
    except Exception as e:
        print( f"Error pinging IP {ip}: {e}" )
        return False


def resolve_hostname(ip):
    """
    Attempts to resolve the hostname of an IP address using both
    reverse DNS lookup and DNS resolver for improved results.
    """
    try:
        # Attempt to get hostname via reverse DNS
        hostname, _, _ = socket.gethostbyaddr( str( ip ) )
        return hostname
    except socket.herror:
        try:
            # Fallback to DNS resolution for hostname (requires DNS module)
            result = dns.resolver.resolve_address( str( ip ) )
            if result:
                return result[0].to_text()
        except Exception:
            return "Unknown Host"


def scan_ports(ip, ports=[22, 80, 443, 21, 23, 25, 110, 143, 3306, 8080]):
    """
    Scans a specified list of ports on an IP address to check if they're open.
    """
    open_ports = []
    for port in ports:
        with socket.socket( socket.AF_INET, socket.SOCK_STREAM ) as sock:
            sock.settimeout( 0.5 )  # Short timeout for faster scanning
            result = sock.connect_ex( (str( ip ), port) )
            if result == 0:  # Port is open
                open_ports.append( port )
    return open_ports


def scan_network(network, ports=None):
    """
    Scans the specified network range for active devices.
    """
    try:
        ip_network = ipaddress.ip_network( network, strict=False )
    except ValueError as e:
        print( f"Invalid network address: {e}" )
        return []

    active_devices = []
    print( f"Scanning network: {network}" )

    with ThreadPoolExecutor( max_workers=10 ) as executor:
        ping_results = {executor.submit( ping_ip, ip ): ip for ip in ip_network.hosts()}

        for future in as_completed( ping_results ):
            ip = ping_results[future]
            if future.result():  # If the ping was successful
                hostname = resolve_hostname( ip )
                open_ports = scan_ports( ip, ports if ports else [22, 80, 443, 21, 23, 25, 110, 143, 3306, 8080] )
                active_devices.append( {"IP": str( ip ), "Hostname": hostname, "Open Ports": open_ports} )
                print( f"Device found at IP: {ip} (Hostname: {hostname}) - Open Ports: {open_ports}" )

    return active_devices


def save_results(devices, filename="scan_results.txt"):
    """
    Saves the scan results to a file in a readable JSON format.
    """
    with open( filename, "w" ) as f:
        json.dump( devices, f, indent=4 )
    print( f"\nResults saved to {filename}" )


if __name__ == "__main__":
    try:
        network = input( "Enter the network/subnet to scan (e.g., 192.168.1.0/24): " )
        ports = input( "Enter ports to scan (comma-separated, or press Enter for default ports): " )

        # Parse the list of ports from user input or use default
        port_list = [int( port.strip() ) for port in ports.split( "," ) if port.strip().isdigit()] if ports else None

        # Scan the network
        active_devices = scan_network( network, port_list )

        # Display results
        print( "\nScan Complete!" )
        if active_devices:
            print( "Active devices found:" )
            for device in active_devices:
                print( f"{device['IP']} - Hostname: {device['Hostname']} - Open Ports: {device['Open Ports']}" )

            # Save results
            save_results( active_devices )
        else:
            print( "No active devices found." )

    except KeyboardInterrupt:
        print( "\nScan aborted by user." )
    except Exception as e:
        print( f"An unexpected error occurred: {e}" )

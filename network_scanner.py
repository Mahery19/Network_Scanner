import socket
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed


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
    Attempts to resolve the hostname of an IP address.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr( str( ip ) )
        return hostname
    except socket.herror:
        return "Unknown Host"


def scan_ports(ip, ports=[22, 80, 443]):
    """
    Scans common ports on an IP address to check if they're open.
    Default ports are SSH (22), HTTP (80), and HTTPS (443).
    """
    open_ports = []
    for port in ports:
        with socket.socket( socket.AF_INET, socket.SOCK_STREAM ) as sock:
            sock.settimeout( 0.5 )  # Set a short timeout for faster scanning
            result = sock.connect_ex( (str( ip ), port) )
            if result == 0:  # Port is open
                open_ports.append( port )
    return open_ports


def scan_network(network):
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
        # Start pinging IPs in the network
        ping_results = {executor.submit( ping_ip, ip ): ip for ip in ip_network.hosts()}

        for future in as_completed( ping_results ):
            ip = ping_results[future]
            if future.result():  # If the ping was successful
                hostname = resolve_hostname( ip )
                open_ports = scan_ports( ip )
                active_devices.append( (ip, hostname, open_ports) )
                print( f"Device found at IP: {ip} (Hostname: {hostname}) - Open Ports: {open_ports}" )

    return active_devices


if __name__ == "__main__":
    try:
        # Get network input from the user
        network = input( "Enter the network/subnet to scan (e.g., 192.168.1.0/24): " )

        # Scan the network
        active_devices = scan_network( network )

        # Display results
        print( "\nScan Complete!" )
        if active_devices:
            print( "Active devices found:" )
            for ip, hostname, ports in active_devices:
                print( f"{ip} - Hostname: {hostname} - Open Ports: {ports}" )
        else:
            print( "No active devices found." )

    except KeyboardInterrupt:
        print( "\nScan aborted by user." )
    except Exception as e:
        print( f"An unexpected error occurred: {e}" )

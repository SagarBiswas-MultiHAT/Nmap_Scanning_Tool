#!/usr/bin/python3
import pyfiglet
from termcolor import colored
import subprocess
import os
import sys

# Display a banner using pyfiglet and termcolor
banner = colored(pyfiglet.figlet_format("Nmap Scanning Tool"), "green")
print(banner)
print(colored("\n******************** Welcome to the Nmap Scanning Tool ********************", "cyan"))
print(colored("************************** Created By Sagar Biswas ************************\n", "red"))

def check_root():
    """Check if the script is run as root."""
    if os.geteuid() != 0:
        print("This script must be run as root. Please use 'sudo' to run it.")
        sys.exit(1)

def run_scan(command):
    """Run the Nmap scan and print output."""
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        output = result.stdout
        
        if "open" in output:
            open_ports = [line for line in output.splitlines() if "open" in line]
            print("\n".join(open_ports))
        else:
            print(output)
    except Exception as e:
        print(f"An error occurred: {e}")

def get_target_info():
    """Get target IP and port info."""
    ip_address = input("\nEnter the IP address to scan: ").strip()

    # Get port or range
    port = input("Enter the port (1-65535) or range (e.g., 1-1000) [Leave blank for all ports]: ").strip()
    if not port:
        port = "1-65535"
    
    return ip_address, port

def choose_scan_type():
    """Let the user select a scan type."""
    print("\nSelect the scan type:")
    print("1. SYN Scan (Stealth Scan)")
    print("2. Aggressive Scan (OS detection + Services)")
    print("3. Service Version Detection Scan")
    print("4. Vulnerability Scanning")
    print("5. Heartbleed Test (SSL/TLS Vulnerability)")
    print("6. HTTP Security Headers Scan")
    print("7. SQL Injection Test")
    print("8. SMB Vulnerability Scan")
    print("9. SSL/TLS Cipher Suite Scan")
    print("10. Service Discovery with Nmap Scripting Engine")
    print("11. OS Detection")
    print("12. Custom Scan (Specify Nmap arguments)")

    scan_type = input("\nEnter your choice (1-12): ").strip()
    if scan_type not in [str(i) for i in range(1, 13)]:
        print("Invalid choice. Exiting.")
        sys.exit(1)

    return scan_type

def construct_nmap_command(scan_type, ip_address, port):
    """Create the Nmap command based on selected scan type."""
    if scan_type == '1':
        return ["nmap", ip_address, "-p", port, "-sS", "-O"]
    elif scan_type == '2':
        return ["nmap", ip_address, "-p", port, "-A"]
    elif scan_type == '3':
        return ["nmap", ip_address, "-p", port, "-sV"]
    elif scan_type == '4':
        return ["nmap", ip_address, "-p", port, "--script=vuln"]
    elif scan_type == '5':
        return ["nmap", ip_address, "-p", port, "--script=ssl-heartbleed"]
    elif scan_type == '6':
        return ["nmap", ip_address, "-p", port, "--script=http-security-headers"]
    elif scan_type == '7':
        return ["nmap", ip_address, "-p", port, "--script=http-sql-injection"]
    elif scan_type == '8':
        return ["nmap", ip_address, "-p", port, "--script=smb-vuln*"]
    elif scan_type == '9':
        return ["nmap", ip_address, "-p", port, "--script=ssl-enum-ciphers"]
    elif scan_type == '10':
        return ["nmap", ip_address, "-p", port, "--script=default"]
    elif scan_type == '11':
        return ["nmap", ip_address, "-p", port, "-O"]
    elif scan_type == '12':
        custom_args = input("Enter the custom Nmap arguments: ").strip()
        return ["nmap", ip_address, custom_args]

def main():
    check_root()
    ip_address, port = get_target_info()
    scan_type = choose_scan_type()
    
    # Create Nmap command based on the scan type
    command = construct_nmap_command(scan_type, ip_address, port)
    
    # Ask if the user wants to filter open ports
    filter_open_ports = input("\nDo you want to see open ports only? (y/N): ").strip().lower()
    if filter_open_ports != 'y':
        filter_open_ports = 'n'

    # Run the scan
    if filter_open_ports == 'y':
        print("Running scan with open port filtering...")
        run_scan(command)
    else:
        print("Running scan without filtering...")
        subprocess.run(command)

if __name__ == "__main__":
    main()

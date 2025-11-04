#!/usr/bin/python3
import subprocess
import os
import sys

from nmap_utils import display_banner, get_target_info, choose_scan_type

# Display the banner
display_banner()

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

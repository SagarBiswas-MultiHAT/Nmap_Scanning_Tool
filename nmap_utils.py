#!/usr/bin/python3
"""
Shared utility functions for Nmap Scanning Tool.
This module contains common functions used across different versions of the tool.
"""
import sys
import pyfiglet
from termcolor import colored


def display_banner():
    """Display the application banner and welcome message."""
    banner = colored(pyfiglet.figlet_format("Nmap Scanning Tool"), "green")
    print(banner)
    print(colored("\n******************** Welcome to the Nmap Scanning Tool ********************", "cyan"))
    print(colored("************************** Created By Sagar Biswas ************************\n", "red"))


def get_target_info():
    """
    Get target IP and port information from user input.
    
    Returns:
        tuple: (ip_address, port) where ip_address is a string and port is a string
               representing either a single port, a range, or "1-65535" for all ports.
    """
    ip_address = input("\nEnter the IP address to scan: ").strip()

    # Get port or range
    port = input("Enter the port (1-65535) or range (e.g., 1-1000) [Leave blank for all ports]: ").strip()
    if not port:
        port = "1-65535"
    
    return ip_address, port


def choose_scan_type():
    """
    Let the user select a scan type from available options.
    
    Returns:
        str: The scan type choice as a string ("1" through "12").
    """
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


def get_base_nmap_command(scan_type, ip_address, port):
    """
    Create the base Nmap command based on selected scan type.
    This function returns the common command structure that can be
    further customized by specific implementations.
    
    Args:
        scan_type (str): The scan type choice ("1" through "12")
        ip_address (str): The target IP address
        port (str): The port specification
        
    Returns:
        list: List of command arguments for subprocess
    """
    base_command = ["nmap", ip_address, "-p", port]
    
    scan_options = {
        "1": ["-sS", "-O"],
        "2": ["-A"],
        "3": ["-sV"],
        "4": ["--script=vuln"],
        "5": ["--script=ssl-heartbleed"],
        "6": ["--script=http-security-headers"],
        "7": ["--script=http-sql-injection"],
        "8": ["--script=smb-vuln*"],
        "9": ["--script=ssl-enum-ciphers"],
        "10": ["--script=default"],
        "11": ["-O"],
    }
    
    if scan_type in scan_options:
        return base_command + scan_options[scan_type]
    elif scan_type == "12":
        # Custom scan - let the calling function handle this
        return base_command
    
    return base_command

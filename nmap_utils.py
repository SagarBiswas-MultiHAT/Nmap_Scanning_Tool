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


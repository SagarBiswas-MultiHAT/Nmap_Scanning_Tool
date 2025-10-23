#!/usr/bin/python3
import subprocess
import os
import sys
import shlex
import shutil

import pyfiglet
from termcolor import colored

# Display a banner using pyfiglet and termcolor
banner = colored(pyfiglet.figlet_format("Nmap Scanning Tool"), "green")
print(banner)
print(colored("\n******************** Welcome to the Nmap Scanning Tool ********************", "cyan"))
print(colored("************************** Created By Sagar Biswas ************************\n", "red"))

def check_root():
    """Check if the script is run with elevated privileges when required."""
    if os.name == "nt":
        try:
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                print(
                    colored(
                        "Warning: This script is not running with Administrator privileges. "
                        "Some scan types may require elevation.",
                        "yellow",
                    )
                )
        except Exception:
            print(
                colored(
                    "Warning: Unable to determine Windows privilege level. "
                    "If scans fail, try rerunning as Administrator.",
                    "yellow",
                )
            )
        return

    try:
        if os.geteuid() != 0:
            print("This script must be run as root. Please use 'sudo' to run it.")
            sys.exit(1)
    except AttributeError:
        # os.geteuid is unavailable on some platforms (e.g., Windows Subsystem without root)
        print(
            colored(
                "Warning: Cannot verify root privileges on this platform. "
                "Ensure you have the required permissions for the selected scan.",
                "yellow",
            )
        )


def ensure_nmap_available():
    """Ensure that the Nmap executable is available on the system."""
    nmap_path = shutil.which("nmap")
    if nmap_path is None:
        print(
            colored(
                "Nmap executable was not found. Please install Nmap and ensure it is in your PATH.",
                "red",
            )
        )
        if os.name == "nt":
            print(
                "Download Nmap from https://nmap.org/download.html and restart the terminal after installation."
            )
        else:
            print(
                "On Debian/Ubuntu, run: sudo apt install nmap\n"
                "On RHEL/CentOS, run: sudo yum install nmap"
            )
        sys.exit(1)

def run_scan(command, show_only_open_ports=False):
    """Run the Nmap scan and handle output consistently."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        print(
            colored(
                "Failed to invoke Nmap. Verify that the executable is installed and accessible.",
                "red",
            )
        )
        return False
    except Exception as exc:  # Broad catch to avoid unhandled subprocess errors
        print(colored(f"An unexpected error occurred while launching Nmap: {exc}", "red"))
        return False

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode != 0:
        print(colored("Nmap exited with an error.", "red"))
        if stderr:
            print(stderr)
        else:
            print("No additional error information was provided by Nmap.")
        return False

    if show_only_open_ports and stdout:
        open_ports = [line for line in stdout.splitlines() if "open" in line]
        if open_ports:
            print("\n".join(open_ports))
        else:
            print("No open ports reported by Nmap for the selected target and scan.")
    else:
        print(stdout or "Nmap did not return any output.")

    if stderr:
        print(colored("Nmap reported the following warnings:", "yellow"))
        print(stderr)

    return True

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
    base_command = ["nmap", ip_address]
    if port:
        base_command.extend(["-p", port])

    if scan_type == "1":
        return base_command + ["-sS", "-O"]
    elif scan_type == "2":
        return base_command + ["-A"]
    elif scan_type == "3":
        return base_command + ["-sV"]
    elif scan_type == "4":
        return base_command + ["--script=vuln"]
    elif scan_type == "5":
        return base_command + ["--script=ssl-heartbleed"]
    elif scan_type == "6":
        return base_command + ["--script=http-security-headers"]
    elif scan_type == "7":
        return base_command + ["--script=http-sql-injection"]
    elif scan_type == "8":
        return base_command + ["--script=smb-vuln*"]
    elif scan_type == "9":
        return base_command + ["--script=ssl-enum-ciphers"]
    elif scan_type == "10":
        return base_command + ["--script=default"]
    elif scan_type == "11":
        return base_command + ["-O"]
    elif scan_type == "12":
        custom_args = input("Enter the custom Nmap arguments: ").strip()
        additional_args = shlex.split(custom_args)

        # Avoid duplicating port arguments if the user already provided custom ones
        if any(arg in ("-p", "--ports") for arg in additional_args):
            base_command = ["nmap", ip_address]

        return base_command + additional_args

def main():
    check_root()
    ensure_nmap_available()
    ip_address, port = get_target_info()
    scan_type = choose_scan_type()
    
    # Create Nmap command based on the scan type
    command = construct_nmap_command(scan_type, ip_address, port)
    
    # Ask if the user wants to filter open ports
    filter_open_ports = input("\nDo you want to see open ports only? (y/N): ").strip().lower() == "y"

    print(
        "Running scan with open port filtering..."
        if filter_open_ports
        else
        "Running scan without filtering..."
    )

    success = run_scan(command, show_only_open_ports=filter_open_ports)
    if not success:
        print(
            colored(
                "Unable to complete the scan. Review the guidance above and try again.",
                "red",
            )
        )

if __name__ == "__main__":
    main()


---

# Nmap Scanning Tool

![Nmap Scanning Tool](https://imgur.com/eDmMlxm.png)

Welcome to the **Nmap Scanning Tool**, a Python-based utility designed to make network scanning easier and more efficient. This tool leverages the power of **Nmap** for various types of scans, including SYN scans, aggressive scans, service detection, vulnerability scanning, and more.

## Overview

This tool allows you to scan IP addresses for open ports, detect services, identify vulnerabilities, and much more with just a few simple steps. Whether you're a network administrator or a cybersecurity enthusiast, this tool simplifies running Nmap scans through a user-friendly interface.

## Features

- **SYN Scan (Stealth Scan)**
- **Aggressive Scan** (OS detection + services)
- **Service Version Detection**
- **Vulnerability Scanning**
- **Heartbleed Test (SSL/TLS Vulnerability)**
- **HTTP Security Headers Scan**
- **SQL Injection Test**
- **SMB Vulnerability Scan**
- **SSL/TLS Cipher Suite Scan**
- **Service Discovery using Nmap Scripting Engine**
- **OS Detection**
- **Custom Scan** (Allows for custom Nmap arguments)

## Requirements

- Python 3.x
- Nmap installed on your system
- `pyfiglet` and `termcolor` libraries for enhanced output styling

You can install the required Python libraries by running the following:

```bash
pip install pyfiglet termcolor
```

Make sure **Nmap** is installed on your machine. You can download it from [Nmap's official site](https://nmap.org/).

## Usage

### Running the Script

To run the Nmap scanning tool, use the following command:

```bash
python3 main_v1.5.py
```

The tool will guide you through the following steps:

1. **Check Root Privileges**: The script must be run as root to perform network scans.
2. **Target Information**: Enter the IP address and ports (or range of ports) to scan.
3. **Select Scan Type**: Choose from a variety of predefined scan types or specify custom Nmap arguments.
4. **Scan Execution**: Run the scan and display results, with an option to filter and show only open ports.

### Example Output

Upon running the script, the output will look something like this:

```
Nmap Scanning Tool
******************** Welcome to the Nmap Scanning Tool ********************
************************** Created By Sagar Biswas ************************

Enter the IP address to scan: 192.168.1.1
Enter the port (1-65535) or range (e.g., 1-1000) [Leave blank for all ports]: 1-1000

Select the scan type:
1. SYN Scan (Stealth Scan)
2. Aggressive Scan (OS detection + Services)
3. Service Version Detection Scan
...

Enter your choice (1-12): 1

Do you want to see open ports only? (y/N): y

Running scan with open port filtering...
80/tcp open  http
443/tcp open  https
...
```

## Contributing

Feel free to contribute! If you'd like to add new features, improve existing functionality, or fix bugs, please open an issue or submit a pull request.

---

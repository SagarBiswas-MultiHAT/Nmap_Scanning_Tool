import subprocess

ip_address = input("IP address: ")
port = input("Port: ") # Enter 1-65535 for all ports

scan = int(input("Enter 1 for Syn scan, 2 for Tcp scan: "))
print("\n")

if scan == 1:
    subprocess.run(["nmap", ip_address, "-p", port, "-sS", "-sV", "-O"]) # -sS is for Syn scan, -sV is for version scan, -O is for OS detection
elif scan == 2:
    subprocess.run(["nmap", ip_address, "-p", port, "-sT", "-sV", "-O"]) # -sT is for Tcp scan. It is slower than Syn scan
else:
    print("Invalid input")


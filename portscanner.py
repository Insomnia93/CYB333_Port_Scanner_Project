import nmap

scanner = nmap.PortScanner()

print("CYB333 Port Scanner Project")
print("<-------------------------------------------------------->\n")

ip_addr = input("Enter the IP address that you would like to scan: ")
type(ip_addr)

resp = input("""\nPlease enter which type of scan you would like to run on this IP
1: SYN Scan
2: Comprehensive Scan
3: Xmas Scan
4: Bypass Firewall Scan 
You chose scan #:""")

if resp == '1':
    print("Nmap Version:", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -T4')
    print(scanner.scaninfo())
    print("IP Status:", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    print("Nmap Version:", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sC -A -O -T4')
    print(scanner.scaninfo())
    print("IP Status:", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())
elif resp == '3':
    print("Nmap Version:", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sX -T4')
    print(scanner.scaninfo())
    print("IP Status:", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())
elif resp == '4':
    print("Nmap Version:", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -PO -T4')
    print(scanner.scaninfo())
    print("IP Status:", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())
elif resp >= '5':
    print("Please enter an option from the provided list.")
    exit()


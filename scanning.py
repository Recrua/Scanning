# This Python script performs a network scan using the Nmap — Network Mapper tool
# Ensure that the nmap Python library is installed — pip install python-nmap

# Linux & macOS:
# — Yes, this script is cross-platform

# Disclaimer: This script IS NOT a malware detector, it is a network scanner (Can be used as part of a malware detection system in certain contexts)

import nmap

def scan(target):
    nm = nmap.PortScanner() # Storing results — nmap.PortScanner object
    nm.scan(hosts=target, arguments='-Pn -sV -p 1-65535') # Targeted parameter — Pn (no host), -sV (service version), & -p 1-65535 (ports)

    # Results
    for host in nm.all_hosts():
        print('----------------------------------------------------') # Separator between different sections
        print(f'Host : {host} ({nm[host].hostname()})')
        print('State :', nm[host].state())
        
        # Ports (TCP, UDP)
        for proto in nm[host].all_protocols():
            print('----------')
            print(f'Protocol : {proto}')

            ports = nm[host][proto].keys()
            for port in ports:
                print (f'Port : {port} \t State : {nm[host][proto][port]["state"]} \t Service : {nm[host][proto][port]["name"]}')
    
    # Main function
if __name__ == "__main__":
    target = input("Enter target IP address or range: ") # User's target IP address/range
    scan(target)

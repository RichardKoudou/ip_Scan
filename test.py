import nmap
# from scapy.all import ARP, Ether, srp

ip_range = '51.195.91.8'

# Nmap port scanning
scanner = nmap.PortScanner()
scanner.scan(ip_range, arguments='-sT')

# Scapy ARP scanning -sS -sU
# arp_result = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=2, verbose=False)[0]

# Extract MAC addresses from ARP results
# mac_addresses = {arp_result[i][1].psrc: arp_result[i][1].hwsrc for i in range(len(arp_result))}

# Display information
for host in scanner.all_hosts():
    if 'tcp' in scanner[host] or 'udp' in scanner[host]:
        print(f"Host: {host} ({scanner[host].hostname()})")

        # ARP information
        # if host in mac_addresses:
        #     print(f"MAC Address: {mac_addresses[host]}")

        # TCP ports
        if 'tcp' in scanner[host]:
            print("\nTCP Ports:")
            for port in scanner[host]['tcp']:
                print(f"Port {port}: {scanner[host]['tcp'][port]['name']} - {scanner[host]['tcp'][port]['state']}")

        # UDP ports
        if 'udp' in scanner[host]:
            print("\nUDP Ports:")
            for port in scanner[host]['udp']:
                print(f"Port {port}: {scanner[host]['udp'][port]['name']} - {scanner[host]['udp'][port]['state']}")
            
            print("\n")
            
    else: print("c'est relou")
        
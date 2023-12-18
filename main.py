import nmap
from scapy.all import ARP, Ether, srp
from flask import Flask, render_template, request
from rich.pretty import pprint
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/', methods=["POST"])
def scan():
    if request.method == 'POST':
        
        #Result return
        res_string = ""
        
        ip_address = request.form['ip']
        option = request.form['options']
        
        
        if option == "mac":
            arp = ARP(pdst=ip_address)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=3, verbose=0)[0]
            if result:
                res_string += "<h3>Ip : "+ip_address+" Mac : "+result[0][1].hwsrc+"</h3>"
            else:
                res_string += "adresse mac non trouvés"
            
        if option != "mac":
            # Nmap port scanning
            scanner = nmap.PortScanner()
            scanner.scan(ip_address, arguments=option) #-sS -sU
        
            # Display information
            for host in scanner.all_hosts():
                if 'tcp' in scanner[host] or 'udp' in scanner[host]:
                    res_string += f"<h3>Host: {host} ({scanner[host].hostname()})</h3><br>"

                    # TCP ports
                    if 'tcp' in scanner[host]:
                        res_string += "\nTCP Ports:<br>"
                        for port in scanner[host]['tcp']:
                            res_string += f"Port {port}: {scanner[host]['tcp'][port]['name']} - {scanner[host]['tcp'][port]['state']}<br>"

                    # UDP ports
                    if 'udp' in scanner[host]:
                        res_string += "\nUDP Ports:<br>"
                        for port in scanner[host]['udp']:
                            res_string += f"Port {port}: {scanner[host]['udp'][port]['name']} - {scanner[host]['udp'][port]['state']}<br>"
            
    return render_template("index.html") +"<br><br><br><br>"+res_string

def scan_websites(ip_address):
    try:
        # Use requests.get to get information about the IP
        response = requests.get(f"http://{ip_address}")

        if response.status_code == 200:
            return [(ip_address, response.url)]
        else:
            return []
    except requests.RequestException:
        return []
    
    
    
if __name__ == '__main__':
    app.run(debug=True)
    
    
# ip_range = '10.60.104.101'

# # Nmap port scanning
# scanner = nmap.PortScanner()
# scanner.scan(ip_range, arguments='-sS -sU')

# # Scapy ARP scanning
# arp_result = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=2, verbose=False)[0]

# # Extract MAC addresses from ARP results
# mac_addresses = {arp_result[i][1].psrc: arp_result[i][1].hwsrc for i in range(len(arp_result))}

# # Display information
# for host in scanner.all_hosts():
#     if 'tcp' in scanner[host] or 'udp' in scanner[host]:
#         print(f"Host: {host} ({scanner[host].hostname()})")

#         # ARP information
#         if host in mac_addresses:
#             print(f"MAC Address: {mac_addresses[host]}")

#         # TCP ports
#         if 'tcp' in scanner[host]:
#             print("\nTCP Ports:")
#             for port in scanner[host]['tcp']:
#                 print(f"Port {port}: {scanner[host]['tcp'][port]['name']} - {scanner[host]['tcp'][port]['state']}")

#         # UDP ports
#         if 'udp' in scanner[host]:
#             print("\nUDP Ports:")
#             for port in scanner[host]['udp']:
#                 print(f"Port {port}: {scanner[host]['udp'][port]['name']} - {scanner[host]['udp'][port]['state']}")

#         print("\n")

    
# nm = nmap.PortScanner()

# ip_address = input("Veuillez renseigner l'ip que vous souhaitez scanner")
# print("l'adresse ip que vous avez renseignée est ", ip_address)
# type(ip_address)

# resp = input("""\nEntrez le type de scan que vous souhaitez réaliser 
#              1) SYN ACK run
#              2) UDP Scan
#              """)
# print("Vous avez selectionnez l'option", resp)

# if resp == "1":
#     print("Nmap version: ", nm.nmap_version())
#     nm.scan(ip_address, '1 - 1024', '-v', 'sS')
#     print(nm.scaninfo())
#     print("ip_status: ", nm[ip_address].state())
#     print(nm[ip_address].all_protocols())
#     print("Open ports: ", nm[ip_address]['tcp'].keys())

    
    
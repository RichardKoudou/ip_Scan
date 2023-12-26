import nmap
from scapy.all import ARP, Ether, srp, sniff
from flask import Flask, render_template, request


app = Flask(__name__)

capture_packets = []

def packet_callback(packet):
   capture_packets.append(packet.summary())
   

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/', methods=["POST"])
def scan():
    if request.method == 'POST':
        
        res_string = []
        
        ip_address = request.form['ip']
        option = request.form['options']
        
        
        if option == "mac":
            arp = ARP(pdst=ip_address)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=3, verbose=0)[0]
            if result:
                res_string.append("<h3>Ip : "+ip_address+" Mac : "+result[0][1].hwsrc+"</h3>")
            else:
                res_string.append("adresse mac non trouvés")
                
        if option == "sniff":
            sniff(prn=packet_callback, filter="ip", count=30)
            for packet in capture_packets:
                res_string.append(packet+"<br>")

            
        if option == "-sS -sU" or option == "-F":
            scanner = nmap.PortScanner()
            scanner.scan(ip_address, arguments=option)
        
            for host in scanner.all_hosts():
                if 'tcp' in scanner[host] or 'udp' in scanner[host]:
                    res_string.append(f"<br><br><h2 style='color: red'>Host: {host}</h2><br>")

                    if 'tcp' in scanner[host]:
                        res_string.append("\n<p style='color: #75e34b'>TCP Ports:</p>")
                        for port in scanner[host]['tcp']:
                            res_string.append(f"<p style='color: #75e34b'>Port {port}: {scanner[host]['tcp'][port]['name']} - {scanner[host]['tcp'][port]['state']}</p>")

                    if 'udp' in scanner[host]:
                        res_string.append("\n<br><p style='color: #4bdee3'>UDP Ports:</p>")
                        for port in scanner[host]['udp']:
                            res_string.append(f"<p style='color: #4bdee3'>Port {port}: {scanner[host]['udp'][port]['name']} - {scanner[host]['udp'][port]['state']}</p>")

    return render_template("index.html", res_string=res_string)

if __name__ == '__main__':
    app.run(debug=True)

 
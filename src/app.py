import nmap
from pathlib import Path
import csv
from scapy.all import ARP, Ether, srp, sniff, IP
from flask import Flask, render_template, request, send_file


log_path = Path(__file__).resolve().parent / "log.csv"

app = Flask(__name__)
                       
capture_packets = []
res_string = []

def packet_callback(packet, ip_address):
   if IP in packet and (packet[IP].src == ip_address or packet[IP].dst == ip_address):
        if 'DNSRR' in packet:
            dns_answers = [str(ans.rdata) for ans in packet['DNSRR']]
            if dns_answers:
                capture_packets.append(packet.summary() + "<br>".join(dns_answers))
        else:
            capture_packets.append(packet.summary())
        
   

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/', methods=["POST"])
def scan():
    global res_string
    if request.method == 'POST':
        
        ip_address = request.form['ip']
        option = request.form['options']
        
        
        if option == "mac":
            res_string = []
            arp = ARP(pdst=ip_address)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=3, verbose=0)[0]
            if result:
                res_string.append("<h3>Ip : "+ip_address+" Mac : "+result[0][1].hwsrc+"</h3>")
            else:
                res_string.append("adresse mac non trouvés")
                
        if option == "sniff":
            res_string = []
            sniff(prn=lambda packet: packet_callback(packet, ip_address), filter="ip", count=30)
            for packet in capture_packets:
                res_string.append(packet+"<br>")

            
        if option == "-sS -sU" or option == "-F":
            res_string = []
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

@app.route('/save', methods=['POST'])
def save_result():
    global res_string
    if not log_path.is_file():
        with open(log_path, "w", newline="", encoding="utf-8") as file:
            csv_writer = csv.writer(file)
            
    with open(log_path, "a", newline="", encoding="utf-8") as file:
        csv_writer = csv.writer(file)
        
        for row in res_string:
            csv_writer.writerow([row])
    
    res_string.append("<br><h1 style='color: #4bdee3'>Result saved</h1>")
        
    return render_template("index.html", res_string=res_string)

@app.route('/clean', methods=['POST'])
def clean_result():
    global res_string

    with open(log_path, "w", newline="", encoding="utf-8"):
        res_string.clear()
    
    return render_template("index.html", res_string=res_string)


@app.route('/saved', methods=['POST'])
def view_csv():
    with open(log_path, "r", encoding="utf-8") as file:
        csv_data = [line.strip() for line in file]

    return render_template("index.html", res_string=csv_data)

@app.route('/download')
def download_file():
    filename = 'result_ipscan.txt'
    return send_file(log_path, as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(debug=True)

 
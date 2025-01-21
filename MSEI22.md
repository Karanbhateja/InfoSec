# 1. Calculate the MD5 hash value and perform steganography

## a) MD5 Calculation
Use the following commands in Linux/Windows:
```bash
# Calculate MD5 of a file
md5sum filename

# Recalculate MD5 after copying
cp filename /path/to/network/location/
md5sum /path/to/network/location/filename
```
* Compare the two MD5 hashes. If they match, the file hasn't changed.

## b) Steganography
**Tool**: Use `steghide` (Linux).

Hide a file in an image:
```bash
steghide embed -cf cover_image.jpg -ef file_to_hide.txt -sf output_image.jpg
```

Reveal the hidden file:
```bash
steghide extract -sf output_image.jpg
```

# 2. Generate digital signature using MAC Code
Use Python's `hmac` library:
```python
import hmac
import hashlib

key = b'secret_key'
message = b'Important data'
mac = hmac.new(key, message, hashlib.sha256).hexdigest()
print("Generated MAC:", mac)
```

# 3. Post Scanning and Port Management

## a) Post-Scanning
Use `nmap`:
```bash
nmap -sT valid_ip_address
```

## b) Open a New Port
Start a service, e.g., HTTP:
```bash
sudo python3 -m http.server 8080
```

## c) Scan Again
Scan for the newly opened port:
```bash
nmap -sT valid_ip_address
```

# 4. Implement IDS and Block ICMP Protocol

## a) Intrusion Detection System (IDS)
Use Snort as an IDS:
```bash
sudo apt install snort
sudo snort -i eth0 -c /etc/snort/snort.conf -l /var/log/snort/
```

Simulate port scanning attacks using `nmap`:
```bash
nmap -sS target_ip_address
```

View Snort logs:
```bash
cat /var/log/snort/alert
```

## b) Block ICMP Protocol
Use iptables in Linux:
```bash
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
```

# 5. Scan the Network and Find Vulnerabilities

## a) Network Scanning
Use `nmap`:
```bash
nmap -sn 192.168.1.0/24
```

## b) Vulnerability Scanning
* Use tools like `OpenVAS` or `Nessus`.

# 6. String Encryption and Decryption Program

## Python Implementation
```python
def encrypt(string, x):
    return ''.join(chr(ord(ch) + x) for ch in string)

def decrypt(string, x):
    return ''.join(chr(ord(ch) - x) for ch in string)

# Input from user
s = input("Enter the string: ")
x = int(input("Enter the integer: "))

encrypted = encrypt(s, x)
print("Encrypted String:", encrypted)

decrypted = decrypt(encrypted, x)
print("Decrypted String:", decrypted)
```

## Java Implementation
```java
import java.util.Scanner;

public class EncryptDecrypt {
    public static String encrypt(String str, int x) {
        StringBuilder encrypted = new StringBuilder();
        for (char ch : str.toCharArray()) {
            encrypted.append((char) (ch + x));
        }
        return encrypted.toString();
    }

    public static String decrypt(String str, int x) {
        StringBuilder decrypted = new StringBuilder();
        for (char ch : str.toCharArray()) {
            decrypted.append((char) (ch - x));
        }
        return decrypted.toString();
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the string: ");
        String s = scanner.nextLine();
        System.out.print("Enter the integer: ");
        int x = scanner.nextInt();

        String encrypted = encrypt(s, x);
        System.out.println("Encrypted String: " + encrypted);
        String decrypted = decrypt(encrypted, x);
        System.out.println("Decrypted String: " + decrypted);
    }
}
```

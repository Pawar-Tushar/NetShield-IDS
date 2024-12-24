import re
import time
from collections import defaultdict
from urllib.parse import unquote
from scapy.all import Raw, IP, TCP, ARP
from src.config import load_signature_rules
from src.logging_new import attack_logger
from urllib.parse import unquote
from collections import defaultdict
/**
 *
 * @author Tushar
 */
rules = load_signature_rules("config/signature_rules.json")

sql_injection_patterns = rules["sql_injection_patterns"]
login_patterns = rules["login_patterns"]
xss_patterns = rules["xss_patterns"]
malware_patterns = rules["malware_patterns"]
FAILED_LOGIN_THRESHOLD = rules["failed_login_threshold"]
BLOCK_TIME = rules["block_time"]
TIME_WINDOW = rules["dos_time_window"]
dos_attack_threshold = rules["dos_attack_threshold"]
port_scan_threshold = rules["port_scan_threshold"]
arp_spoofing_threshold = rules["arp_spoofing_detection"]["threshold"]
arp_time_window = rules["arp_spoofing_detection"]["time_window"]

ip_to_ports = defaultdict(set)
last_time = defaultdict(lambda: time.time())
ip_packet_count = defaultdict(int)
failed_login_attempts = defaultdict(int)
blocked_ips = {}
ip_to_macs = defaultdict(set)
arp_last_time = defaultdict(lambda: time.time())


# Functions for attack detection

def detect_sql_injection(packet):
    try:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')

            if "GET" in payload or "POST" in payload:
                decoded_payload = unquote(payload)

                for pattern in sql_injection_patterns:
                    if re.search(pattern, decoded_payload, re.IGNORECASE):
                        attack_logger.warning(f"ALERT: SQL Injection Detected in request:\n{decoded_payload}")
                        print(f"ALERT: SQL Injection Detected in request:\n{decoded_payload}\n")
                        return  

    except Exception as e:
        attack_logger.error(f"Error processing packet: {e}")
        print(f"Error processing packet: {e}")

def detect_port_scan(packet):
    try:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_src = packet[IP].src
            tcp_dst_port = packet[TCP].dport
            ip_to_ports[ip_src].add(tcp_dst_port)
            if len(ip_to_ports[ip_src]) > port_scan_threshold:  
                attack_logger.warning(f"ALERT: Potential port scan detected from IP: {ip_src}")
                print(f"ALERT: Potential port scan detected from IP: {ip_src}")
                return
    except Exception as e:
        attack_logger.error(f"Error processing packet: {e}")
        print(f"Error processing packet: {e}")

def detect_unauthorized_access(packet):
    try:
        if packet.haslayer(IP) and packet.haslayer(Raw):
            ip_src = packet[IP].src    
            # print(ip_src)
            payload = packet[Raw].load.decode(errors='ignore')
            if ip_src in blocked_ips:
                if time.time() - blocked_ips[ip_src] > BLOCK_TIME:
                    del blocked_ips[ip_src] 
                    attack_logger.warning(f"IP {ip_src} is now unblocked after {BLOCK_TIME} seconds.")
                    print(f"IP {ip_src} is now unblocked after {BLOCK_TIME} seconds.\n")
                else:
                    return  
                
            for service, patterns in login_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, payload, re.IGNORECASE):
                        failed_login_attempts[ip_src] += 1
                        if failed_login_attempts[ip_src] >= FAILED_LOGIN_THRESHOLD:
                            blocked_ips[ip_src] = time.time() 
                            attack_logger.warning(f"ALERT: Unauthorized access attempt detected from IP: {ip_src}. IP blocked temporarily.")
                            print(f"ALERT: Unauthorized access attempt detected from IP: {ip_src}. IP blocked temporarily.\n")
                            return
                        else:
                            attack_logger.warning(f"Failed login attempt from IP: {ip_src} (Attempt {failed_login_attempts[ip_src]})")
                            print(f"Failed login attempt from IP: {ip_src} (Attempt {failed_login_attempts[ip_src]})\n")
                        return
    except Exception as e:
        attack_logger.error(f"Error detecting unauthorized access: {e}")
        print(f"Error detecting unauthorized access: {e}")

def detect_dos_attack(packet):
    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            current_time = time.time()
            if current_time - last_time[ip_src] < TIME_WINDOW:
                ip_packet_count[ip_src] += 1
            else:
                ip_packet_count[ip_src] = 1
            last_time[ip_src] = current_time
            if ip_packet_count[ip_src] > dos_attack_threshold:  
                attack_logger.warning(f"ALERT: Potential DoS attack detected from IP: {ip_src}")
                print(f"ALERT: Potential DoS attack detected from IP: {ip_src}\n")
                ip_packet_count[ip_src]=0
                return
    except Exception as e:
        attack_logger.error(f"Error detecting DoS attack: {e}")
        print(f"Error detecting DoS attack: {e}")

def detect_xss(packet):
    try:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            for pattern in xss_patterns:
                if re.search(pattern, payload):
                    print(f"ALERT: XSS Attack Detected in request:\n{payload}")
                    attack_logger.warning(f"ALERT: XSS Attack Detected in request:\n{payload}")
                    return
    except Exception as e:
        attack_logger.error(f"Error processing packet: {e}")
        print(f"Error processing packet: {e}")

def detect_malware(packet):
    try:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            for pattern in malware_patterns:
                if re.search(pattern, payload):
                    print(f"ALERT: Malware/Ransomware Detected in request:\n{payload}")
                    attack_logger.warning(f"ALERT: Malware/Ransomware Detected in request:\n{payload}")
                    return  
    except Exception as e:
        attack_logger.error(f"Error processing packet: {e}")
        print(f"Error processing packet: {e}")

def detect_arp_spoofing(packet):
    try:
        if packet.haslayer(ARP):
            arp_ip = packet[ARP].psrc
            arp_mac = packet[ARP].hwsrc

            ip_to_macs[arp_ip].add(arp_mac)
            if len(ip_to_macs[arp_ip]) > arp_spoofing_threshold:
                current_time = time.time()
                if current_time - arp_last_time[arp_ip] < arp_time_window:
                    attack_logger.warning(f"ALERT: ARP Spoofing Detected for IP: {arp_ip}")
                    print(f"ALERT: ARP Spoofing Detected for IP: {arp_ip}\n")
                arp_last_time[arp_ip] = current_time
    except Exception as e:
        attack_logger.error(f"Error detecting ARP Spoofing: {e}")
        print(f"Error detecting ARP Spoofing: {e}")

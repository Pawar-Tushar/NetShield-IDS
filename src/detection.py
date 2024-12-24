import json
import logging
from src.utils import detect_arp_spoofing, detect_unauthorized_access, detect_xss
from src.utils import detect_dos_attack, detect_malware, detect_port_scan, detect_sql_injection

def process_packet(packet):
    detect_unauthorized_access(packet)
    detect_port_scan(packet)
    detect_dos_attack(packet)
    detect_sql_injection(packet)
    detect_xss(packet)
    detect_malware(packet)
    detect_arp_spoofing(packet)




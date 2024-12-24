from scapy.all import sniff
from src.logging_new import system_logger, attack_logger

def process_packet(packet, callback):
    try:
        callback(packet)
    except Exception as e:
        attack_logger.error(f"Error processing packet: {e}")

def start_sniffing(callback, packet_count=0, interface=None):    
    try:
        system_logger.info(f"Starting packet sniffing on interface: {interface}")
        print("Starting network capture for attack detection...:: Press Ctrl+C To STOP\n")
        sniff(
            iface=interface,
            prn=lambda packet: process_packet(packet, callback), 
            store=0,       # Do not store packets in memory
            count=packet_count
        )
        system_logger.info("Ending network capture for attack detection...")
        print("Ending network capture for attack detection...\n")
    except Exception as e:
        system_logger.error(f"Error starting sniffing: {e}")


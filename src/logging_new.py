import logging
import os

if not os.path.exists('logs/system_logs'):
    os.makedirs('logs/system_logs')

if not os.path.exists('logs/attack_logs'):
    os.makedirs('logs/attack_logs')

system_logger = logging.getLogger('system_logger')
system_logger.setLevel(logging.INFO) 
system_handler = logging.FileHandler('logs/system_logs/system.log')  
system_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
system_logger.addHandler(system_handler)

attack_logger = logging.getLogger('attack_logger')
attack_logger.setLevel(logging.WARNING) 
attack_handler = logging.FileHandler('logs/attack_logs/attacks.log')  
attack_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
attack_logger.addHandler(attack_handler)

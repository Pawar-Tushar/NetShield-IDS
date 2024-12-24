import hashlib
import os
import sys
from getpass import getpass
from src.sniffing import start_sniffing
from src.detection import  process_packet
import signal
 
def print_n_banner() -> None:
    banner = '''
    ███╗   ██╗███████╗████████╗███████╗ ██╗  ██╗██╗███████╗██╗     ██████╗
    ████╗  ██║██╔════╝   ██╔══╝██╔════╝ ██║  ██║██║██╔════╝██║     ██╔══██╗
    ██╔██╗ ██║█████╗     ██║   ███████╗ ███████║██║█████╗  ██║     ██║  ██║
    ██║╚██╗██║██╔══╝     ██║   ╚════██║ ██╔══██║██║██╔══╝  ██║     ██║  ██║
    ██║ ╚████║███████╗   ██║   ███████║ ██║  ██║██║███████╗███████╗██████╔╝
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
    '''
    print(banner)


PASSWORD_FILE = "password_hash.txt"  # don't touch this file, delete it if facing issues

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(input_password):
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'r') as f:
            stored_hash = f.read().strip()
            return stored_hash == hash_password(input_password)
    return False

def set_password():
    password = getpass("Set a new password: ")
    confirm_password = getpass("Confirm password: ")
    
    if password != confirm_password:
        print("Passwords do not match.")
        sys.exit(1)
    
    with open(PASSWORD_FILE, 'w') as f:
        f.write(hash_password(password))
    print("Password set successfully.")

def login():
    if not os.path.exists(PASSWORD_FILE):
        print("No password set. Please set a new password.")
        set_password()
    
    while True:
        password = getpass("Enter password: ")
        if verify_password(password):
            print("Login successful.")
            break
        else:
            print("Incorrect password. Please try again.")

def start_application():
    Choise = input("Do You want To Start The Monitoring? y/n: ")
    if Choise.lower() == 'y':  # Ensure case-insensitive comparison
        start_sniffing(callback=process_packet, packet_count=0, interface=None)
    else:
        print("Thanks For Visiting Us! Have A Good Day")

def graceful_shutdown(signal, frame):
    print("\nShutting down application gracefully...")
    sys.exit(0)

def main():
    # signal.signal(signal.SIGINT, graceful_shutdown)
    print_n_banner()
    login()
    start_application()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}")

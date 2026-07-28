import socket
import os
import time
import sys
import logging
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_TIMEOUT = 3
MAX_PORTS_PER_TARGET = 5  # Rate limiting
COMMON_PORTS = [80, 443, 20, 21, 3389, 25, 110, 143, 8080, 9090]

# ANSI color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Initialize scanner-specific state
broadcastadr = "FF:FF:FF:FF:FF:FF"

# File paths (using application data directory instead of home root)
app_data_dir = Path.home() / ".local" / "share" / "spy"
spy_database = app_data_dir / "spy_scan_results.txt"

# Ensure directory and database file exist
if not app_data_dir.exists():
    app_data_dir.mkdir(parents=True, exist_ok=True)
if not spy_database.exists():
    spy_database.touch()

label = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⡀⠀⡀⠀⠂⡀⢀⢰⠀⢂⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣐⣬⣄⣷⡀⢸⡃⡘⡸⡄⢸⠀⠀⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⡴⠚⢉⢍⢂⣼⣴⣿⣿⣿⣷⣷⣷⣣⣏⣆⣼⠀⠀⠄⠀⠀⠀
⠀⠀⠀⢠⡞⠋⠀⡑⣮⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⠀
⠀⠀⣰⠋⠀⣀⣺⣾⣿⣿⣿⣿⣿⡿⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⠀
⠀⡼⠁⢀⣿⣿⣿⡿⣿⡛⣿⣿⣿⡷⢸⣿⠀⠀⠀⠀⣹⣿⣿⣟⠣⠀⠀⠀⠀
⡰⠁⢀⣼⣿⠟⢿⡇⠹⣿⣿⣿⠟⠀⢠⡿⠀⠀⣠⣾⡿⣿⡥⠊⠁⠀⠀⠀⠀
⠁⢠⣾⠟⠁⠀⠈⠳⢿⣦⣠⣤⣦⣼⠟⠁⣠⣾⣿⣿⣟⠍⠒⠀⠠⠀⠀⠀⠀
⢠⡟⠁⢀⣀⣀⣀⡀⠈⣉⣉⣡⣤⣶⣿⡿⡿⡿⡻⠥⠑⡀⠀⠀⠀⠀⠀⠀⠀
⠏⡠⠚⠉⠋⢍⠋⢫⠋⠛⢹⢻⡟⠻⣟⢏⠌⢊⡌⠌⠄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠘⠂⠘⠂⠿⠈⠀⠀⠀⠘⠀⠀⠀⠀⠀⠀⠀⠀⠀"""

def menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{RED}{label}{RESET}")
    print("\n----------------------------------------")
    print("What action would you like to do?")
    print("----------------------------------------")
    actions()

def scan():
    destip = input("Input a subnet range or IP address \n ------------------ \n Address : ")
    for i in range(0, 3):
        dots = "." * i
        print(f"\rSending{dots}", end=".", flush=True)
        time.sleep(1)
    print(f"\rSending... Done!", flush=True)

    etherp = Ether(dst=broadcastadr)
    arpp = ARP(pdst=destip)

    packet = etherp / arpp
    answered, unanswered = srp(packet, timeout=DEFAULT_TIMEOUT, verbose=False)

    print("IP Address \t \t  MAC Address")
    
    table = ""
    for sent, received in answered:
        replytime = datetime.fromtimestamp(received.time).strftime("%H:%M:%S")
        line = f"[{replytime}] {received.psrc} is at: \t{received.hwsrc}"
        print(line)
        table += line + "\n"

    if not table:
        print("No hosts found")
        return

    print("Do you want to save this?")
    while True:
        choice = input("[1] Yes \n[2] No \nSelect : ")
        if choice not in ["1", "2"]:
            print("You can only select 1 or 2")
            continue
        elif choice == "1":
            with open(spy_database, "a") as file:
                for line in table.splitlines():
                    file.write(line + "\n")
            print(f"Saved to {spy_database}")
            break
        elif choice == "2":
            break

def ping():
    destip = input("Input a IP address \n ------------------ \n Address : ")
    packet = IP(dst=destip) / ICMP()
    response = sr1(packet, timeout=DEFAULT_TIMEOUT, verbose=0)
    
    if response:
        print(f"Sent and received 1 packet from {response.src}")
        print(f"Protocol : {response[IP].proto}")
        print(f"TTL : {response[IP].ttl}")
    else:
        print("Timed out")

def grab_banner(portip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((portip, port))
        if port == 80 or port == 8080:
            s.send(b"HEAD / HTTP/1.1\r\nHost: local\r\n\r\n")
        banner = s.recv(1024).decode().strip()
        print(f"[+] {port} ---> {banner}{RESET}")
        s.close()
    except Exception:
        print(f"{RED}[-] {port} ---> Could not grab banner{RESET}")

def check_port(portip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(DEFAULT_TIMEOUT)
        result = s.connect_ex((portip, port))
        s.close()
        return port, result
    except Exception as e:
        logger.debug(f"Port check failed for {portip}:{port}: {e}")
        return port, -1

def portscan():
    answered = []
    portip = input("Input IP \n Type : ")
    wnports = COMMON_PORTS[:MAX_PORTS_PER_TARGET]  # Rate limiting applied

    print("Ports that are open\tPorts that are closed")
    print("----------------------\t------------------------")

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lambda p: check_port(portip, p), wnports))

    for ports, result in results:
        if result == 0:
            print(f"{ports}")
            answered.append(ports)
        else:
            print(f"\t\t         {ports}")

    print("Grab Services?")
    while True:
        choice = input("[y] Yes \n[n] No \nType : ").strip()
        if choice not in ["y", "n"]:
            print("Invalid Choice")
            continue
        elif choice == "y":
            print("\nGrabbed")
            print("------------")
            for p in answered:
                grab_banner(portip, p)
            break
        elif choice == "n":
            break

def actions():
    while True:
        choice = input("[1] ARP Scan \n[2] Ping \n[3] Port Scan \n Select : ")
        if choice not in ["1", "2", "3"]:
            print("Invalid choice")
            continue
        elif choice == "1":
            scan()
            while True:
                askif = input("\nContinue? \n[y] Yes \n[n] No \n Select : ").lower()
                if askif not in ["y", "n"]:
                    print("You can only select [y] or [n]")
                    continue
                elif askif == "y":
                    break
                elif askif == "n":
                    sys.exit()
        elif choice == "2":
            ping()
            while True:
                askif = input("\nContinue? \n[y] Yes \n[n] No \n Select : ").lower()
                if askif not in ["y", "n"]:
                    print("You can only select [y] or [n]")
                    continue
                elif askif == "y":
                    break
                elif askif == "n":
                    sys.exit()
        elif choice == "3":
            portscan()
            while True:
                askif = input("\nContinue? \n[y] Yes \n[n] No \n Select : ").lower()
                if askif not in ["y", "n"]:
                    print("You can only select [y] or [n]")
                    continue
                elif askif == "y":
                    break
                elif askif == "n":
                    sys.exit()

menu()

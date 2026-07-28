import socket
import os
import time
import sys
from scapy.all import *
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor   

broadcastadr = "FF:FF:FF:FF:FF:FF"

SpyPath = Path.home() / "Spy"
SpyDatabase = SpyPath / "SpyDatabase.txt"
RED = "\033[91m"
RESET = "\033[0m"

if not SpyPath.exists():
    SpyPath.mkdir(parents=True, exist_ok=True)
if not SpyDatabase.exists():
    SpyDatabase.touch()

label = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⡀⠀⡀⠀⠂⡀⢀⢰⠀⢂⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣐⣬⣄⣷⡀⢸⡃⡘⡸⡄⢸⠀⠀⡇⠀⢠⠀⠀⠀
⠀⠀⠀⠀⠀⣠⡴⠚⢉⢍⢂⣼⣴⣿⣿⣿⣷⣷⣷⣣⣏⣆⣼⠀⠀⠄⠀⠀⠀
⠀⠀⠀⢠⡞⠋⠀⡑⣮⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣷⣼⣆⣌⡠⢁⡤
⠀⠀⣰⠋⠀⣀⣺⣾⣿⣿⣿⣿⣿⡿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠁
⠀⡼⠁⢀⣿⣿⣿⡿⣿⡛⣿⣿⣿⡷⢸⣿⠀⠀⠀⠀⣹⣿⣿⣿⣟⠣⠀⠀⠀
⡰⠁⢀⣼⣿⠟⢿⡇⠹⣿⣿⣿⠟⠀⢠⡿⠀⠀⣠⣾⡿⣿⡥⠊⠁⠀⠀⠀⠀
⠁⢠⣾⠟⠁⠀⠈⠳⢿⣦⣠⣤⣦⣼⠟⠁⣠⣾⣿⣿⣟⠍⠒⠀⠠⠀⠀⠀⠀
⢠⡟⠁⢀⣀⣀⣀⣀⡀⠈⣉⣉⣡⣤⣶⣿⡿⡿⡿⡻⠥⠑⡀⠀⠀⠀⠀⠀⠀
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
    answered, unanswered = srp(packet, timeout=3, verbose=False)


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
            with open(SpyDatabase, "a") as file:
                for line in table.splitlines():
                    file.write(line + "\n")
                print(f"Saved to {SpyDatabase}")
            break
        elif choice == "2":
            break
            

def ping():
    destip = input("Input a IP address \n ------------------ \n Address : ")
    packet = IP(dst=destip) / ICMP()

    response = sr1(packet, timeout=5, verbose=0)
    

    if response:
        print(f"Sent and received 1 packet from {response.src}")
        print(f"Protocol : {response[IP].proto}")
        print(f"TTL : {response[IP].ttl}")
    else:
        print("Timed out")

def grabbanner(portip, answered):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((portip, answered))

        if answered == 80 or answered == 8080:
            s.send(b"HEAD / HTTP/1.1\r\nHost: local\r\n\r\n")

        banner = s.recv(1024).decode().strip()
        print(f"[+] {answered} ---> {banner}{RESET}")
        s.close()
    except Exception:
        print(f"{RED}[-] {answered} ---> Could not grab banner{RESET}")


def checkport(portip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    result = s.connect_ex((portip, port))
    s.close()
    return port, result


def portscan():
    answered = []
    portip = input("Input IP \n Type : ")
    wnports = [
        80, 443, 20, 21, 3389, 25, 110, 143, 8080, 9090
    ]

    print("Ports that are open\tPorts that are closed")
    print("----------------------\t------------------------")

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lambda p: checkport(portip, p), wnports))

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
                grabbanner(portip, p)
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


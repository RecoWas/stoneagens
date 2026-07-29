import socket
import os
import time
import sys
import ipaddress
from scapy.all import *
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor 


# if you see this, you can modify the ports to scan here 
wnports = [ 80, 430, 3389, 8080, 4444, 20, 21, 22, 25, 445, 

]

broadcastadr = "FF:FF:FF:FF:FF:FF"

SpyPath = Path.home() / "Spy"
SpyDatabase = SpyPath / "SpyDatabase.txt"
RED = "\033[91m"
RESET = "\033[0m"


def typeanim(mstext):
    for i in range(1, 3):
        dots = "." * i
        print(f"\r{mstext}{dots}", end="", flush=True)
        time.sleep(1)
    print(f"\r{mstext}... Done", flush=True)

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
    def autosubnet():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect(("8.8.8.8", 80))
            localip = s.getsockname()[0]
            s.close()

            iface = conf.route.route(localip)[0]
            netmask = get_if_netmask(iface)
            return str(ipaddress.IPv4Network(f"{localip}/{netmask}", strict=False))
        except Exception:
            return "null"            
    networksb = autosubnet()
    activation = True
    while True:
            
            if activation and networksb != "null":
                activation = False
                destip = input(f"Subnet found. Press Enter to scan {networksb} or manually type a subnet range or a IP address\n ? : ").strip()
            else:
                destip = input("Input a subnet range or a IP address \n ? : ").strip()

            if not destip:
                    if networksb != "null":
                        destip = networksb
                    else:
                        print("! - No input provided and auto-subnet is unavaible")
                        continue

            try:
                subnet = ipaddress.ip_network(destip, strict=False)
                break
            except ValueError:
                print("Not a valid subnet format. Please use this format : IP.ADD.RE.SS/SubnetRange. If this error caused in auto subnet please report")

    typeanim("Pushing")

    etherp = Ether(dst=broadcastadr)
    arpp = ARP(pdst=str(subnet))

    packet = etherp / arpp
    answered, unanswered = srp(packet, timeout=3, verbose=False)

    print("IP Address \t\t\t MAC Address")

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
        choice = input("[y] Yes \n[n] No \n? : ").lower()
        if choice not in ["y", "n"]:
            print("Only y or n")
            continue
        elif choice == "y":
            typeanim('Saving')
            with open(SpyDatabase, "a") as file:
                for line in table.splitlines():
                    file.write(line + "\n")
                print(f"Saved to {SpyDatabase}")
                break
        elif choice == "n":
            break

def ping():
    while True:
        destip = input("Input a IP address \n ------------------ \n? : ").strip()
        try:
            ipaddress.ip_address(destip)
            break
        except ValueError:
            print("Typo or not a valid IP address")

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
        elif answered == 25:
            s.send(b"EHLO scanner\r\n")
            banner = s.recv(1024).decode().strip()
            s.send(b"QUIT\r\n")
        else:
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
    while True:
        portip = input("Input IP \n? : ")
        try:
            ipaddress.ip_address(portip)
            break
        except ValueError:
            print("Not a valid IP address. Please enter a IP address like 192.168.1.1")
    print("Ports that are opent\tPorts that are closed")
    print("----------------------\t------------------------")

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lambda p: checkport(portip, p), wnports))

    for ports, result in results:
        if result == 0:
            print(f"{ports}")
            answered.append(ports)
        else:
            print(f"\t\t        {ports}")

    print("Grab Services?")
    while True:
        choice = input("[y] Yes \n[n] No \n? : ")
        if choice not in ["y", "n"]:
            print("Not a valid selection. Please select y or n")
        elif choice == "y":
            print("\nGrabbed")
            print("-------------")
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

if __name__ == "__main__":
    menu()

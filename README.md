# stoneagens
This is my first project after i started learning cybersecurity. It works as a stone age network scan tool. I'm still trying to get better at understanding networks and python. Please let me know if you have a suggestion/bug about the tool:)

Spy — Stone Age Network Scanner

A simple, menu-driven network tool built in Python while learning networking and cybersecurity fundamentals. This is my first real project — feedback and suggestions are very welcome!

What it does
ARP Scan — discovers live devices on a local subnet, showing IP address, MAC address, and the exact time each device responded. Results can be saved to a local log file.
Ping (ICMP) — sends a single ICMP echo request to a target IP and reports whether it responded, along with protocol and TTL info.
Port Scan — checks a list of common ports (HTTP, FTP, RDP, SMTP, etc.) on a target IP to see which are open, using multithreading for faster scanning. Optionally grabs service banners from any open ports found.

Why "Stone Age"?

Because it's built from raw sockets and Scapy with no fancy libraries or polish — just the fundamentals, exactly as I'm learning them. No GUI, no frills, just a straightforward CLI menu.

Requirements
Python 3
Scapy
Run with administrator/root privileges (required for raw packet operations like ARP scanning)

Built and tested only on my own local network/lab environment. Only use this against systems and networks you own or have explicit permission to test.



tags (ignore)
python, network scanner, port scanner, beginner, beginner-project, scapy, socket

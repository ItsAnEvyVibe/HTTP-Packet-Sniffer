# -------------------------------------------------------------------------
# Project:HTTP-Packet-Sniffer
# Author: Krystel E Albertson
# Date: February 2026
# Business: Lock it Down Solutions
# -------------------------------------------------------------------------

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(f"[+] HTTP Request >> {url.decode()}")
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            print(f"\n[!] Data Found >> {load.decode()}\n")

sniff("eth0")

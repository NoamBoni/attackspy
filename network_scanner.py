#!/usr/bin/env python3

import scapy.all as scapy
import optparse


def get_parameters():
    parser = optparse.OptionParser()
    parser.add_option('-t', '--target', dest='target', help='IP or a network to scan')
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error('[-] target is required. use --help for more information')
    return options.target


def arp_scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_request = broadcast / arp_request
    return scapy.srp(arp_broadcast_request, timeout=1, verbose=False)[0]


def print_scan(answered):
    print("IP\t\t\tMAC address\n===========================================")
    for answer in answered:
        print(answer[1].psrc + "\t\t" + answer[1].hwsrc)


target = get_parameters()
results = arp_scan(target)
print_scan(results)

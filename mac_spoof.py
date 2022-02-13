#!/usr/bin/env python3

import subprocess
import optparse
import re


def get_parameters():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', '--iface', dest='iface', help='interface to change its MAC address')
    parser.add_option('-m', '--mac', dest='mac', help='new MAC address to set to the given interface')
    (options, arguments) = parser.parse_args()
    if not options.iface:
        parser.error('[-] interface is required. use --help for more information')
    elif not options.mac:
        parser.error('[-] mac address is required. use --help for more information')
    return options


def change_mac(iface, mac):
    print('[+] changing ' + iface + ' MAC address to ' + mac)
    subprocess.call("ifconfig " + iface + " down", shell=True)
    subprocess.call("ifconfig " + iface + " hw ether " + mac, shell=True)
    subprocess.call("ifconfig " + iface + " up", shell=True)


def get_current_mac(iface):
    result = subprocess.run(['ifconfig', iface], check=True, capture_output=True, text=True).stdout
    search_results = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", result)
    if not search_results:
        print("[-] couldn't find current MAC address")
    else:
        return search_results.group(0)


options = get_parameters()
print("[+] Current MAC is " + str(get_current_mac(options.iface)))
change_mac(options.iface, options.mac)
new_mac = str(get_current_mac(options.iface))
if new_mac == options.mac:
    print("[+] MAC address changed successfully to " + new_mac)
else:
    print("[-] MAC address did not changed")



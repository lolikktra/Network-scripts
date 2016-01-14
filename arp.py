#! /usr/bin/python

from netinfo import get_netmask, get_routes
from scapy.all import srp, Ether, ARP

def interface():
    # defines interface connected to the network
    for item in get_routes():
        for key in item:
            if item["gateway"] != "0.0.0.0":
                return item["dev"]

def ip_range():
    # defines IP range
    mask = get_netmask(interface()).rsplit('.')
    bin_mask = []
    for i in mask:
        bin_mask.append(bin(int(i))[2:])
    count = 0
    for item in bin_mask:
        for i in item:
            if i == '1':
                count += 1
    return count

value_for_arp = "192.168.1.0" + "/" + str(ip_range())

ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff:ff:ff")/ARP(pdst=value_for_arp), timeout=2, iface=interface(), inter=0.1)
ans.summary()

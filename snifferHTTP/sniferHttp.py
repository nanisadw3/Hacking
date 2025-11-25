#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http

def proces_pk(pk):
    if pk.haslayer(http.HTTPRequest):
        print(pk.show())

def sniff(interface):
    scapy.sniff(iface=interface, prn=proces_pk, store=0)


def main():
    sniff("enp6s0")


if __name__ == "__main__":
    main()

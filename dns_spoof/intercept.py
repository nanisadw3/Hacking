#!/usr/bin/env python3
import scapy.all as scapy 

def proces(pk):
    if pk.haslayer(scapy.DNSRR):
        qname = pk[scapy.DNSQR].qname

        if b'inakisobera' in qname:
            print(pk.show())

scapy.sniff(iface="enp6s0", filter="udp and port 53", prn=proces, store=0)

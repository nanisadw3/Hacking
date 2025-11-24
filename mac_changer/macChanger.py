#!/usr/bin/env python3

import argparse
import re 
import subprocess
from termcolor import colored
import signal


def senial(sig, frame):
    print(colored("\n[!] Saliendo...\n", "grey"))


signal.signal(signal.SIGINT, senial)

def getarguments():
    pr = argparse.ArgumentParser(description="Herramienta para cambiar la mac de la interfaz")
    pr.add_argument('-i', '--interface', required=True, dest="interface",help='nombre de la interfaz')
    pr.add_argument('-m', '--mac', required=True, dest="mac",help='nueva direcion mac para la interfaz')

    return pr.parse_args()

def is_valid(mac, interface):
    valid_int = re.match(r'^[e][nt][shp]\d{1,2}(s\d{1,2})?$', interface)
    valid_mac = re.match(r'^([A-Fa-f0-9]{2}[:\-]){5}[A-Fa-f0-9]{2}$', mac)

    print(colored(valid_int, "grey"))
    print(colored(valid_mac, "grey"))

    if valid_int and valid_mac:
        return True
    else:
        return False

def mac_changer(interface, mac):

    subprocess.run(["ip", "link", "set", "dev", interface, "down"])
    subprocess.run(["ip", "link", "set", "dev", interface, "address", mac])
    subprocess.run(["ip", "link", "set", "dev", interface, "up"])

    print(colored("\n\t[+] La mac ha sido cambiada exitosamente\n", 'cyan'))

def main():
    args = getarguments()
    mac = args.mac
    interface = args.interface

    if is_valid(mac, interface):
        mac_changer(interface, mac)
    else:
        print(colored("La direccion mac o la interfaz no son validas", 'red'))

    

if __name__ == "__main__":
    main()

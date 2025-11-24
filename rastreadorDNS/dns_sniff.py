#!/usr/bin/env python3
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description='DNS Sniffer')
    parser.add_argument("-i", "--interface", dest="interface", default="eth0", help="Specify interface to sniff on")
    return parser.parse_args()

def dnspacket(pck, domains_seen):
    if pck.haslayer(scapy.DNSQR):
        domain = pck[scapy.DNSQR].qname.decode('utf-8', 'ignore').rstrip('.')

        # Lista de dominios a excluir. Se puede mejorar para que sea más precisa.
        exclude = ["google.", "microsoft.", "apple.", "cloudflare.", "bing.", "mozilla.", "firefox.", "gstatic.com"]

        # Comprueba si el dominio no está en los vistos y no es un subdominio de los excluidos.
        if domain not in domains_seen and not any(domain.endswith(ex) for ex in exclude):
            domains_seen.add(domain)
            print(f"DNS → {domain}")

def main():
    """
    Nota importante sobre el tráfico DNS moderno:
    Este sniffer captura peticiones DNS estándar (puertos 53 UDP/TCP). Sin embargo,
    muchas aplicaciones y sistemas operativos modernos utilizan DNS sobre HTTPS (DoH)
    o DNS sobre TLS (DoT). Este tráfico está cifrado y viaja por otros puertos (como el 443),
    por lo que este script NO PODRÁ capturarlo.

    Si no ves el tráfico esperado (ej. de tu navegador), es muy probable que se deba a que
    está usando DoH/DoT. Desactivarlo suele requerir cambiar la configuración de tu
    navegador o sistema operativo.
    """
    print(main.__doc__)

    args = get_arguments()
    domains_seen = set()

    # Intenta listar las interfaces para ayudar al usuario
    try:
        print("Interfaces de red disponibles:", ", ".join(scapy.get_if_list()))
    except Exception:
        print("No se pudieron listar las interfaces de red. Asegúrate de que la interfaz especificada es correcta.")


    interface = args.interface
    print(f"[+] Escuchando DNS en {interface} (UDP/TCP 53)...")

    # Usamos una expresión lambda para pasar el set de dominios a la función de callback
    packet_handler = lambda p: dnspacket(p, domains_seen)

    try:
        scapy.sniff(iface=interface, filter="udp port 53 or tcp port 53", prn=packet_handler, store=False)
    except Exception as e:
        print(f"[-] Error al iniciar el sniffer: {e}")
        print("[-] Asegúrate de ejecutar el script con privilegios de superusuario (sudo) y de que la interfaz de red es correcta.")


if __name__ == "__main__":
    main()
# Forzando actualizacion git

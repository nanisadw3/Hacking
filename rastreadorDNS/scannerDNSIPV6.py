#!/usr/bin/env python3
import scapy.all as scapy
import argparse
def get_arguments():
    parser = argparse.ArgumentParser(description='DNS Sniffer for IPv6 Traffic')
    parser.add_argument("-i", "--interface", dest="interface", required=True, help="Specify interface to sniff on")
    return parser.parse_args()
def dnspacket_ipv6(pck, domains_seen):
    # Nos aseguramos de que es un paquete IPv6 y que contiene una capa DNS
    if pck.haslayer(scapy.IPv6) and pck.haslayer(scapy.DNSQR):
        domain = pck[scapy.DNSQR].qname.decode('utf-8', 'ignore').rstrip('.')
        # Lista de dominios a excluir
        exclude = ["google.", "microsoft.", "apple.", "cloudflare.", "bing.", "mozilla.", "firefox.", "gstatic.com"]
        if domain not in domains_seen and not any(domain.endswith(ex) for ex in exclude):
            # Obtenemos la IP de origen del paquete IPv6
            source_ip = pck[scapy.IPv6].src
            domains_seen.add(domain)
            print(f"DNS (IPv6) | Source: {source_ip} → {domain}")
def main():
    print("IPv6 DNS Sniffer. Waiting for traffic...")
    print("NOTE: This will only show traffic if you are successfully performing an IPv6 MitM attack (e.g., with mitm6).")
    args = get_arguments()
    domains_seen = set()
    interface = args.interface
    print(f"[+] Sniffing for DNS over IPv6 on {interface} (udp port 53)...")
    # La expresión lambda para pasar el set de dominios a la función de callback
    packet_handler = lambda p: dnspacket_ipv6(p, domains_seen)
    try:
        # El filtro de Scapy "ip6" especifica que solo queremos paquetes IPv6
        scapy.sniff(iface=interface, filter="ip6 and udp port 53", prn=packet_handler, store=False)
    except Exception as e:
        print(f"[-] Error starting sniffer: {e}")
        print("[-] Ensure you are running with superuser privileges (sudo) and the interface is correct.")
if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import socket
import argparse
import sys
import pdb
# import threading
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
import signal
import sys

open = []

def def_handler(sig, frame):
    print(f"\nEl valor es {sig}")
    print(frame)
    print(colored("[!] Saliendo del programa...", "red"))
    for i in open:
        i.close()
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description='Fast tcp port scanner')
    parser.add_argument("-t", "--target", dest="target",required=True, help="Victim target to scan (Ex -t 192.168.100.1)")
    parser.add_argument("-p", "--port", dest="port",required=True, help="Port range tu scan (Ex -p 1-100)")
    options = parser.parse_args() # Recuperar argumentos 
    
    return options.target, options.port

def create_socket():
    s =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    open.append(s)
    return s


def port_scanner(port, host):
    s = create_socket()
    try:
        s.connect((host, port))  # dentro del with y correctamente indentado
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        response = s.recv(1024)
        response = response.decode(errors='ignore').split('\n')[0]

        if response:
            print(colored(f"[+] El puerto {port} esta abierto - {response}", "cyan"))
        else:
            print(colored(f"[>] El puerto {port} está abierto", 'green'))
    except (socket.timeout, ConnectionRefusedError) as e:
        pass
    finally:
        s.close()


def scan_ports(ports, target):
    with ThreadPoolExecutor(max_workers=100) as th:
        th.map(lambda port: port_scanner(port, target),ports)


def parse_ports(port):
    if '-' in port:
        start,end = map(int, port.split('-'))
        return range(start,end + 1)
    elif ',' in port:
        start,end = map(int, port.split(','))
        return range(start,end + 1)
    else:
        return (int(port),)

  
def main():
    target, port = get_arguments()
    p = parse_ports(port)
    scan_ports(p, target)

if __name__ == '__main__':
    main()



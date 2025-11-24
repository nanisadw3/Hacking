#!/usr/bin/env python3

import socket
from typing import List
from termcolor import colored
import argparse
import signal
import os
from concurrent.futures import ThreadPoolExecutor

sockets_list = []

def handler(sig, frame):

    print(colored("[!] Saliendo ...", "grey"))

    for sock in sockets_list:
        try:
            sock.close()
        except Exception as e:
            print(colored(f"[!] Error al cerrar el socket: {e}", "red"))
    os._exit(0)
signal.signal(signal.SIGINT, handler)

def getarguments():
    pr = argparse.ArgumentParser(description='TCP port scanner')
    pr.add_argument('-t', '--target',required=True, dest="target", help='Ex: (-t 192.168.100.1)')
    pr.add_argument('-p', '--port',required=True , dest="port", help='Ex: (-p 1-100)')
    options = pr.parse_args()

    return options.target, options.port

def create_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    return s
def port_scanner(port, host):
    s = create_socket()
    sockets_list.append(s)
    try:
        s.connect((host,port))
        s.sendall(b"HEAD / HTTP/1.0\n\n")
        responce = s.recv(1024)
        responce = responce.decode(errors='ignore').split('\n')[0]
        if not responce:
            print(colored(f"\t[!] El puerto {port} esta abierto", "cyan"))
        else:
            print(colored(f"\t[!] El puert {port} esta abierto - {responce}", "light_blue"))

        s.close()
    except (socket.timeout, ConnectionRefusedError, socket.gaierror):
        pass
        # print(colored(f"[+] El puerto {port} esta cerrado","red"))
    finally:
        s.close()

def parseports(p):
    if '-' in p:
        start, end = map(int, p.split('-'))
        return range(start, end+1)
    elif ',' in p:
        return map(int, p.split(','))
    else:
        return (int(p),)

def scann(ports, target):
    with ThreadPoolExecutor(max_workers=100) as ex:
        ex.map(lambda port: port_scanner(port, target), ports)
def main():

    target, ports = getarguments()
    p = parseports(ports)
    scann(p,target)

if __name__ == "__main__":
    main()

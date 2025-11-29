#!/usr/bin/env python3

from mitmproxy import http
import signal
import os

def senial(s,f):
    print("[+] Saliendo...")
    os._exit(1)

signal.signal(signal.SIGINT, senial)

def response(pk):
    ct = pk.response.headers.get("content-type", "")

    try:

        if "image" in ct:
            print(ct)

            url = pk.request.url
            extencion = ct.split("/")[-1]

            file = f"images/{url.replace('/','_').replace(':','_')}"
            image = pk.response.content 

            with open(file, "wb") as f:
                f.write(image)
            print(f"[+] Imagen guardada: {file}")

    except:
        print("error")
        

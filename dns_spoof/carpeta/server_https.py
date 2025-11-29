import http.server
import ssl
import os

# Directorio donde se encuentran los archivos a servir (index.html, etc.)
web_dir = os.path.join(os.path.dirname(__file__), '.')
os.chdir(web_dir)

# Dirección y puerto
server_address = ('0.0.0.0', 443)

# Configura el servidor HTTP
handler_class = http.server.SimpleHTTPRequestHandler
httpd = http.server.HTTPServer(server_address, handler_class)

# Configura el contexto SSL/TLS
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
try:
    # Carga el certificado y la clave privada
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

    # Envuelve el socket del servidor con el contexto SSL
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"Servidor HTTPS corriendo en https://{server_address[0]}:{server_address[1]}...")
    print("Detén el servidor con CTRL+C")
    httpd.serve_forever()

except FileNotFoundError:
    print("\nError: No se encontraron los archivos 'cert.pem' y 'key.pem'.")
    print("Asegúrate de generarlos primero con el comando openssl.")
except OSError as e:
    if e.errno == 13:
        print("\nError: Permiso denegado para usar el puerto 443.")
        print("Recuerda ejecutar el script con 'sudo': sudo python3 server_https.py")
    else:
        print(f"\nUn error ha ocurrido: {e}")
except Exception as e:
    print(f"Ha ocurrido un error inesperado: {e}")
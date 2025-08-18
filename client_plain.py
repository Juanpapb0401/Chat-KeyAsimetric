import socket
import threading
import sys
import json
import struct
from cripto_utils_plain import Usuario, cargar_clave_publica, encriptar_mensaje, desencriptar_mensaje
import os

HOST = '127.0.0.1'
PORT = 65433  # Puerto diferente para la versión sin cifrado

def recv_exact(sock, num_bytes):
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Conexión cerrada durante recepción")
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(sock):
    header = recv_exact(sock, 4)
    (length,) = struct.unpack('!I', header)
    if length == 0:
        return b''
    return recv_exact(sock, length)

def send_frame(sock, payload_bytes):
    header = struct.pack('!I', len(payload_bytes))
    sock.sendall(header + payload_bytes)

def receive_messages(client_socket, user):
    """Hilo para escuchar y procesar mensajes entrantes SIN CIFRADO."""
    while True:
        try:
            data = recv_frame(client_socket)
            if data is None:
                print("\n[CONEXIÓN CERRADA POR EL SERVIDOR]")
                break

            message_json = data.decode('utf-8')
            print(f"\n[DEBUG WIRESHARK] Paquete recibido ({len(message_json)} bytes):")
            print(f"[DEBUG WIRESHARK] JSON completo: {message_json}")
            
            # Procesar mensaje sin cifrado
            decrypted_message = desencriptar_mensaje(
                message_json,
                user.clave_privada,  # Dummy
                user.clave_publica_destinatario,  # Dummy
            )
            
            # Mostrar mensaje
            print(f"\rMensaje de {user.nombre_destinatario}: {decrypted_message}\nTú> ", end="")

        except json.JSONDecodeError:
            print("\n[ERROR] Se recibió un mensaje mal formado.")
            print(f"[DEBUG] Contenido recibido: {data}")
            continue
        except Exception as e:
            print(f"\n[ERROR] Error al recibir o procesar mensaje: {e}")
            break
    client_socket.close()

def start_client(nombre):
    print(f"\n=== CLIENTE SIN CIFRADO - {nombre} ===")
    print("[WARNING] Esta versión NO usa cifrado - para análisis con Wireshark")
    print("[WARNING] Todos los mensajes viajan en TEXTO PLANO por la red\n")
    
    user = Usuario(nombre)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print(f"[ERROR] No se pudo conectar al servidor en {HOST}:{PORT}. ¿Está en línea?")
        print("[INFO] Asegúrate de ejecutar: python servidor_plain.py")
        return

    # Handshake simplificado - solo nombres (sin claves públicas reales)
    print("Conectado al servidor. Enviando datos...")
    handshake_data = {
        "nombre": user.nombre,
        "public_key_pem": user.serializar_clave_publica().decode('utf-8'),  # Dummy
        "mode": "PLAIN_TEXT",
        "encryption": "NONE"
    }
    
    handshake_json = json.dumps(handshake_data, indent=2)
    print(f"[DEBUG WIRESHARK] Handshake enviado ({len(handshake_json)} bytes):")
    print(f"[DEBUG WIRESHARK] {handshake_json}")
    
    send_frame(client_socket, handshake_json.encode('utf-8'))

    print("Esperando los datos del otro usuario...")
    response_data = recv_frame(client_socket)
    if not response_data:
        print("\n[ERROR] El servidor cerró la conexión inesperadamente.")
        client_socket.close()
        return

    response_json = response_data.decode('utf-8')
    print(f"[DEBUG WIRESHARK] Respuesta handshake recibida ({len(response_json)} bytes):")
    print(f"[DEBUG WIRESHARK] {response_json}")
    
    destinatario_info = json.loads(response_json)
    user.nombre_destinatario = destinatario_info['nombre']
    # No cargamos claves reales porque no las usamos
    user.clave_publica_destinatario = "DUMMY_KEY"

    print(f"\n¡Todo listo! Chat SIN CIFRADO con '{user.nombre_destinatario}' está activo.")
    print("COMANDOS:")
    print("- Escribe cualquier mensaje y presiona Enter")
    print("- '/showkeys' para ver claves dummy")
    print("- '/debug' para mostrar información de debug")
    print("- '/exit' para salir")
    print("\n[WIRESHARK TIP] Filtra por: tcp.port == 65433")
    print("[WIRESHARK TIP] Busca los JSON en los paquetes TCP\n")

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket, user))
    receive_thread.daemon = True
    receive_thread.start()

    while True:
        try:
            message_to_send = input("Tú> ")
            if message_to_send.lower() in ('exit', '/exit'):
                break
            
            if message_to_send.strip() == '/showkeys':
                try:
                    priv_pem = user.serializar_clave_privada()
                    pub_pem = user.serializar_clave_publica()
                    print("\n----- CLAVES DUMMY (MODO SIN CIFRADO) -----")
                    print(priv_pem.decode('utf-8'))
                    print(pub_pem.decode('utf-8'))
                    print("Estas claves son falsas - no se usa criptografía real\n")
                except Exception as e:
                    print(f"[ERROR] No se pudieron mostrar las claves: {e}")
                continue
            
            if message_to_send.strip() == '/debug':
                print(f"\n----- INFORMACIÓN DE DEBUG -----")
                print(f"Nombre: {user.nombre}")
                print(f"Destinatario: {user.nombre_destinatario}")
                print(f"Puerto servidor: {PORT}")
                print(f"Modo: SIN CIFRADO (PLAIN TEXT)")
                print(f"Tip Wireshark: tcp.port == {PORT} and tcp contains '{message_to_send}'")
                print("Todos los mensajes son visibles en texto plano\n")
                continue

            # Crear mensaje sin cifrado
            plain_package = encriptar_mensaje(
                message_to_send,
                user.clave_publica_destinatario,  # Dummy
                user.clave_privada,  # Dummy
            )
            
            print(f"[DEBUG WIRESHARK] Enviando mensaje ({len(plain_package)} bytes):")
            print(f"[DEBUG WIRESHARK] {plain_package}")
            
            send_frame(client_socket, plain_package.encode('utf-8'))
            
        except (KeyboardInterrupt, EOFError):
            break
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
            break

    print("\nSaliendo del chat sin cifrado...")
    client_socket.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python client_plain.py <tu_nombre>")
        print("Ejemplo: python client_plain.py Alice")
    else:
        nombre_usuario = sys.argv[1]
        start_client(nombre_usuario)

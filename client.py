import socket
import threading
import sys
import json
import struct
from cripto_utils import Usuario, cargar_clave_publica, encriptar_mensaje, desencriptar_mensaje

HOST = '127.0.0.1'
PORT = 65432


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
    """Hilo para escuchar y desencriptar mensajes entrantes."""
    while True:
        try:
            data = recv_frame(client_socket)
            if data is None:
                print("\n[CONEXIÓN CERRADA POR EL SERVIDOR]")
                break

            encrypted_package_json = data.decode('utf-8')
            decrypted_message = desencriptar_mensaje(
                encrypted_package_json,
                user.clave_privada,
                user.clave_publica_destinatario,  # se reemplaza por la pública del emisor cuando llegue el paquete handshake del servidor
            )
            # Imprime el mensaje en una nueva línea para no interrumpir lo que el usuario está escribiendo
            print(f"\rMensaje de {user.nombre_destinatario}: {decrypted_message}\nTú> ", end="")

        except json.JSONDecodeError:
            print("\n[ERROR] Se recibió un mensaje mal formado.")
            continue
        except Exception as e:
            print(f"\n[ERROR] Error al recibir o desencriptar mensaje: {e}")
            break
    client_socket.close()


def start_client(nombre):
    user = Usuario(nombre)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("[ERROR] No se pudo conectar al servidor. ¿Está en línea?")
        return

    # Intercambio de claves y nombres a través de un paquete JSON con framing
    print("Conectado al servidor. Enviando datos y clave pública...")
    handshake_data = {
        "nombre": user.nombre,
        "public_key_pem": user.serializar_clave_publica().decode('utf-8')
    }
    send_frame(client_socket, json.dumps(handshake_data).encode('utf-8'))

    print("Esperando los datos del otro usuario...")
    response_data = recv_frame(client_socket)
    if not response_data:
        print("\n[ERROR] El servidor cerró la conexión inesperadamente.")
        client_socket.close()
        return

    destinatario_info = json.loads(response_data.decode('utf-8'))
    user.nombre_destinatario = destinatario_info['nombre']
    public_key_pem_destinatario = destinatario_info['public_key_pem'].encode('utf-8')
    user.clave_publica_destinatario = cargar_clave_publica(public_key_pem_destinatario)

    print(f"¡Todo listo! El chat con '{user.nombre_destinatario}' está activo.")
    print("Escribe tu mensaje y presiona Enter. Comandos: '/showkeys' para ver tus claves, '/exit' para salir.")

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
                    print("\n----- TU CLAVE PRIVADA (PEM) -----\n" + priv_pem.decode('utf-8'))
                    print("----- TU CLAVE PÚBLICA (PEM) -----\n" + pub_pem.decode('utf-8'))
                except Exception as e:
                    print(f"[ERROR] No se pudieron mostrar las claves: {e}")
                continue

            encrypted_package = encriptar_mensaje(
                message_to_send,
                user.clave_publica_destinatario,
                user.clave_privada,
            )
            send_frame(client_socket, encrypted_package.encode('utf-8'))
        except (KeyboardInterrupt, EOFError):
            break
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
            break

    print("\nSaliendo del chat...")
    client_socket.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python client.py <tu_nombre>")
    else:
        nombre_usuario = sys.argv[1]
        start_client(nombre_usuario)

import socket
import threading
import json
import struct

HOST = '127.0.0.1'  # La dirección IP del servidor (localhost)
PORT = 65432        # Puerto para escuchar

clients = []
public_keys = {}
lock = threading.Lock()  # Bloqueo para acceso seguro a recursos compartidos


def recv_exact(conn, num_bytes):
    """Recibe exactamente num_bytes o levanta ConnectionError."""
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = conn.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Conexión cerrada durante recepción")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(conn):
    """Recibe un mensaje con framing longitud-prefijo (uint32 big-endian)."""
    header = recv_exact(conn, 4)
    (length,) = struct.unpack('!I', header)
    if length == 0:
        return b''
    return recv_exact(conn, length)


def send_frame(conn, payload_bytes):
    header = struct.pack('!I', len(payload_bytes))
    conn.sendall(header + payload_bytes)


def handle_client(conn, addr):
    """Maneja la conexión de un cliente de forma segura."""
    print(f"[NUEVA CONEXIÓN] {addr} conectado.")
    client_name_local = ""

    # Recibir los datos iniciales (nombre y clave) con framing
    try:
        data_bytes = recv_frame(conn)
        if not data_bytes:
            raise ConnectionError("Cliente desconectado antes de enviar datos.")

        client_data = json.loads(data_bytes.decode('utf-8'))
        nombre = client_data['nombre']
        client_name_local = nombre
        public_key_pem = client_data['public_key_pem'].encode('utf-8')

        # Usar un Lock para modificar las listas de forma segura
        with lock:
            clients.append((conn, nombre))
            public_keys[nombre] = public_key_pem
            print(f"Datos y clave pública de {nombre} recibidos.")

            # Si ya hay dos clientes, intercambiar sus claves públicas
            if len(clients) == 2:
                (conn1, name1), (conn2, name2) = clients

                print("Dos clientes conectados. Intercambiando datos...")
                # Enviar a cada cliente el nombre y la clave del otro
                paquete_para_1 = json.dumps({"nombre": name2, "public_key_pem": public_keys[name2].decode('utf-8')}).encode('utf-8')
                paquete_para_2 = json.dumps({"nombre": name1, "public_key_pem": public_keys[name1].decode('utf-8')}).encode('utf-8')

                send_frame(conn1, paquete_para_1)
                send_frame(conn2, paquete_para_2)
                print("Datos intercambiados.")

    except (json.JSONDecodeError, KeyError, ConnectionError) as e:
        print(f"[ERROR de Handshake] {e} de {addr}. Cerrando conexión.")
        conn.close()
        return
    except Exception as e:
        print(f"[ERROR INESPERADO] {e}")
        conn.close()
        return

    # Bucle para retransmitir mensajes cifrados con framing
    while True:
        try:
            message = recv_frame(conn)
            if message is None:
                break

            with lock:
                if len(clients) < 2:
                    break
                (conn1, name1), (conn2, name2) = clients

            target_conn = conn2 if conn == conn1 else conn1
            print("Retransmitiendo mensaje...")
            send_frame(target_conn, message)

        except Exception:
            break

    print(f"[CONEXIÓN CERRADA] {addr}")
    with lock:
        # Eliminar al cliente de las listas al desconectarse
        for i, (client_conn, client_name) in enumerate(clients):
            if client_conn == conn:
                clients.pop(i)
                if client_name in public_keys:
                    del public_keys[client_name]
                break
    conn.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(2)
    print(f"[ESCUCHANDO] El servidor está escuchando en {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
    except KeyboardInterrupt:
        print("\n[CERRANDO SERVIDOR]")
    finally:
        for conn, _ in clients:
            conn.close()
        server.close()


if __name__ == "__main__":
    start_server()

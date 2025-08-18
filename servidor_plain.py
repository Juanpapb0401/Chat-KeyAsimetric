import socket
import threading
import json
import struct

HOST = '127.0.0.1'  # La dirección IP del servidor (localhost)
PORT = 65433        # Puerto diferente para la versión sin cifrado

clients = []
client_info = {}  # Almacena información de los clientes (nombres, etc.)
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
    """Maneja la conexión de un cliente SIN CIFRADO."""
    print(f"[NUEVA CONEXIÓN] {addr} conectado al servidor sin cifrado.")
    client_name_local = ""

    # Recibir los datos iniciales (handshake simplificado)
    try:
        data_bytes = recv_frame(conn)
        if not data_bytes:
            raise ConnectionError("Cliente desconectado antes de enviar datos.")

        handshake_json = data_bytes.decode('utf-8')
        print(f"[DEBUG WIRESHARK] Handshake recibido ({len(handshake_json)} bytes):")
        print(f"[DEBUG WIRESHARK] {handshake_json}")
        
        client_data = json.loads(handshake_json)
        nombre = client_data['nombre']
        client_name_local = nombre
        mode = client_data.get('mode', 'UNKNOWN')
        encryption = client_data.get('encryption', 'UNKNOWN')

        print(f"[INFO] Cliente {nombre} - Modo: {mode}, Cifrado: {encryption}")

        # Usar un Lock para modificar las listas de forma segura
        with lock:
            clients.append((conn, nombre))
            client_info[nombre] = {
                'mode': mode,
                'encryption': encryption,
                'addr': addr
            }
            print(f"[INFO] Datos de {nombre} recibidos y almacenados.")

            # Si ya hay dos clientes, intercambiar información básica
            if len(clients) == 2:
                (conn1, name1), (conn2, name2) = clients

                print(f"[INFO] Dos clientes conectados sin cifrado: {name1} y {name2}")
                print("[INFO] Realizando intercambio de información (sin claves reales)...")
                
                # Crear respuestas simplificadas (sin claves públicas reales)
                response_para_1 = {
                    "nombre": name2,
                    "public_key_pem": f"DUMMY_PUBLIC_KEY_FOR_{name2}_PLAIN_MODE",
                    "mode": "PLAIN_TEXT",
                    "encryption": "NONE",
                    "server_message": f"Conectado con {name2} (modo sin cifrado)"
                }
                
                response_para_2 = {
                    "nombre": name1,
                    "public_key_pem": f"DUMMY_PUBLIC_KEY_FOR_{name1}_PLAIN_MODE", 
                    "mode": "PLAIN_TEXT",
                    "encryption": "NONE",
                    "server_message": f"Conectado con {name1} (modo sin cifrado)"
                }

                response1_json = json.dumps(response_para_1, indent=2)
                response2_json = json.dumps(response_para_2, indent=2)
                
                print(f"[DEBUG WIRESHARK] Enviando respuesta a {name1} ({len(response1_json)} bytes)")
                print(f"[DEBUG WIRESHARK] Enviando respuesta a {name2} ({len(response2_json)} bytes)")

                send_frame(conn1, response1_json.encode('utf-8'))
                send_frame(conn2, response2_json.encode('utf-8'))
                
                print("[INFO] Intercambio de información completado - chat sin cifrado activo.")

    except (json.JSONDecodeError, KeyError, ConnectionError) as e:
        print(f"[ERROR de Handshake] {e} de {addr}. Cerrando conexión.")
        conn.close()
        return
    except Exception as e:
        print(f"[ERROR INESPERADO] {e}")
        conn.close()
        return

    # Bucle para retransmitir mensajes SIN CIFRADO con framing
    message_count = 0
    while True:
        try:
            message = recv_frame(conn)
            if message is None:
                break

            message_count += 1
            message_json = message.decode('utf-8')
            
            print(f"\n[MENSAJE #{message_count}] De {client_name_local}:")
            print(f"[DEBUG WIRESHARK] Tamaño: {len(message_json)} bytes")
            print(f"[DEBUG WIRESHARK] Contenido completo:")
            print(message_json)
            
            # Extraer el mensaje en texto plano para logging
            try:
                msg_data = json.loads(message_json)
                plain_text = msg_data.get('mensaje_plano', 'NO_PLAIN_TEXT_FOUND')
                print(f"[TEXTO PLANO VISIBLE] '{plain_text}'")
            except:
                print("[ERROR] No se pudo extraer texto plano del JSON")

            with lock:
                if len(clients) < 2:
                    print("[WARNING] Solo hay un cliente conectado, no se puede retransmitir")
                    break
                (conn1, name1), (conn2, name2) = clients

            target_conn = conn2 if conn == conn1 else conn1
            target_name = name2 if conn == conn1 else name1
            
            print(f"[RETRANSMISIÓN] Enviando mensaje a {target_name}...")
            send_frame(target_conn, message)
            print(f"[ÉXITO] Mensaje retransmitido correctamente\n")

        except Exception as e:
            print(f"[ERROR] Error en bucle de mensajes: {e}")
            break

    print(f"[CONEXIÓN CERRADA] {addr} ({client_name_local})")
    with lock:
        # Eliminar al cliente de las listas al desconectarse
        for i, (client_conn, client_name) in enumerate(clients):
            if client_conn == conn:
                clients.pop(i)
                if client_name in client_info:
                    del client_info[client_name]
                print(f"[INFO] Cliente {client_name} eliminado del servidor")
                break
    conn.close()

def start_server():
    print("=== SERVIDOR SIN CIFRADO ===")
    print("[WARNING] Esta versión NO usa cifrado - para análisis con Wireshark")
    print("[WARNING] Todos los mensajes son visibles en TEXTO PLANO")
    print(f"[INFO] Escuchando en puerto {PORT} (diferente del servidor cifrado)")
    print("[WIRESHARK TIP] Filtra por: tcp.port == 65433")
    print("[WIRESHARK TIP] Los mensajes JSON serán completamente legibles\n")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(2)
    print(f"[ESCUCHANDO] Servidor sin cifrado en {HOST}:{PORT}")

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
        print("[INFO] Servidor sin cifrado cerrado correctamente")

if __name__ == "__main__":
    start_server()

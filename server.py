import socket
import threading
import json
import struct

HOST = '127.0.0.1'  # Server IP address (localhost)
PORT = 65432        # Port to listen on

clients = []
public_keys = {}
lock = threading.Lock()  # Lock for safe access to shared resources


def recv_exact(conn, num_bytes):
    """Receives exactly num_bytes or raises ConnectionError."""
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = conn.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed during reception")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(conn):
    """Receives a message with length-prefix framing (uint32 big-endian)."""
    header = recv_exact(conn, 4)
    (length,) = struct.unpack('!I', header)
    if length == 0:
        return b''
    return recv_exact(conn, length)


def send_frame(conn, payload_bytes):
    header = struct.pack('!I', len(payload_bytes))
    conn.sendall(header + payload_bytes)


def handle_client(conn, addr):
    """Handles a client connection securely."""
    print(f"[NEW CONNECTION] {addr} connected.")
    client_name_local = ""

    # Receive initial data (name and key) with framing
    try:
        data_bytes = recv_frame(conn)
        if not data_bytes:
            raise ConnectionError("Client disconnected before sending data.")

        client_data = json.loads(data_bytes.decode('utf-8'))
        name = client_data['name']
        client_name_local = name
        public_key_pem = client_data['public_key_pem'].encode('utf-8')

        # Use a Lock to safely modify the lists
        with lock:
            clients.append((conn, name))
            public_keys[name] = public_key_pem
            print(f"Data and public key from {name} received.")

            # If there are already two clients, exchange their public keys
            if len(clients) == 2:
                (conn1, name1), (conn2, name2) = clients

                print("Two clients connected. Exchanging data...")
                # Send each client the name and key of the other
                package_for_1 = json.dumps({"name": name2, "public_key_pem": public_keys[name2].decode('utf-8')}).encode('utf-8')
                package_for_2 = json.dumps({"name": name1, "public_key_pem": public_keys[name1].decode('utf-8')}).encode('utf-8')

                send_frame(conn1, package_for_1)
                send_frame(conn2, package_for_2)
                print("Data exchanged.")

    except (json.JSONDecodeError, KeyError, ConnectionError) as e:
        print(f"[HANDSHAKE ERROR] {e} from {addr}. Closing connection.")
        conn.close()
        return
    except Exception as e:
        print(f"[UNEXPECTED ERROR] {e}")
        conn.close()
        return

    # Loop to relay encrypted messages with framing
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
            print("Relaying message...")
            send_frame(target_conn, message)

        except Exception:
            break

    print(f"[CONNECTION CLOSED] {addr}")
    with lock:
        # Remove client from lists when disconnecting
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
    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
    except KeyboardInterrupt:
        print("\n[CLOSING SERVER]")
    finally:
        for conn, _ in clients:
            conn.close()
        server.close()


if __name__ == "__main__":
    start_server()

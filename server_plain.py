import socket
import threading
import json
import struct

HOST = '127.0.0.1'  # Server IP address (localhost)
PORT = 65433        # Different port for the unencrypted version

clients = []
client_info = {}  # Stores client information (names, etc.)
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
    """Handles a client connection WITHOUT ENCRYPTION."""
    print(f"[NEW CONNECTION] {addr} connected to unencrypted server.")
    client_name_local = ""

    # Receive initial data (simplified handshake)
    try:
        data_bytes = recv_frame(conn)
        if not data_bytes:
            raise ConnectionError("Client disconnected before sending data.")

        handshake_json = data_bytes.decode('utf-8')
        print(f"[DEBUG WIRESHARK] Handshake received ({len(handshake_json)} bytes):")
        print(f"[DEBUG WIRESHARK] {handshake_json}")
        
        client_data = json.loads(handshake_json)
        name = client_data['name']
        client_name_local = name
        mode = client_data.get('mode', 'UNKNOWN')
        encryption = client_data.get('encryption', 'UNKNOWN')

        print(f"[INFO] Client {name} - Mode: {mode}, Encryption: {encryption}")

        # Use a Lock to safely modify the lists
        with lock:
            clients.append((conn, name))
            client_info[name] = {
                'mode': mode,
                'encryption': encryption,
                'addr': addr
            }
            print(f"[INFO] Data from {name} received and stored.")

            # If there are already two clients, exchange basic information
            if len(clients) == 2:
                (conn1, name1), (conn2, name2) = clients

                print(f"[INFO] Two clients connected without encryption: {name1} and {name2}")
                print("[INFO] Performing information exchange (without real keys)...")
                
                # Create simplified responses (without real public keys)
                response_for_1 = {
                    "name": name2,
                    "public_key_pem": f"DUMMY_PUBLIC_KEY_FOR_{name2}_PLAIN_MODE",
                    "mode": "PLAIN_TEXT",
                    "encryption": "NONE",
                    "server_message": f"Connected with {name2} (unencrypted mode)"
                }
                
                response_for_2 = {
                    "name": name1,
                    "public_key_pem": f"DUMMY_PUBLIC_KEY_FOR_{name1}_PLAIN_MODE", 
                    "mode": "PLAIN_TEXT",
                    "encryption": "NONE",
                    "server_message": f"Connected with {name1} (unencrypted mode)"
                }

                response1_json = json.dumps(response_for_1, indent=2)
                response2_json = json.dumps(response_for_2, indent=2)
                
                print(f"[DEBUG WIRESHARK] Sending response to {name1} ({len(response1_json)} bytes)")
                print(f"[DEBUG WIRESHARK] Sending response to {name2} ({len(response2_json)} bytes)")

                send_frame(conn1, response1_json.encode('utf-8'))
                send_frame(conn2, response2_json.encode('utf-8'))
                
                print("[INFO] Information exchange completed - unencrypted chat active.")

    except (json.JSONDecodeError, KeyError, ConnectionError) as e:
        print(f"[HANDSHAKE ERROR] {e} from {addr}. Closing connection.")
        conn.close()
        return
    except Exception as e:
        print(f"[UNEXPECTED ERROR] {e}")
        conn.close()
        return

    # Loop to relay UNENCRYPTED messages with framing
    message_count = 0
    while True:
        try:
            message = recv_frame(conn)
            if message is None:
                break

            message_count += 1
            message_json = message.decode('utf-8')
            
            print(f"\n[MESSAGE #{message_count}] From {client_name_local}:")
            print(f"[DEBUG WIRESHARK] Size: {len(message_json)} bytes")
            print(f"[DEBUG WIRESHARK] Full content:")
            print(message_json)
            
            # Extract plain text message for logging
            try:
                msg_data = json.loads(message_json)
                plain_text = msg_data.get('plain_message', 'NO_PLAIN_TEXT_FOUND')
                print(f"[VISIBLE PLAIN TEXT] '{plain_text}'")
            except:
                print("[ERROR] Could not extract plain text from JSON")

            with lock:
                if len(clients) < 2:
                    print("[WARNING] Only one client connected, cannot relay")
                    break
                (conn1, name1), (conn2, name2) = clients

            target_conn = conn2 if conn == conn1 else conn1
            target_name = name2 if conn == conn1 else name1
            
            print(f"[RELAY] Sending message to {target_name}...")
            send_frame(target_conn, message)
            print(f"[SUCCESS] Message relayed successfully\n")

        except Exception as e:
            print(f"[ERROR] Error in message loop: {e}")
            break

    print(f"[CONNECTION CLOSED] {addr} ({client_name_local})")
    with lock:
        # Remove client from lists when disconnecting
        for i, (client_conn, client_name) in enumerate(clients):
            if client_conn == conn:
                clients.pop(i)
                if client_name in client_info:
                    del client_info[client_name]
                print(f"[INFO] Client {client_name} removed from server")
                break
    conn.close()

def start_server():
    print("=== UNENCRYPTED SERVER ===")
    print("[WARNING] This version does NOT use encryption - for Wireshark analysis")
    print("[WARNING] All messages are visible in PLAIN TEXT")
    print(f"[INFO] Listening on port {PORT} (different from encrypted server)")
    print("[WIRESHARK TIP] Filter by: tcp.port == 65433")
    print("[WIRESHARK TIP] JSON messages will be completely readable\n")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(2)
    print(f"[LISTENING] Unencrypted server on {HOST}:{PORT}")

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
        print("[INFO] Unencrypted server closed correctly")

if __name__ == "__main__":
    start_server()

import socket
import threading
import sys
import json
import struct
from crypto_utils_plain import User, load_public_key, encrypt_message, decrypt_message
import os

HOST = '127.0.0.1'
PORT = 65433  # Different port for the unencrypted version

def recv_exact(sock, num_bytes):
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed during reception")
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
    """Thread to listen and process incoming messages WITHOUT ENCRYPTION."""
    while True:
        try:
            data = recv_frame(client_socket)
            if data is None:
                print("\n[CONNECTION CLOSED BY SERVER]")
                break

            message_json = data.decode('utf-8')
            print(f"\n[DEBUG WIRESHARK] Packet received ({len(message_json)} bytes):")
            print(f"[DEBUG WIRESHARK] Complete JSON: {message_json}")
            
            # Process unencrypted message
            decrypted_message = decrypt_message(
                message_json,
                user.private_key,  # Dummy
                user.recipient_public_key,  # Dummy
            )
            
            # Show message
            print(f"\rMessage from {user.recipient_name}: {decrypted_message}\nYou> ", end="")

        except json.JSONDecodeError:
            print("\n[ERROR] Received a malformed message.")
            print(f"[DEBUG] Received content: {data}")
            continue
        except Exception as e:
            print(f"\n[ERROR] Error receiving or processing message: {e}")
            break
    client_socket.close()

def start_client(name):
    print(f"\n=== UNENCRYPTED CLIENT - {name} ===")
    print("[WARNING] This version does NOT use encryption - for Wireshark analysis")
    print("[WARNING] All messages travel in PLAIN TEXT over the network\n")
    
    user = User(name)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print(f"[ERROR] Could not connect to server at {HOST}:{PORT}. Is it online?")
        print("[INFO] Make sure to run: python server_plain.py")
        return

    # Simplified handshake - only names (without real public keys)
    print("Connected to server. Sending data...")
    handshake_data = {
        "name": user.name,
        "public_key_pem": user.serialize_public_key().decode('utf-8'),  # Dummy
        "mode": "PLAIN_TEXT",
        "encryption": "NONE"
    }
    
    handshake_json = json.dumps(handshake_data, indent=2)
    print(f"[DEBUG WIRESHARK] Handshake sent ({len(handshake_json)} bytes):")
    print(f"[DEBUG WIRESHARK] {handshake_json}")
    
    send_frame(client_socket, handshake_json.encode('utf-8'))

    print("Waiting for other user's data...")
    response_data = recv_frame(client_socket)
    if not response_data:
        print("\n[ERROR] Server closed connection unexpectedly.")
        client_socket.close()
        return

    response_json = response_data.decode('utf-8')
    print(f"[DEBUG WIRESHARK] Handshake response received ({len(response_json)} bytes):")
    print(f"[DEBUG WIRESHARK] {response_json}")
    
    recipient_info = json.loads(response_json)
    user.recipient_name = recipient_info['name']
    # We don't load real keys because we don't use them
    user.recipient_public_key = "DUMMY_KEY"

    print(f"\n¡All ready! UNENCRYPTED chat with '{user.recipient_name}' is active.")
    print("COMMANDS:")
    print("- Type any message and press Enter")
    print("- '/showkeys' to view dummy keys")
    print("- '/debug' to show debug information")
    print("- '/exit' to quit")
    print("\n[WIRESHARK TIP] Filter by: tcp.port == 65433")
    print("[WIRESHARK TIP] Look for JSON in TCP packets\n")

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket, user))
    receive_thread.daemon = True
    receive_thread.start()

    while True:
        try:
            message_to_send = input("You> ")
            if message_to_send.lower() in ('exit', '/exit'):
                break
            
            if message_to_send.strip() == '/showkeys':
                try:
                    priv_pem = user.serialize_private_key()
                    pub_pem = user.serialize_public_key()
                    print("\n----- DUMMY KEYS (UNENCRYPTED MODE) -----")
                    print(priv_pem.decode('utf-8'))
                    print(pub_pem.decode('utf-8'))
                    print("These keys are fake - no real cryptography is used\n")
                except Exception as e:
                    print(f"[ERROR] Could not show keys: {e}")
                continue
            
            if message_to_send.strip() == '/debug':
                print(f"\n----- DEBUG INFORMATION -----")
                print(f"Name: {user.name}")
                print(f"Recipient: {user.recipient_name}")
                print(f"Server port: {PORT}")
                print(f"Mode: UNENCRYPTED (PLAIN TEXT)")
                print(f"Wireshark tip: tcp.port == {PORT} and tcp contains '{message_to_send}'")
                print("All messages are visible in plain text\n")
                continue

            # Create unencrypted message
            plain_package = encrypt_message(
                message_to_send,
                user.recipient_public_key,  # Dummy
                user.private_key,  # Dummy
            )
            
            print(f"[DEBUG WIRESHARK] Sending message ({len(plain_package)} bytes):")
            print(f"[DEBUG WIRESHARK] {plain_package}")
            
            send_frame(client_socket, plain_package.encode('utf-8'))
            
        except (KeyboardInterrupt, EOFError):
            break
        except Exception as e:
            print(f"Error sending message: {e}")
            break

    print("\nExiting unencrypted chat...")
    client_socket.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client_plain.py <your_name>")
        print("Example: python client_plain.py Alice")
    else:
        username = sys.argv[1]
        start_client(username)

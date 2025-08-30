import socket
import threading
import sys
import json
import struct
from crypto_utils import User, load_public_key, encrypt_message, decrypt_message
import os

HOST = '127.0.0.1'
PORT = 65432


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
    """Thread to listen and decrypt incoming messages."""
    while True:
        try:
            data = recv_frame(client_socket)
            if data is None:
                print("\n[CONNECTION CLOSED BY SERVER]")
                break

            encrypted_package_json = data.decode('utf-8')
            decrypted_message = decrypt_message(
                encrypted_package_json,
                user.private_key,
                user.recipient_public_key,  # replaced by sender's public key when handshake packet arrives from server
            )
            # Print the message on a new line to not interrupt what the user is typing
            print(f"\rMessage from {user.recipient_name}: {decrypted_message}\nYou> ", end="")

        except json.JSONDecodeError:
            print("\n[ERROR] Received a malformed message.")
            continue
        except Exception as e:
            print(f"\n[ERROR] Error receiving or decrypting message: {e}")
            break
    client_socket.close()


def start_client(name):
    user = User(name)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("[ERROR] Could not connect to server. Is it online?")
        return

    # Key and name exchange through a JSON packet with framing
    print("Connected to server. Sending data and public key...")
    handshake_data = {
        "name": user.name,
        "public_key_pem": user.serialize_public_key().decode('utf-8')
    }
    send_frame(client_socket, json.dumps(handshake_data).encode('utf-8'))

    print("Waiting for other user's data...")
    response_data = recv_frame(client_socket)
    if not response_data:
        print("\n[ERROR] Server closed connection unexpectedly.")
        client_socket.close()
        return

    recipient_info = json.loads(response_data.decode('utf-8'))
    user.recipient_name = recipient_info['name']
    recipient_public_key_pem = recipient_info['public_key_pem'].encode('utf-8')
    user.recipient_public_key = load_public_key(recipient_public_key_pem)

    print(f"All ready! Chat with '{user.recipient_name}' is active.")
    print("Type your message and press Enter. Commands: '/showkeys' to view your keys, '/regenerate' to regenerate keys, '/exit' to quit.")

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
                    print("\n----- YOUR PRIVATE KEY (PEM) -----\n" + priv_pem.decode('utf-8'))
                    print("----- YOUR PUBLIC KEY (PEM) -----\n" + pub_pem.decode('utf-8'))
                except Exception as e:
                    print(f"[ERROR] Could not show keys: {e}")
                continue
            if message_to_send.strip() == '/regenerate':
                try:
                    if user.regenerate_keys():
                        print("[INFO] Keys regenerated and saved successfully.")
                        print("[WARNING] Previous keys are no longer valid for this user.")
                    else:
                        print("[ERROR] Could not regenerate keys.")
                except Exception as e:
                    print(f"[ERROR] Error regenerating keys: {e}")
                continue
            if message_to_send.strip() == '/keyinfo':
                try:
                    keys_dir = "keys"
                    priv_key_file = f"{keys_dir}/{user.name}_private.key"
                    pub_key_file = f"{keys_dir}/{user.name}_public.key"
                    
                    print(f"\n----- KEY INFORMATION FOR {user.name.upper()} -----")
                    print(f"Keys directory: {os.path.abspath(keys_dir)}")
                    print(f"Private key: {'✓ Exists' if os.path.exists(priv_key_file) else '✗ Does not exist'}")
                    print(f"Public key: {'✓ Exists' if os.path.exists(pub_key_file) else '✗ Does not exist'}")
                    
                    if os.path.exists(priv_key_file):
                        file_size = os.path.getsize(priv_key_file)
                        print(f"Private file size: {file_size} bytes")
                    if os.path.exists(pub_key_file):
                        file_size = os.path.getsize(pub_key_file)
                        print(f"Public file size: {file_size} bytes")
                except Exception as e:
                    print(f"[ERROR] Could not show key information: {e}")
                continue

            encrypted_package = encrypt_message(
                message_to_send,
                user.recipient_public_key,
                user.private_key,
            )
            send_frame(client_socket, encrypted_package.encode('utf-8'))
        except (KeyboardInterrupt, EOFError):
            break
        except Exception as e:
            print(f"Error sending message: {e}")
            break

    print("\nExiting chat...")
    client_socket.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py <your_name>")
    else:
        username = sys.argv[1]
        start_client(username)

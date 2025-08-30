# Chat with Asymmetric Key Cryptography

This project implements a point-to-point chat system with **two versions** for educational comparison:

1. **🔒 Secure Version**: Uses hybrid encryption with RSA-OAEP + AES-GCM and RSA-PSS digital signatures
2. **🔓 Unencrypted Version**: Transmits messages in plain text for network traffic analysis with Wireshark

Both versions use the same relay server architecture where the server only forwards messages without reading content (in the encrypted version).

## 🚀 Quick Start

### Requirements

- Python 3.10+
- Dependencies in `requirements.txt`

### Installation

```bash
pip install -r requirements.txt
```

### Choose Your Version

| Version            | Purpose                    | Files                                 | Port  |
| ------------------ | -------------------------- | ------------------------------------- | ----- |
| 🔒 **Encrypted**   | Secure communication       | `server.py` + `client.py`             | 65432 |
| 🔓 **Unencrypted** | Traffic analysis/education | `server_ plain.py` + `client_plain.py` | 65433 |

---

## 🔒 Encrypted Version (Secure)

### How to Run

1. **Start the encrypted server:**

```bash
python server.py
```

2. **Start two clients in separate terminals:**

```bash
python client.py Alice
python client.py Bob
```

### Security Features

- **Key Persistence**: Cryptographic keys are stored locally in base64 format
- **Existing Key Verification**: The system checks if keys exist before generating new ones
- **Secure Storage**: Keys are saved in a separate `keys/` directory
- **Key Regeneration**: Ability to regenerate keys when needed

### Client Commands (Encrypted Version)

- `/showkeys`: Prints your private key (PEM, unencrypted) and public key (PEM) to console. Use only for educational purposes.
- `/regenerate`: Regenerates new cryptographic keys and saves them locally.
- `/keyinfo`: Shows information about the status of stored keys.
- `/exit`: Closes the client.

---

## 🔓 Unencrypted Version (Educational)

⚠️ **WARNING**: This version is **ONLY** for educational purposes and traffic analysis. **NEVER** use for real communications.

### How to Run

1. **Start the unencrypted server:**

```bash
python server_plain.py
```

2. **Start two clients in separate terminals:**

```bash
python client_plain.py Alice
python client_plain.py Bob
```

### Purpose

This version demonstrates the **risks of unencrypted communication** by:

- Transmitting all messages in **plain text**
- Making usernames, messages, and protocol structure **completely visible** in network traffic
- Providing no authentication or integrity protection

### Client Commands (Unencrypted Version)

- `/showkeys`: Shows dummy keys (not real cryptography)
- `/debug`: Shows debugging information useful for Wireshark analysis
- `/exit`: Exit

### Wireshark Analysis

- **Recommended filter**: `tcp.port == 65433`
- **Text search**: Messages appear as readable JSON with `"plain_message"` field
- **Packet structure**: All data is completely visible in network capture
- See `demo_wireshark.md` for detailed analysis guide

---

## Key Persistence System

### File Structure

```
keys/
├── Alice_private.key    # Alice's private key in base64
├── Alice_public.key     # Alice's public key in base64
├── Bob_private.key      # Bob's private key in base64
└── Bob_public.key       # Bob's public key in base64
```

### Behavior

1. **First Execution**: New RSA-2048 keys are generated and stored in base64
2. **Subsequent Executions**: Existing keys are loaded from files
3. **Verification**: The system verifies key integrity before using them
4. **Regeneration**: `/regenerate` command allows creating new keys when needed

### Security

- Keys are stored in base64 format for better compatibility
- The `keys/` directory is excluded from version control (`.gitignore`)
- Private keys are never transmitted over the network
- Only public keys are exchanged during handshake

## Cryptographic Model

- Each client generates an RSA pair (2048 bits) at session start.
- Handshake: the client sends `name` and its PEM public key to the server; the server exchanges them between the two connected clients.
- When sending a message:
  - A random AES-256 symmetric key is generated per message.
  - The message is encrypted with AES-GCM (random nonce).
  - The AES key is wrapped with RSA-OAEP using the recipient's public key.
  - The package (without signature) is signed with RSA-PSS using the sender's private key.
- When receiving a message:
  - The signature is verified with the sender's public key (received in handshake).
  - The AES key is decrypted with the recipient's private key and then the message with AES-GCM.

## 📊 Version Comparison

| Aspect         | 🔒 Encrypted Version         | 🔓 Unencrypted Version                |
| -------------- | ---------------------------- | ------------------------------------- |
| **Port**       | 65432                        | 65433                                 |
| **Files**      | `server.py` + `client.py`    | `server_plain.py` + `client_plain.py` |
| **Messages**   | Encrypted with AES-GCM + RSA | JSON with plain text                  |
| **Keys**       | Real RSA-2048                | Dummy keys                            |
| **Signatures** | Real RSA-PSS                 | No signatures                         |
| **Network**    | Unreadable content           | Completely visible                    |
| **Purpose**    | Secure communication         | Educational analysis                  |

## 🛠️ Technical Details (Encrypted Version)

### Cryptographic Model

- Each client generates an RSA pair (2048 bits) at session start.
- Handshake: the client sends `name` and its PEM public key to the server; the server exchanges them between the two connected clients.
- When sending a message:
  - A random AES-256 symmetric key is generated per message.
  - The message is encrypted with AES-GCM (random nonce).
  - The AES key is wrapped with RSA-OAEP using the recipient's public key.
  - The package (without signature) is signed with RSA-PSS using the sender's private key.
- When receiving a message:
  - The signature is verified with the sender's public key (received in handshake).
  - The AES key is decrypted with the recipient's private key and then the message with AES-GCM.

### Implementation Notes

- The current server pairs exactly two clients and relays between them.
- Message framing with length-prefix (uint32 big-endian) is used for reliability over TCP.
- Keys are maintained between sessions for user convenience.
- In case of key corruption, use `/regenerate` to create new ones.

## 📚 Additional Resources

- **`Flows.md`**: Detailed system architecture and communication flows
- **`demo_wireshark.md`**: Complete guide for network traffic analysis
- **`test_keys.py`**: Script to test the key persistence system

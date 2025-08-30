# Wireshark Analysis Guide - Unencrypted Chat

This guide will help you analyze the network traffic of the unencrypted chat using Wireshark.

## Initial Setup

### 1. Prepare the Environment

```bash
# Terminal 1: Unencrypted server
python server_plain.py

# Terminal 2: Alice client
python client_plain.py Alice

# Terminal 3: Bob client
python client_plain.py Bob
```

### 2. Configure Wireshark

1. **Open Wireshark** as administrator
2. **Select interface**: Loopback (127.0.0.1) or "lo" on Linux/macOS
3. **Apply filter**: `tcp.port == 65433`
4. **Start capture**

## Traffic Patterns to Observe

### Handshake (Initial Connection)

Look for these packets at the beginning:

```json
{
  "name": "Alice",
  "public_key_pem": "DUMMY_PUBLIC_KEY_FOR_Alice_PLAIN_MODE",
  "mode": "PLAIN_TEXT",
  "encryption": "NONE"
}
```

### Chat Messages

Each message appears as readable JSON:

```json
{
  "version": 1,
  "encryption": "NONE",
  "message_type": "PLAIN_TEXT",
  "plain_message": "Hello Bob, this message is completely visible",
  "timestamp": "a1b2c3d4",
  "dummy_signature": "NO_SIGNATURE_PLAIN_MODE"
}
```

## Useful Wireshark Filters

### Basic Filters

```
tcp.port == 65433                          # All chat traffic
tcp.port == 65433 and tcp.len > 0         # Only packets with data
frame contains "plain_message"             # Packets with chat messages
frame contains "Alice"                     # Packets mentioning Alice
```

### Advanced Filters

```
tcp.port == 65433 and tcp.stream eq 0     # Only the first TCP connection
tcp.port == 65433 and tcp.stream eq 1     # Only the second TCP connection
json.value.string contains "Hello"        # Search for specific messages
```

## Packet Structure

### 1. TCP Framing

- **4 bytes**: Message length (uint32 big-endian)
- **N bytes**: JSON payload in UTF-8

### 2. JSON Content

- **Handshake**: name, dummy key, mode
- **Messages**: version, type, plain message, timestamp

### 3. Communication Flow

1. Client → Server: Handshake with name
2. Server → Client: Response with other user's data
3. Client ↔ Server ↔ Client: Message relay

## Debug Commands in the Client

```bash
# In the client, try these commands:
/debug          # Shows useful information for Wireshark
/showkeys       # Shows dummy keys
Hello world     # Normal message that will appear in Wireshark
```

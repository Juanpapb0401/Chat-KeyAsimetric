# Workshop: Network Traffic Analysis - Secure vs Insecure Communication

## Workshop Objective

This educational workshop aims to **demonstrate the importance of encryption in communications** through comparative analysis of network traffic using Wireshark. We will implement and analyze two versions of a chat system: one **secure** (with asymmetric cryptography) and another **insecure** (without encryption), to observe differences in the level of information exposure.

## Theoretical Context

### Why is encryption important?

In today's digital world, information constantly travels through networks that can be intercepted by attackers. Without adequate protection measures, sensitive data such as:

- Private conversations
- Access credentials
- Personal information
- Corporate data

Can be captured and read by anyone with network access.

### Asymmetric Cryptography: The Solution

**Asymmetric key cryptography** (also known as public key cryptography) solves this problem through:

- **Confidentiality**: Only the recipient can read the message
- **Authenticity**: The sender's identity is verified
- **Integrity**: Any message modification is detected
- **Non-repudiation**: The sender cannot deny having sent the message

## System Architecture

### Implemented Chat System

We have developed a point-to-point chat system that uses:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │◄──►│   Server    │◄──►│   Client    │
│   (Alice)   │    │   (Relay)   │    │    (Bob)    │
└─────────────┘    └─────────────┘    └─────────────┘
```

**Main components:**

- **Server**: Acts as relay, exchanges public keys and retransmits messages
- **Client**: Generates keys, encrypts/decrypts messages, handles user interface
- **Protocol**: TCP framing with length-prefix for reliable communication

## Secure Version: Cryptographic Implementation

### Security Model

The secure version implements a **hybrid scheme** that combines:

1. **RSA-2048** for asymmetric cryptography
2. **AES-256-GCM** for symmetric encryption
3. **RSA-PSS** for digital signatures

### Secure Communication Flow

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as Server
    participant B as Bob

    Note over A,B: 1. Key Generation
    A->>A: Generate RSA pair (private_A, public_A)
    B->>B: Generate RSA pair (private_B, public_B)

    Note over A,B: 2. Public Key Exchange
    A->>S: {name: "Alice", public_A}
    B->>S: {name: "Bob", public_B}
    S->>A: {name: "Bob", public_B}
    S->>B: {name: "Alice", public_A}

    Note over A,B: 3. Encrypted Message Sending
    A->>A: Generate random AES_key
    A->>A: Encrypt message with AES-GCM
    A->>A: Encrypt AES_key with public_B (RSA-OAEP)
    A->>A: Sign packet with private_A (RSA-PSS)
    A->>S: Encrypted and signed packet
    S->>B: Relay packet

    Note over A,B: 4. Verification and Decryption
    B->>B: Verify signature with public_A
    B->>B: Decrypt AES_key with private_B
    B->>B: Decrypt message with AES-GCM
```

### Security Features

- **Confidentiality**: Each message uses a unique AES-256 key, wrapped with RSA-OAEP
- **Authenticity**: RSA-PSS signatures guarantee sender identity
- **Integrity**: AES-GCM detects any modification
- **Persistence**: Keys are stored locally for consistent identity

## Insecure Version: Without Protection

### Educational Purpose

The insecure version **deliberately omits all cryptographic protection** to demonstrate the risks of unencrypted communications.

### Insecure Version Features

- **No encryption**: All messages travel in plain text
- **No signatures**: No authenticity verification
- **No verification**: Anyone can read or modify messages
- **Visible protocol**: The entire communication structure is observable

### Insecure Communication Flow

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as Server
    participant B as Bob
    participant E as Attacker

    A->>S: {name: "Alice", mode: "PLAIN_TEXT"}
    B->>S: {name: "Bob", mode: "PLAIN_TEXT"}
    S->>A: {name: "Bob"}
    S->>B: {name: "Alice"}

    Note over A,B: Message completely visible
    A->>S: {"plain_message": "Hello Bob, I have confidential information"}
    Note over E: Attacker intercepts and reads everything
    E->>E: Reads: "Hello Bob, I have confidential information"
    S->>B: {"plain_message": "Hello Bob, I have confidential information"}
```




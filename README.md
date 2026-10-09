# 🔐 ENCRYPTO

### Private • Real-Time • Encrypted Communication

ENCRYPTO is a real-time secure communication platform designed for private, ephemeral conversations.

The application combines client-side cryptography, real-time Socket.IO communication, private encrypted messaging, rule-based threat detection, and forensic incident logging in a futuristic communication interface.

> **Project Status: Working Prototype**

---

## ✨ Features

### 🔐 Client-Side Encryption

ENCRYPTO performs message encryption in the user's browser before the message is transmitted.

Room messages use:

- AES-GCM
- 256-bit encryption keys
- Random initialization vectors
- Randomly generated room secrets

The 4-character room code is used for room discovery and joining, not as the encryption key.

---

### 🔑 ECDH Private Messaging

Private conversations use:

- ECDH
- P-256
- Browser-generated key pairs
- Derived AES-GCM shared keys

Each browser generates its own cryptographic identity.

Private messages are encrypted before transmission.

---

### 🏠 Ephemeral Rooms

Rooms are designed to be temporary.

Features include:

- Custom 4-character room codes
- Maximum 2 users per room
- Real-time room membership
- Automatic room destruction when the last user leaves
- No normal conversation history stored on the server

---

### 💬 Real-Time Messaging

ENCRYPTO uses Socket.IO for real-time communication.

Supported communication:

- Room messaging
- Private messaging
- Typing indicators
- Real-time member updates
- Connection status
- System notifications

---

### 🛡️ Rule-Based Threat Detection

ENCRYPTO includes a client-side rule-based moderation engine.

It analyzes message text before encryption and detects potentially dangerous terminology and threat patterns.

Current severity levels:

| Level | Description |
|---|---|
| NONE | No matching rule |
| LOW | Potentially sensitive terminology |
| MEDIUM | Weapon or threat-related terminology |
| HIGH | Violent intent or dangerous activity |
| CRITICAL | Direct violent threat |

Detection categories include:

- `DIRECT_THREAT`
- `THREAT_CONTEXT`
- `VIOLENCE`
- `WEAPON`
- `SENSITIVE_TERM`
- `SENSITIVE_CONTEXT`

The moderation system currently uses regular expressions and rule-based scoring rather than machine learning.

---

### 🚨 Forensic Incident Logging

Only messages identified as flagged by the moderation system are eligible for forensic storage.

Normal messages are not stored.

Flagged incidents can contain:

- Incident ID
- Room code
- Timestamp
- Sender username
- Sender IP
- Receiver username
- Receiver IP
- Flagged message
- Severity
- Category
- Detection reason
- Risk score

The forensic records are stored using SQLite.

---


---

# 🚨 Moderation Example

A message containing potentially dangerous content can trigger a warning.

Example severity:

```text
HIGH
```

or:

```text
CRITICAL
```

The message is still delivered, but the moderation result is attached to the message.

If flagged, the specific plaintext can also be recorded as a forensic incident.

---

# 🔬 Forensic Database Testing

To inspect stored incidents locally:

```bash
cd server
```

Then:

```bash
node -e "const sqlite3=require('sqlite3').verbose(); const db=new sqlite3.Database('./encrypto.db'); db.all('SELECT * FROM incidents ORDER BY id DESC', (err, rows) => { if(err) console.error(err); else console.table(rows); db.close(); });"
```

---

# 🔐 Security Design

ENCRYPTO is designed around the principle of minimizing server-side plaintext exposure.

### Server

The server handles:

- Room management
- User presence
- Socket.IO communication
- Encrypted message relay
- Encrypted private-message relay
- Moderation metadata
- Flagged forensic records

### Client

The client handles:

- Key generation
- Encryption
- Decryption
- Message moderation
- Private-message cryptography
- UI rendering

---

# ⚠️ Security Considerations

ENCRYPTO is currently a prototype and should not be considered a production-grade secure messenger.

Important limitations include:

### Client-Side Moderation

Because moderation runs in the browser, a modified client can bypass the moderation system.

### Public-Key Authentication

ECDH public keys are exchanged through the application server. The current implementation does not independently authenticate public keys against an active malicious server.

### Forensic Storage

Flagged messages receive different privacy treatment from normal messages because their plaintext can be submitted for forensic storage.

### IP Addresses

IP addresses are observed by the backend as part of incident logging. In real deployments, proxies, VPNs, NAT, and shared networks can affect how an IP represents a user.

### SQLite

SQLite is appropriate for the current prototype but is not necessarily the best storage architecture for a large-scale production deployment.

---

# 🧪 Current Testing

The following functionality has been tested:

- [x] Room creation
- [x] Room joining
- [x] Two-user room limit
- [x] Room encryption establishment
- [x] AES-GCM room messaging
- [x] ECDH private messaging
- [x] Typing indicators
- [x] Member presence
- [x] Room leaving
- [x] Ephemeral room destruction
- [x] Rule-based moderation
- [x] HIGH severity detection
- [x] CRITICAL severity detection
- [x] Forensic SQLite storage

---

# 🛣️ Future Improvements

Potential future improvements include:

- Production HTTPS deployment
- Environment-based configuration
- Strong public-key authentication
- Digital signatures
- Better moderation accuracy
- Rate limiting
- Abuse prevention
- Production database architecture
- Secure administrative forensic access
- Automated security testing
- Automated deployment
- Monitoring and logging infrastructure

---

# 🎯 Project Goals

ENCRYPTO was designed to explore the combination of:

```text
Real-Time Communication
          +
Client-Side Cryptography
          +
Private Messaging
          +
Threat Detection
          +
Forensic Logging
          +
Ephemeral Data
```

The goal is to demonstrate how privacy-oriented communication and security monitoring can coexist within a real-time web application while minimizing persistent storage of normal conversations.

---

# 📜 License

This project is currently intended as an educational and experimental project.

Add an appropriate open-source license before distributing the project publicly.

---

# 👨‍💻 Project

**ENCRYPTO**

Private Communication • Real-Time Messaging • Client-Side Cryptography • Threat Detection

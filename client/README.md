# 🔐 ENCRYPTO

### Private • Real-Time • Encrypted Communication

ENCRYPTO is a real-time secure communication platform designed for private, ephemeral conversations.

The application combines client-side cryptography, real-time Socket.IO communication, private encrypted messaging, rule-based threat detection, forensic incident logging, and ephemeral image sharing in a futuristic communication interface.

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

### 🖼️ Ephemeral Image Sharing

ENCRYPTO supports real-time image sharing.

Supported formats:

- PNG
- JPEG / JPG
- WEBP
- GIF

Current image limit:

- 5 MB on the client

Images are transmitted as temporary data and are not stored in the forensic database.

> Images are intentionally not encrypted in the current implementation.

---

## 🧠 System Architecture

```text
                         ENCRYPTO
                            │
             ┌──────────────┴──────────────┐
             │                             │
          CLIENT                         SERVER
             │                             │
       React + Vite                 Node.js + Express
             │                             │
       Web Crypto API                 Socket.IO
             │                             │
     ┌───────┴────────┐             ┌──────┴─────────┐
     │                │             │                │
 AES-GCM           ECDH          Room Manager    SQLite
     │                │             │                │
     │                │             │          Flagged Incidents
     │                │             │
     └────────────┬───┘             │
                  │                 │
                  └──── Socket.IO ──┘
```

---

# 🔒 Encryption Architecture

## Room Messaging

Room messages follow this flow:

```text
User writes message
        │
        ▼
Client-side moderation
        │
        ▼
Generate random IV
        │
        ▼
AES-GCM encryption
        │
        ▼
Encrypted ciphertext
        │
        ▼
Socket.IO
        │
        ▼
Other room member
        │
        ▼
AES-GCM decryption
        │
        ▼
Plaintext message
```

The server relays the encrypted payload and does not decrypt normal room messages.

---

## Private Messaging

Private messages use ECDH to establish a shared encryption key.

```text
User A
  │
  ├── ECDH Private Key
  └── Public Key
          │
          ▼
       Server
          │
          ▼
     User B Public Key
          │
          ▼
      ECDH Derivation
          │
          ▼
    Shared AES-GCM Key
          │
          ▼
     Encrypted Message
```

The server forwards the encrypted private message but does not receive the plaintext message during normal private messaging.

---

# 🛡️ Moderation Architecture

The moderation engine runs on the client.

```text
Message Input
     │
     ▼
Normalize Text
     │
     ▼
Rule Matching
     │
     ├───────────────┐
     │               │
     ▼               ▼
No Match          Match Found
     │               │
     ▼               ▼
NONE           Calculate Score
                     │
                     ▼
               Determine Level
                     │
                     ▼
            Encrypt Message
                     │
                     ▼
                Socket.IO
```

The moderation system is currently rule-based and does not use an AI model.

---

# 🗃️ Data Storage Model

ENCRYPTO follows an ephemeral communication model.

### Normal Messages

Normal messages are:

- Encrypted client-side
- Relayed through Socket.IO
- Not stored in SQLite
- Not retained as server-side chat history

### Flagged Messages

A specific flagged message may be sent separately for forensic storage.

```text
Flagged Message
      │
      ├── Encrypted copy → recipient
      │
      └── Flagged plaintext → forensic database
```

This creates a deliberate distinction between normal encrypted communication and flagged forensic records.

---

# 🗄️ Database

SQLite is used for forensic incident storage.

The main table is:

```text
incidents
```

Schema:

| Field | Description |
|---|---|
| id | Incident ID |
| room_code | Room where incident occurred |
| timestamp | Incident timestamp |
| sender_username | Sender |
| sender_ip | Sender network address |
| receiver_username | Receiver |
| receiver_ip | Receiver network address |
| message | Flagged message |
| severity | Risk level |
| category | Detection category |
| reason | Detection reason |
| score | Risk score |

The database file is generated automatically:

```text
server/encrypto.db
```

---

# 🧰 Technology Stack

## Frontend

- React
- Vite
- JavaScript
- Web Crypto API
- Socket.IO Client
- Lucide React
- CSS

## Backend

- Node.js
- Express
- Socket.IO
- CORS
- SQLite
- sqlite3
- Nodemon

## Cryptography

- AES-GCM
- ECDH
- P-256
- Web Crypto API

---

# 📁 Project Structure

```text
ENCRYPTO/
│
├── client/
│   │
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── crypto.js
│   │   ├── privateCrypto.js
│   │   └── moderation.js
│   │
│   ├── package.json
│   └── vite.config.js
│
├── server/
│   │
│   ├── server.js
│   ├── database.js
│   ├── package.json
│   └── encrypto.db
│
├── .gitignore
└── README.md
```

> `encrypto.db` is a local runtime database and should not normally be committed to source control.

---

# 🚀 Installation

## Requirements

Install:

- Node.js
- npm
- Git

---

# 1. Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd ENCRYPTO
```

---

# 2. Install Frontend Dependencies

```bash
cd client
npm install
```

---

# 3. Install Backend Dependencies

Open another terminal:

```bash
cd server
npm install
```

If SQLite has not been installed:

```bash
npm install sqlite3
```

---

# ▶️ Running the Application

## Start Backend

From:

```text
ENCRYPTO/server
```

run:

```bash
npm run dev
```

The backend runs on:

```text
http://localhost:5000
```

---

## Start Frontend

From:

```text
ENCRYPTO/client
```

run:

```bash
npm run dev
```

The frontend normally runs on:

```text
http://localhost:5173
```

Open the frontend URL in your browser.

---

# 👥 Using ENCRYPTO

## Create a Room

1. Open ENCRYPTO.
2. Select Create Room.
3. Enter a username.
4. Choose a 4-character room code.
5. Create the room.
6. Share the room code with another user.

Example:

```text
Room Code: om27
```

---

## Join a Room

1. Enter your username.
2. Enter the 4-character room code.
3. Join the room.
4. Wait for encryption to become ready.
5. Start messaging.

Only two users can occupy a room.

---

# 💬 Private Chat

When two users are present:

1. Select the other member.
2. The private chat interface opens.
3. Messages are encrypted using the private ECDH-based encryption system.
4. The recipient decrypts the message locally.

---

# 🖼️ Sending Images

Click the image button in the message composer.

Supported formats:

```text
PNG
JPG
JPEG
WEBP
GIF
```

Maximum size:

```text
5 MB
```

Images are transmitted temporarily and are not stored in the forensic database.

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
- Image relay
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

### Images

Images are intentionally not encrypted in the current implementation.

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
- [x] PNG image sharing
- [x] JPG/JPEG image sharing
- [x] WEBP image sharing
- [x] GIF image sharing
- [x] Ephemeral image transmission

---

# 🛣️ Future Improvements

Potential future improvements include:

- Production HTTPS deployment
- Environment-based configuration
- Strong public-key authentication
- Digital signatures
- Better moderation accuracy
- Image security improvements
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

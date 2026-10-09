const express = require("express");
const http = require("http");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const crypto = require("crypto");
const { Server } = require("socket.io");

const {
  saveIncident,
  getIncidents,
} = require("./database");

// =========================================================
// CONFIG
// =========================================================

const PORT = Number(process.env.PORT) || 5001;
const MAX_ROOM_USERS = 2;
const KNOCK_COOLDOWN_MS = 20 * 1000;
const ROOM_CODE_LENGTH = 4;
const MAX_ROOMS = 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const MAX_CIPHERTEXT_LEN = 20000;
const MAX_IV_LEN = 500;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const ROOM_PASSWORD_MAX_LEN = 64;

if (!process.env.CLIENT_URL) {
  console.warn(
    "[SECURITY] CLIENT_URL not set, defaulting to http://localhost:5173"
  );
}

// =========================================================
// APP
// =========================================================

const app = express();

app.disable("x-powered-by");

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; connect-src 'self' wss: https:; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
  );
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  if (TRUST_PROXY) {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains"
    );
  }
  next();
});

// ponytail: single limiter covers HTTP + sockets (ceiling: in-memory, resets on restart; upgrade to redis for multi-instance)
function makeLimiter(maxSize, pruneTo) {
  const buckets = new Map();

  function check(id, key, limit, windowMs) {
    const now = Date.now();
    const mapKey = `${id}:${key}`;
    let entry = buckets.get(mapKey);

    if (!entry || now - entry.start > windowMs) {
      entry = { count: 0, start: now };
    }

    entry.count += 1;
    buckets.set(mapKey, entry);

    if (buckets.size > maxSize) {
      for (const [k, v] of buckets) {
        if (now - v.start > windowMs) buckets.delete(k);
        if (buckets.size < pruneTo) break;
      }
    }

    return entry.count <= limit;
  }

  function clearId(id) {
    for (const key of buckets.keys()) {
      if (key.startsWith(`${id}:`)) buckets.delete(key);
    }
  }

  return { check, clearId };
}

const httpLimit = makeLimiter(5000, 4000);
const sockLimit = makeLimiter(20000, 15000);

app.use((req, res, next) => {
  const ip =
    req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown";

  if (!httpLimit.check(ip, "http", 120, 60 * 1000)) {
    return res.status(429).json({ error: "Too many requests." });
  }

  next();
});

app.use(
  cors({
    origin: CLIENT_URL,
  })
);

app.use(express.json({ limit: "100kb" }));

// Serve the built client (single-service deploy). Skipped locally
// when client/dist doesn't exist - API + sockets work standalone.
const clientDist = path.join(__dirname, "..", "client", "dist");

if (fs.existsSync(clientDist)) {
  app.use(express.static(clientDist));
}

// =========================================================
// HTTP SERVER
// =========================================================

const httpServer = http.createServer(app);

// =========================================================
// SOCKET.IO
// =========================================================

const io = new Server(httpServer, {
  maxHttpBufferSize: 1 * 1024 * 1024,

  cors: {
    origin: CLIENT_URL,
    methods: ["GET", "POST"],
  },
});

// =========================================================
// RAM-ONLY ROOM STORAGE
// =========================================================
//
// Normal chat messages are NOT stored.
// Room encryption secrets are NOT stored.
// When the last user leaves, the room is destroyed.
//

const rooms = new Map();

// ========================================================
// HELPERS
// =========================================================

function sanitizeRoomCode(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "")
    .slice(0, ROOM_CODE_LENGTH);
}

function sanitizeUsername(value) {
  const cleaned = String(value || "")
    .trim()
    .replace(/[\x00-\x1f\x7f]/g, "")
    .replace(/\s+/g, " ")
    .slice(0, 30);

  // Allowlist: letters, numbers, space, _ . - . Rejects < > / \ ' " ` for
  // defense-in-depth (React already escapes, this stops log/HTML tricks).
  if (!/^[A-Za-z0-9 _.\-]+$/.test(cleaned)) {
    return "";
  }

  return cleaned;
}

// ponytail: O(n) scan, ceiling n=2 room users
function isUsernameTaken(room, username) {
  const lower = username.toLowerCase();

  for (const user of room.users.values()) {
    if (user.username.toLowerCase() === lower) {
      return true;
    }
  }

  return false;
}

// Global uniqueness makes lobby identity reliable at 50+ online.
function isUsernameTakenGlobal(username, exceptId) {
  const lower = String(username).toLowerCase();

  for (const room of rooms.values()) {
    for (const user of room.users.values()) {
      if (user.id !== exceptId && user.username.toLowerCase() === lower) {
        return true;
      }
    }
  }

  return false;
}

function hashRoomPassword(password) {
  return crypto
    .createHash("sha256")
    .update(String(password || ""), "utf8")
    .digest("hex");
}

function sanitizeRoomPassword(value) {
  if (typeof value !== "string" || !value) {
    return null;
  }

  const trimmed = value.slice(0, ROOM_PASSWORD_MAX_LEN);

  if (trimmed.length < 4) {
    return null;
  }

  return trimmed;
}

function isValidRoomCode(roomCode) {
  return /^[a-z0-9]{4}$/.test(roomCode);
}

function isValidPublicKey(key) {
  if (!key || typeof key !== "object" || Array.isArray(key)) {
    return false;
  }

  // Expect ECDH P-256 JWK: { kty: "EC", crv: "P-256", x, y }
  if (key.kty !== "EC" || key.crv !== "P-256") {
    return false;
  }

  if (typeof key.x !== "string" || typeof key.y !== "string") {
    return false;
  }

  if (key.x.length > 100 || key.y.length > 100) {
    return false;
  }

  return true;
}

function isValidCiphertext(value, maxLen) {
  if (typeof value !== "string") {
    return false;
  }

  if (!value || value.length > maxLen) {
    return false;
  }

  // Base64 only - rejects embedded scripts/control chars
  return /^[A-Za-z0-9+/=_-]+$/.test(value);
}

function getSocketIp(socket) {
  if (TRUST_PROXY) {
    const forwarded = socket.handshake.headers["x-forwarded-for"];

    if (forwarded) {
      return String(forwarded).split(",")[0].trim().slice(0, 45);
    }
  }

  return socket.handshake.address || "unknown";
}

function getRoomUsers(room) {
  if (!room) {
    return [];
  }

  return Array.from(room.users.values()).map(
    (user) => ({
      id: user.id,
      username: user.username,
      publicKey: user.publicKey,
    })
  );
}

function emitRoomUsers(roomCode) {
  const room = rooms.get(roomCode);

  if (!room) {
    return;
  }

  io.to(roomCode).emit(
    "room-users",
    getRoomUsers(room)
  );
}

function sendSystemMessage(roomCode, message) {
  io.to(roomCode).emit(
    "system-message",
    {
      message,
      timestamp: new Date().toISOString(),
    }
  );
}

// =========================================================
// FIND USER ROOM
// =========================================================

function findUserRoom(socketId) {
  for (const [roomCode, room] of rooms.entries()) {
    if (room.users.has(socketId)) {
      return {
        roomCode,
        room,
        user: room.users.get(socketId),
      };
    }
  }

  return null;
}

// =========================================================
// MODERATION SANITIZER
// =========================================================
//
// Moderation analysis happens on the client.
//
// Server only validates moderation metadata.
//

function sanitizeModeration(moderation) {
  // Tamper-evidence: honest clients always send an object.
  // Missing/invalid shape is treated as undeclared, never as clean.
  if (!moderation || typeof moderation !== "object") {
    return { flagged: false, undeclared: true };
  }

  if (moderation.flagged !== true) {
    return { flagged: false };
  }

  const allowedLevels = [
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
  ];

  const allowedCategories = [
    "DIRECT_THREAT",
    "THREAT_CONTEXT",
    "VIOLENCE",
    "WEAPON",
    "SENSITIVE_TERM",
    "SENSITIVE_CONTEXT",
    "EXPLOSIVE",
    "ATTACK_PLANNING",
    "HARASSMENT",
    "SELF_HARM",
  ];

  const level =
    allowedLevels.includes(moderation.level)
      ? moderation.level
      : "LOW";

  const category =
    allowedCategories.includes(
      moderation.category
    )
      ? moderation.category
      : "SENSITIVE_TERM";

  const reason = String(
    moderation.reason || ""
  )
    .trim()
    .slice(0, 250);

  let score = Number(moderation.score);

  if (!Number.isFinite(score)) {
    score = 0;
  }

  score = Math.max(
    0,
    Math.min(100, score)
  );

  return {
    flagged: true,
    level,
    category,
    reason,
    score,
  };
}

function relayModeration(moderation) {
  // Minimize metadata leakage on the wire: ciphertext observers
  // only learn flagged+level, full reason/category stays in DB.
  if (!moderation || moderation.flagged !== true) {
    return null;
  }

  return {
    flagged: true,
    level: moderation.level,
  };
}

function publicKeysEqual(a, b) {
  return (
    a &&
    b &&
    a.kty === b.kty &&
    a.crv === b.crv &&
    a.x === b.x &&
    a.y === b.y
  );
}

function validateJoin(data) {
  const username = sanitizeUsername(data?.username);
  const roomCode = sanitizeRoomCode(data?.roomCode);
  if (!username) return { error: "Enter valid username" };
  if (!isValidRoomCode(roomCode)) return { error: "Room code must be exactly 4 letters or numbers." };
  if (!isValidPublicKey(data?.publicKey)) return { error: "Encryption identity is missing." };
  return { username, roomCode, publicKey: data.publicKey };
}

function logIncident(roomCode, sender, receiver, moderation, forensicMessage) {
  const clean = sanitizeForensicMessage(forensicMessage);
  if (moderation?.flagged !== true || !clean) return;
  saveIncident({
    roomCode,
    timestamp: new Date().toISOString(),
    senderUsername: sender.username,
    senderIp: sender.ip,
    receiverUsername: receiver?.username || null,
    receiverIp: receiver?.ip || null,
    message: clean,
    severity: moderation.level,
    category: moderation.category,
    reason: moderation.reason,
    score: moderation.score,
  }).catch((e) => console.error("[FORENSIC]", e.message));
}

// =========================================================
// FORENSIC MESSAGE SANITIZER
// =========================================================
//
// Only flagged plaintext is allowed here.
//

function sanitizeForensicMessage(message) {
  if (typeof message !== "string") {
    return null;
  }

  const cleaned = message.trim();

  if (!cleaned) {
    return null;
  }

  return cleaned.slice(0, 5000);
}

// =========================================================
// HEALTH CHECK
// =========================================================

app.get("/api/health", (req, res) => {
  res.json({
    name: "ENCRYPTO",
    status: "online",
    mode: "ephemeral",
    encryption: "client-side",
    maxRoomUsers: MAX_ROOM_USERS,
  });
});

// =========================================================
// PROTECTED FORENSIC READ (A09 access control)
// =========================================================

app.get("/api/incidents", (req, res) => {
  // Uniform 401 whether or not ADMIN_TOKEN is set - avoids
  // revealing server config via 404/401 oracle.
  const expected = ADMIN_TOKEN || crypto.randomBytes(32).toString("hex");

  const auth = String(req.headers.authorization || "");
  const token = auth.startsWith("Bearer ")
    ? auth.slice(7)
    : "";

  // Constant-time compare to avoid timing oracle on token
  const a = Buffer.from(token);
  const b = Buffer.from(expected);

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return res.status(401).json({ error: "Unauthorized." });
  }

  getIncidents(100)
    .then((rows) => res.json({ incidents: rows }))
    .catch(() =>
      res.status(500).json({ error: "Read failed." })
    );
});

// =========================================================
// OPEN ROOMS (same-platform invite, no external channel)
// =========================================================

app.get("/api/rooms", (req, res) => {
  const list = [];

  for (const room of rooms.values()) {
    if (!room.open || room.users.size !== 1) continue;

    const host = room.users.values().next().value;

    list.push({
      code: room.code,
      host: host?.username || "unknown",
      hasPassword: Boolean(room.passwordHash),
      createdAt: room.createdAt || null,
    });

    if (list.length >= 50) break;
  }

  res.json({ rooms: list });
});

// SPA fallback for the served client (API + socket.io pass through).
if (fs.existsSync(clientDist)) {
  app.use((req, res, next) => {
    if (
      req.method !== "GET" ||
      req.path.startsWith("/api/") ||
      req.path.startsWith("/socket.io/")
    ) {
      return next();
    }

    res.sendFile(path.join(clientDist, "index.html"));
  });
}

// =========================================================
// SOCKET CONNECTION
// =========================================================

io.on("connection", (socket) => {
  const connIp = getSocketIp(socket);

  if (!sockLimit.check(connIp, "conn", 20, 60 * 1000)) {
    socket.disconnect(true);
    return;
  }

  // =======================================================
  // CREATE ROOM
  // =======================================================

  socket.on(
    "create-room",
    (data, callback) => {
      if (typeof callback !== "function") {
        callback = () => {};
      }

      if (!sockLimit.check(socket.id, "create-room", 10, 60 * 1000)) {
        callback({
          success: false,
          message: "Too many requests. Slow down.",
        });

        return;
      }

      if (rooms.size >= MAX_ROOMS) {
        callback({
          success: false,
          message: "Server is busy. Try again later.",
        });

        return;
      }

      const v = validateJoin(data);
      if (v.error) {
        callback({ success: false, message: v.error });
        return;
      }
      const { username, roomCode, publicKey } = v;

      if (isUsernameTakenGlobal(username, socket.id)) {
        callback({ success: false, message: "That name is taken online. Pick another." });
        return;
      }

      // ---------------------------------------------------
      // EXISTING ROOM
      // ---------------------------------------------------

      if (rooms.has(roomCode)) {
        callback({
          success: false,
          message:
            "That room code is already in use.",
        });

        return;
      }

      // ---------------------------------------------------
      // CREATE ROOM
      // ---------------------------------------------------

      const roomPassword = sanitizeRoomPassword(data?.roomPassword);

      if (
        typeof data?.roomPassword === "string" &&
        data.roomPassword &&
        !roomPassword
      ) {
        callback({
          success: false,
          message: "Room password must be at least 4 characters.",
        });

        return;
      }

      const room = {
        code: roomCode,
        users: new Map(),
        passwordHash: roomPassword ? hashRoomPassword(roomPassword) : null,
        open: data?.open === true,
        createdAt: Date.now(),
        approved: new Set(),
      };

      room.users.set(
        socket.id,
        {
          id: socket.id,
          username,
          publicKey,
          ip: getSocketIp(socket),
        }
      );

      rooms.set(
        roomCode,
        room
      );

      socket.join(roomCode);

      // ---------------------------------------------------
      // CALLBACK
      // ---------------------------------------------------

      callback({
        success: true,
        roomCode,
        socketId: socket.id,
      });

      // ---------------------------------------------------
      // USERS
      // ---------------------------------------------------

      emitRoomUsers(roomCode);
    }
  );

  // =======================================================
  // JOIN ROOM
  // =======================================================

  socket.on(
    "join-room",
    (data, callback) => {
      if (typeof callback !== "function") {
        callback = () => {};
      }

      if (!sockLimit.check(socket.id, "join-room", 15, 60 * 1000)) {
        callback({
          success: false,
          message: "Too many requests. Slow down.",
        });

        return;
      }

      const v = validateJoin(data);
      if (v.error) {
        callback({ success: false, message: v.error });
        return;
      }
      const { username, roomCode, publicKey } = v;

      if (isUsernameTakenGlobal(username, socket.id)) {
        callback({ success: false, message: "That name is taken online. Pick another." });
        return;
      }

      // ---------------------------------------------------
      // FIND ROOM
      // ---------------------------------------------------

      const room =
        rooms.get(roomCode);

      if (!room) {
        callback({
          success: false,
          message:
            "Room not found. Check the room code.",
        });

        return;
      }

      // ---------------------------------------------------
      // ROOM LIMIT
      // ---------------------------------------------------

      if (
        room.users.size >=
        MAX_ROOM_USERS
      ) {
        callback({
          success: false,
          message:
            "Room is full. ENCRYPTO supports 2 users per room.",
        });

        return;
      }

      // ---------------------------------------------------
      // ADD USER
      // ---------------------------------------------------

      if (isUsernameTaken(room, username)) {
        callback({
          success: false,
          message: "That username is already taken in this room.",
        });

        return;
      }

      const providedPassword = sanitizeRoomPassword(data?.roomPassword);

      const oneTimeApproval = room.approved && room.approved.has(socket.id);

      // Listed rooms need host approval - knowing the code alone is not enough.
      if (room.open && !oneTimeApproval) {
        callback({
          success: false,
          message: "This room needs host approval. Knock first.",
        });

        return;
      }

      if (room.passwordHash && !oneTimeApproval) {
        if (
          !providedPassword ||
          hashRoomPassword(providedPassword) !== room.passwordHash
        ) {
          callback({
            success: false,
            message: "Incorrect room password.",
          });

          return;
        }
      }

      const joiningUser = {
        id: socket.id,
        username,
        publicKey,
        ip: getSocketIp(socket),
      };

      if (room.approved) room.approved.delete(socket.id);

      room.users.set(
        socket.id,
        joiningUser
      );

      socket.join(roomCode);

      // ---------------------------------------------------
      // CALLBACK
      // ---------------------------------------------------

      callback({
        success: true,
        roomCode,
        socketId: socket.id,
      });

      // ---------------------------------------------------
      // USERS
      // ---------------------------------------------------

      emitRoomUsers(roomCode);

      // ---------------------------------------------------
      // SYSTEM MESSAGE
      // ---------------------------------------------------

      sendSystemMessage(
        roomCode,
        `${username} joined the secure room.`
      );

      // ---------------------------------------------------
      // EXISTING USER
      // ---------------------------------------------------

      const existingUser =
        Array.from(
          room.users.values()
        ).find(
          (user) =>
            user.id !== socket.id
        );

      // ---------------------------------------------------
      // REQUEST ROOM KEY
      // ---------------------------------------------------
      //
      // Existing user will encrypt the room secret
      // using ECDH and the joining user's public key.
      //
      // The server never receives the plaintext secret.
      //

      if (existingUser) {
        io.to(
          existingUser.id
        ).emit(
          "room-key-needed",
          {
            recipientId:
              joiningUser.id,

            recipientPublicKey:
              joiningUser.publicKey,
          }
        );
      }
    }
  );

  // =======================================================
  // ROOM MESSAGE
  // =======================================================

  socket.on(
    "send-message",
    (data) => {
      if (!sockLimit.check(socket.id, "send-message", 60, 60 * 1000)) {
        return;
      }

      const roomCode =
        sanitizeRoomCode(
          data?.roomCode
        );

      const room =
        rooms.get(roomCode);

      if (!room) {
        return;
      }

      // ---------------------------------------------------
      // VERIFY SENDER
      // ---------------------------------------------------

      const sender =
        room.users.get(
          socket.id
        );

      if (!sender) {
        return;
      }

      // ---------------------------------------------------
      // VERIFY CIPHERTEXT
      // ---------------------------------------------------

      if (
        !isValidCiphertext(data?.encryptedMessage, MAX_CIPHERTEXT_LEN) ||
        !isValidCiphertext(data?.iv, MAX_IV_LEN)
      ) {
        return;
      }

      // ---------------------------------------------------
      // MODERATION
      // ---------------------------------------------------

      const moderation =
        sanitizeModeration(
          data?.moderation
        );

      // ---------------------------------------------------
      // FORENSIC STORAGE
      // ---------------------------------------------------
      //
      // Only the specific flagged message is stored.
      //
      // Normal messages remain encrypted and are never
      // stored in the database.
      //

      logIncident(
        roomCode,
        sender,
        Array.from(room.users.values()).find((u) => u.id !== sender.id),
        moderation,
        data?.forensicMessage
      );

      // ---------------------------------------------------
      // RELAY ENCRYPTED MESSAGE
      // ---------------------------------------------------

      const messageId =
        `${Date.now()}-${Math.random()
          .toString(36)
          .slice(2)}`;

      io.to(roomCode).emit(
        "receive-message",
        {
          id: messageId,

          senderId:
            socket.id,

          username:
            sender.username,

          encryptedMessage:
            data.encryptedMessage,

          iv:
            data.iv,

          timestamp:
            new Date().toISOString(),

          moderation: relayModeration(moderation),
        }
      );

      if (moderation?.flagged === true) {
        console.log(
          `[MODERATION] ${moderation.level} ${moderation.category} in room ${roomCode} from ${sender.username}`
        );
      }
    }
  );

  // =======================================================
  // SEND ROOM KEY
  // =======================================================

  socket.on(
    "send-room-key",
    (data) => {
      if (
        !data?.recipientId ||
        !isValidCiphertext(data?.encryptedRoomSecret, MAX_CIPHERTEXT_LEN) ||
        !isValidCiphertext(data?.iv, MAX_IV_LEN)
      ) {
        return;
      }

      // ---------------------------------------------------
      // FIND SENDER ROOM
      // ---------------------------------------------------

      const roomInfo =
        findUserRoom(
          socket.id
        );

      if (!roomInfo) {
        return;
      }

      const {
        room,
        user: sender,
      } = roomInfo;

      // ---------------------------------------------------
      // FIND RECIPIENT
      // ---------------------------------------------------

      const recipient =
        room.users.get(
          data.recipientId
        );

      if (!recipient) {
        return;
      }

      // ---------------------------------------------------
      // FORWARD ENCRYPTED ROOM SECRET
      // ---------------------------------------------------
      //
      // Server does not decrypt this.
      //

      io.to(
        recipient.id
      ).emit(
        "room-key",
        {
          encryptedRoomSecret:
            data.encryptedRoomSecret,

          iv:
            data.iv,

          senderPublicKey:
            sender.publicKey,
        }
      );
    }
  );

  // =======================================================
  // PRIVATE MESSAGE
  // =======================================================

  socket.on(
    "send-private-message",
    (data) => {
      if (!sockLimit.check(socket.id, "send-private-message", 60, 60 * 1000)) {
        return;
      }

      const recipientId =
        data?.recipientId;

      if (
        !recipientId ||
        !isValidCiphertext(data?.encryptedMessage, MAX_CIPHERTEXT_LEN) ||
        !isValidCiphertext(data?.iv, MAX_IV_LEN)
      ) {
        return;
      }

      // ---------------------------------------------------
      // FIND ROOM
      // ---------------------------------------------------

      const roomInfo =
        findUserRoom(
          socket.id
        );

      if (!roomInfo) {
        return;
      }

      const {
        roomCode,
        room,
      } = roomInfo;

      // ---------------------------------------------------
      // USERS
      // ---------------------------------------------------

      const sender =
        room.users.get(
          socket.id
        );

      const recipient =
        room.users.get(
          recipientId
        );

      if (
        !sender ||
        !recipient
      ) {
        return;
      }

      // ---------------------------------------------------
      // PUBLIC KEY
      // ---------------------------------------------------
      //
      // Frontend provides the recipient public key
      // when creating the private encrypted message.
      //

      if (!isValidPublicKey(data?.recipientPublicKey)) {
        return;
      }

      if (!publicKeysEqual(data.recipientPublicKey, recipient.publicKey)) {
        return;
      }

      // ---------------------------------------------------
      // MODERATION
      // ---------------------------------------------------

      const moderation =
        sanitizeModeration(
          data?.moderation
        );

      // ---------------------------------------------------
      // FORENSIC STORAGE
      // ---------------------------------------------------

      logIncident(roomCode, sender, recipient, moderation, data?.forensicMessage);

      // ---------------------------------------------------
      // MESSAGE ID
      // ---------------------------------------------------

      const messageId =
        `${Date.now()}-${Math.random()
          .toString(36)
          .slice(2)}`;

      // ---------------------------------------------------
      // SEND TO RECIPIENT
      // ---------------------------------------------------

      io.to(
        recipient.id
      ).emit(
        "receive-private-message",
        {
          id: messageId,

          senderId:
            sender.id,

          recipientId:
            recipient.id,

          username:
            sender.username,

          encryptedMessage:
            data.encryptedMessage,

          iv:
            data.iv,

          senderPublicKey:
            sender.publicKey,

          timestamp:
            new Date().toISOString(),

          moderation: relayModeration(moderation),
        }
      );

      // ---------------------------------------------------
      // CONFIRM TO SENDER
      // ---------------------------------------------------

      io.to(
        sender.id
      ).emit(
        "private-message-sent",
        {
          id: messageId,

          senderId:
            sender.id,

          recipientId:
            recipient.id,

          username:
            sender.username,

          encryptedMessage:
            data.encryptedMessage,

          iv:
            data.iv,

          recipientPublicKey:
            recipient.publicKey,

          timestamp:
            new Date().toISOString(),

          moderation: relayModeration(moderation),
        }
      );
    }
  );

  // =======================================================
  // ROOM TYPING
  // =======================================================

  socket.on(
    "typing",
    (data) => {
      if (!sockLimit.check(socket.id, "typing", 60, 60 * 1000)) {
        return;
      }

      const roomCode =
        sanitizeRoomCode(
          data?.roomCode
        );

      const room =
        rooms.get(roomCode);

      if (!room) {
        return;
      }

      if (
        !room.users.has(
          socket.id
        )
      ) {
        return;
      }

      const sender =
        room.users.get(
          socket.id
        );

      socket.to(
        roomCode
      ).emit(
        "user-typing",
        {
          username:
            sender?.username,

          isTyping:
            Boolean(
              data?.isTyping
            ),
        }
      );
    }
  );

  // =======================================================
  // PRIVATE TYPING
  // =======================================================

  socket.on(
    "private-typing",
    (data) => {
      if (!sockLimit.check(socket.id, "private-typing", 60, 60 * 1000)) {
        return;
      }

      const recipientId =
        data?.recipientId;

      if (!recipientId) {
        return;
      }

      const roomInfo =
        findUserRoom(
          socket.id
        );

      if (!roomInfo) {
        return;
      }

      const {
        room,
        user: sender,
      } = roomInfo;

      // Recipient must be in same room.

      if (
        !room.users.has(
          recipientId
        )
      ) {
        return;
      }

      io.to(
        recipientId
      ).emit(
        "private-user-typing",
        {
          username:
            sender.username,

          isTyping:
            Boolean(
              data?.isTyping
            ),
        }
      );
    }
  );

  // =======================================================
  // KNOCK + APPROVE (no password exchange needed)
  // =======================================================

  socket.on(
    "request-join",
    (data) => {
      if (!sockLimit.check(socket.id, "request-join", 10, 60 * 1000)) {
        return;
      }

      const roomCode = sanitizeRoomCode(data?.roomCode);
      const room = rooms.get(roomCode);
      if (!room || room.users.size < 1) return;

      // 20s cooldown after a decline so a rejected guest cannot knock-bomb the host.
      const waitMs = KNOCK_COOLDOWN_MS - (Date.now() - ((room.knockAt && room.knockAt.get(socket.id)) || 0));

      if (waitMs > 0) {
        io.to(socket.id).emit("knock-cooldown", {
          roomCode,
          retryAfterSec: Math.ceil(waitMs / 1000),
        });

        return;
      }

      const requesterName = sanitizeUsername(data?.username) || "unknown";

      const host = room.users.values().next().value;
      if (!host) return;

      io.to(host.id).emit("join-request", {
        roomCode,
        requesterId: socket.id,
        requesterName,
      });
    }
  );

  socket.on(
    "approve-join",
    (data) => {
      const roomInfo = findUserRoom(socket.id);
      if (!roomInfo) return;

      const { room } = roomInfo;
      const requesterId = data?.requesterId;
      if (!requesterId || !room.users.has(socket.id)) return;

      if (!room.approved) room.approved = new Set();
      room.approved.add(requesterId);

      io.to(requesterId).emit("join-approved", {
        roomCode: room.code,
      });
    }
  );

  socket.on(
    "decline-join",
    (data) => {
      const roomInfo = findUserRoom(socket.id);
      if (!roomInfo) return;

      const { room } = roomInfo;
      const requesterId = data?.requesterId;
      if (!requesterId || !room.users.has(socket.id)) return;

      if (room.approved) room.approved.delete(requesterId);

      // Start the 20s re-knock cooldown at decline time.
      if (!room.knockAt) room.knockAt = new Map();
      room.knockAt.set(requesterId, Date.now());

      io.to(requesterId).emit("join-declined", {
        roomCode: room.code,
        retryAfterSec: Math.ceil(KNOCK_COOLDOWN_MS / 1000),
      });
    }
  );

  // =======================================================
  // LEAVE ROOM
  // =======================================================

  socket.on(
    "leave-room",
    () => {
      removeUserFromRoom(
        socket
      );
    }
  );

  // =======================================================
  // DISCONNECT
  // =======================================================

  socket.on(
    "disconnect",
    () => {
      sockLimit.clearId(socket.id);

      removeUserFromRoom(
        socket
      );
    }
  );
});

// =========================================================
// REMOVE USER FROM ROOM
// =========================================================

function removeUserFromRoom(
  socket
) {
  // -------------------------------------------------------
  // FIND ROOM
  // -------------------------------------------------------

  const roomInfo =
    findUserRoom(
      socket.id
    );

  if (!roomInfo) {
    return;
  }

  const {
    roomCode,
    room,
    user,
  } = roomInfo;

  // -------------------------------------------------------
  // REMOVE USER
  // -------------------------------------------------------

  room.users.delete(
    socket.id
  );

  socket.leave(
    roomCode
  );

  // -------------------------------------------------------
  // ROOM EMPTY
  // -------------------------------------------------------

  if (
    room.users.size === 0
  ) {
    rooms.delete(
      roomCode
    );

    return;
  }

  // -------------------------------------------------------
  // NOTIFY REMAINING USER
  // -------------------------------------------------------

  emitRoomUsers(
    roomCode
  );

  sendSystemMessage(
    roomCode,
    `${user.username} left the secure room.`
  );
}

// =========================================================
// START SERVER
// =========================================================

httpServer.listen(PORT, () => {
  console.log(`ENCRYPTO online :${PORT} (ephemeral, client-side crypto)`);
});
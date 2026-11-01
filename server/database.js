const { DatabaseSync } = require("node:sqlite");

const crypto = require("crypto");

const path = require("path");

// =========================================================
// DATABASE
// =========================================================

const databasePath =
  process.env.DATABASE_PATH ||
  path.join(
    __dirname,
    "encrypto.db"
  );

// At-rest encryption for forensic messages (A04).
// Set FORENSIC_KEY to 32-byte base64. Without it, messages are
// stored plaintext and a warning is logged (college demo mode).
const FORENSIC_KEY_B64 = process.env.FORENSIC_KEY || "";

let forensicKey = null;

if (FORENSIC_KEY_B64) {
  try {
    const key = Buffer.from(FORENSIC_KEY_B64, "base64");

    if (key.length === 32) {
      forensicKey = key;
    } else {
      console.warn(
        "[DATABASE] FORENSIC_KEY must be 32-byte base64, ignoring."
      );
    }
  } catch {
    console.warn("[DATABASE] Invalid FORENSIC_KEY, ignoring.");
  }
}

if (!forensicKey) {
  console.warn(
    "[SECURITY] FORENSIC_KEY not set, forensic messages stored plaintext."
  );
}

function encryptAtRest(plaintext) {
  if (!forensicKey) {
    return plaintext;
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", forensicKey, iv);
  const enc = Buffer.concat([
    cipher.update(String(plaintext), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return `enc:v1:${iv.toString("base64")}:${tag.toString("base64")}:${enc.toString("base64")}`;
}

function decryptAtRest(stored) {
  if (!stored || typeof stored !== "string") {
    return stored;
  }

  if (!stored.startsWith("enc:v1:")) {
    return stored;
  }

  if (!forensicKey) {
    return "[encrypted: FORENSIC_KEY missing]";
  }

  const parts = stored.split(":");

  if (parts.length !== 5) {
    return "[encrypted: corrupt]";
  }

  try {
    const iv = Buffer.from(parts[2], "base64");
    const tag = Buffer.from(parts[3], "base64");
    const data = Buffer.from(parts[4], "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", forensicKey, iv);
    decipher.setAuthTag(tag);

    return Buffer.concat([
      decipher.update(data),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return "[encrypted: decrypt failed]";
  }
}

const db =
  new DatabaseSync(databasePath);

console.log(
  "[DATABASE] SQLite connected"
);


// =========================================================
// CREATE INCIDENT TABLE
// =========================================================

db.exec(`
  CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    room_code TEXT NOT NULL,

    timestamp TEXT NOT NULL,

    sender_username TEXT NOT NULL,

    sender_ip TEXT,

    receiver_username TEXT,

    receiver_ip TEXT,

    message TEXT NOT NULL,

    severity TEXT NOT NULL,

    category TEXT NOT NULL,

    reason TEXT,

    score INTEGER
  )
`);

const insertIncident = db.prepare(`
  INSERT INTO incidents (
    room_code,
    timestamp,
    sender_username,
    sender_ip,
    receiver_username,
    receiver_ip,
    message,
    severity,
    category,
    reason,
    score
  )
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const trimIncidents = db.prepare(
  `DELETE FROM incidents WHERE id NOT IN (SELECT id FROM incidents ORDER BY id DESC LIMIT 5000)`
);

const selectIncidents = db.prepare(
  `SELECT * FROM incidents ORDER BY id DESC LIMIT ?`
);


// =========================================================
// SAVE FLAGGED INCIDENT
// =========================================================

async function saveIncident({
  roomCode,
  timestamp,
  senderUsername,
  senderIp,
  receiverUsername,
  receiverIp,
  message,
  severity,
  category,
  reason,
  score,
}) {
  try {
    const result = insertIncident.run(
      roomCode,
      timestamp,
      senderUsername,
      senderIp || null,
      receiverUsername || null,
      receiverIp || null,
      encryptAtRest(message),
      severity,
      category,
      reason || null,
      Number.isFinite(score) ? score : 0
    );

    console.log(
      `[DATABASE] Incident saved. ID: ${result.lastInsertRowid}`
    );

    // ponytail: retention ceiling 5000 rows, prevents disk-fill
    trimIncidents.run();

    return result.lastInsertRowid;
  } catch (error) {
    console.error(
      "[DATABASE] Failed to save incident:",
      error.message
    );

    throw error;
  }
}


// =========================================================
// READ INCIDENTS (protected API only)
// =========================================================

async function getIncidents(limit = 100) {
  const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));

  const rows = selectIncidents.all(safeLimit);

  return rows.map((row) => ({
    ...row,
    message: decryptAtRest(row.message),
  }));
}


// =========================================================
// CLOSE DATABASE
// =========================================================

function closeDatabase() {
  try {
    db.close();

    console.log(
      "[DATABASE] SQLite closed"
    );
  } catch (error) {
    console.error(
      "[DATABASE] Close failed:",
      error.message
    );
  }
}


// =========================================================
// EXPORT
// =========================================================

module.exports = {
  saveIncident,
  getIncidents,
  decryptAtRest,
  closeDatabase,
};

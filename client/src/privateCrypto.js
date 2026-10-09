const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ==========================================
// BASE64 HELPERS
// ==========================================

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);

  let binary = "";

  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });

  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);

  const bytes = new Uint8Array(
    binary.length
  );

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

// ==========================================
// GENERATE USER ECDH KEY PAIR
// ==========================================

export async function generatePrivateKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    false,
    ["deriveKey"]
  );
}

// ==========================================
// EXPORT PUBLIC KEY
// ==========================================

export async function exportPublicKey(
  publicKey
) {
  return crypto.subtle.exportKey(
    "jwk",
    publicKey
  );
}

// ==========================================
// IMPORT PUBLIC KEY
// ==========================================

async function importPublicKey(
  publicKeyJwk
) {
  return crypto.subtle.importKey(
    "jwk",
    publicKeyJwk,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    []
  );
}

// ==========================================
// DERIVE SHARED AES KEY
// ==========================================

async function deriveSharedKey(
  privateKey,
  otherPublicKeyJwk
) {
  const otherPublicKey =
    await importPublicKey(
      otherPublicKeyJwk
    );

  return crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: otherPublicKey,
    },
    privateKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

// ==========================================
// PRIVATE MESSAGE ENCRYPTION
// ==========================================

export async function encryptPrivateMessage(
  message,
  privateKey,
  recipientPublicKey
) {
  const sharedKey =
    await deriveSharedKey(
      privateKey,
      recipientPublicKey
    );

  const iv =
    crypto.getRandomValues(
      new Uint8Array(12)
    );

  const encrypted =
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
      },
      sharedKey,
      encoder.encode(message)
    );

  return {
    encryptedMessage:
      arrayBufferToBase64(
        encrypted
      ),

    iv: arrayBufferToBase64(iv),
  };
}

// ==========================================
// PRIVATE MESSAGE DECRYPTION
// ==========================================

export async function decryptPrivateMessage(
  encryptedMessage,
  iv,
  privateKey,
  senderPublicKey
) {
  const sharedKey =
    await deriveSharedKey(
      privateKey,
      senderPublicKey
    );

  const decrypted =
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(
          base64ToArrayBuffer(iv)
        ),
      },
      sharedKey,
      base64ToArrayBuffer(
        encryptedMessage
      )
    );

  return decoder.decode(
    decrypted
  );
}

// ==========================================
// ENCRYPT ROOM SECRET FOR ANOTHER USER
// ==========================================

export async function encryptRoomSecret(
  roomSecret,
  privateKey,
  recipientPublicKey
) {
  const sharedKey =
    await deriveSharedKey(
      privateKey,
      recipientPublicKey
    );

  const iv =
    crypto.getRandomValues(
      new Uint8Array(12)
    );

  const encrypted =
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
      },
      sharedKey,
      encoder.encode(roomSecret)
    );

  return {
    encryptedRoomSecret:
      arrayBufferToBase64(
        encrypted
      ),

    iv: arrayBufferToBase64(iv),
  };
}

// ==========================================
// DECRYPT ROOM SECRET
// ==========================================

export async function decryptRoomSecret(
  encryptedRoomSecret,
  iv,
  privateKey,
  senderPublicKey
) {
  const sharedKey =
    await deriveSharedKey(
      privateKey,
      senderPublicKey
    );

  const decrypted =
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(
          base64ToArrayBuffer(iv)
        ),
      },
      sharedKey,
      base64ToArrayBuffer(
        encryptedRoomSecret
      )
    );

  return decoder.decode(
    decrypted
  );
}
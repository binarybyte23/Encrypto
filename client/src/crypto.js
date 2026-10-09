const encoder = new TextEncoder();
const decoder = new TextDecoder();

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

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

export async function generateRoomSecret() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));

  return arrayBufferToBase64(randomBytes);
}

async function getEncryptionKey(secret) {
  const secretBytes = base64ToArrayBuffer(secret);

  return crypto.subtle.importKey(
    "raw",
    secretBytes,
    {
      name: "AES-GCM",
    },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptMessage(message, secret) {
  const key = await getEncryptionKey(secret);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    encoder.encode(message)
  );

  return {
    encryptedMessage: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv),
  };
}

export async function decryptMessage(
  encryptedMessage,
  iv,
  secret
) {
  try {
    const key = await getEncryptionKey(secret);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(base64ToArrayBuffer(iv)),
      },
      key,
      base64ToArrayBuffer(encryptedMessage)
    );

    return decoder.decode(decrypted);
  } catch (error) {
    console.error("Message decryption failed:", error);

    return "[Unable to decrypt message]";
  }
}
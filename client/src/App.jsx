import {
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { io } from "socket.io-client";

import {
  Copy,
  LogOut,
  Lock,
  Send,
  ShieldCheck,
  User,
  Users,
  MessageCircle,
  ArrowLeft,
  Wifi,
  WifiOff,
  Flag,
} from "lucide-react";

import "./App.css";

import {
  generateRoomSecret,
  encryptMessage,
  decryptMessage,
} from "./crypto";

import {
  generatePrivateKeyPair,
  exportPublicKey,
  encryptPrivateMessage,
  decryptPrivateMessage,
  encryptRoomSecret,
  decryptRoomSecret,
} from "./privateCrypto";

import { analyzeMessage } from "./moderation";

async function keyFingerprint(publicKeyJwk) {
  try {
    const bytes = new TextEncoder().encode(JSON.stringify(publicKeyJwk));
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .slice(0, 16);
  } catch {
    return "unavailable";
  }
}

function validUser(name) {
  return /^[A-Za-z0-9 _.\-]{1,30}$/.test(String(name || "").trim());
}

function buildModeration(risk) {
  return {
    flagged: risk.flagged,
    level: risk.level,
    category: risk.category,
    reason: risk.reason,
    score: risk.score,
  };
}


// =========================================================
// CONFIG
// =========================================================

// Empty = same origin (single-service deploy). Set VITE_SOCKET_URL
// only when API lives on a different host.
const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || "";


// =========================================================
// APP
// =========================================================

function App() {
  // =======================================================
  // CONNECTION
  // =======================================================

  const socketRef = useRef(null);

  const privateKeyRef = useRef(null);
  const publicKeyRef = useRef(null);

  const roomSecretRef = useRef(null);

  const currentRoomRef = useRef("");
  const usernameRef = useRef("");

  const pendingRoomMessagesRef = useRef([]);

  // =======================================================
  // SCREEN
  // =======================================================

  const [screen, setScreen] =
    useState("landing");

  // landing:
  // create / join

  const [mode, setMode] =
    useState("join");

  // =======================================================
  // USER
  // =======================================================

  const [username, setUsername] =
    useState("");

  const [roomCode, setRoomCode] =
    useState("");

  const [currentUserId, setCurrentUserId] =
    useState("");

  const [openRoom, setOpenRoom] =
    useState(false);

  const [openRooms, setOpenRooms] =
    useState([]);

  const [roomsLoading, setRoomsLoading] =
    useState(false);

  const [roomSearch, setRoomSearch] =
    useState("");

  const [knockedRooms, setKnockedRooms] =
    useState({});

  const [knockCooldowns, setKnockCooldowns] =
    useState({});

  function knockWaitSec(code) {
    return Math.max(
      0,
      Math.ceil(
        ((knockCooldowns[code] || 0) - Date.now()) / 1000
      )
    );
  }

  const hasKnockCooldown =
    Object.keys(knockCooldowns).length > 0;

  useEffect(() => {
    if (!hasKnockCooldown) return;

    const timer = setInterval(() => {
      setKnockCooldowns((prev) => {
        const now = Date.now();
        const next = {};

        for (const [code, until] of Object.entries(prev)) {
          if (until > now) next[code] = until;
        }

        return next;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [hasKnockCooldown]);

  const [joinRequests, setJoinRequests] =
    useState([]);

  function knockRoom(room) {
    if (!socketRef.current) return;

    socketRef.current.emit("request-join", {
      roomCode: room.code,
      username: username.trim() || "unknown",
    });

    setKnockedRooms((prev) => ({ ...prev, [room.code]: true }));
  }

  function approveRequest(req) {
    socketRef.current?.emit("approve-join", {
      requesterId: req.requesterId,
    });

    setJoinRequests((prev) =>
      prev.filter((r) => r.requesterId !== req.requesterId)
    );
  }

  function declineRequest(req) {
    socketRef.current?.emit("decline-join", {
      requesterId: req.requesterId,
    });

    setJoinRequests((prev) =>
      prev.filter((r) => r.requesterId !== req.requesterId)
    );
  }

  async function fetchOpenRooms() {
    setRoomsLoading(true);

    try {
      const res = await fetch(`${SOCKET_URL}/api/rooms`);
      const data = await res.json();
      setOpenRooms(Array.isArray(data?.rooms) ? data.rooms : []);
    } catch (e) {
      console.error("fetch /api/rooms failed:", SOCKET_URL, e);
      setOpenRooms([]);
    } finally {
      setRoomsLoading(false);
    }
  }

  // ponytail: poll open rooms on landing, 5s is enough for a lobby list
  useEffect(() => {
    if (screen !== "landing") return;
    fetchOpenRooms();
    const t = setInterval(fetchOpenRooms, 5000);
    return () => clearInterval(t);
  }, [screen]);

  const [keyFingerprints, setKeyFingerprints] =
    useState({});

  // =======================================================
  // ENCRYPTION
  // =======================================================

  const [encryptionReady, setEncryptionReady] =
    useState(false);

  const [roomEncryptionReady, setRoomEncryptionReady] =
    useState(false);

  // =======================================================
  // ROOM
  // =======================================================

  const [users, setUsers] =
    useState([]);

  const [error, setError] =
    useState("");

  const [copied, setCopied] =
    useState(false);

  // =======================================================
  // ROOM MESSAGES
  // =======================================================

  const [messages, setMessages] =
    useState([]);

  const [messageInput, setMessageInput] =
    useState("");

  const [messageRisk, setMessageRisk] = useState({ flagged: false, level: "NONE", category: "", reason: "", score: 0 });

  const [typingUser, setTypingUser] =
    useState("");

  // =======================================================
  // PRIVATE CHAT
  // =======================================================

  const [selectedUser, setSelectedUser] =
    useState(null);

  const [privateMessages, setPrivateMessages] =
    useState({});

  const [privateInput, setPrivateInput] =
    useState("");

  // Moderation for private messages is calculated locally
  // before encryption, just like room messages.
  const [privateMessageRisk, setPrivateMessageRisk] = useState({
    flagged: false,
    level: "NONE",
    category: "",
    reason: "",
    score: 0,
  });

  const [privateTypingUser, setPrivateTypingUser] =
    useState("");

  // =======================================================
  // STATUS
  // =======================================================

  const [connected, setConnected] =
    useState(false);

  const [sending, setSending] =
    useState(false);

  const [privateSending, setPrivateSending] =
    useState(false);

  // =======================================================
  // REFS FOR SCROLL
  // =======================================================

  const messagesEndRef =
    useRef(null);

  const privateMessagesEndRef =
    useRef(null);

  const roomInputRef =
    useRef(null);

  const privateInputRef =
    useRef(null);


  // =======================================================
  // GENERATE ECDH IDENTITY
  // =======================================================

  useEffect(() => {
    let mounted = true;

    async function setupEncryption() {
      try {
        const keyPair =
          await generatePrivateKeyPair();

        privateKeyRef.current =
          keyPair.privateKey;

        publicKeyRef.current =
          await exportPublicKey(
            keyPair.publicKey
          );

        if (mounted) {
          setEncryptionReady(true);
        }

      } catch (error) {
        console.error(
          "Encryption initialization failed:",
          error
        );

        if (mounted) {
          setError(
            "Unable to initialize secure encryption."
          );
        }
      }
    }

    setupEncryption();

    return () => {
      mounted = false;
    };
  }, []);


  // =======================================================
  // SOCKET CONNECTION
  // =======================================================

  useEffect(() => {
    const socket =
      io(SOCKET_URL || undefined, {
        transports: [
          "websocket",
          "polling",
        ],
      });

    socketRef.current =
      socket;


    // =====================================================
    // CONNECT
    // =====================================================

    socket.on(
      "connect",
      () => {
        setConnected(true);
      }
    );


    // =====================================================
    // DISCONNECT
    // =====================================================

    socket.on(
      "disconnect",
      () => {
        setConnected(false);

        /*
         * If the connection drops unexpectedly while
         * inside a room, immediately wipe the local
         * room state. The server also removes this
         * socket from the room on disconnect.
         */
        if (currentRoomRef.current) {
          clearRoomState();
        }
      }
    );


    // =====================================================
    // ROOM USERS
    // =====================================================

    socket.on(
      "room-users",
      (roomUsers) => {
        if (!Array.isArray(roomUsers)) {
          return;
        }

        setUsers(roomUsers);

        // ponytail: prune stale fingerprints, ceiling n=2 users
        setKeyFingerprints((prev) => {
          const ids = new Set(roomUsers.map((u) => u?.id));
          const next = {};

          for (const id of ids) {
            if (prev[id]) next[id] = prev[id];
          }

          return next;
        });

        roomUsers.forEach((u) => {
          if (!u?.publicKey || !u?.id) {
            return;
          }

          keyFingerprint(u.publicKey).then((fp) => {
            setKeyFingerprints((prev) =>
              prev[u.id] === fp
                ? prev
                : { ...prev, [u.id]: fp }
            );
          });
        });
      }
    );


    // =====================================================
    // SYSTEM MESSAGE
    // =====================================================

    socket.on(
      "system-message",
      (data) => {
        if (!data?.message) {
          return;
        }

        const systemMessage = {
          id:
            `system-${Date.now()}-${Math.random()}`,

          senderId:
            "system",

          username:
            "SYSTEM",

          text:
            data.message,

          timestamp:
            data.timestamp ||
            new Date().toISOString(),

          system: true,
        };

        setMessages(
          (previous) => [
            ...previous,
            systemMessage,
          ]
        );
      }
    );


    // =====================================================
    // ROOM MESSAGE
    // =====================================================

    socket.on(
      "receive-message",
      async (data) => {
        if (!data) {
          return;
        }

        /*
         * If the room encryption key has not
         * arrived yet, keep the encrypted
         * message temporarily.
         */

        if (!roomSecretRef.current) {
          pendingRoomMessagesRef.current.push(
            data
          );

          return;
        }

        try {
          const decrypted =
            await decryptMessage(
              data.encryptedMessage,
              data.iv,
              roomSecretRef.current
            );

          setMessages(
            (previous) => [
              ...previous,
              {
                id:
                  data.id,

                senderId:
                  data.senderId,

                username:
                  data.username,

                text:
                  decrypted,

                timestamp:
                  data.timestamp,

                moderation:
                  data.moderation || null,
              },
            ]
          );
        } catch (error) {
          console.error(
            "Room message decryption failed:",
            error
          );
        }
      }
    );


    // =====================================================
    // ROOM KEY NEEDED
    // =====================================================

    socket.on(
      "room-key-needed",
      async (data) => {
        if (
          !roomSecretRef.current ||
          !privateKeyRef.current ||
          !data?.recipientPublicKey ||
          !data?.recipientId
        ) {
          return;
        }

        try {
          /*
           * Existing member encrypts the random
           * room secret using ECDH with the
           * new member's public key.
           */

          const encrypted =
            await encryptRoomSecret(
              roomSecretRef.current,
              privateKeyRef.current,
              data.recipientPublicKey
            );

          socketRef.current?.emit(
            "send-room-key",
            {
              recipientId:
                data.recipientId,

              encryptedRoomSecret:
                encrypted.encryptedRoomSecret,

              iv:
                encrypted.iv,
            }
          );

        } catch (error) {
          console.error(
            "Unable to transfer room key:",
            error
          );
        }
      }
    );


    // =====================================================
    // RECEIVE ROOM KEY
    // =====================================================

    socket.on(
      "room-key",
      async (data) => {
        if (
          !privateKeyRef.current ||
          !data?.senderPublicKey ||
          !data?.encryptedRoomSecret ||
          !data?.iv
        ) {
          return;
        }

        try {
          const roomSecret =
            await decryptRoomSecret(
              data.encryptedRoomSecret,
              data.iv,
              privateKeyRef.current,
              data.senderPublicKey
            );

          roomSecretRef.current =
            roomSecret;

          setRoomEncryptionReady(
            true
          );


          /*
           * Decrypt any room messages that
           * arrived before the key.
           */

          const pending =
            pendingRoomMessagesRef.current;

          pendingRoomMessagesRef.current =
            [];

          for (
            const message of pending
          ) {
            try {
              const decrypted =
                await decryptMessage(
                  message.encryptedMessage,
                  message.iv,
                  roomSecret
                );

              setMessages(
                (previous) => [
                  ...previous,
                  {
                    id:
                      message.id,

                    senderId:
                      message.senderId,

                    username:
                      message.username,

                    text:
                      decrypted,

                    timestamp:
                      message.timestamp,

                    moderation:
                      message.moderation || null,
                  },
                ]
              );
            } catch (error) {
              console.error(
                "Pending room message decryption failed:",
                error
              );
            }
          }
        } catch (error) {
          console.error(
            "Unable to decrypt room key:",
            error
          );

          setError(
            "Unable to establish secure room encryption."
          );
        }
      }
    );


    // =====================================================
    // RECEIVE PRIVATE MESSAGE
    // =====================================================

    socket.on(
      "receive-private-message",
      async (data) => {
        if (
          !privateKeyRef.current ||
          !data?.senderPublicKey
        ) {
          return;
        }

        try {
          const decrypted =
            await decryptPrivateMessage(
              data.encryptedMessage,
              data.iv,
              privateKeyRef.current,
              data.senderPublicKey
            );

          setPrivateMessages(
            (previous) => {
              const userId =
                data.senderId;

              const existing =
                previous[userId] ||
                [];

              return {
                ...previous,

                [userId]: [
                  ...existing,
                  {
                    id:
                      data.id,

                    senderId:
                      data.senderId,

                    recipientId:
                      data.recipientId,

                    username:
                      data.username,

                    text:
                      decrypted,

                    timestamp:
                      data.timestamp,

                    moderation:
                      data.moderation || null,
                  },
                ],
              };
            }
          );
        } catch (error) {
          console.error(
            "Private message decryption failed:",
            error
          );
        }
      }
    );


    // =====================================================
    // PRIVATE MESSAGE SENT
    // =====================================================

    socket.on(
      "private-message-sent",
      async (data) => {
        if (
          !privateKeyRef.current ||
          !data?.recipientPublicKey
        ) {
          return;
        }

        try {
          /*
           * IMPORTANT:
           *
           * The sender encrypted the message
           * using the recipient's public key.
           *
           * Therefore the sender must decrypt
           * using THEIR private key + recipient
           * public key.
           *
           * This fixes:
           *
           * [Unable to decrypt private message]
           */

          const decrypted =
            await decryptPrivateMessage(
              data.encryptedMessage,
              data.iv,
              privateKeyRef.current,
              data.recipientPublicKey
            );

          setPrivateMessages(
            (previous) => {
              const userId =
                data.recipientId;

              const existing =
                previous[userId] ||
                [];

              const alreadyExists =
                existing.some(
                  (message) =>
                    message.id ===
                    data.id
                );

              if (alreadyExists) {
                return previous;
              }

              return {
                ...previous,

                [userId]: [
                  ...existing,
                  {
                    id:
                      data.id,

                    senderId:
                      data.senderId,

                    recipientId:
                      data.recipientId,

                    username:
                      data.username,

                    text:
                      decrypted,

                    timestamp:
                      data.timestamp,

                    moderation:
                      data.moderation || null,
                  },
                ],
              };
            }
          );
        } catch (error) {
          console.error(
            "Sender private message decryption failed:",
            error
          );
        }
      }
    );


    // =====================================================
    // ROOM TYPING
    // =====================================================

    socket.on(
      "user-typing",
      (data) => {
        if (!data?.username) {
          return;
        }

        if (data.isTyping) {
          setTypingUser(
            data.username
          );
        } else {
          setTypingUser("");
        }
      }
    );


    // =====================================================
    // PRIVATE TYPING
    // =====================================================

    socket.on(
      "private-user-typing",
      (data) => {
        if (!data?.username) {
          return;
        }

        if (data.isTyping) {
          setPrivateTypingUser(
            data.username
          );
        } else {
          setPrivateTypingUser("");
        }
      }
    );


    // =====================================================
    // KNOCK APPROVALS
    // =====================================================

    socket.on("join-request", (data) => {
      if (!data?.requesterId) return;

      setJoinRequests((prev) =>
        prev.some((r) => r.requesterId === data.requesterId)
          ? prev
          : [...prev, data]
      );
    });

    socket.on("join-approved", (data) => {
      if (data?.roomCode) {
        setRoomCode(String(data.roomCode).toLowerCase());
        setMode("join");
        setError("Approved! Press JOIN SECURE ROOM.");
      }
    });

    socket.on("join-declined", (data) => {
      if (data?.roomCode) {
        const code = String(data.roomCode).toLowerCase();

        setKnockedRooms((prev) => {
          if (!prev[code]) return prev;

          const next = { ...prev };
          delete next[code];
          return next;
        });

        setKnockCooldowns((prev) => ({
          ...prev,
          [code]: Date.now() + (data.retryAfterSec || 20) * 1000,
        }));

        setError("Host declined your request.");
      }
    });

    socket.on("knock-cooldown", (data) => {
      const secs = data?.retryAfterSec || 20;

      if (data?.roomCode) {
        const code = String(data.roomCode).toLowerCase();

        setKnockCooldowns((prev) =>
          prev[code] && prev[code] > Date.now()
            ? prev
            : { ...prev, [code]: Date.now() + secs * 1000 }
        );
      }

      setError(
        `Wait ${secs}s before knocking again.`
      );
    });


    // =====================================================
    // CLEANUP
    // =====================================================

    return () => {
      socket.removeAllListeners();

      socket.disconnect();

      socketRef.current =
        null;
    };
  }, []);


  // =======================================================
  // CURRENT OTHER USERS
  // =======================================================

  const otherUsers =
    useMemo(() => {
      return users.filter(
        (user) =>
          user.id !==
          currentUserId
      );
    }, [
      users,
      currentUserId,
    ]);


  // =======================================================
  // SELECTED PRIVATE MESSAGES
  // =======================================================

  const selectedPrivateMessages =
    useMemo(() => {
      if (!selectedUser) {
        return [];
      }

      return (
        privateMessages[
          selectedUser.id
        ] || []
      );
    }, [
      privateMessages,
      selectedUser,
    ]);


  // =======================================================
  // KEEP PRIVATE SELECTION STABLE
  // =======================================================
  //
  // room-users refreshes replace user objects. Keep the
  // private view selected by id and refresh the public key
  // so the next DM does not require re-clicking the member.

  useEffect(() => {
    if (!selectedUser) {
      return;
    }

    const fresh = users.find(
      (user) => user.id === selectedUser.id
    );

    if (
      fresh &&
      (fresh.publicKey !== selectedUser.publicKey ||
        fresh.username !== selectedUser.username)
    ) {
      setSelectedUser(fresh);
    }
  }, [users, selectedUser]);


  // =======================================================
  // VISIBLE FLAGGED COUNT (room or current private view)
  // =======================================================

  const visibleMessages =
    selectedUser
      ? selectedPrivateMessages
      : messages;

  const visibleFlagCount =
    visibleMessages.filter(
      (message) =>
        message.moderation?.flagged
    ).length;

  const hasSevereFlag =
    visibleMessages.some(
      (message) =>
        message.moderation?.flagged &&
        (message.moderation.level === "HIGH" ||
          message.moderation.level === "CRITICAL")
    );


  // =======================================================
  // AUTO SCROLL ROOM
  // =======================================================

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({
      behavior: "smooth",
    });
  }, [
    messages,
    typingUser,
  ]);


  // =======================================================
  // AUTO SCROLL PRIVATE
  // =======================================================

  useEffect(() => {
    privateMessagesEndRef.current?.scrollIntoView({
      behavior: "smooth",
    });
  }, [
    selectedPrivateMessages,
    privateTypingUser,
  ]);


  // =======================================================
  // VALIDATE ROOM CODE
  // =======================================================

  function sanitizeRoomCode(value) {
    return value
      .toLowerCase()
      .replace(
        /[^a-z0-9]/g,
        ""
      )
      .slice(0, 4);
  }


  // =======================================================
  // CREATE ROOM
  // =======================================================

  function createRoom() {
    setError("");

    if (!encryptionReady) {
      setError(
        "Secure encryption is still initializing. Please wait."
      );

      return;
    }

    const cleanUsername =
      username.trim();

    if (!validUser(cleanUsername)) {
      setError(
        "Username: letters, numbers, space, _ . - only."
      );

      return;
    }

    const cleanRoomCode =
      sanitizeRoomCode(
        roomCode.trim()
      );

    if (
      !/^[a-z0-9]{4}$/.test(
        cleanRoomCode
      )
    ) {
      setError(
        "Room code must be exactly 4 characters."
      );

      return;
    }

    if (!socketRef.current) {
      setError(
        "Server connection is not ready."
      );

      return;
    }


    /*
     * Generate a strong random room secret.
     *
     * The room code is NOT the encryption key.
     */

    generateRoomSecret()
      .then(
        (secret) => {
          roomSecretRef.current =
            secret;

          setRoomEncryptionReady(
            true
          );

          usernameRef.current =
            cleanUsername;

          socketRef.current.emit(
            "create-room",
            {
              username:
                cleanUsername,

              roomCode:
                cleanRoomCode,

              open:
                openRoom || undefined,

              publicKey:
                publicKeyRef.current,
            },
            (response) => {
              if (!response?.success) {
                roomSecretRef.current =
                  null;

                setRoomEncryptionReady(
                  false
                );

                setError(
                  response?.message ||
                    "Unable to create room."
                );

                return;
              }

              currentRoomRef.current =
                response.roomCode;

              setRoomCode(
                response.roomCode
              );

              setCurrentUserId(
                response.socketId ||
                  socketRef.current.id
              );

              setMessages([]);

              setPrivateMessages({});

              setSelectedUser(
                null
              );

              setMessageInput("");

              setPrivateInput("");

              setTypingUser("");

              setPrivateTypingUser("");

              setCopied(false);

              setError("");

              setScreen(
                "chat"
              );
            }
          );
        }
      )
      .catch(
        (error) => {
          console.error(
            "Room secret generation failed:",
            error
          );

          setError(
            "Unable to initialize room encryption."
          );
        }
      );
  }


  // =======================================================
  // JOIN ROOM
  // =======================================================

  function joinRoom() {
    setError("");

    if (!encryptionReady) {
      setError(
        "Secure encryption is still initializing. Please wait."
      );

      return;
    }

    const cleanUsername =
      username.trim();

    if (!validUser(cleanUsername)) {
      setError(
        "Username: letters, numbers, space, _ . - only."
      );

      return;
    }

    const cleanRoomCode =
      sanitizeRoomCode(
        roomCode.trim()
      );

    if (
      !/^[a-z0-9]{4}$/.test(
        cleanRoomCode
      )
    ) {
      setError(
        "Room code must be exactly 4 characters."
      );

      return;
    }

    if (!socketRef.current) {
      setError(
        "Server connection is not ready."
      );

      return;
    }

    usernameRef.current =
      cleanUsername;

    /*
     * Important:
     *
     * A joining user does NOT create a room
     * encryption key.
     *
     * The existing room member securely
     * transfers it using ECDH.
     */

    roomSecretRef.current =
      null;

    setRoomEncryptionReady(
      false
    );

    socketRef.current.emit(
      "join-room",
      {
        roomCode:
          cleanRoomCode,

        username:
          cleanUsername,

        publicKey:
          publicKeyRef.current,
      },
      (response) => {
        if (!response?.success) {
          setError(
            response?.message ||
              "Unable to join room."
          );

          return;
        }

        currentRoomRef.current =
          response.roomCode;

        setRoomCode(
          response.roomCode
        );

        setCurrentUserId(
          response.socketId ||
            socketRef.current.id
        );

        setMessages([]);

        setPrivateMessages({});

        setSelectedUser(
          null
        );

        setMessageInput("");

        setPrivateInput("");

        setTypingUser("");

        setPrivateTypingUser("");

        setCopied(false);

        setError("");

        setScreen(
          "chat"
        );
      }
    );
  }


  // =======================================================
  // ROOM MESSAGE
  // =======================================================

  async function sendRoomMessage() {
    const text =
      messageInput.trim();

    if (!text) {
      return;
    }

    if (
      !roomSecretRef.current
    ) {
      setError(
        "Secure room encryption is not ready yet."
      );

      return;
    }

    if (
      !socketRef.current ||
      !currentRoomRef.current
    ) {
      return;
    }

    if (sending) {
      return;
    }

    setSending(true);

    try {
      // Analyze the exact text being sent so React state
      // timing can never affect moderation.
      const currentRisk = analyzeMessage(text);

      const encrypted =
        await encryptMessage(
          text,
          roomSecretRef.current
        );

      socketRef.current.emit(
        "send-message",
        {
          roomCode:
            currentRoomRef.current,

          username:
            usernameRef.current,

          encryptedMessage:
            encrypted.encryptedMessage,

          iv:
            encrypted.iv,

          moderation: buildModeration(currentRisk),

          // Only flagged plaintext is sent for forensic storage.
          // Normal plaintext never leaves the browser.
          forensicMessage: currentRisk.flagged
            ? text
            : undefined,
        }
      );

      setMessageInput("");

      // Keep focus so the next message needs no re-click.
      setTimeout(() => roomInputRef.current?.focus(), 0);

      setMessageRisk({
        flagged: false,
        level: "NONE",
        category: "",
        reason: "",
        score: 0,
      });

      socketRef.current.emit(
        "typing",
        {
          roomCode:
            currentRoomRef.current,

          username:
            usernameRef.current,

          isTyping:
            false,
        }
      );
    } catch (error) {
      console.error(
        "Room message encryption failed:",
        error
      );

      setError(
        "Unable to encrypt message."
      );
    } finally {
      setSending(false);

      // Re-focus after re-enable so continuous typing needs no re-click.
      requestAnimationFrame(() =>
        roomInputRef.current?.focus()
      );
    }
  }


  // =======================================================
  // PRIVATE MESSAGE
  // =======================================================

  async function sendPrivateMessage() {
    const text =
      privateInput.trim();

    const currentRisk =
      analyzeMessage(text);

    if (!text) {
      return;
    }

    if (!selectedUser) {
      return;
    }

    if (
      !privateKeyRef.current ||
      !selectedUser.publicKey
    ) {
      setError(
        "Recipient encryption identity is not available."
      );

      return;
    }

    if (!socketRef.current) {
      return;
    }

    if (privateSending) {
      return;
    }

    setPrivateSending(true);

    try {
      /*
       * Encrypt with recipient's public key.
       */

      const encrypted =
        await encryptPrivateMessage(
          text,
          privateKeyRef.current,
          selectedUser.publicKey
        );

      socketRef.current.emit(
        "send-private-message",
        {
          recipientId:
            selectedUser.id,

          encryptedMessage:
            encrypted.encryptedMessage,

          iv:
            encrypted.iv,

          recipientPublicKey:
            selectedUser.publicKey,

          moderation: buildModeration(currentRisk),

          // Only flagged plaintext is sent for forensic storage.
          forensicMessage: currentRisk.flagged
            ? text
            : undefined,
        }
      );

      setPrivateInput("");

      // Keep focus so the next message needs no re-click.
      setTimeout(() => privateInputRef.current?.focus(), 0);

      setPrivateMessageRisk({
        flagged: false,
        level: "NONE",
        category: "",
        reason: "",
        score: 0,
      });

      socketRef.current.emit(
        "private-typing",
        {
          recipientId:
            selectedUser.id,

          username:
            usernameRef.current,

          isTyping:
            false,
        }
      );
    } catch (error) {
      console.error(
        "Private message encryption failed:",
        error
      );

      setError(
        "Unable to encrypt private message."
      );
    } finally {
      setPrivateSending(false);

      // Re-focus after send so continuous DM needs no re-click.
      // Private view stays selected; only the input is cleared.
      requestAnimationFrame(() =>
        privateInputRef.current?.focus()
      );
    }
  }


  // =======================================================
  // ROOM TYPING
  // =======================================================

  function handleRoomTyping(
    value
  ) {
    setMessageInput(
      value
    );

    setMessageRisk(analyzeMessage(value));

    if (
      !socketRef.current ||
      !currentRoomRef.current
    ) {
      return;
    }

    socketRef.current.emit(
      "typing",
      {
        roomCode:
          currentRoomRef.current,

        username:
          usernameRef.current,

        isTyping:
          Boolean(
            value.trim()
          ),
      }
    );
  }


  // =======================================================
  // PRIVATE TYPING
  // =======================================================

  function handlePrivateTyping(
    value
  ) {
    setPrivateInput(
      value
    );

    setPrivateMessageRisk(
      analyzeMessage(value)
    );

    if (
      !socketRef.current ||
      !selectedUser
    ) {
      return;
    }

    socketRef.current.emit(
      "private-typing",
      {
        recipientId:
          selectedUser.id,

        username:
          usernameRef.current,

        isTyping:
          Boolean(
            value.trim()
          ),
      }
    );
  }


  // =======================================================
  // ROOM KEYBOARD
  // =======================================================

  function handleRoomKeyDown(
    event
  ) {
    if (
      event.key ===
        "Enter" &&
      !event.shiftKey
    ) {
      event.preventDefault();

      sendRoomMessage();
    }
  }


  // =======================================================
  // PRIVATE KEYBOARD
  // =======================================================

  function handlePrivateKeyDown(
    event
  ) {
    if (
      event.key ===
        "Enter" &&
      !event.shiftKey
    ) {
      event.preventDefault();

      sendPrivateMessage();
    }
  }


  // =======================================================
  // COPY ROOM CODE
  // =======================================================

  async function copyRoomCode() {
    try {
      await navigator.clipboard.writeText(
        currentRoomRef.current ||
          roomCode
      );

      setCopied(true);

      setTimeout(
        () => {
          setCopied(false);
        },
        1500
      );
    } catch (error) {
      console.error(
        "Copy failed:",
        error
      );
    }
  }


  // =======================================================
  // BROWSER / PAGE UNLOAD
  // =======================================================

  useEffect(() => {
    const handlePageHide = () => {
      if (
        socketRef.current &&
        socketRef.current.connected &&
        currentRoomRef.current
      ) {
        socketRef.current.emit(
          "leave-room"
        );
      }

      roomSecretRef.current =
        null;

      currentRoomRef.current =
        "";

      usernameRef.current =
        "";

      pendingRoomMessagesRef.current =
        [];
    };

    window.addEventListener(
      "pagehide",
      handlePageHide
    );

    return () => {
      window.removeEventListener(
        "pagehide",
        handlePageHide
      );
    };
  }, []);


  // =======================================================
  // CLEAR ROOM STATE
  // =======================================================

  function clearRoomState() {
    /*
     * ENCRYPTO is intentionally ephemeral.
     * Nothing from the previous room should remain
     * available after leaving or losing the connection.
     */

    roomSecretRef.current =
      null;

    currentRoomRef.current =
      "";

    usernameRef.current =
      "";

    pendingRoomMessagesRef.current =
      [];

    setMessages([]);

    setPrivateMessages({});

    setUsers([]);

    setKeyFingerprints({});

    setSelectedUser(
      null
    );

    setMessageInput("");
    setMessageRisk({ flagged: false, level: "NONE", category: "", reason: "", score: 0 });

    setPrivateInput("");

    setPrivateMessageRisk({
      flagged: false,
      level: "NONE",
      category: "",
      reason: "",
      score: 0,
    });

    setTypingUser("");

    setPrivateTypingUser("");

    setRoomEncryptionReady(
      false
    );

    setCurrentUserId(
      ""
    );

    setRoomCode("");

    setError("");

    setCopied(false);

    setJoinRequests([]);

    setKnockedRooms({});

    setKnockCooldowns({});

    setSending(false);

    setPrivateSending(false);

    setScreen(
      "landing"
    );
  }


  // =======================================================
  // LEAVE ROOM
  // =======================================================

  function leaveRoom() {
    if (
      socketRef.current &&
      socketRef.current.connected &&
      currentRoomRef.current
    ) {
      socketRef.current.emit(
        "leave-room"
      );
    }

    clearRoomState();
  }


  // =======================================================
  // LANDING PAGE
  // =======================================================

  if (
    screen ===
    "landing"
  ) {
    return (
      <div className="app">
        <div className="landing-page">

          <div className="landing-glow" />

          <div className="landing-grid" />

          <div className="landing-card">

            {/* ==========================================
                LOGO
            ========================================== */}

            <div className="landing-logo">
              <div className="logo-core">
                ◈
              </div>
            </div>

            <div className="landing-eyebrow">
              END-TO-END ENCRYPTED
            </div>

            <h1>
              ENCRYPTO
            </h1>

            <p className="landing-description">
              Private communication without
              handing your conversations to
              the internet's ever-growing
              collection of data hoarders.
            </p>


            {/* ==========================================
                MODE SWITCH
            ========================================== */}

            <div className="mode-switch">

              <button
                type="button"
                className={
                  mode === "join"
                    ? "active"
                    : ""
                }
                onClick={() => {
                  setMode("join");
                  setError("");
                }}
              >
                JOIN ROOM
              </button>

              <button
                type="button"
                className={
                  mode === "create"
                    ? "active"
                    : ""
                }
                onClick={() => {
                  setMode("create");
                  setError("");
                }}
              >
                CREATE ROOM
              </button>

            </div>


            {/* ==========================================
                FORM
            ========================================== */}

            <div className="landing-form">

              <label>
                <span>
                  USERNAME
                </span>

                <input
                  type="text"
                  value={
                    username
                  }
                  onChange={(event) =>
                    setUsername(
                      event.target.value
                    )
                  }
                  placeholder="Enter your username"
                  autoComplete="off"
                  maxLength={30}
                />
              </label>


              <label>
                <span>
                  ROOM CODE
                </span>

                <input
                  type="text"
                  value={
                    roomCode
                  }
                  onChange={(event) =>
                    setRoomCode(
                      sanitizeRoomCode(
                        event.target.value
                      )
                    )
                  }
                  onKeyDown={(event) => {
                    if (
                      event.key ===
                      "Enter"
                    ) {
                      if (
                        mode ===
                        "create"
                      ) {
                        createRoom();
                      } else {
                        joinRoom();
                      }
                    }
                  }}
                  placeholder="e.g. 1111"
                  autoComplete="off"
                  maxLength={4}
                />

                <small>
                  Exactly 4 letters or numbers
                </small>
              </label>

              <label>
                <span>
                  LIST IN OPEN ROOMS
                </span>

                <input
                  type="checkbox"
                  checked={openRoom}
                  onChange={(event) =>
                    setOpenRoom(event.target.checked)
                  }
                />

                <small>
                  Others can find it and knock
                </small>
              </label>


              {/* ======================================
                  ERROR
              ====================================== */}

              {error && (
                <div className="error-message">
                  <span>
                    !
                  </span>

                  {error}
                </div>
              )}


              {/* ======================================
                  MAIN BUTTON
              ====================================== */}

              <button
                type="button"
                className="primary-action"
                onClick={
                  mode ===
                  "create"
                    ? createRoom
                    : joinRoom
                }
                disabled={
                  !connected ||
                  !encryptionReady
                }
              >

                <ShieldCheck
                  size={18}
                />

                <span>
                  {!connected
                    ? "CONNECTING..."
                    : !encryptionReady
                    ? "INITIALIZING..."
                    : mode ===
                      "create"
                    ? "CREATE SECURE ROOM"
                    : "JOIN SECURE ROOM"}
                </span>

              </button>

              <button
                type="button"
                className="primary-action"
                onClick={fetchOpenRooms}
                disabled={!connected || roomsLoading}
              >
                <span>
                  {roomsLoading ? "LOADING..." : "BROWSE OPEN ROOMS"}
                </span>
              </button>

              {openRooms.length === 0 && !roomsLoading && (
                <small>No open rooms right now. Create one with “LIST IN OPEN ROOMS” checked.</small>
              )}

              {openRooms.length > 0 && (
                <label>
                  <span>
                    SEARCH HOST
                  </span>

                  <input
                    type="text"
                    value={roomSearch}
                    onChange={(event) =>
                      setRoomSearch(event.target.value)
                    }
                    placeholder="Search by username or code"
                    autoComplete="off"
                    maxLength={30}
                  />
                </label>
              )}

              {openRooms
                .filter((r) => {
                  const q = roomSearch.trim().toLowerCase();
                  if (!q) return true;
                  return (
                    String(r.host || "").toLowerCase().includes(q) ||
                    String(r.code || "").toLowerCase().includes(q)
                  );
                })
                .map((r) => (
                <div key={r.code}>
                  <div>
                    <span>
                      {r.host}'s room
                    </span>
                  </div>

                  {knockWaitSec(r.code) > 0 ? (
                    <button
                      type="button"
                      className="primary-action"
                      disabled
                    >
                      <span>WAIT {knockWaitSec(r.code)}s</span>
                    </button>
                  ) : (
                    !knockedRooms[r.code] && (
                      <button
                        type="button"
                        className="primary-action"
                        onClick={() => knockRoom(r)}
                      >
                        <span>KNOCK (ask {r.host} for approval)</span>
                      </button>
                    )
                  )}

                  {knockedRooms[r.code] && (
                    <small>Knocked! Wait for {r.host} to approve.</small>
                  )}
                </div>
              ))}

              {joinRequests.map((req) => (
                <button
                  type="button"
                  key={req.requesterId}
                  className="primary-action"
                  onClick={() => approveRequest(req)}
                >
                  <span>
                    APPROVE {req.requesterName} into {req.roomCode}
                  </span>
                </button>
              ))}

            </div>


            {/* ==========================================
                SECURITY INFO
            ========================================== */}

            <div className="security-info">

              <div>
                <Lock
                  size={14}
                />

                <span>
                  AES-256-GCM
                </span>
              </div>

              <div>
                <ShieldCheck
                  size={14}
                />

                <span>
                  ECDH P-256
                </span>
              </div>

              <div>
                {connected ? (
                  <Wifi
                    size={14}
                  />
                ) : (
                  <WifiOff
                    size={14}
                  />
                )}

                <span>
                  {connected
                    ? "SERVER ONLINE"
                    : "SERVER OFFLINE"}
                </span>
              </div>

            </div>

          </div>

        </div>
      </div>
    );
  }


  // =======================================================
  // CHAT PAGE
  // =======================================================

  return (
    <div className="app">

      {/* =================================================
          LEFT SIDEBAR
      ================================================= */}

      <aside className="chat-sidebar">

        {/* ================================================
            BRAND
        ================================================= */}

        <div className="sidebar-brand">

          <div className="brand-mark">
            <span>
              E
            </span>
          </div>

          <div>
            <div className="brand-name">
              ENCRYPTO
            </div>

            <div className="brand-subtitle">
              PRIVATE COMMUNICATION
            </div>
          </div>

        </div>


        {/* ================================================
            ROOM INFORMATION
        ================================================= */}

        <div className="sidebar-room">

          <div className="sidebar-label">
            ROOM
          </div>

          <div className="room-display">

            <span>
              {currentRoomRef.current ||
                roomCode}
            </span>

            <button
              type="button"
              onClick={
                copyRoomCode
              }
              title="Copy room code"
            >
              {copied ? (
                "✓"
              ) : (
                <Copy
                  size={15}
                />
              )}
            </button>

          </div>

        </div>


        {/* ================================================
            KNOCK REQUESTS
        ================================================= */}

        {joinRequests.length > 0 && (
          <div className="members-section">

            <div className="section-header">

              <span>
                KNOCKS
              </span>

              <span className="member-count">
                {joinRequests.length}
              </span>

            </div>

            <div className="members-list">

              {joinRequests.map((req) => (
                <div key={req.requesterId}>
                  <button
                    type="button"
                    className="member-card"
                    onClick={() => approveRequest(req)}
                  >
                    <span>
                      APPROVE {req.requesterName}
                    </span>
                  </button>

                  <button
                    type="button"
                    className="member-card"
                    onClick={() => declineRequest(req)}
                  >
                    <span>
                      DECLINE {req.requesterName}
                    </span>
                  </button>
                </div>
              ))}

            </div>

          </div>
        )}


        {/* ================================================
            MEMBERS
        ================================================= */}

        <div className="members-section">

          <div className="section-header">

            <span>
              MEMBERS
            </span>

            <span className="member-count">
              {otherUsers.length}
            </span>

          </div>


          <div className="members-list">

            {otherUsers.length ===
            0 ? (

              <div className="empty-members">

                <Users
                  size={18}
                />

                <span>
                  Waiting for others...
                </span>

              </div>

            ) : (

              otherUsers.map(
                (user) => {

                  const active =
                    selectedUser?.id ===
                    user.id;

                  return (
                    <button
                      type="button"
                      key={
                        user.id
                      }
                      className={`member-card ${
                        active
                          ? "active"
                          : ""
                      }`}
                      onClick={() => {
                        setSelectedUser(
                          user
                        );

                        setPrivateTypingUser(
                          ""
                        );
                      }}
                    >

                      <div className="member-avatar">
                        {user.username
                          ?.charAt(
                            0
                          )
                          ?.toUpperCase() ||
                          "U"}
                      </div>

                      <div className="member-info">

                        <div className="member-name">
                          {user.username}
                        </div>

                        <div className="member-status">
                          <span className="online-indicator" />
                          ONLINE
                        </div>

                        <div
                          className="member-status"
                          title="Verify this fingerprint out-of-band to detect MITM"
                        >
                          KEY {keyFingerprints[user.id] || "..."}
                        </div>

                      </div>

                      {active && (
                        <MessageCircle
                          size={15}
                        />
                      )}

                    </button>
                  );
                }
              )

            )}

          </div>

        </div>


        {/* ================================================
            SECURITY FOOTER
        ================================================= */}

        <div className="sidebar-footer">

          <div className="encrypted-badge">

            <Lock
              size={13}
            />

            <span>
              ENCRYPTED
            </span>

          </div>

          <div className="sidebar-footer-text">
            Messages are encrypted
            before transmission.
          </div>

        </div>

      </aside>


      {/* =================================================
          MAIN CHAT
      ================================================= */}

      <main className="chat-main">

        {/* ================================================
            HEADER
        ================================================= */}

        <header className="chat-header">

          <div className="header-left">

            {selectedUser ? (
              <>

                <button
                  type="button"
                  className="mobile-back"
                  onClick={() =>
                    setSelectedUser(
                      null
                    )
                  }
                >
                  <ArrowLeft
                    size={18}
                  />
                </button>

                <div className="header-avatar">
                  {selectedUser.username
                    ?.charAt(
                      0
                    )
                    ?.toUpperCase() ||
                    "U"}
                </div>

                <div>

                  <div className="header-title">
                    PRIVATE CHAT
                  </div>

                  <div className="header-subtitle">
                    <span className="online-indicator" />
                    {selectedUser.username}
                    {" "}
                    • DIRECT ENCRYPTED CHANNEL
                  </div>

                </div>

              </>
            ) : (

              <>

                <div className="header-avatar encrypted-avatar">
                  <Lock
                    size={17}
                  />
                </div>

                <div>

                  <div className="header-title">
                    SECURE ROOM
                  </div>

                  <div className="header-subtitle">
                    <span className="online-indicator" />
                    ROOM
                    {" "}
                    {currentRoomRef.current ||
                      roomCode}
                    {" "}
                    •
                    {" "}
                    {roomEncryptionReady
                      ? "ENCRYPTION READY"
                      : "ESTABLISHING ENCRYPTION"}
                  </div>

                </div>

              </>

            )}

          </div>


          {/* ==============================================
              HEADER RIGHT
          ============================================== */}

          <div className="header-right">

            {visibleFlagCount > 0 && (
              <div
                className={`flag-counter ${hasSevereFlag ? "severe" : ""}`}
                title={
                  hasSevereFlag
                    ? "HIGH/CRITICAL threat language detected in this view. Leave the room if you feel unsafe."
                    : "Flagged language detected in this view."
                }
              >
                <Flag
                  size={13}
                />

                <span>
                  {visibleFlagCount} FLAGGED
                </span>
              </div>
            )}

            <div className="connection-status">

              <span
                className={
                  connected
                    ? "connection-dot online"
                    : "connection-dot"
                }
              />

              {connected
                ? "CONNECTED"
                : "DISCONNECTED"}

            </div>


            <button
              type="button"
              className="leave-button"
              onClick={
                leaveRoom
              }
            >

              <LogOut
                size={15}
              />

              <span>
                LEAVE
              </span>

            </button>

          </div>

        </header>


        {/* ================================================
            CHAT CONTENT
        ================================================= */}

        <section className="chat-content">

          {!selectedUser ? (

            /* =============================================
               ROOM CHAT
            ============================================= */

            <>

              <div className="messages-area">

                {messages.length ===
                0 ? (

                  <div className="chat-welcome">

                    <div className="welcome-symbol">
                      <Lock
                        size={27}
                      />
                    </div>

                    <div className="welcome-label">
                      END-TO-END ENCRYPTED
                    </div>

                    <h1>
                      Private room.
                      <br />
                      <span>
                        Private messages.
                      </span>
                    </h1>

                    <p>
                      Messages are encrypted
                      in your browser before
                      they are sent to the
                      server.
                    </p>

                    <div className="welcome-room">
                      ROOM
                      {" "}
                      <strong>
                        {currentRoomRef.current ||
                          roomCode}
                      </strong>
                    </div>

                  </div>

                ) : (

                  <div className="message-list">

                    {messages.map(
                      (message) => {

                        if (
                          message.system
                        ) {
                          return (
                            <div
                              key={
                                message.id
                              }
                              className="system-message"
                            >
                              {message.text}
                            </div>
                          );
                        }

                        const own =
                          message.senderId ===
                          currentUserId;

                        return (
                          <div
                            key={
                              message.id
                            }
                            className={`message-row ${
                              own
                                ? "own"
                                : ""
                            }`}
                          >

                            {!own && (
                              <div className="message-avatar">
                                {message.username
                                  ?.charAt(
                                    0
                                  )
                                  ?.toUpperCase() ||
                                  "U"}
                              </div>
                            )}

                            <div className="message-block">

                              <div className="message-meta">

                                <span>
                                  {own
                                    ? "YOU"
                                    : message.username}
                                </span>

                                <span>
                                  {formatTime(
                                    message.timestamp
                                  )}
                                </span>

                              </div>

                              <div className="message-bubble">
                                {message.text}
                              </div>

                              {message.moderation?.flagged && (
                                <div
                                  className={`message-flag-badge moderation-${message.moderation.level.toLowerCase()}`}
                                >
                                  🚩 {message.moderation.level}
                                </div>
                              )}

                            </div>

                          </div>
                        );
                      }
                    )}


                    {typingUser && (
                      <div className="typing-indicator">

                        <div className="typing-avatar">
                          {typingUser
                            ?.charAt(
                              0
                            )
                            ?.toUpperCase()}
                        </div>

                        <div className="typing-bubble">

                          <span />
                          <span />
                          <span />

                        </div>

                        <span className="typing-name">
                          {typingUser}
                          {" "}
                          is typing
                        </span>

                      </div>
                    )}

                    <div
                      ref={
                        messagesEndRef
                      }
                    />

                  </div>

                )}

              </div>


              {/* =========================================
                  ROOM COMPOSER
              ========================================= */}

              <div className="composer-area">

                {messageRisk.flagged && (
                  <div
                    className={`moderation-popup moderation-${messageRisk.level.toLowerCase()}`}
                    role="alert"
                    aria-live="polite"
                  >
                    <div className="moderation-popup-icon">
                      <Flag size={19} strokeWidth={2.2} />
                    </div>

                    <div className="moderation-popup-content">
                      <div className="moderation-popup-top">
                        <strong>{messageRisk.level} RISK</strong>
                        <span className="moderation-popup-category">
                          {messageRisk.category}
                        </span>
                      </div>

                      <div className="moderation-popup-reason">
                        {messageRisk.reason}
                      </div>
                    </div>

                    <div className="moderation-popup-indicator" />
                  </div>
                )}

                {!roomEncryptionReady && (
                  <div className="encryption-notice">
                    <Lock
                      size={13}
                    />

                    Establishing secure
                    room encryption...
                  </div>
                )}

                <div className="composer">

                  <textarea
                    ref={
                      roomInputRef
                    }
                    value={
                      messageInput
                    }
                    onChange={(event) =>
                      handleRoomTyping(
                        event.target.value
                      )
                    }
                    onKeyDown={
                      handleRoomKeyDown
                    }
                    placeholder={
                      roomEncryptionReady
                        ? "Transmit an encrypted message..."
                        : "Waiting for secure encryption..."
                    }
                    rows={1}
                    disabled={
                      !roomEncryptionReady
                    }
                  />

                  <button
                    type="button"
                    onClick={
                      sendRoomMessage
                    }
                    disabled={
                      !messageInput.trim() ||
                      !roomEncryptionReady ||
                      sending
                    }
                  >
                    <Send
                      size={17}
                    />
                  </button>

                </div>

                <div className="composer-footer">

                  <span>
                    ENTER TO SEND
                  </span>

                  <span>
                    SHIFT + ENTER
                  </span>

                  <span className="secure-composer">
                    <ShieldCheck
                      size={12}
                    />

                    ENCRYPTED LOCALLY
                  </span>

                </div>

              </div>

            </>

          ) : (

            /* =============================================
               PRIVATE CHAT
            ============================================= */

            <>

              <div className="messages-area">

                {selectedPrivateMessages.length ===
                0 ? (

                  <div className="chat-welcome">

                    <div className="welcome-symbol private-symbol">
                      <User
                        size={26}
                      />
                    </div>

                    <div className="welcome-label">
                      PRIVATE CHANNEL
                    </div>

                    <h1>
                      Directly with
                      <br />
                      <span>
                        {selectedUser.username}
                      </span>
                    </h1>

                    <p>
                      Messages in this
                      conversation are
                      encrypted using
                      ECDH-derived keys.
                    </p>

                    <div className="welcome-room">
                      <Lock
                        size={13}
                      />

                      ONLY YOU AND
                      {" "}
                      {selectedUser.username.toUpperCase()}
                    </div>

                  </div>

                ) : (

                  <div className="message-list">

                    {selectedPrivateMessages.map(
                      (message) => {

                        const own =
                          message.senderId ===
                          currentUserId;

                        return (
                          <div
                            key={
                              message.id
                            }
                            className={`message-row ${
                              own
                                ? "own"
                                : ""
                            }`}
                          >

                            {!own && (
                              <div className="message-avatar">
                                {message.username
                                  ?.charAt(
                                    0
                                  )
                                  ?.toUpperCase() ||
                                  "U"}
                              </div>
                            )}

                            <div className="message-block">

                              <div className="message-meta">

                                <span>
                                  {own
                                    ? "YOU"
                                    : message.username}
                                </span>

                                <span>
                                  {formatTime(
                                    message.timestamp
                                  )}
                                </span>

                              </div>

                              <div className="message-bubble private-bubble">
                                {message.text}
                              </div>

                              {message.moderation?.flagged && (
                                <div
                                  className={`message-flag-badge moderation-${message.moderation.level.toLowerCase()}`}
                                >
                                  🚩 {message.moderation.level}
                                </div>
                              )}

                            </div>

                          </div>
                        );
                      }
                    )}


                    {privateTypingUser && (
                      <div className="typing-indicator">

                        <div className="typing-avatar">
                          {privateTypingUser
                            ?.charAt(
                              0
                            )
                            ?.toUpperCase()}
                        </div>

                        <div className="typing-bubble">

                          <span />
                          <span />
                          <span />

                        </div>

                        <span className="typing-name">
                          {privateTypingUser}
                          {" "}
                          is typing
                        </span>

                      </div>
                    )}

                    <div
                      ref={
                        privateMessagesEndRef
                      }
                    />

                  </div>

                )}

              </div>


              {/* =========================================
                  PRIVATE COMPOSER
              ========================================= */}

              <div className="composer-area">

                {privateMessageRisk.flagged && (
                  <div
                    className={`moderation-popup moderation-${privateMessageRisk.level.toLowerCase()}`}
                    role="alert"
                    aria-live="polite"
                  >
                    <div className="moderation-popup-icon">
                      <Flag size={19} strokeWidth={2.2} />
                    </div>

                    <div className="moderation-popup-content">
                      <div className="moderation-popup-top">
                        <strong>
                          {privateMessageRisk.level} RISK
                        </strong>

                        <span className="moderation-popup-category">
                          {privateMessageRisk.category}
                        </span>
                      </div>

                      <div className="moderation-popup-reason">
                        {privateMessageRisk.reason}
                      </div>
                    </div>

                    <div className="moderation-popup-indicator" />
                  </div>
                )}

                <div className="composer">

                  <textarea
                    ref={
                      privateInputRef
                    }
                    value={
                      privateInput
                    }
                    onChange={(event) =>
                      handlePrivateTyping(
                        event.target.value
                      )
                    }
                    onKeyDown={
                      handlePrivateKeyDown
                    }
                    placeholder={`Private message to ${selectedUser.username}...`}
                    rows={1}
                  />

                  <button
                    type="button"
                    onClick={
                      sendPrivateMessage
                    }
                    disabled={
                      !privateInput.trim() ||
                      privateSending
                    }
                  >
                    <Send
                      size={17}
                    />
                  </button>

                </div>

                <div className="composer-footer">

                  <span>
                    ENTER TO SEND
                  </span>

                  <span>
                    SHIFT + ENTER
                  </span>

                  <span className="secure-composer">
                    <ShieldCheck
                      size={12}
                    />

                    ECDH PRIVATE CHANNEL
                  </span>

                </div>

              </div>

            </>

          )}

        </section>

      </main>

    </div>
  );
}


// =========================================================
// TIME FORMATTER
// =========================================================

function formatTime(
  timestamp
) {
  if (!timestamp) {
    return "";
  }

  try {
    return new Date(
      timestamp
    ).toLocaleTimeString(
      [],
      {
        hour: "2-digit",
        minute: "2-digit",
      }
    );
  } catch {
    return "";
  }
}


export default App;
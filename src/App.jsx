import React, { useState, useEffect, useRef } from "react";
import { io } from "socket.io-client";

const SERVER_URL = "http://210.79.129.235:3003";
const ICE_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun1.l.google.com:19302" },
];

// Encryption utilities
const generateKeyPair = async () => {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
  return keyPair;
};

const exportPublicKey = async (publicKey) => {
  const exported = await window.crypto.subtle.exportKey("spki", publicKey);
  return btoa(String.fromCharCode(...new Uint8Array(exported)));
};

const exportPrivateKey = async (privateKey) => {
  const exported = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  return btoa(String.fromCharCode(...new Uint8Array(exported)));
};

const importPublicKey = async (publicKeyString) => {
  const binaryString = atob(publicKeyString);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return await window.crypto.subtle.importKey(
    "spki",
    bytes,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
};

const importPrivateKey = async (privateKeyString) => {
  const binaryString = atob(privateKeyString);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return await window.crypto.subtle.importKey(
    "pkcs8",
    bytes,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
};

const encryptMessage = async (message, publicKey) => {
  const aesKey = await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encodedMessage = new TextEncoder().encode(message);

  const encryptedMessage = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encodedMessage
  );

  const exportedAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
  const encryptedAesKey = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    exportedAesKey
  );

  return {
    encryptedMessage: btoa(
      String.fromCharCode(...new Uint8Array(encryptedMessage))
    ),
    encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encryptedAesKey))),
    iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
  };
};

const decryptMessage = async (encryptedData, encryptedKey, iv, privateKey) => {
  try {
    const encryptedKeyBytes = Uint8Array.from(atob(encryptedKey), (c) =>
      c.charCodeAt(0)
    );
    const aesKeyBytes = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encryptedKeyBytes
    );

    const aesKey = await window.crypto.subtle.importKey(
      "raw",
      aesKeyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const ivBytes = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0));
    const encryptedBytes = Uint8Array.from(atob(encryptedData), (c) =>
      c.charCodeAt(0)
    );

    const decryptedMessage = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      aesKey,
      encryptedBytes
    );

    return new TextDecoder().decode(decryptedMessage);
  } catch (error) {
    console.error("Decryption error:", error);
    return "[Unable to decrypt message]";
  }
};

// Key backup/restore utilities
const deriveKeyFromPassphrase = async (passphrase, salt) => {
  const encoder = new TextEncoder();
  const passphraseKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    passphraseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
};

const encryptKeyWithPassphrase = async (privateKeyString, passphrase) => {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await deriveKeyFromPassphrase(passphrase, salt);

  const encoder = new TextEncoder();
  const encryptedKey = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    aesKey,
    encoder.encode(privateKeyString)
  );

  return {
    salt: btoa(String.fromCharCode(...salt)),
    iv: btoa(String.fromCharCode(...iv)),
    encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encryptedKey))),
  };
};

const decryptKeyWithPassphrase = async (encryptedData, passphrase) => {
  try {
    const salt = Uint8Array.from(atob(encryptedData.salt), (c) =>
      c.charCodeAt(0)
    );
    const iv = Uint8Array.from(atob(encryptedData.iv), (c) => c.charCodeAt(0));
    const encrypted = Uint8Array.from(atob(encryptedData.encryptedKey), (c) =>
      c.charCodeAt(0)
    );

    const aesKey = await deriveKeyFromPassphrase(passphrase, salt);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      encrypted
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    throw new Error("Invalid passphrase or corrupted backup");
  }
};

function App() {
  const [userId, setUserId] = useState("");
  const [username, setUsername] = useState("");
  const [partnerId, setPartnerId] = useState("");
  const [isRegistered, setIsRegistered] = useState(false);
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState("");
  const [partnerStatus, setPartnerStatus] = useState("offline");
  const [partnerLastSeen, setPartnerLastSeen] = useState("");
  const [inCall, setInCall] = useState(false);
  const [isPartnerTyping, setIsPartnerTyping] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState("Disconnected");
  const [isMicMuted, setIsMicMuted] = useState(false);
  const [isAudioMuted, setIsAudioMuted] = useState(false);
  const [callDuration, setCallDuration] = useState(0);
  const [selectedImage, setSelectedImage] = useState(null);
  const [imagePreview, setImagePreview] = useState(null);
  const [showKeyBackup, setShowKeyBackup] = useState(false);
  const [backupPassphrase, setBackupPassphrase] = useState("");
  const [showKeyRestore, setShowKeyRestore] = useState(false);
  const [restorePassphrase, setRestorePassphrase] = useState("");
  const [encryptedKeyBackup, setEncryptedKeyBackup] = useState("");
  const [partnerName, setPartnerName] = useState("");
  const [showDebug, setShowDebug] = useState(false);

  const socketRef = useRef(null);
  const peerConnectionRef = useRef(null);
  const typingTimeoutRef = useRef(null);
  const localStreamRef = useRef(null);
  const remoteAudioRef = useRef(null);
  const isTypingRef = useRef(false);
  const messagesEndRef = useRef(null);
  const callTimerRef = useRef(null);
  const fileInputRef = useRef(null);
  const keyPairRef = useRef(null);
  const partnerPublicKeyRef = useRef(null);

  useEffect(() => {
    initializeEncryption();
    loadUserData();
    return () => cleanup();
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (inCall) {
      callTimerRef.current = setInterval(() => {
        setCallDuration((prev) => prev + 1);
      }, 1000);
    } else {
      if (callTimerRef.current) {
        clearInterval(callTimerRef.current);
      }
      setCallDuration(0);
    }
    return () => {
      if (callTimerRef.current) {
        clearInterval(callTimerRef.current);
      }
    };
  }, [inCall]);

  const initializeEncryption = async () => {
    try {
      // Check if we have stored keys
      const storedPrivateKey = localStorage.getItem("privateKey");
      const storedPublicKey = localStorage.getItem("publicKey");

      if (storedPrivateKey && storedPublicKey) {
        // Import existing keys
        const privateKey = await importPrivateKey(storedPrivateKey);
        const publicKey = await importPublicKey(storedPublicKey);
        keyPairRef.current = { privateKey, publicKey };
        console.log("🔐 Encryption keys loaded from storage");
      } else {
        // Generate new keys
        const keyPair = await generateKeyPair();
        keyPairRef.current = keyPair;

        // Store keys in localStorage
        const exportedPrivateKey = await exportPrivateKey(keyPair.privateKey);
        const exportedPublicKey = await exportPublicKey(keyPair.publicKey);
        localStorage.setItem("privateKey", exportedPrivateKey);
        localStorage.setItem("publicKey", exportedPublicKey);

        console.log("🔐 New encryption keys generated and stored");
      }
    } catch (error) {
      console.error("Error initializing encryption:", error);
    }
  };

  const cleanup = () => {
    if (socketRef.current) socketRef.current.disconnect();
    if (peerConnectionRef.current) peerConnectionRef.current.close();
    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach((track) => track.stop());
    }
    if (callTimerRef.current) {
      clearInterval(callTimerRef.current);
    }
  };

  const loadUserData = () => {
    const storedUserId = localStorage.getItem("userId");
    const storedUsername = localStorage.getItem("username");
    const storedPartnerId = localStorage.getItem("partnerId");

    if (storedUserId && storedUsername && storedPartnerId) {
      setUserId(storedUserId);
      setUsername(storedUsername);
      setPartnerId(storedPartnerId);
      connectToServer(storedUserId, storedUsername, storedPartnerId);
    }
  };

  const connectToServer = async (uid, uname, pid) => {
    if (socketRef.current) socketRef.current.disconnect();

    setConnectionStatus("Connecting...");

    // Ensure keys are initialized
    if (!keyPairRef.current) {
      await initializeEncryption();
    }

    const socket = io(SERVER_URL, {
      transports: ["websocket"],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    socketRef.current = socket;

    socket.on("connect", async () => {
      console.log("Connected to server");
      setConnectionStatus("Connected");

      const publicKey = await exportPublicKey(keyPairRef.current.publicKey);
      socket.emit("register", { userId: uid, username: uname, publicKey });
      setIsRegistered(true);

      // Request message history
      socket.emit("request-history", { userId: uid, partnerId: pid });
    });

    socket.on("disconnect", () => {
      console.log("Disconnected from server");
      setConnectionStatus("Disconnected");
      setPartnerStatus("offline");
    });

    socket.on("connect_error", (error) => {
      console.error("Connection error:", error);
      setConnectionStatus("Connection Failed");
      alert("Failed to connect to server. Check SERVER_URL.");
    });

    socket.on("message-history", async (history) => {
      console.log("Loading message history:", history.length, "messages");

      // Load cached sent messages
      const sentMessagesCache = JSON.parse(
        localStorage.getItem("sentMessages") || "{}"
      );
      const mySentMessages = sentMessagesCache[pid] || [];
      const sentMessageMap = new Map(
        mySentMessages.map((msg) => [msg.timestamp, msg.text])
      );

      const decryptedMessages = [];

      for (const msg of history) {
        if (msg.message_type === "image") {
          // Handle image messages
          if (msg.to_user === uid && msg.image_viewed === 0 && msg.image_data) {
            // Unviewed image - show it
            decryptedMessages.push({
              id: msg.id,
              text: null,
              imageData: msg.image_data,
              sender: msg.from_user,
              timestamp: new Date(msg.timestamp),
              messageType: "image",
              isViewed: false,
            });
          } else {
            // Viewed or sent image
            decryptedMessages.push({
              id: msg.id,
              text: msg.to_user === uid ? "[Image (viewed)]" : "[Image sent]",
              sender: msg.from_user,
              timestamp: new Date(msg.timestamp),
              messageType: "image",
              isViewed: true,
            });
          }
        } else {
          // Handle text messages
          let messageText = msg.message;

          if (msg.from_user === uid) {
            // Messages I sent - check cache first
            const cachedText = sentMessageMap.get(msg.timestamp);
            if (cachedText) {
              messageText = cachedText;
              console.log(`Using cached text for sent message ${msg.id}`);
            } else {
              // Fallback: show placeholder (can't decrypt our own sent messages without original text)
              messageText = "[Message sent]";
              console.warn(
                `No cache found for sent message ${msg.id}, showing placeholder`
              );
            }
          } else if (msg.to_user === uid) {
            // Messages sent to me - only decrypt if they have encryption metadata
            if (msg.encrypted_key && msg.iv && keyPairRef.current?.privateKey) {
              try {
                console.log(
                  `Attempting to decrypt message ${msg.id} from ${msg.from_user}`
                );
                messageText = await decryptMessage(
                  msg.message,
                  msg.encrypted_key,
                  msg.iv,
                  keyPairRef.current.privateKey
                );
                console.log(`Successfully decrypted message ${msg.id}`);
              } catch (error) {
                console.error("Decryption failed for message:", msg.id, error);
                messageText = "[Unable to decrypt message]";
              }
            } else if (!msg.encrypted_key && !msg.iv) {
              // Unencrypted message (legacy or fallback)
              messageText = msg.message;
            } else {
              // Has encryption metadata but we can't decrypt
              messageText = "[Unable to decrypt message - missing keys]";
            }
          }

          decryptedMessages.push({
            id: msg.id,
            text: messageText,
            sender: msg.from_user,
            timestamp: new Date(msg.timestamp),
            messageType: "text",
          });
        }
      }

      console.log(
        "Message history loaded:",
        decryptedMessages.length,
        "messages"
      );
      setMessages(decryptedMessages);
    });

    socket.on("users-status", (users) => {
      const partner = users.find((u) => u.userId === pid);
      if (partner) {
        setPartnerStatus(partner.status);
        setPartnerLastSeen(partner.lastSeen);
        setPartnerName(partner.username || pid);
        if (partner.publicKey) {
          importPublicKey(partner.publicKey).then((key) => {
            partnerPublicKeyRef.current = key;
          });
        }
      }
    });

    socket.on(
      "user-online",
      async ({ userId: onlineUserId, publicKey, username }) => {
        if (onlineUserId === pid) {
          setPartnerStatus("online");
          if (username) setPartnerName(username);
          if (publicKey) {
            const key = await importPublicKey(publicKey);
            partnerPublicKeyRef.current = key;
          }
          if (Notification.permission === "granted") {
            new Notification("Partner Online", {
              body: "Your partner just came online!",
            });
          }
        }
      }
    );

    socket.on("user-offline", ({ userId: offlineUserId, lastSeen }) => {
      if (offlineUserId === pid) {
        setPartnerStatus("offline");
        setPartnerLastSeen(lastSeen);
      }
    });

    socket.on(
      "receive-message",
      async ({
        id,
        from,
        message,
        messageType,
        imageData,
        encryptedKey,
        iv,
        timestamp,
      }) => {
        if (messageType === "image") {
          setMessages((prev) => [
            ...prev,
            {
              id: id || `${Date.now()}-${Math.random()}`,
              text: null,
              imageData: imageData,
              sender: from,
              timestamp: new Date(timestamp),
              messageType: "image",
              isViewed: false,
            },
          ]);
        } else {
          let messageText = message;

          // Only decrypt if encrypted and I have the private key
          if (encryptedKey && iv && keyPairRef.current?.privateKey) {
            try {
              console.log(`Decrypting incoming message from ${from}`);
              messageText = await decryptMessage(
                message,
                encryptedKey,
                iv,
                keyPairRef.current.privateKey
              );
              console.log("Successfully decrypted incoming message");
            } catch (error) {
              console.error("Decryption failed for incoming message:", error);
              messageText = message; // Fallback to encrypted text
            }
          }

          setMessages((prev) => [
            ...prev,
            {
              id: id || `${Date.now()}-${Math.random()}`,
              text: messageText,
              sender: from,
              timestamp: new Date(timestamp),
              messageType: "text",
            },
          ]);
        }

        if (Notification.permission === "granted" && document.hidden) {
          new Notification("New Message", {
            body: messageType === "image" ? "📷 Image" : messageText || message,
          });
        }
      }
    );

    socket.on("incoming-call", ({ from, offer }) => {
      if (
        confirm(`${from === pid ? "Your partner" : from} is calling. Answer?`)
      ) {
        answerCall(offer, from);
      } else {
        socket.emit("end-call", { to: from });
      }
    });

    socket.on("call-answered", async ({ answer }) => {
      try {
        if (peerConnectionRef.current) {
          await peerConnectionRef.current.setRemoteDescription(
            new RTCSessionDescription(answer)
          );
        }
      } catch (error) {
        console.error("Error setting remote description:", error);
      }
    });

    socket.on("ice-candidate", async ({ candidate }) => {
      try {
        if (peerConnectionRef.current && candidate) {
          await peerConnectionRef.current.addIceCandidate(
            new RTCIceCandidate(candidate)
          );
        }
      } catch (error) {
        console.error("Error adding ICE candidate:", error);
      }
    });

    socket.on("call-ended", () => {
      endCall();
      alert("Call ended");
    });

    socket.on("user-typing", ({ from }) => {
      if (from === pid) setIsPartnerTyping(true);
    });

    socket.on("user-stop-typing", ({ from }) => {
      if (from === pid) setIsPartnerTyping(false);
    });
  };

  const handleRegister = () => {
    if (!userId.trim() || !username.trim() || !partnerId.trim()) {
      alert("Please fill all fields");
      return;
    }

    if (userId === partnerId) {
      alert("Your User ID and Partner ID cannot be the same");
      return;
    }

    localStorage.setItem("userId", userId.trim());
    localStorage.setItem("username", username.trim());
    localStorage.setItem("partnerId", partnerId.trim());

    connectToServer(userId.trim(), username.trim(), partnerId.trim());

    if (Notification.permission === "default") {
      Notification.requestPermission();
    }
  };

  const resetEncryptionKeys = async () => {
    if (
      confirm(
        "Reset encryption keys? You won't be able to read old messages encrypted with current keys."
      )
    ) {
      localStorage.removeItem("privateKey");
      localStorage.removeItem("publicKey");
      await initializeEncryption();
      alert("Encryption keys reset. Please reconnect.");
      window.location.reload();
    }
  };

  const handleBackupKeys = async () => {
    if (!backupPassphrase || backupPassphrase.length < 8) {
      alert("Please enter a passphrase of at least 8 characters");
      return;
    }

    try {
      const privateKeyString = localStorage.getItem("privateKey");
      const publicKeyString = localStorage.getItem("publicKey");
      const sentMessages = localStorage.getItem("sentMessages");

      if (!privateKeyString || !publicKeyString) {
        alert("No keys found to backup");
        return;
      }

      const keyData = JSON.stringify({
        privateKey: privateKeyString,
        publicKey: publicKeyString,
        sentMessages: sentMessages || "{}",
        userId: userId,
        timestamp: new Date().toISOString(),
      });

      const encrypted = await encryptKeyWithPassphrase(
        keyData,
        backupPassphrase
      );
      const backupData = JSON.stringify(encrypted);

      // Download backup file
      const blob = new Blob([backupData], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `chat-keys-backup-${userId}-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);

      alert("Keys backed up successfully! Keep this file and passphrase safe.");
      setShowKeyBackup(false);
      setBackupPassphrase("");
    } catch (error) {
      console.error("Backup error:", error);
      alert("Failed to backup keys: " + error.message);
    }
  };

  const handleRestoreKeys = async () => {
    if (!restorePassphrase) {
      alert("Please enter your backup passphrase");
      return;
    }

    if (!encryptedKeyBackup) {
      alert("Please select a backup file");
      return;
    }

    try {
      const backupData = JSON.parse(encryptedKeyBackup);
      const decryptedData = await decryptKeyWithPassphrase(
        backupData,
        restorePassphrase
      );
      const keyData = JSON.parse(decryptedData);

      // Restore keys and sent messages to localStorage
      localStorage.setItem("privateKey", keyData.privateKey);
      localStorage.setItem("publicKey", keyData.publicKey);
      if (keyData.sentMessages) {
        localStorage.setItem("sentMessages", keyData.sentMessages);
      }

      alert("Keys and message history restored successfully! Reloading...");
      window.location.reload();
    } catch (error) {
      console.error("Restore error:", error);
      alert("Failed to restore keys: Invalid passphrase or corrupted backup");
    }
  };

  const handleBackupFileSelect = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      setEncryptedKeyBackup(event.target.result);
    };
    reader.readAsText(file);
  };

  const handleImageSelect = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (!file.type.startsWith("image/")) {
      alert("Please select an image file");
      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      alert("Image size must be less than 5MB");
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      setSelectedImage(file);
      setImagePreview(event.target.result);
    };
    reader.readAsDataURL(file);
  };

  const sendImage = () => {
    if (!imagePreview) return;
    if (!socketRef.current?.connected) {
      alert("Not connected to server");
      return;
    }

    const timestamp = new Date().toISOString();
    socketRef.current.emit("send-message", {
      from: userId,
      to: partnerId,
      messageType: "image",
      imageData: imagePreview,
      timestamp,
    });

    setMessages((prev) => [
      ...prev,
      {
        id: `${Date.now()}-${Math.random()}`,
        text: "[Image sent]",
        sender: userId,
        timestamp: new Date(),
        messageType: "image",
        isViewed: true,
      },
    ]);

    setSelectedImage(null);
    setImagePreview(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const sendMessage = async () => {
    if (!inputMessage.trim()) return;
    if (!socketRef.current?.connected) {
      alert("Not connected to server");
      return;
    }

    const timestamp = new Date().toISOString();
    const originalText = inputMessage.trim();
    let encryptedData = null;

    // Encrypt message if partner's public key is available
    if (partnerPublicKeyRef.current) {
      try {
        encryptedData = await encryptMessage(
          originalText,
          partnerPublicKeyRef.current
        );
        console.log("Message encrypted for partner");
      } catch (error) {
        console.error("Encryption error:", error);
        alert("Failed to encrypt message. Sending unencrypted.");
      }
    } else {
      console.warn("Partner public key not available, sending unencrypted");
    }

    const tempId = `${Date.now()}-${Math.random()}`;

    // Cache message BEFORE sending (with exact timestamp that will be stored in DB)
    try {
      const messageCache = JSON.parse(
        localStorage.getItem("sentMessages") || "{}"
      );
      if (!messageCache[partnerId]) messageCache[partnerId] = {};

      // Store by timestamp for easy lookup
      messageCache[partnerId][timestamp] = originalText;

      localStorage.setItem("sentMessages", JSON.stringify(messageCache));
      console.log(`Cached sent message with timestamp: ${timestamp}`);
    } catch (error) {
      console.error("Error caching sent message:", error);
    }

    socketRef.current.emit("send-message", {
      from: userId,
      to: partnerId,
      message: encryptedData ? encryptedData.encryptedMessage : originalText,
      encryptedKey: encryptedData?.encryptedKey,
      iv: encryptedData?.iv,
      timestamp,
      messageType: "text",
      originalMessage: originalText, // Send original for server to store
    });

    // Store in local state with original text
    const newMessage = {
      id: tempId,
      text: originalText,
      sender: userId,
      timestamp: new Date(timestamp),
      messageType: "text",
    };

    setMessages((prev) => [...prev, newMessage]);

    setInputMessage("");
    stopTyping();
  };

  const handleImageView = (messageId) => {
    socketRef.current?.emit("image-viewed", { messageId, userId });

    setMessages((prev) =>
      prev.map((msg) =>
        msg.id === messageId
          ? {
              ...msg,
              isViewed: true,
              imageData: null,
              text: "[Image (viewed)]",
            }
          : msg
      )
    );
  };

  const handleTyping = (text) => {
    setInputMessage(text);

    if (!isTypingRef.current && text.trim()) {
      isTypingRef.current = true;
      socketRef.current?.emit("typing", { to: partnerId });
    }

    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);

    typingTimeoutRef.current = setTimeout(() => {
      stopTyping();
    }, 1000);
  };

  const stopTyping = () => {
    if (isTypingRef.current) {
      isTypingRef.current = false;
      socketRef.current?.emit("stop-typing", { to: partnerId });
    }
  };

  const startCall = async () => {
    if (!socketRef.current?.connected) {
      alert("Not connected to server");
      return;
    }

    if (partnerStatus !== "online") {
      alert("Partner is offline");
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: false,
      });
      localStreamRef.current = stream;

      const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
      peerConnectionRef.current = pc;

      stream.getTracks().forEach((track) => pc.addTrack(track, stream));

      pc.ontrack = (event) => {
        console.log("Received remote track");
        if (remoteAudioRef.current && event.streams[0]) {
          remoteAudioRef.current.srcObject = event.streams[0];
          remoteAudioRef.current
            .play()
            .catch((e) => console.error("Error playing audio:", e));
        }
      };

      pc.onicecandidate = (event) => {
        if (event.candidate) {
          socketRef.current?.emit("ice-candidate", {
            to: partnerId,
            candidate: event.candidate,
          });
        }
      };

      pc.onconnectionstatechange = () => {
        console.log("Connection state:", pc.connectionState);
        if (
          pc.connectionState === "failed" ||
          pc.connectionState === "disconnected"
        ) {
          endCall();
          alert("Call failed - connection lost");
        }
      };

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      socketRef.current.emit("call-user", {
        to: partnerId,
        from: userId,
        offer: offer,
      });

      setInCall(true);
      setIsMicMuted(false);
      setIsAudioMuted(false);
    } catch (error) {
      console.error("Start call error:", error);
      alert(`Failed to start call: ${error.message}`);
      endCall();
    }
  };

  const answerCall = async (offer, fromUserId) => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: false,
      });
      localStreamRef.current = stream;

      const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
      peerConnectionRef.current = pc;

      stream.getTracks().forEach((track) => pc.addTrack(track, stream));

      pc.ontrack = (event) => {
        console.log("Received remote track");
        if (remoteAudioRef.current && event.streams[0]) {
          remoteAudioRef.current.srcObject = event.streams[0];
          remoteAudioRef.current
            .play()
            .catch((e) => console.error("Error playing audio:", e));
        }
      };

      pc.onicecandidate = (event) => {
        if (event.candidate) {
          socketRef.current?.emit("ice-candidate", {
            to: fromUserId || partnerId,
            candidate: event.candidate,
          });
        }
      };

      pc.onconnectionstatechange = () => {
        console.log("Connection state:", pc.connectionState);
        if (
          pc.connectionState === "failed" ||
          pc.connectionState === "disconnected"
        ) {
          endCall();
          alert("Call failed - connection lost");
        }
      };

      await pc.setRemoteDescription(new RTCSessionDescription(offer));
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);

      socketRef.current?.emit("call-answer", {
        to: fromUserId || partnerId,
        answer: answer,
      });

      setInCall(true);
      setIsMicMuted(false);
      setIsAudioMuted(false);
    } catch (error) {
      console.error("Answer call error:", error);
      alert(`Failed to answer call: ${error.message}`);
      endCall();
    }
  };

  const endCall = () => {
    if (peerConnectionRef.current) {
      peerConnectionRef.current.close();
      peerConnectionRef.current = null;
    }

    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach((track) => track.stop());
      localStreamRef.current = null;
    }

    if (remoteAudioRef.current) {
      remoteAudioRef.current.srcObject = null;
    }

    socketRef.current?.emit("end-call", { to: partnerId });
    setInCall(false);
    setIsMicMuted(false);
    setIsAudioMuted(false);
  };

  const toggleMic = () => {
    if (localStreamRef.current) {
      const audioTrack = localStreamRef.current.getAudioTracks()[0];
      if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        setIsMicMuted(!audioTrack.enabled);
      }
    }
  };

  const toggleAudio = () => {
    if (remoteAudioRef.current) {
      remoteAudioRef.current.muted = !remoteAudioRef.current.muted;
      setIsAudioMuted(remoteAudioRef.current.muted);
    }
  };

  const formatCallDuration = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, "0")}:${secs
      .toString()
      .padStart(2, "0")}`;
  };

  const formatLastSeen = (timestamp) => {
    if (!timestamp) return "";
    try {
      const date = new Date(timestamp);
      const now = new Date();
      const diffMs = now - date;
      const diffMins = Math.floor(diffMs / 60000);

      if (diffMins < 1) return "Just now";
      if (diffMins < 60) return `${diffMins} min ago`;
      if (diffMins < 1440) return `${Math.floor(diffMins / 60)} hours ago`;
      return date.toLocaleDateString();
    } catch (error) {
      return "";
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  if (!isRegistered) {
    return (
      <div style={styles.app}>
        <div style={styles.registerContainer}>
          <h1 style={styles.title}>🔐 Secure P2P Chat</h1>
          <p style={styles.subtitle}>End-to-end encrypted messaging</p>
          <div
            style={{
              ...styles.statusBadge,
              backgroundColor:
                connectionStatus === "Connected" ? "#10b981" : "#ef4444",
            }}
          >
            {connectionStatus}
          </div>
          <input
            type="text"
            placeholder="Your User ID (e.g., user1)"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            style={styles.input}
          />
          <input
            type="text"
            placeholder="Your Name"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            style={styles.input}
          />
          <input
            type="text"
            placeholder="Partner's User ID (e.g., user2)"
            value={partnerId}
            onChange={(e) => setPartnerId(e.target.value)}
            style={styles.input}
          />
          <button onClick={handleRegister} style={styles.button}>
            Connect
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.app}>
      <audio ref={remoteAudioRef} autoPlay />

      {inCall && (
        <div style={styles.callModal}>
          <div style={styles.callModalContent}>
            <div style={styles.callModalHeader}>
              <div style={styles.callIcon}>📞</div>
              <h2 style={styles.callModalTitle}>{username}</h2>
              <p style={styles.callStatus}>Connected</p>
              <p style={styles.callDuration}>
                {formatCallDuration(callDuration)}
              </p>
            </div>

            <div style={styles.callControls}>
              <button
                onClick={toggleMic}
                style={{
                  ...styles.callControlButton,
                  backgroundColor: isMicMuted ? "#ef4444" : "#4b5563",
                }}
                title={isMicMuted ? "Unmute Microphone" : "Mute Microphone"}
              >
                {isMicMuted ? "🎤❌" : "🎤"}
              </button>

              <button
                onClick={endCall}
                style={{
                  ...styles.callControlButton,
                  backgroundColor: "#dc2626",
                }}
                title="End Call"
              >
                ❌
              </button>

              <button
                onClick={toggleAudio}
                style={{
                  ...styles.callControlButton,
                  backgroundColor: isAudioMuted ? "#ef4444" : "#4b5563",
                }}
                title={isAudioMuted ? "Unmute Audio" : "Mute Audio"}
              >
                {isAudioMuted ? "🔇" : "🔊"}
              </button>
            </div>
          </div>
        </div>
      )}

      {imagePreview && (
        <div style={styles.imagePreviewModal}>
          <div style={styles.imagePreviewContent}>
            <h3 style={styles.imagePreviewTitle}>Send Image (One-Time View)</h3>
            <img src={imagePreview} alt="Preview" style={styles.imagePreview} />
            <div style={styles.imagePreviewButtons}>
              <button
                onClick={() => {
                  setImagePreview(null);
                  setSelectedImage(null);
                  if (fileInputRef.current) fileInputRef.current.value = "";
                }}
                style={{
                  ...styles.imagePreviewButton,
                  backgroundColor: "#6b7280",
                }}
              >
                Cancel
              </button>
              <button
                onClick={sendImage}
                style={{
                  ...styles.imagePreviewButton,
                  backgroundColor: "#3b82f6",
                }}
              >
                Send
              </button>
            </div>
          </div>
        </div>
      )}

      {showKeyBackup && (
        <div style={styles.imagePreviewModal}>
          <div style={styles.imagePreviewContent}>
            <h3 style={styles.imagePreviewTitle}>🔐 Backup Encryption Keys</h3>
            <p style={styles.backupDescription}>
              Create a password-protected backup of your encryption keys. You
              can use this to restore access to your messages even if you clear
              browser data.
            </p>
            <input
              type="password"
              placeholder="Enter a strong passphrase (min 8 characters)"
              value={backupPassphrase}
              onChange={(e) => setBackupPassphrase(e.target.value)}
              style={styles.input}
            />
            <p style={styles.backupWarning}>
              ⚠️ Remember this passphrase! Without it, your backup is useless.
            </p>
            <div style={styles.imagePreviewButtons}>
              <button
                onClick={() => {
                  setShowKeyBackup(false);
                  setBackupPassphrase("");
                }}
                style={{
                  ...styles.imagePreviewButton,
                  backgroundColor: "#6b7280",
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleBackupKeys}
                style={{
                  ...styles.imagePreviewButton,
                  backgroundColor: "#10b981",
                }}
              >
                Download Backup
              </button>
            </div>
          </div>
        </div>
      )}

      {showKeyRestore && (
        <div style={styles.imagePreviewModal}>
          <div style={styles.imagePreviewContent}>
            <h3 style={styles.imagePreviewTitle}>📥 Restore Encryption Keys</h3>
            <p style={styles.backupDescription}>
              Upload your backup file and enter the passphrase to restore your
              encryption keys.
            </p>
            <input
              type="file"
              accept=".json"
              onChange={handleBackupFileSelect}
              style={{ ...styles.input, padding: "8px" }}
            />
            <input
              type="password"
              placeholder="Enter your backup passphrase"
              value={restorePassphrase}
              onChange={(e) => setRestorePassphrase(e.target.value)}
              style={styles.input}
            />
            <div style={styles.imagePreviewButtons}>
              <button
                onClick={() => {
                  setShowKeyRestore(false);
                  setRestorePassphrase("");
                  setEncryptedKeyBackup("");
                }}
                style={{
                  ...styles.imagePreviewButton,
                  backgroundColor: "#6b7280",
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleRestoreKeys}
                style={{
                  ...styles.imagePreviewButton,
                  backgroundColor: "#3b82f6",
                }}
              >
                Restore Keys
              </button>
            </div>
          </div>
        </div>
      )}

      <div style={styles.header}>
        <div>
          <h2 style={styles.headerTitle}>{partnerName || partnerId}</h2>
          <div style={styles.headerActions}>
            <div
              style={styles.encryptionBadge}
              onClick={() => setShowKeyBackup(true)}
              title="Click to backup encryption keys"
            >
              💾 Backup Keys
            </div>
            <div
              style={{ ...styles.encryptionBadge, backgroundColor: "#6366f1" }}
              onClick={() => setShowKeyRestore(true)}
              title="Click to restore encryption keys"
            >
              📥 Restore Keys
            </div>
            <div
              style={{ ...styles.encryptionBadge, backgroundColor: "#f59e0b" }}
              onClick={() => setShowDebug(!showDebug)}
              title="Toggle debug info"
            >
              🔍 Debug
            </div>
          </div>
        </div>
        <div style={styles.statusContainer}>
          <div
            style={{
              ...styles.statusDot,
              backgroundColor:
                partnerStatus === "online" ? "#10b981" : "#9ca3af",
            }}
          ></div>
          <span style={styles.statusText}>
            {partnerStatus === "online"
              ? "Online"
              : `Last seen: ${formatLastSeen(partnerLastSeen)}`}
          </span>
        </div>
      </div>

      {showDebug && (
        <div style={styles.debugPanel}>
          <div style={styles.debugTitle}>🔍 Debug Information</div>
          <div style={styles.debugInfo}>
            <strong>Your User ID:</strong> {userId}
            <br />
            <strong>Partner ID:</strong> {partnerId}
            <br />
            <strong>Your Keys:</strong>{" "}
            {keyPairRef.current ? "✅ Loaded" : "❌ Missing"}
            <br />
            <strong>Partner Public Key:</strong>{" "}
            {partnerPublicKeyRef.current ? "✅ Loaded" : "❌ Missing"}
            <br />
            <strong>Connection:</strong> {connectionStatus}
            <br />
            <strong>Partner Status:</strong> {partnerStatus}
          </div>
          <button
            onClick={() => {
              console.log("=== DEBUG INFO ===");
              console.log("User ID:", userId);
              console.log("Partner ID:", partnerId);
              console.log("Keys:", keyPairRef.current ? "Present" : "Missing");
              console.log(
                "Partner Public Key:",
                partnerPublicKeyRef.current ? "Present" : "Missing"
              );
              console.log("Messages:", messages.length);
              console.log("Recent messages:", messages.slice(-5));
            }}
            style={{
              ...styles.imagePreviewButton,
              backgroundColor: "#3b82f6",
              marginTop: "8px",
            }}
          >
            Log to Console
          </button>
        </div>
      )}

      <div style={styles.messagesContainer}>
        {messages.map((msg) => (
          <div
            key={msg.id}
            style={{
              ...styles.message,
              alignSelf: msg.sender === userId ? "flex-end" : "flex-start",
              backgroundColor: msg.sender === userId ? "#3b82f6" : "#374151",
            }}
          >
            {msg.messageType === "image" && !msg.isViewed && msg.imageData ? (
              <div style={styles.imageMessage}>
                <img
                  src={msg.imageData}
                  alt="Received"
                  style={styles.receivedImage}
                  onClick={() => handleImageView(msg.id)}
                />
                <div style={styles.imageViewWarning}>
                  ⚠️ Tap to view (one-time only)
                </div>
              </div>
            ) : (
              <div style={styles.messageText}>{msg.text}</div>
            )}
            <div style={styles.messageTime}>
              {msg.timestamp.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
              })}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {isPartnerTyping && (
        <div style={styles.typingIndicator}>Partner is typing...</div>
      )}

      <div style={styles.inputContainer}>
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          onChange={handleImageSelect}
          style={{ display: "none" }}
        />
        <button
          style={styles.imageBtn}
          onClick={() => fileInputRef.current?.click()}
          title="Send Image (One-Time View)"
        >
          📷
        </button>
        <button
          style={{
            ...styles.callBtn,
            opacity: partnerStatus !== "online" ? 0.5 : 1,
          }}
          onClick={startCall}
          disabled={partnerStatus !== "online" || inCall}
        >
          📞
        </button>
        <textarea
          placeholder="Type a message..."
          value={inputMessage}
          onChange={(e) => handleTyping(e.target.value)}
          onKeyPress={handleKeyPress}
          style={styles.textarea}
          rows={1}
        />
        <button
          style={{
            ...styles.sendBtn,
            opacity: !inputMessage.trim() ? 0.5 : 1,
          }}
          onClick={sendMessage}
          disabled={!inputMessage.trim()}
        >
          ➤
        </button>
      </div>
    </div>
  );
}

const styles = {
  app: {
    display: "flex",
    flexDirection: "column",
    height: "100vh",
    backgroundColor: "#111827",
    color: "#f3f4f6",
    fontFamily: "system-ui, -apple-system, sans-serif",
  },
  registerContainer: {
    maxWidth: "400px",
    margin: "auto",
    padding: "32px",
    backgroundColor: "#1f2937",
    borderRadius: "12px",
    boxShadow: "0 4px 6px rgba(0,0,0,0.3)",
  },
  title: {
    textAlign: "center",
    marginBottom: "8px",
    fontSize: "24px",
  },
  subtitle: {
    textAlign: "center",
    marginBottom: "24px",
    fontSize: "14px",
    color: "#9ca3af",
  },
  statusBadge: {
    padding: "8px 16px",
    borderRadius: "20px",
    textAlign: "center",
    marginBottom: "16px",
    fontSize: "14px",
    fontWeight: "600",
  },
  input: {
    width: "100%",
    padding: "12px",
    marginBottom: "12px",
    backgroundColor: "#374151",
    border: "1px solid #4b5563",
    borderRadius: "8px",
    color: "#f3f4f6",
    fontSize: "14px",
    boxSizing: "border-box",
  },
  button: {
    width: "100%",
    padding: "12px",
    backgroundColor: "#3b82f6",
    border: "none",
    borderRadius: "8px",
    color: "white",
    fontSize: "16px",
    fontWeight: "600",
    cursor: "pointer",
  },
  header: {
    padding: "16px",
    backgroundColor: "#1f2937",
    borderBottom: "1px solid #374151",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
  },
  headerTitle: {
    margin: "0 0 8px 0",
    fontSize: "20px",
  },
  headerActions: {
    display: "flex",
    gap: "8px",
    flexWrap: "wrap",
  },
  encryptionBadge: {
    display: "inline-block",
    padding: "4px 8px",
    backgroundColor: "#10b981",
    borderRadius: "4px",
    fontSize: "11px",
    fontWeight: "600",
    cursor: "pointer",
    transition: "opacity 0.2s",
  },
  backupDescription: {
    fontSize: "14px",
    color: "#9ca3af",
    marginBottom: "16px",
    lineHeight: "1.5",
  },
  backupWarning: {
    fontSize: "12px",
    color: "#fbbf24",
    marginTop: "8px",
    marginBottom: "16px",
  },
  debugPanel: {
    backgroundColor: "#1f2937",
    borderBottom: "1px solid #374151",
    padding: "12px 16px",
  },
  debugTitle: {
    fontSize: "14px",
    fontWeight: "600",
    marginBottom: "8px",
    color: "#f59e0b",
  },
  debugInfo: {
    fontSize: "12px",
    color: "#9ca3af",
    lineHeight: "1.8",
    fontFamily: "monospace",
  },
  statusContainer: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
  },
  statusDot: {
    width: "10px",
    height: "10px",
    borderRadius: "50%",
  },
  statusText: {
    fontSize: "14px",
    color: "#9ca3af",
  },
  messagesContainer: {
    flex: 1,
    overflowY: "auto",
    padding: "16px",
    display: "flex",
    flexDirection: "column",
    gap: "8px",
  },
  message: {
    maxWidth: "70%",
    padding: "12px",
    borderRadius: "12px",
    wordWrap: "break-word",
  },
  messageText: {
    marginBottom: "4px",
  },
  messageTime: {
    fontSize: "11px",
    opacity: 0.7,
  },
  imageMessage: {
    display: "flex",
    flexDirection: "column",
    gap: "8px",
  },
  receivedImage: {
    maxWidth: "300px",
    maxHeight: "300px",
    borderRadius: "8px",
    cursor: "pointer",
    filter: "blur(10px)",
    transition: "filter 0.3s",
  },
  imageViewWarning: {
    fontSize: "11px",
    color: "#fbbf24",
    textAlign: "center",
  },
  typingIndicator: {
    padding: "8px 16px",
    fontSize: "14px",
    fontStyle: "italic",
    color: "#9ca3af",
  },
  inputContainer: {
    padding: "16px",
    backgroundColor: "#1f2937",
    borderTop: "1px solid #374151",
    display: "flex",
    gap: "8px",
    alignItems: "center",
  },
  imageBtn: {
    padding: "12px",
    backgroundColor: "#8b5cf6",
    border: "none",
    borderRadius: "8px",
    fontSize: "20px",
    cursor: "pointer",
  },
  callBtn: {
    padding: "12px",
    backgroundColor: "#10b981",
    border: "none",
    borderRadius: "8px",
    fontSize: "20px",
    cursor: "pointer",
  },
  textarea: {
    flex: 1,
    padding: "12px",
    backgroundColor: "#374151",
    border: "1px solid #4b5563",
    borderRadius: "8px",
    color: "#f3f4f6",
    fontSize: "14px",
    resize: "none",
    fontFamily: "inherit",
  },
  sendBtn: {
    padding: "12px 20px",
    backgroundColor: "#3b82f6",
    border: "none",
    borderRadius: "8px",
    fontSize: "20px",
    cursor: "pointer",
    color: "white",
  },
  callModal: {
    position: "fixed",
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: "rgba(0, 0, 0, 0.9)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 1000,
  },
  callModalContent: {
    backgroundColor: "#1f2937",
    borderRadius: "16px",
    padding: "32px",
    minWidth: "320px",
    textAlign: "center",
  },
  callModalHeader: {
    marginBottom: "32px",
  },
  callIcon: {
    fontSize: "64px",
    marginBottom: "16px",
  },
  callModalTitle: {
    margin: "0 0 8px 0",
    fontSize: "24px",
  },
  callStatus: {
    color: "#10b981",
    margin: "0 0 8px 0",
    fontSize: "14px",
    fontWeight: "600",
  },
  callDuration: {
    color: "#9ca3af",
    margin: 0,
    fontSize: "16px",
    fontFamily: "monospace",
  },
  callControls: {
    display: "flex",
    gap: "16px",
    justifyContent: "center",
  },
  callControlButton: {
    width: "60px",
    height: "60px",
    border: "none",
    borderRadius: "50%",
    fontSize: "24px",
    cursor: "pointer",
    transition: "transform 0.2s",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  imagePreviewModal: {
    position: "fixed",
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: "rgba(0, 0, 0, 0.95)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 1001,
  },
  imagePreviewContent: {
    backgroundColor: "#1f2937",
    borderRadius: "16px",
    padding: "24px",
    maxWidth: "500px",
    width: "90%",
  },
  imagePreviewTitle: {
    margin: "0 0 16px 0",
    textAlign: "center",
    fontSize: "18px",
  },
  imagePreview: {
    width: "100%",
    maxHeight: "400px",
    objectFit: "contain",
    borderRadius: "8px",
    marginBottom: "16px",
  },
  imagePreviewButtons: {
    display: "flex",
    gap: "12px",
    justifyContent: "center",
  },
  imagePreviewButton: {
    padding: "12px 24px",
    border: "none",
    borderRadius: "8px",
    color: "white",
    fontSize: "16px",
    fontWeight: "600",
    cursor: "pointer",
  },
};

export default App;
